package trunk

import (
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
)

// compactNames maps a header's long name to its compact form, for the
// headers the session-timer code reads (RFC 4028 §4: x = Session-Expires;
// RFC 3261 §7.3.3 / §20: k = Supported). sipgo's parser expands only the
// compact forms RFC 3261 core headers use, so a message carrying "x: 30"
// keeps a header literally named "x".
var compactNames = map[string]string{
	"session-expires": "x",
	"supported":       "k",
}

// headersNamed returns m's headers called name, in its long or compact
// form.
func headersNamed(m sip.Message, name string) []sip.Header {
	hs := m.GetHeaders(name)
	if c, ok := compactNames[strings.ToLower(name)]; ok {
		hs = append(hs, m.GetHeaders(c)...)
	}
	return hs
}

// maxDeltaSeconds is the largest delta-seconds value honoured: RFC 3261
// §25.1 (via RFC 4028 §4) says larger values are treated as 2^32-1.
const maxDeltaSeconds = 1<<32 - 1

// headerSeconds parses the leading delta-seconds value of a header (the
// number before any ';' parameters), e.g. "1800;refresher=uac" → 1800s,
// accepting the header's compact form. Values above 2^32-1 are clamped to
// it. Returns 0 if the header is absent or unparseable.
func headerSeconds(m sip.Message, name string) time.Duration {
	headers := headersNamed(m, name)
	if len(headers) == 0 {
		return 0
	}
	v := headers[0].Value()
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n > maxDeltaSeconds {
		// All digits, so the only possible error is overflow.
		n = maxDeltaSeconds
	}
	return time.Duration(n) * time.Second
}

// hasOptionTag reports whether any of m's headers called name (long or
// compact form) lists the option tag (case-insensitive).
func hasOptionTag(m sip.Message, name, tag string) bool {
	for _, h := range headersNamed(m, name) {
		for _, t := range strings.Split(h.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(t), tag) {
				return true
			}
		}
	}
	return false
}

// challengeHeader returns the challenge header value sipgo answers for a
// 401/407: the FIRST WWW-Authenticate for 401, the first Proxy-Authenticate
// for 407 (sipgo's digestAuthApply/digestProxyAuthApply read exactly that).
func challengeHeader(res *sip.Response) (string, bool) {
	name := "WWW-Authenticate"
	if res.StatusCode == sip.StatusProxyAuthRequired {
		name = "Proxy-Authenticate"
	}
	h := res.GetHeader(name)
	if h == nil {
		return "", false
	}
	return h.Value(), true
}

// challengeRealm extracts the realm from a 401/407 digest challenge (see
// challengeHeader for which header). The challenge is parsed as RFC 2617
// §1.2 / RFC 3261 §25.1 define it: a "Digest" scheme followed by
// comma-separated auth-params whose names are case-insensitive and whose
// values are tokens or quoted-strings. Returns "" when the header is
// absent, unparseable, not Digest, or names a realm more than once —
// callers compare it against a pinned realm, so "" never matches (fail
// closed).
func challengeRealm(res *sip.Response) string {
	v, ok := challengeHeader(res)
	if !ok {
		return ""
	}
	params, ok := parseDigestChallenge(v)
	if !ok {
		return ""
	}
	realm, n := "", 0
	for _, p := range params {
		if strings.EqualFold(p[0], "realm") {
			realm = p[1]
			n++
		}
	}
	if n != 1 {
		return ""
	}
	return realm
}

// realmPinned reports whether a 401/407 challenge may be answered for a
// peer that pins realm: the challenge must name exactly that realm under
// RFC parsing (challengeRealm) AND under the parser sipgo itself digests
// with (icholy/digest), so the realm checked is the realm our credentials
// would be hashed over. A challenge the two parsers read differently — a
// realm hidden in another parameter's name or value, a case variant only
// one of them understands, a duplicated realm — is never answered.
func realmPinned(res *sip.Response, realm string) bool {
	if challengeRealm(res) != realm {
		return false
	}
	v, _ := challengeHeader(res)
	chal, err := digest.ParseChallenge(v)
	return err == nil && chal.Realm == realm
}

// parseDigestChallenge splits a Digest challenge into its auth-params, in
// order, as [name, value] pairs (quoted-string values unquoted and
// unescaped). ok is false for anything that is not a well-formed Digest
// challenge.
func parseDigestChallenge(v string) (params [][2]string, ok bool) {
	v = strings.TrimSpace(v)
	scheme, rest, _ := strings.Cut(v, " ")
	if !strings.EqualFold(scheme, "Digest") {
		return nil, false
	}
	i := 0
	skip := func(set string) {
		for i < len(rest) && strings.IndexByte(set, rest[i]) >= 0 {
			i++
		}
	}
	for {
		skip(" \t,")
		if i >= len(rest) {
			return params, true
		}
		start := i
		for i < len(rest) && isTokenChar(rest[i]) {
			i++
		}
		name := rest[start:i]
		skip(" \t")
		if name == "" || i >= len(rest) || rest[i] != '=' {
			return nil, false
		}
		i++
		skip(" \t")
		var value strings.Builder
		if i < len(rest) && rest[i] == '"' {
			i++
			closed := false
			for i < len(rest) {
				c := rest[i]
				i++
				if c == '\\' && i < len(rest) {
					value.WriteByte(rest[i])
					i++
					continue
				}
				if c == '"' {
					closed = true
					break
				}
				value.WriteByte(c)
			}
			if !closed {
				return nil, false
			}
		} else {
			start := i
			for i < len(rest) && isTokenChar(rest[i]) {
				i++
			}
			if start == i {
				return nil, false
			}
			value.WriteString(rest[start:i])
		}
		params = append(params, [2]string{name, value.String()})
		skip(" \t")
		if i < len(rest) && rest[i] != ',' {
			return nil, false
		}
	}
}

// isTokenChar reports whether c may appear in an RFC 3261 §25.1 token.
func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		strings.IndexByte("-.!%*_+`'~", c) >= 0
}

// requires100rel reports whether any Require header lists the 100rel option
// tag (reliable provisional responses, which we do not support).
func requires100rel(req *sip.Request) bool {
	return hasOptionTag(req, "Require", "100rel")
}

// negotiateSE picks the session interval to advertise: the smaller of the
// peer's requested value (when present) and our configured sessionExpires,
// floored at the larger of our minSE and the peer's own declared peerMinSE.
// RFC 4028 §9 — as the UAS we MUST NOT set the interval below the peer's
// Min-SE; a value above our sessionExpires just means less-frequent
// refreshes, which is safe (the endpoints refresh, not us). peerMinSE 0
// means the peer declared no Min-SE.
func negotiateSE(peerSE, peerMinSE, sessionExpires, minSE time.Duration) time.Duration {
	se := sessionExpires
	if peerSE > 0 && peerSE < se {
		se = peerSE
	}
	floor := minSE
	if peerMinSE > floor {
		floor = peerMinSE
	}
	if se < floor {
		se = floor
	}
	return se
}

// sessionExpiresHeader builds a Session-Expires header with a refresher param.
func sessionExpiresHeader(d time.Duration, refresher string) sip.Header {
	return sip.NewHeader("Session-Expires", strconv.Itoa(int(d.Seconds()))+";refresher="+refresher)
}

// isRefreshReInvite reports whether an in-dialog INVITE is a session-timer
// refresh: it carries a Session-Expires and its offered SDP matches the
// established one modulo the o= line (a media-changing re-INVITE differs
// even with the o= line ignored, and is handled separately). Callers ensure
// req is in-dialog (has a To-tag) before asking.
func isRefreshReInvite(req *sip.Request, establishedSDP []byte) bool {
	if headerSeconds(req, "Session-Expires") == 0 {
		return false
	}
	return sdpEqualIgnoringOrigin(req.Body(), establishedSDP)
}

// sdpEqualIgnoringOrigin reports whether a and b are identical SDP once
// their o= (origin) lines are stripped out. RFC 3264 §8 has a real UAC bump
// the o= line's version number on every re-offer, including a session-timer
// refresh that re-sends otherwise-identical SDP — comparing raw bytes would
// then wrongly treat a legitimate refresh as a media change (and 501 it,
// killing the ability to refresh the session). Any other line differing
// (c=, m=, ...) still fails the comparison, so a genuine media change is
// still correctly detected.
func sdpEqualIgnoringOrigin(a, b []byte) bool {
	return stripOriginLine(a) == stripOriginLine(b)
}

// stripOriginLine returns sdp with its o= line (if any) removed, lines
// rejoined with "\n" (the join separator only has to be consistent between
// the two sides of a later equality comparison, not match SDP's own CRLF
// convention). SDP uses CRLF line endings (RFC 4566 §5), but a bare "\n" is
// tolerated too since callers here compare our own generated SDP against a
// peer's, and strict CRLF-only splitting would silently fail to strip a
// peer's o= line on any input using bare LF.
func stripOriginLine(sdp []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(sdp), "\r\n", "\n"), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(line, "o=") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// refresherParam returns the refresher parameter of m's Session-Expires
// header ("uac" or "uas", lower-cased), or "" when the header or the
// parameter is absent.
func refresherParam(m sip.Message) string {
	headers := headersNamed(m, "Session-Expires")
	if len(headers) == 0 {
		return ""
	}
	for _, p := range strings.Split(headers[0].Value(), ";")[1:] {
		name, value, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), "refresher") {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

// refresherOf returns the refresher parameter carried on req's own
// Session-Expires header, defaulting to "uac" if the header is absent or
// carries no refresher param. A refresh re-INVITE answered locally can
// arrive from either leg, and whichever endpoint sent it is the refresher
// it names; echoing the request's own value is correct for both without
// inspecting which dialog matched.
func refresherOf(req *sip.Request) string {
	if r := refresherParam(req); r != "" {
		return r
	}
	return "uac"
}
