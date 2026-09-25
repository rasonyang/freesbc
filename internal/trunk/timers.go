package trunk

import (
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
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

// challengeRealm extracts the realm from a 401/407 digest challenge
// response: WWW-Authenticate for 401, Proxy-Authenticate for
// 407. Returns "" when the header is absent or unparseable — callers
// compare it against a pinned realm, so "" simply never matches (fail
// closed). Both double- and single-quoted realms are accepted (some
// servers violate the quoted-string convention).
func challengeRealm(res *sip.Response) string {
	name := "WWW-Authenticate"
	if res.StatusCode == sip.StatusProxyAuthRequired {
		name = "Proxy-Authenticate"
	}
	headers := res.GetHeaders(name)
	if len(headers) == 0 {
		return ""
	}
	v := headers[0].Value()
	i := strings.Index(v, "realm=")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(v[i+len("realm="):])
	if rest == "" {
		return ""
	}
	if rest[0] == '"' || rest[0] == '\'' {
		if j := strings.IndexByte(rest[1:], rest[0]); j >= 0 {
			return rest[1 : 1+j]
		}
		return ""
	}
	if j := strings.IndexAny(rest, ", "); j >= 0 {
		rest = rest[:j]
	}
	return rest
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
