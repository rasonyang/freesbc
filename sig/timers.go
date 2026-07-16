package sig

import (
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

// headerSeconds parses the leading delta-seconds value of a header (the
// number before any ';' parameters), e.g. "1800;refresher=uac" → 1800s.
// Returns 0 if the header is absent or unparseable.
func headerSeconds(m sip.Message, name string) time.Duration {
	headers := m.GetHeaders(name)
	if len(headers) == 0 {
		return 0
	}
	h := headers[0]
	v := h.Value()
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// requires100rel reports whether any Require header lists the 100rel option
// tag (reliable provisional responses, which we do not support).
func requires100rel(req *sip.Request) bool {
	for _, h := range req.GetHeaders("Require") {
		for _, tag := range strings.Split(h.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(tag), "100rel") {
				return true
			}
		}
	}
	return false
}

// negotiateSE picks the session interval to advertise: the smaller of the
// peer's requested value (when present) and our configured sessionExpires,
// never below minSE.
func negotiateSE(peerSE, sessionExpires, minSE time.Duration) time.Duration {
	se := sessionExpires
	if peerSE > 0 && peerSE < se {
		se = peerSE
	}
	if se < minSE {
		se = minSE
	}
	return se
}

// sessionExpiresHeader builds a Session-Expires header with a refresher param.
func sessionExpiresHeader(d time.Duration, refresher string) sip.Header {
	return sip.NewHeader("Session-Expires", strconv.Itoa(int(d.Seconds()))+";refresher="+refresher)
}

// isRefreshReInvite reports whether an in-dialog INVITE is a session-timer
// refresh: it carries a Session-Expires and its offered SDP is byte-identical
// to the established one (a media-changing re-INVITE differs and is handled
// separately). Callers ensure req is in-dialog (has a To-tag) before asking.
func isRefreshReInvite(req *sip.Request, establishedSDP []byte) bool {
	if headerSeconds(req, "Session-Expires") == 0 {
		return false
	}
	return string(req.Body()) == string(establishedSDP)
}

// refresherOf returns the refresher parameter carried on req's own
// Session-Expires header (e.g. "uac" from ";refresher=uac"), defaulting to
// "uac" if the header is absent or carries no refresher param. A
// session-timer refresh re-INVITE that we locally answer (see
// bridge.onInvite) only ever arrives from the A-leg (the caller) in this
// bridge — and the established call's own 200 OK always negotiated
// refresher=uac for that leg (see b2bua.go's aLeg.Respond) — so echoing the
// caller's own value back is always correct here without needing to
// inspect which dialog matched.
func refresherOf(req *sip.Request) string {
	headers := req.GetHeaders("Session-Expires")
	if len(headers) == 0 {
		return "uac"
	}
	v := headers[0].Value()
	i := strings.Index(v, "refresher=")
	if i < 0 {
		return "uac"
	}
	v = v[i+len("refresher="):]
	if j := strings.IndexByte(v, ';'); j >= 0 {
		v = v[:j]
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "uac"
	}
	return v
}
