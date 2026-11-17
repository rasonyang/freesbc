package edge

import (
	"net/netip"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// The call-path credential check (issue #288). A binding is recorded only
// after a 2xx to a REGISTER whose digest username equals the To user
// (bindingProof, registerproof.go), so a source admitted as a registration is
// an account holder. Without this check that account holder could guess other
// accounts' passwords on the call path: an INVITE, MESSAGE or SUBSCRIBE
// carrying another user's Authorization or Proxy-Authorization reaches the
// switch, which answers 401/403/407, and nothing counts the failures.
//
// So a registration source may present only a credential it has already
// proved by registering. For an out-of-dialog INVITE, MESSAGE or SUBSCRIBE
// admitted as a registration (a source that is also a carrier counts as the
// registration), every Authorization and Proxy-Authorization username must be
// the digest username of a live binding at that exact transport and source
// (Location.HasDigestUser, Binding.DigestUser). Otherwise, or when a username
// cannot be read, the edge answers 403 itself and forwards nothing. A request
// with no credential is untouched: the switch challenges it. A carrier-only
// source and in-dialog requests are not checked.
//
// It is a refusal, not a strike: the way to a binding for another account is
// a 2xx to a REGISTER with that account's credential, which register_ban_aor
// already bounds, so nobody is banned and a shared NAT pays nothing. It runs
// before admitEarly and beginDialog, so a refused INVITE takes no session
// slot, invite_rate_limit token or media port.

// credMethod is the method label of freesbc_edge_credential_mismatch_total.
type credMethod int

const (
	credInvite credMethod = iota
	credMessage
	credSubscribe
	numCredMethods
)

var credMethodLabels = [numCredMethods]string{
	credInvite:    "INVITE",
	credMessage:   "MESSAGE",
	credSubscribe: "SUBSCRIBE",
}

// credWarnEvery is the least time between two WARN lines about refused
// credentials; the other refusals are Debug.
const credWarnEvery = time.Minute

// credWarner rate-limits the one WARN a minute and counts what it summarises.
type credWarner struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

// allow reports whether a WARN may be logged now and how many refusals since
// the previous one it stands for (itself excluded).
func (w *credWarner) allow() (ok bool, since int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now := time.Now(); w.last.IsZero() || now.Sub(w.last) >= credWarnEvery {
		w.last, since, w.suppressed = now, w.suppressed, 0
		return true, since
	}
	w.suppressed++
	return false, 0
}

// credentialMismatch reports whether req, an out-of-dialog request admitted
// as a registration source, carries a credential that no live binding at its
// transport and source has proved; it counts and logs the refusal, and the
// caller answers 403.
func (s *Server) credentialMismatch(req *sip.Request, src netip.AddrPort) bool {
	transport := sip.NetworkToLower(req.Transport())
	bad, found := "", false
	for _, name := range [...]string{"Authorization", "Proxy-Authorization"} {
		for _, h := range req.GetHeaders(name) {
			user, _, _ := fsip.DigestIdentity(h.Value())
			if !s.loc.HasDigestUser(transport, src, user) {
				bad, found = user, true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return false
	}
	var m credMethod
	switch req.Method {
	case sip.MESSAGE:
		m = credMessage
	case sip.SUBSCRIBE:
		m = credSubscribe
	default:
		m = credInvite
	}
	s.metrics.CredentialMismatch(m)
	attrs := []any{"method", credMethodLabels[m], "transport", transport,
		"public_remote", src.String(), "auth_user", bad, "sip_call_id", fsip.CallID(req)}
	if ok, since := s.credWarn.allow(); ok {
		s.log.Warn("credential refused: no binding at this source proved it",
			append(attrs, "also_refused_since_last_warn", since)...)
		return true
	}
	s.log.Debug("credential refused: no binding at this source proved it", attrs...)
	return true
}
