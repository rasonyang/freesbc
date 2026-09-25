package edge

import (
	"strings"

	"github.com/emiago/sipgo/sip"
)

// This file keeps what the two endpoints advertise to each other honest
// about what the proxy can carry (P2-EDG-010).
//
// FreeSBC proxies INVITE, ACK, CANCEL, BYE, INFO and REGISTER and answers
// OPTIONS itself; anything else — PRACK and UPDATE included — gets 405
// (onNoRoute). If a caller's "Supported: 100rel" reached the callee, the
// callee could send a reliable 18x (RFC 3262) whose PRACK would be refused
// here, and the callee would fail the call after 64·T1. If an "Allow:
// UPDATE" reached a session-timer refresher, it could refresh with UPDATE
// (RFC 4028 §9) and have the call torn down at expiry. So on every request
// FreeSBC forwards and every response it relays:
//
//   - Allow lists only the methods in allowedMethods;
//   - Supported loses 100rel.
//
// Supported: timer stays: with UPDATE gone from Allow, a refresher has to
// use re-INVITE (RFC 4028 §7.4, §8.1), which the proxy carries, so session
// timers keep working end to end. An INVITE that REQUIRES 100rel cannot be
// honoured through FreeSBC at all and is answered 420 (RFC 3261 §8.2.2.3,
// RFC 3262 §3), which a conforming UAC answers by retrying without it.
//
// PRACK and UPDATE are not proxied instead because both can carry SDP
// offers and answers inside an early or confirmed dialog, and FreeSBC
// builds every SDP body itself: proxying them would mean a second
// offer/answer engine next to the INVITE one, for an extension neither
// FreeSWITCH nor a browser needs to complete a call.

// ext100rel is the RFC 3262 option tag.
const ext100rel = "100rel"

// headerSet is the header access both *sip.Request and *sip.Response have.
type headerSet interface {
	Headers() []sip.Header
	GetHeaders(name string) []sip.Header
	RemoveHeader(name string) bool
	AppendHeader(h sip.Header)
}

// sanitizeExtensions applies the rules above to a message about to be
// forwarded or relayed.
func sanitizeExtensions(m headerSet) {
	filterTokenHeader(m, "Allow", []string{"allow"}, func(tok string) bool {
		for _, a := range allowedMethods {
			if strings.EqualFold(tok, a) {
				return true
			}
		}
		return false
	})
	filterTokenHeader(m, "Supported", []string{"supported", "k"}, func(tok string) bool {
		return !strings.EqualFold(tok, ext100rel)
	})
}

// requires reports whether any Require header of m lists tag.
func requires(m headerSet, tag string) bool {
	for _, h := range m.GetHeaders("Require") {
		for _, tok := range strings.Split(h.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(tok), tag) {
				return true
			}
		}
	}
	return false
}

// filterTokenHeader rewrites the comma-separated token headers of m whose
// name (in any case, or its compact form) is one of names, keeping only the
// tokens keep accepts. Nothing changes when every token is kept. Otherwise
// all of them are replaced by one header named canonical, or by none when
// no token is left.
func filterTokenHeader(m headerSet, canonical string, names []string, keep func(string) bool) {
	var found []sip.Header
	for _, h := range m.Headers() {
		for _, n := range names {
			if strings.EqualFold(h.Name(), n) {
				found = append(found, h)
				break
			}
		}
	}
	if len(found) == 0 {
		return
	}
	var kept []string
	dropped := false
	for _, h := range found {
		for _, tok := range strings.Split(h.Value(), ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if keep(tok) {
				kept = append(kept, tok)
			} else {
				dropped = true
			}
		}
	}
	if !dropped {
		return
	}
	for _, h := range found {
		m.RemoveHeader(h.Name())
	}
	if len(kept) > 0 {
		m.AppendHeader(sip.NewHeader(canonical, strings.Join(kept, ", ")))
	}
}

// rejectRequired100rel answers an INVITE that requires 100rel with 420 and
// reports whether it did.
func (s *Server) rejectRequired100rel(req *sip.Request, tx sip.ServerTransaction) bool {
	if !requires(req, ext100rel) {
		return false
	}
	res := sip.NewResponseFromRequest(req, 420, "Bad Extension", nil)
	res.AppendHeader(sip.NewHeader("Unsupported", ext100rel))
	s.respond(req, tx, res)
	return true
}
