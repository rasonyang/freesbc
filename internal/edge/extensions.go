package edge

import (
	"strings"

	"github.com/emiago/sipgo/sip"
)

// This file keeps what the two endpoints advertise to each other honest
// about what the proxy can carry (P2-EDG-010).
//
// FreeSBC proxies INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, NOTIFY and
// REGISTER and answers OPTIONS itself; anything else gets 405 (onNoRoute).
// So on every request FreeSBC forwards and every response it relays, Allow
// lists only the methods in allowedMethods.
//
// Reliable provisional responses (RFC 3262) and UPDATE (RFC 3311) are end
// to end: Supported, Require, RSeq and RAck pass unchanged, as do the
// CSeq, Call-ID and tags a PRACK or UPDATE is matched by, and FreeSBC never
// generates a reliable provisional itself (its own 100 Trying stays
// unreliable). A PRACK or UPDATE without a body is forwarded like any other
// in-dialog request (onPrackUpdate). An UPDATE that carries SDP has its
// body rebuilt like a re-INVITE's (update.go). A PRACK that carries SDP is
// not yet handled: it is refused rather than forwarded with the far end's
// addresses in it.

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
