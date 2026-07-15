package sig

import (
	"github.com/emiago/sipgo/sip"
)

// bridge is the B2BUA: it pairs an inbound A-leg with an outbound B-leg,
// anchoring media and hiding topology. One bridge instance is shared; each
// call runs in its own onInvite goroutine.
type bridge struct {
	s *Server
}

// onInvite handles an inbound INVITE end to end: identify the source, route
// it, and (Task 6+) place the B-leg and bridge media. Runs in sipgo's
// per-request goroutine.
func (b *bridge) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	name, _, ok := b.s.identify(req)
	if !ok {
		b.s.dropUnidentified(req)
		return
	}
	cfg := b.s.store.Current()
	decision, ok := Resolve(cfg, name, req.Recipient.User)
	if !ok || decision.OutNumber == "" {
		b.reject(req, tx, 404, "Not Found")
		return
	}
	// Task 6 replaces this with: ReadInvite, allocate media, failover loop.
	b.reject(req, tx, 404, "Not Found")
}

// reject answers an INVITE we will not bridge, before any dialog is created.
func (b *bridge) reject(req *sip.Request, tx sip.ServerTransaction, code int, reason string) {
	_ = tx.Respond(sip.NewResponseFromRequest(req, code, reason, nil))
	b.s.log.Info("rejected invite", "code", code, "reason", reason, "source", req.Source())
}
