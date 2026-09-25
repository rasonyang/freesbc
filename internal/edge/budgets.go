package edge

import "time"

// The failure budgets are hot: they are re-read from the store on every
// call or registration, so a reload changes them for the next one. The
// sections they live in are not: the upstream node set and the PSTN
// gateways are topology, built once from the startup snapshot. A reload
// that removes sip.pstn (or both upstream shapes) therefore leaves the
// running topology in place while the live snapshot's budgets fall to
// zero, which would cancel every attempt the instant it starts (audit
// P2-CFG-002). Defaults make a configured budget non-zero, so a zero live
// value means "section absent" and the budget the plane started with
// applies instead.

// upstreamPenalty is the cooldown for an upstream node that answered
// nothing: sip.upstreams.cooldown from the live snapshot, else the startup
// snapshot's.
func (s *Server) upstreamPenalty() time.Duration {
	if d := s.store.Current().SIP.Upstreams.Cooldown; d > 0 {
		return d.Std()
	}
	return s.boot.SIP.Upstreams.Cooldown.Std()
}

// pstnBudget is the per-gateway attempt budget and the cooldown of the PSTN
// trunk, from one live snapshot when it still configures them, else from
// the startup snapshot.
func (s *Server) pstnBudget() (attempt, cooldown time.Duration) {
	p := s.store.Current().SIP.Pstn
	if p.AttemptTimeout <= 0 || p.Cooldown <= 0 {
		p = s.boot.SIP.Pstn
	}
	return p.AttemptTimeout.Std(), p.Cooldown.Std()
}
