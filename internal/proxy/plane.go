package proxy

import (
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

// privateSources remembers which transport addresses have been seen
// arriving on the PRIVATE listener.
//
// It exists because sipgo does not record which local socket an inbound
// message arrived on — only its source. Deciding a request's plane from
// the source IP alone is wrong whenever the public and private planes
// share an address, which is exactly the all-on-one-host case (a lab, a
// single-VM deployment, every test in this package): FreeSWITCH and a
// phone would then be indistinguishable, and a phone's REGISTER would be
// treated as coming from the switch.
//
// The read filter DOES see the local address, so it records the exact
// source address:port of everything the private listener accepts — and it
// only accepts the configured upstream IP. Handlers then ask this table,
// which is precise (address AND port) rather than a guess.
//
// Bounded and self-pruning: entries can only ever be addresses the filter
// already accepted as upstream, and each is refreshed on use, so the table
// holds one entry per source port FreeSWITCH happens to use.
type privateSources struct {
	mu  sync.RWMutex
	m   map[string]time.Time
	ttl time.Duration
	max int
}

func newPrivateSources() *privateSources {
	return &privateSources{
		m: map[string]time.Time{},
		// Long enough to span a quiet period between calls, short enough
		// that a stale entry cannot outlive a FreeSWITCH restart by much.
		ttl: 10 * time.Minute,
		max: 256,
	}
}

// note records that addr sent us something on the private listener.
func (p *privateSources) note(addr string) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.m[addr]; !exists && len(p.m) >= p.max {
		p.pruneLocked(now)
		if len(p.m) >= p.max {
			// Still full of live entries: refuse rather than grow. The
			// upstream does not legitimately use hundreds of source
			// ports, so this is a symptom, not a capacity limit to raise.
			return
		}
	}
	p.m[addr] = now
}

// has reports whether addr is a live private-plane source.
func (p *privateSources) has(addr string) bool {
	p.mu.RLock()
	seen, ok := p.m[addr]
	p.mu.RUnlock()
	return ok && time.Since(seen) < p.ttl
}

func (p *privateSources) pruneLocked(now time.Time) {
	for k, v := range p.m {
		if now.Sub(v) >= p.ttl {
			delete(p.m, k)
		}
	}
}

// arrivedOnPrivate reports whether a request came from FreeSWITCH — that
// is, whether it arrived on the private listener from the configured
// upstream address. This is the direction switch every handler uses.
//
// Both halves matter. The source-address table is what makes it precise
// when the two planes share an IP; the topology check is what makes it
// safe if the table were ever poisoned, since only the configured upstream
// IP can be in it in the first place.
func (s *Server) arrivedOnPrivate(req *sip.Request) bool {
	if sip.NetworkToLower(req.Transport()) != "udp" {
		return false // the private plane is UDP only
	}
	src, ok := sourceAddrPort(req)
	if !ok || !s.topo.fromUpstream(src.Addr()) {
		return false
	}
	return s.privSources.has(req.Source())
}
