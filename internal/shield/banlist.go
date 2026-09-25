package shield

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// banCap is the hard ceiling on distinct banned sources: a
// unique-source flood within one auto_ban.duration window (default 1h) must
// not grow the table without bound. 64k entries is far beyond any realistic
// deployment's distinct-source count while bounding memory to ~a few MiB.
const banCap = 65536

// sweepEvery bounds how often a full expired-entry sweep runs at the cap:
// without it, every refused unique source would pay an O(cap) scan, letting
// a sustained flood of fresh source IPs burn a core sweeping an
// already-fresh table. Refusals between sweeps are O(1); the background
// pruneLoop keeps clearing expired entries regardless.
const sweepEvery = time.Second

// banList is the in-memory ban table: a source IP mapped to the instant its
// ban expires, with lazy expiry on read.
type banList struct {
	mu    sync.Mutex
	until map[netip.Addr]time.Time
	now   func() time.Time

	// lastSweep is the (b.now-based) instant of the most recent full sweep
	// at the cap; zero value means "never", so the first refusal always
	// sweeps.
	lastSweep time.Time

	// overflow counts ban additions refused at the hard cap (cumulative,
	// exposed via Shield.Stats).
	overflow atomic.Int64
}

func newBanList() *banList {
	return &banList{until: make(map[netip.Addr]time.Time), now: time.Now}
}

// ban blocks ip for dur (extending any existing ban). It reports whether
// the ban was recorded: when the table is at banCap and ip is not already
// banned, expired entries are swept lazily first, and if the table is still
// full the addition is refused (the overflow counter increments).
func (b *banList) ban(ip netip.Addr, dur time.Duration) bool {
	b.mu.Lock()
	_, tracked := b.until[ip]
	if !tracked && len(b.until) >= banCap {
		if b.now().Sub(b.lastSweep) >= sweepEvery {
			now := b.now()
			for k, t := range b.until {
				if !now.Before(t) {
					delete(b.until, k)
				}
			}
			b.lastSweep = now
		}
		if len(b.until) >= banCap {
			b.mu.Unlock()
			b.overflow.Add(1)
			return false
		}
	}
	b.until[ip] = b.now().Add(dur)
	b.mu.Unlock()
	return true
}

// unban removes any ban on ip and reports whether one existed.
func (b *banList) unban(ip netip.Addr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.until[ip]; !ok {
		return false
	}
	delete(b.until, ip)
	return true
}

// overflowed returns the cumulative number of ban additions refused at the
// hard cap.
func (b *banList) overflowed() int64 { return b.overflow.Load() }

// banned reports whether ip is currently banned, deleting the entry once its
// ban has expired (lazy expiry).
func (b *banList) banned(ip netip.Addr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.until[ip]
	if !ok {
		return false
	}
	if !b.now().Before(t) { // now >= expiry
		delete(b.until, ip)
		return false
	}
	return true
}

// size returns the number of currently-tracked (possibly expired) ban entries.
func (b *banList) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.until)
}

// prune drops expired entries.
func (b *banList) prune() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for ip, t := range b.until {
		if !now.Before(t) {
			delete(b.until, ip)
		}
	}
}
