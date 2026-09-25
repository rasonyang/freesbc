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

// banList is an in-memory ban table: a source key mapped to the instant
// its ban expires, with lazy expiry on read. The Shield keeps two: source
// IPs (a verdict on a connection-oriented transport) and UDP source sockets
// (see Shield.CheckFrom). Separate tables mean a forged-datagram flood that
// fills the socket table can never keep a real scanner's IP out of the IP
// table.
type banList[K comparable] struct {
	mu    sync.Mutex
	until map[K]time.Time
	now   func() time.Time

	// lastSweep is the (b.now-based) instant of the most recent full sweep
	// at the cap; zero value means "never", so the first refusal always
	// sweeps.
	lastSweep time.Time

	// overflow counts ban additions refused at the hard cap (cumulative,
	// exposed via Shield.Stats).
	overflow atomic.Int64
}

func newBanList() *banList[netip.Addr] { return newBanTable[netip.Addr]() }

func newBanTable[K comparable]() *banList[K] {
	return &banList[K]{until: make(map[K]time.Time), now: time.Now}
}

// ban blocks key for dur. An existing ban is extended, never shortened: the
// expiry becomes the later of the two (P2-SHD-008). It reports whether
// the ban was recorded: when the table is at banCap and key is not already
// banned, expired entries are swept lazily first, and if the table is still
// full the addition is refused (the overflow counter increments).
func (b *banList[K]) ban(key K, dur time.Duration) bool {
	b.mu.Lock()
	_, tracked := b.until[key]
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
	if until := b.now().Add(dur); !tracked || until.After(b.until[key]) {
		b.until[key] = until
	}
	b.mu.Unlock()
	return true
}

// unban removes any ban on key and reports whether one existed.
func (b *banList[K]) unban(key K) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.until[key]; !ok {
		return false
	}
	delete(b.until, key)
	return true
}

// overflowed returns the cumulative number of ban additions refused at the
// hard cap.
func (b *banList[K]) overflowed() int64 { return b.overflow.Load() }

// banned reports whether key is currently banned, deleting the entry once its
// ban has expired (lazy expiry).
func (b *banList[K]) banned(key K) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.until[key]
	if !ok {
		return false
	}
	if !b.now().Before(t) { // now >= expiry
		delete(b.until, key)
		return false
	}
	return true
}

// size returns the number of currently-tracked (possibly expired) ban entries.
func (b *banList[K]) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.until)
}

// prune drops expired entries.
func (b *banList[K]) prune() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for key, t := range b.until {
		if !now.Before(t) {
			delete(b.until, key)
		}
	}
}

// unbanWhere removes every ban whose key matches and reports how many
// existed.
func (b *banList[K]) unbanWhere(match func(K) bool) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for key := range b.until {
		if match(key) {
			delete(b.until, key)
			n++
		}
	}
	return n
}
