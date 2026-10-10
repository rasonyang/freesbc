package shield

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// banCap is the hard ceiling on distinct banned sources: a
// unique-source flood within one shield.ban window (default 1h) must
// not grow the table without bound. 64k entries is far beyond any realistic
// deployment's distinct-source count while bounding memory to ~a few MiB.
const banCap = 65536

// sweepEvery bounds how often a full expired-entry sweep runs at the cap:
// without it, every refused unique source would pay an O(cap) scan, letting
// a sustained flood of fresh source IPs burn a core sweeping an
// already-fresh table. Refusals between sweeps are O(1); the background
// pruneLoop keeps clearing expired entries regardless.
const sweepEvery = time.Second

// Ban reasons recorded at insert. A scanner User-Agent verdict is the only
// path that bans today; rate limiting and enumeration only drop.
const (
	BanReasonScanner = "scanner"
)

// Ban kinds: which of the two tables an entry lives in.
const (
	BanKindIP        = "ip"
	BanKindUDPSocket = "udp_socket"
)

// banEntry is one ban: when it expires, when it was first recorded and why.
type banEntry struct {
	until  time.Time
	since  time.Time
	reason string
}

// banList is an in-memory ban table: a source key mapped to the instant
// its ban expires (plus when and why it started), with lazy expiry on read.
// The Shield keeps two: source IPs (a verdict on a connection-oriented
// transport) and UDP source sockets (see Shield.CheckFrom). Separate tables
// mean a forged-datagram flood that fills the socket table can never keep a
// real scanner's IP out of the IP table.
type banList[K comparable] struct {
	mu    sync.Mutex
	until map[K]banEntry
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
	return &banList[K]{until: make(map[K]banEntry), now: time.Now}
}

// ban blocks key for dur. An existing ban is extended, never shortened: the
// expiry becomes the later of the two (P2-SHD-008). It reports whether
// the ban was recorded: when the table is at banCap and key is not already
// banned, expired entries are swept lazily first, and if the table is still
// full the addition is refused (the overflow counter increments).
func (b *banList[K]) ban(key K, dur time.Duration, reason string) bool {
	b.mu.Lock()
	old, tracked := b.until[key]
	if !tracked && len(b.until) >= banCap {
		if b.now().Sub(b.lastSweep) >= sweepEvery {
			now := b.now()
			for k, e := range b.until {
				if !now.Before(e.until) {
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
	now := b.now()
	if !tracked {
		b.until[key] = banEntry{until: now.Add(dur), since: now, reason: reason}
	} else if until := now.Add(dur); until.After(old.until) {
		// An extension keeps the original start time and reason.
		old.until = until
		b.until[key] = old
	}
	b.mu.Unlock()
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
	e, ok := b.until[key]
	if !ok {
		return false
	}
	if !b.now().Before(e.until) { // now >= expiry
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
	for key, e := range b.until {
		if !now.Before(e.until) {
			delete(b.until, key)
		}
	}
}

// listed is one live ban copied out of the table.
type listed[K comparable] struct {
	key K
	banEntry
}

// live copies the unexpired entries out under the lock, without deleting
// any. The caller sorts and slices outside it.
func (b *banList[K]) live() []listed[K] {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	out := make([]listed[K], 0, len(b.until))
	for k, e := range b.until {
		if now.Before(e.until) {
			out = append(out, listed[K]{k, e})
		}
	}
	return out
}

// sortBans orders newest first, then by source string, so a page boundary
// is stable between calls.
func sortBans(in []BanInfo) {
	sort.Slice(in, func(i, j int) bool {
		if !in[i].Since.Equal(in[j].Since) {
			return in[i].Since.After(in[j].Since)
		}
		if in[i].Source != in[j].Source {
			return in[i].Source < in[j].Source
		}
		return in[i].Kind < in[j].Kind
	})
}
