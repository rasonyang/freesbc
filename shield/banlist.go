package shield

import (
	"net/netip"
	"sync"
	"time"
)

// banList is the authoritative, always-on in-memory ban table: a source IP
// mapped to the instant its ban expires, with lazy expiry on read. Task 4
// adds an optional nftables backend field so bans are ALSO dropped at the
// kernel; the in-memory table alone is sufficient and cross-platform.
type banList struct {
	mu    sync.Mutex
	until map[netip.Addr]time.Time
	now   func() time.Time
	nft   *nftBackend // nil = in-process only
}

func newBanList() *banList {
	return &banList{until: make(map[netip.Addr]time.Time), now: time.Now}
}

// ban blocks ip for dur (extending any existing ban), then, if an nftables
// backend is attached, also installs a matching kernel drop.
func (b *banList) ban(ip netip.Addr, dur time.Duration) {
	b.mu.Lock()
	b.until[ip] = b.now().Add(dur)
	b.mu.Unlock()
	if b.nft != nil {
		b.nft.ban(ip, dur)
	}
}

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

// prune drops expired entries (the kernel handles nftables element timeouts
// on its own).
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
