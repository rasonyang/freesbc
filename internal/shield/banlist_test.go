package shield

import (
	"net/netip"
	"testing"
	"time"
)

func TestBanListBanAndExpiry(t *testing.T) {
	bl := newBanList()
	now := time.Unix(1000, 0)
	bl.now = func() time.Time { return now }
	ip := netip.MustParseAddr("198.51.100.9")

	if bl.banned(ip) {
		t.Fatal("fresh ip not banned")
	}
	bl.ban(ip, time.Hour, true)
	if !bl.banned(ip) {
		t.Fatal("banned within the window")
	}
	now = now.Add(59 * time.Minute)
	if !bl.banned(ip) {
		t.Fatal("still banned at 59m")
	}
	now = now.Add(2 * time.Minute) // 61m > 1h
	if bl.banned(ip) {
		t.Fatal("ban expired at 61m")
	}
}

func TestBanListPruneDropsExpired(t *testing.T) {
	bl := newBanList()
	now := time.Unix(1000, 0)
	bl.now = func() time.Time { return now }
	ip := netip.MustParseAddr("198.51.100.9")
	bl.ban(ip, time.Minute, true)
	now = now.Add(2 * time.Minute)
	bl.prune()
	if len(bl.until) != 0 {
		t.Fatalf("prune should drop the expired entry, have %d", len(bl.until))
	}
}

// capIP returns a unique IPv4 address for index i (i < 2^24), so the cap
// test can flood the ban table with distinct sources without hand-rolling
// thousands of literals.
func capIP(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i)})
}

// TestBanListCap is the T-03 (F-05) red test: a unique-source flood must
// not grow the ban table past its hard cap — at the cap, bans are refused
// (after a lazy sweep of expired entries) and each refusal is counted.
func TestBanListCap(t *testing.T) {
	bl := newBanList()
	now := time.Unix(1000, 0)
	bl.now = func() time.Time { return now }

	for i := 0; i < banCap; i++ {
		if !bl.ban(capIP(i), time.Hour, true) {
			t.Fatalf("ban %d below the cap was refused", i)
		}
	}
	if len(bl.until) != banCap {
		t.Fatalf("table size after filling = %d, want cap %d", len(bl.until), banCap)
	}

	// One more unique source: refused, counted, and the table does not grow.
	if bl.ban(capIP(banCap), time.Hour, true) {
		t.Fatal("ban at the hard cap must be refused")
	}
	if got := bl.overflowed(); got == 0 {
		t.Fatal("refused ban was not counted in the overflow counter")
	}
	if len(bl.until) != banCap {
		t.Fatalf("refused ban grew the table: %d > cap %d", len(bl.until), banCap)
	}

	// Re-banning an already-tracked source is an extension, not a new entry:
	// it must still succeed at the cap.
	if !bl.ban(capIP(0), time.Hour, true) {
		t.Fatal("extending an existing ban at the cap must not be refused")
	}

	// Once every entry expires, the lazy sweep frees room: the previously
	// refused source is now accepted, and the table holds only it.
	now = now.Add(2 * time.Hour)
	if !bl.ban(capIP(banCap), time.Hour, true) {
		t.Fatal("ban after expiry sweep must succeed")
	}
	if len(bl.until) != 1 {
		t.Fatalf("sweep left stale entries: table size = %d, want 1", len(bl.until))
	}
}
