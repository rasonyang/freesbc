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
	bl.ban(ip, time.Hour)
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
	bl.ban(ip, time.Minute)
	now = now.Add(2 * time.Minute)
	bl.prune()
	if len(bl.until) != 0 {
		t.Fatalf("prune should drop the expired entry, have %d", len(bl.until))
	}
}
