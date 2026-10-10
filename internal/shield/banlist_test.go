package shield

import (
	"net/netip"
	"sync"
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
	bl.ban(ip, time.Hour, "test")
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
	bl.ban(ip, time.Minute, "test")
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
		if !bl.ban(capIP(i), time.Hour, "test") {
			t.Fatalf("ban %d below the cap was refused", i)
		}
	}
	if len(bl.until) != banCap {
		t.Fatalf("table size after filling = %d, want cap %d", len(bl.until), banCap)
	}

	// One more unique source: refused, counted, and the table does not grow.
	if bl.ban(capIP(banCap), time.Hour, "test") {
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
	if !bl.ban(capIP(0), time.Hour, "test") {
		t.Fatal("extending an existing ban at the cap must not be refused")
	}

	// Once every entry expires, the lazy sweep frees room: the previously
	// refused source is now accepted, and the table holds only it.
	now = now.Add(2 * time.Hour)
	if !bl.ban(capIP(banCap), time.Hour, "test") {
		t.Fatal("ban after expiry sweep must succeed")
	}
	if len(bl.until) != 1 {
		t.Fatalf("sweep left stale entries: table size = %d, want 1", len(bl.until))
	}
}

func TestShieldBansRecordReasonAndTime(t *testing.T) {
	s := testShield(t, shieldCfg)
	if page, total := s.Bans(10, 0); page == nil || len(page) != 0 || total != 0 {
		t.Fatalf("empty table: page=%v total=%d, want non-nil empty", page, total)
	}
	t0 := time.Unix(5000, 0)
	s.bans.now = func() time.Time { return t0 }
	s.socketBans.now = func() time.Time { return t0.Add(time.Second) }

	s.Check(netip.MustParseAddr("198.51.100.5"), "sipvicious", "tcp")
	s.CheckFrom(netip.MustParseAddrPort("198.51.100.6:5070"), "sipvicious", "udp")

	page, total := s.Bans(10, 0)
	if total != 2 || len(page) != 2 {
		t.Fatalf("bans = %v total %d, want 2", page, total)
	}
	// Newest first: the socket ban was recorded a second later.
	sock, ip := page[0], page[1]
	if sock.Kind != BanKindUDPSocket || sock.Source != "198.51.100.6:5070" || sock.Reason != BanReasonScanner {
		t.Errorf("socket ban = %+v", sock)
	}
	if ip.Kind != BanKindIP || ip.Source != "198.51.100.5" || ip.Reason != "scanner" {
		t.Errorf("ip ban = %+v", ip)
	}
	if !ip.Since.Equal(t0) || !ip.Until.Equal(t0.Add(time.Hour)) {
		t.Errorf("ip ban since/until = %v / %v", ip.Since, ip.Until)
	}
	if !sock.Until.Equal(sock.Since.Add(socketBanMax)) {
		t.Errorf("socket ban lasts %v, want %v", sock.Until.Sub(sock.Since), socketBanMax)
	}
}

func TestShieldBansPaginationAndExpiry(t *testing.T) {
	s := testShield(t, shieldCfg)
	now := time.Unix(9000, 0)
	s.bans.now = func() time.Time { return now }
	for i := 0; i < 25; i++ {
		now = time.Unix(9000, 0).Add(time.Duration(i) * time.Second)
		s.bans.ban(capIP(i), time.Hour, BanReasonScanner)
	}
	now = time.Unix(9000, 0).Add(30 * time.Second)
	s.bans.ban(capIP(100), time.Second, BanReasonScanner) // expires below

	now = now.Add(5 * time.Second)
	page, total := s.Bans(10, 0)
	if total != 25 || len(page) != 10 {
		t.Fatalf("page len %d total %d, want 10 of 25 (expired excluded)", len(page), total)
	}
	if page[0].Source != capIP(24).String() {
		t.Errorf("first = %s, want newest %s", page[0].Source, capIP(24))
	}
	p2, _ := s.Bans(10, 10)
	p3, _ := s.Bans(10, 20)
	if len(p2) != 10 || len(p3) != 5 || p2[0].Source == page[0].Source {
		t.Errorf("pages 2/3 = %d/%d", len(p2), len(p3))
	}
	seen := map[string]bool{}
	for _, b := range append(append(page, p2...), p3...) {
		if seen[b.Source] {
			t.Errorf("duplicate %s across pages", b.Source)
		}
		seen[b.Source] = true
	}
	if p, tot := s.Bans(10, 99); len(p) != 0 || p == nil || tot != 25 {
		t.Errorf("offset past end: %v %d", p, tot)
	}
	if p, _ := s.Bans(0, -3); len(p) != 1 {
		t.Errorf("limit 0 clamps to 1, got %d", len(p))
	}
	if p, _ := s.Bans(1_000_000, 0); len(p) > maxBanPage {
		t.Errorf("page %d exceeds maxBanPage", len(p))
	}
}

func TestShieldBansExtensionKeepsStart(t *testing.T) {
	bl := newBanList()
	now := time.Unix(100, 0)
	bl.now = func() time.Time { return now }
	ip := netip.MustParseAddr("198.51.100.40")
	bl.ban(ip, time.Minute, BanReasonScanner)
	now = now.Add(10 * time.Second)
	bl.ban(ip, time.Hour, "other")
	got := bl.live()
	if len(got) != 1 || !got[0].since.Equal(time.Unix(100, 0)) || got[0].reason != BanReasonScanner {
		t.Fatalf("extended ban = %+v", got)
	}
}

func TestShieldBansRaceWithAdds(t *testing.T) {
	s := testShield(t, shieldCfg)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				s.bans.ban(capIP(w*100000+i%5000), time.Hour, BanReasonScanner)
				s.socketBans.ban(netip.AddrPortFrom(capIP(i%5000), uint16(1000+w)), time.Minute, BanReasonScanner)
			}
		}(w)
	}
	for i := 0; i < 50; i++ {
		page, total := s.Bans(100, 0)
		if len(page) > 100 || len(page) > total {
			t.Fatalf("page %d total %d", len(page), total)
		}
	}
	close(stop)
	wg.Wait()
	if st := s.Stats(); st.BanAddsRejected < 0 {
		t.Fatal("stats")
	}
}
