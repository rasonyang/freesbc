package shield

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

func testShield(t *testing.T, yaml string) *Shield {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := New(config.NewStore(cfg), discard(), nil)
	t.Cleanup(func() { s.Close() })
	return s
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const shieldCfg = `
public: { ip: 203.0.113.7 }
private: { ip: 10.77.0.2 }
edge:
  switch: [10.77.0.10:5060]
  listen: { udp: 5060 }
shield:
  rate_limit: 2/s per_ip
  carrier_rate_limit: 5/s per_ip
  ban: 1h
`

func TestCheckScannerInstantBan(t *testing.T) {
	s := testShield(t, shieldCfg)
	bad := netip.MustParseAddr("198.51.100.5")
	if s.Check(bad, "sipvicious", "tcp") != Drop {
		t.Fatal("scanner UA must be dropped")
	}
	// now banned: even a benign UA from that IP drops.
	if s.Check(bad, "Zoiper", "tcp") != Drop {
		t.Fatal("scanner source must be banned after the first hit")
	}
}

// audit: P2-SHD-001
// A scanner verdict bans only on a connection-oriented transport. Over UDP,
// or with no transport known, the request is dropped and counted, but the
// forgeable source address is not banned.
func TestCheckScannerBanNeedsConnection(t *testing.T) {
	s := testShield(t, shieldCfg)
	for i, tc := range []struct {
		transport string
		ban       bool
	}{
		{"udp", false}, {"", false}, {"UDP", false},
		{"tcp", true}, {"tls", true}, {"ws", true}, {"wss", true}, {"WSS", true},
	} {
		src := netip.AddrFrom4([4]byte{198, 51, 100, byte(100 + i)})
		if s.Check(src, "friendly-scanner", tc.transport) != Drop {
			t.Fatalf("%q: scanner UA must be dropped", tc.transport)
		}
		if got := s.bans.banned(src); got != tc.ban {
			t.Errorf("%q: banned = %v, want %v", tc.transport, got, tc.ban)
		}
	}
	if got := s.Stats().DropsByReason["scanner"]; got != 8 {
		t.Errorf("scanner drops = %d, want 8 (UDP drops count too)", got)
	}
}

// TestScannerBanRespectsRateLimit is the T-04 (F-03) red test: a scanner UA
// is a client-controlled "ban me" signal, so it must not skip the rate
// limiter — with the source's budget exhausted, the scanner packet is a
// plain rate drop and creates NO ban.
func TestScannerBanRespectsRateLimit(t *testing.T) {
	s := testShield(t, shieldCfg) // rate 2/s per_ip, burst 2
	bad := netip.MustParseAddr("198.51.100.30")

	// Exhaust the budget with ordinary traffic: 3 rapid benign checks →
	// 2 allowed, the 3rd rate-dropped.
	s.Check(bad, "", "udp")
	s.Check(bad, "", "udp")
	s.Check(bad, "", "udp")

	// A scanner-UA packet on the exhausted source must hit the limiter
	// first (rate drop), never reach the scanner ban.
	if s.Check(bad, "sipvicious", "udp") != Drop {
		t.Fatal("rate-exhausted scanner source must still drop")
	}
	if s.bans.banned(bad) {
		t.Fatal("scanner UA from a rate-exhausted source must NOT create a ban (scanner check runs after the rate limiter)")
	}
	if got := s.Stats().DropsByReason["scanner"]; got != 0 {
		t.Fatalf("scanner drop counter = %d, want 0 (the drop was a rate drop)", got)
	}
}

func TestCheckRateLimitDropsButDoesNotBan(t *testing.T) {
	s := testShield(t, shieldCfg)
	bad := netip.MustParseAddr("198.51.100.6")
	// rate 2/s: several rapid Checks in the same instant → first 2 allow, rest
	// drop (no refill between them). Crucially a rate drop is NOT a ban.
	var allowed, dropped int
	for i := 0; i < 6; i++ {
		if s.Check(bad, "", "udp") == Allow {
			allowed++
		} else {
			dropped++
		}
	}
	if allowed < 1 || dropped < 1 {
		t.Fatalf("expected some allowed and some rate-dropped, got allowed=%d dropped=%d", allowed, dropped)
	}
	// The rate-limited source must NOT be banned (rate-exceed is not a ban
	// signal); the ban table has no entry for it.
	if s.bans.banned(bad) {
		t.Fatal("a rate-limited source must NOT be banned")
	}
}

func TestShieldStatsCountsDrops(t *testing.T) {
	s := testShield(t, shieldCfg) // rate 2/s
	bad := netip.MustParseAddr("198.51.100.20")
	s.Check(bad, "sipvicious", "tcp") // scanner drop (+ ban)
	s.Check(bad, "", "tcp")           // now banned → banned drop
	st := s.Stats()
	if st.DropsByReason["scanner"] < 1 {
		t.Errorf("scanner drops = %d, want >=1", st.DropsByReason["scanner"])
	}
	if st.DropsByReason["banned"] < 1 {
		t.Errorf("banned drops = %d, want >=1", st.DropsByReason["banned"])
	}
	if st.BannedCurrent < 1 {
		t.Errorf("banned current = %d, want >=1", st.BannedCurrent)
	}
}

// audit: P2-SHD-001
// With the source port known (CheckFrom, the edge plane's path), a UDP
// scanner verdict bans only that socket, and only briefly: another socket
// on the same IP is untouched, the IP table stays empty, and the ban lapses
// after socketBanMax.
func TestCheckFromUDPScannerBansSocketOnly(t *testing.T) {
	s := testShield(t, shieldCfg)
	clock := time.Unix(1_700_000_000, 0)
	s.socketBans.now = func() time.Time { return clock }
	s.limiter.now = func() time.Time { return clock }
	scan := netip.MustParseAddrPort("198.51.100.60:5060")
	other := netip.MustParseAddrPort("198.51.100.60:5062")
	if s.CheckFrom(scan, "friendly-scanner", "udp") != Drop {
		t.Fatal("scanner UA must be dropped")
	}
	if !s.BannedFrom(scan, "udp") {
		t.Fatal("the scanner's UDP socket must be banned")
	}
	if s.BannedFrom(scan, "tcp") || s.bans.banned(scan.Addr()) {
		t.Fatal("a UDP verdict must not ban the IP or its TCP side")
	}
	if s.CheckFrom(other, "Yealink", "udp") != Allow {
		t.Fatal("another socket on the same IP must not be banned")
	}
	clock = clock.Add(socketBanMax)
	if s.BannedFrom(scan, "udp") {
		t.Fatalf("a socket ban must lapse after %v", socketBanMax)
	}
}

// audit: P2-SHD-001
// A forged-datagram flood fills at most the socket table; a real scanner
// over TCP still gets its IP banned.
func TestSocketBanFloodLeavesIPTableFree(t *testing.T) {
	if testing.Short() {
		t.Skip("fills a 64k table")
	}
	s := testShield(t, shieldCfg)
	base := netip.MustParseAddr("2001:db8::").As16()
	for i := 0; i <= banCap; i++ {
		a := base // one source per /64, so the rate limiter admits each
		a[4], a[5], a[6], a[7] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		s.CheckFrom(netip.AddrPortFrom(netip.AddrFrom16(a), 5060), "friendly-scanner", "udp")
	}
	if s.socketBans.overflowed() == 0 {
		t.Fatal("the flood should have filled the socket table")
	}
	real := netip.MustParseAddrPort("192.0.2.66:40000")
	s.CheckFrom(real, "sipvicious", "tcp")
	if !s.bans.banned(real.Addr()) {
		t.Error("a real TCP scanner could not be banned after a UDP flood")
	}
}

// audit: P2-SHD-009
// Ban keys are unmapped, so a lookup by the 4in6 form of an IPv4 address
// finds that address's ban. (The admin unban this finding was about has
// since been removed.)
func TestBannedUnmaps4in6(t *testing.T) {
	s := testShield(t, shieldCfg)
	s.Check(netip.MustParseAddr("198.51.100.70"), "friendly-scanner", "tcp")
	mapped := netip.MustParseAddr("::ffff:198.51.100.70")
	if !s.Banned(mapped) || !s.BannedFrom(netip.AddrPortFrom(mapped, 5060), "tcp") {
		t.Error("the 4in6 form of a banned IPv4 address was not seen as banned")
	}
}

// Carrier sources are exempt from the scanner ban and use carrier_rate_limit.
func TestCarrierSourceExemptFromScannerBanAndUsesCarrierLimit(t *testing.T) {
	cfg, err := config.Parse([]byte(shieldCfg))
	if err != nil {
		t.Fatal(err)
	}
	carrier := netip.MustParseAddr("198.51.100.9")
	s := New(config.NewStore(cfg), discard(), func(a netip.Addr) bool { return a == carrier })
	t.Cleanup(func() { s.Close() })
	if s.Check(carrier, "friendly-scanner", "tcp") != Allow {
		t.Error("carrier source with a scanner UA must not be dropped or banned")
	}
	if s.BannedFrom(netip.AddrPortFrom(carrier, 0), "tcp") {
		t.Error("carrier source was banned")
	}
	allowed := 0
	for i := 0; i < 20; i++ {
		if s.Check(carrier, "x", "udp") == Allow {
			allowed++
		}
	}
	if allowed < 4 || allowed > 6 {
		t.Errorf("carrier burst = %d, want about 5 (carrier_rate_limit)", allowed)
	}
	other := netip.MustParseAddr("198.51.100.10")
	n := 0
	for i := 0; i < 20; i++ {
		if s.Check(other, "x", "udp") == Allow {
			n++
		}
	}
	if n < 1 || n > 3 {
		t.Errorf("non-carrier burst = %d, want about 2 (rate_limit)", n)
	}
}

// A parsable request costs one token end to end: AllowRate is the only
// charge, CheckScanner takes none, and CheckFrom is the two composed.
func TestAllowRateThenCheckScannerChargesOnce(t *testing.T) {
	s := testShield(t, shieldCfg) // rate_limit 2/s: a bucket of 2
	src := netip.MustParseAddrPort("198.51.100.9:5060")
	for i := 0; i < 2; i++ {
		if !s.AllowRate(src.Addr()) {
			t.Fatalf("token %d refused", i)
		}
		if s.CheckScanner(src, "Zoiper", "udp") != Allow {
			t.Fatalf("request %d: CheckScanner must not charge a token", i)
		}
	}
	if s.AllowRate(src.Addr()) {
		t.Fatal("third read allowed: the bucket should be empty after two charges")
	}
	if got := s.Stats().DropsByReason["rate"]; got != 1 {
		t.Fatalf("rate drops = %d, want 1", got)
	}
	other := netip.MustParseAddrPort("198.51.100.10:5060")
	if s.CheckFrom(other, "Zoiper", "udp") != Allow || s.CheckFrom(other, "Zoiper", "udp") != Allow ||
		s.CheckFrom(other, "Zoiper", "udp") != Drop {
		t.Fatal("CheckFrom must charge exactly one token per call")
	}
}
