package shield

import (
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// Audit tests (docs/audit/REPORT.md). A failing test here is the
// deliverable: it demonstrates a defect. Do not make it pass by editing the
// test; fix the production code instead.

func auditEdgeShield(t *testing.T) *Shield {
	t.Helper()
	cfg, err := config.Parse([]byte(shieldCfg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := NewNoKernel(config.NewStore(cfg), discard())
	t.Cleanup(func() { s.Close() })
	return s
}

// audit: P2-SHD-001
// docs/design.md §14.1: a forgeable datagram must not blackhole a third
// party. The edge plane (NewNoKernel) enforces the in-memory ban on every
// later request, so one spoofed UDP scanner datagram locks the victim out.
func TestAuditUDPScannerVerdictDoesNotBanVictim(t *testing.T) {
	s := auditEdgeShield(t)
	victim := netip.MustParseAddr("198.51.100.20")
	if v := s.Check(victim, "friendly-scanner", "udp"); v != Drop {
		t.Fatalf("scanner UA not dropped: %v", v)
	}
	if v := s.Check(victim, "Yealink SIP-T46S", "udp"); v != Allow {
		t.Errorf("one forged UDP scanner datagram banned %s from the edge plane (verdict %v)", victim, v)
	}
}

// audit: P2-SHD-001
// banCap forged UDP sources fill the ban table; afterwards a real scanner
// (arriving over TCP, where the verdict is trustworthy) cannot be banned.
func TestAuditForgedUDPFloodFillsBanTable(t *testing.T) {
	if testing.Short() {
		t.Skip("fills a 64k table")
	}
	s := auditEdgeShield(t)
	base := netip.MustParseAddr("2001:db8::").As16()
	for i := 0; i < banCap; i++ {
		a := base
		a[12], a[13], a[14], a[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		s.Check(netip.AddrFrom16(a), "friendly-scanner", "udp")
	}
	real := netip.MustParseAddr("192.0.2.66")
	s.Check(real, "sipvicious", "tcp")
	if !s.bans.banned(real) {
		t.Errorf("after %d forged UDP scanner datagrams a real TCP scanner could not be banned (overflow=%d)",
			banCap, s.Stats().BanAddsRejected)
	}
}

// audit: P2-SHD-002
// The per-IP bucket map must be bounded like the ban table (banlist.go:10-13).
// One IPv6 /64 supplies unlimited legitimate distinct sources.
func TestAuditRateLimiterBucketMapBounded(t *testing.T) {
	s := auditEdgeShield(t)
	const n = 200_000
	base := netip.MustParseAddr("2001:db8:1:2::").As16()
	for i := 0; i < n; i++ {
		a := base
		a[12], a[13], a[14], a[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		s.Check(netip.AddrFrom16(a), "Yealink", "udp")
	}
	s.limiter.mu.Lock()
	got := len(s.limiter.buckets)
	s.limiter.mu.Unlock()
	if got > banCap {
		t.Errorf("rate-limit bucket map holds %d entries after %d distinct sources (bound %d)", got, n, banCap)
	}
}

// audit: P2-SHD-003
// With a 10/h limit, a drained bucket refills 10 tokens per hour. prune
// deletes it after one idle minute and the next request gets a fresh, full
// bucket.
func TestAuditPruneDoesNotResetHourlyBucket(t *testing.T) {
	r := newRateLimiter()
	clock := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return clock }
	src := netip.MustParseAddr("198.51.100.30")
	for i := 0; i < 10; i++ {
		if !r.allow(src, 10, time.Hour, true) {
			t.Fatalf("token %d refused", i)
		}
	}
	if r.allow(src, 10, time.Hour, true) {
		t.Fatal("11th request allowed before the prune")
	}
	clock = clock.Add(61 * time.Second)
	r.prune()
	allowed := 0
	for i := 0; i < 10; i++ {
		if r.allow(src, 10, time.Hour, true) {
			allowed++
		}
	}
	if allowed > 1 {
		t.Errorf("after 61 s idle and a prune, %d of 10 requests allowed; a 10/h bucket refills ~0.17 tokens", allowed)
	}
}

// audit: P2-SHD-008
// banlist.go:47 and docs/design.md say a re-ban extends an existing ban. A
// shorter re-ban must not shorten it.
func TestAuditReBanDoesNotShorten(t *testing.T) {
	b := newBanList()
	clock := time.Unix(1_700_000_000, 0)
	b.now = func() time.Time { return clock }
	ip := netip.MustParseAddr("198.51.100.40")
	b.ban(ip, time.Hour)
	b.ban(ip, time.Minute)
	clock = clock.Add(2 * time.Minute)
	if !b.banned(ip) {
		t.Errorf("a 1 h ban was cut to 1 min by a later shorter ban")
	}
}

// audit: resource balance (shield)
// Close must stop the prune goroutine.
func TestAuditShieldCloseReleasesGoroutines(t *testing.T) {
	cfg, err := config.Parse([]byte(shieldCfg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	runtime.GC()
	base := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		s := NewNoKernel(config.NewStore(cfg), discard())
		s.Check(netip.MustParseAddr("198.51.100.50"), "x", "udp")
		s.Close()
	}
	var now int
	for try := 0; try < 50; try++ {
		if now = runtime.NumGoroutine(); now <= base {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("goroutines %d after 20 New/Close cycles, baseline %d", now, base)
}
