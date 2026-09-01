package shield

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/config"
)

func testShield(t *testing.T, yaml string) *Shield {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := New(config.NewStore(cfg), discard())
	t.Cleanup(func() { s.Close() })
	return s
}

// testShieldWithRecordingNFT builds a Shield exactly like New does, but
// replaces the nft backend's exec with a recorder — T-02's kernel-sync
// tests must observe whether an element add was actually enqueued, which
// the real backend (availability-gated, real exec) can't show.
func testShieldWithRecordingNFT(t *testing.T, yaml string) (*Shield, *recordedCmds) {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rec := &recordedCmds{}
	bl := newBanList()
	bl.nft = &nftBackend{
		log:     discard(),
		listens: cfg.Listen.SIP,
		run: func(ctx context.Context, args ...string) error {
			rec.add(strings.Join(args, " "))
			return nil
		},
	}
	bl.nft.start()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Shield{
		store:       config.NewStore(cfg),
		log:         discard(),
		limiter:     newRateLimiter(),
		peerLimiter: newRateLimiter(),
		bans:        bl,
		counter:     newFailCounter(),
		stop:        cancel,
		done:        make(chan struct{}),
	}
	go s.pruneLoop(ctx)
	t.Cleanup(func() { s.Close() })
	return s, rec
}

const shieldCfg = `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
shield:
  rate_limit: 2/s per_ip
  auto_ban: { failures: 3, window: 60s, duration: 1h }
  nftables: off
peers:
  trunk:
    address: 203.0.113.10:5060
    allowed_ips: [203.0.113.10/32]
routes:
  - name: r
    from: trunk
    to: [trunk]
`

func TestCheckConfiguredPeerExempt(t *testing.T) {
	s := testShield(t, shieldCfg)
	peer := netip.MustParseAddr("203.0.113.10")
	// A scanner UA from a configured peer is exempt from the scanner/ban
	// plane — the peer keeps its exemption semantics under the T-18 peer
	// rate limit, which is a separate, looser ceiling (default 200/s per_ip;
	// these 100 hits stay inside the burst).
	for i := 0; i < 100; i++ {
		if s.Check(peer, "friendly-scanner", "udp") != Allow {
			t.Fatalf("configured peer must be exempt from scanner/ban (iter %d)", i)
		}
	}
}

// TestShieldCheckAppliesPeerRateLimit is the T-18 (F-19) red test: a
// configured peer source is no longer rate-limit-free — past the (loose,
// separately configured) peer limit, its traffic Drops like anyone else's.
// Pre-fix, isConfiguredPeer returned Allow unconditionally, so a spoofed
// peer source had no rate ceiling at all.
func TestShieldCheckAppliesPeerRateLimit(t *testing.T) {
	s := testShield(t, strings.Replace(shieldCfg,
		"rate_limit: 2/s per_ip", "rate_limit: 2/s per_ip\n  peer_rate_limit: 3/s per_ip", 1))
	peer := netip.MustParseAddr("203.0.113.10")
	// Burst = rate = 3: three checks consume the bucket, the fourth must Drop.
	for i := 0; i < 3; i++ {
		if s.Check(peer, "", "udp") != Allow {
			t.Fatalf("peer check %d: want Allow inside the peer rate budget", i+1)
		}
	}
	if s.Check(peer, "", "udp") != Drop {
		t.Fatal("peer past its rate budget must Drop")
	}
	// The peer limit is independent of the non-peer limiter: a NON-peer
	// source's budget (2) is unaffected by the peer's exhaustion.
	other := netip.MustParseAddr("198.51.100.7")
	if s.Check(other, "", "udp") != Allow {
		t.Fatal("non-peer source must have its own untouched budget")
	}
}

func TestCheckScannerInstantBan(t *testing.T) {
	s := testShield(t, shieldCfg)
	bad := netip.MustParseAddr("198.51.100.5")
	if s.Check(bad, "sipvicious", "udp") != Drop {
		t.Fatal("scanner UA must be dropped")
	}
	// now banned: even a benign UA from that IP drops.
	if s.Check(bad, "Zoiper", "udp") != Drop {
		t.Fatal("scanner source must be banned after the first hit")
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
	s := testShield(t, shieldCfg) // rate 2/s, nftables off; from earlier tasks
	bad := netip.MustParseAddr("198.51.100.20")
	s.Check(bad, "sipvicious", "udp") // scanner drop (+ ban)
	s.Check(bad, "", "udp")           // now banned → banned drop
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

func TestRecordUnidentifiedBansAtThreshold(t *testing.T) {
	s := testShield(t, shieldCfg)
	bad := netip.MustParseAddr("198.51.100.7")
	// failures: 3 → the 3rd unidentified request bans the source.
	s.RecordUnidentified(bad)
	s.RecordUnidentified(bad)
	if s.Check(bad, "", "udp") != Allow {
		t.Fatal("under threshold: still allowed")
	}
	s.RecordUnidentified(bad) // 3rd
	if s.Check(bad, "", "udp") != Drop {
		t.Fatal("at threshold: banned → drop")
	}
}

// TestUDPScannerSinglePacketMemoryOnly is the T-02 (F-04) red test: the
// single-packet scanner verdict over UDP (a forgable source) bans in memory
// only — no kernel sync. The TCP positive control proves the same verdict
// over a connection-based transport still reaches nft.
func TestUDPScannerSinglePacketMemoryOnly(t *testing.T) {
	s, rec := testShieldWithRecordingNFT(t, shieldCfg) // rate 2/s per_ip
	bad := netip.MustParseAddr("198.51.100.40")
	if s.Check(bad, "sipvicious", "udp") != Drop {
		t.Fatal("scanner UA must be dropped")
	}
	if !s.bans.banned(bad) {
		t.Fatal("UDP scanner must still be banned in memory")
	}
	// Give the worker a beat to run any stray enqueue, then assert the
	// kernel never heard about it.
	time.Sleep(100 * time.Millisecond)
	if got := rec.count(); got != 0 {
		t.Fatalf("nft execs = %d, want 0 (UDP single-packet scanner ban is memory-only)", got)
	}

	// Positive control: the same verdict over TCP does sync to the kernel.
	badTCP := netip.MustParseAddr("198.51.100.41")
	if s.Check(badTCP, "sipvicious", "tcp") != Drop {
		t.Fatal("TCP scanner must be dropped")
	}
	waitForRecords(t, rec, 1)
}
