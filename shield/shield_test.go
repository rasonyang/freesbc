package shield

import (
	"net/netip"
	"testing"

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
	// Even a scanner UA from a configured peer is exempt (allow), and repeated
	// hits never throttle.
	for i := 0; i < 100; i++ {
		if s.Check(peer, "friendly-scanner") != Allow {
			t.Fatalf("configured peer must be exempt (iter %d)", i)
		}
	}
}

func TestCheckScannerInstantBan(t *testing.T) {
	s := testShield(t, shieldCfg)
	bad := netip.MustParseAddr("198.51.100.5")
	if s.Check(bad, "sipvicious") != Drop {
		t.Fatal("scanner UA must be dropped")
	}
	// now banned: even a benign UA from that IP drops.
	if s.Check(bad, "Zoiper") != Drop {
		t.Fatal("scanner source must be banned after the first hit")
	}
}

func TestCheckRateLimitDropsButDoesNotBan(t *testing.T) {
	s := testShield(t, shieldCfg)
	bad := netip.MustParseAddr("198.51.100.6")
	// rate 2/s: several rapid Checks in the same instant → first 2 allow, rest
	// drop (no refill between them). Crucially a rate drop is NOT a ban.
	var allowed, dropped int
	for i := 0; i < 6; i++ {
		if s.Check(bad, "") == Allow {
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

func TestRecordUnidentifiedBansAtThreshold(t *testing.T) {
	s := testShield(t, shieldCfg)
	bad := netip.MustParseAddr("198.51.100.7")
	// failures: 3 → the 3rd unidentified request bans the source.
	s.RecordUnidentified(bad)
	s.RecordUnidentified(bad)
	if s.Check(bad, "") != Allow {
		t.Fatal("under threshold: still allowed")
	}
	s.RecordUnidentified(bad) // 3rd
	if s.Check(bad, "") != Drop {
		t.Fatal("at threshold: banned → drop")
	}
}
