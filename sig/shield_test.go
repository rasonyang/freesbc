package sig

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/shield"
)

// unidentifiedShieldCfg is knownPeerCfg's shield-flavored twin: allowed_ips
// excludes loopback (10.0.0.0/8 instead of 127.0.0.1/32), so every request
// sent by these tests (all originate from 127.0.0.1) is an unidentified
// source as far as identify()/isConfiguredPeer are concerned — exactly the
// population the shield's auto-ban and scanner checks are meant to catch.
// auto_ban.failures is small (3) so the tests don't need many round trips.
const unidentifiedShieldCfg = `
listen:
  sip: [udp://127.0.0.1:%d]
shield:
  rate_limit: 100/s per_ip
  auto_ban: { failures: 3, window: 60s, duration: 1h }
  nftables: off
peers:
  remote:
    address: 203.0.113.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: remote
    to: [remote]
`

// configuredPeerShieldCfg is knownPeerCfg plus an explicit (tight) rate
// limit, so TestShieldConfiguredPeerNotThrottled proves exemption rather
// than merely a generous default limit never being hit.
const configuredPeerShieldCfg = `
listen:
  sip: [udp://127.0.0.1:%d]
shield:
  rate_limit: 2/s per_ip
  auto_ban: { failures: 3, window: 60s, duration: 1h }
  nftables: off
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: in
    from: local-uac
    to: [local-uac]
`

// TestShieldBansAfterFailures drives `failures` unidentified OPTIONS
// requests from one source through dropUnidentified (each silently
// dropped, exactly as before the shield existed), then asserts the source
// is now banned by calling srv.shield.Check directly. This proves the
// RecordUnidentified -> auto-ban wiring end-to-end: dropUnidentified feeds
// the shield's failure counter, and the Nth failure within the window
// bans the source (shield.Shield.RecordUnidentified, spec §3).
func TestShieldBansAfterFailures(t *testing.T) {
	const port = 45700
	srv := startServer(t, port, fmt.Sprintf(unidentifiedShieldCfg, port))

	for i := 0; i < 3; i++ {
		got := roundTrip(t, port, "OPTIONS", fmt.Sprintf("ban-%d", i), 1*time.Second, "")
		if strings.Contains(got, "SIP/2.0") {
			t.Fatalf("iter %d: unidentified source must be dropped, got a response:\n%s", i, got)
		}
	}

	sh := srv.shield.Load()
	if sh == nil {
		t.Fatal("srv.shield is nil after Run — construction wiring broken")
	}
	src := netip.MustParseAddr("127.0.0.1")
	if v := sh.Check(src, ""); v != shield.Drop {
		t.Fatalf("after 3 unidentified failures, Check(%s) = %v, want Drop (auto-ban)", src, v)
	}
}

// TestShieldConfiguredPeerNotThrottled proves configured peers are exempt
// from the shield's rate limiter (spec §3): configuredPeerShieldCfg sets a
// tight 2/s per_ip limit, yet a configured peer's rapid-fire OPTIONS all
// still get 200 — an unconfigured source under the same limit would start
// getting silently dropped well before this many requests.
func TestShieldConfiguredPeerNotThrottled(t *testing.T) {
	const port = 45701
	startServer(t, port, fmt.Sprintf(configuredPeerShieldCfg, port))

	const n = 10
	for i := 0; i < n; i++ {
		got := roundTrip(t, port, "OPTIONS", fmt.Sprintf("peer-%d", i), 2*time.Second, "SIP/2.0 200")
		if !strings.Contains(got, "SIP/2.0 200") {
			t.Fatalf("iter %d/%d: configured peer must not be throttled, expected 200, got:\n%s", i, n, got)
		}
	}
}

// TestShieldScannerInstantBan proves a single request bearing a known
// scanner User-Agent bans its source immediately (spec §3), without
// needing to cross the auto_ban.failures threshold: after one OPTIONS from
// an unidentified source with User-Agent: friendly-scanner, that source's
// next Check is Drop.
func TestShieldScannerInstantBan(t *testing.T) {
	const port = 45702
	srv := startServer(t, port, fmt.Sprintf(unidentifiedShieldCfg, port))

	got := roundTripWithHeaders(t, port, "OPTIONS", "scan-0", 1*time.Second, "",
		"User-Agent: friendly-scanner")
	if strings.Contains(got, "SIP/2.0") {
		t.Fatalf("scanner-UA request must be silently dropped, got a response:\n%s", got)
	}

	sh := srv.shield.Load()
	if sh == nil {
		t.Fatal("srv.shield is nil after Run — construction wiring broken")
	}
	src := netip.MustParseAddr("127.0.0.1")
	if v := sh.Check(src, ""); v != shield.Drop {
		t.Fatalf("after one scanner-UA request, Check(%s) = %v, want Drop (instant ban)", src, v)
	}
}
