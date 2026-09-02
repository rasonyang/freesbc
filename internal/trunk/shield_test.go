package trunk

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/shield"
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
// requests from one source and asserts both halves of the T-01 boundary:
// the client hears nothing, and the shield is never fed — pre-parse
// filtering drops the bytes before dropUnidentified/RecordUnidentified
// could run, so no auto-ban exists for this source (Check returns Allow,
// all drop counters zero). Before T-01 this test asserted the opposite —
// that the Nth unidentified failure within the window auto-banned the
// source via dropUnidentified's RecordUnidentified wiring. That path is
// now unreachable over the wire (non-peer bytes never become requests),
// and the shield-side auto-ban logic is covered by the shield package's
// own TestRecordUnidentifiedBansAtThreshold.
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
	if v := sh.Check(src, "", "udp"); v != shield.Allow {
		t.Fatalf("pre-parse drop must keep the shield clean: Check(%s) = %v, want Allow (no ban recorded)", src, v)
	}
	if stats := sh.Stats(); stats.BannedCurrent != 0 || stats.DropsByReason["banned"] != 0 || stats.DropsByReason["scanner"] != 0 || stats.DropsByReason["rate"] != 0 {
		t.Fatalf("shield saw non-peer traffic it should never have received: %+v", stats)
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

// TestShieldScannerInstantBan proves a scanner-UA request from an
// unidentified source is dropped at the T-01 pre-parse boundary: the
// client hears nothing and the shield never sees the scanner User-Agent,
// so no instant ban exists for this source (Check returns Allow, the
// scanner drop counter is zero). Before T-01 this test asserted the
// opposite — that one OPTIONS with User-Agent: friendly-scanner from an
// unidentified source instantly banned it. Non-peer bytes never reach the
// shield's scanner check anymore; that check itself is covered by the
// shield package's own TestCheckScannerInstantBan.
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
	if v := sh.Check(src, "", "udp"); v != shield.Allow {
		t.Fatalf("pre-parse drop must keep the shield clean: Check(%s) = %v, want Allow (no scanner ban)", src, v)
	}
	if drops := sh.Stats().DropsByReason["scanner"]; drops != 0 {
		t.Fatalf("shield scanner-ban counter = %d, want 0 (pre-parse drop keeps non-peer bytes away)", drops)
	}
}
