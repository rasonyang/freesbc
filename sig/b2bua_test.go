package sig

import (
	"strings"
	"testing"
	"time"
)

// A known peer (loopback) with a route to a target that is NOT this peer,
// so onInvite identifies + routes but (in Task 5) rejects because the B-leg
// isn't implemented yet. Task 6 replaces the expected code with a real bridge.
const bridgeNoRouteCfg = `
listen:
  sip: [udp://127.0.0.1:45070]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: nomatch
    from: local-uac
    match: { to: "^999$" }
    to: [local-uac]
`

func TestBridgeRejectsUnroutableInvite(t *testing.T) {
	// Dialed number 111 matches no route (only ^999$ exists) → 404.
	startServer(t, 45070, bridgeNoRouteCfg)
	got := roundTrip(t, 45070, "INVITE", "b2bua-noroute-1", 3*time.Second, "SIP/2.0 404")
	if !strings.Contains(got, "SIP/2.0 404") {
		t.Fatalf("unroutable INVITE must get 404, got:\n%s", got)
	}
}
