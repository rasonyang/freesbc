package sig

import (
	"testing"

	"github.com/freesbc/freesbc/config"
)

// routingCfg parses a config used across the routing tests: an outbound
// route (9-prefixed numbers, internal-pbx → carrier-a,carrier-b), an
// international route, and a catch-all inbound route (carrier-a →
// internal-pbx, no match clause).
func routingCfg(t *testing.T) *config.Config {
	t.Helper()
	const src = `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    auth: { username: u, password: p }
    allowed_ips: [203.0.113.0/24]
  carrier-b:
    address: sip.carrier-b.com:5060
    auth: { username: u2, password: p2 }
    allowed_ips: [198.51.100.0/24]
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a, carrier-b]
  - name: intl
    from: internal-pbx
    match: { to: "^00(\\d+)$" }
    transform: { to: "+${1}" }
    to: [carrier-b]
  - name: inbound
    from: carrier-a
    to: [internal-pbx]
`
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cfg
}

func TestMatchRouteFirstHitWins(t *testing.T) {
	cfg := routingCfg(t)
	r, ok := matchRoute(cfg, "internal-pbx", "9123")
	if !ok || r.Name != "outbound" {
		t.Fatalf("9123 from internal-pbx → %v, ok=%v (want outbound)", r, ok)
	}
	r, ok = matchRoute(cfg, "internal-pbx", "00441234")
	if !ok || r.Name != "intl" {
		t.Fatalf("00441234 → %v, ok=%v (want intl)", r, ok)
	}
}

func TestMatchRouteNoMatchClauseMatchesAny(t *testing.T) {
	cfg := routingCfg(t)
	// inbound route has no match clause → matches any number.
	r, ok := matchRoute(cfg, "carrier-a", "anything-at-all")
	if !ok || r.Name != "inbound" {
		t.Fatalf("→ %v, ok=%v (want inbound)", r, ok)
	}
}

func TestMatchRouteFiltersByFromPeer(t *testing.T) {
	cfg := routingCfg(t)
	// "9123" only matches the outbound route, whose from is internal-pbx;
	// the same number from carrier-a must fall through to the inbound
	// route (no match clause), not the outbound one.
	r, ok := matchRoute(cfg, "carrier-a", "9123")
	if !ok || r.Name != "inbound" {
		t.Fatalf("9123 from carrier-a → %v, ok=%v (want inbound)", r, ok)
	}
}

func TestMatchRouteNoMatch(t *testing.T) {
	cfg := routingCfg(t)
	// carrier-b is not the `from` of any route.
	if r, ok := matchRoute(cfg, "carrier-b", "9123"); ok {
		t.Fatalf("carrier-b has no route, got %v", r)
	}
	// A number that matches no outbound pattern from internal-pbx (no
	// catch-all for internal-pbx) must not match.
	if r, ok := matchRoute(cfg, "internal-pbx", "555"); ok {
		t.Fatalf("555 from internal-pbx matches no route, got %v", r)
	}
}
