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

func TestTransformNumberStripsPrefix(t *testing.T) {
	cfg := routingCfg(t)
	route, ok := matchRoute(cfg, "internal-pbx", "9123")
	if !ok {
		t.Fatal("setup: outbound route must match")
	}
	// transform "$1" over match "^9(\d+)$": strips the leading 9.
	if got := transformNumber(route, "9123"); got != "123" {
		t.Errorf("transformNumber = %q, want \"123\"", got)
	}
}

func TestTransformNumberBracedGroupWithLiteral(t *testing.T) {
	cfg := routingCfg(t)
	route, ok := matchRoute(cfg, "internal-pbx", "00441234")
	if !ok {
		t.Fatal("setup: intl route must match")
	}
	// transform "+${1}" over match "^00(\d+)$": ${1} = "441234", so the
	// braced group survives config parsing (Task 1) and expands correctly.
	if got := transformNumber(route, "00441234"); got != "+441234" {
		t.Errorf("transformNumber = %q, want \"+441234\"", got)
	}
}

func TestTransformNumberNoTransformIsPassthrough(t *testing.T) {
	cfg := routingCfg(t)
	route, ok := matchRoute(cfg, "carrier-a", "5551234")
	if !ok {
		t.Fatal("setup: inbound route must match")
	}
	// inbound route has no transform → number passes through unchanged.
	if got := transformNumber(route, "5551234"); got != "5551234" {
		t.Errorf("transformNumber = %q, want \"5551234\"", got)
	}
}

func TestResolveOutboundWithFailoverOrder(t *testing.T) {
	cfg := routingCfg(t)
	d, ok := Resolve(cfg, "internal-pbx", "9123")
	if !ok {
		t.Fatal("9123 must resolve")
	}
	if d.Route.Name != "outbound" {
		t.Errorf("route = %q, want outbound", d.Route.Name)
	}
	if d.OutNumber != "123" {
		t.Errorf("OutNumber = %q, want \"123\"", d.OutNumber)
	}
	if len(d.Targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(d.Targets))
	}
	// Failover order = config order: carrier-a then carrier-b.
	if d.Targets[0].Name != "carrier-a" || d.Targets[1].Name != "carrier-b" {
		t.Errorf("target order = %q,%q; want carrier-a,carrier-b",
			d.Targets[0].Name, d.Targets[1].Name)
	}
	// Targets carry the resolved *Peer, not just the name.
	if d.Targets[0].Peer == nil || d.Targets[0].Peer != cfg.Peers["carrier-a"] {
		t.Error("Targets[0].Peer must be the resolved carrier-a peer")
	}
}

func TestResolveInboundPassthrough(t *testing.T) {
	cfg := routingCfg(t)
	d, ok := Resolve(cfg, "carrier-a", "5551234")
	if !ok {
		t.Fatal("inbound must resolve")
	}
	if d.Route.Name != "inbound" || d.OutNumber != "5551234" {
		t.Errorf("route=%q out=%q; want inbound / 5551234", d.Route.Name, d.OutNumber)
	}
	if len(d.Targets) != 1 || d.Targets[0].Name != "internal-pbx" {
		t.Errorf("targets = %+v; want [internal-pbx]", d.Targets)
	}
}

func TestResolveNoRoute(t *testing.T) {
	cfg := routingCfg(t)
	if d, ok := Resolve(cfg, "carrier-b", "9123"); ok {
		t.Fatalf("carrier-b has no route, got %+v", d)
	}
}

func TestTransformNumberUnanchoredReplacesAll(t *testing.T) {
	// Pins the semantics: an UNANCHORED match.to with a transform is a
	// replace-ALL that keeps surrounding text. Operators should anchor
	// match.to with ^...$ when transforming; this guards the behavior so
	// it cannot change silently.
	const src = `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: replaceall
    from: pbx
    match: { to: "0" }
    transform: { to: "00" }
    to: [pbx]
`
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// "102030": each of the three 0s → "00", surrounding 1/2/3 kept.
	if got := transformNumber(cfg.Routes[0], "102030"); got != "100200300" {
		t.Errorf("transformNumber = %q, want \"100200300\"", got)
	}
}
