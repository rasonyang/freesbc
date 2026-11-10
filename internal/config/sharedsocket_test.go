package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The single-IP layout (issue #320): private.ip equals public.bind, behind a
// 1:1 NAT, one UDP socket for both sides.

const sharedYAML = `
public:
  ip: 203.0.113.7
  bind: 10.77.0.2
private:
  ip: 10.77.0.2
rtp: 10000-19999
edge:
  switch: [10.77.0.3:5080]
  listen: { udp: 5060 }
`

func TestSharedSocketAccepted(t *testing.T) {
	c := mustParse(t, sharedYAML)
	if !c.SharedSocket() {
		t.Fatal("SharedSocket = false for private.ip == public.bind")
	}
	// Both planes draw from the one range: two pairs per call.
	if c.Shield.MaxSessions != 2500 {
		t.Errorf("default max_sessions = %d, want 2500 (half of 5000 pairs)", c.Shield.MaxSessions)
	}
	// Any order of the keys gives the same answer.
	swapped := `
private:
  ip: 10.77.0.2
edge:
  listen: { udp: 5060 }
  switch: [10.77.0.3:5080]
public:
  bind: 10.77.0.2
  ip: 203.0.113.7
rtp: 10000-19999
`
	if !mustParse(t, swapped).SharedSocket() {
		t.Error("SharedSocket depends on key order")
	}
	// CGNAT counts as private; a udp advertise of the same port is a no-op.
	cg := strings.NewReplacer("10.77.0.2", "100.64.1.2", "10.77.0.3", "100.64.1.3").Replace(sharedYAML)
	if !mustParse(t, cg).SharedSocket() {
		t.Error("CGNAT shared address refused")
	}
	adv := strings.Replace(sharedYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  advertise: { udp: 5060 }", 1)
	mustParse(t, adv)
	// An explicit max_sessions within half the range is kept.
	if c := mustParse(t, sharedYAML+"shield: { max_sessions: 100 }\n"); c.Shield.MaxSessions != 100 {
		t.Errorf("max_sessions = %d", c.Shield.MaxSessions)
	}
}

func TestSharedSocketRefusals(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"no NAT: all three equal", strings.Replace(sharedYAML, "ip: 203.0.113.7", "ip: 10.77.0.2", 1),
			"private.ip: \"10.77.0.2\" must differ from public.bind; the two sides need separate sockets"},
		{"public address shared", strings.NewReplacer("10.77.0.2", "198.51.100.9", "203.0.113.7", "203.0.113.8").Replace(sharedYAML),
			"is shared with public.bind but is not a private or CGNAT address"},
		{"no udp listener", strings.Replace(sharedYAML, "listen: { udp: 5060 }", "listen: { tcp: 5060 }", 1),
			"edge.listen.udp: required when private.ip equals public.bind"},
		{"udp advertise translates a moved port", strings.Replace(sharedYAML, "listen: { udp: 5060 }", "listen: { udp: 16060 }\n  advertise: { udp: 5060 }", 1),
			"edge.advertise.udp: 5060 translates the udp port 16060"},
		{"udp advertise translated", strings.Replace(sharedYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  advertise: { udp: 16060 }", 1),
			"edge.advertise.udp: 16060 translates the udp port"},
		{"switch is public", strings.Replace(sharedYAML, "10.77.0.3:5080", "198.51.100.20:5080", 1),
			"edge.switch[0]: \"198.51.100.20:5080\" is not a private or CGNAT address"},
		{"carrier source covers switch", sharedYAML + "", "edge.carrier_sources: 10.77.0.0/24 covers 10.77.0.3"},
		{"carrier at switch address", strings.Replace(sharedYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { pstn: \"10.77.0.3:5080\" }", 1),
			"edge.carriers.pstn: 10.77.0.3 is also edge.switch[0]"},
		{"range holds one pair", strings.Replace(sharedYAML, "10000-19999", "10000-10001", 1), "needs at least 2"},
		{"max_sessions above half", sharedYAML + "shield: { max_sessions: 2501 }\n", "exceeds the 2500 calls"},
	}
	cases[6].src = strings.Replace(sharedYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carrier_sources: [10.77.0.0/24]", 1)
	for _, c := range cases {
		if err := parseErr(t, c.src); !strings.Contains(err, c.want) {
			t.Errorf("%s: error does not contain %q:\n%s", c.name, c.want, err)
		}
	}
	// A carrier named by DNS cannot be checked at startup and is accepted.
	mustParse(t, strings.Replace(sharedYAML, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { pstn: sip.example.net }", 1))
}

// A separate-address config keeps every old behaviour: not shared, the
// default max_sessions is the full pair count, a translated udp port is fine.
func TestSeparateAddressesNotShared(t *testing.T) {
	c := mustParse(t, minimalYAML)
	if c.SharedSocket() {
		t.Error("minimalYAML reports a shared socket")
	}
	if c.Shield.MaxSessions != 5000 {
		t.Errorf("default max_sessions = %d, want 5000", c.Shield.MaxSessions)
	}
	if c.SharedSocketNote() != "" {
		t.Error("separate addresses print a shared-socket note")
	}
	nat := mustParse(t, natYAML)
	if nat.SharedSocket() || strings.Contains(nat.NATChecklist(), "single-IP") {
		t.Error("a NAT config with separate addresses reads as shared")
	}
	mustParse(t, strings.Replace(minimalYAML, "{ udp: 5060 }", "{ udp: 16060 }\n  advertise: { udp: 5060 }", 1))
}

func TestSharedSocketChecklist(t *testing.T) {
	c := mustParse(t, sharedYAML)
	want := `NAT mode: advertised public endpoint = 203.0.113.7 (udp/5060 udp/10000-19999 (rtp))
REQUIRED forwards -> 10.77.0.2 (same port numbers):
  udp/5060
  udp/10000-19999 (rtp)
in-dialog requests (2xx ACK, BYE) use Contact/Record-Route, not Via:
these ports MUST be reachable from clients.
single-IP layout: private.ip and public.bind are both 10.77.0.2, so one UDP socket (10.77.0.2:5060) serves both sides.
the switch is identified by its source IP (10.77.0.3), not by the socket it reaches: a datagram from that address is trusted and skips the shield.
REQUIRED forwards: udp/5060 and the rtp range 10000-19999 to 10.77.0.2 (listed above).
`
	if got := c.NATChecklist(); got != want {
		t.Errorf("NATChecklist =\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(c.NATChecklist(), "provider") {
		t.Error("the checklist asks the operator about provider filtering")
	}
}

// Moving between the layouts changes private.ip or public.bind: both are
// restart-only, so a reload that does it is flagged.
func TestRestartOnlyChangesSharedLayout(t *testing.T) {
	sep := strings.Replace(sharedYAML, "  ip: 10.77.0.2\nrtp", "  ip: 10.77.0.9\nrtp", 1)
	got := RestartOnlyChanges(mustParse(t, sharedYAML), mustParse(t, sep))
	if !slices.Contains(got, "private") {
		t.Errorf("RestartOnlyChanges = %q, want private", got)
	}
}

// The shared socket follows edge.listen.udp (issue #328); the two-address
// layout keeps its private socket on 5060 whatever the listen port.
func TestSharedSocketMovedPort(t *testing.T) {
	moved := strings.Replace(sharedYAML, "udp: 5060", "udp: 16060", 1)
	c := mustParse(t, moved)
	if got, want := c.PrivateAddr(), netip.MustParseAddrPort("10.77.0.2:16060"); got != want {
		t.Errorf("PrivateAddr = %v, want %v", got, want)
	}
	mustParse(t, strings.Replace(moved, "listen: { udp: 16060 }", "listen: { udp: 16060 }\n  advertise: { udp: 16060 }", 1))
	got := c.NATChecklist()
	for _, w := range []string{"  udp/16060\n", "one UDP socket (10.77.0.2:16060) serves both sides", "REQUIRED forwards: udp/16060 and the rtp range"} {
		if !strings.Contains(got, w) {
			t.Errorf("checklist lacks %q:\n%s", w, got)
		}
	}
	if strings.Contains(got, "5060") {
		t.Errorf("checklist still names 5060:\n%s", got)
	}

	sep := mustParse(t, strings.Replace(minimalYAML, "{ udp: 5060 }", "{ udp: 16060 }", 1))
	if sep.SharedSocket() || sep.PrivateAddr().Port() != PrivateSIPPort {
		t.Errorf("two-address layout: shared=%v private=%v, want port %d", sep.SharedSocket(), sep.PrivateAddr(), PrivateSIPPort)
	}
}
