package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// validConfig returns a minimal config that passes Validate.
func validConfig() *Config {
	c := &Config{
		Listen: ListenConfig{SIP: []SIPListen{{Transport: "udp", Host: "0.0.0.0", Port: 5060}}},
		Peers: map[string]*Peer{
			"pbx": {Address: "10.0.0.10:5060", AllowedIPs: []string{"10.0.0.0/8"}},
		},
		Routes: []*Route{{Name: "in", From: "pbx", To: []string{"pbx"}}},
	}
	withDefaults(c)
	return c
}

func TestValidateOK(t *testing.T) {
	if err := validConfig().validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateCompilesAllowedIPs(t *testing.T) {
	c := validConfig()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	p := c.Peers["pbx"]
	if !p.AllowsIP(netip.MustParseAddr("10.1.2.3")) {
		t.Error("10.1.2.3 should be allowed")
	}
	if p.AllowsIP(netip.MustParseAddr("192.168.1.1")) {
		t.Error("192.168.1.1 should not be allowed")
	}
}

func TestValidateBareIPBecomesHostPrefix(t *testing.T) {
	c := validConfig()
	c.Peers["pbx"].AllowedIPs = []string{"203.0.113.7"}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if !c.Peers["pbx"].AllowsIP(netip.MustParseAddr("203.0.113.7")) {
		t.Error("bare IP should allow itself")
	}
	if c.Peers["pbx"].AllowsIP(netip.MustParseAddr("203.0.113.8")) {
		t.Error("bare IP must not allow neighbors")
	}
}

func TestValidateCompilesMatchRegex(t *testing.T) {
	c := validConfig()
	c.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	re := c.Routes[0].CompiledMatch()
	if re == nil || !re.MatchString("9123") || re.MatchString("8123") {
		t.Errorf("compiled regex wrong: %v", re)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"no listeners", func(c *Config) { c.Listen.SIP = nil }, "listen.sip"},
		{"low port range", func(c *Config) { c.Listen.Media.PortRange = PortRange{Min: 80, Max: 90} }, "port_range"},
		{"bad public ip", func(c *Config) { c.Listen.Media.PublicIP = "not-an-ip" }, "public_ip"},
		{"no peers", func(c *Config) { c.Peers = nil }, "peers"},
		{"peer no address", func(c *Config) { c.Peers["pbx"].Address = "" }, "pbx: address"},
		{"peer bad transport", func(c *Config) { c.Peers["pbx"].Transport = "sctp" }, "transport"},
		{"register without auth", func(c *Config) { c.Peers["pbx"].Register = true }, "requires auth"},
		{"bad cidr", func(c *Config) { c.Peers["pbx"].AllowedIPs = []string{"10.0.0.0/99"} }, "allowed_ips"},
		{"route no name", func(c *Config) { c.Routes[0].Name = "" }, "name required"},
		{"route unknown from", func(c *Config) { c.Routes[0].From = "ghost" }, `unknown peer "ghost"`},
		{"route empty to", func(c *Config) { c.Routes[0].To = nil }, "to:"},
		{"route unknown to", func(c *Config) { c.Routes[0].To = []string{"ghost"} }, `unknown peer "ghost"`},
		{"bad regex", func(c *Config) { c.Routes[0].Match = &RouteMatch{To: "("} }, "match.to"},
		{"transform without match", func(c *Config) { c.Routes[0].Transform = &RouteTransform{To: "$1"} }, "transform.to requires match.to"},
		{"bad rate limit", func(c *Config) { c.Shield.RateLimit = "lots" }, "rate_limit"},
		{"bad nftables", func(c *Config) { c.Shield.NFTables = "maybe" }, "nftables"},
		{"negative auto_ban failures", func(c *Config) { c.Shield.AutoBan.Failures = -1 }, "auto_ban.failures"},
		{"zero auto_ban window", func(c *Config) { c.Shield.AutoBan.Window = 0 }, "auto_ban.window"},
		{"negative auto_ban window", func(c *Config) { c.Shield.AutoBan.Window = Duration(-time.Second) }, "auto_ban.window"},
		{"zero auto_ban duration", func(c *Config) { c.Shield.AutoBan.Duration = 0 }, "auto_ban.duration"},
		{"negative auto_ban duration", func(c *Config) { c.Shield.AutoBan.Duration = Duration(-time.Second) }, "auto_ban.duration"},
		{"bad admin listen", func(c *Config) { c.Admin = &AdminConfig{Listen: "nope"} }, "admin.listen"},
		{"bad media_latch", func(c *Config) { c.Peers["pbx"].MediaLatch = "sticky" }, "media_latch"},
		{"negative rtp_timeout", func(c *Config) { c.Listen.Media.RTPTimeout = Duration(-time.Second) }, "rtp_timeout"},
		{"transform group out of range", func(c *Config) {
			c.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`}
			c.Routes[0].Transform = &RouteTransform{To: "$2"}
		}, "capture group"},
		{"transform braced group out of range", func(c *Config) {
			c.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`}
			c.Routes[0].Transform = &RouteTransform{To: "${5}"}
		}, "capture group"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(c)
			err := c.validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestValidateBadMatchRegexWithTransformIsOneError checks that a route with
// both an invalid match.to regex and a transform.to reports only the regex
// compile failure — not a spurious "transform.to requires match.to" (the
// match clause is present, it just fails to compile).
func TestValidateBadMatchRegexWithTransformIsOneError(t *testing.T) {
	c := validConfig()
	c.Routes[0].Match = &RouteMatch{To: "("}
	c.Routes[0].Transform = &RouteTransform{To: "$1"}
	err := c.validate()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "match.to:") {
		t.Errorf("expected regex compile error, got: %q", msg)
	}
	if strings.Contains(msg, "transform.to requires") {
		t.Errorf("must not also report spurious transform.to requires match.to: %q", msg)
	}
}

func TestValidateAggregatesAllErrors(t *testing.T) {
	c := validConfig()
	c.Listen.SIP = nil
	c.Routes[0].From = "ghost"
	err := c.validate()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "listen.sip") || !strings.Contains(msg, "ghost") {
		t.Errorf("expected both errors reported, got: %q", msg)
	}
}

func TestValidateTransformGroupInRange(t *testing.T) {
	c := validConfig()
	c.Routes[0].Match = &RouteMatch{To: `^9(\d+)(\d)$`}
	c.Routes[0].Transform = &RouteTransform{To: "$1$2"} // both groups exist
	if err := c.validate(); err != nil {
		t.Fatalf("in-range group refs must pass: %v", err)
	}
	c2 := validConfig()
	c2.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`}
	c2.Routes[0].Transform = &RouteTransform{To: "+$0"} // $0 = whole match, always valid
	if err := c2.validate(); err != nil {
		t.Fatalf("$0 (whole match) must pass: %v", err)
	}
	c3 := validConfig()
	c3.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`}
	c3.Routes[0].Transform = &RouteTransform{To: `$$1`} // $$ is an escaped literal $, not a ref
	if err := c3.validate(); err != nil {
		t.Fatalf("$$ escape must pass: %v", err)
	}
}

func TestValidateTransformEdgeCasesNotFalseRejected(t *testing.T) {
	// These templates never reference a real out-of-range group at runtime
	// (they mirror regexp.Expand: unterminated ${ is literal; leading-zero
	// names are named refs, not group indices), so validation must ACCEPT them.
	for _, tmpl := range []string{"${5", "$012", "$01", "$00"} {
		c := validConfig()
		c.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`} // 1 group
		c.Routes[0].Transform = &RouteTransform{To: tmpl}
		if err := c.validate(); err != nil {
			t.Errorf("template %q must not be rejected as out-of-range: %v", tmpl, err)
		}
	}
}
