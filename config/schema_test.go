package config

import (
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

func TestSchemaUnmarshalFullExample(t *testing.T) {
	src := `
listen:
  sip:
    - udp://0.0.0.0:5060
    - tls://0.0.0.0:5061
  media:
    port_range: 16384-32768
    public_ip: auto
peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    transport: udp
    auth: { username: acct01, password: secret }
    register: true
    allowed_ips: [203.0.113.0/24]
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a]
  - name: inbound
    from: carrier-a
    to: [internal-pbx]
shield:
  rate_limit: 20/s per_ip
  auto_ban: { failures: 5, window: 60s, duration: 1h }
  nftables: auto
admin:
  listen: 127.0.0.1:8080
  auth: { username: admin, password_hash: "x" }
`
	var c Config
	if err := yaml.UnmarshalWithOptions([]byte(src), &c, yaml.Strict()); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(c.Listen.SIP) != 2 || c.Listen.SIP[1].Transport != "tls" {
		t.Errorf("listen.sip: %+v", c.Listen.SIP)
	}
	ca := c.Peers["carrier-a"]
	if ca == nil || !ca.Register || ca.Auth == nil || ca.Auth.Username != "acct01" {
		t.Errorf("carrier-a: %+v", ca)
	}
	if len(c.Routes) != 2 || c.Routes[0].Match.To != `^9(\d+)$` || c.Routes[0].Transform.To != "$1" {
		t.Errorf("routes: %+v, %+v", c.Routes[0], c.Routes[1])
	}
	if c.Shield.AutoBan.Window.Std() != 60*time.Second {
		t.Errorf("auto_ban.window: %v", c.Shield.AutoBan.Window.Std())
	}
	if c.Admin == nil || c.Admin.Listen != "127.0.0.1:8080" {
		t.Errorf("admin: %+v", c.Admin)
	}
}

func TestWithDefaults(t *testing.T) {
	c := &Config{Peers: map[string]*Peer{"p": {Address: "10.0.0.1:5060"}}}
	withDefaults(c)
	if c.Peers["p"].Transport != "udp" {
		t.Errorf("peer transport default: %q", c.Peers["p"].Transport)
	}
	if c.Listen.Media.PortRange.Min != 16384 || c.Listen.Media.PortRange.Max != 32768 {
		t.Errorf("port range default: %+v", c.Listen.Media.PortRange)
	}
	if c.Listen.Media.PublicIP != "auto" {
		t.Errorf("public_ip default: %q", c.Listen.Media.PublicIP)
	}
	if c.Listen.Media.RTPTimeout.Std() != 5*time.Minute {
		t.Errorf("rtp_timeout default: %v", c.Listen.Media.RTPTimeout.Std())
	}
	if c.Peers["p"].MediaLatch != "strict" {
		t.Errorf("media_latch default: %q", c.Peers["p"].MediaLatch)
	}
	if c.Shield.RateLimit != "20/s per_ip" {
		t.Errorf("rate_limit default: %q", c.Shield.RateLimit)
	}
	if c.Shield.AutoBan.Failures != 5 || c.Shield.AutoBan.Window.Std() != 60*time.Second || c.Shield.AutoBan.Duration.Std() != time.Hour {
		t.Errorf("auto_ban default: %+v", c.Shield.AutoBan)
	}
	if c.Shield.NFTables != "auto" {
		t.Errorf("nftables default: %q", c.Shield.NFTables)
	}
	if c.RingTimeout.Std() != 60*time.Second {
		t.Errorf("ring_timeout default: %v", c.RingTimeout.Std())
	}
	if c.RegisterExpires.Std() != 3600*time.Second {
		t.Errorf("register_expires default: %v", c.RegisterExpires.Std())
	}
}

func TestParseRingTimeout(t *testing.T) {
	// minimalYAML defined in loader_test.go, but we'll use a simpler approach here
	src := `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: pbx
    to: [pbx]
ring_timeout: 30s
`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.RingTimeout.Std() != 30*time.Second {
		t.Errorf("ring_timeout = %v, want 30s", c.RingTimeout.Std())
	}
}

func TestParseRegisterExpires(t *testing.T) {
	src := minimalYAML + "register_expires: 1200s\n"
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.RegisterExpires.Std() != 1200*time.Second {
		t.Errorf("register_expires = %v, want 1200s", c.RegisterExpires.Std())
	}
}

// TestParsePeerRegisterExpiresOverride proves a per-peer register_expires
// parses distinctly from the config-global default (Fix 5, whole-branch
// review): "pbx" overrides to 600s while the global stays 1200s.
func TestParsePeerRegisterExpiresOverride(t *testing.T) {
	src := `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
    register_expires: 600s
routes:
  - name: in
    from: pbx
    to: [pbx]
register_expires: 1200s
`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.RegisterExpires.Std() != 1200*time.Second {
		t.Errorf("global register_expires = %v, want 1200s", c.RegisterExpires.Std())
	}
	if got := c.Peers["pbx"].RegisterExpires.Std(); got != 600*time.Second {
		t.Errorf("peer register_expires override = %v, want 600s", got)
	}
}
