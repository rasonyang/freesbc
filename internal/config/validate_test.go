package config

import (
	"net/netip"
	"strings"

	"golang.org/x/crypto/bcrypt"
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
		{"zero auto_ban duration", func(c *Config) { c.Shield.AutoBan.Duration = 0 }, "auto_ban.duration"},
		{"negative auto_ban duration", func(c *Config) { c.Shield.AutoBan.Duration = Duration(-time.Second) }, "auto_ban.duration"},
		{"bad admin listen", func(c *Config) { c.Admin = &AdminConfig{Listen: "nope"} }, "admin.listen"},
		{"bad media_latch", func(c *Config) { c.Peers["pbx"].MediaLatch = "sticky" }, "media_latch"},
		{"negative rtp_timeout", func(c *Config) { c.Listen.Media.RTPTimeout = Duration(-time.Second) }, "rtp_timeout"},
		{"negative ring_timeout", func(c *Config) { c.RingTimeout = Duration(-time.Second) }, "ring_timeout"},
		{"negative register_expires", func(c *Config) { c.RegisterExpires = Duration(-time.Second) }, "register_expires"},
		{"peer register_expires negative", func(c *Config) {
			c.Peers["pbx"].RegisterExpires = Duration(-time.Second)
		}, "register_expires"},
		{"sub-second register_expires truncates to Expires:0", func(c *Config) {
			c.RegisterExpires = Duration(500 * time.Millisecond)
		}, "at least 1s"},
		{"peer sub-second register_expires truncates to Expires:0", func(c *Config) {
			c.Peers["pbx"].RegisterExpires = Duration(500 * time.Millisecond)
		}, "at least 1s"},
		{"transform group out of range", func(c *Config) {
			c.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`}
			c.Routes[0].Transform = &RouteTransform{To: "$2"}
		}, "capture group"},
		{"transform braced group out of range", func(c *Config) {
			c.Routes[0].Match = &RouteMatch{To: `^9(\d+)$`}
			c.Routes[0].Transform = &RouteTransform{To: "${5}"}
		}, "capture group"},
		{"min_se too small", func(c *Config) { c.MinSE = Duration(500 * time.Millisecond) }, "min_se"},
		{"session_expires below min_se", func(c *Config) {
			c.MinSE = Duration(120 * time.Second)
			c.SessionExpires = Duration(90 * time.Second)
		}, "session_expires"},
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

func TestValidatePeerCooldownMustBePositive(t *testing.T) {
	_, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peer_cooldown: -1s
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err == nil || !strings.Contains(err.Error(), "peer_cooldown") {
		t.Fatalf("want peer_cooldown error, got %v", err)
	}
}

func TestValidateSRVCacheTTLMinimum(t *testing.T) {
	_, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
srv_cache_ttl: 500ms
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err == nil || !strings.Contains(err.Error(), "srv_cache_ttl") {
		t.Fatalf("want srv_cache_ttl error, got %v", err)
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

func TestValidateAdminAuth(t *testing.T) {
	// a real bcrypt hash of "secret"
	good := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	base := func(admin string) string {
		return `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
` + admin + `
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`
	}
	// valid admin block
	if _, err := Parse([]byte(base("admin:\n  listen: 127.0.0.1:8080\n  auth: { username: admin, password_hash: \"" + good + "\" }"))); err != nil {
		t.Fatalf("valid admin block should parse: %v", err)
	}
	// empty username
	_, err := Parse([]byte(base("admin:\n  listen: 127.0.0.1:8080\n  auth: { username: \"\", password_hash: \"" + good + "\" }")))
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("empty username should fail, got %v", err)
	}
	// non-bcrypt password_hash
	_, err = Parse([]byte(base("admin:\n  listen: 127.0.0.1:8080\n  auth: { username: admin, password_hash: notbcrypt }")))
	if err == nil || !strings.Contains(err.Error(), "password_hash") {
		t.Fatalf("non-bcrypt hash should fail, got %v", err)
	}
	// no admin block → fine
	if _, err := Parse([]byte(base(""))); err != nil {
		t.Fatalf("no admin block should parse: %v", err)
	}
}

// TestValidateRejectsNonLoopbackAdmin is the T-26 (D4-6) red test: a
// non-loopback admin.listen is a full-config exposure point, so it must not
// pass silently — only an explicit admin.allow_remote: true admits it (the
// operator has signed off on the exposure; the error message itself points
// at the TLS route).
func TestValidateRejectsNonLoopbackAdmin(t *testing.T) {
	good := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	base := func(admin string) string {
		return `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
` + admin + `
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`
	}
	auth := `  auth: { username: admin, password_hash: "` + good + `" }`
	// 0.0.0.0 without allow_remote → rejected.
	_, err := Parse([]byte(base("admin:\n  listen: 0.0.0.0:8080\n" + auth)))
	if err == nil || !strings.Contains(err.Error(), "allow_remote") {
		t.Fatalf("non-loopback admin listen without allow_remote should fail mentioning allow_remote, got %v", err)
	}
	// A LAN address without allow_remote → rejected too.
	_, err = Parse([]byte(base("admin:\n  listen: 192.168.1.10:8080\n" + auth)))
	if err == nil {
		t.Fatal("LAN admin listen without allow_remote should fail")
	}
	// With allow_remote → admitted.
	if _, err := Parse([]byte(base("admin:\n  listen: 0.0.0.0:8080\n  allow_remote: true\n" + auth))); err != nil {
		t.Fatalf("allow_remote should admit non-loopback listen: %v", err)
	}
	// Loopback needs no opt-in.
	if _, err := Parse([]byte(base("admin:\n  listen: 127.0.0.1:8080\n" + auth))); err != nil {
		t.Fatalf("loopback admin listen should parse without allow_remote: %v", err)
	}
}

// TestValidateRejectsLowBcryptCost is the T-26 (D4-6) red test: a cost-4
// hash makes offline cracking cheap; the config gate demands cost >= 10.
func TestValidateRejectsLowBcryptCost(t *testing.T) {
	lowCost, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate low-cost hash: %v", err)
	}
	if cost, cerr := bcrypt.Cost(lowCost); cerr != nil || cost >= 10 {
		t.Fatalf("test setup: want a cost <10 hash, got cost %d err %v", cost, cerr)
	}
	base := func(hash string) string {
		return `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
admin:
  listen: 127.0.0.1:8080
  auth: { username: admin, password_hash: "` + hash + `" }
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`
	}
	_, err = Parse([]byte(base(string(lowCost))))
	if err == nil || !strings.Contains(err.Error(), "cost") {
		t.Fatalf("low-cost hash should fail mentioning cost, got %v", err)
	}
	// cost 10 passes.
	if _, err := Parse([]byte(base("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"))); err != nil {
		t.Fatalf("cost-10 hash should parse: %v", err)
	}
}

// TestValidateRejectsWildcardPrefix is the T-11 (F-16) red test: a
// wildcard/over-wide allowed_ips silently opened the whole inbound trust
// boundary — Parse must refuse it, and the empty list (which silently
// fail-closed before) must be refused too.
func TestValidateRejectsWildcardPrefix(t *testing.T) {
	base := func(prefix string) string {
		return `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: ["` + prefix + `"]
routes:
  - name: r
    from: p
    to: [p]
`
	}
	_, err := Parse([]byte(base("0.0.0.0/0")))
	if err == nil || !strings.Contains(err.Error(), "allowed_ips") {
		t.Fatalf("wildcard prefix should fail mentioning allowed_ips, got %v", err)
	}
	if _, err := Parse([]byte(base("10.0.0.0/7"))); err == nil {
		t.Fatal("ipv4 prefix wider than /8 must be refused")
	}
	if _, err := Parse([]byte(base("2001:db8::/24"))); err == nil {
		t.Fatal("ipv6 prefix wider than /32 must be refused")
	}
	empty := `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: []
routes:
  - name: r
    from: p
    to: [p]
`
	if _, err := Parse([]byte(empty)); err == nil || !strings.Contains(err.Error(), "allowed_ips") {
		t.Fatalf("empty allowed_ips should fail, got %v", err)
	}
	// The floors themselves pass: /8 (this repo's own example uses it) and
	// an IPv6 site allocation /32.
	if _, err := Parse([]byte(base("10.0.0.0/8"))); err != nil {
		t.Fatalf("exactly /8 should pass: %v", err)
	}
	if _, err := Parse([]byte(base("2001:db8::/32"))); err != nil {
		t.Fatalf("exactly /32 (v6) should pass: %v", err)
	}
}

// TestValidateAllowedIPsCanonicalized (T-11): a non-canonical prefix is
// stored masked, so 10.0.1.5/16 matches exactly what the operator meant
// instead of silently mismatching netip's unmasked semantics.
func TestValidateAllowedIPsCanonicalized(t *testing.T) {
	c := validConfig()
	c.Peers["pbx"].AllowedIPs = []string{"10.0.1.5/16"}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if !c.Peers["pbx"].AllowsIP(netip.MustParseAddr("10.0.2.3")) {
		t.Error("10.0.2.3 should be allowed under the masked 10.0.1.5/16")
	}
	if !c.Peers["pbx"].AllowsIP(netip.MustParseAddr("10.0.1.5")) {
		t.Error("10.0.1.5 itself should be allowed")
	}
	if c.Peers["pbx"].AllowsIP(netip.MustParseAddr("10.1.0.1")) {
		t.Error("10.1.0.1 must not be allowed")
	}
}

func TestValidatePeerSRTPInvalid(t *testing.T) {
	_, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  p:
    address: 127.0.0.1:5070
    srtp: bogus
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err == nil || !strings.Contains(err.Error(), "srtp") {
		t.Fatalf("want srtp validation error, got %v", err)
	}
}

// --- NAT/VPN bind-advertised topology (sip/rtp sections) ---

// natTopoCfg is the user-facing shape of the bind/advertised topology: a
// private bind address (VPN) with a public advertised address, independent
// for signaling and media.
func natTopoCfg() string {
	return `
sip:
  bind_ip: 10.77.0.2
  bind_port: 16060
  advertised_ip: 198.51.100.7
  advertised_port: 15060
rtp:
  bind_ip: 10.77.0.2
  advertised_ip: 203.0.113.7
peers:
  carrier:
    address: 203.0.113.10:5060
    allowed_ips: [203.0.113.0/24]
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [carrier]
`
}

func TestValidateNATTopologyParsesAndDefaults(t *testing.T) {
	cfg, err := Parse([]byte(natTopoCfg()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.SIP.BindIP != "10.77.0.2" || cfg.SIP.BindPort != 16060 {
		t.Errorf("sip bind: %+v", cfg.SIP)
	}
	if cfg.SIP.AdvertisedIP != "198.51.100.7" || cfg.SIP.AdvertisedPort != 15060 {
		t.Errorf("sip advertised: %+v", cfg.SIP)
	}
	if cfg.RTP.BindIP != "10.77.0.2" || cfg.RTP.AdvertisedIP != "203.0.113.7" {
		t.Errorf("rtp: %+v", cfg.RTP)
	}
	ls := cfg.Listeners()
	if len(ls) != 1 || ls[0].Transport != "udp" || ls[0].Host != "10.77.0.2" || ls[0].Port != 16060 {
		t.Errorf("Listeners() = %+v, want the sip.bind_ip listener", ls)
	}
}

// TestValidateNATTopologyAdvertisedDefaultsToBind proves advertised_ip and
// advertised_port fall back to their bind counterparts (withDefaults), so a
// deployment that binds a public address needs no advertised section at all.
func TestValidateNATTopologyAdvertisedDefaultsToBind(t *testing.T) {
	cfg, err := Parse([]byte(`
sip:
  bind_ip: 10.77.0.2
  bind_port: 16060
rtp:
  bind_ip: 10.77.0.2
  advertised_ip: 203.0.113.7
peers:
  carrier:
    address: 203.0.113.10:5060
    allowed_ips: [203.0.113.0/24]
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [carrier]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.SIP.AdvertisedIP != "10.77.0.2" || cfg.SIP.AdvertisedPort != 16060 {
		t.Errorf("advertised must default to bind values, got ip=%q port=%d", cfg.SIP.AdvertisedIP, cfg.SIP.AdvertisedPort)
	}
}

func TestValidateNATTopologyErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"no bind_ip", func(c *Config) { c.SIP.BindIP = "" }, "sip.bind_ip"},
		{"no bind_port", func(c *Config) { c.SIP.BindPort = 0 }, "sip.bind_port"},
		{"bad bind_ip", func(c *Config) { c.SIP.BindIP = "not-an-ip" }, "sip.bind_ip"},
		{"bad advertised_ip", func(c *Config) { c.SIP.AdvertisedIP = "not-an-ip" }, "sip.advertised_ip"},
		{"unspecified advertised_ip", func(c *Config) { c.SIP.AdvertisedIP = "0.0.0.0" }, "unroutable"},
		{"bad bind_port", func(c *Config) { c.SIP.BindPort = 70000 }, "sip.bind_port"},
		{"bad advertised_port", func(c *Config) { c.SIP.AdvertisedPort = 70000 }, "sip.advertised_port"},
		{"bad transport", func(c *Config) { c.SIP.Transport = "sctp" }, "sip.transport"},
		{"bad rtp bind_ip", func(c *Config) { c.RTP.BindIP = "not-an-ip" }, "rtp.bind_ip"},
		{"bad rtp advertised_ip", func(c *Config) { c.RTP.AdvertisedIP = "not-an-ip" }, "rtp.advertised_ip"},
		{"unspecified rtp advertised_ip", func(c *Config) { c.RTP.AdvertisedIP = "::" }, "blackhole"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(natTopoCfg()))
			if err != nil {
				t.Fatalf("base parse: %v", err)
			}
			tc.mutate(cfg)
			if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want validation error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

// TestValidateNATTopologyExcludesListenSIP proves the two listener sources
// are mutually exclusive: the sip section REPLACES listen.sip, so keeping
// both is an ambiguity error, not silent precedence.
func TestValidateNATTopologyExcludesListenSIP(t *testing.T) {
	_, err := Parse([]byte(`
listen:
  sip: [udp://0.0.0.0:5060]
sip:
  bind_ip: 10.77.0.2
  bind_port: 16060
rtp:
  advertised_ip: 203.0.113.7
peers:
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [pbx]
`))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want mutually-exclusive error, got %v", err)
	}
}

// TestValidateNATTopologyRequiresRTPAdvertised proves the SDP blackhole
// guard: with sip.bind_ip configured (no listen.sip hosts to fall back on)
// and public_ip left "auto", a missing rtp.advertised_ip would make every
// SDP advertise 127.0.0.1.
func TestValidateNATTopologyRequiresRTPAdvertised(t *testing.T) {
	_, err := Parse([]byte(`
sip:
  bind_ip: 10.77.0.2
  bind_port: 16060
  advertised_ip: 198.51.100.7
peers:
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [pbx]
`))
	if err == nil || !strings.Contains(err.Error(), "rtp.advertised_ip") {
		t.Fatalf("want rtp.advertised_ip requirement error, got %v", err)
	}

	// With a literal public_ip the legacy resolution still works, so the
	// same config must pass.
	_, err = Parse([]byte(`
listen:
  media:
    public_ip: 203.0.113.7
sip:
  bind_ip: 10.77.0.2
  bind_port: 16060
  advertised_ip: 198.51.100.7
peers:
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [pbx]
`))
	if err != nil {
		t.Fatalf("literal public_ip must satisfy the SDP advertised requirement, got %v", err)
	}
}

// TestValidateNoListenerAtAll covers the both-absent case: an empty
// listen.sip with no sip.bind_ip fails, but either source alone passes.
func TestValidateNoListenerAtAll(t *testing.T) {
	c := validConfig()
	c.Listen.SIP = nil
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "sip.bind_ip") {
		t.Fatalf("want at-least-one-listener error, got %v", err)
	}
	c.SIP.BindIP = "127.0.0.1"
	c.SIP.BindPort = 5060
	c.RTP.AdvertisedIP = "203.0.113.7" // satisfy the SDP blackhole guard too
	if err := c.validate(); err != nil {
		t.Fatalf("sip.bind_ip alone must satisfy the listener requirement, got %v", err)
	}
}

// --- rtp.port_min/port_max explicit range ---

// TestValidateRTPRangeParsesAndWins proves the rtp-section range drives
// RTPPortRange (precedence over the legacy default) and parses from the
// user-facing YAML shape.
func TestValidateRTPRangeParsesAndWins(t *testing.T) {
	cfg, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
rtp:
  port_min: 20000
  port_max: 20100
peers:
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [pbx]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.RTPPortRange(); got.Min != 20000 || got.Max != 20100 {
		t.Errorf("RTPPortRange() = %d-%d, want 20000-20100", got.Min, got.Max)
	}
	// The legacy range must stay zero (not default-filled), so the two
	// sources stay distinguishable.
	if cfg.Listen.Media.PortRange != (PortRange{}) {
		t.Errorf("listen.media.port_range = %+v, want zero (rtp range replaces it)", cfg.Listen.Media.PortRange)
	}
}

// TestValidateRTPRangeWithNATTopology proves the explicit range composes
// with the rest of the bind/advertised topology.
func TestValidateRTPRangeWithNATTopology(t *testing.T) {
	cfg, err := Parse([]byte(`
sip:
  bind_ip: 10.77.0.2
  bind_port: 16060
  advertised_ip: 198.51.100.7
rtp:
  bind_ip: 10.77.0.2
  advertised_ip: 203.0.113.7
  port_min: 20000
  port_max: 20100
peers:
  carrier:
    address: 203.0.113.10:5060
    allowed_ips: [203.0.113.0/24]
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [carrier]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.RTPPortRange(); got.Min != 20000 || got.Max != 20100 {
		t.Errorf("RTPPortRange() = %d-%d, want 20000-20100", got.Min, got.Max)
	}
}

func TestValidateRTPRangeErrors(t *testing.T) {
	cases := []struct {
		name    string
		cfgYAML string
		wantSub string
	}{
		{"min only", "rtp: { port_min: 20000 }", "set together"},
		{"max only", "rtp: { port_max: 20100 }", "set together"},
		{"min above max", "rtp: { port_min: 20100, port_max: 20000 }", "port_min must be less than port_max"},
		{"min equals max", "rtp: { port_min: 20000, port_max: 20000 }", "port_min must be less than port_max"},
		{"min below 1024", "rtp: { port_min: 500, port_max: 20000 }", "rtp.port_min"},
		{"max above 65535", "rtp: { port_min: 20000, port_max: 70000 }", "rtp.port_max"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.cfgYAML + `
listen:
  sip: [udp://127.0.0.1:5060]
peers:
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [pbx]
`))
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want validation error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

// TestValidateRTPRangeExcludesLegacyRange proves the two range sources are
// mutually exclusive, same as sip.bind_ip vs listen.sip.
func TestValidateRTPRangeExcludesLegacyRange(t *testing.T) {
	_, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
rtp:
  port_min: 20000
  port_max: 20100
peers:
  pbx:
    address: 10.77.0.5:5060
    allowed_ips: [10.77.0.0/24]
routes:
  - name: out
    from: pbx
    to: [pbx]
`))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want mutually-exclusive error, got %v", err)
	}
}

// TestValidateLegacyRangeStillDefaults proves an rtp-section-less config
// keeps the legacy default range and rejects a too-low legacy range.
func TestValidateLegacyRangeStillDefaults(t *testing.T) {
	c := validConfig()
	if got := c.RTPPortRange(); got.Min != 16384 || got.Max != 32768 {
		t.Errorf("legacy default range = %d-%d, want 16384-32768", got.Min, got.Max)
	}
	c.Listen.Media.PortRange = PortRange{Min: 80, Max: 90}
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "port_range") {
		t.Fatalf("want legacy port_range floor error, got %v", err)
	}
}
