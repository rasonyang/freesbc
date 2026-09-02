package config

import (
	"strings"
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

// TestTLSConfigFieldsParse (T-26b red test): the admin TLS fields — and
// allow_remote — unmarshal under the Strict parser, so a LAN deployment can
// serve the admin API over HTTPS.
func TestTLSConfigFieldsParse(t *testing.T) {
	src := `
listen:
  sip: [udp://127.0.0.1:5060]
peers:
  carrier:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: out
    from: carrier
    to: [carrier]
admin:
  listen: 192.168.1.10:8443
  allow_remote: true
  tls_cert: /etc/freesbc/admin-cert.pem
  tls_key: /etc/freesbc/admin-key.pem
  auth: { username: admin, password_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" }
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Admin == nil || !cfg.Admin.AllowRemote ||
		cfg.Admin.TLSCert != "/etc/freesbc/admin-cert.pem" ||
		cfg.Admin.TLSKey != "/etc/freesbc/admin-key.pem" {
		t.Fatalf("admin tls fields: %+v", cfg.Admin)
	}
}

// TestPeerAuthRealmParses is the T-19 (F-20) red test: the optional
// auth.realm pin on a peer parses under the Strict parser.
func TestPeerAuthRealmParses(t *testing.T) {
	src := `
listen:
  sip: [udp://127.0.0.1:5060]
peers:
  carrier:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
    auth: { username: acct01, password: secret, realm: carrier-realm }
routes:
  - name: out
    from: carrier
    to: [carrier]
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Peers["carrier"].Auth == nil || cfg.Peers["carrier"].Auth.Realm != "carrier-realm" {
		t.Fatalf("auth realm: %+v", cfg.Peers["carrier"].Auth)
	}
	// The field stays optional: no realm parses as the zero value.
	src2 := `
listen:
  sip: [udp://127.0.0.1:5060]
peers:
  carrier:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
    auth: { username: acct01, password: secret }
routes:
  - name: out
    from: carrier
    to: [carrier]
`
	cfg2, err := Parse([]byte(src2))
	if err != nil {
		t.Fatalf("parse (no realm): %v", err)
	}
	if cfg2.Peers["carrier"].Auth.Realm != "" {
		t.Fatalf("absent realm should be empty, got %q", cfg2.Peers["carrier"].Auth.Realm)
	}
}

// TestSIPTLSConfigFieldsParse is the T-17 (F-13) red test: the SIP-plane
// TLS fields — inbound listen.tls_cert/tls_key/tls_client_ca and outbound
// per-peer tls_ca/tls_client_cert/tls_client_key — unmarshal under the
// Strict parser.
func TestSIPTLSConfigFieldsParse(t *testing.T) {
	src := `
listen:
  sip: [udp://127.0.0.1:5060, tls://127.0.0.1:5061]
  tls_cert: /etc/freesbc/sip-cert.pem
  tls_key: /etc/freesbc/sip-key.pem
  tls_client_ca: /etc/freesbc/client-ca.pem
peers:
  carrier:
    address: carrier.example.com:5061
    transport: tls
    allowed_ips: [203.0.113.0/24]
    tls_ca: /etc/freesbc/carrier-ca.pem
    tls_client_cert: /etc/freesbc/carrier-client.pem
    tls_client_key: /etc/freesbc/carrier-client-key.pem
routes:
  - name: out
    from: carrier
    to: [carrier]
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Listen.TLSCert != "/etc/freesbc/sip-cert.pem" ||
		cfg.Listen.TLSKey != "/etc/freesbc/sip-key.pem" ||
		cfg.Listen.TLSClientCA != "/etc/freesbc/client-ca.pem" {
		t.Fatalf("listen tls fields: %+v", cfg.Listen)
	}
	p := cfg.Peers["carrier"]
	if p == nil || p.TLSCA != "/etc/freesbc/carrier-ca.pem" ||
		p.TLSClientCert != "/etc/freesbc/carrier-client.pem" ||
		p.TLSClientKey != "/etc/freesbc/carrier-client-key.pem" {
		t.Fatalf("peer tls fields: %+v", p)
	}
}

// TestValidateSIPTLSPairs (T-17): half-configured TLS pairs must be
// rejected — an operator who sets only one half believes verification (or
// mTLS) is on while it silently isn't.
func TestValidateSIPTLSPairs(t *testing.T) {
	base := func(extra string) string {
		return `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
` + extra + `
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
	_, err := Parse([]byte(base("  tls_cert: /tmp/c.pem")))
	if err == nil || !strings.Contains(err.Error(), "tls_key") {
		t.Fatalf("listen tls_cert without tls_key should fail, got %v", err)
	}
	_, err = Parse([]byte(base("  tls_key: /tmp/k.pem")))
	if err == nil {
		t.Fatal("listen tls_key without tls_cert should fail")
	}
	_, err = Parse([]byte(base("  tls_client_ca: /tmp/ca.pem")))
	if err == nil || !strings.Contains(err.Error(), "tls_client_ca") {
		t.Fatalf("listen tls_client_ca without cert should fail, got %v", err)
	}
	_, err = Parse([]byte(base("")))
	if err != nil {
		t.Fatalf("plain config should parse: %v", err)
	}
	// Peer client pair rules.
	peerBase := `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
` + "    tls_client_cert: /tmp/c.pem" + `
routes:
  - name: r
    from: p
    to: [p]
`
	_, err = Parse([]byte(peerBase))
	if err == nil || !strings.Contains(err.Error(), "tls_client_key") {
		t.Fatalf("peer tls_client_cert without key should fail, got %v", err)
	}
}

// TestValidateAdminTLSCertRequiresKey (T-26b): a half-configured TLS pair
// must be rejected — an operator who sets only tls_cert believes TLS is on
// while the listener would silently stay plaintext.
func TestValidateAdminTLSCertRequiresKey(t *testing.T) {
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
	_, err := Parse([]byte(base("admin:\n  listen: 127.0.0.1:8443\n  tls_cert: /tmp/c.pem\n  auth: { username: admin, password_hash: \"" + good + "\" }")))
	if err == nil || !strings.Contains(err.Error(), "tls_cert") {
		t.Fatalf("tls_cert without tls_key should fail mentioning tls_cert, got %v", err)
	}
	if _, err := Parse([]byte(base("admin:\n  listen: 127.0.0.1:8443\n  tls_key: /tmp/k.pem\n  auth: { username: admin, password_hash: \"" + good + "\" }"))); err == nil {
		t.Fatal("tls_key without tls_cert should fail")
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
	if c.SessionExpires.Std() != 1800*time.Second {
		t.Errorf("session_expires default: %v", c.SessionExpires.Std())
	}
	if c.MinSE.Std() != 90*time.Second {
		t.Errorf("min_se default: %v", c.MinSE.Std())
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

func TestParseSessionTimers(t *testing.T) {
	src := minimalYAML + "session_expires: 3600s\nmin_se: 120s\n"
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.SessionExpires.Std() != 3600*time.Second || c.MinSE.Std() != 120*time.Second {
		t.Errorf("got session_expires=%v min_se=%v", c.SessionExpires.Std(), c.MinSE.Std())
	}
}

func TestPeerCooldownAndSRVCacheTTLDefaults(t *testing.T) {
	// Minimal config omitting both fields → defaults applied.
	cfg, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.PeerCooldown.Std(); got != 30*time.Second {
		t.Errorf("peer_cooldown default = %v, want 30s", got)
	}
	if got := cfg.SRVCacheTTL.Std(); got != 300*time.Second {
		t.Errorf("srv_cache_ttl default = %v, want 300s", got)
	}
}

func TestPeerCooldownAndSRVCacheTTLParsed(t *testing.T) {
	cfg, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peer_cooldown: 45s
srv_cache_ttl: 120s
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.PeerCooldown.Std(); got != 45*time.Second {
		t.Errorf("peer_cooldown = %v, want 45s", got)
	}
	if got := cfg.SRVCacheTTL.Std(); got != 120*time.Second {
		t.Errorf("srv_cache_ttl = %v, want 120s", got)
	}
}

func TestPeerSRTPDefaultsDisabled(t *testing.T) {
	cfg, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Peers["p"].SRTP != "disabled" {
		t.Errorf("srtp default = %q, want disabled", cfg.Peers["p"].SRTP)
	}
}

func TestPeerSRTPParsed(t *testing.T) {
	cfg, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  sec:
    address: 127.0.0.1:5070
    srtp: required
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: sec
    to: [sec]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Peers["sec"].SRTP != "required" {
		t.Errorf("srtp = %q, want required", cfg.Peers["sec"].SRTP)
	}
}

// TestPeerMaxConcurrentCallsParses is the T-06 (F-06) red test: the new
// per-peer and global concurrent-call quota fields must parse (Strict YAML
// rejects unknown keys today, so this fails until the schema grows them).
func TestPeerMaxConcurrentCallsParses(t *testing.T) {
	cfg, err := Parse([]byte(`
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
    max_concurrent_calls: 3
routes:
  - name: in
    from: pbx
    to: [pbx]
max_concurrent_calls: 10
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.Peers["pbx"].MaxConcurrentCalls; got != 3 {
		t.Errorf("peer max_concurrent_calls = %d, want 3", got)
	}
	if got := cfg.MaxConcurrentCalls; got != 10 {
		t.Errorf("global max_concurrent_calls = %d, want 10", got)
	}
}

// TestMaxConcurrentCallsRejectsNegative proves a negative quota (which would
// make acquire's `peerMax > 0` guard silently read as unlimited — the
// opposite of what the operator asked for) is rejected at parse time.
func TestMaxConcurrentCallsRejectsNegative(t *testing.T) {
	if _, err := Parse([]byte(`
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
    max_concurrent_calls: -1
routes:
  - name: in
    from: pbx
    to: [pbx]
`)); err == nil {
		t.Fatal("negative peer max_concurrent_calls must fail Parse")
	}
	if _, err := Parse([]byte(`
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
max_concurrent_calls: -5
`)); err == nil {
		t.Fatal("negative global max_concurrent_calls must fail Parse")
	}
}
