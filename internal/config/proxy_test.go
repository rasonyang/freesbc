package config

import (
	"strings"
	"testing"
	"time"
)

// proxyYAML is a complete, minimal edge-proxy config: no trunk peers, no
// listen.sip — exactly the "proxy-only" deployment shape.
const proxyYAML = `
network:
  public:
    bind_ip: 0.0.0.0
    advertised_ip: 203.0.113.7
  private:
    bind_ip: 10.77.0.2

sip:
  public:
    udp:
      enabled: true
      bind: 0.0.0.0:16060
    ws:
      enabled: true
      bind: 0.0.0.0:18080
    wss:
      enabled: true
      bind: 0.0.0.0:18443
  private:
    bind: 10.77.0.2:5060
  upstream:
    address: 10.77.0.10:5060
    transport: udp

rtp:
  public:
    bind_ip: 0.0.0.0
    advertised_ip: 203.0.113.7
    port_min: 30000
    port_max: 39999
  private:
    bind_ip: 10.77.0.2
    port_min: 40000
    port_max: 49999

webrtc:
  enabled: true
  ice_mode: lite
  rtcp_mux: true
`

func mustParseProxy(t *testing.T, yaml string) *Config {
	t.Helper()
	c, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// pstnTrunk is a valid sip.pstn section for the proxyYAML shape: a carrier
// gateway on the public side whose match address nothing else uses (it is
// not the private socket and not the upstream).
const pstnTrunk = "  pstn:\n    address: 223.76.90.4:16060\n    match: 203.0.113.7:16060\n"

// withPSTN tucks a sip.pstn section into a proxyYAML-shaped config, right
// after the upstream stanza it belongs beside — both are keys of sip:.
func withPSTN(base, pstnSection string) string {
	return strings.Replace(base, "    transport: udp\n", "    transport: udp\n"+pstnSection, 1)
}

func TestProxyOnlyConfigIsValid(t *testing.T) {
	c := mustParseProxy(t, proxyYAML)
	if !c.ProxyEnabled() {
		t.Fatal("ProxyEnabled() = false")
	}
	if got := len(c.PublicSIPListeners()); got != 3 {
		t.Errorf("public listeners = %d, want 3", got)
	}
	if got := c.PublicAdvertisedIP().String(); got != "203.0.113.7" {
		t.Errorf("PublicAdvertisedIP = %s", got)
	}
	// network.private.advertised_ip is unset, so it falls back to the
	// specific private bind address.
	if got := c.PrivateAdvertisedIP().String(); got != "10.77.0.2" {
		t.Errorf("PrivateAdvertisedIP = %s", got)
	}
	if got := c.PublicRTPAdvertisedIP().String(); got != "203.0.113.7" {
		t.Errorf("PublicRTPAdvertisedIP = %s", got)
	}
	if got := c.PrivateRTPAdvertisedIP().String(); got != "10.77.0.2" {
		t.Errorf("PrivateRTPAdvertisedIP = %s", got)
	}
	if got := c.PrivateSIPAdvertisedPort(); got != 5060 {
		t.Errorf("PrivateSIPAdvertisedPort = %d", got)
	}
}

// The optional sip.pstn trunk section parses, and its transport defaults to
// udp — the only transport the carrier leg can ride (validation rejects the
// rest). A config without the section must keep the zero PstnConfig, or the
// proxy would believe a trunk was configured where none was.
func TestPSTNTrunkParses(t *testing.T) {
	c := mustParseProxy(t, withPSTN(proxyYAML, pstnTrunk))
	if got := c.SIP.Pstn.Address; got != "223.76.90.4:16060" {
		t.Errorf("Pstn.Address = %q", got)
	}
	if got := c.SIP.Pstn.Match.Host; got != "203.0.113.7" || c.SIP.Pstn.Match.Port != 16060 {
		t.Errorf("Pstn.Match = %s, want 203.0.113.7:16060", c.SIP.Pstn.Match)
	}
	if got := c.SIP.Pstn.Transport; got != "udp" {
		t.Errorf("Pstn.Transport = %q, want the udp default", got)
	}
	// The failure budgets default exactly like the trunk plane's
	// peer_cooldown: zero in the file means "the default", never "zero".
	if got := c.SIP.Pstn.AttemptTimeout.Std(); got != 32*time.Second {
		t.Errorf("AttemptTimeout = %s, want the 32s default", got)
	}
	if got := c.SIP.Pstn.Cooldown.Std(); got != 30*time.Second {
		t.Errorf("Cooldown = %s, want the 30s default", got)
	}
	// And absent stays absent: no phantom trunk, no phantom budgets.
	plain := mustParseProxy(t, proxyYAML)
	if plain.SIP.Pstn.Address != "" || !plain.SIP.Pstn.Match.IsZero() || plain.SIP.Pstn.Transport != "" ||
		plain.SIP.Pstn.AttemptTimeout != 0 || plain.SIP.Pstn.Cooldown != 0 ||
		len(plain.SIP.Pstn.Gateways) > 0 || len(plain.SIP.Pstn.Routes) > 0 {
		t.Errorf("SIP.Pstn not zero when the section is absent: %+v", plain.SIP.Pstn)
	}
}

// multiPSTN is a valid multi-gateway sip.pstn section for the proxyYAML
// shape: two named gateways and two routes (a mobile-number prefix rule and
// a catch-all whose to list doubles as the failover order). The route
// regexp is single-quoted YAML on purpose: a double-quoted "\d" is not a
// YAML escape and would not parse.
const multiPSTN = `  pstn:
    match: 203.0.113.7:16060
    gateways:
      gw-mobile:
        address: 223.76.90.4:16060
      gw-fixed:
        address: 223.76.90.5:16060
    routes:
      - match: '^1[3-9]\d{9}$'
        to: [gw-mobile]
      - to: [gw-fixed, gw-mobile]
`

// The multi-gateway shape parses: named gateways, per-number routes whose
// match compiles at validate time, and per-gateway transport defaulting to
// udp. Unwritten budgets get the same defaults as the alias shape.
func TestPSTNGatewaysParses(t *testing.T) {
	c := mustParseProxy(t, withPSTN(proxyYAML, multiPSTN))
	pstn := c.SIP.Pstn
	if pstn.Address != "" {
		t.Errorf("alias Address set in the multi shape: %q", pstn.Address)
	}
	if got := pstn.Match.String(); got != "203.0.113.7:16060" {
		t.Errorf("Match = %s", got)
	}
	if got := pstn.AttemptTimeout.Std(); got != 32*time.Second {
		t.Errorf("AttemptTimeout = %s, want the 32s default", got)
	}
	if got := pstn.Cooldown.Std(); got != 30*time.Second {
		t.Errorf("Cooldown = %s, want the 30s default", got)
	}
	if mobile := pstn.Gateways["gw-mobile"]; mobile == nil || mobile.Address != "223.76.90.4:16060" {
		t.Fatalf("gateway gw-mobile = %+v", pstn.Gateways["gw-mobile"])
	} else if got := mobile.Transport; got != "udp" {
		t.Errorf("gw-mobile transport = %q, want the udp default", got)
	}
	if fixed := pstn.Gateways["gw-fixed"]; fixed == nil || fixed.Address != "223.76.90.5:16060" || fixed.Transport != "udp" {
		t.Errorf("gateway gw-fixed = %+v", fixed)
	}
	if len(pstn.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(pstn.Routes))
	}
	// The mobile route compiles; the catch-all stays nil so the topology
	// builder can match it against every number.
	if re := pstn.Routes[0].CompiledMatch(); re == nil || !re.MatchString("13800138000") || re.MatchString("0281234567") {
		t.Errorf("route[0] regexp miscompiled from %q", pstn.Routes[0].Match)
	}
	if re := pstn.Routes[1].CompiledMatch(); re != nil {
		t.Errorf("catch-all route[1] compiled to %v, want nil", re)
	}
	if to := pstn.Routes[1].To; len(to) != 2 || to[0] != "gw-fixed" || to[1] != "gw-mobile" {
		t.Errorf("route[1] to = %v, want [gw-fixed gw-mobile]", to)
	}
}

// The multi shape also parses with an explicit attempt_timeout and with
// several catch-all routes — only the first one ever fires, but writing
// several is not a config error. The inline { address: ... } gateway form
// is exercised too, as that is the shape the examples document.
func TestPSTNGatewaysExplicitAndCatchalls(t *testing.T) {
	explicit := `  pstn:
    match: 203.0.113.7:16060
    attempt_timeout: 45s
    cooldown: 90s
    gateways:
      gw-a: { address: 223.76.90.4:16060 }
      gw-b: { address: 223.76.90.5:16060, transport: udp }
    routes:
      - to: [gw-a]
      - to: [gw-b, gw-a]
`
	c := mustParseProxy(t, withPSTN(proxyYAML, explicit))
	pstn := c.SIP.Pstn
	if got := pstn.AttemptTimeout.Std(); got != 45*time.Second {
		t.Errorf("AttemptTimeout = %s, want 45s", got)
	}
	if got := pstn.Cooldown.Std(); got != 90*time.Second {
		t.Errorf("Cooldown = %s, want 90s", got)
	}
	if len(pstn.Routes) != 2 || pstn.Routes[0].CompiledMatch() != nil || pstn.Routes[1].CompiledMatch() != nil {
		t.Fatalf("catch-all routes = %+v", pstn.Routes)
	}
	if g := pstn.Gateways["gw-b"]; g == nil || g.Address != "223.76.90.5:16060" || g.Transport != "udp" {
		t.Errorf("flow-style gateway gw-b = %+v", g)
	}
}

// multiUpstreams is a valid multi-FreeSWITCH sip.upstreams pool for the
// proxyYAML shape: two named nodes, the algorithm and cooldown left to their
// defaults, per-node transport left to its default too.
const multiUpstreams = `  upstreams:
    nodes:
      fs-a:
        address: 10.77.0.10:5060
      fs-b:
        address: 10.77.0.11:5060
`

// withUpstreams swaps the v1 upstream alias stanza for a sip.upstreams pool.
// The two shapes are mutually exclusive, so a config carries exactly one.
func withUpstreams(base, upstreamsSection string) string {
	return strings.Replace(base, "  upstream:\n    address: 10.77.0.10:5060\n    transport: udp\n", upstreamsSection, 1)
}

// The multi-switch pool parses and defaults like the alias: cooldown 30s
// (the passive penalty applies to BOTH shapes — with the alias synthesised
// as node "default", a zero window would disable it in production), the
// algorithm to hash-user, and every node's transport to udp. The pool alone
// enables the proxy plane: no alias required.
func TestUpstreamsParses(t *testing.T) {
	c := mustParseProxy(t, withUpstreams(proxyYAML, multiUpstreams))
	ups := c.SIP.Upstreams
	if c.SIP.Upstream.Address != "" {
		t.Errorf("alias Address set in the pool shape: %q", c.SIP.Upstream.Address)
	}
	if !c.ProxyEnabled() {
		t.Fatal("ProxyEnabled() = false with only sip.upstreams.nodes set")
	}
	if got := ups.Algorithm; got != "hash-user" {
		t.Errorf("Algorithm = %q, want the hash-user default", got)
	}
	if got := ups.Cooldown.Std(); got != 30*time.Second {
		t.Errorf("Cooldown = %s, want the 30s default", got)
	}
	if len(ups.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(ups.Nodes))
	}
	for name, want := range map[string]string{"fs-a": "10.77.0.10:5060", "fs-b": "10.77.0.11:5060"} {
		n := ups.Nodes[name]
		if n == nil || n.Address != want || n.Transport != "udp" {
			t.Errorf("node %s = %+v, want address %s transport udp", name, n, want)
		}
	}

	// The alias shape gets the same cooldown default (D8): its synthesised
	// node "default" is penalized exactly like a pool node.
	alias := mustParseProxy(t, proxyYAML)
	if got := alias.SIP.Upstreams.Cooldown.Std(); got != 30*time.Second {
		t.Errorf("alias Cooldown = %s, want the 30s default", got)
	}
	if alias.SIP.Upstreams.Algorithm != "" || len(alias.SIP.Upstreams.Nodes) != 0 {
		t.Errorf("alias config grew pool fields: %+v", alias.SIP.Upstreams)
	}
	// And an alias-only config keeps a fully zero pool, so "is the pool
	// configured" stays decidable.
	if got := alias.SIP.Upstreams.Algorithm; got != "" {
		t.Errorf("alias config grew an algorithm: %q", got)
	}
	if len(alias.SIP.Upstreams.Nodes) != 0 {
		t.Errorf("alias config grew nodes: %+v", alias.SIP.Upstreams.Nodes)
	}
}

func TestUpstreamsValidationErrors(t *testing.T) {
	// replaceUps rewrites multiUpstreams then swaps it into the proxy YAML.
	replaceUps := func(edit func(string) string) string {
		return withUpstreams(proxyYAML, edit(multiUpstreams))
	}
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{
			"alias and pool together",
			func(s string) string {
				return strings.Replace(s, "  upstreams:\n", "  upstream:\n    address: 10.77.0.10:5060\n  upstreams:\n", 1)
			},
			"sip.upstreams: sip.upstream.address and sip.upstreams.nodes are mutually exclusive",
		},
		{
			"unsupported algorithm",
			func(s string) string {
				return strings.Replace(s, "  upstreams:\n", "  upstreams:\n    algorithm: round-robin\n", 1)
			},
			`sip.upstreams.algorithm: only "hash-user" is supported, got "round-robin"`,
		},
		{
			"node missing address",
			func(s string) string {
				return strings.Replace(s, "      fs-a:\n        address: 10.77.0.10:5060\n", "      fs-a:\n        transport: udp\n", 1)
			},
			"sip.upstreams.nodes.fs-a.address: required",
		},
		{
			"node address not host:port",
			func(s string) string { return strings.Replace(s, "10.77.0.10:5060", "10.77.0.10", 1) },
			`sip.upstreams.nodes.fs-a.address: "10.77.0.10" is not "host:port"`,
		},
		{
			"node address bad port",
			func(s string) string { return strings.Replace(s, "10.77.0.10:5060", "10.77.0.10:99999", 1) },
			"sip.upstreams.nodes.fs-a.address: bad port",
		},
		{
			"node transport tcp",
			func(s string) string {
				return strings.Replace(s, "      fs-b:\n        address: 10.77.0.11:5060\n", "      fs-b:\n        address: 10.77.0.11:5060\n        transport: tcp\n", 1)
			},
			`sip.upstreams.nodes.fs-b.transport: only "udp" is supported, got "tcp"`,
		},
		{
			"negative cooldown",
			func(s string) string {
				return strings.Replace(s, "  upstreams:\n", "  upstreams:\n    cooldown: -1m\n", 1)
			},
			"sip.upstreams.cooldown: must not be negative, got -1m0s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(replaceUps(tt.edit)))
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

// A sip.pstn match must not name ANY upstream node, not just the alias: the
// classification keys on the match address, so naming a pool node would
// shadow the traffic that node carries for everything else.
func TestPSTNMatchRejectsPoolNode(t *testing.T) {
	// The pstn stanza goes after the pool block (the alias stanza withPSTN
	// keys on is not there any more).
	poolYAML := strings.Replace(withUpstreams(proxyYAML, multiUpstreams),
		"      fs-b:\n        address: 10.77.0.11:5060\n",
		"      fs-b:\n        address: 10.77.0.11:5060\n"+pstnTrunk, 1)
	yaml := strings.Replace(poolYAML, "match: 203.0.113.7:16060", "match: 10.77.0.11:5060", 1)
	if _, err := Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "sip.pstn.match: must not name the upstream") {
		t.Fatalf("want the must-not-name-the-upstream error, got %v", err)
	}
	// A match naming nothing upstream is fine in the pool shape.
	if _, err := Parse([]byte(poolYAML)); err != nil {
		t.Fatalf("valid pool + pstn config rejected: %v", err)
	}
	// The alias collision keeps the same message (and the same check).
	aliasYAML := strings.Replace(withPSTN(proxyYAML, pstnTrunk), "match: 203.0.113.7:16060", "match: 10.77.0.10:5060", 1)
	if _, err := Parse([]byte(aliasYAML)); err == nil || !strings.Contains(err.Error(), "sip.pstn.match: must not name the upstream") {
		t.Fatalf("alias: want the must-not-name-the-upstream error, got %v", err)
	}
}

func TestPSTNMultiValidationErrors(t *testing.T) {
	// replacePSTN rewrites multiPSTN then swaps it into the proxy YAML.
	replacePSTN := func(edit func(string) string) string {
		return withPSTN(proxyYAML, edit(multiPSTN))
	}
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{
			"address alias combined with gateways",
			func(s string) string {
				return strings.Replace(s, "  pstn:\n    match:", "  pstn:\n    address: 223.76.90.9:16060\n    match:", 1)
			},
			"address and gateways are mutually exclusive",
		},
		{
			"gateways without routes",
			func(s string) string {
				s = strings.Replace(s, "    routes:\n", "", 1)
				return strings.Replace(s, "      - match: '^1[3-9]\\d{9}$'\n        to: [gw-mobile]\n      - to: [gw-fixed, gw-mobile]\n", "", 1)
			},
			"sip.pstn.routes: at least one route required",
		},
		{
			"gateways without match",
			func(s string) string { return strings.Replace(s, "    match: 203.0.113.7:16060\n", "", 1) },
			"sip.pstn.match: required with sip.pstn.gateways",
		},
		{
			"gateway missing address",
			func(s string) string {
				return strings.Replace(s, "      gw-mobile:\n        address: 223.76.90.4:16060\n", "      gw-mobile:\n        transport: udp\n", 1)
			},
			"sip.pstn.gateways.gw-mobile.address: required",
		},
		{
			"gateway address not host:port",
			func(s string) string {
				return strings.Replace(s, "223.76.90.4:16060", "223.76.90.4", 1)
			},
			`sip.pstn.gateways.gw-mobile.address: "223.76.90.4" is not "host:port"`,
		},
		{
			"gateway address bad port",
			func(s string) string {
				return strings.Replace(s, "223.76.90.4:16060", "223.76.90.4:99999", 1)
			},
			"sip.pstn.gateways.gw-mobile.address: bad port",
		},
		{
			"gateway transport tcp",
			func(s string) string {
				return strings.Replace(s, "      gw-mobile:\n        address: 223.76.90.4:16060\n", "      gw-mobile:\n        address: 223.76.90.4:16060\n        transport: tcp\n", 1)
			},
			`sip.pstn.gateways.gw-mobile.transport: only "udp" is supported`,
		},
		{
			"route with empty to",
			func(s string) string { return strings.Replace(s, "to: [gw-mobile]\n", "to: []\n", 1) },
			"sip.pstn.routes[0]: to: at least one gateway required",
		},
		{
			"route naming an unknown gateway",
			func(s string) string {
				return strings.Replace(s, "to: [gw-fixed, gw-mobile]", "to: [gw-fixed, gw-ghost]", 1)
			},
			`sip.pstn.routes[1]: to: unknown gateway "gw-ghost"`,
		},
		{
			"route with a bad regexp",
			func(s string) string { return strings.Replace(s, "'^1[3-9]\\d{9}$'", "'['", 1) },
			"sip.pstn.routes[0]: match: error parsing regexp",
		},
		{
			"negative attempt_timeout",
			func(s string) string {
				return strings.Replace(s, "  pstn:\n    match:", "  pstn:\n    attempt_timeout: -5s\n    match:", 1)
			},
			"sip.pstn.attempt_timeout: must not be negative, got -5s",
		},
		{
			"negative cooldown",
			func(s string) string {
				return strings.Replace(s, "  pstn:\n    match:", "  pstn:\n    cooldown: -1m\n    match:", 1)
			},
			"sip.pstn.cooldown: must not be negative, got -1m0s",
		},
		{
			"routes without gateways",
			func(s string) string { return "  pstn:\n    routes:\n      - to: [gw-mobile]\n" },
			"sip.pstn.routes: require sip.pstn.gateways",
		},
		{
			"budget without either shape",
			func(s string) string { return "  pstn:\n    attempt_timeout: 5s\n" },
			"sip.pstn: address or gateways required",
		},
		{
			"match names the private socket in the multi shape",
			func(s string) string {
				return strings.Replace(s, "match: 203.0.113.7:16060", "match: 10.77.0.2:5060", 1)
			},
			"sip.pstn.match: must not name the SBC's private SIP address",
		},
		{
			"match names the upstream in the multi shape",
			func(s string) string {
				return strings.Replace(s, "match: 203.0.113.7:16060", "match: 10.77.0.10:5060", 1)
			},
			"sip.pstn.match: must not name the upstream",
		},
		{
			"top-level transport tcp in the multi shape",
			func(s string) string {
				return strings.Replace(s, "  pstn:\n    match:", "  pstn:\n    transport: tcp\n    match:", 1)
			},
			`sip.pstn.transport: only "udp" is supported`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(replacePSTN(tt.edit)))
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

// A private IP must never be what public clients are told to send to, and
// vice versa: the two advertised planes are resolved from independent
// config and must not bleed into one another.
func TestProxyAdvertisedPlanesAreIndependent(t *testing.T) {
	c := mustParseProxy(t, proxyYAML)
	if c.PublicRTPAdvertisedIP() == c.PrivateRTPAdvertisedIP() {
		t.Fatal("public and private media addresses collapsed to one value")
	}
}

func TestProxyValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{
			"no upstream but listeners configured",
			func(s string) string { return strings.Replace(s, "    address: 10.77.0.10:5060\n", "", 1) },
			"sip.upstream: required to enable the edge proxy",
		},
		{
			"upstream transport tcp",
			func(s string) string { return strings.Replace(s, "transport: udp", "transport: tcp", 1) },
			"only \"udp\" is supported",
		},
		{
			"wildcard public bind with no advertised ip",
			func(s string) string { return strings.Replace(s, "    advertised_ip: 203.0.113.7\n", "", 1) },
			"network.public.advertised_ip: required",
		},
		{
			"overlapping media ranges",
			func(s string) string { return strings.Replace(s, "    port_min: 40000", "    port_min: 35000", 1) },
			"overlap",
		},
		{
			"public range inverted",
			func(s string) string { return strings.Replace(s, "    port_max: 39999", "    port_max: 30000", 1) },
			"port_min must be less than port_max",
		},
		{
			"privileged media port",
			func(s string) string { return strings.Replace(s, "    port_min: 30000", "    port_min: 100", 1) },
			"port_min: must be 1024-65535",
		},
		{
			"webrtc without websocket signaling",
			func(s string) string {
				s = strings.Replace(s, "    ws:\n      enabled: true\n      bind: 0.0.0.0:18080\n", "", 1)
				return strings.Replace(s, "    wss:\n      enabled: true\n      bind: 0.0.0.0:18443\n", "", 1)
			},
			"requires sip.public.ws or sip.public.wss",
		},
		{
			"webrtc ice mode full",
			func(s string) string { return strings.Replace(s, "ice_mode: lite", "ice_mode: full", 1) },
			"only \"lite\" is supported",
		},
		{
			"rtcp mux disabled",
			func(s string) string { return strings.Replace(s, "rtcp_mux: true", "rtcp_mux: false", 1) },
			"webrtc.rtcp_mux: must be true",
		},
		{
			"duplicate ws/wss bind",
			func(s string) string { return strings.Replace(s, "bind: 0.0.0.0:18443", "bind: 0.0.0.0:18080", 1) },
			"already bound by",
		},
		{
			"bad upstream address",
			func(s string) string { return strings.Replace(s, "address: 10.77.0.10:5060", "address: 10.77.0.10", 1) },
			"is not \"host:port\"",
		},
		{
			"pstn transport tcp",
			func(s string) string { return withPSTN(s, pstnTrunk+"    transport: tcp\n") },
			`sip.pstn.transport: only "udp" is supported`,
		},
		{
			"pstn address not host:port",
			func(s string) string {
				s = withPSTN(s, pstnTrunk)
				return strings.Replace(s, "223.76.90.4:16060", "223.76.90.4", 1)
			},
			`is not "host:port"`,
		},
		{
			"pstn address bad port",
			func(s string) string {
				s = withPSTN(s, pstnTrunk)
				return strings.Replace(s, "223.76.90.4:16060", "223.76.90.4:99999", 1)
			},
			"sip.pstn.address: bad port",
		},
		{
			"pstn match names the private socket",
			func(s string) string {
				s = withPSTN(s, pstnTrunk)
				return strings.Replace(s, "match: 203.0.113.7:16060", "match: 10.77.0.2:5060", 1)
			},
			"sip.pstn.match: must not name the SBC's private SIP address",
		},
		{
			"pstn match names the upstream",
			func(s string) string {
				s = withPSTN(s, pstnTrunk)
				return strings.Replace(s, "match: 203.0.113.7:16060", "match: 10.77.0.10:5060", 1)
			},
			"sip.pstn.match: must not name the upstream",
		},
		{
			"pstn without upstream",
			func(s string) string {
				s = withPSTN(s, pstnTrunk)
				return strings.Replace(s, "    address: 10.77.0.10:5060\n", "", 1)
			},
			"required to enable the edge proxy",
		},
		{
			"pstn without public udp",
			func(s string) string {
				s = withPSTN(s, pstnTrunk)
				return strings.Replace(s, "enabled: true\n      bind: 0.0.0.0:16060",
					"enabled: false\n      bind: 0.0.0.0:16060", 1)
			},
			"sip.pstn: requires sip.public.udp.enabled",
		},
		{
			"pstn match without address",
			func(s string) string {
				return withPSTN(s, "  pstn:\n    match: 203.0.113.7:16060\n")
			},
			"sip.pstn.match: requires sip.pstn.address",
		},
		{
			"pstn address without match",
			func(s string) string {
				return withPSTN(s, "  pstn:\n    address: 223.76.90.4:16060\n")
			},
			"sip.pstn.match: required with sip.pstn.address",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.edit(proxyYAML)))
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

// The trunk B2BUA plane and the edge proxy must be able to coexist in one
// file; the trunk's own media range participates in the overlap check.
func TestProxyAndTrunkCoexist(t *testing.T) {
	both := proxyYAML + `
listen:
  sip: [udp://10.77.0.2:5080]
  media:
    port_range: 20000-20999
peers:
  carrier:
    address: 10.9.0.1:5060
    allowed_ips: [10.9.0.0/16]
routes:
  - name: out
    from: carrier
    to: [carrier]
`
	c := mustParseProxy(t, both)
	if !c.ProxyEnabled() {
		t.Error("proxy plane should still be enabled")
	}
	if len(c.Peers) != 1 {
		t.Error("trunk peers lost")
	}
}

func TestProxyTrunkMediaRangeOverlapRejected(t *testing.T) {
	both := proxyYAML + `
listen:
  sip: [udp://10.77.0.2:5080]
  media:
    port_range: 30500-30999
peers:
  carrier:
    address: 10.9.0.1:5060
    allowed_ips: [10.9.0.0/16]
routes:
  - name: out
    from: carrier
    to: [carrier]
`
	if _, err := Parse([]byte(both)); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("want overlap error, got %v", err)
	}
}

// A trunk-only config must be entirely unaffected by the new sections.
func TestTrunkOnlyConfigUnaffected(t *testing.T) {
	c := mustParseProxy(t, `
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
`)
	if c.ProxyEnabled() {
		t.Error("ProxyEnabled() should be false without sip.upstream")
	}
	if len(c.PublicSIPListeners()) != 0 {
		t.Error("no public listeners expected")
	}
}

func TestHostPortParse(t *testing.T) {
	var h HostPort
	if err := h.UnmarshalYAML([]byte("10.0.0.1:5060")); err != nil {
		t.Fatal(err)
	}
	if h.Host != "10.0.0.1" || h.Port != 5060 {
		t.Fatalf("got %+v", h)
	}
	if h.String() != "10.0.0.1:5060" {
		t.Errorf("String() = %s", h.String())
	}
	for _, bad := range []string{"10.0.0.1", "10.0.0.1:0", "10.0.0.1:99999", "10.0.0.1:abc"} {
		var h HostPort
		if err := h.UnmarshalYAML([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// audit: P2-CFG-010
// validateProxy has no "bind required" check for the public listeners or
// the private socket, because defaults always fill them while the proxy is
// on. This pins that invariant: if a default is ever dropped, an unbound
// listener must not slip through validation silently.
func TestProxyDefaultsAlwaysFillBinds(t *testing.T) {
	src := `
network:
  public:
    bind_ip: 203.0.113.7
  private:
    bind_ip: 10.77.0.2
sip:
  public:
    udp: { enabled: true }
    ws: { enabled: true }
    wss: { enabled: true, cert_file: c.pem, key_file: k.pem }
  upstream:
    address: 10.77.0.10:5060
rtp:
  public: { port_min: 30000, port_max: 30999 }
  private: { port_min: 40000, port_max: 40999 }
`
	c := mustParseProxy(t, src)
	for _, l := range c.PublicSIPListeners() {
		if l.Bind.IsZero() {
			t.Errorf("sip.public.%s: bind left empty by defaults", l.Transport)
		}
	}
	if c.SIP.Private.Bind.IsZero() {
		t.Error("sip.private.bind left empty by defaults")
	}
	want := map[string]string{"udp": "203.0.113.7:5060", "ws": "203.0.113.7:5066", "wss": "203.0.113.7:5061"}
	for _, l := range c.PublicSIPListeners() {
		if got := l.Bind.String(); got != want[l.Transport] {
			t.Errorf("sip.public.%s.bind = %s, want %s", l.Transport, got, want[l.Transport])
		}
	}
	if got := c.SIP.Private.Bind.String(); got != "10.77.0.2:5060" {
		t.Errorf("sip.private.bind = %s, want 10.77.0.2:5060", got)
	}
}

// audit: P2-CFG-004
// With both network binds left as wildcards, the default public UDP bind
// and the default private bind are both 0.0.0.0:5060: `run` cannot bind
// the second, so `check` must reject it. Also covers the admin API sharing
// a TCP port with a ws listener.
func TestProxySocketCollisionsRejected(t *testing.T) {
	defaults := `
network:
  public: { bind_ip: 0.0.0.0, advertised_ip: 203.0.113.7 }
  private: { bind_ip: 0.0.0.0, advertised_ip: 10.77.0.2 }
sip:
  public:
    udp: { enabled: true }
  upstream:
    address: 10.77.0.10:5060
rtp:
  public: { port_min: 30000, port_max: 30999 }
  private: { port_min: 40000, port_max: 40999 }
`
	_, err := Parse([]byte(defaults))
	if err == nil || !strings.Contains(err.Error(), "sip.private.bind: udp/0.0.0.0:5060 already bound by sip.public.udp.bind") {
		t.Errorf("default public/private binds collide; got %v", err)
	}

	admin := proxyYAML + `
admin:
  listen: 127.0.0.1:18080
  auth: { username: a, password_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" }
`
	_, err = Parse([]byte(admin))
	if err == nil || !strings.Contains(err.Error(), "admin.listen: tcp/127.0.0.1:18080 already bound by sip.public.ws.bind") {
		t.Errorf("admin on the ws port; got %v", err)
	}

	// udp and tcp on one port are two sockets, and two specific addresses
	// on one port do not collide.
	ok := strings.Replace(proxyYAML, "      bind: 0.0.0.0:18080\n", "      bind: 0.0.0.0:16060\n", 1)
	if _, err := Parse([]byte(ok)); err != nil {
		t.Errorf("udp and ws on the same port number must not collide: %v", err)
	}
}

// audit: P2-CFG-009
// An edge media plane must hold at least one RTP/RTCP pair.
func TestProxyRTPPlaneHoldsOnePair(t *testing.T) {
	src := strings.Replace(proxyYAML, "    port_min: 30000\n    port_max: 39999\n", "    port_min: 30001\n    port_max: 30002\n", 1)
	_, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "rtp.public: 30001-30002 holds no RTP/RTCP pair") {
		t.Errorf("a pair-less range validated: %v", err)
	}
}
