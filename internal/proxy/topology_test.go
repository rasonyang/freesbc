package proxy

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
)

const topoYAML = `
network:
  public:
    bind_ip: 0.0.0.0
    advertised_ip: 203.0.113.7
  private:
    bind_ip: 10.77.0.2
sip:
  public:
    udp: {enabled: true, bind: "0.0.0.0:16060"}
    ws:  {enabled: true, bind: "0.0.0.0:18080"}
  private:
    bind: "10.77.0.2:16060"
  upstream:
    address: 10.77.0.10:5060
rtp:
  public:  {bind_ip: 0.0.0.0, advertised_ip: 203.0.113.7, port_min: 30000, port_max: 30999}
  private: {bind_ip: 10.77.0.2, port_min: 40000, port_max: 40999}
`

func testTopology(t *testing.T) *topology {
	t.Helper()
	cfg, err := config.Parse([]byte(topoYAML))
	if err != nil {
		t.Fatal(err)
	}
	topo, err := buildTopology(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

func TestTopologySides(t *testing.T) {
	topo := testTopology(t)
	udp, ok := topo.publicSide("udp")
	if !ok {
		t.Fatal("no udp public side")
	}
	if udp.advIP.String() != "203.0.113.7" || udp.advPort != 16060 {
		t.Errorf("udp side = %v:%d", udp.advIP, udp.advPort)
	}
	if udp.laddr.Port != 16060 {
		t.Errorf("udp laddr not pinned: %+v", udp.laddr)
	}
	ws, ok := topo.publicSide("ws")
	if !ok {
		t.Fatal("no ws public side")
	}
	// A WebSocket has no outbound socket to pin: the connection is found
	// by the client's remote address instead.
	if ws.laddr.IP != nil {
		t.Errorf("ws side pinned a local socket: %+v", ws.laddr)
	}
	if _, ok := topo.publicSide("wss"); ok {
		t.Error("wss side exists though it is not enabled")
	}
	if topo.private.advIP.String() != "10.77.0.2" {
		t.Errorf("private side = %v", topo.private.advIP)
	}
}

func TestSideURIAndRecordRoute(t *testing.T) {
	topo := testTopology(t)
	ws, _ := topo.publicSide("ws")
	u := ws.uri()
	if !strings.Contains(u.String(), "transport=ws") {
		t.Errorf("ws contact URI missing transport: %s", u.String())
	}
	rr := ws.recordRoute().Value()
	if !strings.Contains(rr, "lr") || !strings.Contains(rr, "transport=ws") {
		t.Errorf("ws Record-Route = %s", rr)
	}
	udp, _ := topo.publicSide("udp")
	udpURI := udp.uri()
	if strings.Contains(udpURI.String(), "transport") {
		t.Errorf("udp contact URI should not name a transport: %s", udpURI.String())
	}
	// rport is requested on UDP (it is what makes NAT traversal work) and
	// meaningless on a WebSocket.
	if _, ok := udp.via("z9hG4bKtest").Params.Get("rport"); !ok {
		t.Error("udp Via missing rport")
	}
	if _, ok := ws.via("z9hG4bKtest").Params.Get("rport"); ok {
		t.Error("ws Via should not request rport")
	}
}

func TestTopologyIsSelf(t *testing.T) {
	topo := testTopology(t)
	for _, u := range []sip.Uri{
		{Host: "203.0.113.7", Port: 16060},
		{Host: "203.0.113.7", Port: 18080},
		{Host: "10.77.0.2", Port: 16060},
	} {
		if !topo.isSelf(u) {
			t.Errorf("%v not recognised as self", u)
		}
	}
	for _, u := range []sip.Uri{
		{Host: "203.0.113.7", Port: 5060},  // right host, wrong port
		{Host: "203.0.113.8", Port: 16060}, // wrong host
		{Host: "example.com", Port: 16060}, // not an IP at all
		{Host: "10.77.0.10", Port: 5060},   // the upstream, not us
	} {
		if topo.isSelf(u) {
			t.Errorf("%v wrongly recognised as self", u)
		}
	}
}

func TestTopologyFromUpstream(t *testing.T) {
	topo := testTopology(t)
	if !topo.fromUpstream(netip.MustParseAddr("10.77.0.10")) {
		t.Error("upstream address not recognised")
	}
	// The port is deliberately not compared: FreeSWITCH may source from an
	// ephemeral port while listening on its configured one.
	if !topo.fromUpstream(netip.MustParseAddr("::ffff:10.77.0.10").Unmap()) {
		t.Error("IPv4-mapped upstream address not recognised")
	}
	if topo.fromUpstream(netip.MustParseAddr("203.0.113.99")) {
		t.Error("a public address was treated as upstream")
	}
}

// The upstream must be a literal: resolving a name for the private leg
// would let a poisoned resolver redirect it.
func TestBuildTopologyRejectsHostname(t *testing.T) {
	cfg, err := config.Parse([]byte(strings.Replace(topoYAML, "address: 10.77.0.10:5060", "address: fs.example.com:5060", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildTopology(cfg); err == nil {
		t.Fatal("a hostname upstream was accepted")
	}
}

// pstnTopoBlock is a valid sip.pstn section (v1 alias shape) for the
// topoYAML config. The match address must not collide with anything
// FreeSWITCH already talks to for other traffic: the private socket is
// 10.77.0.2:16060 and the upstream is 10.77.0.10:5060, so 10.77.0.2:16061
// is free.
const pstnTopoBlock = "  pstn:\n    address: 223.76.90.4:16060\n    match: 10.77.0.2:16061\n"

// pstnMultiTopoBlock is a valid sip.pstn section in the multi shape: two
// gateways and two routes (a mobile prefix and a catch-all). Single-quoted
// YAML keeps the regexp escapes alive.
const pstnMultiTopoBlock = "  pstn:\n" +
	"    match: 10.77.0.2:16061\n" +
	"    gateways:\n" +
	"      gw-mobile:\n        address: 223.76.90.4:16060\n" +
	"      gw-fixed:\n        address: 223.76.90.5:16060\n" +
	"    routes:\n" +
	"      - match: '^1[3-9]\\d{9}$'\n        to: [gw-mobile]\n" +
	"      - to: [gw-fixed, gw-mobile]\n"

// testPSTNTopology builds the topology for a pstn section block.
func testPSTNTopology(t *testing.T, pstnBlock string) *topology {
	t.Helper()
	cfg, err := config.Parse([]byte(strings.Replace(topoYAML,
		"    address: 10.77.0.10:5060\n", "    address: 10.77.0.10:5060\n"+pstnBlock, 1)))
	if err != nil {
		t.Fatal(err)
	}
	topo, err := buildTopology(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

// The v1 alias converges on the multi runtime model at build time: one
// gateway synthesised under the name "default" plus a catch-all route
// naming it — so the single-gateway config and the equivalent multi config
// behave identically by construction.
func TestTopologyPSTNAliasSynthesised(t *testing.T) {
	topo := testPSTNTopology(t, pstnTopoBlock)
	if !topo.pstnEnabled() {
		t.Fatal("pstnEnabled() = false with sip.pstn configured")
	}
	if topo.pstn.match.Host != "10.77.0.2" || topo.pstn.match.Port != 16061 {
		t.Errorf("pstn match = %v, want 10.77.0.2:16061", topo.pstn.match)
	}
	gw, ok := topo.pstn.gateways["default"]
	if !ok {
		t.Fatalf("alias gateway not synthesised: %+v", topo.pstn.gateways)
	}
	if got := gw.addr.String(); got != "223.76.90.4:16060" {
		t.Errorf("gateway addr = %s", got)
	}
	if gw.host != "223.76.90.4:16060" {
		t.Errorf("gateway host = %q", gw.host)
	}
	// The synthesised catch-all resolves EVERY number to the alias gateway.
	names, ok := resolvePSTNRoute(topo.pstn.routes, "13800138000")
	if !ok || len(names) != 1 || names[0] != "default" {
		t.Errorf("resolvePSTNRoute = %v, %v; want [default]", names, ok)
	}

	// A topology without sip.pstn must report the trunk off — the empty
	// gateways map is what the classification tests rely on.
	plain := testTopology(t)
	if plain.pstnEnabled() {
		t.Error("pstnEnabled() = true without sip.pstn configured")
	}
	if len(plain.pstn.gateways) != 0 || len(plain.pstn.routes) != 0 {
		t.Errorf("plain topology grew a pstn model: %+v", plain.pstn)
	}
}

// The multi shape resolves as configured: per-name gateways, routes in
// evaluation order with their regexps compiled, and the failover list the
// caller will dial.
func TestTopologyPSTNMulti(t *testing.T) {
	topo := testPSTNTopology(t, pstnMultiTopoBlock)
	if !topo.pstnEnabled() {
		t.Fatal("pstnEnabled() = false with sip.pstn configured")
	}
	if len(topo.pstn.gateways) != 2 {
		t.Fatalf("gateways = %d, want 2", len(topo.pstn.gateways))
	}
	if g := topo.pstn.gateways["gw-mobile"]; g.addr.String() != "223.76.90.4:16060" || g.host != "223.76.90.4:16060" {
		t.Errorf("gw-mobile = %+v", g)
	}
	if g := topo.pstn.gateways["gw-fixed"]; g.addr.String() != "223.76.90.5:16060" || g.host != "223.76.90.5:16060" {
		t.Errorf("gw-fixed = %+v", g)
	}
	if len(topo.pstn.routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(topo.pstn.routes))
	}
	r0 := topo.pstn.routes[0]
	if r0.re == nil || !r0.re.MatchString("13800138000") || r0.re.MatchString("0281234567") {
		t.Errorf("route[0] regexp = %v", r0.re)
	}
	if len(r0.targets) != 1 || r0.targets[0] != "gw-mobile" {
		t.Errorf("route[0] targets = %v", r0.targets)
	}
	r1 := topo.pstn.routes[1]
	if r1.re != nil {
		t.Errorf("catch-all route[1] compiled to %v, want nil", r1.re)
	}
	if len(r1.targets) != 2 || r1.targets[0] != "gw-fixed" || r1.targets[1] != "gw-mobile" {
		t.Errorf("route[1] targets = %v", r1.targets)
	}
}

// Every gateway address is resolved like the upstream: no DNS. A hostname
// would make the carrier leg resolve per dial — or, if the name is gone,
// silently fail every bridged call. (All rows still PASS config validation
// — a host:port name is a legal config shape — and fail only here, at
// topology build.)
func TestBuildTopologyRejectsPSTNHostnames(t *testing.T) {
	tests := []struct {
		name  string
		block string // pstn section to start from (alias or multi shape)
		// from/to break one field of the otherwise valid block.
		from, to, want string
	}{
		{
			"alias address",
			pstnTopoBlock,
			"address: 223.76.90.4:16060", "address: gw.example.com:16060",
			"sip.pstn.address must be a literal IP:port, got gw.example.com",
		},
		{
			"alias match",
			pstnTopoBlock,
			"match: 10.77.0.2:16061", "match: pstn.example.com:16061",
			"sip.pstn.match must be a literal IP, got pstn.example.com",
		},
		{
			"multi gateway address names a host",
			pstnMultiTopoBlock,
			"address: 223.76.90.4:16060\n", "address: gw-mobile.example.com:16060\n",
			"sip.pstn.gateways.gw-mobile must be a literal IP:port, got gw-mobile.example.com",
		},
		{
			"multi match",
			pstnMultiTopoBlock,
			"match: 10.77.0.2:16061\n", "match: pstn.example.com:16061\n",
			"sip.pstn.match must be a literal IP, got pstn.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := strings.Replace(topoYAML, "    address: 10.77.0.10:5060\n",
				"    address: 10.77.0.10:5060\n"+tt.block, 1)
			cfg, err := config.Parse([]byte(strings.Replace(yaml, tt.from, tt.to, 1)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildTopology(cfg); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

// resolvePSTNRoute is the pure first-wins route engine: the first route
// whose regexp matches the called number wins; a nil regexp is a catch-all;
// no hit means the call is not a PSTN call.
func TestResolvePSTNRoute(t *testing.T) {
	mobile := pstnRoute{re: regexp.MustCompile(`^1[3-9]\d{9}$`), targets: []string{"gw-mobile"}}
	fixed := pstnRoute{re: regexp.MustCompile(`^0\d+$`), targets: []string{"gw-fixed"}}
	catchAll := pstnRoute{targets: []string{"gw-backup"}}
	cases := []struct {
		name   string
		routes []pstnRoute
		user   string
		want   []string
		ok     bool
	}{
		{"prefix hits before a later catch-all",
			[]pstnRoute{mobile, fixed, catchAll}, "13912345678", []string{"gw-mobile"}, true},
		{"second prefix",
			[]pstnRoute{mobile, fixed, catchAll}, "0281234567", []string{"gw-fixed"}, true},
		{"catch-all takes what no prefix matched",
			[]pstnRoute{mobile, fixed, catchAll}, "10086", []string{"gw-backup"}, true},
		{"first match wins, not the longest",
			[]pstnRoute{{re: regexp.MustCompile(`^1`), targets: []string{"one"}},
				{re: regexp.MustCompile(`^1[3-9]`), targets: []string{"two"}}},
			"1391", []string{"one"}, true},
		{"no match at all",
			[]pstnRoute{mobile, fixed}, "not-a-number", nil, false},
		{"empty route list never matches",
			nil, "1391", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := resolvePSTNRoute(c.routes, c.user)
			if ok != c.ok || (ok && (len(got) != len(c.want) || got[0] != c.want[0])) {
				t.Errorf("resolvePSTNRoute(%v) = %v, %v; want %v, %v", c.user, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestSameAddr(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"10.0.0.1:5060", "10.0.0.1:5060", true},
		{"0.0.0.0:5060", "10.0.0.1:5060", true}, // wildcard listener
		{"10.0.0.1:5060", "0.0.0.0:5060", true},
		{"10.0.0.1:5060", "10.0.0.2:5060", false},
		{"0.0.0.0:5060", "10.0.0.1:5061", false}, // different port
	}
	for _, c := range cases {
		if got := sameAddr(c.a, c.b); got != c.want {
			t.Errorf("sameAddr(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// isSelfVia is what stops the proxy from popping a Via that is not its
// own — RFC 3261 §16.7 step 3.
func TestTopologyIsSelfVia(t *testing.T) {
	topo := testTopology(t)
	self := []*sip.ViaHeader{
		{Transport: "UDP", Host: "203.0.113.7", Port: 16060},
		{Transport: "WS", Host: "203.0.113.7", Port: 18080},
		{Transport: "UDP", Host: "10.77.0.2", Port: 16060},
	}
	for _, v := range self {
		if !topo.isSelfVia(v) {
			t.Errorf("%s:%d not recognised as our own Via", v.Host, v.Port)
		}
	}
	notSelf := []*sip.ViaHeader{
		{Transport: "UDP", Host: "203.0.113.7", Port: 5060}, // right host, wrong port
		{Transport: "UDP", Host: "10.77.0.10", Port: 5060},  // the upstream
		{Transport: "UDP", Host: "198.51.100.9", Port: 5060},
		{Transport: "UDP", Host: "phone.example", Port: 5060}, // not an IP
		nil,
	}
	for _, v := range notSelf {
		if topo.isSelfVia(v) {
			t.Errorf("%v wrongly recognised as our own Via", v)
		}
	}
	// A Via with no port falls back to the transport's default, which must
	// not accidentally match one of our listeners.
	if topo.isSelfVia(&sip.ViaHeader{Transport: "UDP", Host: "203.0.113.7"}) {
		t.Error("a portless Via matched a listener on a non-default port")
	}
}
