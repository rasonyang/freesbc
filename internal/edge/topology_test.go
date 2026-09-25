package edge

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
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
    udp: {enabled: true, bind: "203.0.113.7:16060"}
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

// multiUpstreamBlock replaces topoYAML's v1 alias stanza with a three-node
// pool: enough nodes for the hash to spread over and for a cooled node to
// have alternatives.
const multiUpstreamBlock = `  upstreams:
    nodes:
      fs-a: { address: 10.77.0.10:5060 }
      fs-b: { address: 10.77.0.11:5060 }
      fs-c: { address: 10.77.0.12:5060 }
`

func testMultiTopology(t *testing.T) *topology {
	t.Helper()
	cfg, err := config.Parse([]byte(strings.Replace(topoYAML,
		"  upstream:\n    address: 10.77.0.10:5060\n", multiUpstreamBlock, 1)))
	if err != nil {
		t.Fatal(err)
	}
	topo, err := buildTopology(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return topo
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

	// The trust decision is a set over the WHOLE pool: any switch in it may
	// source a request, and a node that is not in it is not trusted.
	multi := testMultiTopology(t)
	for _, ip := range []string{"10.77.0.10", "10.77.0.11", "10.77.0.12", "::ffff:10.77.0.12"} {
		if !multi.fromUpstream(netip.MustParseAddr(ip)) {
			t.Errorf("pool address %s not recognised", ip)
		}
	}
	if multi.fromUpstream(netip.MustParseAddr("10.77.0.13")) {
		t.Error("an address outside the pool was treated as upstream")
	}
}

// parseThenBreak parses a valid config, checks that config validation
// already rejects the broken form (so `check` catches it), then applies the
// same break to the parsed snapshot so buildTopology's own guard is still
// exercised: it is the defence behind validation.
func parseThenBreak(t *testing.T, valid, from, to string, breakCfg func(*config.Config)) *config.Config {
	t.Helper()
	if _, err := config.Parse([]byte(strings.Replace(valid, from, to, 1))); err == nil {
		t.Errorf("config validation accepted %q", to)
	}
	cfg, err := config.Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	breakCfg(cfg)
	return cfg
}

// The upstream must be a literal: resolving a name for the private leg
// would let a poisoned resolver redirect it.
func TestBuildTopologyRejectsHostname(t *testing.T) {
	cfg := parseThenBreak(t, topoYAML, "address: 10.77.0.10:5060", "address: fs.example.com:5060",
		func(c *config.Config) { c.SIP.Upstream.Address = "fs.example.com:5060" })
	if _, err := buildTopology(cfg); err == nil {
		t.Fatal("a hostname upstream was accepted")
	}
}

// The v1 alias converges on the pool model at build time as the single node
// "default": one runtime model for both config shapes, so the request path
// never knows which one produced it and the hash degenerates trivially
// (one node is always index 0).
func TestTopologyUpstreamAliasSynthesised(t *testing.T) {
	topo := testTopology(t)
	if len(topo.upstreams) != 1 || len(topo.upstreamNames) != 1 || topo.upstreamNames[0] != "default" {
		t.Fatalf("upstreams = %+v names = %v, want exactly [default]", topo.upstreams, topo.upstreamNames)
	}
	entry := topo.upstreamEntryFor("default")
	if got := entry.addr.String(); got != "10.77.0.10:5060" {
		t.Errorf("entry addr = %s", got)
	}
	if entry.host != "10.77.0.10:5060" {
		t.Errorf("entry host = %q", entry.host)
	}
	// The dial order for ANY user is that one node.
	for _, user := range []string{"1001", "alice", ""} {
		if order := topo.upstreamDialOrder(user, alwaysAvailable); len(order) != 1 || order[0] != "default" {
			t.Errorf("dial order for %q = %v, want [default]", user, order)
		}
	}
}

// The multi shape resolves per name, with the names sorted once at build
// time — the hash pool and the failover order must never depend on Go's map
// iteration order.
func TestTopologyUpstreamMulti(t *testing.T) {
	topo := testMultiTopology(t)
	want := []string{"fs-a", "fs-b", "fs-c"}
	if len(topo.upstreamNames) != len(want) {
		t.Fatalf("names = %v, want %v", topo.upstreamNames, want)
	}
	for i, name := range want {
		if topo.upstreamNames[i] != name {
			t.Fatalf("names = %v, want %v", topo.upstreamNames, want)
		}
		entry := topo.upstreamEntryFor(name)
		wantHost := "10.77.0." + map[string]string{"fs-a": "10", "fs-b": "11", "fs-c": "12"}[name] + ":5060"
		if entry.host != wantHost || entry.addr.String() != wantHost {
			t.Errorf("node %s = %+v, want %s", name, entry, wantHost)
		}
	}
	if _, ok := topo.upstreams["default"]; ok {
		t.Error("the alias node leaked into the pool shape")
	}
}

// Every node address is resolved like the alias: no DNS.
func TestBuildTopologyRejectsUpstreamNodeHostname(t *testing.T) {
	valid := strings.Replace(topoYAML, "  upstream:\n    address: 10.77.0.10:5060\n", multiUpstreamBlock, 1)
	cfg := parseThenBreak(t, valid, "10.77.0.11:5060", "fs-b.example.com:5060",
		func(c *config.Config) { c.SIP.Upstreams.Nodes["fs-b"].Address = "fs-b.example.com:5060" })
	if _, err := buildTopology(cfg); err == nil ||
		!strings.Contains(err.Error(), "sip.upstreams.nodes.fs-b must be a literal IP:port, got fs-b.example.com") {
		t.Fatalf("want the per-node literal-IP error, got %v", err)
	}
}

// hashUpstreamUser is the selection contract: FNV-1a 64 over the LOWER-CASED
// user. The fixed vectors pin the algorithm (changing it silently would
// remap every user), the case check pins the lower-casing (a phone that
// registers as "Bob" and calls as "bob" must land on one switch), and the
// empty string pins that a missing user part is still a deterministic input.
func TestHashUpstreamUser(t *testing.T) {
	vectors := []struct {
		user string
		want uint64
	}{
		{"1001", 973458052660218839},
		{"1002", 973459152171847050},
		{"alice", 5803779529149266183},
		{"Bob", 21748447695211092},
		{"bob", 21748447695211092},
		{"", 14695981039346656037}, // FNV-1a 64 offset basis
	}
	for _, v := range vectors {
		if got := hashUpstreamUser(v.user); got != v.want {
			t.Errorf("hashUpstreamUser(%q) = %d, want %d", v.user, got, v.want)
		}
	}
	if hashUpstreamUser("Bob") != hashUpstreamUser("bob") {
		t.Error("hash is case-sensitive: Bob and bob must agree")
	}
}

// upstreamDialOrder is the failover plan: the hash-chosen node first, the
// rest of the available pool in rotation from it, and cooled nodes only
// after every available one — and excluded from the hash pool entirely
// (D6), so a sick node stops receiving its share of the users.
func TestUpstreamDialOrder(t *testing.T) {
	topo := testMultiTopology(t)
	all := func(string) bool { return true }

	// Determinism: the same user always yields the same order, and the
	// order is a permutation of the pool.
	first := topo.upstreamDialOrder("1001", all)
	if len(first) != 3 {
		t.Fatalf("order = %v, want 3 nodes", first)
	}
	if again := topo.upstreamDialOrder("1001", all); !equalStrings(first, again) {
		t.Errorf("order not deterministic: %v then %v", first, again)
	}
	seen := map[string]bool{}
	for _, name := range first {
		if seen[name] {
			t.Fatalf("order repeats %s: %v", name, first)
		}
		seen[name] = true
	}
	// The head is the pure hash of the user modulo the pool, exactly as
	// selectUpstream promises.
	wantHead := topo.upstreamNames[hashUpstreamUser("1001")%3]
	if first[0] != wantHead {
		t.Errorf("head = %s, want %s", first[0], wantHead)
	}
	// Rotation: the order is the sorted pool rotated to start at the head.
	wantOrder := append(append([]string{}, topo.upstreamNames[hashUpstreamUser("1001")%3:]...),
		topo.upstreamNames[:hashUpstreamUser("1001")%3]...)
	if !equalStrings(first, wantOrder) {
		t.Errorf("order = %v, want rotation %v", first, wantOrder)
	}

	// Spread: over the three pool sizes at least two distinct heads appear
	// (a degenerate hash would pin everyone to one switch).
	heads := map[string]bool{}
	for _, user := range []string{"1001", "1002", "1003", "1004", "1005", "1006", "1007", "1008"} {
		heads[topo.upstreamDialOrder(user, all)[0]] = true
	}
	if len(heads) < 2 {
		t.Errorf("every user hashed to one node: %v", heads)
	}

	// Cooled nodes: fs-a cooling drops it from the hash pool AND puts it
	// last, so a user who hashes to fs-a now starts elsewhere and only
	// reaches fs-a if both alternatives fail.
	coolingA := func(name string) bool { return name != "fs-a" }
	order := topo.upstreamDialOrder("1001", coolingA)
	if order[0] == "fs-a" {
		t.Errorf("cooled node dialed first: %v", order)
	}
	if order[len(order)-1] != "fs-a" {
		t.Errorf("cooled node not last: %v", order)
	}
	// A user whose hash WOULD pick fs-a (over the two-node available pool)
	// is remapped onto the available pool entirely — the cooled node cannot
	// win by modulo.
	for _, user := range []string{"1001", "1002", "alice", "u0", "u1", "u2"} {
		if got := topo.upstreamDialOrder(user, coolingA); got[0] == "fs-a" {
			t.Errorf("user %q still hashed to a cooled node: %v", user, got)
		}
	}

	// All cooled: dial the full pool rather than nothing — a cooldown is a
	// suspicion, not a verdict. The order is the user's normal hash order
	// (the pool is the same), not the sorted order.
	none := func(string) bool { return false }
	if order := topo.upstreamDialOrder("1001", none); !equalStrings(order, first) {
		t.Errorf("all-cooled order = %v, want the full-pool hash order %v", order, first)
	}
}

func TestSelectUpstream(t *testing.T) {
	topo := testMultiTopology(t)
	all := func(string) bool { return true }
	name, entry, ok := topo.selectUpstream("1001", all)
	if !ok {
		t.Fatal("selectUpstream found no node")
	}
	if name != topo.upstreamNames[hashUpstreamUser("1001")%3] {
		t.Errorf("selected %s, want the hash head", name)
	}
	if entry.host == "" || entry.addr.Addr().String() == "" {
		t.Errorf("entry not resolved: %+v", entry)
	}
	// Selection skips a cooled node in favour of its alternatives.
	coolingA := func(n string) bool { return n != "fs-a" }
	for i := 0; i < 3; i++ {
		if name, _, _ := topo.selectUpstream("1001", coolingA); name == "fs-a" {
			t.Errorf("selected a cooled node")
		}
	}
	// An empty pool is the only failure mode (impossible on a validated
	// config, but the caller must not panic on it).
	empty := &topology{}
	if _, _, ok := empty.selectUpstream("1001", all); ok {
		t.Error("empty topology reported a selection")
	}
}

// alwaysAvailable is the availability oracle of a topology with nothing
// cooling.
func alwaysAvailable(string) bool { return true }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
// silently fail every bridged call. Config validation rejects every row
// too, so `check` agrees with `run` (audit P2-CFG-004); the break is also
// applied to a parsed snapshot to keep this guard covered.
func TestBuildTopologyRejectsPSTNHostnames(t *testing.T) {
	matchHost := func(c *config.Config) { c.SIP.Pstn.Match.Host = "pstn.example.com" }
	tests := []struct {
		name  string
		block string // pstn section to start from (alias or multi shape)
		// from/to break one field of the otherwise valid block; breakCfg
		// applies the same break to a parsed config.
		from, to, want string
		breakCfg       func(*config.Config)
	}{
		{
			"alias address",
			pstnTopoBlock,
			"address: 223.76.90.4:16060", "address: gw.example.com:16060",
			"sip.pstn.address must be a literal IP:port, got gw.example.com",
			func(c *config.Config) { c.SIP.Pstn.Address = "gw.example.com:16060" },
		},
		{
			"alias match",
			pstnTopoBlock,
			"match: 10.77.0.2:16061", "match: pstn.example.com:16061",
			"sip.pstn.match must be a literal IP, got pstn.example.com",
			matchHost,
		},
		{
			"multi gateway address names a host",
			pstnMultiTopoBlock,
			"address: 223.76.90.4:16060\n", "address: gw-mobile.example.com:16060\n",
			"sip.pstn.gateways.gw-mobile must be a literal IP:port, got gw-mobile.example.com",
			func(c *config.Config) { c.SIP.Pstn.Gateways["gw-mobile"].Address = "gw-mobile.example.com:16060" },
		},
		{
			"multi match",
			pstnMultiTopoBlock,
			"match: 10.77.0.2:16061\n", "match: pstn.example.com:16061\n",
			"sip.pstn.match must be a literal IP, got pstn.example.com",
			matchHost,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := strings.Replace(topoYAML, "    address: 10.77.0.10:5060\n",
				"    address: 10.77.0.10:5060\n"+tt.block, 1)
			cfg := parseThenBreak(t, yaml, tt.from, tt.to, tt.breakCfg)
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

// The read filter's private-listener test: the address comparison treats a
// wildcard bind as any host on its port, and a read on another transport
// never matches the UDP private bind.
func TestSameListener(t *testing.T) {
	cases := []struct {
		tr, a, b string
		want     bool
	}{
		{"udp", "10.0.0.1:5060", "10.0.0.1:5060", true},
		{"udp", "0.0.0.0:5060", "10.0.0.1:5060", true}, // wildcard listener
		{"udp", "10.0.0.1:5060", "0.0.0.0:5060", true},
		{"udp", "10.0.0.1:5060", "10.0.0.2:5060", false},
		{"udp", "0.0.0.0:5060", "10.0.0.1:5061", false}, // different port
		{"ws", "10.0.0.1:5060", "0.0.0.0:5060", false},  // different transport
	}
	for _, c := range cases {
		if got := fsip.SameListener(c.tr, c.a, "udp", c.b); got != c.want {
			t.Errorf("fsip.SameListener(%s %q, udp %q) = %v, want %v", c.tr, c.a, c.b, got, c.want)
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
