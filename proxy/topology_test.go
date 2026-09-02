package proxy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/config"
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
