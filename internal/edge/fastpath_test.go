package edge

import (
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// The helpers below replace allocating calls on the signaling path (issue
// #173). Each must give exactly the answer of the call it replaces; these
// tests compare them against it.

// foldNames mixes the names the helpers meet with the non-ASCII ones that
// tell an ASCII fold from strings.ToLower or strings.EqualFold: the Kelvin
// sign (lower-cases to k), the dotted capital I (to i) and the long s
// (folds to s under EqualFold, lower-cases to itself).
var foldNames = []string{
	"", "x", "X-", "X-FreeSBC", "X-FreeSBC-", "x-freesbc-", "X-FREESBC-ARRIVAL", "X-FreeSBC-Arrival",
	"x-FreeSBC-arrival", "X-FreeSBC-Carrier", "X-Freesbc-Extra", "X-FreeSBX-Carrier", "X_FreeSBC-Carrier",
	"X-Freeſbc-Carrier", "X-FreeSBCK", "K", "k", "K", "Call-ID", "call-id", "Call-İD",
	"CALL-ID", "Via", "VIA", "v", "User-Agent", "Server", "P-Asserted-Identity", "p-asserted-identity",
	"P-Charge-Info", "Diversion", "ReKord-Route", "Record-Route", "Contact", "contact", "m",
	"P-Preferred-Identity-And-A-Very-Long-Suffix", "Request-Disposition", "Authentication-Info",
	"Allow-Events", "Max-Forwards", "Content-Length", "Content-length", "X-Custom", "\xff\xfe",
}

func TestASCIIFoldMatchesSipgoHeaderCompare(t *testing.T) {
	for _, a := range foldNames {
		for _, b := range foldNames {
			want := sip.HeaderToLower(a) == sip.HeaderToLower(b)
			if got := asciiEqualFold(a, b); got != want {
				t.Errorf("asciiEqualFold(%q, %q) = %v, want %v", a, b, got, want)
			}
		}
	}
}

func TestIsInternalHeaderMatchesToLowerPrefix(t *testing.T) {
	for _, name := range foldNames {
		want := strings.HasPrefix(strings.ToLower(name), internalHeaderPrefix)
		if got := isInternalHeader(name); got != want {
			t.Errorf("isInternalHeader(%q) = %v, want %v", name, got, want)
		}
	}
	// The long s folds to s under strings.EqualFold, so EqualFold would
	// have taken this for an internal header; neither ToLower nor the
	// ASCII fold does.
	if isInternalHeader("X-Freeſbc-Carrier") {
		t.Error("a long s matched the internal prefix")
	}
}

func TestAllowedToClientMatchesToLowerLookup(t *testing.T) {
	names := append([]string(nil), foldNames...)
	for n := range clientHeaderAllowlist {
		names = append(names, n, strings.ToUpper(n), strings.ToUpper(n[:1])+n[1:])
	}
	for _, name := range names {
		want := clientHeaderAllowlist[strings.ToLower(name)]
		if got := allowedToClient(name); got != want {
			t.Errorf("allowedToClient(%q) = %v, want %v", name, got, want)
		}
	}
	// ToLower lower-cases the Kelvin sign into an allowlisted compact name;
	// the non-ASCII fallback keeps that answer.
	if !allowedToClient("K") {
		t.Error("the Kelvin sign no longer lower-cases to k")
	}
}

// take finds the marker by the same case-insensitive name GetHeaders used,
// and only its first occurrence counts.
func TestArrivalTakeMarkerNameAnyCase(t *testing.T) {
	m := mustMarker(t)
	for _, tc := range []struct {
		name    string
		headers [][2]string
		want    arrival
	}{
		{"canonical", [][2]string{{arrivalHeader, string(m.private)}}, arrPrivate},
		{"lower case", [][2]string{{"x-freesbc-arrival", string(m.private)}}, arrPrivate},
		{"mixed case", [][2]string{{"X-FREESBC-arrival", string(m.private)}}, arrPrivate},
		{"forged first", [][2]string{{arrivalHeader, "forged"}, {arrivalHeader, string(m.private)}}, arrPublic},
		{"other internal first", [][2]string{{"X-FreeSBC-Carrier", "c"}, {arrivalHeader, string(m.private)}}, arrPrivate},
		{"long s in name", [][2]string{{"X-Freeſbc-Arrival", string(m.private)}}, arrPublic},
		{"no marker", [][2]string{{"X-FreeSBC-Carrier", "c"}}, arrPublic},
	} {
		req := sip.NewRequest(sip.OPTIONS, sip.Uri{User: "1", Host: "example.com"})
		for _, h := range tc.headers {
			req.AppendHeader(sip.NewHeader(h[0], h[1]))
		}
		req.AppendHeader(sip.NewHeader("X-Other", "kept"))
		got, arr := m.take(req)
		if arr != tc.want {
			t.Errorf("%s: arrival = %d, want %d", tc.name, arr, tc.want)
		}
		if names := internalHeaderNames(got); len(names) != 0 {
			t.Errorf("%s: internal headers left: %v", tc.name, names)
		}
		if len(got.GetHeaders("X-Other")) != 1 {
			t.Errorf("%s: an unrelated header was removed", tc.name)
		}
	}
}

func TestParseIPHostMatchesParseAddr(t *testing.T) {
	hosts := []string{
		"", "1.2.3.4", "01.2.3.4", "1.2.3.4.5", "256.1.1.1", "1..2.3", ".1.2.3", "1.2.3.", "1.2.3.x",
		"1.2.3.4:5060", "example.com", "sip.example.com", "a.b", "localhost", "abc", "1e100", "1234",
		"::1", "::", "0.0.0.0", "FD00::10", "fd00::10", "[::1]", "fe80::1%eth0", "fe80::1%", "%eth0",
		"1%eth0", "::ffff:1.2.3.4", "::ffff:1.2.3", "1:2", "1.2.3.4%eth0", "a:b:c", "2001:db8::1.2.3.4",
	}
	r := rand.New(rand.NewSource(173))
	const alphabet = "0123456789.:%abcdefx[]"
	for i := 0; i < 20000; i++ {
		b := make([]byte, 1+r.Intn(16))
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		hosts = append(hosts, string(b))
	}
	for _, h := range hosts {
		want, err := netip.ParseAddr(h)
		got, ok := parseIPHost(h)
		if ok != (err == nil) || got != want {
			t.Errorf("parseIPHost(%q) = %v, %v; ParseAddr = %v, %v", h, got, ok, want, err)
		}
	}
}

func TestIsSwitchHostForms(t *testing.T) {
	s := &Server{topo: buildTestTopology(t, `
public: {ip: 203.0.113.7, bind: 172.31.5.10}
private: {ip: "fd00::2"}
edge:
  switch: ["[fd00::10]:5060", "10.77.0.10:5060"]
  listen: {udp: 16060}
`)}
	for host, want := range map[string]bool{
		"[fd00::10]":        true,
		"fd00::10":          true,
		"FD00::10":          true,
		"[fd00:0::10]":      true,
		"fd00::2":           true,
		"[fd00::2]":         true,
		"10.77.0.10":        true,
		"::ffff:10.77.0.10": true,
		"[2001:db8::1]":     false,
		"10.77.0.11":        false,
		"switch.internal":   false,
		"10.77.0.10.nip.io": false,
		"fd00::10%eth0":     false,
		"":                  false,
	} {
		if got := s.isSwitchHost(host); got != want {
			t.Errorf("isSwitchHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// readAddrPort and sameListenerAddr are the string round trips they
// replace, for every address shape a read can carry.
func TestReadAddrPortMatchesStringParse(t *testing.T) {
	addrs := []net.Addr{
		&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 5060},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}, // 16-byte, IPv4-mapped
		&net.UDPAddr{IP: net.ParseIP("::ffff:10.0.0.1"), Port: 1},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 65535},
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 5060, Zone: "eth0"},
		&net.UDPAddr{IP: net.IP{10, 0, 0, 1}, Port: 5060, Zone: "eth0"},
		&net.UDPAddr{IP: net.IPv4zero, Port: 5060},
		&net.UDPAddr{IP: nil, Port: 5060},
		&net.UDPAddr{IP: net.IP{1, 2, 3, 4, 5}, Port: 5060},
		&net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 70000},
		&net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 0},
		(*net.UDPAddr)(nil),
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5061},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443},
		&net.TCPAddr{IP: net.ParseIP("fe80::2"), Port: 80, Zone: "en0"},
		&net.TCPAddr{IP: nil, Port: 80},
		(*net.TCPAddr)(nil),
		&net.UnixAddr{Name: "/tmp/sock", Net: "unix"},
		nil,
	}
	for _, a := range addrs {
		var want netip.AddrPort
		var werr error = net.UnknownNetworkError("nil")
		if a != nil {
			want, werr = netip.ParseAddrPort(a.String())
		}
		got, ok := readAddrPort(a)
		if ok != (werr == nil) || got != want {
			t.Errorf("readAddrPort(%v) = %v, %v; ParseAddrPort(String()) = %v, %v", a, got, ok, want, werr)
		}
		if ap, ok := udpAddrPort(a); ok && ap != want {
			t.Errorf("udpAddrPort(%v) = %v, want %v", a, ap, want)
		}
	}

	binds := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:5060"),
		netip.MustParseAddrPort("[::1]:5060"),
		netip.MustParseAddrPort("[::ffff:127.0.0.1]:5060"),
		netip.MustParseAddrPort("0.0.0.0:5060"),
		netip.MustParseAddrPort("[::]:5060"),
	}
	locals := []net.Addr{
		&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 5060},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 5060},
		&net.UDPAddr{IP: net.IP{127, 0, 0, 2}, Port: 5060},
		&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 5061},
		&net.UDPAddr{IP: net.IPv4zero, Port: 5060},
		&net.UDPAddr{IP: net.IPv6unspecified, Port: 5060},
	}
	for _, bind := range binds {
		for _, local := range locals {
			ap, ok := udpAddrPort(local)
			if !ok {
				t.Fatalf("udpAddrPort(%v) failed", local)
			}
			want := fsip.SameListener("udp", local.String(), "udp", bind.String())
			if got := sameListenerAddr(ap, bind); got != want {
				t.Errorf("sameListenerAddr(%v, %v) = %v, SameListener says %v", local, bind, got, want)
			}
		}
	}
}

// The read filter's fast path trusts the private socket however its local
// address is written, and only on UDP.
func TestReadFilterTrustsPrivateSocketAddressForms(t *testing.T) {
	h := startHarness(t, false)
	f := h.srv.readFilter()
	priv := netip.MustParseAddrPort(h.privateSIP)
	upstream := &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 40000}
	stamped := string(h.srv.marker.stamp(arrPrivate, []byte(arrOptions)))
	for name, tc := range map[string]struct {
		transport string
		local     net.Addr
		remote    net.Addr
		want      string
	}{
		"4-byte local":         {"udp", &net.UDPAddr{IP: priv.Addr().AsSlice(), Port: int(priv.Port())}, upstream, stamped},
		"IPv4-mapped local":    {"UDP", &net.UDPAddr{IP: net.IP(netip.AddrFrom16(priv.Addr().As16()).AsSlice()), Port: int(priv.Port())}, upstream, stamped},
		"IPv4-mapped upstream": {"udp", &net.UDPAddr{IP: priv.Addr().AsSlice(), Port: int(priv.Port())}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, stamped},
		"tcp same port":        {"tcp", &net.TCPAddr{IP: priv.Addr().AsSlice(), Port: int(priv.Port())}, upstream, arrOptions},
		"other port":           {"udp", &net.UDPAddr{IP: priv.Addr().AsSlice(), Port: int(priv.Port()) + 1}, upstream, arrOptions},
		"foreign upstream":     {"udp", &net.UDPAddr{IP: priv.Addr().AsSlice(), Port: int(priv.Port())}, &net.UDPAddr{IP: net.IP{203, 0, 113, 5}, Port: 5060}, ""},
	} {
		out, err := f(sip.TransportReadProps{Transport: tc.transport, LocalAddr: tc.local, RemoteAddr: tc.remote}, []byte(arrOptions))
		if err != nil {
			t.Fatalf("%s: a read filter must never return an error: %v", name, err)
		}
		if string(out) != tc.want {
			t.Errorf("%s: filter returned %q, want %q", name, out, tc.want)
		}
	}
}

func TestHeadersNamedMatchesGetHeaders(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "1", Host: "example.com"})
	for _, n := range foldNames {
		if n != "" {
			req.AppendHeader(sip.NewHeader(n, "v"))
		}
	}
	for _, n := range append(foldNames, "record-route", "VIA", "Missing") {
		want := req.GetHeaders(n)
		got := headersNamed(req, n)
		if len(got) != len(want) {
			t.Fatalf("headersNamed(%q) found %d, GetHeaders %d", n, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("headersNamed(%q)[%d] differs from GetHeaders", n, i)
			}
		}
		if hasHeader(req, n) != (len(want) > 0) {
			t.Errorf("hasHeader(%q) = %v", n, !(len(want) > 0))
		}
	}
}

// The rewritten helpers allocate nothing on their common path.
func TestSignalingHelpersDoNotAllocate(t *testing.T) {
	m := mustMarker(t)
	req := parseReq(t, []byte(strings.Replace(arrOptions, "\r\nVia:", "\r\nUser-Agent: phone\r\nAllow: INVITE\r\nP-Charge-Info: x\r\nVia:", 1)))
	s := &Server{topo: testTopology(t), metrics: NewMetrics()}
	s.metrics.ResponseOut(200)
	for name, fn := range map[string]func(){
		"take, no internal header": func() { m.take(req) },
		"isSwitchHost, a name":     func() { s.isSwitchHost("sip.example.com") },
		"isSwitchHost, an IP":      func() { s.isSwitchHost("198.51.100.1") },
		"allowedToClient":          func() { allowedToClient("User-Agent") },
		"hasHeader":                func() { hasHeader(req, "Contact") },
		"ResponseOut":              func() { s.metrics.ResponseOut(200) },
		"side names":               func() { _, _ = s.topo.private.host(), s.topo.private.upperTransport() },
	} {
		if n := testing.AllocsPerRun(100, fn); n != 0 {
			t.Errorf("%s: %v allocations, want 0", name, n)
		}
	}
}
