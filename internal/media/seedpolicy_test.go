package media

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Seed policy tests (issue #290). Ports 20400-20499 belong to this file.

// TestPinnedSeedPrivateSDPNeedsNoAlias is the pin without the 127.0.0.2
// alias: the client sits on 127.0.0.1 and its SDP names private addresses.
func TestPinnedSeedPrivateSDPNeedsNoAlias(t *testing.T) {
	client := auditUDP(t, "127.0.0.1")
	fs := auditUDP(t, "127.0.0.1")
	port := client.LocalAddr().(*net.UDPAddr).Port
	pool := newAuditPool("seed", 20480, 20489, "127.0.0.1")
	pool.loopback.Store(true)
	s, err := AllocateAcross(pool.PlanePool, pool.PlanePool, SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchStrict}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetSignallingSource(SideA, netip.MustParseAddr("127.0.0.1"))
	s.PinSeedToSignallingSource(SideA, true)
	s.SetRemote(SideA, netip.AddrPortFrom(netip.MustParseAddr("10.77.0.10"), uint16(port)))
	s.SetRTCPRemote(SideA, netip.AddrPortFrom(netip.MustParseAddr("10.77.0.10"), uint16(port+1)))
	s.SetRemote(SideB, auditAddrPort(fs))
	s.Start()
	if got, want := s.rtp[SideA].dest(), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)); got != want {
		t.Fatalf("rtp dest = %v, want %v", got, want)
	}
	if got, want := s.rtcp[SideA].dest(), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port+1)); got != want {
		t.Fatalf("rtcp dest = %v, want %v", got, want)
	}
	if _, err := fs.WriteToUDP([]byte("early-media"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideB)}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := client.ReadFromUDP(buf); err != nil || string(buf[:n]) != "early-media" {
		t.Fatalf("client heard %q, %v", buf[:n], err)
	}
}

// TestPinnedSeedSendsOnlyToSignallingSource: a client side pinned to its
// signalling source sends early media to that IP at the SDP port, never to
// the address its SDP names (the private LAN, or another host). The client
// stands on 127.0.0.2; the decoy shares its port on 127.0.0.1.
func TestPinnedSeedSendsOnlyToSignallingSource(t *testing.T) {
	client := auditUDP(t, "127.0.0.2") // skips when the alias is missing
	port := client.LocalAddr().(*net.UDPAddr).Port
	decoy, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:%d: %v", port, err)
	}
	defer decoy.Close()
	fs := auditUDP(t, "127.0.0.1")

	for i, sdpIP := range []string{"10.77.0.10", "192.168.1.5", "172.16.4.4", "127.0.0.1"} {
		t.Run(sdpIP, func(t *testing.T) {
			pool := newAuditPool("seed", 20400+i*10, 20409+i*10, "127.0.0.1")
			pool.loopback.Store(true)
			s, err := AllocateAcross(pool.PlanePool, pool.PlanePool, SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchStrict}, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.SetSignallingSource(SideA, netip.MustParseAddr("127.0.0.2"))
			s.PinSeedToSignallingSource(SideA, true)
			s.SetRemote(SideA, netip.AddrPortFrom(netip.MustParseAddr(sdpIP), uint16(port)))
			s.SetRemote(SideB, auditAddrPort(fs))
			s.Start()

			priv := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideB)}
			if _, err := fs.WriteToUDP([]byte("early-media"), priv); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1500)
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := client.ReadFromUDP(buf)
			if err != nil || string(buf[:n]) != "early-media" {
				t.Fatalf("signalling source heard %q, %v; want the early media", buf[:n], err)
			}
			_ = decoy.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if n, _, err := decoy.ReadFromUDP(buf); err == nil {
				t.Fatalf("SDP address heard %q; the pin must never send there", buf[:n])
			}
		})
	}
}

func TestPinnedSeedWithoutSignallingSourceSendsNothing(t *testing.T) {
	l := &latch{pinSeed: true, allowLoopback: true}
	l.seed(netip.MustParseAddrPort("203.0.113.9:4000"))
	if l.dst.IsValid() {
		t.Fatalf("dst = %v, want none before the signalling source is known", l.dst)
	}
	if l.expected != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("expected = %v, the source check must still be armed", l.expected)
	}
	// Learning the source later starts the seeded-but-unsent side sending
	// to it at the SDP port; a fresh seed then uses it too, and an SDP IP
	// equal to it changes nothing.
	l.setSignallingSource(netip.MustParseAddr("198.51.100.7"))
	if want := netip.MustParseAddrPort("198.51.100.7:4000"); l.dst != want {
		t.Fatalf("dst = %v after the source arrived, want %v", l.dst, want)
	}
	l.seed(netip.MustParseAddrPort("10.0.0.1:4000"))
	if want := netip.MustParseAddrPort("198.51.100.7:4000"); l.dst != want {
		t.Fatalf("dst = %v, want %v", l.dst, want)
	}
	l.seed(netip.MustParseAddrPort("198.51.100.7:4002"))
	if want := netip.MustParseAddrPort("198.51.100.7:4002"); l.dst != want {
		t.Fatalf("dst = %v, want %v", l.dst, want)
	}
	// A later fork's source moves an unlatched pinned destination.
	l.setSignallingSource(netip.MustParseAddr("198.51.100.8"))
	if want := netip.MustParseAddrPort("198.51.100.8:4002"); l.dst != want {
		t.Fatalf("dst = %v after a new source, want %v", l.dst, want)
	}
}

func TestCarrierDestPolicy(t *testing.T) {
	own := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("172.31.0.9"), netip.MustParseAddr("10.77.0.2")}
	prod := DestPolicy{Restrict: true, Own: own}
	lab := DestPolicy{Restrict: true, AllowPrivate: true, Own: own}
	cases := []struct {
		ip           string
		prod, lab    bool // true = seeded
		allowLoopbck bool
	}{
		{"198.51.100.20", true, true, false}, // public media IP, unlike the signalling IP
		{"2001:db8::5", true, true, false},
		{"10.77.0.10", false, true, false},
		{"192.168.1.5", false, true, false},
		{"172.16.4.4", false, true, false},
		{"172.31.255.1", false, true, false},
		{"fd00::1", false, true, false}, // ULA
		{"100.64.0.1", false, true, false},
		{"100.127.255.254", false, true, false},
		{"100.128.0.1", true, true, false}, // just outside CGNAT
		{"::ffff:10.1.1.1", false, true, false},
		{"127.0.0.1", false, false, false}, // loopback: the pool rule
		{"127.0.0.1", true, true, true},
		{"169.254.1.1", false, false, false},
		{"0.0.0.0", false, false, false},
		{"224.0.0.1", false, false, false},
		{"255.255.255.255", false, false, false},
		{"203.0.113.7", false, false, false}, // public.ip: refused in production; a public own address is no lab class
	}
	for _, c := range cases {
		for _, pol := range []struct {
			name string
			p    DestPolicy
			want bool
		}{{"prod", prod, c.prod}, {"lab", lab, c.lab}} {
			name := fmt.Sprintf("%s/%s/loop=%v", pol.name, c.ip, c.allowLoopbck)
			t.Run(name, func(t *testing.T) {
				l := &latch{policy: pol.p, allowLoopback: c.allowLoopbck}
				l.seed(netip.AddrPortFrom(netip.MustParseAddr(c.ip), 4000))
				got := l.dst.IsValid()
				if got != pol.want {
					t.Fatalf("seeded = %v, want %v (dst %v)", got, pol.want, l.dst)
				}
				// The source check is armed even when the send is refused.
				if ip := netip.MustParseAddr(c.ip).Unmap(); unicastMediaAddr(ip) && l.expected != ip {
					t.Fatalf("expected = %v, want %v", l.expected, ip)
				}
			})
		}
	}
	// A lab whose own addresses are all private class: they pass.
	labOwn := DestPolicy{Restrict: true, AllowPrivate: true, Own: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	if labOwn.refuses(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("a private own address must pass in a lab")
	}
	// The zero policy (the private plane) refuses nothing.
	if (DestPolicy{}).refuses(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("the zero policy must refuse nothing")
	}
}
