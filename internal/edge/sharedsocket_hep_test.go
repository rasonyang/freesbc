package edge

import (
	"net/netip"
	"testing"

	"github.com/freesbc/freesbc/internal/hep"
)

// With a shared socket the one local address faces both the internet and the
// switch. A message whose far end is a switch node keeps the shared address
// as its local end; any other far end sees public.ip; a mirror without
// switchIPs (separate sockets) is unchanged.
func TestHEPSharedSocketLocalEnd(t *testing.T) {
	col := startHEPCollector(t)
	sender, err := hep.New(hep.Options{Network: "udp", Addr: col.addr, CaptureID: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close(t.Context())
	bind, pub := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("203.0.113.7")
	shared := &hepMirror{sender: sender, bind: bind, pub: pub,
		switchIPs: map[netip.Addr]struct{}{netip.MustParseAddr("10.77.0.3"): {}}}
	plain := &hepMirror{sender: sender, bind: bind, pub: pub}
	msg := func(id string) []byte { return []byte("OPTIONS sip:x SIP/2.0\r\nCall-ID: " + id + "\r\n\r\n") }
	local := netip.MustParseAddrPort("10.77.0.2:5060")
	swNode := netip.MustParseAddrPort("10.77.0.3:5080")
	carrier := netip.MustParseAddrPort("198.51.100.4:5070")

	shared.capture(17, local, swNode, true, msg("sw-in"))
	shared.capture(17, local, swNode, false, msg("sw-out"))
	shared.capture(17, local, carrier, true, msg("pub-in"))
	shared.capture(17, local, carrier, false, msg("pub-out"))
	plain.capture(17, local, swNode, false, msg("plain-out"))

	col.await(t, "switch in", "sw-in", "OPTIONS", "10.77.0.3:5080", "10.77.0.2:5060")
	col.await(t, "switch out", "sw-out", "OPTIONS", "10.77.0.2:5060", "10.77.0.3:5080")
	col.await(t, "public in", "pub-in", "OPTIONS", "198.51.100.4:5070", "203.0.113.7:5060")
	col.await(t, "public out", "pub-out", "OPTIONS", "203.0.113.7:5060", "198.51.100.4:5070")
	col.await(t, "no switchIPs", "plain-out", "OPTIONS", "203.0.113.7:5060", "10.77.0.3:5080")
}
