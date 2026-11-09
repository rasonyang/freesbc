package admin

import (
	"net/netip"
	"testing"
)

// The socket label follows the listener's role: one shared socket is
// "shared", never "public" or "private".
func TestUDPSocketLabels(t *testing.T) {
	cases := []struct {
		name  string
		infos []Listener
		want  map[string]string
	}{
		{"shared", []Listener{{Transport: "udp", Bind: "10.77.0.2:5060", Shared: true}, {Transport: "tcp", Bind: "10.77.0.2:5060"}},
			map[string]string{"10.77.0.2:5060": "shared"}},
		{"separate", []Listener{{Transport: "udp", Bind: "10.0.0.5:5060"}, {Transport: "udp", Bind: "10.77.0.2:5060", Private: true}},
			map[string]string{"10.0.0.5:5060": "public", "10.77.0.2:5060": "private"}},
	}
	for _, c := range cases {
		want, label := udpSocketLabels(c.infos)
		if len(want) != len(c.want) {
			t.Errorf("%s: %d sockets, want %d", c.name, len(want), len(c.want))
		}
		for addr, w := range c.want {
			if got := label[netip.MustParseAddrPort(addr)]; got != w {
				t.Errorf("%s: %s labelled %q, want %q", c.name, addr, got, w)
			}
		}
	}
}
