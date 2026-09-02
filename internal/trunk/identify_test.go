package trunk

import (
	"net/netip"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
)

func TestIdentifyPeer(t *testing.T) {
	src := `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    auth: { username: u, password: p }
    allowed_ips: [203.0.113.0/24]
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: carrier-a
    to: [internal-pbx]
`
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	name, peer, ok := IdentifyPeer(cfg, netip.MustParseAddr("203.0.113.7"))
	if !ok || name != "carrier-a" || peer == nil {
		t.Errorf("203.0.113.7 → %q, ok=%v", name, ok)
	}
	name, _, ok = IdentifyPeer(cfg, netip.MustParseAddr("10.1.2.3"))
	if !ok || name != "internal-pbx" {
		t.Errorf("10.1.2.3 → %q, ok=%v", name, ok)
	}
	if _, _, ok := IdentifyPeer(cfg, netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("192.0.2.1 should not match any peer")
	}
}

func TestIdentifyPeerDeterministicOnOverlap(t *testing.T) {
	// Two peers whose ranges both contain the address; the sorted-name
	// winner must be stable across runs (map iteration is not).
	src := `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  aaa:
    address: 10.0.0.1:5060
    allowed_ips: [10.0.0.0/8]
  zzz:
    address: 10.0.0.2:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: in
    from: aaa
    to: [zzz]
`
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := 0; i < 20; i++ {
		name, _, ok := IdentifyPeer(cfg, netip.MustParseAddr("10.9.9.9"))
		if !ok || name != "aaa" {
			t.Fatalf("iteration %d: got %q (want deterministic \"aaa\")", i, name)
		}
	}
}
