package shield

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

const floorCfg = `
public: { ip: 203.0.113.7 }
private: { ip: 10.77.0.2 }
edge:
  switch: [10.77.0.10:5060]
  listen: { udp: 5060 }
shield:
  rate_limit: 10/s per_ip
  carrier_rate_limit: 20/s per_ip
  ban: 1h
`

// floorShield builds a shield with an injectable clock and a vouched
// predicate over a set of "transport|addr:port" strings; calls counts the
// predicate's invocations.
func floorShield(t *testing.T, yaml string, vouched map[string]bool, carrier netip.Addr) (s *Shield, calls *int) {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	s = New(config.NewStore(cfg), discard(),
		func(ip netip.Addr) bool { return ip == carrier },
		func(tr string, ap netip.AddrPort) bool { n++; return vouched[tr+"|"+ap.String()] })
	t.Cleanup(func() { s.Close() })
	now := time.Unix(1000, 0)
	s.limiter.now = func() time.Time { return now }
	return s, &n
}

func count(s *Shield, ap netip.AddrPort, tr string, n int) (ok int) {
	for i := 0; i < n; i++ {
		if s.AllowRate(ap, tr) {
			ok++
		}
	}
	return ok
}

// A forged datagram flood naming a victim IP drains the IP bucket, but a
// vouched socket keeps its own floor, an unvouched one is denied, and
// stream traffic from the same IP is on a separate bucket.
func TestForgedFloodDoesNotLockOutVouchedSocket(t *testing.T) {
	v := map[string]bool{"udp|198.51.100.9:5062": true, "tls|198.51.100.9:40000": true}
	s, calls := floorShield(t, floorCfg, v, netip.Addr{})
	forged := netip.MustParseAddrPort("198.51.100.9:5060")
	phone := netip.MustParseAddrPort("198.51.100.9:5062")
	stranger := netip.MustParseAddrPort("198.51.100.9:5070")

	if got := count(s, forged, "UDP", 10); got != 10 || *calls != 0 {
		t.Fatalf("burst = %d, predicate calls = %d; want 10 and 0 while the IP bucket has tokens", got, *calls)
	}
	if got := count(s, forged, "UDP", 500); got != 0 {
		t.Fatalf("forged flood admitted %d datagrams past an empty bucket", got)
	}
	if got := count(s, phone, "udp", 30); got != 10 {
		t.Errorf("vouched socket admitted %d, want its floor of 10", got)
	}
	if got := count(s, stranger, "udp", 30); got != 0 {
		t.Errorf("unvouched socket admitted %d during the flood, want 0", got)
	}
	// Stream class is untouched by the datagram flood.
	tlsAP := netip.MustParseAddrPort("198.51.100.9:40000")
	if got := count(s, tlsAP, "tls", 10); got != 10 {
		t.Errorf("stream class admitted %d, want 10 (separate bucket)", got)
	}
	// A vouched abuser is bounded: IP bucket + floor, then denied.
	if got := count(s, tlsAP, "tls", 100); got != 10 {
		t.Errorf("vouched stream socket admitted %d more, want its 10-token floor only", got)
	}
}

// A forged datagram from the exact IP:port of a stream socket cannot touch
// that stream socket's floor.
func TestForgedDatagramDoesNotDrainStreamFloor(t *testing.T) {
	v := map[string]bool{"tls|198.51.100.9:40000": true, "udp|198.51.100.9:40000": false}
	s, _ := floorShield(t, floorCfg, v, netip.Addr{})
	ap := netip.MustParseAddrPort("198.51.100.9:40000")
	count(s, ap, "udp", 100) // drains the datagram bucket; udp is not vouched
	count(s, ap, "tls", 10)  // stream IP bucket
	if got := count(s, ap, "tls", 20); got != 10 {
		t.Errorf("stream floor admitted %d, want 10 untouched by the datagram flood", got)
	}
}

// A carrier source uses carrier_rate_limit for both buckets, and only its
// vouched (exact) address gets the floor.
func TestCarrierFloorUsesCarrierRate(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.50")
	v := map[string]bool{"udp|192.0.2.50:5060": true}
	s, _ := floorShield(t, floorCfg, v, ip)
	forged := netip.AddrPortFrom(ip, 5060)
	other := netip.AddrPortFrom(ip, 6000)
	count(s, other, "udp", 100) // drains the carrier IP bucket (20)
	if got := count(s, other, "udp", 50); got != 0 {
		t.Errorf("unvouched carrier port admitted %d, want 0", got)
	}
	if got := count(s, forged, "udp", 50); got != 20 {
		t.Errorf("vouched carrier socket admitted %d, want 20 (carrier_rate_limit)", got)
	}
}

// A global (per_ip: false) limit is one bucket: no class split, no floor.
func TestGlobalLimitHasNoFloor(t *testing.T) {
	y := strings.Replace(floorCfg, "10/s per_ip", "10/s", 1)
	v := map[string]bool{"udp|198.51.100.9:5062": true}
	s, calls := floorShield(t, y, v, netip.Addr{})
	count(s, netip.MustParseAddrPort("198.51.100.1:1"), "udp", 10)
	if s.AllowRate(netip.MustParseAddrPort("198.51.100.9:5062"), "udp") {
		t.Error("global bucket should be empty for everyone")
	}
	if s.AllowRate(netip.MustParseAddrPort("198.51.100.9:5062"), "tls") {
		t.Error("global bucket has no stream class split")
	}
	if *calls != 0 {
		t.Errorf("predicate consulted %d times for a global limit", *calls)
	}
}
