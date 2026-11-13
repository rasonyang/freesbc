package edge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// clampConfig parses a minimal config whose addresses the clamp is built
// from. public is the YAML of the public section.
func clampConfig(t *testing.T, public, private, sw string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf("public: %s\nprivate: {ip: %s}\nedge:\n  switch: [%s]\n  listen: {udp: 5060}\n",
		public, private, sw)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// publicClampConfig is an internet-facing layout: public.ip public,
// private.ip and the switch on a private LAN.
func publicClampConfig(t *testing.T) *config.Config {
	return clampConfig(t, "{ip: 203.0.113.7, bind: 198.51.100.4}", "10.77.0.2", "10.77.0.10:5060")
}

// newClampDirectory is newTestDirectory with the clamp cfg implies.
func newClampDirectory(cfg *config.Config, stub *dnsStub, clk *fakeClock, carriers ...config.Carrier) *carrierDirectory {
	d := newTestDirectory(stub, clk, nil, carriers...)
	d.policy = newCarrierAddrPolicy(cfg, cfg.PrivateAddr().Addr())
	return d
}

// aCarrier resolves through A/AAAA only (an explicit port); srvCarrier
// through the SRV record sip.example, whose one target is gw.example.
var (
	aCarrier   = config.Carrier{Name: "a", Host: "gw.example", Port: 5060, ExplicitPort: true}
	srvCarrier = config.Carrier{Name: "s", Host: "sip.example", Port: 5060}
	srvRecords = map[string][]*net.SRV{"sip.example": {{Target: "gw.example.", Port: 5070, Priority: 1}}}
)

// assertRefused checks that carrier name resolved to nothing, that ip is no
// carrier source, and that the lookup error names ip with its reason class.
func assertRefused(t *testing.T, d *carrierDirectory, name, ip, reason string) {
	t.Helper()
	snap := d.snapshot()
	if got := snap.addrs[name]; len(got) != 0 {
		t.Errorf("%s: %s: addrs = %v, want none", name, ip, got)
	}
	if snap.isSource(netip.MustParseAddr(ip)) {
		t.Errorf("%s: %s is a carrier source", name, ip)
	}
	for _, info := range d.snapshotInfo() {
		if info.Name != name {
			continue
		}
		want := fmt.Sprintf("every address refused: %s (%s)", netip.MustParseAddr(ip), reason)
		if !info.Failing || !strings.Contains(info.LastError, want) {
			t.Errorf("%s: %s: failing=%v err=%q, want failing with %q", name, ip, info.Failing, info.LastError, want)
		}
	}
}

// Every refused class, on the A/AAAA path and through an SRV target.
func TestCarrierClampRefusesAddressClasses(t *testing.T) {
	cfg := publicClampConfig(t)
	for _, c := range []struct{ ip, reason string }{
		{"127.0.0.1", clampLoopback},
		{"::1", clampLoopback},
		{"169.254.169.254", clampLinkLocal},
		{"fe80::1", clampLinkLocal},
		{"10.0.0.1", clampPrivate},
		{"192.168.1.20", clampPrivate},
		{"fd00::1", clampPrivate},
		{"100.64.0.1", clampPrivate},
		{"224.0.0.1", clampMulticast},
		{"ff02::1", clampMulticast},
		{"239.1.2.3", clampMulticast},
		{"255.255.255.255", clampMulticast},
		{"0.1.2.3", clampUnspecified},
		{"0.0.0.0", clampUnspecified},
		{"::", clampUnspecified},
		{"::ffff:127.0.0.1", clampLoopback}, // mapped: judged unmapped
	} {
		stub := &dnsStub{srv: srvRecords, ips: map[string][]string{"gw.example": {c.ip}}}
		d := newClampDirectory(cfg, stub, &fakeClock{t: time.Unix(1000, 0)}, aCarrier, srvCarrier)
		d.refresh(context.Background())
		ip := netip.MustParseAddr(c.ip).Unmap().String()
		assertRefused(t, d, "a", ip, c.reason)
		assertRefused(t, d, "s", ip, c.reason)
	}
}

// FreeSBC's own addresses (public.ip, public.bind, private.ip) and every
// edge.switch IP are refused, ahead of the private class.
func TestCarrierClampRefusesOwnAndSwitch(t *testing.T) {
	cfg := publicClampConfig(t)
	for _, c := range []struct{ ip, reason string }{
		{"203.0.113.7", clampOwn},  // public.ip
		{"198.51.100.4", clampOwn}, // public.bind
		{"10.77.0.2", clampOwn},    // private.ip
		{"10.77.0.10", clampSwitch},
	} {
		stub := &dnsStub{srv: srvRecords, ips: map[string][]string{"gw.example": {c.ip}}}
		d := newClampDirectory(cfg, stub, &fakeClock{t: time.Unix(1000, 0)}, aCarrier, srvCarrier)
		d.refresh(context.Background())
		assertRefused(t, d, "a", c.ip, c.reason)
		assertRefused(t, d, "s", c.ip, c.reason)
	}
}

// A refused address listed first never becomes the destination: the clamp
// runs before the order is used, on the A/AAAA path and across SRV targets.
func TestCarrierClampGoodAddressLeadsWhateverTheOrder(t *testing.T) {
	cfg := publicClampConfig(t)
	stub := &dnsStub{
		srv: map[string][]*net.SRV{"sip.example": {
			{Target: "lan.example.", Port: 5070, Priority: 1},
			{Target: "wan.example.", Port: 5080, Priority: 2},
		}},
		ips: map[string][]string{
			"gw.example":  {"10.0.0.1", "192.0.2.10"},
			"lan.example": {"10.0.0.2"},
			"wan.example": {"192.0.2.20"},
		},
	}
	d := newClampDirectory(cfg, stub, &fakeClock{t: time.Unix(1000, 0)}, aCarrier, srvCarrier)
	d.refresh(context.Background())
	s := &Server{carriers: d}
	for _, c := range []struct{ name, want, refused string }{
		{"a", "192.0.2.10:5060", "10.0.0.1"},
		{"s", "192.0.2.20:5080", "10.0.0.2"},
	} {
		if got := d.snapshot().addrs[c.name]; len(got) != 1 || got[0] != ap(c.want) {
			t.Errorf("%s: addrs = %v, want only %s", c.name, got, c.want)
		}
		if dest, ok := s.carrierDest(c.name); !ok || dest != c.want {
			t.Errorf("%s: carrierDest = %q, %v; want %s", c.name, dest, ok, c.want)
		}
		if d.snapshot().isSource(netip.MustParseAddr(c.refused)) {
			t.Errorf("%s: the refused %s is a carrier source", c.name, c.refused)
		}
		if name, ok := d.snapshot().carrierFor(ap(c.refused+":5060"), "udp"); ok {
			t.Errorf("%s: carrierFor(%s) = %q, want no carrier", c.name, c.refused, name)
		}
		if !d.snapshot().isSource(netip.MustParseAddr(strings.Split(c.want, ":")[0])) {
			t.Errorf("%s: the good address is not a carrier source", c.name)
		}
	}
	for _, info := range d.snapshotInfo() {
		if info.Failing {
			t.Errorf("%s: failing (%s) with a good address in the answer", info.Name, info.LastError)
		}
	}
}

// An answer the clamp empties is a failed lookup: the last good set stays,
// and the error the operator view (and the carrier_dns health condition)
// shows says the addresses were refused.
func TestCarrierClampAllRefusedKeepsLastGood(t *testing.T) {
	cfg := publicClampConfig(t)
	stub := &dnsStub{ips: map[string][]string{"gw.example": {"192.0.2.1"}}}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	d := newClampDirectory(cfg, stub, clk, aCarrier)
	d.refresh(context.Background())

	stub.mu.Lock()
	stub.ips["gw.example"] = []string{"127.0.0.1", "10.0.0.1"}
	stub.mu.Unlock()
	clk.advance(carrierDNSTTL + time.Second)
	d.refresh(context.Background())

	if got := d.snapshot().addrs["a"]; len(got) != 1 || got[0] != ap("192.0.2.1:5060") {
		t.Fatalf("addrs after an all-refused answer = %v, want the last good 192.0.2.1:5060", got)
	}
	snap := d.snapshot()
	if !snap.isSource(netip.MustParseAddr("192.0.2.1")) || snap.isSource(netip.MustParseAddr("10.0.0.1")) || snap.isSource(netip.MustParseAddr("127.0.0.1")) {
		t.Error("sources after an all-refused answer are not the last good set alone")
	}
	info := d.snapshotInfo()[0]
	if !info.Failing || len(info.Addresses) != 1 || !info.Addresses[0].InUse {
		t.Errorf("info = %+v, want failing on the stale set", info)
	}
	want := "lookup gw.example: every address refused: 127.0.0.1 (loopback), 10.0.0.1 (private)"
	if info.LastError != want {
		t.Errorf("LastError = %q, want %q", info.LastError, want)
	}
	if !info.ExpiresAt.Equal(clk.now().Add(carrierDNSNegTTL)) {
		t.Errorf("next retry at %v, want the negative TTL", info.ExpiresAt)
	}
}

// With public.ip itself private (a lab, a private peering) the private
// classes are lifted, as on the public media plane; loopback, link-local,
// FreeSBC's own addresses and the switch stay refused.
func TestCarrierClampPrivatePublicIPLiftsPrivate(t *testing.T) {
	cfg := clampConfig(t, "{ip: 10.0.0.5}", "10.0.1.6", "10.0.1.10:5060")
	for _, c := range []struct{ ip, reason string }{
		{"10.0.0.1", ""},
		{"172.16.0.1", ""},
		{"100.64.0.1", ""},
		{"fd00::1", ""},
		{"192.0.2.1", ""},
		{"127.0.0.1", clampLoopback},
		{"169.254.169.254", clampLinkLocal},
		{"fe80::1", clampLinkLocal},
		{"10.0.0.5", clampOwn},
		{"10.0.1.6", clampOwn},
		{"10.0.1.10", clampSwitch},
	} {
		stub := &dnsStub{srv: srvRecords, ips: map[string][]string{"gw.example": {c.ip}}}
		d := newClampDirectory(cfg, stub, &fakeClock{t: time.Unix(1000, 0)}, aCarrier, srvCarrier)
		d.refresh(context.Background())
		if c.reason != "" {
			assertRefused(t, d, "a", c.ip, c.reason)
			assertRefused(t, d, "s", c.ip, c.reason)
			continue
		}
		snap := d.snapshot()
		ip := netip.MustParseAddr(c.ip)
		if got := snap.addrs["a"]; len(got) != 1 || got[0] != netip.AddrPortFrom(ip, 5060) {
			t.Errorf("%s: a addrs = %v, want it accepted", c.ip, got)
		}
		if got := snap.addrs["s"]; len(got) != 1 || got[0] != netip.AddrPortFrom(ip, 5070) {
			t.Errorf("%s: s addrs = %v, want it accepted", c.ip, got)
		}
		if !snap.isSource(ip) {
			t.Errorf("%s: not a carrier source", c.ip)
		}
	}
}

// A public plane on loopback (a single-host lab, the test suites) may
// resolve a carrier to loopback, the media pools' AllowLoopback rule: there
// FreeSBC, the switch and the carrier share 127.0.0.1. Nothing else is
// lifted: 127.0.0.1 is not a private class.
func TestCarrierClampLoopbackPlaneAllowsLoopback(t *testing.T) {
	cfg := clampConfig(t, "{ip: 127.0.0.1}", "127.0.0.2", "127.0.0.1:5070")
	p := newCarrierAddrPolicy(cfg, netip.MustParseAddr("127.0.0.1"))
	for _, c := range []struct{ ip, reason string }{
		{"127.0.0.1", ""},
		{"127.0.0.2", ""},
		{"::1", ""},
		{"10.0.0.1", clampPrivate},
		{"169.254.169.254", clampLinkLocal},
		{"192.0.2.1", ""},
	} {
		if got := p.refuses(netip.MustParseAddr(c.ip)); got != c.reason {
			t.Errorf("refuses(%s) = %q, want %q", c.ip, got, c.reason)
		}
	}
	// public.bind alone on loopback is enough, as for the media plane.
	cfg = clampConfig(t, "{ip: 203.0.113.7, bind: 127.0.0.1}", "10.77.0.2", "10.77.0.10:5060")
	if got := newCarrierAddrPolicy(cfg, cfg.PrivateAddr().Addr()).refuses(netip.MustParseAddr("127.0.0.1")); got != "" {
		t.Errorf("refuses(127.0.0.1) with public.bind on loopback = %q, want accepted", got)
	}
}

// Each refused address is warned about once, naming the carrier, the
// address and its class, however many targets carried it; while later
// answers still hold it the repeat is Debug, and an address that leaves the
// answer and comes back is warned about again.
func TestCarrierClampWarnsOncePerAddress(t *testing.T) {
	cfg := publicClampConfig(t)
	stub := &dnsStub{
		srv: map[string][]*net.SRV{"sip.example": {
			{Target: "gw1.example.", Port: 5070, Priority: 1},
			{Target: "gw2.example.", Port: 5080, Priority: 2},
		}},
		ips: map[string][]string{
			"gw1.example": {"127.0.0.1", "192.0.2.1"},
			"gw2.example": {"127.0.0.1", "169.254.169.254"},
		},
	}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	rec := newLogRecorder()
	d := newClampDirectory(cfg, stub, clk, srvCarrier)
	d.log = slog.New(rec)
	warns := func() map[string]string {
		out := map[string]string{}
		for _, r := range rec.snapshot() {
			if r.level == slog.LevelWarn && strings.Contains(r.msg, "refused") {
				if r.attrs["carrier"] != "s" {
					t.Errorf("refusal warning %q names carrier %q, want s", r.msg, r.attrs["carrier"])
				}
				if _, dup := out[r.attrs["addr"]]; dup {
					t.Errorf("address %s warned about twice", r.attrs["addr"])
				}
				out[r.attrs["addr"]] = r.attrs["reason"]
			}
		}
		return out
	}

	d.refresh(context.Background())
	if got := warns(); len(got) != 2 || got["127.0.0.1"] != clampLoopback || got["169.254.169.254"] != clampLinkLocal {
		t.Fatalf("refusal warnings = %v, want one each for 127.0.0.1 (loopback) and 169.254.169.254 (link-local)", got)
	}
	if got := d.snapshot().addrs["s"]; len(got) != 1 || got[0] != ap("192.0.2.1:5070") {
		t.Fatalf("addrs = %v, want 192.0.2.1:5070", got)
	}

	clk.advance(carrierDNSTTL + time.Second)
	d.refresh(context.Background()) // the same answer again
	if got := warns(); len(got) != 2 {
		t.Errorf("a repeated answer warned again: %v", got)
	}

	stub.mu.Lock()
	stub.ips["gw2.example"] = []string{"192.0.2.2"}
	stub.mu.Unlock()
	clk.advance(carrierDNSTTL + time.Second)
	d.refresh(context.Background()) // 169.254.169.254 leaves the answer
	stub.mu.Lock()
	stub.ips["gw2.example"] = []string{"169.254.169.254"}
	stub.mu.Unlock()
	clk.advance(carrierDNSTTL + time.Second)
	d.refresh(context.Background()) // and comes back
	n := 0
	for _, r := range rec.snapshot() {
		if r.level == slog.LevelWarn && r.attrs["addr"] == "169.254.169.254" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("169.254.169.254 warned about %d times, want 2 (first answer, and again after it left and came back)", n)
	}
}

// A literal-IP carrier is the operator's own statement and is not clamped:
// a private-network carrier written as an IP is a destination and a source.
func TestCarrierClampLeavesLiteralCarriers(t *testing.T) {
	cfg := publicClampConfig(t)
	stub := &dnsStub{}
	lit := config.Carrier{Name: "lan", Host: "10.0.0.9", Port: 5060, Addr: netip.MustParseAddr("10.0.0.9")}
	d := newTestDirectory(stub, &fakeClock{t: time.Unix(1000, 0)},
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.9/32")}, lit)
	d.policy = newCarrierAddrPolicy(cfg, cfg.PrivateAddr().Addr())
	d.refresh(context.Background())
	if s, i := stub.calls(); s != 0 || i != 0 {
		t.Fatalf("a literal carrier triggered %d SRV and %d address lookups", s, i)
	}
	if got := d.snapshot().addrs["lan"]; len(got) != 1 || got[0] != ap("10.0.0.9:5060") {
		t.Errorf("literal private carrier addrs = %v, want 10.0.0.9:5060", got)
	}
	if name, ok := d.snapshot().carrierFor(ap("10.0.0.9:5060"), "udp"); !ok || name != "lan" {
		t.Errorf("carrierFor(10.0.0.9:5060) = %q, %v; want lan", name, ok)
	}
	if dest, ok := (&Server{carriers: d}).carrierDest("lan"); !ok || dest != "10.0.0.9:5060" {
		t.Errorf("carrierDest = %q, %v; want 10.0.0.9:5060", dest, ok)
	}
}
