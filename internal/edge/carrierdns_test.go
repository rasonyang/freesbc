package edge

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// dnsStub is a controllable resolver for the carrier directory: it counts
// lookups and answers from maps the test edits between refreshes.
type dnsStub struct {
	mu       sync.Mutex
	srv      map[string][]*net.SRV // name → records
	srvErr   error
	ips      map[string][]string // host → addresses
	ipErr    error
	srvCalls []string
	ipCalls  []string
}

func (s *dnsStub) lookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.srvCalls = append(s.srvCalls, "_"+service+"._"+proto+"."+name)
	if s.srvErr != nil {
		return "", nil, s.srvErr
	}
	recs, ok := s.srv[name]
	if !ok {
		return "", nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return "", recs, nil
}

func (s *dnsStub) lookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipCalls = append(s.ipCalls, host)
	if s.ipErr != nil {
		return nil, s.ipErr
	}
	var out []netip.Addr
	for _, a := range s.ips[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

func (s *dnsStub) calls() (srv, ip int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.srvCalls), len(s.ipCalls)
}

// fakeClock is a settable time source.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestDirectory(stub *dnsStub, clk *fakeClock, static []netip.Prefix, carriers ...config.Carrier) *carrierDirectory {
	d := &carrierDirectory{
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		carriers:  carriers,
		static:    static,
		lookupSRV: stub.lookupSRV,
		lookupIP:  stub.lookupIP,
		now:       clk.now,
		entries:   map[string]*carrierEntry{},
		rnd:       rand.New(rand.NewSource(1)),
	}
	d.publish()
	return d
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestCarrierDirectoryLiteralIsStatic(t *testing.T) {
	stub := &dnsStub{}
	d := newTestDirectory(stub, &fakeClock{t: time.Unix(1000, 0)},
		[]netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")},
		config.Carrier{Name: "lit", Host: "198.51.100.4", Port: 16060, ExplicitPort: true, Addr: netip.MustParseAddr("198.51.100.4")})
	d.refresh(context.Background())
	if s, i := stub.calls(); s != 0 || i != 0 {
		t.Fatalf("a literal carrier triggered %d SRV and %d address lookups", s, i)
	}
	snap := d.snapshot()
	if got := snap.addrs["lit"]; len(got) != 1 || got[0] != ap("198.51.100.4:16060") {
		t.Errorf("literal carrier addrs = %v", got)
	}
	if !snap.isSource(netip.MustParseAddr("198.51.100.4")) || !snap.isSource(netip.MustParseAddr("203.0.113.9")) {
		t.Error("static prefixes are not sources")
	}
}

func TestCarrierDirectorySRVOrderAndTargets(t *testing.T) {
	stub := &dnsStub{
		srv: map[string][]*net.SRV{"sip.carrier.example": {
			{Target: "gw2.carrier.example.", Port: 5062, Priority: 20, Weight: 10},
			{Target: "gw1.carrier.example.", Port: 5061, Priority: 10, Weight: 10},
			{Target: ".", Port: 5060, Priority: 5, Weight: 1}, // service unavailable: skipped
		}},
		ips: map[string][]string{
			"gw1.carrier.example": {"192.0.2.1"},
			"gw2.carrier.example": {"192.0.2.2", "2001:db8::2"},
		},
	}
	d := newTestDirectory(stub, &fakeClock{t: time.Unix(1000, 0)}, nil,
		config.Carrier{Name: "a", Host: "sip.carrier.example", Port: 5060})
	d.refresh(context.Background())

	if stub.srvCalls[0] != "_sip._udp.sip.carrier.example" {
		t.Errorf("SRV query = %q, want _sip._udp.sip.carrier.example", stub.srvCalls[0])
	}
	want := []netip.AddrPort{ap("192.0.2.1:5061"), ap("192.0.2.2:5062"), ap("[2001:db8::2]:5062")}
	got := d.snapshot().addrs["a"]
	if len(got) != len(want) {
		t.Fatalf("addrs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("addrs[%d] = %v, want %v (priority 10 before 20)", i, got[i], want[i])
		}
	}
	if !d.snapshot().isSource(netip.MustParseAddr("192.0.2.2")) {
		t.Error("a resolved address is not a carrier source")
	}
}

func TestCarrierDirectoryExplicitPortSkipsSRV(t *testing.T) {
	stub := &dnsStub{ips: map[string][]string{"gw.carrier.example": {"192.0.2.7"}}}
	d := newTestDirectory(stub, &fakeClock{t: time.Unix(1000, 0)}, nil,
		config.Carrier{Name: "a", Host: "gw.carrier.example", Port: 5080, ExplicitPort: true})
	d.refresh(context.Background())
	if s, _ := stub.calls(); s != 0 {
		t.Fatalf("an explicit port still queried SRV (%d lookups)", s)
	}
	if got := d.snapshot().addrs["a"]; len(got) != 1 || got[0] != ap("192.0.2.7:5080") {
		t.Errorf("addrs = %v, want 192.0.2.7:5080", got)
	}
}

func TestCarrierDirectoryNoSRVFallsBackToHost(t *testing.T) {
	stub := &dnsStub{ips: map[string][]string{"plain.carrier.example": {"192.0.2.8"}}}
	d := newTestDirectory(stub, &fakeClock{t: time.Unix(1000, 0)}, nil,
		config.Carrier{Name: "a", Host: "plain.carrier.example", Port: 5060})
	d.refresh(context.Background())
	if got := d.snapshot().addrs["a"]; len(got) != 1 || got[0] != ap("192.0.2.8:5060") {
		t.Errorf("addrs = %v, want the host's A record on 5060", got)
	}
}

func TestCarrierDirectoryCacheTTLAndRefresh(t *testing.T) {
	stub := &dnsStub{ips: map[string][]string{"gw.example": {"192.0.2.1"}}}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	d := newTestDirectory(stub, clk, nil, config.Carrier{Name: "a", Host: "gw.example", Port: 5060, ExplicitPort: true})
	d.refresh(context.Background())
	_, base := stub.calls()
	if base != 1 {
		t.Fatalf("first refresh made %d lookups, want 1", base)
	}

	clk.advance(carrierDNSTTL - time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.99"} // changed, but the cache still holds
	d.refresh(context.Background())
	if _, n := stub.calls(); n != base {
		t.Fatalf("a refresh inside the TTL looked up again (%d lookups)", n)
	}
	if got := d.snapshot().addrs["a"]; got[0] != ap("192.0.2.1:5060") {
		t.Errorf("addrs inside TTL = %v, want the cached 192.0.2.1", got)
	}

	clk.advance(2 * time.Second) // past the 300s TTL
	d.refresh(context.Background())
	if _, n := stub.calls(); n != base+1 {
		t.Fatalf("a refresh after the TTL made %d lookups, want %d", n, base+1)
	}
	if got := d.snapshot().addrs["a"]; got[0] != ap("192.0.2.99:5060") {
		t.Errorf("addrs after TTL = %v, want the new 192.0.2.99", got)
	}
	if d.snapshot().isSource(netip.MustParseAddr("192.0.2.1")) {
		t.Error("the old address is still a carrier source after the refresh")
	}
}

func TestCarrierDirectoryKeepsLastGoodOnError(t *testing.T) {
	stub := &dnsStub{ips: map[string][]string{"gw.example": {"192.0.2.1"}}}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	d := newTestDirectory(stub, clk, nil, config.Carrier{Name: "a", Host: "gw.example", Port: 5060, ExplicitPort: true})
	d.refresh(context.Background())

	stub.mu.Lock()
	stub.ipErr = errors.New("resolver down")
	stub.mu.Unlock()
	clk.advance(carrierDNSTTL + time.Second)
	d.refresh(context.Background())
	if got := d.snapshot().addrs["a"]; len(got) != 1 || got[0] != ap("192.0.2.1:5060") {
		t.Fatalf("addrs after a failed refresh = %v, want the last good set", got)
	}
	if !d.snapshot().isSource(netip.MustParseAddr("192.0.2.1")) {
		t.Error("the last good address stopped being a carrier source")
	}

	// An SRV error that is not "not found" also keeps the set rather than
	// falling back to the bare host.
	stub2 := &dnsStub{
		srv: map[string][]*net.SRV{"sip.example": {{Target: "gw.example.", Port: 5060, Priority: 1}}},
		ips: map[string][]string{"gw.example": {"192.0.2.5"}},
	}
	clk2 := &fakeClock{t: time.Unix(1000, 0)}
	d2 := newTestDirectory(stub2, clk2, nil, config.Carrier{Name: "b", Host: "sip.example", Port: 5060})
	d2.refresh(context.Background())
	stub2.mu.Lock()
	stub2.srvErr = errors.New("timeout")
	stub2.mu.Unlock()
	clk2.advance(carrierDNSTTL + time.Second)
	d2.refresh(context.Background())
	if got := d2.snapshot().addrs["b"]; len(got) != 1 || got[0] != ap("192.0.2.5:5060") {
		t.Errorf("addrs after an SRV error = %v, want the last good set", got)
	}
}

func TestCarrierDirectoryNegativeCache(t *testing.T) {
	stub := &dnsStub{ipErr: errors.New("resolver down")}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	d := newTestDirectory(stub, clk, nil, config.Carrier{Name: "a", Host: "gw.example", Port: 5060, ExplicitPort: true})

	d.refresh(context.Background()) // a startup failure is not fatal
	if got := d.snapshot().addrs["a"]; len(got) != 0 {
		t.Fatalf("addrs after a failed lookup = %v, want none", got)
	}
	_, n1 := stub.calls()

	clk.advance(carrierDNSNegTTL - time.Second)
	d.refresh(context.Background())
	if _, n := stub.calls(); n != n1 {
		t.Errorf("a refresh inside the negative TTL looked up again")
	}

	stub.mu.Lock()
	stub.ipErr = nil
	stub.ips = map[string][]string{"gw.example": {"192.0.2.3"}}
	stub.mu.Unlock()
	clk.advance(2 * time.Second) // past the 10s negative TTL, far short of 300s
	d.refresh(context.Background())
	if got := d.snapshot().addrs["a"]; len(got) != 1 || got[0] != ap("192.0.2.3:5060") {
		t.Errorf("addrs after the retry = %v, want 192.0.2.3:5060", got)
	}
}

func TestCarrierSnapshotCarrierFor(t *testing.T) {
	snap := &carrierSnapshot{
		names: []string{"alpha", "beta", "tlsco"},
		addrs: map[string][]netip.AddrPort{
			"alpha": {ap("192.0.2.1:5060")},
			"beta":  {ap("192.0.2.1:5070"), ap("192.0.2.2:5060")},
			"tlsco": {ap("192.0.2.9:5061")},
		},
		transports: map[string]string{"alpha": "udp", "beta": "udp", "tlsco": "tls"},
		nets: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("192.0.2.2/32"),
			netip.MustParsePrefix("192.0.2.9/32"), netip.MustParsePrefix("198.51.100.0/24")},
		extra: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	}
	for _, c := range []struct {
		src      string
		network  string
		wantName string
		wantOK   bool
	}{
		{"192.0.2.1:5070", "udp", "beta", true},             // exact IP:port beats the first name by IP
		{"192.0.2.1:9999", "udp", "alpha", true},            // IP only: first by sorted name
		{"192.0.2.2:9999", "udp", "beta", true},             // IP only
		{"[::ffff:192.0.2.1]:5060", "udp", "alpha", true},   // mapped address
		{"198.51.100.77:5060", "udp", carrierUnknown, true}, // in carrier_sources, matches no entry
		{"198.51.100.77:5060", "tls", carrierUnknown, true}, // carrier_sources match on any transport
		{"203.0.113.1:5060", "udp", "", false},              // not a carrier source
		{"192.0.2.9:44000", "tls", "tlsco", true},           // a tls carrier over tls, any source port
		{"192.0.2.9:5061", "udp", "", false},                // a tls carrier's IP over UDP is nobody
		{"192.0.2.1:5060", "tls", "", false},                // a udp carrier's IP over tls is nobody
		{"192.0.2.1:5060", "tcp", "", false},
	} {
		name, ok := snap.carrierFor(ap(c.src), c.network)
		if name != c.wantName || ok != c.wantOK {
			t.Errorf("carrierFor(%s, %s) = %q, %v; want %q, %v", c.src, c.network, name, ok, c.wantName, c.wantOK)
		}
	}
}

func TestOrderSRVWeights(t *testing.T) {
	recs := []*net.SRV{
		{Target: "p2.", Port: 1, Priority: 2, Weight: 5},
		{Target: "p1a.", Port: 1, Priority: 1, Weight: 0},
		{Target: "p1b.", Port: 1, Priority: 1, Weight: 100},
		{Target: "bad.", Port: 0, Priority: 1, Weight: 1}, // port 0: skipped
	}
	counts := map[string]int{}
	for seed := int64(0); seed < 200; seed++ {
		out := orderSRV(recs, rand.New(rand.NewSource(seed)))
		if len(out) != 3 || out[2].host != "p2" {
			t.Fatalf("order = %v, want the priority-2 record last and the port-0 record skipped", out)
		}
		counts[out[0].host]++
	}
	if counts["p1b"] <= counts["p1a"] || counts["p1a"] == 0 {
		t.Errorf("first-pick counts = %v; the heavy record should lead most often and the zero-weight one sometimes", counts)
	}
}

// The SRV name follows the carrier's transport, and a DNS-name carrier with
// no SRV record is dialed on the transport's default port.
func TestCarrierDirectorySRVNamePerTransport(t *testing.T) {
	for _, c := range []struct {
		transport, wantSRV string
		wantPort           string
	}{
		{"udp", "_sip._udp.sip.carrier.example", "5060"},
		{"tcp", "_sip._tcp.sip.carrier.example", "5060"},
		{"tls", "_sips._tcp.sip.carrier.example", "5061"},
	} {
		stub := &dnsStub{ips: map[string][]string{"sip.carrier.example": {"192.0.2.7"}}}
		d := newTestDirectory(stub, &fakeClock{t: time.Unix(1000, 0)}, nil,
			config.Carrier{Name: "a", Host: "sip.carrier.example", Port: 5060, Transport: c.transport})
		d.refresh(context.Background())
		if len(stub.srvCalls) != 1 || stub.srvCalls[0] != c.wantSRV {
			t.Errorf("%s: SRV queries = %v, want %s", c.transport, stub.srvCalls, c.wantSRV)
		}
		got := d.snapshot().addrs["a"]
		if len(got) != 1 || got[0] != ap("192.0.2.7:"+c.wantPort) {
			t.Errorf("%s: addrs = %v, want 192.0.2.7:%s", c.transport, got, c.wantPort)
		}
	}
}

// SRV targets and ports are used per transport, and an explicit port skips
// SRV for tls as well.
func TestCarrierDirectoryTLSSRVAndExplicitPort(t *testing.T) {
	stub := &dnsStub{
		srv: map[string][]*net.SRV{"sip.carrier.example": {{Target: "gw.carrier.example.", Port: 5071, Priority: 1}}},
		ips: map[string][]string{"gw.carrier.example": {"192.0.2.1"}, "sip.carrier.example": {"192.0.2.2"}},
	}
	d := newTestDirectory(stub, &fakeClock{t: time.Unix(1000, 0)}, nil,
		config.Carrier{Name: "srv", Host: "sip.carrier.example", Port: 5060, Transport: "tls"},
		config.Carrier{Name: "port", Host: "sip.carrier.example", Port: 7000, ExplicitPort: true, Transport: "tls"})
	d.refresh(context.Background())
	snap := d.snapshot()
	if got := snap.addrs["srv"]; len(got) != 1 || got[0] != ap("192.0.2.1:5071") {
		t.Errorf("srv addrs = %v, want the SRV target 192.0.2.1:5071", got)
	}
	if got := snap.addrs["port"]; len(got) != 1 || got[0] != ap("192.0.2.2:7000") {
		t.Errorf("explicit-port addrs = %v, want 192.0.2.2:7000 without SRV", got)
	}
	if len(stub.srvCalls) != 1 || stub.srvCalls[0] != "_sips._tcp.sip.carrier.example" {
		t.Errorf("SRV queries = %v, want one _sips._tcp lookup", stub.srvCalls)
	}
}
