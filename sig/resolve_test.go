package sig

import (
	"net"
	"testing"
	"time"

	"github.com/freesbc/freesbc/config"
)

func TestResolveLiteralIP(t *testing.T) {
	r := newResolver(1)
	// No lookupSRV should ever be called for a literal IP.
	r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		t.Fatal("lookupSRV must not be called for a literal IP")
		return "", nil, nil
	}
	eps := r.Resolve(&config.Peer{Address: "1.2.3.4", Transport: "udp"}, time.Minute)
	if len(eps) != 1 || eps[0] != (Endpoint{Host: "1.2.3.4", Port: 5060, Transport: "udp"}) {
		t.Fatalf("literal IP → %+v, want single 1.2.3.4:5060/udp", eps)
	}
	eps = r.Resolve(&config.Peer{Address: "1.2.3.4:5070", Transport: "tcp"}, time.Minute)
	if len(eps) != 1 || eps[0].Port != 5070 || eps[0].Host != "1.2.3.4" {
		t.Fatalf("literal IP:port → %+v, want 1.2.3.4:5070", eps)
	}
}

func TestResolveHostWithExplicitPortSkipsSRV(t *testing.T) {
	r := newResolver(1)
	r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		t.Fatal("lookupSRV must not be called when the address has an explicit port")
		return "", nil, nil
	}
	eps := r.Resolve(&config.Peer{Address: "carrier.example:5080", Transport: "udp"}, time.Minute)
	if len(eps) != 1 || eps[0] != (Endpoint{Host: "carrier.example", Port: 5080, Transport: "udp"}) {
		t.Fatalf("host:port → %+v, want carrier.example:5080/udp (no SRV)", eps)
	}
}

func TestResolveHostSRVPriorityOrder(t *testing.T) {
	r := newResolver(1)
	var gotService, gotProto, gotName string
	r.lookupSRV = func(service, proto, name string) (string, []*net.SRV, error) {
		gotService, gotProto, gotName = service, proto, name
		return "", []*net.SRV{
			{Target: "sip2.carrier.example.", Port: 5060, Priority: 20, Weight: 0},
			{Target: "sip1.carrier.example.", Port: 5061, Priority: 10, Weight: 0},
		}, nil
	}
	eps := r.Resolve(&config.Peer{Address: "carrier.example", Transport: "udp"}, time.Minute)
	if gotService != "sip" || gotProto != "udp" || gotName != "carrier.example" {
		t.Fatalf("SRV query = _%s._%s.%s, want _sip._udp.carrier.example", gotService, gotProto, gotName)
	}
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %+v", eps)
	}
	// Priority 10 must sort before priority 20; trailing dot stripped.
	if eps[0].Host != "sip1.carrier.example" || eps[0].Port != 5061 {
		t.Errorf("first endpoint = %s:%d, want sip1.carrier.example:5061", eps[0].Host, eps[0].Port)
	}
	if eps[1].Host != "sip2.carrier.example" {
		t.Errorf("second endpoint = %s, want sip2.carrier.example", eps[1].Host)
	}
}

func TestResolveHostNoSRVFallsBackToHostname(t *testing.T) {
	r := newResolver(1)
	r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		return "", nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	eps := r.Resolve(&config.Peer{Address: "plain.example", Transport: "tls"}, time.Minute)
	if len(eps) != 1 || eps[0] != (Endpoint{Host: "plain.example", Port: 5060, Transport: "tls"}) {
		t.Fatalf("no-SRV fallback → %+v, want plain.example:5060/tls", eps)
	}
}

func TestResolveTLSUsesSipsService(t *testing.T) {
	r := newResolver(1)
	var gotService, gotProto string
	r.lookupSRV = func(service, proto, _ string) (string, []*net.SRV, error) {
		gotService, gotProto = service, proto
		return "", nil, nil
	}
	r.Resolve(&config.Peer{Address: "secure.example", Transport: "tls"}, time.Minute)
	if gotService != "sips" || gotProto != "tcp" {
		t.Errorf("tls SRV query = _%s._%s, want _sips._tcp", gotService, gotProto)
	}
}

func TestResolveCachesWithinTTL(t *testing.T) {
	r := newResolver(1)
	fakeNow := time.Unix(1000, 0)
	r.now = func() time.Time { return fakeNow }
	calls := 0
	r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		calls++
		return "", []*net.SRV{{Target: "a.example.", Port: 5060, Priority: 10, Weight: 0}}, nil
	}
	peer := &config.Peer{Address: "cached.example", Transport: "udp"}
	r.Resolve(peer, 100*time.Second)
	r.Resolve(peer, 100*time.Second) // within TTL → cache hit
	if calls != 1 {
		t.Fatalf("lookupSRV called %d times, want 1 (second is a cache hit)", calls)
	}
	fakeNow = fakeNow.Add(101 * time.Second) // TTL expired
	r.Resolve(peer, 100*time.Second)
	if calls != 2 {
		t.Fatalf("lookupSRV called %d times, want 2 (re-resolve after TTL)", calls)
	}
}

func TestEndpointKey(t *testing.T) {
	k := endpointKey(Endpoint{Host: "1.2.3.4", Port: 5060, Transport: "UDP"})
	if k != "1.2.3.4:5060/udp" {
		t.Errorf("endpointKey = %q, want 1.2.3.4:5060/udp (transport lowercased)", k)
	}
}

func TestResolveWeightedShuffleDeterministicWithSeed(t *testing.T) {
	// Two equal-priority, equal-weight records: with a fixed seed the order
	// is stable across runs (proves the shuffle uses the injected rand, not
	// the global one).
	mk := func() []Endpoint {
		r := newResolver(42)
		r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
			return "", []*net.SRV{
				{Target: "x.example.", Port: 5060, Priority: 10, Weight: 10},
				{Target: "y.example.", Port: 5060, Priority: 10, Weight: 10},
			}, nil
		}
		return r.Resolve(&config.Peer{Address: "w.example", Transport: "udp"}, time.Minute)
	}
	a, b := mk(), mk()
	if len(a) != 2 || a[0].Host != b[0].Host || a[1].Host != b[1].Host {
		t.Fatalf("seeded shuffle not deterministic: %+v vs %+v", a, b)
	}
}
