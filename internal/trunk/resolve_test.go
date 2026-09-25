package trunk

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
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
	// T-30 (D8-4): the tls fallback port is 5061 (RFC 3263 §4.1), not 5060.
	eps := r.Resolve(&config.Peer{Address: "plain.example", Transport: "tls"}, time.Minute)
	if len(eps) != 1 || eps[0] != (Endpoint{Host: "plain.example", Port: 5061, Transport: "tls"}) {
		t.Fatalf("no-SRV fallback → %+v, want plain.example:5061/tls", eps)
	}
}

// TestResolveTLSUsesDefaultPort5061 (T-30/D8-4): a tls peer with no
// explicit port and no SRV must fall back to 5061 — dialing 5060 over TLS
// was a real call-failure bug. udp keeps 5060.
func TestResolveTLSUsesDefaultPort5061(t *testing.T) {
	r := newResolver(1)
	r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		return "", nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	eps := r.Resolve(&config.Peer{Address: "1.2.3.4", Transport: "tls"}, time.Minute)
	if len(eps) != 1 || eps[0].Port != 5061 {
		t.Fatalf("tls literal IP → %+v, want port 5061", eps)
	}
	eps = r.Resolve(&config.Peer{Address: "1.2.3.4", Transport: "udp"}, time.Minute)
	if len(eps) != 1 || eps[0].Port != 5060 {
		t.Fatalf("udp literal IP → %+v, want port 5060", eps)
	}
}

// TestResolveSRVSkipsUnusableRecords (T-29/D8-2): RFC 2782 Target "."
// ("service unavailable") and port-0 records must not become dialable
// endpoints; an all-filtered record set falls back like a no-SRV answer.
func TestResolveSRVSkipsUnusableRecords(t *testing.T) {
	r := newResolver(1)
	r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{Target: ".", Port: 5060, Priority: 10, Weight: 0},
			{Target: "good.example.", Port: 0, Priority: 10, Weight: 0},
			{Target: "ok.example.", Port: 5060, Priority: 10, Weight: 0},
		}, nil
	}
	eps := r.Resolve(&config.Peer{Address: "mixed.example", Transport: "udp"}, time.Minute)
	if len(eps) != 1 || eps[0].Host != "ok.example" || eps[0].Port != 5060 {
		t.Fatalf("filtered SRV → %+v, want only ok.example:5060", eps)
	}

	r2 := newResolver(1)
	r2.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		return "", []*net.SRV{{Target: ".", Port: 5060, Priority: 10, Weight: 0}}, nil
	}
	eps = r2.Resolve(&config.Peer{Address: "dead.example", Transport: "udp"}, time.Minute)
	if len(eps) != 1 || eps[0] != (Endpoint{Host: "dead.example", Port: 5060, Transport: "udp"}) {
		t.Fatalf("all-filtered SRV → %+v, want fallback dead.example:5060/udp", eps)
	}
}

// TestResolveNegativeCacheIsShort (T-28/D8-1): a transient lookup failure
// must not pin the fallback endpoint for the full srv_cache_ttl — it is
// cached only for srvFailCacheTTL, then re-queried.
func TestResolveNegativeCacheIsShort(t *testing.T) {
	r := newResolver(1)
	fakeNow := time.Unix(1000, 0)
	r.now = func() time.Time { return fakeNow }
	calls := 0
	r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		calls++
		return "", nil, &net.DNSError{Err: "timeout"}
	}
	peer := &config.Peer{Address: "flaky.example", Transport: "udp"}
	r.Resolve(peer, 5*time.Minute) // failure → short negative cache
	r.Resolve(peer, 5*time.Minute)
	if calls != 1 {
		t.Fatalf("lookupSRV called %d times, want 1 (short-cached failure)", calls)
	}
	fakeNow = fakeNow.Add(srvFailCacheTTL + time.Second)
	r.Resolve(peer, 5*time.Minute) // short TTL expired → re-query, not 300s
	if calls != 2 {
		t.Fatalf("lookupSRV called %d times, want 2 (failure must re-query after %v, not the full TTL)", calls, srvFailCacheTTL)
	}
}

// TestResolveConcurrentLookupSingleflighted (T-28/D8-1): a burst of
// concurrent Resolves for the same uncached host triggers exactly ONE DNS
// lookup — the rest share the in-flight result or the cache.
func TestResolveConcurrentLookupSingleflighted(t *testing.T) {
	r := newResolver(1)
	var calls atomic.Int32
	release := make(chan struct{})
	r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		calls.Add(1)
		<-release
		return "", []*net.SRV{{Target: "a.example.", Port: 5060, Priority: 10, Weight: 0}}, nil
	}
	peer := &config.Peer{Address: "burst.example", Transport: "udp"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eps := r.Resolve(peer, time.Minute)
			if len(eps) != 1 || eps[0].Host != "a.example" {
				t.Errorf("unexpected result: %+v", eps)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond) // let the burst pile up on the flight
	close(release)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("lookupSRV called %d times, want exactly 1 for a concurrent burst", got)
	}
}

// TestResolveLookupTimeoutFallsBack (T-28/D8-1): a resolver that hangs past
// srvLookupTimeout must not pin the call — it falls back like any other
// lookup failure, bounded in time.
func TestResolveLookupTimeoutFallsBack(t *testing.T) {
	r := newResolver(1)
	block := make(chan struct{})
	defer close(block)
	r.lookupSRV = lookupSRVTimeout(func(ctx context.Context, _, _, _ string) (string, []*net.SRV, error) {
		select { // hang past the wrapper's deadline
		case <-block:
		case <-ctx.Done():
		}
		return "", nil, &net.DNSError{Err: "late"}
	})
	start := time.Now()
	eps := r.Resolve(&config.Peer{Address: "hung.example", Transport: "udp"}, time.Minute)
	if elapsed := time.Since(start); elapsed > 2*srvLookupTimeout {
		t.Fatalf("lookup took %v, want bounded by ~%v", elapsed, srvLookupTimeout)
	}
	if len(eps) != 1 || eps[0] != (Endpoint{Host: "hung.example", Port: 5060, Transport: "udp"}) {
		t.Fatalf("timeout fallback → %+v, want hung.example:5060/udp", eps)
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

// TestResolveWeightedSelectionZeroWeightGetsAChance proves RFC 2782 compliance:
// "In the presence of records containing weights greater than 0, records with
// weight 0 should be placed at the beginning of the list" — a weight-0 record
// in a mixed-weight group must retain a small but nonzero chance of being
// selected first, not a hard 0%. We sample across many independently-seeded
// resolvers (the cache means a single resolver instance would only ever
// resolve once, so we vary the seed per iteration to sample the underlying
// distribution). With 200 samples and roughly a 1/101 chance per trial of the
// zero-weight record landing first, seeing it at least once is essentially
// certain (failure probability (100/101)^200 ≈ 1.4e-1... — see below for the
// exact margin), so this assertion cannot flake in practice while still
// proving weighting works: the weight-100 record must dominate.
func TestResolveWeightedSelectionZeroWeightGetsAChance(t *testing.T) {
	const samples = 200
	zeroFirst := 0
	heavyFirst := 0
	for i := 0; i < samples; i++ {
		r := newResolver(int64(i) + 1) // distinct seed per sample
		r.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
			return "", []*net.SRV{
				{Target: "heavy.example.", Port: 5060, Priority: 10, Weight: 100},
				{Target: "zero.example.", Port: 5060, Priority: 10, Weight: 0},
			}, nil
		}
		eps := r.Resolve(&config.Peer{Address: "mixed.example", Transport: "udp"}, time.Minute)
		if len(eps) != 2 {
			t.Fatalf("sample %d: want 2 endpoints, got %+v", i, eps)
		}
		switch eps[0].Host {
		case "zero.example":
			zeroFirst++
		case "heavy.example":
			heavyFirst++
		default:
			t.Fatalf("sample %d: unexpected first endpoint %+v", i, eps[0])
		}
	}
	// The old (buggy) behavior gave the weight-0 record exactly 0% chance of
	// being first whenever it appeared after the weighted record in the DNS
	// answer — the mock above lists heavy.example (weight 100) first and
	// zero.example (weight 0) second, exactly that ordering, so the
	// running-sum walk in the pre-fix code always landed on heavy.example.
	// Seeing zero.example first at all — across 200 independent seeds —
	// proves the fix is in effect. This is not a
	// probabilistic near-miss: with target := rnd.Intn(101), zero.example is
	// picked first only when target == 0 (~1% chance per sample), so getting
	// zero hits across 200 samples would require ~200 consecutive misses of a
	// ~1% event, astronomically unlikely for a well-distributed PRNG.
	if zeroFirst == 0 {
		t.Fatalf("weight-0 record was never selected first across %d samples; want at least one (RFC 2782 §3 wants it to retain a small nonzero chance)", samples)
	}
	// The weighted record should still dominate — proves weighting is not
	// broken by the zero-weight reordering (e.g. accidentally treating the
	// group as uniform).
	if heavyFirst < samples*9/10 {
		t.Fatalf("weight-100 record was first only %d/%d times, want large majority (weighting still in effect)", heavyFirst, samples)
	}
}

// audit: P2-TRK-020
// A timed-out SRV lookup must end, not be abandoned in a goroutine that
// keeps running until the system resolver gives up: the lookup runs under
// a context that expires with srvLookupTimeout.
func TestSRVLookupTimeoutEndsTheLookup(t *testing.T) {
	r := newResolver(1)
	ended := make(chan struct{})
	r.lookupSRV = lookupSRVTimeout(func(ctx context.Context, _, _, _ string) (string, []*net.SRV, error) {
		defer close(ended)
		<-ctx.Done() // a resolver that only returns when told to
		return "", nil, ctx.Err()
	})
	r.Resolve(&config.Peer{Address: "hung.example", Transport: "udp"}, time.Minute)
	select {
	case <-ended:
	default:
		t.Fatal("Resolve returned while the timed-out lookup was still running")
	}
}
