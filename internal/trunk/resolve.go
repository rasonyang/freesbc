package trunk

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
	"golang.org/x/sync/singleflight"
)

const (
	// srvLookupTimeout bounds ONE DNS resolution: the lookup runs under a
	// context with this deadline, so a slow resolver neither pins the
	// per-call goroutine for the resolver's own (much longer) timeout nor
	// leaves a lookup running after the caller gave up.
	srvLookupTimeout = 3 * time.Second
	// srvFailCacheTTL is the short cache window for a FAILED or EMPTY SRV
	// lookup: a transient DNS fault must not pin the fallback
	// endpoint for the whole srv_cache_ttl (300s by default) — re-query
	// after this instead. Cap-effective: never longer than the caller's TTL.
	srvFailCacheTTL = 10 * time.Second
)

// Endpoint is one concrete dialable trunk destination: a host (an SRV target
// name, a bare hostname, or a literal IP — sipgo does A/AAAA at send time),
// a port, and a transport. It is what a *config.Peer resolves into; a peer
// with a hostname and an SRV record resolves into several.
type Endpoint struct {
	Host      string
	Port      int
	Transport string
}

// endpointKey identifies an endpoint for health/cooldown tracking:
// "host:port/transport" with the transport lowercased so the same physical
// destination shares one entry.
func endpointKey(ep Endpoint) string {
	return net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)) + "/" + strings.ToLower(ep.Transport)
}

type cacheEntry struct {
	endpoints []Endpoint
	expiry    time.Time
}

// Resolver turns a peer into ordered endpoints via DNS SRV (with A/AAAA
// fallback left to sipgo). Results are cached per (host, transport) for a
// caller-supplied TTL — Go's net.LookupSRV exposes no record TTL, so the
// cache window is a configured value (srv_cache_ttl), not the record's own.
// lookupSRV and now are function fields so tests can inject stubs.
type Resolver struct {
	mu        sync.Mutex
	cache     map[string]cacheEntry
	sf        singleflight.Group // dedupes concurrent lookups per key
	rand      *rand.Rand
	lookupSRV func(service, proto, name string) (string, []*net.SRV, error)
	now       func() time.Time
}

func newResolver(seed int64) *Resolver {
	return &Resolver{
		cache:     make(map[string]cacheEntry),
		rand:      rand.New(rand.NewSource(seed)),
		lookupSRV: lookupSRVTimeout(net.DefaultResolver.LookupSRV),
		now:       time.Now,
	}
}

// lookupSRVTimeout adapts a context-aware SRV lookup (net.Resolver's) to
// the resolver's lookupSRV field, bounded by srvLookupTimeout. The lookup
// runs on the caller's goroutine under a context with that deadline, so
// when the deadline passes the lookup itself is cancelled and returns —
// nothing is left running — and resolveSRV falls back exactly as for any
// other lookup failure (short negative cache).
func lookupSRVTimeout(fn func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)) func(service, proto, name string) (string, []*net.SRV, error) {
	return func(service, proto, name string) (string, []*net.SRV, error) {
		ctx, cancel := context.WithTimeout(context.Background(), srvLookupTimeout)
		defer cancel()
		cname, recs, err := fn(ctx, service, proto, name)
		if err != nil && ctx.Err() != nil {
			return "", nil, fmt.Errorf("srv lookup timed out after %v: %w", srvLookupTimeout, err)
		}
		return cname, recs, err
	}
}

// Resolve returns the ordered endpoints for peer. Address-shape rules
// (RFC 3263 §4): a literal IP or a host with an explicit port is used
// directly (no SRV); a bare hostname triggers an SRV lookup, ordered by
// priority then weight, falling back to the bare hostname when there is no
// SRV record. Always returns at least one endpoint for a non-empty address.
// The default port follows the transport: tls → 5061
// (RFC 3263 §4.1 sips fallback), udp/tcp → 5060.
func (r *Resolver) Resolve(peer *config.Peer, cacheTTL time.Duration) []Endpoint {
	transport := peer.Transport
	if transport == "" {
		transport = "udp"
	}
	host, port, explicitPort, isIP := classifyAddress(peer.Address)
	if !explicitPort {
		port = fsip.DefaultPort(transport)
	}
	if isIP || explicitPort {
		return []Endpoint{{Host: host, Port: port, Transport: transport}}
	}
	return r.resolveSRV(host, transport, cacheTTL)
}

func (r *Resolver) resolveSRV(host, transport string, cacheTTL time.Duration) []Endpoint {
	key := host + "/" + strings.ToLower(transport)

	r.mu.Lock()
	if e, ok := r.cache[key]; ok && r.now().Before(e.expiry) {
		r.mu.Unlock()
		return e.endpoints
	}
	r.mu.Unlock()

	// Concurrent Resolves for the same uncached key share ONE
	// lookup (singleflight) — a cache-miss burst of N calls must not mean N
	// DNS queries.
	epsAny, _, _ := r.sf.Do(key, func() (any, error) {
		r.mu.Lock()
		// Another caller may have filled the cache before this flight ran.
		if e, ok := r.cache[key]; ok && r.now().Before(e.expiry) {
			r.mu.Unlock()
			return e.endpoints, nil
		}
		r.mu.Unlock()

		// Do the (blocking, timeout-bounded) DNS lookup without the lock
		// held, so a slow resolver for one host does not stall calls to
		// other hosts.
		service, proto := srvService(transport)
		_, recs, err := r.lookupSRV(service, proto, host)

		r.mu.Lock()
		defer r.mu.Unlock()
		var eps []Endpoint
		ttl := cacheTTL
		switch {
		case err != nil || len(recs) == 0:
			// No SRV at all, or a transient DNS failure: fall back to the
			// bare host — but cached only briefly (srvFailCacheTTL) so a
			// momentary resolver outage doesn't pin the fallback for the
			// whole srv_cache_ttl.
			eps = []Endpoint{{Host: host, Port: fsip.DefaultPort(transport), Transport: transport}}
			ttl = min(cacheTTL, srvFailCacheTTL)
		default:
			eps = orderSRV(recs, transport, r.rand)
			if len(eps) == 0 {
				// Every record was filtered as unusable (all
				// Target "." / port 0) — treat like no SRV, and cache it
				// short: the record set clearly changed recently.
				eps = []Endpoint{{Host: host, Port: fsip.DefaultPort(transport), Transport: transport}}
				ttl = min(cacheTTL, srvFailCacheTTL)
			}
		}
		r.cache[key] = cacheEntry{endpoints: eps, expiry: r.now().Add(ttl)}
		return eps, nil
	})
	return epsAny.([]Endpoint)
}

// classifyAddress splits a peer address into host/port and reports whether a
// port was explicitly given and whether the host is a literal IP. The port
// default is transport-aware in Resolve (defaultPort); the 5060
// here is only a placeholder for callers that don't consult the transport.
func classifyAddress(address string) (host string, port int, explicitPort, isIP bool) {
	port = 5060
	if h, ps, err := net.SplitHostPort(address); err == nil {
		host = h
		if n, e := strconv.Atoi(ps); e == nil {
			port = n
			explicitPort = true
		}
	} else {
		host = address
	}
	_, perr := netip.ParseAddr(host)
	isIP = perr == nil
	return host, port, explicitPort, isIP
}

// srvService maps a transport to the SRV owner name's service/proto labels:
// udp → _sip._udp, tcp → _sip._tcp, tls → _sips._tcp.
func srvService(transport string) (service, proto string) {
	switch strings.ToLower(transport) {
	case "tls":
		return "sips", "tcp"
	case "tcp":
		return "sip", "tcp"
	default:
		return "sip", "udp"
	}
}

// orderSRV converts SRV records into endpoints ordered by priority ascending,
// then RFC 2782 weighted-random selection within each equal-priority group.
// rnd must be called under the Resolver mutex (rand.Rand is not concurrency
// safe); resolveSRV holds it.
func orderSRV(recs []*net.SRV, transport string, rnd *rand.Rand) []Endpoint {
	// Group by priority (ascending), skipping unusable records first:
	// Target "." means "service unavailable" per RFC 2782, and
	// a port-0 target is undialable — either would enter the failover chain
	// as a bogus endpoint. resolveSRV treats an all-filtered set as no-SRV.
	byPrio := map[uint16][]*net.SRV{}
	var prios []uint16
	for _, rec := range recs {
		if rec.Target == "." || rec.Port == 0 {
			continue
		}
		if _, seen := byPrio[rec.Priority]; !seen {
			prios = append(prios, rec.Priority)
		}
		byPrio[rec.Priority] = append(byPrio[rec.Priority], rec)
	}
	sortUint16(prios)

	var out []Endpoint
	for _, p := range prios {
		group := byPrio[p]
		// RFC 2782: "In the presence of records containing weights greater
		// than 0, records with weight 0 should be placed at the beginning
		// of the list" — move zero-weight records to the front (stable,
		// preserving relative order within each subgroup) so they retain a
		// small but nonzero chance of being picked first, instead of the
		// running-sum walk below always landing on a nonzero record.
		zeros := make([]*net.SRV, 0, len(group))
		nonzeros := make([]*net.SRV, 0, len(group))
		for _, rec := range group {
			if rec.Weight == 0 {
				zeros = append(zeros, rec)
			} else {
				nonzeros = append(nonzeros, rec)
			}
		}
		group = append(zeros, nonzeros...)
		// RFC 2782 weighted selection: repeatedly pick a record with
		// probability proportional to its weight, remove it, repeat.
		for len(group) > 0 {
			total := 0
			for _, rec := range group {
				total += int(rec.Weight)
			}
			var pick int
			if total == 0 {
				pick = rnd.Intn(len(group)) // all weight 0 → uniform
			} else {
				target := rnd.Intn(total + 1) // 0..total inclusive per RFC 2782
				acc, idx := 0, 0
				for i, rec := range group {
					acc += int(rec.Weight)
					if acc >= target {
						idx = i
						break
					}
				}
				pick = idx
			}
			rec := group[pick]
			out = append(out, Endpoint{
				Host:      strings.TrimSuffix(rec.Target, "."),
				Port:      int(rec.Port),
				Transport: transport,
			})
			group = append(group[:pick], group[pick+1:]...)
		}
	}
	return out
}

func sortUint16(s []uint16) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
