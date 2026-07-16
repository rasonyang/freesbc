package sig

import (
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/freesbc/freesbc/config"
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
	rand      *rand.Rand
	lookupSRV func(service, proto, name string) (string, []*net.SRV, error)
	now       func() time.Time
}

func newResolver(seed int64) *Resolver {
	return &Resolver{
		cache:     make(map[string]cacheEntry),
		rand:      rand.New(rand.NewSource(seed)),
		lookupSRV: net.LookupSRV,
		now:       time.Now,
	}
}

// Resolve returns the ordered endpoints for peer. Address-shape rules
// (RFC 3263 §4): a literal IP or a host with an explicit port is used
// directly (no SRV); a bare hostname triggers an SRV lookup, ordered by
// priority then weight, falling back to the bare hostname when there is no
// SRV record. Always returns at least one endpoint for a non-empty address.
func (r *Resolver) Resolve(peer *config.Peer, cacheTTL time.Duration) []Endpoint {
	transport := peer.Transport
	if transport == "" {
		transport = "udp"
	}
	host, port, explicitPort, isIP := classifyAddress(peer.Address)
	if isIP || explicitPort {
		return []Endpoint{{Host: host, Port: port, Transport: transport}}
	}
	return r.resolveSRV(host, transport, cacheTTL)
}

func (r *Resolver) resolveSRV(host, transport string, cacheTTL time.Duration) []Endpoint {
	key := host + "/" + transport

	r.mu.Lock()
	if e, ok := r.cache[key]; ok && r.now().Before(e.expiry) {
		r.mu.Unlock()
		return e.endpoints
	}
	r.mu.Unlock()

	// Do the (blocking) DNS lookup without the lock held, so a slow resolver
	// for one host does not stall calls to other hosts.
	service, proto := srvService(transport)
	_, recs, err := r.lookupSRV(service, proto, host)

	r.mu.Lock()
	defer r.mu.Unlock()
	// Another goroutine may have filled the cache while we were looking up.
	if e, ok := r.cache[key]; ok && r.now().Before(e.expiry) {
		return e.endpoints
	}
	var eps []Endpoint
	if err != nil || len(recs) == 0 {
		eps = []Endpoint{{Host: host, Port: 5060, Transport: transport}}
	} else {
		eps = orderSRV(recs, transport, r.rand)
	}
	r.cache[key] = cacheEntry{endpoints: eps, expiry: r.now().Add(cacheTTL)}
	return eps
}

// classifyAddress splits a peer address into host/port and reports whether a
// port was explicitly given and whether the host is a literal IP. A missing
// port defaults to 5060.
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
	// Group by priority (ascending).
	byPrio := map[uint16][]*net.SRV{}
	var prios []uint16
	for _, rec := range recs {
		if _, seen := byPrio[rec.Priority]; !seen {
			prios = append(prios, rec.Priority)
		}
		byPrio[rec.Priority] = append(byPrio[rec.Priority], rec)
	}
	sortUint16(prios)

	var out []Endpoint
	for _, p := range prios {
		group := byPrio[p]
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
