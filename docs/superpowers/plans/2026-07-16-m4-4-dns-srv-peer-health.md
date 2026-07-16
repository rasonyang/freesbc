# FreeSBC M4.4 — DNS SRV + Passive Peer Health/Cooldown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve carrier hostnames via DNS SRV (priority/weight, A/AAAA fallback) and fold the resolved endpoints into the failover loop, skipping endpoints that recently failed to connect (passive per-endpoint cooldown).

**Architecture:** A new pure `Resolver` (`sig/resolve.go`) turns a `*config.Peer` into an ordered `[]Endpoint` — literal IPs and host:port pass straight through, a bare hostname does an SRV lookup (injectable for tests) with a fixed-TTL cache and RFC 2782 priority/weight ordering, falling back to the bare hostname when there is no SRV record. A new `endpointHealth` (`sig/health.go`) is a mutex-guarded map of `endpointKey → cooldown-until` with lazy time-based expiry. The B2BUA's `placeCall` gains an `expandTargets` step that flattens `[]Target` into `[]dialEndpoint`, skips cooled-down endpoints (dialing them anyway if every endpoint is cooled), penalizes an endpoint on a `failDial` outcome, and clears it on a bridged success. `Resolve` in `sig/routing.go` stays pure and untouched.

**Tech Stack:** Go (stdlib `net.LookupSRV` / `net.SplitHostPort` / `net/netip`, `math/rand`), sipgo v1.4.3. No new dependencies.

## Global Constraints

- **Dependencies unchanged.** stdlib only — no `github.com/miekg/dns`, nothing new in `go.mod`. (spec §1 decision 5)
- **Go stdlib `net.LookupSRV` exposes no record TTL** — the cache uses the configurable `srv_cache_ttl`, not the record's own TTL. (spec §0)
- **sipgo does A/AAAA at send time** — the resolver never does A lookups itself; only `lookupSRV` is injectable, and health keys on the SRV target *name*, not its resolved IP. (spec §2, §3)
- **`failDial`-only cooldown trigger.** Only `failDial` penalizes an endpoint. `failReal`/`failRing`/`failUnusable` never do. (spec §1 decision 4)
- **Per-endpoint health keying**: `endpointKey` = `host:port/transport` (transport lowercased). (spec §1 decision 3, §4)
- **Cooldown is never a hard block**: when every candidate endpoint is cooled down, `expandTargets` dials them anyway. (spec §5)
- **`Resolve` in `sig/routing.go` stays pure/stateless** — DNS I/O and health state live in the bridge. (spec §2)
- All English identifiers/comments; stdlib `testing`; `gofmt -l .` clean; gate is `go test ./... -race`.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `config/schema.go`, `config/validate.go` | `peer_cooldown` + `srv_cache_ttl` config fields, defaults, validation | 1 |
| `sig/resolve.go` (new) | `Endpoint`, `endpointKey`, `Resolver` (SRV→A resolution, priority/weight, TTL cache) | 2 |
| `sig/health.go` (new) | `endpointHealth` (`Available`/`Penalize`/`Recover`, mutex map, lazy expiry) | 3 |
| `sig/server.go`, `sig/b2bua.go` | Wire `Resolver`/`endpointHealth` into `Server`; `expandTargets`; `dialTarget`/`peerURI` take an `Endpoint` | 4 |
| `sig/b2bua.go` | Health filtering in `expandTargets`; `Penalize` on `failDial`, `Recover` on success | 5 |
| `README.md`, `sbc.example.yaml` | Roadmap + config docs + full verification | 6 |

---

### Task 1: Config — `peer_cooldown` + `srv_cache_ttl`

**Files:**
- Modify: `config/schema.go` (add fields to `Config`, defaults in `withDefaults`)
- Modify: `config/validate.go` (add two checks in `validate`)
- Test: `config/schema_test.go`, `config/validate_test.go`
- Modify: `sbc.example.yaml`

**Interfaces:**
- Consumes: existing `Config` struct, `withDefaults(c *Config)`, `Duration` type, `(c *Config) validate()`.
- Produces: `Config.PeerCooldown Duration` (yaml `peer_cooldown`, default 30s, `> 0`), `Config.SRVCacheTTL Duration` (yaml `srv_cache_ttl`, default 300s, `>= 1s`). Later tasks read `cfg.PeerCooldown.Std()` and `cfg.SRVCacheTTL.Std()`.

- [ ] **Step 1: Write the failing test** — append to `config/schema_test.go`:

```go
func TestPeerCooldownAndSRVCacheTTLDefaults(t *testing.T) {
	// Minimal config omitting both fields → defaults applied.
	cfg, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.PeerCooldown.Std(); got != 30*time.Second {
		t.Errorf("peer_cooldown default = %v, want 30s", got)
	}
	if got := cfg.SRVCacheTTL.Std(); got != 300*time.Second {
		t.Errorf("srv_cache_ttl default = %v, want 300s", got)
	}
}

func TestPeerCooldownAndSRVCacheTTLParsed(t *testing.T) {
	cfg, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peer_cooldown: 45s
srv_cache_ttl: 120s
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.PeerCooldown.Std(); got != 45*time.Second {
		t.Errorf("peer_cooldown = %v, want 45s", got)
	}
	if got := cfg.SRVCacheTTL.Std(); got != 120*time.Second {
		t.Errorf("srv_cache_ttl = %v, want 120s", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run 'TestPeerCooldownAndSRVCacheTTL' -v`
Expected: FAIL — compile error (`cfg.PeerCooldown` / `cfg.SRVCacheTTL` undefined).

- [ ] **Step 3: Add the fields** — in `config/schema.go`, in the `Config` struct after `MinSE`:

```go
	MinSE           Duration         `yaml:"min_se"`           // minimum session interval accepted (else 422)
	PeerCooldown    Duration         `yaml:"peer_cooldown"`    // skip a peer endpoint this long after a connect failure
	SRVCacheTTL     Duration         `yaml:"srv_cache_ttl"`    // cache DNS SRV/endpoint resolutions this long (stdlib exposes no record TTL)
```

- [ ] **Step 4: Add the defaults** — in `config/schema.go` `withDefaults`, after the `MinSE` default block:

```go
	if c.PeerCooldown == 0 {
		c.PeerCooldown = Duration(30 * time.Second)
	}
	if c.SRVCacheTTL == 0 {
		c.SRVCacheTTL = Duration(300 * time.Second)
	}
```

- [ ] **Step 5: Add validation** — in `config/validate.go` `validate`, after the `session_expires >= min_se` check (line ~50):

```go
	if c.PeerCooldown.Std() <= 0 {
		fail("peer_cooldown: must be > 0, got %v", c.PeerCooldown.Std())
	}
	if c.SRVCacheTTL.Std() < time.Second {
		fail("srv_cache_ttl: must be at least 1s, got %v", c.SRVCacheTTL.Std())
	}
```

- [ ] **Step 6: Add validation failing tests** — append to `config/validate_test.go`. Note the `peer_cooldown` value must be **`-1s`**, not `0s`: `withDefaults` fills a zero (`0s`) Duration to the 30s default *before* `validate` runs, so only a non-zero-yet-non-positive value (a negative duration, which parses fine and stays non-zero) actually reaches the `<= 0` check. `srv_cache_ttl: 500ms` is already non-zero and correctly reaches the `< 1s` check.

```go
func TestValidatePeerCooldownMustBePositive(t *testing.T) {
	_, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peer_cooldown: -1s
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err == nil || !strings.Contains(err.Error(), "peer_cooldown") {
		t.Fatalf("want peer_cooldown error, got %v", err)
	}
}

func TestValidateSRVCacheTTLMinimum(t *testing.T) {
	_, err := Parse([]byte(`
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
srv_cache_ttl: 500ms
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`))
	if err == nil || !strings.Contains(err.Error(), "srv_cache_ttl") {
		t.Fatalf("want srv_cache_ttl error, got %v", err)
	}
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./config/ -run 'TestPeerCooldownAndSRVCacheTTL|TestValidatePeerCooldown|TestValidateSRVCacheTTL' -v`
Expected: PASS (4 tests). Confirm `strings` and `time` are imported in the test files (both already are in this package's tests).

- [ ] **Step 8: Document in `sbc.example.yaml`** — after the `min_se:` line:

```yaml
peer_cooldown: 30s   # after a connect failure (no response) to a peer endpoint, skip it this long before retrying
srv_cache_ttl: 300s  # cache DNS SRV/A resolutions this long (Go's resolver exposes no record TTL, so this is a fixed window)
```

- [ ] **Step 9: Verify example config still parses**

Run: `go build -o /tmp/freesbc-m44 . && CARRIER_A_PASS=x /tmp/freesbc-m44 check -c sbc.example.yaml`
Expected: `sbc.example.yaml: config OK`

- [ ] **Step 10: Commit**

```bash
git add config/schema.go config/validate.go config/schema_test.go config/validate_test.go sbc.example.yaml
git commit -m "feat(config): peer_cooldown and srv_cache_ttl (M4.4 SRV + health)"
```

---

### Task 2: `sig/resolve.go` — `Endpoint` + `Resolver`

**Files:**
- Create: `sig/resolve.go`
- Test: `sig/resolve_test.go`

**Interfaces:**
- Consumes: `config.Peer` (fields `Address string`, `Transport string`); stdlib `net`, `net/netip`, `math/rand`, `sync`, `time`, `strconv`, `strings`.
- Produces:
  - `type Endpoint struct { Host string; Port int; Transport string }`
  - `func endpointKey(ep Endpoint) string` — `"host:port/transport"`, transport lowercased.
  - `type Resolver struct { … lookupSRV func(service, proto, name string) (string, []*net.SRV, error) … }`
  - `func newResolver(seed int64) *Resolver` — `lookupSRV` defaults to `net.LookupSRV`, `now` to `time.Now`.
  - `func (r *Resolver) Resolve(peer *config.Peer, cacheTTL time.Duration) []Endpoint` — always returns ≥1 endpoint for a valid peer address.

- [ ] **Step 1: Write the failing tests** — create `sig/resolve_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./sig/ -run 'TestResolve|TestEndpointKey' -v`
Expected: FAIL — compile error (`newResolver`, `Endpoint`, `endpointKey` undefined).

- [ ] **Step 3: Implement `sig/resolve.go`**

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./sig/ -run 'TestResolve|TestEndpointKey' -race -v`
Expected: PASS (8 tests). If `TestResolveWeightedShuffleDeterministicWithSeed` is flaky, it means the shuffle read the global rand — confirm `orderSRV` uses only `rnd`.

- [ ] **Step 5: Commit**

```bash
git add sig/resolve.go sig/resolve_test.go
git commit -m "feat(sig): DNS SRV resolver with priority/weight ordering and TTL cache"
```

---

### Task 3: `sig/health.go` — passive endpoint cooldown

**Files:**
- Create: `sig/health.go`
- Test: `sig/health_test.go`

**Interfaces:**
- Consumes: `Endpoint` and `endpointKey` (Task 2); stdlib `sync`, `time`.
- Produces:
  - `type endpointHealth struct { … now func() time.Time }`
  - `func newEndpointHealth() *endpointHealth`
  - `func (h *endpointHealth) Available(ep Endpoint) bool`
  - `func (h *endpointHealth) Penalize(ep Endpoint, cooldown time.Duration)`
  - `func (h *endpointHealth) Recover(ep Endpoint)`

- [ ] **Step 1: Write the failing tests** — create `sig/health_test.go`:

```go
package sig

import (
	"sync"
	"testing"
	"time"
)

func TestEndpointHealthPenalizeAndExpire(t *testing.T) {
	h := newEndpointHealth()
	fakeNow := time.Unix(2000, 0)
	h.now = func() time.Time { return fakeNow }
	ep := Endpoint{Host: "1.2.3.4", Port: 5060, Transport: "udp"}

	if !h.Available(ep) {
		t.Fatal("fresh endpoint must be available")
	}
	h.Penalize(ep, 30*time.Second)
	if h.Available(ep) {
		t.Fatal("penalized endpoint must be unavailable within the window")
	}
	fakeNow = fakeNow.Add(29 * time.Second)
	if h.Available(ep) {
		t.Fatal("still within cooldown at 29s")
	}
	fakeNow = fakeNow.Add(2 * time.Second) // now 31s > 30s window
	if !h.Available(ep) {
		t.Fatal("cooldown expired → available again")
	}
}

func TestEndpointHealthRecoverClearsImmediately(t *testing.T) {
	h := newEndpointHealth()
	ep := Endpoint{Host: "5.6.7.8", Port: 5060, Transport: "tcp"}
	h.Penalize(ep, time.Hour)
	if h.Available(ep) {
		t.Fatal("penalized for an hour → unavailable")
	}
	h.Recover(ep)
	if !h.Available(ep) {
		t.Fatal("Recover must clear the cooldown immediately")
	}
}

func TestEndpointHealthConcurrent(t *testing.T) {
	h := newEndpointHealth()
	ep := Endpoint{Host: "9.9.9.9", Port: 5060, Transport: "udp"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Penalize(ep, time.Second)
			_ = h.Available(ep)
			h.Recover(ep)
		}()
	}
	wg.Wait() // -race is the assertion
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./sig/ -run 'TestEndpointHealth' -v`
Expected: FAIL — compile error (`newEndpointHealth` undefined).

- [ ] **Step 3: Implement `sig/health.go`**

```go
package sig

import (
	"sync"
	"time"
)

// endpointHealth tracks per-endpoint cooldowns passively: a connect failure
// (failDial) Penalizes an endpoint, which then reports unavailable until the
// cooldown window elapses (lazy, no background sweeper) or a subsequent
// successful call Recovers it. Safe for concurrent use.
type endpointHealth struct {
	mu    sync.Mutex
	until map[string]time.Time // endpointKey → cooldown-until
	now   func() time.Time
}

func newEndpointHealth() *endpointHealth {
	return &endpointHealth{until: make(map[string]time.Time), now: time.Now}
}

// Available reports whether ep may be dialed now — true unless it is inside
// an unexpired cooldown window.
func (h *endpointHealth) Available(ep Endpoint) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.until[endpointKey(ep)]
	return !ok || !h.now().Before(t) // now >= t ⇒ expired ⇒ available
}

// Penalize starts (or extends) ep's cooldown window.
func (h *endpointHealth) Penalize(ep Endpoint, cooldown time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.until[endpointKey(ep)] = h.now().Add(cooldown)
}

// Recover clears any cooldown on ep, making it immediately available.
func (h *endpointHealth) Recover(ep Endpoint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.until, endpointKey(ep))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./sig/ -run 'TestEndpointHealth' -race -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add sig/health.go sig/health_test.go
git commit -m "feat(sig): passive per-endpoint health/cooldown tracker"
```

---

### Task 4: Wire resolver into the bridge — `expandTargets` + endpoint-based dialing

**Files:**
- Modify: `sig/server.go` (`Server` struct fields + `NewServer`)
- Modify: `sig/b2bua.go` (`peerURI` signature; `dialTarget` signature; `placeCall` loop; new `dialEndpoint` + `expandTargets`)
- Test: `sig/b2bua_test.go` (a new `expandTargets` unit test); existing failover/bridge tests must stay green.

**Interfaces:**
- Consumes: `Resolver`/`newResolver`/`Endpoint`/`endpointKey` (Task 2); `endpointHealth`/`newEndpointHealth` (Task 3); existing `Target`, `placeCall`, `dialTarget`, `peerURI`, `b.s.store`, `b.s.registrar.IsRegistered`.
- Produces:
  - `Server.resolver *Resolver`, `Server.health *endpointHealth` (constructed in `NewServer`).
  - `type dialEndpoint struct { Target Target; Endpoint Endpoint }`
  - `func (b *bridge) expandTargets(targets []Target) []dialEndpoint` (Task 4: register-gate + resolver expansion, **no health filtering yet**).
  - `func peerURI(ep Endpoint) sip.Uri`
  - `dialTarget(aLeg *sipgo.DialogServerSession, target Target, ep Endpoint, outNumber string, bOffer []byte, sess *media.Session, ourIP netip.Addr, startOnce *sync.Once) (…)`

- [ ] **Step 1: Add the server fields** — in `sig/server.go` `Server` struct, after `registrar *Registrar`:

```go
	registrar *Registrar

	// resolver turns a peer into ordered dialable endpoints (DNS SRV with
	// A/AAAA fallback, priority/weight); health tracks per-endpoint cooldowns
	// after connect failures. Both are internally synchronized and shared
	// across concurrent calls. (M4.4)
	resolver *Resolver
	health   *endpointHealth
```

- [ ] **Step 2: Construct them in `NewServer`** — in `sig/server.go` `NewServer`, add to the returned `&Server{…}`:

```go
	return &Server{
		store:    store,
		pool:     pool,
		log:      log,
		registry: callstate.NewRegistry(),
		sdps:     newCallSDPStore(),
		resolver: newResolver(time.Now().UnixNano()),
		health:   newEndpointHealth(),
	}
```

Add `"time"` to `sig/server.go`'s imports if not already present.

- [ ] **Step 3: Change `peerURI` to take an `Endpoint`** — in `sig/b2bua.go`, replace the whole `peerURI` function (currently `func peerURI(p *config.Peer) sip.Uri` at ~917):

```go
// peerURI builds the sip.Uri sipgo needs to dial a resolved endpoint
// (host/port/transport). The dialed number is set separately as the
// Request-URI user part by the caller.
func peerURI(ep Endpoint) sip.Uri {
	transport := ep.Transport
	if transport == "" {
		transport = "udp"
	}
	params := sip.NewParams()
	params.Add("transport", transport)
	return sip.Uri{
		Scheme:    "sip",
		Host:      ep.Host,
		Port:      ep.Port,
		UriParams: params,
	}
}
```

- [ ] **Step 4: Add `dialEndpoint` + `expandTargets`** — in `sig/b2bua.go`, just above `placeCall` (~line 331):

```go
// dialEndpoint pairs a resolved dial destination with the Target (peer) it
// came from — dialing needs the endpoint's host/port, but auth credentials,
// From/Contact, and session-timer headers still come from the peer.
type dialEndpoint struct {
	Target   Target
	Endpoint Endpoint
}

// expandTargets flattens the ordered failover Targets into the concrete
// endpoints to dial, in order: each peer is resolved (DNS SRV → priority/
// weight-ordered endpoints, or a single endpoint for an IP/host:port), and a
// register:true peer we have not registered with is skipped entirely (the
// far end has no idea who we are). Health filtering is layered on in Task 5.
func (b *bridge) expandTargets(targets []Target) []dialEndpoint {
	cfg := b.s.store.Current()
	var out []dialEndpoint
	for _, t := range targets {
		// b.s.registrar is nil only in tests that build a bridge without
		// Server.Run; treat that as "no gating" rather than skipping every
		// target (mirrors the pre-M4.4 inline gate this replaces).
		if t.Peer.Register && b.s.registrar != nil && !b.s.registrar.IsRegistered(t.Name) {
			b.s.log.Debug("skipping unregistered target", "peer", t.Name)
			continue
		}
		for _, ep := range b.s.resolver.Resolve(t.Peer, cfg.SRVCacheTTL.Std()) {
			out = append(out, dialEndpoint{Target: t, Endpoint: ep})
		}
	}
	return out
}
```

- [ ] **Step 5: Rewrite `placeCall`'s loop to iterate endpoints** — in `sig/b2bua.go` `placeCall`, replace the loop header and body's `dialTarget` call. Change:

```go
	for _, target := range targets {
		// A register:true target we have not (yet, or no longer) actually
		// registered with must never be dialed … [the whole inline gate block]
		if target.Peer.Register && b.s.registrar != nil && !b.s.registrar.IsRegistered(target.Name) {
			b.s.log.Debug("skipping unregistered target", "peer", target.Name)
			continue
		}

		dialedLeg, res := b.dialTarget(aLeg, target, outNumber, bOffer, sess, ourIP, &startOnce)
		if res.ok {
			return dialedLeg, target, res.aAnswer, bOffer, true
		}
```

to:

```go
	for _, de := range b.expandTargets(targets) {
		dialedLeg, res := b.dialTarget(aLeg, de.Target, de.Endpoint, outNumber, bOffer, sess, ourIP, &startOnce)
		if res.ok {
			return dialedLeg, de.Target, res.aAnswer, bOffer, true
		}
```

Leave the rest of the loop body (the `!res.retryable` return, the `failReal`/`failRing` bookkeeping, and the `aLeg.Context().Err()` check) unchanged.

- [ ] **Step 6: Change `dialTarget` to take the endpoint** — in `sig/b2bua.go`, update the signature and the `peerURI` call. Change the signature to:

```go
func (b *bridge) dialTarget(aLeg *sipgo.DialogServerSession, target Target, ep Endpoint, outNumber string, bOffer []byte, sess *media.Session, ourIP netip.Addr, startOnce *sync.Once) (bLeg *sipgo.DialogClientSession, res attemptResult) {
```

and inside it change:

```go
	bTarget := peerURI(target.Peer)
	bTarget.User = outNumber
```

to:

```go
	bTarget := peerURI(ep)
	bTarget.User = outNumber
```

Everything else in `dialTarget` (latch mode from `target.Peer.MediaLatch`, `ourSigPort(cfg, target.Peer.Transport)`, `authUser(target)`/`authPass(target)`, From/Contact, session-timer headers) stays as-is — only the destination host/port now comes from `ep`.

- [ ] **Step 7: Write the `expandTargets` unit test** — append to `sig/b2bua_test.go`:

```go
func TestExpandTargetsResolvesEndpointsInOrder(t *testing.T) {
	cfg, err := config.Parse([]byte(bridgeCallCfg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := NewServer(config.NewStore(cfg), nil, discardLogger())
	// expandTargets doesn't use the cfg's carrier peer here — we stub the
	// resolver and pass our own multi-endpoint peer.
	b := &bridge{s: s}

	peerA := &config.Peer{Address: "multi.example", Transport: "udp"}
	s.resolver.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{Target: "ep1.example.", Port: 5060, Priority: 10, Weight: 0},
			{Target: "ep2.example.", Port: 5061, Priority: 20, Weight: 0},
		}, nil
	}
	targets := []Target{{Name: "a", Peer: peerA}}
	des := b.expandTargets(targets)
	if len(des) != 2 {
		t.Fatalf("want 2 dialEndpoints, got %d: %+v", len(des), des)
	}
	if des[0].Endpoint.Host != "ep1.example" || des[1].Endpoint.Host != "ep2.example" {
		t.Errorf("endpoint order = [%s, %s], want [ep1.example, ep2.example]",
			des[0].Endpoint.Host, des[1].Endpoint.Host)
	}
	if des[0].Target.Name != "a" {
		t.Errorf("dialEndpoint lost its Target: %+v", des[0].Target)
	}
}
```

If `mustParseCfg` / `discardLogger` helpers don't already exist in the test package, use the inline equivalents the surrounding tests use (`config.Parse` + `slog.New(slog.NewTextHandler(io.Discard, nil))`) — check the top of `sig/b2bua_test.go` and reuse whatever is there. Ensure `net` is imported in the test file (it is).

- [ ] **Step 8: Run the new test + the full bridge/failover suite**

Run: `go test ./sig/ -run 'TestExpandTargets|TestBridge|TestResolve|TestEndpointHealth' -race -v`
Expected: PASS. The existing `TestBridgeFailoverToSecondTarget`, `TestBridgePlacesCallAndBridges`, register-gate tests, etc. must still pass — they exercise the new endpoint path with IP:port peers (single-endpoint resolution, behavior-identical to before).

- [ ] **Step 9: Full race suite (catch any missed `dialTarget`/`peerURI` caller)**

Run: `go build ./... && go test ./sig/ -race`
Expected: PASS. If a test called `peerURI(peer)` or `dialTarget(...)` with the old signature, fix it to the new one.

- [ ] **Step 10: Commit**

```bash
git add sig/server.go sig/b2bua.go sig/b2bua_test.go
git commit -m "feat(sig): resolve peers to endpoints and fail over across them (SRV)"
```

---

### Task 5: Health filtering + `Penalize`/`Recover` wiring

**Files:**
- Modify: `sig/b2bua.go` (`expandTargets` health filter; `placeCall` Penalize/Recover)
- Test: `sig/b2bua_test.go` (an `expandTargets` filter unit test + a full-call integration test)

**Interfaces:**
- Consumes: `b.s.health` (Task 4), `dialEndpoint`/`expandTargets` (Task 4), `cfg.PeerCooldown` (Task 1), the `failDial` classification (M4.1).
- Produces: `expandTargets` now skips cooled-down endpoints (dialing them anyway when all are cooled); `placeCall` calls `b.s.health.Penalize(de.Endpoint, cfg.PeerCooldown.Std())` on a `failDial` outcome and `b.s.health.Recover(de.Endpoint)` on a bridged success.

- [ ] **Step 1: Write the failing filter unit test** — append to `sig/b2bua_test.go`:

```go
func TestExpandTargetsSkipsCooledEndpoints(t *testing.T) {
	cfg, err := config.Parse([]byte(bridgeCallCfg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := NewServer(config.NewStore(cfg), nil, discardLogger())
	b := &bridge{s: s}

	s.resolver.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{Target: "ep1.example.", Port: 5060, Priority: 10, Weight: 0},
			{Target: "ep2.example.", Port: 5061, Priority: 20, Weight: 0},
		}, nil
	}
	targets := []Target{{Name: "a", Peer: &config.Peer{Address: "multi.example", Transport: "udp"}}}

	// Cool down ep1: expandTargets returns only ep2.
	s.health.Penalize(Endpoint{Host: "ep1.example", Port: 5060, Transport: "udp"}, time.Hour)
	des := b.expandTargets(targets)
	if len(des) != 1 || des[0].Endpoint.Host != "ep2.example" {
		t.Fatalf("with ep1 cooled, want [ep2.example], got %+v", des)
	}

	// Cool down ep2 as well: everything is cooled → dial them ALL anyway.
	s.health.Penalize(Endpoint{Host: "ep2.example", Port: 5061, Transport: "udp"}, time.Hour)
	des = b.expandTargets(targets)
	if len(des) != 2 {
		t.Fatalf("all cooled → dial-anyway must return both, got %+v", des)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./sig/ -run 'TestExpandTargetsSkipsCooledEndpoints' -v`
Expected: FAIL — with ep1 cooled the current (Task 4) `expandTargets` still returns 2 endpoints (no filtering).

- [ ] **Step 3: Add health filtering to `expandTargets`** — in `sig/b2bua.go`, replace the `expandTargets` body from Task 4 with:

```go
func (b *bridge) expandTargets(targets []Target) []dialEndpoint {
	cfg := b.s.store.Current()
	var available, cooled []dialEndpoint
	for _, t := range targets {
		if t.Peer.Register && b.s.registrar != nil && !b.s.registrar.IsRegistered(t.Name) {
			b.s.log.Debug("skipping unregistered target", "peer", t.Name)
			continue
		}
		for _, ep := range b.s.resolver.Resolve(t.Peer, cfg.SRVCacheTTL.Std()) {
			de := dialEndpoint{Target: t, Endpoint: ep}
			if b.s.health.Available(ep) {
				available = append(available, de)
			} else {
				cooled = append(cooled, de)
			}
		}
	}
	// Cooldown is a skip-if-alternatives, never a hard block: if every
	// endpoint is cooled down, dial them all anyway rather than fail the call.
	if len(available) > 0 {
		return available
	}
	return cooled
}
```

- [ ] **Step 4: Wire `Penalize`/`Recover` into `placeCall`** — in `sig/b2bua.go` `placeCall`:

First, add a config fetch near the top of `placeCall` (after the `rewriteSDP` block), if `cfg` isn't already in scope there:

```go
	cfg := b.s.store.Current()
```

Then in the loop, on success add `Recover` before returning, and on a `failDial` result add `Penalize`. Change:

```go
	for _, de := range b.expandTargets(targets) {
		dialedLeg, res := b.dialTarget(aLeg, de.Target, de.Endpoint, outNumber, bOffer, sess, ourIP, &startOnce)
		if res.ok {
			return dialedLeg, de.Target, res.aAnswer, bOffer, true
		}
		if !res.retryable {
			return nil, Target{}, nil, nil, false
		}
		if res.kind == failReal {
			haveReal = true
			lastRealCode, lastRealReason = res.code, res.reason
		}
		if res.kind == failRing {
			haveRing = true
		}
```

to:

```go
	for _, de := range b.expandTargets(targets) {
		dialedLeg, res := b.dialTarget(aLeg, de.Target, de.Endpoint, outNumber, bOffer, sess, ourIP, &startOnce)
		if res.ok {
			// A bridged call proves this endpoint is reachable — clear any
			// prior cooldown so it is usable immediately on the next call.
			b.s.health.Recover(de.Endpoint)
			return dialedLeg, de.Target, res.aAnswer, bOffer, true
		}
		if !res.retryable {
			return nil, Target{}, nil, nil, false
		}
		// Only a genuine connect failure (no usable response at all) cools an
		// endpoint down; a real carrier final / ring-timeout / our-side
		// unusable answer all mean the endpoint itself is reachable.
		if res.kind == failDial {
			b.s.health.Penalize(de.Endpoint, cfg.PeerCooldown.Std())
		}
		if res.kind == failReal {
			haveReal = true
			lastRealCode, lastRealReason = res.code, res.reason
		}
		if res.kind == failRing {
			haveRing = true
		}
```

- [ ] **Step 5: Run the filter test to verify it passes**

Run: `go test ./sig/ -run 'TestExpandTargets' -race -v`
Expected: PASS (both `TestExpandTargetsResolvesEndpointsInOrder` and `TestExpandTargetsSkipsCooledEndpoints`).

- [ ] **Step 6a: Add a `startServerConfigured` test helper** — in `sig/server_test.go`, next to `startServer`, add a variant that lets a test configure the `*Server` *before* `Run` launches (so a resolver stub is installed race-free), and refactor `startServer` to delegate to it:

```go
// startServerConfigured is startServer with a hook to mutate the *Server
// before Run starts — e.g. to install a resolver lookupSRV stub. The hook
// runs before the Run goroutine is spawned, so its writes happen-before any
// call-handling goroutine reads them (no data race under -race).
func startServerConfigured(t *testing.T, port int, cfgYAML string, configure func(*Server)) *Server {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore(cfg)
	pool := media.NewPool(store)
	srv := NewServer(store, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if configure != nil {
		configure(srv)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
			time.Sleep(100 * time.Millisecond)
			return srv
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not start")
	return nil
}
```

Then replace the body of the existing `startServer` with a one-line delegation:

```go
func startServer(t *testing.T, port int, cfgYAML string) *Server {
	t.Helper()
	return startServerConfigured(t, port, cfgYAML, nil)
}
```

- [ ] **Step 6b: Write the full-call health integration test** — append to `sig/b2bua_test.go`. This drives a real INVITE through a server whose "carrier" peer resolves (via a stubbed SRV) to a dead endpoint then a live stub carrier, and asserts the dead endpoint is penalized and the call bridges on the live one:

```go
// TestBridgePenalizesDeadEndpointThenBridges proves the M4.4 health path
// end to end: a peer resolving to [dead, live] fails over from the dead
// endpoint to the live one, and the dead endpoint is left in cooldown.
func TestBridgePenalizesDeadEndpointThenBridges(t *testing.T) {
	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	// Live stub carrier on a real port; the "dead" endpoint is a port with
	// nothing listening.
	const livePort = 45194
	const deadPort = 45195
	live := startStubCarrier(t, fmt.Sprintf("127.0.0.1:%d", livePort), testSDPBody(echoRTPPort))

	// A peer addressed by hostname so resolution goes through SRV; the SBC's
	// "carrier" peer in healthCfg uses address: srvhost.test (no port). The
	// resolver stub MUST be installed before Run starts handling calls —
	// startServerConfigured sets it inside NewServer→Run's happens-before
	// window (goroutine start), so -race sees no data race on lookupSRV.
	srv := startServerConfigured(t, 45191, healthCfg, func(s *Server) {
		s.resolver.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
			return "", []*net.SRV{
				{Target: "127.0.0.1.", Port: deadPort, Priority: 10, Weight: 0}, // tried first
				{Target: "127.0.0.1.", Port: livePort, Priority: 20, Weight: 0}, // fallback
			}, nil
		}
	})

	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	uacUA, _ := sipgo.NewUA()
	defer uacUA.Close()
	uacClient, _ := sipgo.NewClient(uacUA, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	defer uacClient.Close()
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45191}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sess, err := dialogCli.Invite(ctx, bridgeURI, testSDPBody(uacRTPPort))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()
	if err := sess.WaitAnswer(ctx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (should bridge on the live endpoint)", sess.InviteResponse.StatusCode)
	}
	select {
	case <-live.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("live carrier never received the B-leg INVITE")
	}
	_ = sess.Ack(context.Background())

	// The dead endpoint must now be in cooldown; the live one must not.
	if srv.health.Available(Endpoint{Host: "127.0.0.1", Port: deadPort, Transport: "udp"}) {
		t.Error("dead endpoint should be cooled down after failDial")
	}
	if !srv.health.Available(Endpoint{Host: "127.0.0.1", Port: livePort, Transport: "udp"}) {
		t.Error("live endpoint should be Recovered after a successful bridge")
	}

	_ = sess.Bye(context.Background())
	waitForActiveCalls(t, srv, 0, 5*time.Second)
}
```

Add the `healthCfg` YAML constant near the other `*Cfg` constants in the test file (modeled on `failoverCfg`/`bridgeCallCfg`, with the carrier peer addressed by a bare hostname so SRV runs, its `media_latch: loose`, and a media pool of a couple of pairs):

```go
const healthCfg = `
listen:
  sip: [udp://127.0.0.1:45191]
  media:
    port_range: 46210-46213
    public_ip: 127.0.0.1
ring_timeout: 3s
peer_cooldown: 60s
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: srvhost.test
    transport: udp
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`
```

Note the short `ring_timeout: 3s`: the dead endpoint produces a connection-refused/timeout `failDial`; keeping the ring timeout small bounds how long the test waits before failover. (If loopback UDP to a dead port yields an immediate ICMP-port-unreachable rather than a timeout, failover is faster still.)

- [ ] **Step 7: Run the integration test**

Run: `go test ./sig/ -run 'TestBridgePenalizesDeadEndpointThenBridges' -race -v`
Expected: PASS. If it flakes on timing, confirm `ring_timeout` is small and that `startStubCarrier` for the live port is up before the INVITE (the helper blocks until bound).

- [ ] **Step 8: Full race suite**

Run: `go build ./... && go test ./... -race`
Expected: PASS across `config`, `media`, `callstate`, `sig`. No regression to M4.1 failover / M4.3 session timers / M4.2 registration.

- [ ] **Step 9: Commit**

```bash
git add sig/b2bua.go sig/b2bua_test.go
git commit -m "feat(sig): skip and cool down endpoints that fail to connect (passive health)"
```

---

### Task 6: README roadmap + full verification

**Files:**
- Modify: `README.md` (roadmap: M4.4 done, M4 parent done, M5 next)
- Verify: full build/test/smoke

**Interfaces:**
- Consumes: nothing new. Documentation + verification only.

- [ ] **Step 1: Update the roadmap** — in `README.md`, change the M4.4 and M4 parent rows:

```
| M4 | Trunk interop: From/CLI, outbound REGISTER, session timers, PRACK, DNS SRV | ✅ done |
```
```
| └ M4.4 | DNS SRV + peer health/cooldown | ✅ done |
```
and change the M5 row's status cell to `next`:
```
| M5 | SRTP (SDES) | next |
```

- [ ] **Step 2: gofmt / vet / build**

Run: `gofmt -l . && go vet ./... && go build ./...`
Expected: no output from `gofmt -l .`; vet and build clean.

- [ ] **Step 3: Full race suite**

Run: `go test ./... -race -count=1`
Expected: `ok` for `config`, `media`, `callstate`, `sig`.

- [ ] **Step 4: Config smoke test**

Run: `go build -o /tmp/freesbc-m44 . && CARRIER_A_PASS=x /tmp/freesbc-m44 check -c sbc.example.yaml`
Expected: `sbc.example.yaml: config OK`

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: mark M4.4 (DNS SRV + peer health) done, M5 next"
```

---

## Notes for the implementer

- **`Resolve` in `sig/routing.go` is NOT modified** — it stays the pure route-matcher producing `[]Target`. All resolution/health lives in `sig/resolve.go`, `sig/health.go`, and the bridge.
- **Health keys on the SRV target name**, not its resolved IP (sipgo does A/AAAA at send time). `endpointKey("sip1.carrier.com", 5060, "udp")` = `"sip1.carrier.com:5060/udp"`.
- **Hot-reload**: `peer_cooldown` and `srv_cache_ttl` are read from `b.s.store.Current()` on each call/resolution, so both follow hot-reload. The resolver's cache retains entries stamped with the TTL that was current at insertion — acceptable and self-correcting.
- **Concurrency**: `Resolver` guards its cache and `rand` with one mutex (the DNS lookup runs unlocked to avoid stalling other hosts); `endpointHealth` guards its map. Both are exercised under `-race`.
- **Deferred (do NOT implement)**: NAPTR, real per-record TTL, active OPTIONS keepalive, per-peer cooldown/TTL override, mid-call re-resolution, IPv6 SRV prioritization, cooldown thresholds/metrics. (spec §8)
```
