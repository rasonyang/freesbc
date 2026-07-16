# FreeSBC M4.4 — DNS SRV Resolution + Passive Peer Health/Cooldown Design

The final M4 (trunk interop) slice. Resolve carrier hostnames via DNS SRV
(RFC 3263-style, priority/weight) with A/AAAA fallback, folding the resolved
endpoints into the existing failover list; and track per-endpoint health
passively — a connectivity failure cools an endpoint down for a window, and
the failover loop skips it while alternatives exist. Parent spec:
`freesbc-allinone-design.md` (interop baseline line 80: "peer address
supports SRV resolution, priority/weight folded into failover, fall back to
A/AAAA when no SRV record"). M1–M4.3 complete and merged.

## 0. Go stdlib reality (investigated) — why this scope

Go's standard library `net.LookupSRV(service, proto, name)` returns
`(cname string, addrs []*net.SRV, err error)` where
`net.SRV{Target, Port, Priority, Weight}` — it does **not** expose the
record TTL. The stdlib resolver has no cache and no TTL accessor. So a cache
that honors the *actual* DNS record TTL is not achievable with stdlib alone;
it would require a third-party DNS library (`github.com/miekg/dns`). Staying
true to FreeSBC's single-binary, stdlib-first ethos, M4.4 uses a
**configurable fixed cache TTL** (`srv_cache_ttl`) as a pragmatic stand-in.
Passive per-endpoint cooldown catches a dead endpoint within one call
regardless of cache staleness, so the fixed TTL is operationally sufficient.
Real per-record TTL (and NAPTR) are documented deferrals.

sipgo v1.4.3's client resolves a request URI's `Host` via `net.Resolver`
(A/AAAA) at send time — it performs **no** SRV resolution. M4.4 therefore
does SRV itself before dialing and hands sipgo a concrete endpoint.

## 1. Decisions (confirmed 2026-07-16)

1. **Passive health only.** An endpoint is marked unhealthy as a side effect
   of a real call failing to connect to it; there is no active OPTIONS
   keepalive pinger (deferred). Health is a byproduct of call attempts.
2. **Per-call resolution with a fixed-TTL cache.** Resolve at call time,
   caching results for `srv_cache_ttl` (default 300s). Not the record's own
   TTL (stdlib can't) — a configurable window.
3. **Per-endpoint health keying.** Cooldown tracks the specific dead
   `host:port/transport`, not the whole peer: an SRV name with three
   endpoints keeps serving on the healthy two when one is down. An
   IP-address peer is simply a single-endpoint case.
4. **failDial-only cooldown trigger.** Only a genuine connectivity failure
   (no response, dial error, transaction Timer B timeout — the M4.1
   `failDial` classification) cools an endpoint down. A real SIP final
   (`failReal`: 486/503/603 — the endpoint answered, it is up), a
   ring-timeout (`failRing`: it sent provisionals), and our-side
   `failUnusable` all keep the endpoint healthy.
5. **stdlib resolver (Approach A), no new dependency.** `net.LookupSRV` +
   `net.LookupIPAddr`; `github.com/miekg/dns` is not added.

## 2. Components & module layout

| File | Change |
|---|---|
| `sig/resolve.go` (new) | `Endpoint{Host string; Port int; Transport string}`; a `Resolver` holding a TTL cache and an injectable `lookupSRV` function field; `Resolve(peer *config.Peer) []Endpoint` (SRV→A fallback, priority/weight ordering); `endpointKey(ep) string`. |
| `sig/health.go` (new) | `endpointHealth` — mutex-guarded `map[string]time.Time` (cooldown-until, keyed by `endpointKey`); `Available(ep) bool`, `Penalize(ep, cooldown)`, `Recover(ep)`. Lazy time-based expiry, no background goroutine. |
| `sig/b2bua.go` | `expandTargets` step in `placeCall` flattening `[]Target` → `[]dialEndpoint{Target, Endpoint}` (skip unregistered peers, skip cooled-down endpoints, dial-anyway when all cooled down); `dialTarget` dials a resolved `Endpoint`; `peerURI` takes an `Endpoint`; `Penalize` on `failDial`, `Recover` on bridge success. |
| `sig/routing.go` | Unchanged — `Resolve` stays pure/stateless (route match → peer target list). |
| `sig/server.go` | Construct the `Resolver` and `endpointHealth`, hang them off the server/bridge (like `store`/`pool`/`registrar`). |
| `config/schema.go`, `validate.go` | `PeerCooldown Duration` (yaml `peer_cooldown`, default 30s, `> 0`) + `SRVCacheTTL Duration` (yaml `srv_cache_ttl`, default 300s, `>= 1s`). |
| `sbc.example.yaml` | Document `peer_cooldown` / `srv_cache_ttl`. |

`Resolver` and `endpointHealth` are constructed once at server start and
shared across calls (both are internally synchronized). Keeping `Resolve`
(pure routing) separate from resolution/health (I/O + mutable state)
preserves the M3.3 invariant that routing is stateless and testable in
isolation.

## 3. Resolution logic (`resolve.go`)

`Resolve(peer)` decides by the shape of `peer.Address` (mirrors RFC 3263
§4's target-selection rules):

```
peer.Address is a literal IP (e.g. 1.2.3.4 or 1.2.3.4:5060):
    → single Endpoint{host, port|5060, peer.Transport|udp}; no DNS.

peer.Address is host WITH explicit port (e.g. carrier.com:5060):
    → SRV disabled (RFC 3263: an explicit port means "use it directly");
      single Endpoint{host, port, transport}; sipgo A/AAAA-resolves host
      at send time.

peer.Address is host WITHOUT a port (e.g. carrier.com):
    → SRV lookup _sip._<proto>.<host>  (proto: "udp"|"tcp"; "sips"/"tcp"
      service+proto for transport tls — i.e. _sips._tcp.<host>)
        records found → sort by Priority ASC, then weighted-random shuffle
          within each equal-priority group (RFC 2782); each SRV record
          yields Endpoint{Target, Port, transport}.
        no records / NXDOMAIN / DNS error → fall back to a single
          Endpoint{host, 5060, transport}; sipgo A/AAAA-resolves host.
```

Transport → (service, proto) mapping for the SRV owner name:
`udp → _sip._udp`, `tcp → _sip._tcp`, `tls → _sips._tcp`.

**Caching:** results cached per `(host, transport)` for `srv_cache_ttl`,
under a mutex, lazily expired (an expired entry is re-resolved on next
access; no sweeper). Literal-IP peers may skip the cache (nothing to
resolve).

**Weighted shuffle:** RFC 2782 weighted selection within a priority group
needs randomness. The `Resolver` holds a `*rand.Rand` (seeded at
construction; tests inject a fixed seed) so ordering is deterministic under
test. Zero-weight records are handled per RFC 2782 (they still participate,
with proportionally low selection probability).

**Test seam:** `Resolver` exposes one function field
`lookupSRV func(service, proto, name string) (string, []*net.SRV, error)`
(defaulting to `net.LookupSRV`), swapped for a stub in tests so no real DNS
is hit. A/AAAA resolution of the chosen endpoint host is left to sipgo's
client at send time — the resolver never does A lookups itself, so no
`lookupIP` seam is needed. Health therefore keys on the SRV target *name*
(e.g. `sip1.carrier.com:5060/udp`), not its resolved IP.

## 4. Passive health / cooldown (`health.go`)

```
endpointHealth:
    mu sync.Mutex
    until map[string]time.Time   // key = endpointKey(ep), value = cooldown-until

Available(ep):   now >= until[key]  (absent key ⇒ available)
Penalize(ep, d): until[key] = now.Add(d)     // called ONLY on failDial
Recover(ep):     delete(until, key)          // called on bridge success
```

- `endpointKey(ep)` = `"host:port/transport"` (lowercased transport), so the
  same physical endpoint reached via the same transport shares one entry.
- Auto-recovery is a pure `time.Now()` comparison — no goroutine. The map
  only accumulates recently-failed endpoints; an optional prune is YAGNI.
- `Recover` on success clears the cooldown immediately, so a carrier that
  comes back is usable on the next call without waiting out the full window.
- All three methods take the mutex; safe under concurrent calls (`-race`).

## 5. Failover wiring (`placeCall` / `dialTarget`)

`placeCall` gains an expansion step before its existing per-candidate loop:

```
expandTargets(targets) -> []dialEndpoint:
    available, cooled := [], []
    for each Target t (peer):
        if t.Peer.Register && registrar != nil && !registrar.IsRegistered(t.Name):
            continue                                  // existing peer-level gate
        for each ep in resolver.Resolve(t.Peer):
            de := dialEndpoint{Target: t, Endpoint: ep}
            if health.Available(ep): available = append(available, de)
            else:                    cooled    = append(cooled, de)
    if len(available) > 0: return available
    return cooled          // ALL cooled down ⇒ dial them anyway (cooldown is
                           // skip-if-alternatives, never a hard call-block)
```

The existing loop then iterates `[]dialEndpoint` exactly as it iterates
`[]Target` today. Unchanged: the `failReal`/`failRing`/`failUnusable`
classification, the raced-2xx/CANCEL/early-media handling, the
all-exhausted response precedence (`haveReal → lastRealCode`,
`haveRing → 408`, else `503`). Added:

- on a `failDial` result → `health.Penalize(de.Endpoint, cfg.PeerCooldown)`
- on a bridged success → `health.Recover(de.Endpoint)`

`dialTarget` signature changes from `(… target Target …)` to also carry the
resolved `Endpoint`; `peerURI` is rebuilt from the `Endpoint`
(host/port/transport) rather than re-parsing `peer.Address`. The dialed
number (`outNumber`) as the Request-URI user part is unchanged. Digest
credentials, From/Contact, and session-timer headers still come from
`target.Peer` — only the *destination host:port* now comes from the
resolved endpoint.

The initial latch mode at Allocate time (`decision.Targets[0].Peer.MediaLatch`,
b2bua.go) is unchanged: latch policy is peer-level, endpoints inherit it, and
`dialTarget` already re-sets `SetLatchMode(SideB, …)` per attempt.

## 6. Error handling

| Scenario | Behavior |
|---|---|
| SRV NXDOMAIN / no records | Fall back to bare-hostname A/AAAA endpoint (not an error) |
| SRV DNS error (timeout / servfail) | Log at debug, fall back to bare hostname; the call still attempts |
| All endpoints of all targets cooled down | Dial them anyway (cooldown never hard-fails a call) |
| Endpoint `failDial` | `Penalize(ep, peer_cooldown)`, failover to next endpoint (existing loop) |
| Endpoint `failReal`/`failRing`/`failUnusable` | Health untouched (endpoint is up / not its fault) |
| Resolver returns zero endpoints (shouldn't happen for a valid peer) | No dialEndpoint emitted for that peer; if all peers empty, existing 503 path |
| Bridge success on an endpoint | `Recover(ep)` clears any prior cooldown |

## 7. Testing

- **`resolve.go`** (stubbed `lookupSRV`, no real DNS):
  literal-IP → single endpoint no-DNS; host+port → SRV skipped, single
  endpoint; host-no-port with SRV → priority-ordered endpoints;
  host-no-port no-SRV → bare-hostname fallback; transport→service/proto
  mapping (udp/tcp/tls); priority ASC ordering; weighted shuffle
  distribution with a fixed seed (deterministic); cache hit within TTL,
  re-resolve after expiry.
- **`health.go`**: `Penalize` → `Available` false; expiry → `Available`
  true; `Recover` → `Available` true immediately; concurrent
  Penalize/Available/Recover under `-race`.
- **Integration** (stub-carrier harness): a peer resolving to two endpoints
  (dead, alive) → first attempt `failDial` on ep1 penalizes it, call
  bridges on ep2; a second call within the window skips ep1 and goes
  straight to ep2; when all endpoints are cooled down the call still dials;
  a successful call `Recover`s the endpoint. No regression to M4.1 failover,
  M4.3 session timers, M4.2 registration.
- Full `go vet ./... && go test ./... -race` stays green.

## 8. Scope

**In M4.4:** DNS SRV resolution (priority/weight ordering, transport-derived
`_sip._udp`/`_sip._tcp`/`_sips._tcp` owner name) with A/AAAA fallback;
fixed-TTL endpoint cache (`srv_cache_ttl`); per-endpoint passive cooldown
(`failDial`-triggered, time-recovered and success-cleared); config
`peer_cooldown` / `srv_cache_ttl`; `Resolver` + `endpointHealth` wired into
the bridge.

**Deferred (documented non-goals):**
- NAPTR resolution (RFC 3263 full flow; rarely deployed on SIP trunks).
- Real per-record DNS TTL (needs `github.com/miekg/dns`; we use a fixed
  configurable cache TTL instead).
- Active OPTIONS keepalive pinging (health is passive/call-driven only).
- Per-peer `peer_cooldown` / `srv_cache_ttl` override (global only).
- SRV re-resolution mid-call or mid-failover (resolved once per call at
  `expandTargets`).
- IPv6 SRV targets resolve and dial normally but are not specially
  prioritized over IPv4.
- A cooldown *count/threshold* (a single `failDial` cools the endpoint down;
  no "N strikes" policy).
- Cooldown metrics/observability (M7).
