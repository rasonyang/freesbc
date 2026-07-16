# FreeSBC M4.2 — Outbound REGISTER Design

The second M4 (trunk interop) slice. A stateful registration client: FreeSBC registers one trunk account per `register: true` peer to registration-based carriers, so those trunks accept our calls and can route inbound to us. Parent spec: `freesbc-allinone-design.md` (§4 `sig/register.go`, §5 peer `register`, §7 REGISTER-failure row). M1–M4.1 complete and merged.

## 1. Decisions (confirmed 2026-07-16)

1. **Scope: the SBC registers itself** (one trunk account per peer), NOT REGISTER forwarding / registrar-proxy (that remains a deferred non-goal). Internal PBX stays IP-auth (M4.1 covers it).
2. **Routing gate: registration state gates outbound routing.** A `register: true` peer that is not currently Registered is skipped as an outbound failover target; if every target is skipped/failed the caller gets 503. M4.2 owns registration state and exposes `IsRegistered(peerName) bool`; M4.4 later generalizes this into cross-call health/cooldown for all peers.
3. **Graceful shutdown un-REGISTERs** (best-effort REGISTER with Expires: 0, bounded ~2s total) so the carrier stops routing inbound to a dead SBC immediately.
4. **Expires: global `register_expires` (default 3600s) + optional per-peer override.** We REQUEST that value; the carrier's 200 OK may GRANT a shorter one; we refresh at ~90% of the granted value.

## 2. Components & module layout

Contained to `config` and `sig` — no `main.go` change (the `Registrar` lives inside `Server.Run`, whose lifecycle is already in the shutdown WaitGroup).

| File | Change |
|---|---|
| `config/schema.go`, `validate.go` | Global `RegisterExpires Duration` (yaml `register_expires`, default 3600s, > 0) + per-peer `Peer.RegisterExpires Duration` (optional override; if set, > 0). |
| `config/store.go` | Add `Subscribe() <-chan struct{}` — a coalescing notify channel fired on `Replace`, so the Registrar reconciles promptly on hot reload. `Current`/readers stay lock-free. |
| `sig/register.go` (new) | The `Registrar`: a manager goroutine that reconciles active registrations against config, one goroutine per registered peer running the lifecycle, and `IsRegistered(name) bool`. |
| `sig/server.go` | `Server.Run` constructs the `Registrar` (once the sipgo `Client` is built), starts it, stores it on `Server` for the bridge, and triggers shutdown un-REGISTER on ctx cancel. |
| `sig/b2bua.go` | `placeCall` skips a target where `Peer.Register && !registrar.IsRegistered(name)`. |
| `sbc.example.yaml` | Document `register_expires`. |

### sipgo v1.4.3 mechanism (verified)

REGISTER is not a dialog. Per peer: build the request, `ClientRequestRegisterBuild(client, req)` (fills CSeq/Call-ID/Via/Max-Forwards), `res, err := client.Do(ctx, req)`; on 401/407 `res, err = client.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username, Password})` (internally retries with digest, returns the final 200). Read the granted `Expires` (Expires header, else the Contact's `expires` param). No `RegisterClient` state machine exists in sipgo — we own the refresh/backoff loop.

## 3. Registration state machine (per peer)

```
Unregistered ─▶ build REGISTER:
                  Request-URI = registrar (sip:<peer.address host:port>)
                  To/From AOR = sip:<auth.username>@<registrar host>
                  Contact     = sip:<ourIP>:<ourSigPort>;transport=<peer transport>
                  Expires     = requested (per-peer override or global register_expires)
                ClientRequestRegisterBuild → client.Do → 401? → DoDigestAuth(peer.auth)
        ┌──────── 200 OK: read GRANTED expires E ─────────┐
        ▼                                                  │
   Registered (IsRegistered=true), refresh timer at ~0.9·E │
        │  timer fires ─▶ refresh (same REGISTER, CSeq++) ─┘
        │
        ▼ (timeout / 5xx / 403 / 4xx-other / network / digest still 401)
     Failed (IsRegistered=false) ─▶ exponential backoff (5s→10s→20s…cap 60s),
                                     then retry from Unregistered. Reset backoff on success.
```

- The per-peer goroutine ends on: ctx cancel (→ un-REGISTER), or the manager stopping it (peer removed / `register: false` / params changed → un-REGISTER then restart with new params).
- `ourIP`/`ourSigPort` reuse the M4.1 helpers (same package).

## 4. Config

```yaml
register_expires: 3600s          # global default lifetime we REQUEST (carrier may grant less)

peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    auth: { username: acct01, password: "${CARRIER_A_PASS}" }
    register: true
    # register_expires: 600s      # per-peer override (optional)
    allowed_ips: [203.0.113.0/24]
```

Validation: `register_expires` (global) > 0; a per-peer `register_expires`, if present, > 0. `register: true` already requires `auth` (M1).

## 5. Routing integration

The bridge holds the `*Registrar`. In `placeCall`'s failover loop, before dialing a target: if `target.Peer.Register && !registrar.IsRegistered(target.Name)`, **skip** it (do not dial; not counted as a real carrier failure). `Resolve` (M3.2) stays pure — the runtime availability check lives in the bridge. Exhaustion codes (M4.1) extend by one rule: if targets were skipped only because unregistered (no real failure, no ring), the caller gets **503 Service Unavailable** (no reachable target). A peer without `register: true` is always considered available (IP-auth trunk — unchanged).

## 6. Lifecycle

- **Startup**: `Server.Run` builds the sipgo `Client`, constructs the `Registrar(store, client)`, and launches its manager goroutine. The manager reads `store.Current()`, starts a per-peer goroutine for each `register: true` peer, and subscribes to `store.Subscribe()`.
- **Hot reload**: on each `Subscribe()` fire, the manager reconciles the desired set (peers with `register: true`, keyed by name, with their address/auth/expires) against the running set: **added** → start; **removed / register:false** → un-REGISTER + stop; **changed** (address, auth, or expires differ) → stop (un-REGISTER old) + start (new). In-flight calls are unaffected (they hold their own snapshot).
- **Shutdown**: when `Run`'s ctx cancels, the manager signals every per-peer goroutine to un-REGISTER (REGISTER Expires: 0), waits up to ~2s total, then returns — `Run` blocks on this before completing so the WaitGroup shutdown stays ordered.

## 7. Error handling (design §7)

| Scenario | Behavior |
|---|---|
| REGISTER 401/407 | `DoDigestAuth` retries with `peer.auth`; success → Registered |
| Digest still rejected (bad creds) / 403 | Failed; `IsRegistered=false`; exponential backoff retry; logged |
| Timeout / 5xx / network | Failed; backoff retry; logged (design §7 REGISTER-failure row) |
| Granted Expires very small | Refresh at ~0.9·granted with a sane floor (e.g. ≥ 10s) to avoid a hot loop |
| Peer skipped as target (unregistered) | Not dialed; if all targets unavailable → 503 to caller |
| Shutdown un-REGISTER fails/times out | Best-effort; bounded ~2s; logged, does not block exit past the bound |

## 8. Testing

A **stub registrar UAS** (a sipgo server) that challenges REGISTER with 401 then grants a 200 with a chosen Expires, and records the requests it received. Over real UDP loopback:
- initial REGISTER succeeds via digest; the granted Expires drives a refresh that the stub observes before expiry;
- a 401→digest retry carries correct credentials (stub asserts the Authorization);
- a failing/silent registrar → the per-peer goroutine backs off and `IsRegistered` is false;
- **routing gate**: with a `register: true` peer that never registers, an INVITE routed to it is skipped and the caller gets 503 (the stub carrier never receives the INVITE);
- **hot reload**: flipping `register: true`→`false` (or removing the peer) triggers an Expires: 0 un-REGISTER and stops refreshing; adding a peer starts registration;
- **shutdown**: cancelling the context sends Expires: 0 to the registrar.
- Full `go vet ./... && go test ./... -race` stays green.

## 9. Scope

**In M4.2:** per-peer outbound REGISTER with digest, granted-Expires refresh, exponential backoff, `IsRegistered` + routing skip, global/per-peer `register_expires`, hot-reload reconcile via `Store.Subscribe`, graceful un-REGISTER on shutdown.

**Deferred:** session timers + 100rel/PRACK (M4.3); DNS SRV + cross-call peer health/cooldown for all peers + configurable uniform failover code (M4.4); REGISTER forwarding / registrar-proxy (non-goal); registration to a registrar host distinct from the peer's call address (single `address` used for both in MVP); per-peer CLI override / PAI (later). Inbound calls from a registered trunk already work via source-IP identification (M3.1) — no new inbound work.
