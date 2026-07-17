# FreeSBC M7.1 — Admin API + Prometheus Metrics Design

The first M7 (operability) slice: a `net/http` admin server behind bcrypt HTTP
Basic Auth, exposing Prometheus `/metrics` and a **read-only** JSON API over the
existing runtime seams. Foundation for M7.2 (config write-back) and M7.3
(embedded WebUI). Parent spec: `freesbc-allinone-design.md` (§107-111:
`admin/api.go` REST via net/http no framework, `admin/webui/` go:embed,
`admin/metrics.go` Prometheus; §122: `prometheus/client_golang`; §163-165:
`admin: {listen, auth: {username, password_hash}}`). M1–M6 complete and merged.

## 0. Reality baseline (existing code)

- `config.AdminConfig{Listen string, Auth AdminAuth{Username, PasswordHash string}}`
  is scaffolded; `Config.Admin *AdminConfig` (nil = admin disabled). Validation
  today only checks `admin.listen` parses as host:port.
- `callstate.Registry` (dependency-free): `Snapshot() []Call`, `Count()`;
  `Call{ID, FromPeer, ToPeer, StartUnixNano}`.
- `sig.Server` holds `registry *callstate.Registry`, `registrar *Registrar`
  (`IsRegistered(name) bool`, internal `state map[string]bool`), `pool
  *media.Pool`, `shield atomic.Pointer[shield.Shield]`, `store *config.Store`;
  exposes `ActiveCalls() int`.
- `media.Pool` has no public usage accessor yet (portpool.go: allocatePair /
  release under a mutex).
- `shield.Shield` counts nothing exposable yet (Check drops silently).
- `main.go` is the composition root: builds the store, media pool, sig.Server,
  runs sig in a goroutine under a `wg`; comment notes "the admin API (M7) still
  attaches here". No HTTP server anywhere yet.
- Deps today: sipgo, pion, fsnotify, goccy/go-yaml. NO prometheus, NO bcrypt.

## 1. Decisions (confirmed 2026-07-17)

1. **HTTP Basic Auth + bcrypt.** The admin API authenticates via HTTP Basic
   Auth; `password_hash` is a bcrypt string; the server
   `bcrypt.CompareHashAndPassword` the presented password and
   `subtle.ConstantTimeCompare` the username. Adds `golang.org/x/crypto/bcrypt`.
2. **Read-only + metrics this slice; kick-call deferred.** M7.1 exposes
   observability only (no mutation of call/config state). `DELETE /api/calls/{id}`
   (kick-call) is a later slice needing a bridge teardown-by-Call-ID mechanism.
3. **`/metrics` behind the same admin Basic Auth.** Prometheus scrapes with
   `basic_auth` in its scrape config; metrics (call volumes, peer topology) are
   gated, consistent with the security posture. The admin listener binds private
   by default.
4. **`admin` decouples from `sig`.** The `admin` package imports `config` and the
   dependency-free `callstate`, and consumes narrow interfaces for the sig-side
   data (peer/register status, port stats, shield stats). `main` adapts
   `sig.Server` to those interfaces. Adds `github.com/prometheus/client_golang`.

## 2. Components & module layout

| File | Change |
|---|---|
| `admin/server.go` (new) | `Server`; `New(cfg *config.AdminConfig, store *config.Store, deps Deps) *Server`; `Run(ctx) error` (http.Server + graceful Shutdown); the bcrypt Basic Auth middleware; a panic-recover middleware; the route mux; the `Deps` interface struct + `PeerStatus`/`ShieldStats` types. |
| `admin/api.go` (new) | Read-only JSON handlers: `handleHealthz`, `handleStatus`, `handleCalls`, `handlePeers`, `handleConfig` (redacted). |
| `admin/metrics.go` (new) | A custom `prometheus.Collector` reading the injected seams on scrape; a private `*prometheus.Registry` (+ `collectors.NewGoCollector()`); the `/metrics` handler. |
| `admin/redact.go` (new) | Config → redacted JSON view (secrets → `"***"`). |
| `config/validate.go` | When `Admin != nil`: require non-empty `Auth.Username` and a `Auth.PasswordHash` that parses as bcrypt (`bcrypt.Cost` succeeds). |
| `media/portpool.go` | `func (p *Pool) Stats() (inUse, total int)`. |
| `sig/shield` (shield.go) | Drop counters (`atomic.Int64` per reason) incremented in `Check`; `func (s *Shield) Stats() Stats` accessor (banned-current, drops-by-reason). |
| `sig/server.go` | A simple nil-safe `IsRegistered(name string) bool` accessor (delegates to the registrar) so `main` can build peer status. `sig` does NOT import `admin` — `main` maps `store` peers + `IsRegistered` into `[]admin.PeerStatus`. |
| `main.go` | Build the `admin.Deps` (from `store`, `registry.Snapshot`, `srv.IsRegistered`, `pool.Stats`, `shield.Stats`), construct `admin.Server`, add to the run group; nil-safe when `admin` absent. |

### The `Deps` seam

```go
// admin package
type PeerStatus struct {
    Name, Address, Transport, SRTP string
    Register   bool   // peer wants outbound REGISTER
    Registered bool   // currently registered (meaningful when Register)
}
type ShieldStats struct {
    BannedCurrent int
    DropsByReason map[string]int64 // "banned","scanner","rate"
}
type Deps struct {
    Calls       func() []callstate.Call
    Peers       func() []PeerStatus
    Ports       func() (inUse, total int)
    Shield      func() ShieldStats
    ActiveCalls func() int
    Version     string
}
```

`main` builds `Deps` from the `sig.Server` (registry.Snapshot, a new
`Server.PeerStatuses()`, `pool.Stats()`, `shield.Stats()`), keeping `admin`
free of a `sig` import. All `Deps` funcs must be safe to call concurrently
(they read already-synchronized structures).

## 3. Metrics (`/metrics`)

A custom `prometheus.Collector` (`Describe`/`Collect`) that reads the injected
`Deps` on each scrape — no duplicated state; the registry/pool/shield remain the
source of truth. Registered in a **private** `prometheus.Registry` (not the
global default) plus `collectors.NewGoCollector()` for basic process health.
All metrics namespaced `freesbc_`:

| Metric | Type | Source (per scrape) |
|---|---|---|
| `freesbc_active_calls` | gauge | `deps.ActiveCalls()` |
| `freesbc_media_ports_in_use` | gauge | `deps.Ports()` |
| `freesbc_media_ports_total` | gauge | `deps.Ports()` |
| `freesbc_peer_registered{peer}` | gauge 0/1 | `deps.Peers()` (only `Register` peers) |
| `freesbc_shield_banned_current` | gauge | `deps.Shield().BannedCurrent` |
| `freesbc_shield_drops_total{reason}` | counter | `deps.Shield().DropsByReason` |
| `freesbc_build_info{version}` | gauge=1 | `deps.Version` |

`shield_drops_total` is a true monotonic counter: the `shield.Shield` gains
three `atomic.Int64` counters incremented on each drop reason in `Check`
(banned / scanner / rate), surfaced via `Shield.Stats()`. The Collector emits
them as counter samples (their monotonicity is guaranteed by the atomics). All
other metrics are gauges sampled live at scrape time — no per-event wiring, so
the SIP/media hot paths are untouched except the shield's three atomic adds.

## 4. API endpoints (read-only JSON)

Content-Type `application/json`. All under Basic Auth **except** `/healthz`:

- `GET /healthz` → `200 {"status":"ok"}`, **no auth** (liveness; leaks nothing
  an attacker who reached the private listener doesn't already know).
- `GET /api/status` → `{version, uptime_seconds, active_calls, ports:{in_use,
  total}, listeners:[...], config_path}`.
- `GET /api/calls` → `[{id, from, to, started (RFC3339), duration_seconds}]`
  from `deps.Calls()`.
- `GET /api/peers` → `[{name, address, transport, srtp, register, registered}]`
  from `deps.Peers()`.
- `GET /api/config` → the current config as **redacted** JSON (§5). Mandatory
  redaction — the config holds carrier passwords and the admin password hash.

Unknown path → `404`; wrong method → `405`. Handlers never leak stack traces or
internal detail in the body; a panic is caught by the recover middleware → `500`.

## 5. Config redaction (`redact.go`)

`GET /api/config` returns a structured JSON view of `store.Current()` with every
secret replaced by `"***"`:

- `admin.auth.password_hash` → `"***"`.
- every `peers.<name>.auth.password` → `"***"`.
- (env-sourced values are already expanded in the live config; since the live
  config may hold expanded secrets, redaction operates on the known secret
  fields by path, not by trying to detect env origin.)

Redaction is a whitelist of known-secret fields, applied to a copy — never
mutating the live config. A test asserts a real password value is absent from
the response body. The raw-YAML-file view (with `${ENV}` refs intact, for the
editor) is M7.2/M7.3's concern, not this read-only slice.

## 6. Auth (`server.go`)

Basic Auth middleware wraps every route except `/healthz`:

1. Parse `Authorization: Basic <base64>`. Absent/malformed → `401` +
   `WWW-Authenticate: Basic realm="freesbc"`.
2. `subtle.ConstantTimeCompare([]byte(user), []byte(cfg.Auth.Username))` AND
   `bcrypt.CompareHashAndPassword([]byte(cfg.Auth.PasswordHash), []byte(pass))`.
   Evaluate BOTH before deciding (avoid a username-timing oracle), then `401`
   on either failure — identical response for bad-user and bad-pass (no
   enumeration).
3. bcrypt is deliberately slow; combined with a private-bound listener this is
   the M7.1 baseline. A login rate-limit ships with the WebUI (M7.3).

Config validation (`validate.go`): when `Admin != nil`, `Auth.Username` must be
non-empty and `Auth.PasswordHash` must parse as bcrypt (`bcrypt.Cost(hash)`
returns no error) — a misconfigured admin block fails at load, not at first
request. (`admin.listen` host:port check stays.)

## 7. Lifecycle & error handling

- `admin.Server.Run(ctx) error`: builds the mux, `http.Server{Addr: cfg.Listen,
  Handler: mux}`; `ListenAndServe` in the foreground of Run; on `ctx.Done()`,
  `srv.Shutdown(ctxWithTimeout)` for graceful drain, then return. A bind failure
  returns an error (fatal — `main` tears the process down, like a SIP bind
  failure).
- Admin is **optional**: `Config.Admin == nil` → `main` doesn't construct/run the
  admin server.
- Hot-reload: handlers read `store.Current()` (and the `Deps` funcs read live
  structures) per request, so status/calls/peers/config track reloads. The
  **listen address and auth credentials are captured at start** — changing them
  needs a restart (documented; mirrors the SIP Contact-port behavior).

| Scenario | Behavior |
|---|---|
| No `admin:` block | Admin server not started |
| Missing/bad credentials | `401`, generic (no user enumeration) |
| `password_hash` not bcrypt at load | Config validation error (fail fast) |
| Admin listener bind failure | Fatal (process teardown) |
| Secrets in `/api/config` | Redacted to `"***"` |
| Panic in a handler | recover middleware → `500`, no stack leak, server stays up |
| `/metrics` without auth | `401` (behind Basic Auth) |

## 8. Testing

- **Auth** (`server_test.go`, `httptest`): no creds → 401; wrong user → 401;
  wrong pass → 401; correct user+pass (real bcrypt hash) → 200; `/healthz`
  without creds → 200; `/metrics` without creds → 401.
- **API** (`api_test.go`): `/api/status` JSON shape/fields; `/api/calls`
  reflects an injected `Deps.Calls` snapshot (ids/from/to/duration); `/api/peers`
  reflects injected peer+register state; `/api/config` **redacts** — inject a
  config with a peer password and admin hash, assert the response contains
  `"***"` and does NOT contain the real secret; 404 unknown path; 405 wrong
  method.
- **Metrics** (`metrics_test.go`): scrape (with auth) contains each `freesbc_*`
  metric with injected values — `active_calls` = N; a `register:true` peer's
  `peer_registered` label present with 0/1; `shield_drops_total{reason="rate"}`
  reflects an injected count; `build_info{version="..."}` = 1. Uses
  `promhttp`/`testutil` against the private registry.
- **Redaction** (`redact_test.go`): known-secret fields → `"***"`, non-secret
  fields intact, live config unmutated.
- **Config validation** (`validate_test.go`): admin block with empty username →
  error; non-bcrypt `password_hash` → error; valid block → ok.
- **Pool/shield accessors**: `pool.Stats()` returns (inUse, total) consistent
  with allocations; `shield.Stats()` drop counters increment per reason (extend
  the existing shield tests).
- Full `go vet ./... && go test ./... -race` green; no regression to M1–M6
  (the SIP/media path is untouched; the shield gains three atomic adds + an
  accessor; admin is additive and optional).

## 9. Scope

**In M7.1:** `admin/` net/http server; bcrypt HTTP Basic Auth (all routes except
`/healthz`); Prometheus `/metrics` (custom Collector over live seams + shield
drop counters + Go collector) behind auth; read-only JSON (`/healthz`,
`/api/status`, `/api/calls`, `/api/peers`, `/api/config` redacted);
`media.Pool.Stats()`, `shield.Shield.Stats()` + drop counters, `sig` peer-status
accessor; admin auth config validation; wired in `main`, optional, graceful
shutdown. New deps: `prometheus/client_golang`, `golang.org/x/crypto/bcrypt`.

**Deferred (documented non-goals):**
- Kick-call (`DELETE /api/calls/{id}`) — its own slice (bridge teardown-by-Call-ID).
- Config write-back (`PUT /api/config`, YAML AST patch, env-ref preservation) — M7.2.
- Embedded WebUI (`go:embed`) — M7.3.
- CDR / historical call records; a per-call detail endpoint.
- Login/session rate-limiting (ships with the WebUI, M7.3).
- Hot-reload of the admin listen address / credentials (restart required).
- TLS on the admin listener (bind-private baseline; front with a reverse proxy,
  or a later slice).
- Per-endpoint health/cooldown and per-IP ban detail in `/api/peers` (peer-level
  register status only; the shield/health internals are aggregated in metrics).
- Raw-YAML config view with `${ENV}` refs (that's the editor path, M7.2/M7.3).
