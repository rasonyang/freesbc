# FreeSBC M7.1 — Admin API + Prometheus Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `net/http` admin server behind bcrypt HTTP Basic Auth exposing Prometheus `/metrics` and a read-only JSON API over the existing runtime seams — the operability foundation for M7.2 (config write-back) and M7.3 (WebUI).

**Architecture:** A new `admin/` package that imports only `config` + the dependency-free `callstate` and consumes a narrow `Deps` interface struct for sig-side data (peer/register status, port stats, shield stats); `main` adapts `sig.Server` into `Deps`. The admin server runs alongside the SIP server in `main`'s run group, optional (only when `admin:` is configured), with a bcrypt Basic Auth middleware on every route except `/healthz`.

**Tech Stack:** Go stdlib `net/http`, `crypto/subtle`, `github.com/prometheus/client_golang`, `golang.org/x/crypto/bcrypt`.

## Global Constraints

- **New deps:** `github.com/prometheus/client_golang v1.23.2`, `golang.org/x/crypto` (for `.../bcrypt`, latest). No other new deps. (spec §1)
- **`admin` imports only `config` + `callstate`** — NOT `sig`. It defines `Deps`/`PeerStatus`/`ShieldStats`; `main` adapts `sig.Server`. `sig` gains only a nil-safe `IsRegistered(name) bool` and a shield-stats accessor. (spec §1.4, §2)
- **Read-only this slice.** No mutation of call/config state. No kick-call, no config write. (spec §1.2)
- **`/metrics` and `/api/*` behind bcrypt Basic Auth; `/healthz` is unauthenticated.** Both auth checks (username via `subtle.ConstantTimeCompare`, password via `bcrypt.CompareHashAndPassword`) are evaluated before deciding; a generic `401` on failure (no user enumeration). (spec §3, §6)
- **`/api/config` redacts secrets** (`admin.auth.password_hash`, every `peers.<name>.auth.password`) by field-path → `"***"`; a test asserts the real secret is absent from the body. (spec §5)
- **Admin is optional** (`Config.Admin == nil` → not started) and **bind failure is fatal**. Listen address + credentials captured at start (restart to change). (spec §7)
- **Config validation:** when `Admin != nil`, `Auth.Username` non-empty and `Auth.PasswordHash` a valid bcrypt hash (fail fast at load). (spec §6)
- English identifiers/comments; stdlib `testing` + `httptest`/`promhttp` testutil; `gofmt -l .` clean; gate `go test ./... -race`.

## Verified existing facts (use these)

- `config.AdminConfig{Listen string, Auth AdminAuth{Username, PasswordHash string}}`; `Config.Admin *AdminConfig`. `validate.go` already checks `admin.listen` is host:port; `withDefaults` doesn't touch admin.
- `callstate.Registry.Snapshot() []Call`; `Call{ID, FromPeer, ToPeer, StartUnixNano}`.
- `media.Pool` has `inUse map[int]struct{}` + `mu sync.Mutex`; range from `p.store.Current().Listen.Media.PortRange.{Min,Max}`.
- `shield.Shield.Check(src, ua) Verdict` has three drop points (banned / scanner / rate); `shield.Shield` holds `bans *banList` (with `until map[netip.Addr]time.Time`, `mu`).
- `sig.Server` holds `registrar *Registrar` (`IsRegistered(name) bool`), `pool *media.Pool`, `shield atomic.Pointer[shield.Shield]`, `store`, `registry`; has `ActiveCalls() int`.
- `main.go run(cfgPath)`: builds `store`, `pool`, `sipServer := sig.NewServer(store, pool, log)`, runs each under a `sync.WaitGroup wg` with a shared `ctx`/`stop`. No HTTP server, no version var yet.
- Latest: `prometheus/client_golang v1.23.2`, `golang.org/x/crypto v0.54.0`.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `go.mod`/`go.sum` | add prometheus + x/crypto | 1 |
| `config/validate.go` | admin auth validation (bcrypt) | 1 |
| `media/portpool.go` | `Pool.Stats()` | 2 |
| `shield/shield.go`, `shield/banlist.go` | drop counters + `Stats()` + `banList.size()` | 2 |
| `sig/server.go` | `IsRegistered`, `ShieldStats` accessors | 2 |
| `admin/server.go` (new) | `Server`, `Deps`/`PeerStatus`/`ShieldStats`, `New`, `Run`, auth + recover middleware, mux (stubbed handlers) | 3 |
| `admin/api.go`, `admin/redact.go` (new) | read-only JSON handlers + redaction | 4 |
| `admin/metrics.go` (new) | Prometheus Collector + registry + handler | 5 |
| `main.go` | build `Deps`, run the admin server | 6 |
| `README.md`, `sbc.example.yaml` | roadmap + admin docs + verification | 7 |

---

### Task 1: dependencies + admin auth config validation

**Files:** Modify `go.mod`/`go.sum`, `config/validate.go`; Test `config/validate_test.go`.

**Interfaces:**
- Produces: validation that rejects an `admin` block with empty `username` or a non-bcrypt `password_hash`.

- [ ] **Step 1: Add the dependencies**

Run: `go get github.com/prometheus/client_golang@v1.23.2 && go get golang.org/x/crypto/bcrypt && go mod tidy`
Expected: go.mod gains `prometheus/client_golang` and `golang.org/x/crypto` (+ transitives). `go build ./...` still clean.

- [ ] **Step 2: Write the failing test** — append to `config/validate_test.go`:

```go
func TestValidateAdminAuth(t *testing.T) {
	// a real bcrypt hash of "secret"
	good := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	base := func(admin string) string {
		return `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
` + admin + `
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`
	}
	// valid admin block
	if _, err := Parse([]byte(base("admin:\n  listen: 127.0.0.1:8080\n  auth: { username: admin, password_hash: \"" + good + "\" }"))); err != nil {
		t.Fatalf("valid admin block should parse: %v", err)
	}
	// empty username
	_, err := Parse([]byte(base("admin:\n  listen: 127.0.0.1:8080\n  auth: { username: \"\", password_hash: \"" + good + "\" }")))
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("empty username should fail, got %v", err)
	}
	// non-bcrypt password_hash
	_, err = Parse([]byte(base("admin:\n  listen: 127.0.0.1:8080\n  auth: { username: admin, password_hash: notbcrypt }")))
	if err == nil || !strings.Contains(err.Error(), "password_hash") {
		t.Fatalf("non-bcrypt hash should fail, got %v", err)
	}
	// no admin block → fine
	if _, err := Parse([]byte(base(""))); err != nil {
		t.Fatalf("no admin block should parse: %v", err)
	}
}
```

- [ ] **Step 3: Run to verify fail** — `go test ./config/ -run TestValidateAdminAuth -v` → FAIL.

- [ ] **Step 4: Implement** — in `config/validate.go`, extend the existing `if c.Admin != nil` block (which currently only checks `admin.listen`):

```go
	if c.Admin != nil {
		if _, err := netip.ParseAddrPort(c.Admin.Listen); err != nil {
			fail("admin.listen: %q is not host:port", c.Admin.Listen)
		}
		if c.Admin.Auth.Username == "" {
			fail("admin.auth.username: required when admin is configured")
		}
		if _, err := bcrypt.Cost([]byte(c.Admin.Auth.PasswordHash)); err != nil {
			fail("admin.auth.password_hash: must be a bcrypt hash: %v", err)
		}
	}
```

Add `"golang.org/x/crypto/bcrypt"` to `config/validate.go` imports.

- [ ] **Step 5: Run to verify pass** — `go test ./config/ -run TestValidateAdminAuth -v` → PASS (confirm `strings` imported in validate_test.go — it is).

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum config/validate.go config/validate_test.go
git commit -m "feat(config): validate admin auth (bcrypt password_hash); add prometheus + x/crypto deps"
```

---

### Task 2: runtime seams — Pool.Stats, shield drop counters/Stats, sig accessors

**Files:** Modify `media/portpool.go`, `shield/shield.go`, `shield/banlist.go`, `sig/server.go`; Tests in each package.

**Interfaces:**
- Produces:
  - `func (p *Pool) Stats() (inUse, total int)` (media).
  - `shield.Shield` gains `dropsBanned/dropsScanner/dropsRate atomic.Int64` incremented in `Check`; `type Stats struct { BannedCurrent int; DropsByReason map[string]int64 }`; `func (s *Shield) Stats() Stats`. `banList` gains `func (b *banList) size() int`.
  - `func (s *Server) IsRegistered(name string) bool` (nil-safe); `func (s *Server) ShieldStats() shield.Stats` (nil-safe; loads the shield atomic); `func (s *Server) Calls() []callstate.Call` (`return s.registry.Snapshot()`).

- [ ] **Step 1: Write the failing tests**

`media/portpool_test.go` (append):
```go
func TestPoolStats(t *testing.T) {
	p := NewPool(testStore(41000, 41007)) // 8 ports → 4 pairs
	inUse, total := p.Stats()
	if inUse != 0 || total != 4 {
		t.Fatalf("empty pool: inUse=%d total=%d, want 0/4", inUse, total)
	}
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer pair.Close()
	inUse, total = p.Stats()
	if inUse != 1 || total != 4 {
		t.Fatalf("after 1 alloc: inUse=%d total=%d, want 1/4", inUse, total)
	}
}
```
(Reuse the `testStore` helper the existing media tests use for a port range.)

`shield/shield_test.go` (append) — drop counters via the existing test harness:
```go
func TestShieldStatsCountsDrops(t *testing.T) {
	s := testShield(t, shieldCfg) // rate 2/s, nftables off; from earlier tasks
	bad := netip.MustParseAddr("198.51.100.20")
	s.Check(bad, "sipvicious")            // scanner drop (+ ban)
	s.Check(bad, "")                       // now banned → banned drop
	st := s.Stats()
	if st.DropsByReason["scanner"] < 1 {
		t.Errorf("scanner drops = %d, want >=1", st.DropsByReason["scanner"])
	}
	if st.DropsByReason["banned"] < 1 {
		t.Errorf("banned drops = %d, want >=1", st.DropsByReason["banned"])
	}
	if st.BannedCurrent < 1 {
		t.Errorf("banned current = %d, want >=1", st.BannedCurrent)
	}
}
```

`sig/server_test.go` (append) — nil-safe accessors on a bare server:
```go
func TestServerAccessorsNilSafe(t *testing.T) {
	s := NewServer(config.NewStore(mustMinimalCfg(t)), nil, discardLogger())
	// registrar/shield are nil before Run — accessors must not panic.
	if s.IsRegistered("nobody") {
		t.Error("nil registrar → not registered")
	}
	_ = s.ShieldStats() // must not panic; zero-value stats
}
```
(Use whatever minimal-config helper `sig` tests already have; if none, parse a tiny valid config inline.)

- [ ] **Step 2: Run to verify fail** — `go test ./media/ ./shield/ ./sig/ -run 'TestPoolStats|TestShieldStatsCountsDrops|TestServerAccessorsNilSafe' -v` → FAIL.

- [ ] **Step 3: Implement `media.Pool.Stats`** — in `media/portpool.go`:

```go
// Stats returns the number of RTP port pairs currently allocated and the
// total number of pairs the configured range can hold.
func (p *Pool) Stats() (inUse, total int) {
	media := p.store.Current().Listen.Media
	lo, hi := int(media.PortRange.Min), int(media.PortRange.Max)
	if lo%2 != 0 {
		lo++
	}
	total = (hi - lo + 1) / 2
	if total < 0 {
		total = 0
	}
	p.mu.Lock()
	inUse = len(p.inUse)
	p.mu.Unlock()
	return inUse, total
}
```

- [ ] **Step 4: Implement shield drop counters + Stats** — in `shield/shield.go`, add fields to `Shield`:

```go
	dropsBanned  atomic.Int64
	dropsScanner atomic.Int64
	dropsRate    atomic.Int64
```

Increment them at the three drop points in `Check` (add `s.dropsBanned.Add(1)` before the banned-return, `s.dropsScanner.Add(1)` before the scanner-return, `s.dropsRate.Add(1)` before the rate-return). Add:

```go
// Stats is a snapshot of shield activity for metrics.
type Stats struct {
	BannedCurrent int
	DropsByReason map[string]int64
}

// Stats returns a snapshot of current bans and cumulative drops by reason.
func (s *Shield) Stats() Stats {
	return Stats{
		BannedCurrent: s.bans.size(),
		DropsByReason: map[string]int64{
			"banned":  s.dropsBanned.Load(),
			"scanner": s.dropsScanner.Load(),
			"rate":    s.dropsRate.Load(),
		},
	}
}
```

Add `"sync/atomic"` to `shield/shield.go` imports. In `shield/banlist.go`:

```go
// size returns the number of currently-tracked (possibly expired) ban entries.
func (b *banList) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.until)
}
```

- [ ] **Step 5: Implement sig accessors** — in `sig/server.go`:

```go
// IsRegistered reports whether the peer is currently registered (nil-safe:
// false before Run builds the registrar).
func (s *Server) IsRegistered(name string) bool {
	if s.registrar == nil {
		return false
	}
	return s.registrar.IsRegistered(name)
}

// ShieldStats returns the current shield activity snapshot (nil-safe: zero
// value before Run builds the shield).
func (s *Server) ShieldStats() shield.Stats {
	sh := s.shield.Load()
	if sh == nil {
		return shield.Stats{DropsByReason: map[string]int64{}}
	}
	return sh.Stats()
}

// Calls returns a snapshot of the active-call registry (for the admin API).
func (s *Server) Calls() []callstate.Call { return s.registry.Snapshot() }
```

(Confirm `sig` already imports `callstate` — it does, `registry` is a `*callstate.Registry`.)

(Confirm `sig` already imports `shield`; it does from M6.)

- [ ] **Step 6: Run to verify pass** — `go test ./media/ ./shield/ ./sig/ -run 'TestPoolStats|TestShieldStatsCountsDrops|TestServerAccessorsNilSafe' -race -v` → PASS. Then `go test ./shield/ -race` (the drop-counter adds don't break existing shield tests) and `go build ./...`.

- [ ] **Step 7: Commit**

```bash
git add media/portpool.go shield/shield.go shield/banlist.go sig/server.go media/portpool_test.go shield/shield_test.go sig/server_test.go
git commit -m "feat: expose Pool.Stats, shield drop counters/Stats, and sig registration/shield accessors"
```

---

### Task 3: `admin/server.go` — server, auth, mux (stubbed handlers)

**Files:** Create `admin/server.go`; Test `admin/server_test.go`.

**Interfaces:**
- Consumes: `config.AdminConfig`, `config.Store`, `callstate.Call`; `golang.org/x/crypto/bcrypt`, `crypto/subtle`, `net/http`.
- Produces:
  - `type PeerStatus struct { Name, Address, Transport, SRTP string; Register, Registered bool }`.
  - `type ShieldStats struct { BannedCurrent int; DropsByReason map[string]int64 }`.
  - `type Deps struct { Calls func() []callstate.Call; Peers func() []PeerStatus; Ports func() (inUse, total int); Shield func() ShieldStats; ActiveCalls func() int; Version string }`.
  - `type Server struct{…}`; `func New(cfg *config.AdminConfig, store *config.Store, deps Deps, log *slog.Logger) *Server`; `func (s *Server) Run(ctx context.Context) error`.
  - Stubbed handler methods (`handleStatus`/`handleCalls`/`handlePeers`/`handleConfig`/`handleMetrics`) returning `501` — Tasks 4/5 implement them.

- [ ] **Step 1: Write the failing test** — `admin/server_test.go`:

```go
package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/freesbc/freesbc/config"
	"golang.org/x/crypto/bcrypt"
)

// emptyDeps returns Deps with harmless zero-value closures; individual tests
// override the fields they exercise.
func emptyDeps() Deps {
	return Deps{
		Calls:       func() []callstate.Call { return nil },
		Peers:       func() []PeerStatus { return nil },
		Ports:       func() (int, int) { return 0, 0 },
		Shield:      func() ShieldStats { return ShieldStats{DropsByReason: map[string]int64{}} },
		ActiveCalls: func() int { return 0 },
		Version:     "test",
	}
}

func newTestServer(t *testing.T, deps Deps) *Server {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0"}
	cfg.Auth.Username = "admin"
	cfg.Auth.PasswordHash = string(hash)
	store := config.NewStore(mustCfg(t))
	return New(cfg, store, deps, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func testServer(t *testing.T) *Server { return newTestServer(t, emptyDeps()) }
```

(Add a `mustCfg(t)` helper that parses a minimal valid config via `config.Parse`. Tasks 4/5 add variants that override specific `Deps` fields via `newTestServer(t, deps)`.) The actual tests:

```go
func TestAuthRequired(t *testing.T) {
	s := testServer(t)
	h := s.handler()
	// no creds → 401
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/status", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no creds: got %d want 401", rr.Code)
	}
	// wrong pass → 401
	rr = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "wrong")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong pass: got %d want 401", rr.Code)
	}
	// correct → not 401 (stub returns 501 until Task 4)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("correct creds must pass auth, got 401")
	}
}

func TestHealthzNoAuth(t *testing.T) {
	s := testServer(t)
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz no-auth: got %d want 200", rr.Code)
	}
}

func TestMetricsBehindAuth(t *testing.T) {
	s := testServer(t)
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics without creds: got %d want 401", rr.Code)
	}
}
```

Expose a `handler() http.Handler` method (the composed mux+middleware) so tests drive it via httptest without binding a socket.

- [ ] **Step 2: Run to verify fail** — `go test ./admin/ -v` → FAIL (undefined).

- [ ] **Step 3: Implement `admin/server.go`**

```go
// Package admin serves the read-only operator HTTP surface: a Prometheus
// /metrics endpoint and a JSON status API, behind bcrypt HTTP Basic Auth.
// It imports only config and the dependency-free callstate; sig-side data
// arrives via the Deps closures (main adapts sig.Server).
package admin

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/freesbc/freesbc/callstate"
	"github.com/freesbc/freesbc/config"
	"golang.org/x/crypto/bcrypt"
)

// PeerStatus is one peer's operator-visible status.
type PeerStatus struct {
	Name, Address, Transport, SRTP string
	Register, Registered           bool
}

// ShieldStats mirrors the shield's activity snapshot for the API/metrics.
type ShieldStats struct {
	BannedCurrent int
	DropsByReason map[string]int64
}

// Deps are the live-data closures the admin surface reads. All must be safe
// for concurrent use (they read already-synchronized structures).
type Deps struct {
	Calls       func() []callstate.Call
	Peers       func() []PeerStatus
	Ports       func() (inUse, total int)
	Shield      func() ShieldStats
	ActiveCalls func() int
	Version     string
}

// Server is the admin HTTP server.
type Server struct {
	cfg     *config.AdminConfig
	store   *config.Store
	deps    Deps
	log     *slog.Logger
	started time.Time
}

func New(cfg *config.AdminConfig, store *config.Store, deps Deps, log *slog.Logger) *Server {
	return &Server{cfg: cfg, store: store, deps: deps, log: log, started: time.Now()}
}

// handler composes the mux with the recover and (per-route) auth middleware.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz) // no auth
	mux.HandleFunc("/metrics", s.requireAuth(s.handleMetrics))
	mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/calls", s.requireAuth(s.handleCalls))
	mux.HandleFunc("/api/peers", s.requireAuth(s.handlePeers))
	mux.HandleFunc("/api/config", s.requireAuth(s.handleConfig))
	return s.recoverMW(mux)
}

// Run serves until ctx is cancelled, then shuts down gracefully. A bind
// failure returns an error (fatal to the process).
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{Addr: s.cfg.Listen, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	s.log.Info("admin server listening", "addr", s.cfg.Listen)
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// requireAuth wraps h with HTTP Basic Auth: constant-time username compare AND
// bcrypt password compare, both evaluated before deciding (no timing oracle),
// generic 401 on any failure (no user enumeration). /healthz is not wrapped.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.cfg.Auth.Username)) == 1
		passOK := bcrypt.CompareHashAndPassword([]byte(s.cfg.Auth.PasswordHash), []byte(pass)) == nil
		if !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="freesbc"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// recoverMW turns a handler panic into a 500 without leaking a stack trace.
func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("admin handler panic", "err", rec, "path", r.URL.Path)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// The following are stubs replaced in Tasks 4 (api) and 5 (metrics).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request)  { stub(w) }
func (s *Server) handleCalls(w http.ResponseWriter, r *http.Request)   { stub(w) }
func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request)   { stub(w) }
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request)  { stub(w) }
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) { stub(w) }

func stub(w http.ResponseWriter) { http.Error(w, "not implemented", http.StatusNotImplemented) }
```

Add a `mustCfg(t)` test helper in `admin/server_test.go` that returns a `*config.Config` from a minimal valid YAML via `config.Parse`.

- [ ] **Step 4: Run to verify pass** — `go test ./admin/ -race -v` → PASS (auth 401s, healthz 200, metrics 401, correct-creds passes auth to the 501 stub). `gofmt -l .`, `go vet ./admin/`, `go build ./...`.

- [ ] **Step 5: Commit**

```bash
git add admin/server.go admin/server_test.go
git commit -m "feat(admin): http server with bcrypt Basic Auth middleware and route mux"
```

---

### Task 4: `admin/api.go` + `admin/redact.go` — read-only JSON handlers

**Files:** Create `admin/api.go`, `admin/redact.go`; Test `admin/api_test.go`, `admin/redact_test.go`. Modify `admin/server.go` only to delete the four api stubs (handleStatus/Calls/Peers/Config) — they move to api.go.

**Interfaces:**
- Consumes: `Deps`, `config.Store` (Task 3); `callstate.Call`.
- Produces: real `handleStatus`/`handleCalls`/`handlePeers`/`handleConfig`; `func redactConfig(*config.Config) any` (a redacted, JSON-marshalable view).

- [ ] **Step 1: Write the failing tests** — `admin/api_test.go`:

```go
func TestAPIStatus(t *testing.T) {
	s := testServer(t) // from server_test.go; wire ActiveCalls/Ports to known values
	body := authGET(t, s, "/api/status")
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("status json: %v", err)
	}
	for _, k := range []string{"version", "uptime_seconds", "active_calls", "ports"} {
		if _, ok := st[k]; !ok {
			t.Errorf("status missing %q", k)
		}
	}
}

func TestAPICalls(t *testing.T) {
	// override the Calls dep to return one call, assert it's reflected.
	s := testServerWithCalls(t, []callstate.Call{{ID: "abc", FromPeer: "a", ToPeer: "b", StartUnixNano: time.Now().UnixNano()}})
	body := authGET(t, s, "/api/calls")
	var calls []map[string]any
	if err := json.Unmarshal(body, &calls); err != nil {
		t.Fatalf("calls json: %v", err)
	}
	if len(calls) != 1 || calls[0]["id"] != "abc" || calls[0]["from"] != "a" {
		t.Fatalf("calls not reflected: %v", calls)
	}
}

func TestAPIConfigRedactsSecrets(t *testing.T) {
	// a config with a peer password and admin hash; assert redaction.
	s := testServerWithSecretConfig(t, "s3cr3t-carrier-pw")
	body := authGET(t, s, "/api/config")
	str := string(body)
	if strings.Contains(str, "s3cr3t-carrier-pw") {
		t.Fatal("peer password LEAKED in /api/config")
	}
	if !strings.Contains(str, "***") {
		t.Fatal("redaction marker missing")
	}
}
```

Write the helpers: `authGET(t, s, path) []byte` (does a `SetBasicAuth("admin","secret")` request through `s.handler()`, asserts 200, returns body); `testServerWithCalls`/`testServerWithSecretConfig` (variants of `testServer` overriding `Deps.Calls` / the store config). `redact_test.go`:

```go
func TestRedactConfig(t *testing.T) {
	cfg := mustCfgWithSecret(t, "peer-pw", "$2a$10$...adminhash...")
	v := redactConfig(cfg)
	b, _ := json.Marshal(v)
	s := string(b)
	if strings.Contains(s, "peer-pw") {
		t.Error("peer password not redacted")
	}
	if strings.Contains(s, "adminhash") {
		t.Error("admin password_hash not redacted")
	}
	// non-secret field preserved (a peer address appears)
	if !strings.Contains(s, "127.0.0.1") {
		t.Error("non-secret field lost")
	}
}
```

- [ ] **Step 2: Run to verify fail** — `go test ./admin/ -run 'TestAPI|TestRedact' -v` → FAIL.

- [ ] **Step 3: Implement `admin/api.go`** — remove the four api stubs from server.go; add:

```go
package admin

import (
	"encoding/json"
	"net/http"
	"time"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	inUse, total := s.deps.Ports()
	var listeners []string
	for _, l := range s.store.Current().Listen.SIP {
		listeners = append(listeners, l.String()) // or reconstruct host:port/transport
	}
	writeJSON(w, map[string]any{
		"version":        s.deps.Version,
		"uptime_seconds": int(time.Since(s.started).Seconds()),
		"active_calls":   s.deps.ActiveCalls(),
		"ports":          map[string]int{"in_use": inUse, "total": total},
		"listeners":      listeners,
	})
}

func (s *Server) handleCalls(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	out := []map[string]any{}
	for _, c := range s.deps.Calls() {
		start := time.Unix(0, c.StartUnixNano)
		out = append(out, map[string]any{
			"id":               c.ID,
			"from":             c.FromPeer,
			"to":               c.ToPeer,
			"started":          start.Format(time.RFC3339),
			"duration_seconds": int(now.Sub(start).Seconds()),
		})
	}
	writeJSON(w, out)
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.deps.Peers())
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, redactConfig(s.store.Current()))
}
```

(For `listeners`, use whatever string form `config.SIPListen` already provides — if it has a `String()` use it; else build `transport://host:port`. Check the type.)

Implement `admin/redact.go` — build a redacted, JSON-marshalable view. Since `config.Config` structs carry `yaml:` tags (not `json:`), marshal a bespoke map so the shape is stable and secrets are dropped:

```go
package admin

import "github.com/freesbc/freesbc/config"

// redactConfig returns a JSON-marshalable view of cfg with secrets replaced
// by "***": admin.auth.password_hash and every peers.<name>.auth.password.
// It never mutates cfg.
func redactConfig(cfg *config.Config) any {
	peers := map[string]any{}
	for name, p := range cfg.Peers {
		pv := map[string]any{
			"address":   p.Address,
			"transport": p.Transport,
			"srtp":      p.SRTP,
			"register":  p.Register,
		}
		if p.Auth != nil {
			auth := map[string]any{"username": p.Auth.Username}
			if p.Auth.Password != "" {
				auth["password"] = "***"
			}
			pv["auth"] = auth
		}
		peers[name] = pv
	}
	view := map[string]any{"peers": peers}
	if cfg.Admin != nil {
		admin := map[string]any{"listen": cfg.Admin.Listen}
		a := map[string]any{"username": cfg.Admin.Auth.Username}
		if cfg.Admin.Auth.PasswordHash != "" {
			a["password_hash"] = "***"
		}
		admin["auth"] = a
		view["admin"] = admin
	}
	// include non-secret top-level fields useful to an operator
	view["routes"] = cfg.Routes // routes carry no secrets
	return view
}
```

(Verify `config.Peer` field names — `Auth *PeerAuth{Username, Password}`, `Address`, `Transport`, `SRTP`, `Register`. Adjust the bespoke map to the real field set; the invariant is: NO `password`/`password_hash` value ever appears verbatim.)

- [ ] **Step 4: Run to verify pass** — `go test ./admin/ -race -v` → PASS (all api + redact + the Task-3 auth tests). `gofmt`/`vet`/`build` clean.

- [ ] **Step 5: Commit**

```bash
git add admin/api.go admin/redact.go admin/server.go admin/api_test.go admin/redact_test.go
git commit -m "feat(admin): read-only status/calls/peers/config JSON handlers with secret redaction"
```

---

### Task 5: `admin/metrics.go` — Prometheus collector

**Files:** Create `admin/metrics.go`; Test `admin/metrics_test.go`. Modify `admin/server.go` only to delete the `handleMetrics` stub.

**Interfaces:**
- Consumes: `Deps` (Task 3); `github.com/prometheus/client_golang/prometheus`, `.../promhttp`, `.../collectors`.
- Produces: a custom `collector` implementing `prometheus.Collector` over `Deps`; the real `handleMetrics` serving a private registry.

- [ ] **Step 1: Write the failing test** — `admin/metrics_test.go`:

```go
func TestMetricsExposition(t *testing.T) {
	// deps with known values
	s := testServerWithMetrics(t, /*activeCalls*/ 3, /*ports*/ 2, 4,
		[]PeerStatus{{Name: "carrier", Register: true, Registered: true}},
		ShieldStats{BannedCurrent: 5, DropsByReason: map[string]int64{"rate": 7, "scanner": 0, "banned": 0}})
	body := authGET(t, s, "/metrics")
	str := string(body)
	for _, want := range []string{
		"freesbc_active_calls 3",
		"freesbc_media_ports_in_use 2",
		"freesbc_media_ports_total 4",
		`freesbc_peer_registered{peer="carrier"} 1`,
		"freesbc_shield_banned_current 5",
		`freesbc_shield_drops_total{reason="rate"} 7`,
	} {
		if !strings.Contains(str, want) {
			t.Errorf("/metrics missing %q\n---\n%s", want, str)
		}
	}
}
```

Write `testServerWithMetrics` overriding the relevant `Deps` funcs.

- [ ] **Step 2: Run to verify fail** — `go test ./admin/ -run TestMetrics -v` → FAIL.

- [ ] **Step 3: Implement `admin/metrics.go`** — remove the `handleMetrics` stub from server.go; add:

```go
package admin

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// collector samples the live Deps on each scrape — no duplicated state.
type collector struct {
	deps Deps
	// descriptors
	activeCalls   *prometheus.Desc
	portsInUse    *prometheus.Desc
	portsTotal    *prometheus.Desc
	peerReg       *prometheus.Desc
	bannedCurrent *prometheus.Desc
	dropsTotal    *prometheus.Desc
	buildInfo     *prometheus.Desc
}

func newCollector(deps Deps) *collector {
	return &collector{
		deps:          deps,
		activeCalls:   prometheus.NewDesc("freesbc_active_calls", "Currently active bridged calls.", nil, nil),
		portsInUse:    prometheus.NewDesc("freesbc_media_ports_in_use", "RTP port pairs in use.", nil, nil),
		portsTotal:    prometheus.NewDesc("freesbc_media_ports_total", "RTP port pairs the range can hold.", nil, nil),
		peerReg:       prometheus.NewDesc("freesbc_peer_registered", "1 if a register:true peer is currently registered.", []string{"peer"}, nil),
		bannedCurrent: prometheus.NewDesc("freesbc_shield_banned_current", "Sources currently in the shield ban table.", nil, nil),
		dropsTotal:    prometheus.NewDesc("freesbc_shield_drops_total", "Total shield drops by reason.", []string{"reason"}, nil),
		buildInfo:     prometheus.NewDesc("freesbc_build_info", "Build info; always 1.", []string{"version"}, nil),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.activeCalls
	ch <- c.portsInUse
	ch <- c.portsTotal
	ch <- c.peerReg
	ch <- c.bannedCurrent
	ch <- c.dropsTotal
	ch <- c.buildInfo
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	g := func(d *prometheus.Desc, v float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
	}
	g(c.activeCalls, float64(c.deps.ActiveCalls()))
	inUse, total := c.deps.Ports()
	g(c.portsInUse, float64(inUse))
	g(c.portsTotal, float64(total))
	for _, p := range c.deps.Peers() {
		if !p.Register {
			continue
		}
		v := 0.0
		if p.Registered {
			v = 1
		}
		g(c.peerReg, v, p.Name)
	}
	st := c.deps.Shield()
	g(c.bannedCurrent, float64(st.BannedCurrent))
	for reason, n := range st.DropsByReason {
		ch <- prometheus.MustNewConstMetric(c.dropsTotal, prometheus.CounterValue, float64(n), reason)
	}
	g(c.buildInfo, 1, c.deps.Version)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.registry().ServeHTTP(w, r)
}

// registry builds the private Prometheus registry on first use (Go runtime
// metrics + the freesbc collector) and returns an http.Handler for it.
func (s *Server) registry() http.Handler {
	s.metricsOnce.Do(func() {
		reg := prometheus.NewRegistry()
		reg.MustRegister(collectors.NewGoCollector())
		reg.MustRegister(newCollector(s.deps))
		s.metricsHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	})
	return s.metricsHandler
}
```

Add `metricsOnce sync.Once` and `metricsHandler http.Handler` fields to `Server` (in server.go), and `"sync"` to its imports. Removing the `handleMetrics` stub means all five stubs are now gone (the four api stubs went in Task 4) — also delete the now-unused `stub(w)` helper from server.go.

- [ ] **Step 4: Run to verify pass** — `go test ./admin/ -race -v` → PASS (metrics exposition + all prior admin tests). `gofmt`/`vet`/`build` clean (no unused `stub`).

- [ ] **Step 5: Commit**

```bash
git add admin/metrics.go admin/metrics_test.go admin/server.go
git commit -m "feat(admin): Prometheus collector over live seams behind auth"
```

---

### Task 6: wire the admin server into `main.go`

**Files:** Modify `main.go`; Test: a build + smoke (admin is exercised by unit tests; main wiring is verified by build + a manual smoke).

**Interfaces:**
- Consumes: `admin.New`, `admin.Server.Run`, `admin.Deps`/`PeerStatus`/`ShieldStats`; `sig.Server.{ActiveCalls,IsRegistered,ShieldStats}`, `registry`/`pool` seams.

- [ ] **Step 1: Add a version var** — in `main.go`, package level: `var version = "dev"` (overridable via `-ldflags "-X main.version=…"`).

- [ ] **Step 2: Build Deps + run the admin server** — in `run()`, after `sipServer` is constructed and started, before the final block:

```go
	if adminCfg := store.Current().Admin; adminCfg != nil {
		deps := admin.Deps{
			Calls:       sipServer.Calls, // registry.Snapshot exposed on Server (add if absent)
			ActiveCalls: sipServer.ActiveCalls,
			Ports:       pool.Stats,
			Shield: func() admin.ShieldStats {
				st := sipServer.ShieldStats()
				return admin.ShieldStats{BannedCurrent: st.BannedCurrent, DropsByReason: st.DropsByReason}
			},
			Peers: func() []admin.PeerStatus {
				cfg := store.Current()
				out := make([]admin.PeerStatus, 0, len(cfg.Peers))
				for name, p := range cfg.Peers {
					out = append(out, admin.PeerStatus{
						Name: name, Address: p.Address, Transport: p.Transport, SRTP: p.SRTP,
						Register: p.Register, Registered: sipServer.IsRegistered(name),
					})
				}
				return out
			},
			Version: version,
		}
		adminSrv := admin.New(adminCfg, store, deps, log)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := adminSrv.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("admin server exited", "err", err)
				stop() // fatal bind error tears the process down (like the SIP listener)
			}
		}()
	}
```

`sipServer.Calls` is the `func() []callstate.Call` accessor added in Task 2. Match the exact `stop`/`ctx`/`wg`/`log` names already in `run()` (verify them; the run group uses a shared `ctx` and a `stop` cancel func).

- [ ] **Step 3: Build + smoke** — `go build ./...`. Then a manual smoke: run with an admin block (a real bcrypt hash), curl `/healthz` (200 no auth), `/api/status` (401 without creds, 200 with), `/metrics` (401 without creds, 200 with). Document the smoke commands + output in the report.

- [ ] **Step 4: Full race suite** — `go test ./... -race` → green (main isn't unit-tested, but nothing regresses).

- [ ] **Step 5: Commit**

```bash
git add main.go
git commit -m "feat(main): run the admin server when configured, wired to sig/media seams"
```

---

### Task 7: README + example config + verification

**Files:** Modify `README.md`, `sbc.example.yaml`.

- [ ] **Step 1: Roadmap** — in `README.md`, add M7 sub-rows (M7.1 done, M7.2/M7.3 pending). If M7 is a single row, split it like M3/M4:

```
| M7 | Operability: admin API, metrics, embedded WebUI | in progress |
| ├ M7.1 | Admin API + Prometheus metrics (read-only) | ✅ done |
| ├ M7.2 | Config write-back (PUT /api/config) | next |
| └ M7.3 | Embedded WebUI | |
```

- [ ] **Step 2: Example config** — in `sbc.example.yaml`, ensure the `admin` block is documented (it's currently optional/absent). Add a commented example:

```yaml
# admin:                          # optional operator API + Prometheus /metrics (bcrypt Basic Auth)
#   listen: 127.0.0.1:8080        # bind PRIVATE — no TLS on this listener
#   auth:
#     username: admin
#     password_hash: "$2a$10$..." # bcrypt hash; generate with: htpasswd -bnBC 10 "" secret | tr -d ':\n'
```

- [ ] **Step 3: gofmt / vet / build** — `gofmt -l . && go vet ./... && go build ./...` → clean.

- [ ] **Step 4: Full race suite** — `go test ./... -race -count=1` → `ok` for admin, config, media, callstate, shield, sig.

- [ ] **Step 5: Config smoke** — `go build -o /tmp/freesbc-m71 . && CARRIER_A_PASS=x /tmp/freesbc-m71 check -c sbc.example.yaml` → `config OK`.

- [ ] **Step 6: Commit**

```bash
git add README.md sbc.example.yaml
git commit -m "docs: mark M7.1 (admin API + metrics) done, M7.2 next"
```

---

## Notes for the implementer

- **`admin` never imports `sig`.** It defines `Deps`/`PeerStatus`/`ShieldStats`; `main` builds them from `sig.Server` accessors + `store`. A `sig` import in `admin` is a design violation.
- **Redaction is a whitelist, applied to a copy/bespoke view.** No secret value (`peers.*.auth.password`, `admin.auth.password_hash`) may appear verbatim in `/api/config`. The test asserts the real secret string is absent — keep that assertion.
- **Auth: evaluate both checks before deciding.** Compute `userOK` (constant-time) and `passOK` (bcrypt) unconditionally, then 401 on either failure with an identical response — no user enumeration, no short-circuit timing oracle. `/healthz` is the only unauthenticated route.
- **Metrics are scrape-time gauges over live seams** (no per-event wiring on the SIP/media hot path); the only event counters are the shield's three atomic drop counters. Use a **private** registry, not the global default.
- **Admin is optional and bind-failure is fatal.** No `admin:` block → no server. A bind failure calls `stop()` (process teardown), like the SIP listener.
- **Deferred (do NOT implement):** kick-call, `PUT /api/config` write-back, WebUI, CDR, per-call detail, login rate-limiting, admin-listener TLS, hot-reload of listen/creds, raw-YAML config view.
```
