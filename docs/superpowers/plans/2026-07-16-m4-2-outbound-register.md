# FreeSBC M4.2 — Outbound REGISTER Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** FreeSBC registers one trunk account per `register: true` peer to registration-based carriers (digest, granted-Expires refresh, backoff), exposes `IsRegistered`, skips unregistered peers as outbound targets, reconciles on hot reload, and un-REGISTERs on shutdown.

**Architecture:** A `Registrar` in the `sig` package: a manager goroutine reconciles the set of active registrations against config (via a new `Store.Subscribe` notify channel), one goroutine per registered peer runs the register→refresh→backoff lifecycle using sipgo's client REGISTER + digest primitives (no dialog), and the bridge consults `IsRegistered` in its failover loop. Contained to `config` + `sig`; the Registrar lives inside `Server.Run` (already in the shutdown WaitGroup).

**Tech Stack:** existing deps (sipgo v1.4.3, config/sig, Go stdlib). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-16-m4-2-outbound-register-design.md`. Second of four M4 slices (M4.1 done; M4.3 session timers + PRACK, M4.4 DNS SRV + peer health follow).

## Global Constraints

- Module `github.com/freesbc/freesbc`, Go ≥ 1.22. No new dependencies. English code/comments; stdlib testing only; `gofmt -l .` clean; final task runs `go vet ./... && go test ./... -race`.
- Config lifecycle (M1): read snapshots via `(*config.Store).Current()`; never mutate a published `*config.Config`.
- Scope: the SBC registers ITSELF (one trunk account per peer). Not REGISTER forwarding.
- Registration gates routing: an unregistered `register: true` peer is skipped as an outbound target; if no target is dialable → 503. A peer without `register: true` is always available.
- Refresh at ~0.9 × the GRANTED Expires (floor ≥ 10s). Backoff exponential 5s→cap 60s, reset on success. Shutdown un-REGISTERs (Expires: 0), bounded ~2s total.
- sipgo v1.4.3 REGISTER mechanism (verified; re-verify per task, BLOCK if materially different):
  - `sip.NewRequest(sip.REGISTER, registrarURI)` where `registrarURI = sip.Uri{Scheme:"sip", Host:<peer address host>, Port:<port>}` (its `User` is cleared by the build step).
  - Set `From`/`To` to the AOR (`sip:<auth.username>@<registrar host>`, From with a fresh tag), a `Contact` (`sip:<ourIP>:<ourSigPort>;transport=...`), and an `ExpiresHeader` (`*sip.ExpiresHeader`, a `uint32`), before calling `sipgo.ClientRequestRegisterBuild(client, req)` (fills CSeq/Call-ID/Via/Max-Forwards; increments CSeq on reuse).
  - `res, err := client.Do(ctx, req)`; on `res.StatusCode == 401 || 407` → `res, err = client.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username, Password})` (returns the final response).
  - Granted Expires: read the response `Expires` header (`res.GetHeader("Expires")` → parse `.Value()` as int), else the Contact header's `expires` param, else fall back to the requested value.
  - `Client`/`ourIP`/`ourSigPort`: the `Registrar` is built inside `Server.Run` where the sipgo `Client` exists, and reuses the M4.1 `Server.ourIP`/`ourSigPort` helpers (same package).

---

### Task 1: Config — `register_expires` (global + per-peer)

**Files:**
- Modify: `config/schema.go` (Config, Peer, withDefaults), `config/validate.go`
- Modify: `sbc.example.yaml`
- Test: `config/schema_test.go`, `config/validate_test.go`

**Interfaces:**
- Consumes: `config.Duration`, `Config`, `Peer`, `withDefaults`, `validate`.
- Produces: `Config.RegisterExpires Duration` (yaml `register_expires`, default 3600s, > 0); `Peer.RegisterExpires Duration` (yaml `register_expires`, optional; if set, > 0). Task 5 reads the effective value (per-peer override else global).

- [ ] **Step 1: Write the failing tests**

Add to `TestWithDefaults` in `config/schema_test.go`:

```go
	if c.RegisterExpires.Std() != 3600*time.Second {
		t.Errorf("register_expires default: %v", c.RegisterExpires.Std())
	}
```

Add to the `cases` table in `TestValidateErrors` in `config/validate_test.go`:

```go
		{"negative register_expires", func(c *Config) { c.RegisterExpires = Duration(-time.Second) }, "register_expires"},
		{"peer register_expires negative", func(c *Config) {
			c.Peers["pbx"].RegisterExpires = Duration(-time.Second)
		}, "register_expires"},
```

Add a parse round-trip to `config/schema_test.go`:

```go
func TestParseRegisterExpires(t *testing.T) {
	src := minimalYAML + "register_expires: 1200s\n"
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.RegisterExpires.Std() != 1200*time.Second {
		t.Errorf("register_expires = %v, want 1200s", c.RegisterExpires.Std())
	}
}
```

(`minimalYAML` is in `config/loader_test.go`, same package.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/ -run 'TestWithDefaults|TestValidateErrors|TestParseRegisterExpires' -v`
Expected: FAIL (compile error: `RegisterExpires` undefined).

- [ ] **Step 3: Implement**

In `config/schema.go`, add to `Config` (after `RingTimeout`):

```go
	RegisterExpires Duration `yaml:"register_expires"` // requested REGISTER lifetime (carrier may grant less)
```

Add to `Peer` (after `MediaLatch`):

```go
	// RegisterExpires overrides the global register_expires for this peer
	// (0 = use the global default). Only meaningful with register: true.
	RegisterExpires Duration `yaml:"register_expires"`
```

In `withDefaults`, add:

```go
	if c.RegisterExpires == 0 {
		c.RegisterExpires = Duration(3600 * time.Second)
	}
```

In `config/validate.go`, after the `ring_timeout` check:

```go
	if c.RegisterExpires.Std() <= 0 {
		fail("register_expires: must be > 0, got %v", c.RegisterExpires.Std())
	}
```

and inside the (sorted) peers loop, after the `media_latch` check:

```go
		if p.RegisterExpires != 0 && p.RegisterExpires.Std() <= 0 {
			fail("peers.%s: register_expires must be > 0 when set", name)
		}
```

In `sbc.example.yaml`, add near `ring_timeout`:

```yaml
register_expires: 3600s   # requested REGISTER lifetime for register:true peers (carrier may grant less)
```

- [ ] **Step 4: Run the config suite**

Run: `go test ./config/ -v && go build -o freesbc . && CARRIER_A_PASS=test ./freesbc check -c sbc.example.yaml`
Expected: PASS; `sbc.example.yaml: config OK`.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ sbc.example.yaml && git commit -m "feat(config): register_expires (global + per-peer override)"
```

---

### Task 2: Config — `Store.Subscribe` notify channel

**Files:**
- Modify: `config/store.go`
- Test: `config/store_test.go`

**Interfaces:**
- Consumes: existing `Store`, `Replace`, `Current`.
- Produces (Task 5 relies on this): `func (s *Store) Subscribe() <-chan struct{}` — a buffered(1), coalescing channel that receives a signal on each `Replace`. `Current`/reads stay lock-free.

- [ ] **Step 1: Write the failing test**

Add to `config/store_test.go`:

```go
func TestStoreSubscribeNotifiesOnReplace(t *testing.T) {
	s := NewStore(validConfig())
	ch := s.Subscribe()
	select {
	case <-ch:
		t.Fatal("should not fire before any Replace")
	default:
	}
	s.Replace(validConfig())
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("Subscribe did not fire on Replace")
	}
}

func TestStoreSubscribeCoalesces(t *testing.T) {
	s := NewStore(validConfig())
	ch := s.Subscribe()
	for i := 0; i < 5; i++ {
		s.Replace(validConfig())
	}
	// Buffered(1) + non-blocking send: at least one signal, never a block.
	got := 0
	for {
		select {
		case <-ch:
			got++
		default:
			if got < 1 {
				t.Fatal("expected at least one coalesced signal")
			}
			return
		}
	}
}

func TestStoreReplaceNeverBlocksWithSlowSubscriber(t *testing.T) {
	s := NewStore(validConfig())
	_ = s.Subscribe() // never drained
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			s.Replace(validConfig())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Replace blocked on an undrained subscriber")
	}
}
```

(`config/store_test.go` needs `time` imported; `validConfig()` is the existing helper.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run TestStoreSubscribe -v`
Expected: FAIL (compile error: `Subscribe` undefined).

- [ ] **Step 3: Implement**

Rewrite `config/store.go`:

```go
package config

import (
	"sync"
	"sync/atomic"
)

// Store publishes immutable *Config snapshots. Readers call Current and use
// that snapshot for the lifetime of one call/request (lock-free). The
// hot-reload path calls Replace, which also notifies Subscribe listeners.
type Store struct {
	p atomic.Pointer[Config]

	mu   sync.Mutex
	subs []chan struct{}
}

func NewStore(c *Config) *Store {
	s := &Store{}
	s.p.Store(c)
	return s
}

// Current returns the active config snapshot. Never nil. Lock-free.
func (s *Store) Current() *Config { return s.p.Load() }

// Replace atomically swaps in a new validated config and coalescing-notifies
// every Subscribe listener. In-flight calls keep the snapshot they hold.
func (s *Store) Replace(c *Config) {
	s.p.Store(c)
	s.mu.Lock()
	for _, ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default: // already has a pending signal — coalesce
		}
	}
	s.mu.Unlock()
}

// Subscribe returns a channel that receives a signal on each Replace. The
// channel is buffered(1) and sends are non-blocking, so a slow subscriber
// coalesces bursts and never blocks Replace. Intended for a long-lived
// reconciler (e.g. the registrar); there is no unsubscribe.
func (s *Store) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	return ch
}
```

- [ ] **Step 4: Run tests to verify they pass (race on)**

Run: `go test ./config/ -race -v`
Expected: PASS (all config tests, no races).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ && git commit -m "feat(config): Store.Subscribe coalescing reload notifications"
```

---

### Task 3: `registerOnce` — a single REGISTER exchange + stub-registrar harness

**Files:**
- Create: `sig/register.go`
- Test: `sig/register_test.go`

**Interfaces:**
- Consumes: `sipgo.Client`, `sipgo.ClientRequestRegisterBuild`, `client.Do`, `client.DoDigestAuth`, `sipgo.DigestAuth`, `sip.NewRequest`, `sip.ExpiresHeader`; `netip.Addr`.
- Produces (Task 4 relies on this):
  - `type regParams struct{ Name, RegistrarHost string; RegistrarPort int; Transport, Username, Password string; ContactIP netip.Addr; ContactPort int }`
  - `func registerOnce(ctx context.Context, client *sipgo.Client, p regParams, expires time.Duration) (granted time.Duration, err error)` — sends one REGISTER for `p` requesting `expires` (0 = un-REGISTER); returns the granted lifetime on 200, or an error.

- [ ] **Step 1: Verify the sipgo REGISTER build path**

Read `github.com/emiago/sipgo` in the module cache: `ClientRequestRegisterBuild`, `DoDigestAuth`, `DigestAuth`, and how to read an `Expires` header off a response (`res.GetHeader("Expires")` → `*sip.ExpiresHeader` or its `.Value()`). Confirm the plan's build order (set From/To/Contact/Expires, then `ClientRequestRegisterBuild`, then `Do`) compiles and produces a valid REGISTER. Note any adaptation; BLOCK only if REGISTER + digest can't be expressed.

- [ ] **Step 2: Write the failing test (with the stub registrar)**

Create `sig/register_test.go`. Build a **stub registrar UAS** (a sipgo server that answers REGISTER: first with 401 + a WWW-Authenticate challenge, then 200 with an `Expires` header once an Authorization is present) and capture what it received. Then test one `registerOnce` exchange:

```go
package sig

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestRegisterOnceSucceedsWithDigest(t *testing.T) {
	reg := startStubRegistrar(t, 45320, "reguser", "regpass", 1800) // grants 1800s
	client := reg.client(t)                                          // a sipgo client bound to loopback
	p := regParams{
		Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45320,
		Transport: "udp", Username: "reguser", Password: "regpass",
		ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45999,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	granted, err := registerOnce(ctx, client, p, time.Hour)
	if err != nil {
		t.Fatalf("registerOnce: %v", err)
	}
	if granted != 1800*time.Second {
		t.Errorf("granted = %v, want 1800s", granted)
	}
	if !reg.sawAuthorizedRegister() {
		t.Error("registrar never received an authorized REGISTER")
	}
}

func TestRegisterOnceBadCredentialsFails(t *testing.T) {
	reg := startStubRegistrar(t, 45322, "reguser", "rightpass", 1800)
	client := reg.client(t)
	p := regParams{
		Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45322,
		Transport: "udp", Username: "reguser", Password: "WRONGpass",
		ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45998,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := registerOnce(ctx, client, p, time.Hour); err == nil {
		t.Fatal("expected error for wrong password")
	}
}
```

Write the complete `startStubRegistrar` helper (a sipgo UA/Server with an `OnRegister`-style handler using `srv.OnRequest(sip.REGISTER, ...)`, digest challenge/verify via the sipgo/`icholy/digest` primitives already used in the M4.1 digest-auth test harness, an `Expires` header on the 200) and the `client`/`sawAuthorizedRegister`/`sawUnregister` accessors — no placeholders. Ports 45320–45339. Timing-based — re-run once before treating a flake as failure.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./sig/ -run TestRegisterOnce -v`
Expected: FAIL (compile error: `registerOnce`/`regParams`/`startStubRegistrar` undefined).

- [ ] **Step 4: Implement `registerOnce`**

Create `sig/register.go` (adapt the sipgo calls to the Step 1 findings):

```go
package sig

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// regParams is the immutable identity of one peer's registration.
type regParams struct {
	Name          string
	RegistrarHost string
	RegistrarPort int
	Transport     string
	Username      string
	Password      string
	ContactIP     netip.Addr
	ContactPort   int
}

// registerOnce performs a single REGISTER exchange for p, requesting the
// given expires (0 = un-REGISTER). It handles a 401/407 digest challenge and
// returns the lifetime the registrar granted, or an error.
func registerOnce(ctx context.Context, client *sipgo.Client, p regParams, expires time.Duration) (time.Duration, error) {
	registrar := sip.Uri{Scheme: "sip", Host: p.RegistrarHost, Port: p.RegistrarPort}
	req := sip.NewRequest(sip.REGISTER, registrar)

	aor := sip.Uri{Scheme: "sip", User: p.Username, Host: p.RegistrarHost}
	req.AppendHeader(&sip.FromHeader{Address: aor, Params: newTagParams()})
	req.AppendHeader(&sip.ToHeader{Address: aor, Params: sip.NewParams()})

	contact := sip.Uri{Scheme: "sip", Host: p.ContactIP.String(), Port: p.ContactPort}
	if p.Transport != "" && p.Transport != "udp" {
		contact.UriParams = sip.NewParams()
		contact.UriParams.Add("transport", p.Transport)
	}
	req.AppendHeader(&sip.ContactHeader{Address: contact})

	exp := sip.ExpiresHeader(uint32(expires.Seconds()))
	req.AppendHeader(&exp)

	if err := sipgo.ClientRequestRegisterBuild(client, req); err != nil {
		return 0, fmt.Errorf("build register: %w", err)
	}

	res, err := client.Do(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("register: %w", err)
	}
	if res.StatusCode == sip.StatusUnauthorized || res.StatusCode == sip.StatusProxyAuthRequired {
		res, err = client.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: p.Username, Password: p.Password})
		if err != nil {
			return 0, fmt.Errorf("register digest: %w", err)
		}
	}
	if res.StatusCode != sip.StatusOK {
		return 0, fmt.Errorf("register rejected: %d %s", res.StatusCode, res.Reason)
	}
	return grantedExpires(res, expires), nil
}

// grantedExpires reads the lifetime the registrar granted: the Expires
// header if present, else the Contact expires param, else the requested value.
func grantedExpires(res *sip.Response, requested time.Duration) time.Duration {
	if h := res.GetHeader("Expires"); h != nil {
		if n, err := strconv.Atoi(h.Value()); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	if c := res.Contact(); c != nil {
		if v, ok := c.Params.Get("expires"); ok {
			if n, err := strconv.Atoi(v); err == nil {
				return time.Duration(n) * time.Second
			}
		}
	}
	return requested
}

// newTagParams returns header params carrying a fresh From tag (reuses the
// bridge's freshTag).
func newTagParams() sip.HeaderParams {
	pr := sip.NewParams()
	pr.Add("tag", freshTag())
	return pr
}
```

(Adapt `sip.NewParams()`/`HeaderParams` and the `Expires`-header read to the exact sipgo API confirmed in Step 1; `freshTag` is the M4.1 helper in `sig/b2bua.go`.)

- [ ] **Step 5: Run tests to verify they pass (race on)**

Run: `go test ./sig/ -run TestRegisterOnce -race -v`
Expected: PASS (digest register succeeds, granted expires read; wrong password errors).

- [ ] **Step 6: Commit**

```bash
gofmt -l . && git add sig/register.go sig/register_test.go && git commit -m "feat(sig): single REGISTER exchange with digest and granted-expires parsing"
```

---

### Task 4: Per-peer registration lifecycle

**Files:**
- Modify: `sig/register.go`
- Test: `sig/register_test.go`

**Interfaces:**
- Consumes: `registerOnce`, `regParams` (Task 3).
- Produces (Task 5 relies on these):
  - `type registration struct{ client *sipgo.Client; params regParams; setRegistered func(name string, ok bool); log *slog.Logger }`
  - `func (rg *registration) run(ctx context.Context, requested time.Duration)` — blocks: register → mark registered → schedule refresh at ~0.9×granted (floor 10s) → refresh; on any failure mark unregistered + exponential backoff (5s→60s, reset on success); on ctx cancel → best-effort un-REGISTER (Expires 0, bounded) then return.
  - `func (rg *registration) unregister()` — best-effort Expires:0 REGISTER, bounded, marks the peer unregistered.
  - constants `regBackoffMin = 5s`, `regBackoffMax = 60s`, `regRefreshFloor = 10s`.

- [ ] **Step 1: Write the failing test**

Add to `sig/register_test.go`:

```go
func TestRegistrationRunRefreshesAndUnregisters(t *testing.T) {
	// Grant a short 2s lifetime so a refresh (at ~0.9×2s≈floor 10s? no —
	// use the floor path: refresh floor is 10s, so grant a longer lifetime
	// and instead assert the FIRST register + a clean un-register on cancel).
	reg := startStubRegistrar(t, 45324, "u", "p", 60)
	client := reg.client(t)
	var mu sync.Mutex
	states := map[string]bool{}
	set := func(name string, ok bool) { mu.Lock(); states[name] = ok; mu.Unlock() }
	rg := &registration{
		params: regParams{
			Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45324,
			Transport: "udp", Username: "u", Password: "p",
			ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45997,
		},
		setRegistered: set,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rg.run(ctx, time.Hour); close(done) }()
	// Wait until registered.
	waitFor(t, 3*time.Second, func() bool { mu.Lock(); defer mu.Unlock(); return states["carrier"] })
	if !reg.sawAuthorizedRegister() {
		t.Fatal("registrar saw no authorized REGISTER")
	}
	// Cancel → un-REGISTER (Expires 0).
	cancel()
	<-done
	waitFor(t, 3*time.Second, reg.sawUnregister)
	mu.Lock()
	if states["carrier"] {
		t.Error("registration should be marked unregistered after cancel")
	}
	mu.Unlock()
}

func TestRegistrationRunBacksOffOnFailure(t *testing.T) {
	// No registrar listening on this port → every register fails; the loop
	// must mark unregistered and keep retrying (not spin, not exit).
	client := loopbackClient(t) // a client with nothing to talk to at 45326
	set := func(string, bool) {}
	rg := &registration{
		params: regParams{
			Name: "dead", RegistrarHost: "127.0.0.1", RegistrarPort: 45326,
			Transport: "udp", Username: "u", Password: "p",
			ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45996,
		},
		setRegistered: set,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { rg.run(ctx, time.Hour); close(done) }()
	select {
	case <-done: // returns when ctx expires — must not spin-exit early
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after ctx cancel")
	}
}
```

Add a `waitFor` helper if one isn't already shared in the `sig` test files (poll-with-timeout), and a `loopbackClient` helper (a sipgo client with no reachable registrar). Reuse `startStubRegistrar` from Task 3.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestRegistrationRun -v`
Expected: FAIL (compile error: `registration`/`run` undefined).

- [ ] **Step 3: Implement the lifecycle**

Append to `sig/register.go`:

```go
const (
	regBackoffMin   = 5 * time.Second
	regBackoffMax   = 60 * time.Second
	regRefreshFloor = 10 * time.Second
)

// registration runs one peer's register→refresh→backoff loop.
type registration struct {
	client        *sipgo.Client
	params        regParams
	setRegistered func(name string, ok bool)
	log           *slog.Logger
}

// run blocks until ctx is cancelled, keeping the peer registered: it
// registers, marks the peer registered, refreshes at ~0.9×granted (floor
// regRefreshFloor), and on any failure marks it unregistered and retries
// with exponential backoff. On ctx cancel it best-effort un-REGISTERs.
func (rg *registration) run(ctx context.Context, requested time.Duration) {
	backoff := regBackoffMin
	for {
		granted, err := registerOnce(ctx, rg.client, rg.params, requested)
		if ctx.Err() != nil {
			break
		}
		var wait time.Duration
		if err != nil {
			rg.setRegistered(rg.params.Name, false)
			rg.log.Warn("register failed", "peer", rg.params.Name, "err", err, "retry_in", backoff)
			wait = backoff
			if backoff *= 2; backoff > regBackoffMax {
				backoff = regBackoffMax
			}
		} else {
			rg.setRegistered(rg.params.Name, true)
			backoff = regBackoffMin
			wait = time.Duration(float64(granted) * 0.9)
			if wait < regRefreshFloor {
				wait = regRefreshFloor
			}
			rg.log.Info("registered", "peer", rg.params.Name, "granted", granted, "refresh_in", wait)
		}
		select {
		case <-ctx.Done():
			rg.unregister()
			return
		case <-time.After(wait):
		}
	}
	rg.unregister()
}

// unregister sends a best-effort Expires:0 REGISTER, bounded, and marks the
// peer unregistered.
func (rg *registration) unregister() {
	rg.setRegistered(rg.params.Name, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := registerOnce(ctx, rg.client, rg.params, 0); err != nil {
		rg.log.Debug("un-register failed", "peer", rg.params.Name, "err", err)
	}
}
```

Add `"log/slog"` to the imports. The test constructs `registration` with `client`, `params`, `setRegistered`, and a discard `log` — adjust the test's struct literal to include `client: client` and `log: slog.New(slog.NewTextHandler(io.Discard, nil))`.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -run 'TestRegistration|TestRegisterOnce' -race -v`
Expected: PASS (registers, un-registers on cancel, backs off on failure). Timing-based — re-run once before flake.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/register.go sig/register_test.go && git commit -m "feat(sig): per-peer registration lifecycle (refresh, backoff, un-register)"
```

---

### Task 5: `Registrar` manager — reconcile, `IsRegistered`, startup, shutdown

**Files:**
- Modify: `sig/register.go`
- Test: `sig/register_test.go`

**Interfaces:**
- Consumes: `registration`, `regParams` (Tasks 3–4), `config.Store.Subscribe`/`Current`, `sipgo.Client`, `Server.ourIP`/`ourSigPort`.
- Produces (Task 6 relies on these):
  - `func NewRegistrar(store *config.Store, client *sipgo.Client, srv *Server, log *slog.Logger) *Registrar`
  - `func (r *Registrar) IsRegistered(name string) bool` — lock-free-ish read; a non-`register:true` peer returns true (always available); an unknown/unregistered `register:true` peer returns false.
  - `func (r *Registrar) Run(ctx context.Context) error` — reconcile once at startup, then on each `store.Subscribe()` fire; on ctx cancel, stop all per-peer goroutines (each un-REGISTERs) and return after they finish (bounded by the per-peer 2s un-register).

- [ ] **Step 1: Write the failing test**

Add to `sig/register_test.go`:

```go
func TestRegistrarReconcilesAndReportsRegistered(t *testing.T) {
	reg := startStubRegistrar(t, 45330, "u", "p", 120)
	// Config with one register:true peer pointing at the stub registrar.
	store := registrarTestStore(t, 45330, "u", "p") // helper builds the config
	client := reg.client(t)
	srv := serverForRegistrar(t, store) // minimal Server exposing ourIP/ourSigPort
	r := NewRegistrar(store, client, srv, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = r.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return r.IsRegistered("carrier") })
	// A non-register peer is always available.
	if !r.IsRegistered("internal-pbx") {
		t.Error("a non-register:true peer must report available")
	}
	cancel()
	waitFor(t, 3*time.Second, reg.sawUnregister)
}

func TestRegistrarHotReloadStopsRemovedPeer(t *testing.T) {
	reg := startStubRegistrar(t, 45332, "u", "p", 120)
	store := registrarTestStore(t, 45332, "u", "p")
	client := reg.client(t)
	srv := serverForRegistrar(t, store)
	r := NewRegistrar(store, client, srv, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return r.IsRegistered("carrier") })
	// Hot-reload: flip carrier to register:false → un-REGISTER + stop.
	store.Replace(withCarrierRegisterFalse(t)) // helper returns a modified config
	waitFor(t, 3*time.Second, func() bool { return !r.IsRegistered("carrier") })
	waitFor(t, 3*time.Second, reg.sawUnregister)
}
```

Write the helpers (`registrarTestStore`, `serverForRegistrar`, `withCarrierRegisterFalse`, `discardLogger`) — complete, no placeholders. `serverForRegistrar` builds the minimal `*Server` needed for `ourIP`/`ourSigPort` (a store with a `public_ip` literal + a udp listener).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestRegistrar -v`
Expected: FAIL (compile error: `NewRegistrar`/`IsRegistered`/`Run` undefined).

- [ ] **Step 3: Implement the manager**

Append to `sig/register.go`:

```go
// Registrar manages outbound REGISTER for all register:true peers: one
// registration goroutine per peer, reconciled against config on hot reload.
type Registrar struct {
	store  *config.Store
	client *sipgo.Client
	srv    *Server
	log    *slog.Logger

	mu       sync.RWMutex
	state    map[string]bool                   // peer name → registered
	running  map[string]*runningReg            // peer name → active goroutine handle
}

type runningReg struct {
	params regParams
	cancel context.CancelFunc
	done   chan struct{}
}

func NewRegistrar(store *config.Store, client *sipgo.Client, srv *Server, log *slog.Logger) *Registrar {
	return &Registrar{
		store: store, client: client, srv: srv, log: log,
		state: map[string]bool{}, running: map[string]*runningReg{},
	}
}

// IsRegistered reports whether the bridge may route to this peer now. A peer
// without register:true is always available; a register:true peer is
// available only while its registration is live.
func (r *Registrar) IsRegistered(name string) bool {
	cfg := r.store.Current()
	p := cfg.Peers[name]
	if p == nil || !p.Register {
		return true
	}
	r.mu.RLock()
	ok := r.state[name]
	r.mu.RUnlock()
	return ok
}

func (r *Registrar) setRegistered(name string, ok bool) {
	r.mu.Lock()
	r.state[name] = ok
	r.mu.Unlock()
}

// Run reconciles registrations against config until ctx is cancelled, then
// stops every peer goroutine (each un-REGISTERs) and returns once they exit.
func (r *Registrar) Run(ctx context.Context) error {
	sub := r.store.Subscribe()
	r.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			r.stopAll()
			return nil
		case <-sub:
			r.reconcile(ctx)
		}
	}
}

// reconcile diffs the desired register:true set against the running set.
func (r *Registrar) reconcile(ctx context.Context) {
	cfg := r.store.Current()
	desired := map[string]regParams{}
	for name, p := range cfg.Peers {
		if p.Register && p.Auth != nil {
			desired[name] = r.paramsFor(cfg, name, p)
		}
	}
	r.mu.Lock()
	// Stop removed or changed.
	for name, rr := range r.running {
		if d, ok := desired[name]; !ok || d != rr.params {
			rr.cancel()
			delete(r.running, name)
		}
	}
	// Start added or changed (re-added after the stop above).
	for name, d := range desired {
		if _, ok := r.running[name]; ok {
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		rg := &registration{client: r.client, params: d, setRegistered: r.setRegistered, log: r.log}
		requested := r.requestedExpires(cfg, name)
		go func() { rg.run(cctx, requested); close(done) }()
		r.running[name] = &runningReg{params: d, cancel: cancel, done: done}
	}
	r.mu.Unlock()
}

func (r *Registrar) stopAll() {
	r.mu.Lock()
	handles := make([]*runningReg, 0, len(r.running))
	for name, rr := range r.running {
		rr.cancel()
		handles = append(handles, rr)
		delete(r.running, name)
	}
	r.mu.Unlock()
	for _, rr := range handles {
		<-rr.done // each un-REGISTERs, bounded by the per-peer 2s
	}
}

// paramsFor builds the immutable regParams for a peer.
func (r *Registrar) paramsFor(cfg *config.Config, name string, p *config.Peer) regParams {
	host, port := splitHostPortDefault(p.Address, 5060)
	ourIP := r.srv.ourIP(cfg)
	return regParams{
		Name: name, RegistrarHost: host, RegistrarPort: port,
		Transport: p.Transport, Username: p.Auth.Username, Password: p.Auth.Password,
		ContactIP: ourIP, ContactPort: r.srv.ourSigPort(cfg, p.Transport),
	}
}

// requestedExpires returns the per-peer override or the global default.
func (r *Registrar) requestedExpires(cfg *config.Config, name string) time.Duration {
	if p := cfg.Peers[name]; p != nil && p.RegisterExpires != 0 {
		return p.RegisterExpires.Std()
	}
	return cfg.RegisterExpires.Std()
}
```

Add `"sync"`, `"github.com/freesbc/freesbc/config"` imports. Add a `splitHostPortDefault(addr string, defPort int) (string, int)` helper (parse `host:port`, default the port if absent) — put it in `sig/register.go` or reuse an existing sig helper if one exists (check `peerURI`/`ourSigPort` for an existing parse). Note: `regParams` must stay comparable (all fields comparable — `netip.Addr` is) so the `d != rr.params` change-detection works.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -run 'TestRegistrar|TestRegistration|TestRegisterOnce' -race -v`
Expected: PASS (reconcile registers a peer, IsRegistered reflects it, hot-reload stops a removed peer with un-REGISTER, non-register peers always available).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/register.go sig/register_test.go && git commit -m "feat(sig): Registrar manager — reconcile, IsRegistered, startup, shutdown"
```

---

### Task 6: Wire the Registrar into `Server.Run` + routing gate

**Files:**
- Modify: `sig/server.go` (construct/start/stop the Registrar in `Run`; `Server.registrar`)
- Modify: `sig/b2bua.go` (`placeCall` skips unregistered targets)
- Test: `sig/b2bua_test.go`

**Interfaces:**
- Consumes: `NewRegistrar`, `(*Registrar).Run`, `(*Registrar).IsRegistered` (Task 5).
- Produces: the running server registers all `register: true` peers and skips unregistered ones as outbound targets.

- [ ] **Step 1: Write the failing test**

Add to `sig/b2bua_test.go` a test that a `register: true` target which never registers is skipped, and the caller gets 503:

```go
func TestBridgeSkipsUnregisteredTarget(t *testing.T) {
	// A route whose only target is a register:true peer with NO reachable
	// registrar (so it never registers). An INVITE routed there must be
	// skipped (the peer's call address never receives the INVITE) and the
	// caller must get 503.
	// ... start the bridge server (which starts the Registrar) with a config
	//     where target "carrier" is register:true pointing at a dead
	//     registrar port; place a call; assert 503 and that nothing was
	//     dialed to carrier's call address ...
}
```

Write the complete test using the existing bridge harness. The key assertions: the caller's final response is 503, and a stub carrier at the peer's *call* address receives no INVITE (because the peer is unregistered → skipped). Fresh ports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestBridgeSkipsUnregisteredTarget -v`
Expected: FAIL — without the gate, the INVITE is dialed to the unregistered peer.

- [ ] **Step 3: Implement**

In `sig/server.go` `Run`, after building the sipgo `Client` and the dialog caches, construct and start the Registrar within the same lifecycle (it must stop and un-REGISTER before `Run` returns):

```go
	s.registrar = NewRegistrar(s.store, client, s, s.log)
	regDone := make(chan struct{})
	go func() { _ = s.registrar.Run(ctx); close(regDone) }()
	defer func() { <-regDone }() // wait for un-REGISTER on shutdown
```

Add `registrar *Registrar` to the `Server` struct. (The `ctx` here is `Run`'s context, cancelled on shutdown; the `defer` makes `Run` block on the registrar's clean stop, keeping shutdown ordered.)

In `sig/b2bua.go` `placeCall`, before dialing each target, skip an unregistered `register: true` peer:

```go
		if target.Peer.Register && b.s.registrar != nil && !b.s.registrar.IsRegistered(target.Name) {
			b.s.log.Debug("skipping unregistered target", "peer", target.Name)
			continue
		}
```

If the failover loop dials nothing (every target skipped) and there was no real failure/ring, `placeCall`'s existing exhaustion path already returns 503 when no `failReal`/`failRing` was recorded — confirm this holds (a fully-skipped loop records neither, so the exhaustion default is 503). If the current code would instead do something else on an all-skipped loop (e.g. panic on an empty result), add an explicit `if nothingDialed { aLeg.Respond(503, "Service Unavailable", nil); return }`.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -race -v`
Expected: PASS (unregistered target skipped → 503; all prior bridge tests — happy path, early media, failover, ring timeout, auth, 481/400 — still green).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): start Registrar in Run; skip unregistered peers as outbound targets"
```

---

### Task 7: Roadmap + full verification

**Files:**
- Modify: `README.md`
- Test: full-suite + CLI smoke

**Interfaces:**
- Consumes: everything above.
- Produces: M4.2 marked done; whole repo green.

- [ ] **Step 1: Update the README roadmap**

Mark M4.2 done and M4.3 next (change only these two sub-rows):

```markdown
| ├ M4.2 | Outbound REGISTER | ✅ done |
| ├ M4.3 | Session timers (RFC 4028) + 100rel/PRACK | next |
```

- [ ] **Step 2: Full verification + smoke**

```bash
go vet ./... && go test ./... -race
```

Expected: vet clean; all packages (config, media, sig, callstate) PASS.

```bash
go build -o freesbc . && CARRIER_A_PASS=test ./freesbc run -c sbc.example.yaml & PID=$!
sleep 1; kill -TERM $PID; wait $PID; echo "exit=$?"
```

Expected: startup logs (`media plane ready`, `sip server listening`, `freesbc started`) plus a register attempt for `carrier-a` (which will fail against the example's non-existent `sip.carrier-a.com` — a `register failed ... retry_in` log is expected and correct); clean `shutting down`; `exit=0`. (Use the scratchpad high-port copy if 5060/5061 are busy, per M3.1 Task 4's note.)

- [ ] **Step 3: Commit**

```bash
gofmt -l . && git add README.md && git commit -m "docs: mark M4.2 done in roadmap"
```

---

## Spec Coverage (M4.2)

| Spec section | Task |
|---|---|
| §1.1 SBC registers itself (per peer) | 3, 4, 5 |
| §1.2 routing gate (skip unregistered → 503) | 6 |
| §1.3 shutdown un-REGISTER | 4 (per-peer), 5 (stopAll), 6 (Run lifecycle) |
| §1.4 global + per-peer register_expires, refresh at 0.9×granted | 1, 4, 5 |
| §2 Store.Subscribe | 2 |
| §3 state machine (register/refresh/backoff/digest) | 3, 4 |
| §5 routing integration | 6 |
| §6 lifecycle (startup/reload/shutdown) | 5, 6 |
| §7 error handling (401/backoff/failure) | 3, 4 |
| §8 stub-registrar testing | 3, 4, 5, 6 |

Deferred (spec §9): session timers + PRACK (M4.3); DNS SRV + cross-call health/cooldown + configurable failover code (M4.4); REGISTER forwarding (non-goal); separate registrar host distinct from call address; per-peer CLI/PAI.

## Post-Implementation Amendments (2026-07-16, whole-branch review)

- **Shutdown sequencing** (Fix 1): the registrar now stops and un-REGISTERs *before* listener sockets close. sipgo pools the UDP listener connection under remotes it has heard from and reuses it for outbound requests, so a concurrent listener close was making the shutdown un-REGISTER fail (`net.ErrClosed`) against any carrier that had sent us traffic. Registrar and listeners now use separate contexts, cancelled in order.
- **Changed-peer restart serialized** (Fix 2): on a param change (e.g. credential rotation) the new registration goroutine waits for the old one's un-REGISTER (`Expires:0`) to finish before it registers, so the old goroutine can't wipe the carrier's fresh binding. The wait is inside the new goroutine (not under `reconcile`'s mutex — that would deadlock the old goroutine's state write).
- **`register_expires` floor** (Fix 3): validated `>= 1s` (global + per-peer) — a sub-second value truncated to `Expires: 0` (an un-register masquerading as a registration).

## Carry-over for M4.3/M4.4 (from whole-branch review)

- **423 Interval Too Brief** (M4.3/M4.4): a carrier's 423 is currently a generic backoff-retry with the same Expires, so a `register_expires` below the carrier's Min-Expires never registers. RFC 3261 §10.2.8 wants a retry with the Min-Expires from the 423. Handle when trunk-interop hardening lands.
- **Call-ID / CSeq continuity** (spec §3 deviation): each refresh is a fresh REGISTER (new Call-ID, random CSeq), not "same Call-ID, CSeq++" as the design's state machine describes. RFC 3261 §10.2.4 is a SHOULD and registrars tolerate it, but it deviates from spec §3 — either implement per-peer Call-ID/CSeq continuity or amend the spec text in a later pass.
- **`grantedExpires` first-Contact** (M4.4): reads the first Contact of the 200; a shared trunk account with multiple registered devices could read the wrong binding's expires. Correct fix: match our own Contact URI. Mitigated today by the Expires-header-first precedence.
- **Grace-until-expiry on transient refresh failure** (M4.4 health): one failed refresh gates the peer out of routing immediately even though the carrier-side binding is valid until its granted expiry; fold into M4.4's generalized peer health.
- **`stopAll` draining** (Minor): a peer stopped by an earlier reconcile just before shutdown isn't waited on by `stopAll`; its in-flight un-REGISTER can race `client.Close`. Best-effort; fold stopped-but-draining handles into the wait list if it matters.
