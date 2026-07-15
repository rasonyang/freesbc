# FreeSBC M3.2 — Routing Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pure, stateless routing engine in the `sig` package that, given an inbound peer name and a dialed number, selects the matching route (first `from`+`match` hit wins), applies the route's number transform, and resolves the ordered `to` list into failover candidates — the decision the M3.3 B2BUA consumes to place its B-leg. Plus a config fix so regexp capture-group references (`${1}`) in route transforms survive env expansion.

**Architecture:** Three pure functions with no I/O and no shared state. `matchRoute` walks `cfg.Routes` in order and returns the first route whose `From` equals the inbound peer and whose compiled `match.to` regex matches the number (a route with no `match` clause matches any number). `transformNumber` applies the route's `transform.to` as a regexp capture-group replacement (passthrough when there is no transform). `Resolve` composes both and resolves `route.To` names into an ordered `[]Target`, returning a `*Decision`. Everything operates on a `*config.Config` snapshot the caller already holds, so results are consistent within one call and pick up hot-reloaded routes on the next.

**Tech Stack:** Go stdlib + the project's `config` package only. **No new dependencies** — routing does not even import sipgo (M3.3 adapts SIP messages into the string arguments). Config already compiles `match.to` regexes at parse time and exposes them via `(*config.Route).CompiledMatch()`.

**Roadmap context:** Second of three M3 slices (M3.1 front door ✅ → **M3.2 routing** → M3.3 bridge). This slice ships a tested library with no runtime wiring — the bridge in M3.3 is its first caller, at which point the end-to-end call lights up. Intentionally deferred: failover *execution* (try next target on 5xx/timeout) and peer health/cooldown skipping — both stateful and owned by M3.3's B2BUA attempt loop; DNS SRV resolution of peer addresses (M4); per-peer SDP codec filtering (M3.3, an SDP-layer concern). No separate `sig/normalize.go`: the compressed config model puts number transformation inline in each route (`transform`), so a standalone normalization stage would be dead code (spec §5: "transform 内联于路由，无需单独定义再引用").

**Why the config fix (Task 1):** M1's env expansion walks every exported string field (including `route.Transform.To`) and rejects any `${...}` span that is not a valid `${VAR}` reference. A regexp replacement template like `${1}` is digit-led, so it can never be a valid env variable name — yet the current `malformedRef` check rejects it, so `transform: { to: "${1}" }` fails at parse with a baffling "malformed ${...} reference" error. Bare `$1` survives (it contains no `${`), but the braced form users need to place a group next to literal digits (`${1}000`) is broken. The fix: treat `${<digits>}` as a literal (a regexp group ref), never an env reference — safe because a digit-led name is never a valid env var, so no real env typo is masked.

## Global Constraints

- Module `github.com/freesbc/freesbc`, Go ≥ 1.22. Dependencies unchanged (goccy/go-yaml, fsnotify, emiago/sipgo); this slice adds none. The routing file imports stdlib + `config` only; the config fix touches `config/expand.go` (stdlib only).
- All code, comments, and log messages in English. Tests use stdlib `testing` only (no assertion libraries).
- Every task: `gofmt -l .` prints nothing before committing; the final task runs `go vet ./... && go test ./... -race`.
- Config lifecycle contract (M1): callers pass a `*config.Config` snapshot from `(*config.Store).Current()`; routing never mutates it. `match.to` regexes are already compiled and validated at parse time; a route's `Transform` is only non-empty when `match.to` compiled successfully (M1 validation enforces "transform.to requires match.to").
- Routing semantics (spec §5): inbound peer identified upstream by source IP (M3.1); match by `routes` order, `from`+`match` regex, first hit wins, no priority numbers; `transform` uses regex capture groups inline; `to` list order is failover order.
- The `toNumber` argument is the dialed number — M3.3 will supply the INVITE Request-URI user part. Routing treats it as an opaque string.
- Deviation note: spec §6 names the entry `routing.Match(from, to号码)`. The as-built public entry is `Resolve(cfg, fromPeer, toNumber) (*Decision, bool)` — it returns the transformed number and resolved target peers in one struct, which is what the bridge needs; `matchRoute`/`transformNumber` are the package-private primitives.
- Env-expansion invariant (do not weaken): well-formed `${VAR}` references are still expanded; genuinely malformed spans (`${VAR:-default}`, `${FOO BAR}`) are still rejected; a reference to an unset well-formed variable is still reported as "missing". Only digit-led `${<digits>}` spans change behavior (now treated as literals).

---

### Task 1: Config fix — let `${N}` regexp group refs survive env expansion

**Files:**
- Modify: `config/expand.go` (`malformedRef`; add a numeric-group regex)
- Test: `config/loader_test.go`

**Interfaces:**
- Consumes: existing `config.Parse`, `expandEnv`, `malformedRef` (M1).
- Produces: no signature change. Behavior change: a config string containing `${<digits>}` (e.g. `${1}`) is left verbatim by env expansion instead of being rejected as malformed. Task 3's transform tests rely on `transform: { to: "${1}..." }` parsing successfully.

- [ ] **Step 1: Write the failing test**

Add to `config/loader_test.go`:

```go
func TestParseNumericBraceRefIsLiteral(t *testing.T) {
	// ${1} is a regexp capture-group reference, not an env var (a digit-led
	// name is never a valid env variable), so it must survive parsing
	// verbatim — routing transforms depend on this.
	src := strings.Replace(minimalYAML, "from: pbx",
		"from: pbx\n    match: { to: \"^9(\\\\d+)$\" }\n    transform: { to: \"00${1}\" }", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("${1} in a transform must parse, got: %v", err)
	}
	if got := c.Routes[0].Transform.To; got != "00${1}" {
		t.Errorf("transform.to = %q, want literal \"00${1}\"", got)
	}
}

func TestParseMalformedRefStillRejected(t *testing.T) {
	// A bash-style default is still malformed and must still be rejected —
	// the numeric-group carve-out must not weaken this.
	src := strings.Replace(minimalYAML, "address: 10.0.0.10:5060",
		"address: 10.0.0.10:5060\n    auth: { username: u, password: \"${PASS:-x}\" }", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected malformed-ref error, got: %v", err)
	}
}
```

(The `minimalYAML` constant and `strings` import already exist in `config/loader_test.go`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/ -run 'TestParseNumericBraceRefIsLiteral|TestParseMalformedRefStillRejected' -v`
Expected: `TestParseNumericBraceRefIsLiteral` FAILS (Parse returns a "malformed ${...} reference" error for `${1}`); `TestParseMalformedRefStillRejected` PASSES already (guards against regression).

- [ ] **Step 3: Implement**

In `config/expand.go`, add the numeric-group regex next to `envRef`:

```go
// numericGroupRef matches ${123} — a regexp replacement group reference,
// not an env variable (a digit-led name can never be a valid env var). Such
// spans are left verbatim so route transforms can use ${N} next to literal
// digits (e.g. "${1}000"); they are neither expanded nor flagged malformed.
var numericGroupRef = regexp.MustCompile(`\$\{[0-9]+\}`)
```

In `malformedRef`, strip numeric-group refs before checking for leftover `${`:

```go
func malformedRef(s string) (string, bool) {
	stripped := envRef.ReplaceAllString(s, "")
	stripped = numericGroupRef.ReplaceAllString(stripped, "")
	if !strings.Contains(stripped, "${") {
		return "", false
	}
	rest := stripped[strings.Index(stripped, "${"):]
	if end := strings.IndexByte(rest, '}'); end >= 0 {
		rest = rest[:end+1]
	} else if len(rest) > 40 {
		rest = rest[:40] + "..."
	}
	return rest, true
}
```

(The expansion path in `walk` already leaves `${1}` verbatim: `envRef` does not match digit-led names, so `envRef.ReplaceAllFunc` skips it. Only `malformedRef` needed the carve-out.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./config/ -v`
Expected: PASS (all config tests, including both new ones).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/expand.go config/loader_test.go && git commit -m "fix(config): treat \${N} as a regexp group ref, not a malformed env reference"
```

---

### Task 2: Route matching

**Files:**
- Create: `sig/routing.go`
- Test: `sig/routing_test.go`

**Interfaces:**
- Consumes: `config.Config` (`Routes []*Route`), `config.Route` (`From string`, `(*Route).CompiledMatch() *regexp.Regexp`) from M1.
- Produces (Tasks 3–4 rely on this): `func matchRoute(cfg *config.Config, fromPeer, toNumber string) (*config.Route, bool)` — first route with `From == fromPeer` whose `CompiledMatch()` matches `toNumber`; a nil `CompiledMatch()` (no `match` clause) matches any number. Returns `(nil, false)` when nothing matches.

- [ ] **Step 1: Write the failing test**

Create `sig/routing_test.go`:

```go
package sig

import (
	"testing"

	"github.com/freesbc/freesbc/config"
)

// routingCfg parses a config used across the routing tests: an outbound
// route (9-prefixed numbers, internal-pbx → carrier-a,carrier-b), an
// international route, and a catch-all inbound route (carrier-a →
// internal-pbx, no match clause).
func routingCfg(t *testing.T) *config.Config {
	t.Helper()
	const src = `
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    auth: { username: u, password: p }
    allowed_ips: [203.0.113.0/24]
  carrier-b:
    address: sip.carrier-b.com:5060
    auth: { username: u2, password: p2 }
    allowed_ips: [198.51.100.0/24]
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]
routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a, carrier-b]
  - name: intl
    from: internal-pbx
    match: { to: "^00(\\d+)$" }
    transform: { to: "+${1}" }
    to: [carrier-b]
  - name: inbound
    from: carrier-a
    to: [internal-pbx]
`
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cfg
}

func TestMatchRouteFirstHitWins(t *testing.T) {
	cfg := routingCfg(t)
	r, ok := matchRoute(cfg, "internal-pbx", "9123")
	if !ok || r.Name != "outbound" {
		t.Fatalf("9123 from internal-pbx → %v, ok=%v (want outbound)", r, ok)
	}
	r, ok = matchRoute(cfg, "internal-pbx", "00441234")
	if !ok || r.Name != "intl" {
		t.Fatalf("00441234 → %v, ok=%v (want intl)", r, ok)
	}
}

func TestMatchRouteNoMatchClauseMatchesAny(t *testing.T) {
	cfg := routingCfg(t)
	// inbound route has no match clause → matches any number.
	r, ok := matchRoute(cfg, "carrier-a", "anything-at-all")
	if !ok || r.Name != "inbound" {
		t.Fatalf("→ %v, ok=%v (want inbound)", r, ok)
	}
}

func TestMatchRouteFiltersByFromPeer(t *testing.T) {
	cfg := routingCfg(t)
	// "9123" only matches the outbound route, whose from is internal-pbx;
	// the same number from carrier-a must fall through to the inbound
	// route (no match clause), not the outbound one.
	r, ok := matchRoute(cfg, "carrier-a", "9123")
	if !ok || r.Name != "inbound" {
		t.Fatalf("9123 from carrier-a → %v, ok=%v (want inbound)", r, ok)
	}
}

func TestMatchRouteNoMatch(t *testing.T) {
	cfg := routingCfg(t)
	// carrier-b is not the `from` of any route.
	if r, ok := matchRoute(cfg, "carrier-b", "9123"); ok {
		t.Fatalf("carrier-b has no route, got %v", r)
	}
	// A number that matches no outbound pattern from internal-pbx (no
	// catch-all for internal-pbx) must not match.
	if r, ok := matchRoute(cfg, "internal-pbx", "555"); ok {
		t.Fatalf("555 from internal-pbx matches no route, got %v", r)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestMatchRoute -v`
Expected: FAIL (compile error: `matchRoute` undefined).

- [ ] **Step 3: Implement**

Create `sig/routing.go`:

```go
package sig

import "github.com/freesbc/freesbc/config"

// matchRoute returns the first route whose From equals fromPeer and whose
// match.to regex matches toNumber. A route with no match clause (nil
// compiled regex) matches any number. Routes are tried in config order;
// the first hit wins (spec §5: no priority numbers). ok is false when no
// route matches — the caller rejects such calls (404 in M3.3).
func matchRoute(cfg *config.Config, fromPeer, toNumber string) (*config.Route, bool) {
	for _, r := range cfg.Routes {
		if r.From != fromPeer {
			continue
		}
		if re := r.CompiledMatch(); re != nil && !re.MatchString(toNumber) {
			continue
		}
		return r, true
	}
	return nil, false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./sig/ -run TestMatchRoute -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/routing.go sig/routing_test.go && git commit -m "feat(sig): route matching by from-peer and match.to regex, first hit wins"
```

---

### Task 3: Number transform

**Files:**
- Modify: `sig/routing.go`
- Test: `sig/routing_test.go`

**Interfaces:**
- Consumes: `config.Route` (`Transform *RouteTransform` with `To string`, `(*Route).CompiledMatch()`) from M1; the M1 validation guarantee that `Transform.To != ""` implies `CompiledMatch() != nil`; the `${N}`-survives-parsing fix from Task 1.
- Produces (Task 4 relies on this): `func transformNumber(route *config.Route, toNumber string) string` — applies `route.Transform.To` as a regexp capture-group replacement over `route.CompiledMatch()`; returns `toNumber` unchanged when the route has no transform.

- [ ] **Step 1: Write the failing test**

Add to `sig/routing_test.go`:

```go
func TestTransformNumberStripsPrefix(t *testing.T) {
	cfg := routingCfg(t)
	route, ok := matchRoute(cfg, "internal-pbx", "9123")
	if !ok {
		t.Fatal("setup: outbound route must match")
	}
	// transform "$1" over match "^9(\d+)$": strips the leading 9.
	if got := transformNumber(route, "9123"); got != "123" {
		t.Errorf("transformNumber = %q, want \"123\"", got)
	}
}

func TestTransformNumberBracedGroupWithLiteral(t *testing.T) {
	cfg := routingCfg(t)
	route, ok := matchRoute(cfg, "internal-pbx", "00441234")
	if !ok {
		t.Fatal("setup: intl route must match")
	}
	// transform "+${1}" over match "^00(\d+)$": ${1} = "441234", so the
	// braced group survives config parsing (Task 1) and expands correctly.
	if got := transformNumber(route, "00441234"); got != "+441234" {
		t.Errorf("transformNumber = %q, want \"+441234\"", got)
	}
}

func TestTransformNumberNoTransformIsPassthrough(t *testing.T) {
	cfg := routingCfg(t)
	route, ok := matchRoute(cfg, "carrier-a", "5551234")
	if !ok {
		t.Fatal("setup: inbound route must match")
	}
	// inbound route has no transform → number passes through unchanged.
	if got := transformNumber(route, "5551234"); got != "5551234" {
		t.Errorf("transformNumber = %q, want \"5551234\"", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestTransformNumber -v`
Expected: FAIL (compile error: `transformNumber` undefined).

- [ ] **Step 3: Implement**

Append to `sig/routing.go`:

```go
// transformNumber applies a route's number transform. When the route has a
// transform, route.Transform.To is a regexp replacement template expanded
// against route.CompiledMatch() (which is guaranteed non-nil whenever a
// transform is set — config validation enforces "transform requires
// match"). Capture groups are referenced as $1 or, next to literal digits,
// ${1}. With no transform, the number passes through unchanged.
func transformNumber(route *config.Route, toNumber string) string {
	if route.Transform == nil || route.Transform.To == "" {
		return toNumber
	}
	re := route.CompiledMatch()
	return re.ReplaceAllString(toNumber, route.Transform.To)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./sig/ -run TestTransformNumber -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/routing.go sig/routing_test.go && git commit -m "feat(sig): number transform via regexp capture-group replacement"
```

---

### Task 4: Resolve — compose match + transform + target resolution

**Files:**
- Modify: `sig/routing.go`
- Modify: `README.md`
- Test: `sig/routing_test.go`

**Interfaces:**
- Consumes: `matchRoute` (Task 2), `transformNumber` (Task 3), `config.Config` (`Peers map[string]*Peer`), `config.Route` (`To []string`), `config.Peer` from M1.
- Produces (M3.3 bridge relies on these):
  - `type Target struct{ Name string; Peer *config.Peer }`
  - `type Decision struct{ Route *config.Route; OutNumber string; Targets []Target }`
  - `func Resolve(cfg *config.Config, fromPeer, toNumber string) (*Decision, bool)` — the public routing entry: matches a route, transforms the number, and resolves `route.To` (validated to reference real peers) into ordered failover `Targets`. `(nil, false)` when no route matches.

- [ ] **Step 1: Write the failing test**

Add to `sig/routing_test.go`:

```go
func TestResolveOutboundWithFailoverOrder(t *testing.T) {
	cfg := routingCfg(t)
	d, ok := Resolve(cfg, "internal-pbx", "9123")
	if !ok {
		t.Fatal("9123 must resolve")
	}
	if d.Route.Name != "outbound" {
		t.Errorf("route = %q, want outbound", d.Route.Name)
	}
	if d.OutNumber != "123" {
		t.Errorf("OutNumber = %q, want \"123\"", d.OutNumber)
	}
	if len(d.Targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(d.Targets))
	}
	// Failover order = config order: carrier-a then carrier-b.
	if d.Targets[0].Name != "carrier-a" || d.Targets[1].Name != "carrier-b" {
		t.Errorf("target order = %q,%q; want carrier-a,carrier-b",
			d.Targets[0].Name, d.Targets[1].Name)
	}
	// Targets carry the resolved *Peer, not just the name.
	if d.Targets[0].Peer == nil || d.Targets[0].Peer != cfg.Peers["carrier-a"] {
		t.Error("Targets[0].Peer must be the resolved carrier-a peer")
	}
}

func TestResolveInboundPassthrough(t *testing.T) {
	cfg := routingCfg(t)
	d, ok := Resolve(cfg, "carrier-a", "5551234")
	if !ok {
		t.Fatal("inbound must resolve")
	}
	if d.Route.Name != "inbound" || d.OutNumber != "5551234" {
		t.Errorf("route=%q out=%q; want inbound / 5551234", d.Route.Name, d.OutNumber)
	}
	if len(d.Targets) != 1 || d.Targets[0].Name != "internal-pbx" {
		t.Errorf("targets = %+v; want [internal-pbx]", d.Targets)
	}
}

func TestResolveNoRoute(t *testing.T) {
	cfg := routingCfg(t)
	if d, ok := Resolve(cfg, "carrier-b", "9123"); ok {
		t.Fatalf("carrier-b has no route, got %+v", d)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestResolve -v`
Expected: FAIL (compile error: `Resolve`, `Decision`, `Target` undefined).

- [ ] **Step 3: Implement**

Add the type declarations near the top of `sig/routing.go` (after the import), and append `Resolve`:

```go
// Target is one failover candidate: a peer name and its resolved config.
type Target struct {
	Name string
	Peer *config.Peer
}

// Decision is the outcome of routing an inbound call: the matched route,
// the dialed number after transform, and the ordered failover candidates
// the B2BUA tries in turn.
type Decision struct {
	Route     *config.Route
	OutNumber string
	Targets   []Target
}
```

```go
// Resolve routes an inbound call. It selects the first matching route for
// fromPeer/toNumber, applies the route's number transform, and resolves
// the route's To list (validated to reference real peers) into ordered
// failover Targets. ok is false when no route matches. Resolve is pure and
// stateless: peer health/cooldown skipping and failover execution are the
// B2BUA's job (M3.3).
func Resolve(cfg *config.Config, fromPeer, toNumber string) (*Decision, bool) {
	route, ok := matchRoute(cfg, fromPeer, toNumber)
	if !ok {
		return nil, false
	}
	targets := make([]Target, 0, len(route.To))
	for _, name := range route.To {
		targets = append(targets, Target{Name: name, Peer: cfg.Peers[name]})
	}
	return &Decision{
		Route:     route,
		OutNumber: transformNumber(route, toNumber),
		Targets:   targets,
	}, true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./sig/ -v`
Expected: PASS (all sig tests: routing + the M3.1 identify/tlscert/server tests).

- [ ] **Step 5: Update the README roadmap**

In `README.md`, mark M3.2 done and M3.3 next (change only these two sub-rows):

```markdown
| ├ M3.2 | Routing engine: match / transform / failover | ✅ done |
| └ M3.3 | B2BUA bridge: leg pairing, SDP rewrite, media wiring, Relatch | next |
```

- [ ] **Step 6: Full verification**

Run: `go vet ./... && go test ./... -race`
Expected: vet clean; all config, media, and sig tests PASS.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && git add sig/routing.go sig/routing_test.go README.md && git commit -m "feat(sig): Resolve routing decision (route + transformed number + failover targets)"
```

---

## Spec Coverage (M3.2 slice)

| Spec requirement | Task |
|---|---|
| §4 `sig/routing.go` — 路由匹配 → 选网关 | 2, 4 |
| §5 匹配：routes 顺序，from+match 正则首条命中即用，无优先级 | 2 |
| §5 变换：transform 正则捕获组，内联于路由 | 1 (parsing), 3 (logic) |
| §5 failover：to 列表依序（顺序即 failover 顺序） | 4 (ordered Targets) |
| §6 step 5 — routing.Match(from, to号码) → 目标 peer | 4 (`Resolve`) |
| §5 无 normalize 单独层（transform 内联） | design decision (no `normalize.go`) |
| M1 backlog — `${N}` regexp group refs vs env-syntax collision | 1 |

Deferred (documented in header): failover *execution* + peer health/cooldown skipping (M3.3 B2BUA loop); DNS SRV peer-address resolution (M4); per-peer SDP codec filtering (M3.3). No runtime wiring in this slice — `Resolve` is a library consumed first by the M3.3 bridge.
