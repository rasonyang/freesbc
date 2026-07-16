# FreeSBC M4.1 — Outbound-INVITE Realism Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the B2BUA bridge's outbound INVITE acceptable to a real carrier — propagate calling identity (From/CLI), cap ring time with failover, return truthful response codes, and fix the in-dialog 481/400 codes.

**Architecture:** Corrections to the existing `sig` bridge (`b2bua.go`, `server.go`) plus one global config field. The outbound INVITE carries a `From` (caller's number, our host) and a per-transport `Contact`, both passed via sipgo's `Invite` variadic headers (sipgo defaults them only when absent). Each failover attempt runs under a `ring_timeout` deadline and returns a classified failure so the caller sees the truest final code.

**Tech Stack:** existing deps (sipgo v1.4.3, pion/sdp, config/media/sig/callstate), Go stdlib. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-16-m4-1-outbound-invite-realism-design.md`. First of four M4 slices (M4.2 REGISTER, M4.3 session timers + PRACK, M4.4 DNS SRV + peer health follow).

## Global Constraints

- Module `github.com/freesbc/freesbc`, Go ≥ 1.22. No new dependencies. English code/comments; stdlib testing only; `gofmt -l .` clean; final task runs `go vet ./... && go test ./... -race`.
- Config lifecycle (M1): read snapshots via `(*config.Store).Current()`; never mutate a published `*config.Config`.
- Topology hiding (M3.3): the outbound From/Contact host is `ourIP` (via the existing `Server.ourIP(cfg) netip.Addr`, which skips unspecified listeners), never the caller's IP.
- Response-code precedence when all targets fail: (a) last real final response code seen; else (b) 408 if any attempt ring-timed-out; else (c) 503.
- Must not regress M3.3: happy-path bridge, early media, digest auth, failover, latch arming, teardown, the post-CANCEL failover guard, the SDP topology-hiding rewrite.
- sipgo v1.4.3 facts (verified against the module cache; re-verify per task):
  - `DialogUA.Invite` (used by `dialogCli.Invite(ctx, uri, body, headers...)`) appends passed headers and only synthesizes a default From/Contact when none is present (`dialog_ua.go:106-127`) — so a passed `*sip.FromHeader` and `*sip.ContactHeader` win.
  - `DialogServerSession.Respond(code int, reason string, body []byte, headers ...sip.Header) error` takes variadic headers; `RespondSDP(sdp []byte)` does not. Whether a Contact passed to `Respond` overrides the cache's default Contact is verified in Task 5.
  - Header/URI types: `sip.FromHeader{DisplayName string; Address sip.Uri; Params sip.HeaderParams}`, `sip.ContactHeader{DisplayName string; Address sip.Uri; Params sip.HeaderParams}`, `sip.Uri{Scheme, User, Host string; Port int; UriParams sip.HeaderParams}`. `req.From()` returns `*sip.FromHeader`. Add URI params via the `HeaderParams` API (verify the constructor/`Add` shape, e.g. `sip.NewParams()` / `.Add(k,v)`, in Task 2).
  - A per-attempt ring-timeout uses `context.WithTimeout(aLeg.Context(), d)`; on expiry `WaitAnswer` sends CANCEL (M3.3-verified path). Distinguish our timeout (the attempt ctx expired but `aLeg.Context()` is still live) from a caller CANCEL (`aLeg.Context().Err() != nil`).

---

### Task 1: Config — global `ring_timeout`

**Files:**
- Modify: `config/schema.go` (Config struct, withDefaults), `config/validate.go`
- Modify: `sbc.example.yaml`
- Test: `config/schema_test.go`, `config/validate_test.go`

**Interfaces:**
- Consumes: `config.Duration`, `config.Config`, `withDefaults`, the `validate()` routes/shield checks (M1/M2).
- Produces: `Config.RingTimeout Duration` (yaml `ring_timeout`, default 60s, must be > 0). The bridge reads `cfg.RingTimeout.Std()` in Task 4.

- [ ] **Step 1: Write the failing tests**

Add to `TestWithDefaults` in `config/schema_test.go`:

```go
	if c.RingTimeout.Std() != 60*time.Second {
		t.Errorf("ring_timeout default: %v", c.RingTimeout.Std())
	}
```

Add to the `cases` table in `TestValidateErrors` in `config/validate_test.go`:

```go
		{"negative ring_timeout", func(c *Config) { c.RingTimeout = Duration(-time.Second) }, "ring_timeout"},
```

Add a round-trip check to `config/loader_test.go` (or the schema test) — a config with `ring_timeout: 30s` parses to 30s:

```go
func TestParseRingTimeout(t *testing.T) {
	src := minimalYAML + "ring_timeout: 30s\n"
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.RingTimeout.Std() != 30*time.Second {
		t.Errorf("ring_timeout = %v, want 30s", c.RingTimeout.Std())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/ -run 'TestWithDefaults|TestValidateErrors|TestParseRingTimeout' -v`
Expected: FAIL (compile error: `RingTimeout` undefined).

- [ ] **Step 3: Implement**

In `config/schema.go`, add to the `Config` struct (after `Admin`):

```go
	RingTimeout Duration `yaml:"ring_timeout"` // cancel a ringing target after this long, then failover
```

In `withDefaults`, add:

```go
	if c.RingTimeout == 0 {
		c.RingTimeout = Duration(60 * time.Second)
	}
```

In `config/validate.go`, after the media `rtp_timeout` check:

```go
	if c.RingTimeout.Std() <= 0 {
		fail("ring_timeout: must be > 0, got %v", c.RingTimeout.Std())
	}
```

In `sbc.example.yaml`, add a top-level line near the media section:

```yaml
ring_timeout: 60s   # cancel a target that rings this long without answering, then failover
```

- [ ] **Step 4: Run the config suite**

Run: `go test ./config/ -v && go build -o freesbc . && CARRIER_A_PASS=test ./freesbc check -c sbc.example.yaml`
Expected: PASS; `sbc.example.yaml: config OK`.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ sbc.example.yaml && git commit -m "feat(config): global ring_timeout for call setup"
```

---

### Task 2: From/CLI + per-transport B-leg Contact on the outbound INVITE

**Files:**
- Modify: `sig/b2bua.go` (build+pass From and Contact to `dialogCli.Invite`), `sig/server.go` (Contact/port helper)
- Test: `sig/b2bua_test.go`

**Interfaces:**
- Consumes: `Server.ourIP(cfg) netip.Addr` (M3.3), `req.From()`, `dialogCli.Invite(ctx, uri, body, headers...)`, target `Peer.Transport`.
- Produces (later tasks unaffected): the B-leg INVITE carries `From: <caller-user>@<ourIP>` (display name preserved, fresh tag) and `Contact: <sip:ourIP:port;transport=...>` matching the target's transport. Helpers `Server.ourSigPort(cfg, transport string) int` (our listener port for a transport) and `(b *bridge) buildFrom(req) *sip.FromHeader`, `(b *bridge) buildContact(cfg, transport string) *sip.ContactHeader`.

- [ ] **Step 1: Write the failing test**

Extend the stub carrier in `sig/b2bua_test.go` to capture the `From` and `Contact` of the INVITE it receives (record `req.From()` and `req.Contact()` on the carrier's OnInvite). Add:

```go
func TestBridgeOutboundFromAndContact(t *testing.T) {
	// Establish a call; the stub carrier records the INVITE's From/Contact.
	// Assert From user = the caller's number, From host = ourIP (not the
	// caller's address), and the Contact carries transport=udp.
	// (Reuse the Task 6/8 happy-path harness; the caller's INVITE uses
	// From user "1001"; ourIP resolves to 127.0.0.1 in the test config.)
	// ... establish call, read carrier.lastInvite ...
	from := carrier.lastFrom() // *sip.FromHeader captured by the stub
	if from.Address.User != "1001" {
		t.Errorf("From user = %q, want caller number 1001", from.Address.User)
	}
	if from.Address.Host != "127.0.0.1" { // ourIP in the test config
		t.Errorf("From host = %q, want ourIP", from.Address.Host)
	}
	if _, ok := from.Params["tag"]; !ok {
		t.Error("From must carry a tag")
	}
	contact := carrier.lastContact()
	if tp, _ := contact.Params.Get("transport"); tp != "udp" && contact.Address.Host != "127.0.0.1" {
		t.Errorf("Contact = %+v, want ourIP with transport udp", contact)
	}
}
```

Write the complete helper wiring (the stub carrier capturing From/Contact, and the caller INVITE using From user "1001") — no placeholders. Verify the exact `HeaderParams` read API (`Params["tag"]` vs `Params.Get("tag")`) against sipgo and use the real one.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestBridgeOutboundFromAndContact -v`
Expected: FAIL — the outbound INVITE currently has sipgo's synthesized `From: sipgo@localhost` and the cache default Contact.

- [ ] **Step 3: Implement**

In `sig/server.go`, add a helper for our per-transport signaling port:

```go
// ourSigPort returns our listening port for the given transport (the first
// matching listen.sip entry), or the first listener's port as a fallback.
func (s *Server) ourSigPort(cfg *config.Config, transport string) int {
	for _, l := range cfg.Listen.SIP {
		if l.Transport == transport {
			return l.Port
		}
	}
	if len(cfg.Listen.SIP) > 0 {
		return cfg.Listen.SIP[0].Port
	}
	return 5060
}
```

In `sig/b2bua.go`, add the From/Contact builders and pass them to `Invite`. Build them from the A-leg request and the target transport (adapt the `HeaderParams` construction to the verified sipgo API):

```go
// buildFrom clones the caller's identity onto a B-leg From: the caller's
// user and display name (CLI pass-through) with our host (topology hiding)
// and a fresh local tag.
func (b *bridge) buildFrom(req *sip.Request, ourIP netip.Addr, port int) *sip.FromHeader {
	caller := req.From()
	f := &sip.FromHeader{
		DisplayName: caller.DisplayName,
		Address: sip.Uri{
			Scheme: "sip",
			User:   caller.Address.User,
			Host:   ourIP.String(),
			Port:   port,
		},
		Params: sip.NewParams(),
	}
	f.Params.Add("tag", freshTag())
	return f
}

// buildContact advertises our address for the given transport so in-dialog
// requests reach us on the right leg.
func (b *bridge) buildContact(ourIP netip.Addr, port, transportParam string) *sip.ContactHeader {
	c := &sip.ContactHeader{
		Address: sip.Uri{Scheme: "sip", Host: ourIP.String(), Port: port},
	}
	if transportParam != "" && transportParam != "udp" {
		c.Address.UriParams = sip.NewParams()
		c.Address.UriParams.Add("transport", transportParam)
	}
	return c
}
```

Add `freshTag()` — a random hex tag via `crypto/rand` (12 bytes → hex). At the B-leg placement in `dialTarget`, compute `ourIP := b.s.ourIP(cfg)`, `port := b.s.ourSigPort(cfg, target.Peer.Transport)`, build `from`/`contact`, and pass them: `b.s.dialogCli.Invite(ctx, peerURI(target.Peer), bOffer, b.buildFrom(req, ourIP, port), b.buildContact(ourIP, port, target.Peer.Transport))`.

Note on the Contact transport param: for `udp` (SIP default) omit the param; for `tcp`/`tls` set `transport=tcp`/`tls`. The test asserts udp works (no param) via the host check; add a tcp/tls assertion only if a listener of that transport exists in the test config.

- [ ] **Step 4: Run the test (race on)**

Run: `go test ./sig/ -run 'TestBridgeOutboundFromAndContact|TestBridgePlacesCallAndBridges' -race -v`
Expected: PASS (From/Contact correct; happy path still works). If sipgo's client re-synthesizes or rejects our From tag, see Step 3's verification note and adjust the tag handling.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): outbound INVITE carries caller From/CLI and per-transport Contact"
```

---

### Task 3: Response-code fidelity — classify failures

**Files:**
- Modify: `sig/b2bua.go` (`dialTarget` result, `placeCall` precedence)
- Test: `sig/b2bua_test.go`

**Interfaces:**
- Consumes: `bLeg.InviteResponse` (guarded `!IsProvisional()` from M3.3), `WaitAnswer`.
- Produces (Task 4 extends this): `dialTarget` returns a failure kind — `failReal` (a genuine final code), `failDial` (couldn't reach / no response → 503), `failUnusable` (2xx with bad SDP → 502). `placeCall` picks the caller code by precedence: last `failReal` code, else 503. (Ring-timeout/`failRing`→408 is added in Task 4.)

- [ ] **Step 1: Write the failing test**

Add to `sig/b2bua_test.go` (extend the stub carrier to answer a configurable final code):

```go
func TestBridgePassesRealFinalCode(t *testing.T) {
	// A single carrier that returns 486 Busy Here; the caller must see 486,
	// not a synthetic 502/503.
	// ... start stub carrier answering 486, start bridge with one target ...
	// ... UAC INVITEs, reads the final response ...
	if finalCode != 486 {
		t.Fatalf("caller got %d, want 486 (real carrier code)", finalCode)
	}
}

func TestBridgeFailoverThenRealCode(t *testing.T) {
	// carrier-a → 486, carrier-b → 404; both real finals; caller sees the
	// LAST real code (404).
	// ... two targets, a=486, b=404 ...
	if finalCode != 404 {
		t.Fatalf("caller got %d, want 404 (last real code)", finalCode)
	}
}
```

Write the complete harness (a stub carrier whose answer code is configurable). Reuse the failover config shape from M3.3's failover test.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run 'TestBridgePassesRealFinalCode|TestBridgeFailoverThenRealCode' -v`
Expected: FAIL — M3.3 flattens non-2xx to a coarse code; 486/404 may not pass through faithfully.

- [ ] **Step 3: Implement**

Introduce a small failure kind in `sig/b2bua.go`:

```go
type failKind int

const (
	failDial     failKind = iota // couldn't reach the target / no final response → 503
	failReal                     // a genuine SIP final failure from the target
	failUnusable                 // 2xx received but its SDP is missing/unparseable → 502
)

type attemptResult struct {
	ok       bool     // 2xx bridged
	kind     failKind // valid when !ok
	code     int      // the real final code when kind == failReal
	reason   string
}
```

Refactor `dialTarget` to return `attemptResult`: on `WaitAnswer` error with no usable final → `{kind: failDial}`; on a real final (`bLeg.InviteResponse != nil && !bLeg.InviteResponse.IsProvisional()` and not success) → `{kind: failReal, code: StatusCode, reason: Reason}`; on 2xx-with-bad-SDP → `{kind: failUnusable}`; on success → `{ok: true}`. In `placeCall`, track the last `failReal` `{code, reason}`; after the loop, respond the caller: the last real code if any `failReal` occurred, else `503 Service Unavailable`. Preserve the M3.3 post-CANCEL guard and the answered-B-leg teardown rules.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -run TestBridge -race -v`
Expected: PASS (486/404 pass through; all prior bridge tests — happy path, early media, failover, auth, teardown — still green).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): propagate real carrier final codes to the caller"
```

---

### Task 4: Ring timeout with failover

**Files:**
- Modify: `sig/b2bua.go` (`dialTarget` per-attempt deadline; `failRing` kind; `placeCall` 408 precedence)
- Test: `sig/b2bua_test.go`

**Interfaces:**
- Consumes: `cfg.RingTimeout` (Task 1), the `attemptResult`/`failKind` from Task 3.
- Produces: a `failRing` kind (→408). `placeCall` precedence becomes: last `failReal` code, else 408 if any `failRing`, else 503.

- [ ] **Step 1: Write the failing test**

```go
func TestBridgeRingTimeoutFailsOver(t *testing.T) {
	// carrier-a rings (180) and never answers; carrier-b answers 200.
	// With a short ring_timeout, the bridge CANCELs carrier-a and bridges
	// to carrier-b. Assert the call bridges (200) and carrier-a got a CANCEL.
	// ... config ring_timeout: 300ms, two targets ...
}

func TestBridgeRingTimeoutNoTargetsReturns408(t *testing.T) {
	// Single carrier that rings forever; short ring_timeout; caller gets 408.
	if finalCode != 408 {
		t.Fatalf("caller got %d, want 408 Request Timeout", finalCode)
	}
}
```

Use a stub carrier that sends 180 then holds (never sends a final) and records whether it received a CANCEL. Set `ring_timeout` small (e.g. 300ms) in the test config.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestBridgeRingTimeout -v`
Expected: FAIL — no ring cap yet; the call parks until the test's own timeout.

- [ ] **Step 3: Implement**

In `dialTarget`, wrap the attempt's `WaitAnswer` context: `attemptCtx, cancel := context.WithTimeout(aLeg.Context(), cfg.RingTimeout.Std()); defer cancel()`. Pass `attemptCtx` to `WaitAnswer`. After `WaitAnswer` returns an error, classify: if `aLeg.Context().Err() != nil` → caller CANCEL (existing M3.3 guard stops the loop); else if `attemptCtx.Err() == context.DeadlineExceeded` → `{kind: failRing}` (WaitAnswer already CANCELed the target via its ctx-done path); else the existing `failDial`/`failReal` classification. In `placeCall`, extend the exhaustion precedence: last `failReal` code → else `408 Request Timeout` if any `failRing` → else `503`.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -run TestBridge -race -v`
Expected: PASS (ring timeout → CANCEL + failover / 408; all prior tests green). Timing-based — re-run once before treating a flake as failure.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): ring_timeout cancels a hung target and fails over (408 on exhaustion)"
```

---

### Task 5: In-dialog codes (481/400) + A-leg per-transport Contact

**Files:**
- Modify: `sig/server.go` (`onBye`, the `ReadInvite`-failure path), `sig/b2bua.go` (A-leg answer Contact)
- Test: `sig/b2bua_test.go`, `sig/server_test.go`

**Interfaces:**
- Consumes: `dialogSrv.ReadBye`/`dialogCli.ReadBye` return values, `DialogServerSession.Respond` (variadic headers), `Server.ourIP`/`ourSigPort`.
- Produces: a BYE matching no dialog → 481; a malformed INVITE → 400; the A-leg 200 OK Contact matches the inbound transport (best-effort per §5).

- [ ] **Step 1: Write the failing tests**

```go
func TestServerByeNoDialogGets481(t *testing.T) {
	// A BYE from a KNOWN source that matches no established dialog → 481
	// (not silent). Raw-UDP BYE with a To-tag but no real dialog.
	startServer(t, 45072, knownPeerCfg) // adjust port
	got := roundTrip(t, 45072, "BYE", "bye-nodialog-1", 2*time.Second, "SIP/2.0 481")
	if !strings.Contains(got, "SIP/2.0 481") {
		t.Fatalf("BYE with no dialog must get 481, got:\n%s", got)
	}
}

func TestBridgeMalformedInviteGets400(t *testing.T) {
	// An INVITE from a known source with no Contact header → ReadInvite fails
	// → 400 Bad Request (not 500). Craft a raw INVITE without a Contact.
	// ... assert 400 ...
}
```

For the A-leg Contact, extend `TestBridgePlacesCallAndBridges` (or a new test) to assert the 200 OK the caller receives has a Contact host = ourIP (already true) AND, if the mechanism supports it, the transport param matching the inbound transport.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./sig/ -run 'TestServerByeNoDialog|TestBridgeMalformedInvite' -v`
Expected: FAIL — a no-dialog BYE is currently silent (M3.1 identify-gate then nothing); a malformed INVITE currently gets 500.

- [ ] **Step 3: Implement**

In `sig/server.go` `onBye`: after the identify gate, try `dialogSrv.ReadBye`; if it returns a no-match error, try `dialogCli.ReadBye`; if BOTH report no matching dialog, respond `481` via the transaction (`tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil))`). Verify how `ReadBye` signals "no matching dialog" (an error value / sentinel) against sipgo and match on it; do not 481 a BYE that WAS handled.

In `sig/b2bua.go`, where `ReadInvite` failure currently returns 500, change to 400: `b.reject(req, tx, 400, "Bad Request")`.

For the A-leg Contact: verify whether passing a `*sip.ContactHeader` to `DialogServerSession.Respond` overrides the cache default (send the establishing 2xx via `Respond(200, "OK", sdpBody, contactHeader, contentTypeHeader)` instead of `RespondSDP`, replicating RespondSDP's Content-Type). If it overrides cleanly, build the Contact from `ourIP` + the inbound transport (the A-leg's transport — read from `req.Transport()`); if it does not, keep `RespondSDP` and document that the A-leg Contact uses the cache default (ourIP + primary transport) as the §5 fallback, noting it in the report.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -race -v`
Expected: PASS (481/400 correct; A-leg Contact per the chosen mechanism; all prior tests green).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): 481 for unknown-dialog BYE, 400 for malformed INVITE, per-transport A-leg Contact"
```

---

### Task 6: Roadmap + full verification

**Files:**
- Modify: `README.md`
- Test: full-suite + CLI smoke

**Interfaces:**
- Consumes: everything above.
- Produces: M4.1 marked in the roadmap; whole repo green.

- [ ] **Step 1: Update the README roadmap**

Split the M4 row to show M4.1 done and the rest pending (mirror the M3 sub-row style):

```markdown
| M4 | Trunk interop: From/CLI, REGISTER, session timers, PRACK, DNS SRV | in progress |
| ├ M4.1 | Outbound-INVITE realism: From/CLI, ring cap, response codes | ✅ done |
| ├ M4.2 | Outbound REGISTER | next |
| ├ M4.3 | Session timers (RFC 4028) + 100rel/PRACK | |
| └ M4.4 | DNS SRV + peer health/cooldown | |
```

(Replace only the single existing M4 row with these five lines; leave M5–M7 unchanged.)

- [ ] **Step 2: Full verification + smoke**

```bash
go vet ./... && go test ./... -race
```

Expected: vet clean; all packages (config, media, sig, callstate) PASS.

```bash
go build -o freesbc . && CARRIER_A_PASS=test ./freesbc run -c sbc.example.yaml & PID=$!
sleep 1; kill -TERM $PID; wait $PID; echo "exit=$?"
```

Expected: startup logs (`media plane ready`, `sip server listening`, `freesbc started`); clean `shutting down`; `exit=0`. (Use the scratchpad high-port copy if 5060/5061 are busy, per M3.1 Task 4's note.)

- [ ] **Step 3: Commit**

```bash
gofmt -l . && git add README.md && git commit -m "docs: mark M4.1 done in roadmap"
```

---

## Spec Coverage (M4.1)

| Spec section | Task |
|---|---|
| §1.1 From/CLI pass-through, our host | 2 |
| §1.2 ring cap, failover, 408 | 1, 4 |
| §1.3 response-code fidelity + precedence | 3, 4 |
| §1.4 481 (no-dialog BYE), 400 (malformed INVITE) | 5 |
| §4 config `ring_timeout` | 1 |
| §5 per-transport Contact (B-leg confirmed, A-leg best-effort) | 2, 5 |
| §6 error-handling table | 3, 4, 5 |
| §7 testing | 2, 3, 4, 5, 6 |

Deferred (spec §8): outbound REGISTER (M4.2); session timers + PRACK (M4.3); DNS SRV + peer health + configurable uniform failover code (M4.4); per-peer CLI override + PAI; full multi-transport A-leg Contact if the mechanism is unclean; declined-section SDP scrub (M4/M5); registry Call-ID uniqueness (M7).
