# FreeSBC M4.3 — Session Timers + 100rel Handling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Negotiate RFC 4028 session timers (Min-SE 422, refresher pushed to the endpoints, B-leg 422 retry), best-effort answer session-timer refresh re-INVITEs locally, honestly decline 100rel (420), and retry a REGISTER on 423.

**Architecture:** A pure `sig/timers.go` (parse/negotiate/detect, no I/O) drives header-level negotiation wired into the existing bridge. The SBC never *sends* a mid-dialog re-INVITE — it designates both endpoints as refreshers and only *answers* their refresh re-INVITEs (a spike with a 501 fallback), sidestepping the mid-dialog send that sipgo can't express.

**Tech Stack:** existing deps (sipgo v1.4.3, config/sig, Go stdlib). No new dependencies. Session-timer headers are generic (`sip.NewHeader`/`GetHeader`) — sipgo has no typed support.

**Spec:** `docs/superpowers/specs/2026-07-16-m4-3-session-timers-100rel-design.md`. Third of four M4 slices (M4.1/M4.2 done; M4.4 DNS SRV + peer health follows).

## Global Constraints

- Module `github.com/freesbc/freesbc`, Go ≥ 1.22. No new dependencies. English code/comments; stdlib testing only; `gofmt -l .` clean; final task runs `go vet ./... && go test ./... -race`.
- Config lifecycle (M1): read snapshots via `(*config.Store).Current()`; never mutate a published `*config.Config`.
- Must not regress M3.3/M4.1/M4.2: happy-path bridge, early media, failover, ring cap (`failRing`→408), response-code fidelity (`failReal`/`failDial`/`failUnusable`), 481/400, the re-INVITE 501 (except the session-timer-refresh case this plan adds), digest auth, registration + routing gate.
- Session-timer semantics (spec): A-leg 200 gets `Session-Expires;refresher=uac` (caller refreshes); B-leg INVITE gets `Supported: timer` + `Session-Expires;refresher=uas` + `Min-SE` (carrier refreshes), NO `Supported: 100rel`; inbound `Require: 100rel` → 420 + `Unsupported: 100rel`; inbound Session-Expires < `min_se` → 422 + `Min-SE`; B-leg 422 → retry once with the carrier's Min-SE; REGISTER 423 → retry once with `Min-Expires`.
- sipgo v1.4.3 facts (verified; re-verify per task, BLOCK if materially different): generic header build `sip.NewHeader(name, value) sip.Header`; read `req.GetHeader(name) sip.Header` (nil if absent) → `.Value() string`, or `req.GetHeaders(name) []sip.Header` for repeats; `req.AppendHeader(h)`, `req.RemoveHeader(name)`; status constants `sip.StatusBadExtension` = 420, `sip.StatusIntervalToBrief` = 423; **422 has no constant — use the literal `422` with reason `"Session Interval Too Small"`**. Both `*sip.Request` and `*sip.Response` satisfy `sip.Message` (which has `GetHeader`/`GetHeaders`).

---

### Task 1: Config — `session_expires` + `min_se`

**Files:**
- Modify: `config/schema.go` (Config, withDefaults), `config/validate.go`
- Modify: `sbc.example.yaml`
- Test: `config/schema_test.go`, `config/validate_test.go`

**Interfaces:**
- Consumes: `config.Duration`, `Config`, `withDefaults`, `validate` (M1/M4.1/M4.2).
- Produces: `Config.SessionExpires Duration` (yaml `session_expires`, default 1800s) and `Config.MinSE Duration` (yaml `min_se`, default 90s). Task 3/4 read `cfg.SessionExpires.Std()` / `cfg.MinSE.Std()`. Validation: `min_se ≥ 1s`, `session_expires ≥ min_se`.

- [ ] **Step 1: Write the failing tests**

Add to `TestWithDefaults` in `config/schema_test.go`:

```go
	if c.SessionExpires.Std() != 1800*time.Second {
		t.Errorf("session_expires default: %v", c.SessionExpires.Std())
	}
	if c.MinSE.Std() != 90*time.Second {
		t.Errorf("min_se default: %v", c.MinSE.Std())
	}
```

Add to the `cases` table in `TestValidateErrors` in `config/validate_test.go`:

```go
		{"min_se too small", func(c *Config) { c.MinSE = Duration(500 * time.Millisecond) }, "min_se"},
		{"session_expires below min_se", func(c *Config) {
			c.MinSE = Duration(120 * time.Second)
			c.SessionExpires = Duration(90 * time.Second)
		}, "session_expires"},
```

Add a parse test to `config/schema_test.go`:

```go
func TestParseSessionTimers(t *testing.T) {
	src := minimalYAML + "session_expires: 3600s\nmin_se: 120s\n"
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.SessionExpires.Std() != 3600*time.Second || c.MinSE.Std() != 120*time.Second {
		t.Errorf("got session_expires=%v min_se=%v", c.SessionExpires.Std(), c.MinSE.Std())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./config/ -run 'TestWithDefaults|TestValidateErrors|TestParseSessionTimers' -v`
Expected: FAIL (compile error: `SessionExpires`/`MinSE` undefined).

- [ ] **Step 3: Implement**

In `config/schema.go`, add to `Config` (after `RegisterExpires`):

```go
	SessionExpires Duration `yaml:"session_expires"` // RFC 4028 Session-Expires we advertise/accept
	MinSE          Duration `yaml:"min_se"`          // minimum session interval accepted (else 422)
```

In `withDefaults`:

```go
	if c.SessionExpires == 0 {
		c.SessionExpires = Duration(1800 * time.Second)
	}
	if c.MinSE == 0 {
		c.MinSE = Duration(90 * time.Second)
	}
```

In `config/validate.go`, after the `register_expires` check:

```go
	if c.MinSE.Std() < time.Second {
		fail("min_se: must be at least 1s, got %v", c.MinSE.Std())
	}
	if c.SessionExpires.Std() < c.MinSE.Std() {
		fail("session_expires: must be >= min_se (%v), got %v", c.MinSE.Std(), c.SessionExpires.Std())
	}
```

In `sbc.example.yaml`, near `register_expires`:

```yaml
session_expires: 1800s   # RFC 4028 session timer we advertise/accept (carrier may lower it)
min_se: 90s              # smallest session interval accepted; a lower request gets 422 + Min-SE
```

- [ ] **Step 4: Run the config suite**

Run: `go test ./config/ -v && go build -o freesbc . && CARRIER_A_PASS=test ./freesbc check -c sbc.example.yaml`
Expected: PASS; `sbc.example.yaml: config OK`.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add config/ sbc.example.yaml && git commit -m "feat(config): session_expires and min_se (RFC 4028 session timers)"
```

---

### Task 2: `sig/timers.go` — pure session-timer logic

**Files:**
- Create: `sig/timers.go`
- Test: `sig/timers_test.go`

**Interfaces:**
- Consumes: `sip.Message`/`sip.Request` header accessors, `sip.NewHeader`.
- Produces (Tasks 3–6 rely on these):
  - `func headerSeconds(m sip.Message, name string) time.Duration` — parse the leading delta-seconds of a header (before any `;`), 0 if absent/unparseable.
  - `func requires100rel(req *sip.Request) bool` — the request's `Require` header(s) list `100rel`.
  - `func negotiateSE(peerSE, sessionExpires, minSE time.Duration) time.Duration` — `min(peerSE or sessionExpires, sessionExpires)`, floored at `minSE`. (peerSE==0 → use sessionExpires.)
  - `func sessionExpiresHeader(d time.Duration, refresher string) sip.Header` — `Session-Expires: <secs>;refresher=<refresher>`.
  - `func isRefreshReInvite(req *sip.Request, establishedSDP []byte) bool` — an in-dialog INVITE carrying a Session-Expires whose offered SDP matches the established one (a timer refresh, not a media change).

- [ ] **Step 1: Write the failing test**

Create `sig/timers_test.go`:

```go
package sig

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

func reqWith(headers ...sip.Header) *sip.Request {
	r := sip.NewRequest(sip.INVITE, sip.Uri{Scheme: "sip", User: "x", Host: "h"})
	for _, h := range headers {
		r.AppendHeader(h)
	}
	return r
}

func TestHeaderSeconds(t *testing.T) {
	r := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	if got := headerSeconds(r, "Session-Expires"); got != 1800*time.Second {
		t.Errorf("got %v, want 1800s", got)
	}
	r2 := reqWith(sip.NewHeader("Min-SE", "90"))
	if got := headerSeconds(r2, "Min-SE"); got != 90*time.Second {
		t.Errorf("got %v, want 90s", got)
	}
	if got := headerSeconds(reqWith(), "Session-Expires"); got != 0 {
		t.Errorf("absent header should be 0, got %v", got)
	}
	if got := headerSeconds(reqWith(sip.NewHeader("Session-Expires", "junk")), "Session-Expires"); got != 0 {
		t.Errorf("unparseable should be 0, got %v", got)
	}
}

func TestRequires100rel(t *testing.T) {
	if !requires100rel(reqWith(sip.NewHeader("Require", "100rel"))) {
		t.Error("Require: 100rel should be detected")
	}
	if !requires100rel(reqWith(sip.NewHeader("Require", "timer, 100rel"))) {
		t.Error("Require: timer, 100rel should be detected")
	}
	if requires100rel(reqWith(sip.NewHeader("Supported", "100rel"))) {
		t.Error("Supported (not Require) must not count")
	}
	if requires100rel(reqWith()) {
		t.Error("no Require header → false")
	}
}

func TestNegotiateSE(t *testing.T) {
	se, min := 1800*time.Second, 90*time.Second
	if got := negotiateSE(3600*time.Second, se, min); got != 1800*time.Second {
		t.Errorf("caller higher → ours (1800s), got %v", got)
	}
	if got := negotiateSE(600*time.Second, se, min); got != 600*time.Second {
		t.Errorf("caller lower → caller (600s), got %v", got)
	}
	if got := negotiateSE(30*time.Second, se, min); got != 90*time.Second {
		t.Errorf("below floor → min_se (90s), got %v", got)
	}
	if got := negotiateSE(0, se, min); got != 1800*time.Second {
		t.Errorf("no caller SE → ours (1800s), got %v", got)
	}
}

func TestSessionExpiresHeader(t *testing.T) {
	h := sessionExpiresHeader(1800*time.Second, "uac")
	if h.Name() != "Session-Expires" || h.Value() != "1800;refresher=uac" {
		t.Errorf("got %s: %q", h.Name(), h.Value())
	}
}

func TestIsRefreshReInvite(t *testing.T) {
	established := []byte("v=0\r\nm=audio 40000 RTP/AVP 0\r\n")
	// In-dialog (To-tag) + Session-Expires + same SDP → refresh.
	refresh := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	refresh.To().Params.Add("tag", "abc")
	refresh.SetBody(established)
	if !isRefreshReInvite(refresh, established) {
		t.Error("in-dialog + Session-Expires + same SDP should be a refresh")
	}
	// Same but different SDP → media change, not a refresh.
	media := reqWith(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
	media.To().Params.Add("tag", "abc")
	media.SetBody([]byte("v=0\r\nm=audio 50000 RTP/AVP 0\r\n"))
	if isRefreshReInvite(media, established) {
		t.Error("changed SDP is a media re-INVITE, not a refresh")
	}
	// No Session-Expires → not a refresh.
	noSE := reqWith()
	noSE.To().Params.Add("tag", "abc")
	noSE.SetBody(established)
	if isRefreshReInvite(noSE, established) {
		t.Error("no Session-Expires → not a refresh")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run 'TestHeaderSeconds|TestRequires100rel|TestNegotiateSE|TestSessionExpiresHeader|TestIsRefreshReInvite' -v`
Expected: FAIL (compile error: functions undefined).

- [ ] **Step 3: Implement**

Create `sig/timers.go`:

```go
package sig

import (
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

// headerSeconds parses the leading delta-seconds value of a header (the
// number before any ';' parameters), e.g. "1800;refresher=uac" → 1800s.
// Returns 0 if the header is absent or unparseable.
func headerSeconds(m sip.Message, name string) time.Duration {
	h := m.GetHeader(name)
	if h == nil {
		return 0
	}
	v := h.Value()
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// requires100rel reports whether any Require header lists the 100rel option
// tag (reliable provisional responses, which we do not support).
func requires100rel(req *sip.Request) bool {
	for _, h := range req.GetHeaders("Require") {
		for _, tag := range strings.Split(h.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(tag), "100rel") {
				return true
			}
		}
	}
	return false
}

// negotiateSE picks the session interval to advertise: the smaller of the
// peer's requested value (when present) and our configured sessionExpires,
// never below minSE.
func negotiateSE(peerSE, sessionExpires, minSE time.Duration) time.Duration {
	se := sessionExpires
	if peerSE > 0 && peerSE < se {
		se = peerSE
	}
	if se < minSE {
		se = minSE
	}
	return se
}

// sessionExpiresHeader builds a Session-Expires header with a refresher param.
func sessionExpiresHeader(d time.Duration, refresher string) sip.Header {
	return sip.NewHeader("Session-Expires", strconv.Itoa(int(d.Seconds()))+";refresher="+refresher)
}

// isRefreshReInvite reports whether an in-dialog INVITE is a session-timer
// refresh: it carries a Session-Expires and its offered SDP is byte-identical
// to the established one (a media-changing re-INVITE differs and is handled
// separately). Callers ensure req is in-dialog (has a To-tag) before asking.
func isRefreshReInvite(req *sip.Request, establishedSDP []byte) bool {
	if headerSeconds(req, "Session-Expires") == 0 {
		return false
	}
	return string(req.Body()) == string(establishedSDP)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./sig/ -run 'TestHeaderSeconds|TestRequires100rel|TestNegotiateSE|TestSessionExpiresHeader|TestIsRefreshReInvite' -v`
Expected: PASS. Verify `sip.Message` has `GetHeader`/`GetHeaders` and `h.Name()` exists — adjust if the API differs (Step 1's `reqWith` compiles against the real API).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/timers.go sig/timers_test.go && git commit -m "feat(sig): pure session-timer parsing/negotiation helpers"
```

---

### Task 3: Inbound gating — 420 for Require:100rel, 422 for low Session-Expires

**Files:**
- Modify: `sig/b2bua.go` (`onInvite`, before the bridge)
- Test: `sig/b2bua_test.go`

**Interfaces:**
- Consumes: `requires100rel`, `headerSeconds` (Task 2); `cfg.MinSE` (Task 1); the existing `bridge.reject` helper and the in-dialog re-INVITE detection (M3.3 To-tag check).
- Produces: an inbound INVITE is rejected early with 420 (Require:100rel) or 422 (Session-Expires < min_se) before any bridging.

- [ ] **Step 1: Write the failing test**

Add to `sig/b2bua_test.go` (raw-UDP, reusing the M3.3/M4.1 helpers):

```go
func TestBridgeRejects100relRequire(t *testing.T) {
	startServer(t, 45410, knownPeerCfg) // adjust port
	got := roundTripWithHeaders(t, 45410, "INVITE", "req100rel-1", 3*time.Second, "SIP/2.0 420",
		"Require: 100rel")
	if !strings.Contains(got, "SIP/2.0 420") {
		t.Fatalf("Require:100rel must get 420, got:\n%s", got)
	}
	if !strings.Contains(strings.ToLower(got), "unsupported: 100rel") {
		t.Errorf("420 should carry Unsupported: 100rel, got:\n%s", got)
	}
}

func TestBridgeRejectsLowSessionExpires(t *testing.T) {
	// Config min_se default 90s; a Session-Expires of 30 → 422 + Min-SE.
	startServer(t, 45412, knownPeerCfg) // adjust port; ensure min_se default applies
	got := roundTripWithHeaders(t, 45412, "INVITE", "lowse-1", 3*time.Second, "SIP/2.0 422",
		"Session-Expires: 30")
	if !strings.Contains(got, "SIP/2.0 422") {
		t.Fatalf("low Session-Expires must get 422, got:\n%s", got)
	}
	if !strings.Contains(strings.ToLower(got), "min-se:") {
		t.Errorf("422 should carry Min-SE, got:\n%s", got)
	}
}
```

Add a `roundTripWithHeaders` helper (or extend `sipRequest`) that injects extra header lines into the raw INVITE. Write it complete — no placeholders. Fresh ports (45410–45419).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run 'TestBridgeRejects100relRequire|TestBridgeRejectsLowSessionExpires' -v`
Expected: FAIL — no gating yet; a Require:100rel INVITE routes/404s and a low Session-Expires is ignored.

- [ ] **Step 3: Implement**

In `sig/b2bua.go` `onInvite`, after the identify gate and the M3.3 in-dialog re-INVITE branch (which handles To-tagged requests — the gating below is for INITIAL INVITEs only), before `Resolve`/`ReadInvite`, add:

```go
	if requires100rel(req) {
		res := sip.NewResponseFromRequest(req, sip.StatusBadExtension, "Bad Extension", nil)
		res.AppendHeader(sip.NewHeader("Unsupported", "100rel"))
		_ = tx.Respond(res)
		b.s.log.Info("declined Require: 100rel", "source", req.Source())
		return
	}
	if se := headerSeconds(req, "Session-Expires"); se > 0 {
		if minSE := cfg.MinSE.Std(); se < minSE {
			res := sip.NewResponseFromRequest(req, 422, "Session Interval Too Small", nil)
			res.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(int(minSE.Seconds()))))
			_ = tx.Respond(res)
			b.s.log.Info("rejected low Session-Expires", "requested", se, "min_se", minSE)
			return
		}
	}
```

`cfg` is the snapshot already fetched in `onInvite` (`cfg := b.s.store.Current()`); place the gating after that fetch. Ensure `strconv` is imported. Verify `sip.NewResponseFromRequest` + `res.AppendHeader` and that responding via the raw `tx` before `ReadInvite` mirrors the existing `reject` path (M3.3).

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -race -v`
Expected: PASS (420/422 gating; all prior bridge tests still green — a normal INVITE with no Require:100rel and no low Session-Expires is unaffected).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): 420 Require:100rel and 422 low Session-Expires at the front door"
```

---

### Task 4: Session-timer headers on the A-leg 200 and B-leg INVITE

**Files:**
- Modify: `sig/b2bua.go` (A-leg answer path; B-leg INVITE build in `dialTarget`)
- Test: `sig/b2bua_test.go`

**Interfaces:**
- Consumes: `negotiateSE`, `sessionExpiresHeader`, `headerSeconds` (Task 2); `cfg.SessionExpires`/`cfg.MinSE` (Task 1); the A-leg request (for the caller's Session-Expires) and the B-leg INVITE headers passed to `dialogCli.Invite`.
- Produces: the caller's 200 carries `Session-Expires;refresher=uac` + `Supported: timer`; the B-leg INVITE carries `Supported: timer` + `Session-Expires;refresher=uas` + `Min-SE`, and no `Supported: 100rel`.

- [ ] **Step 1: Write the failing test**

Add `TestBridgeSessionTimerHeaders` to `sig/b2bua_test.go`: establish a call (M3.3 harness). Have the stub carrier capture the B-leg INVITE's headers; have the UAC read the A-leg 200's headers. Assert the B-leg INVITE carries `Supported: timer`, `Session-Expires: <n>;refresher=uas`, `Min-SE: 90`, and NOT `Supported: 100rel`; assert the A-leg 200 carries `Session-Expires: <n>;refresher=uac` and `Supported: timer`. Write the complete test; reuse the From/Contact-capture pattern from M4.1's `TestBridgeOutboundFromAndContact`. Fresh ports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestBridgeSessionTimerHeaders -v`
Expected: FAIL — no session-timer headers added yet.

- [ ] **Step 3: Implement**

In `dialTarget`, where the B-leg INVITE headers (From/Contact from M4.1) are built and passed to `dialogCli.Invite`, add the session-timer headers:

```go
	seB := cfg.SessionExpires.Std()
	bHeaders := []sip.Header{
		b.buildFrom(req, ourIP, port),
		b.buildContact(ourIP, port, target.Peer.Transport),
		sip.NewHeader("Supported", "timer"),
		sessionExpiresHeader(seB, "uas"),
		sip.NewHeader("Min-SE", strconv.Itoa(int(cfg.MinSE.Std().Seconds()))),
	}
	// ... dialogCli.Invite(ctx, peerURI(target.Peer), bOffer, bHeaders...) ...
```

(Keep the existing From/Contact; just append the three timer headers to the variadic. Do NOT add `Supported: 100rel`.)

For the A-leg answer, where the establishing 200 is sent (M4.1 changed this to `aLeg.Respond(200, "OK", aAnswer, contentType, contact)`), add the session-timer headers computed from the caller's request:

```go
	negotiated := negotiateSE(headerSeconds(req, "Session-Expires"), cfg.SessionExpires.Std(), cfg.MinSE.Std())
	aHeaders := []sip.Header{
		contentTypeHeader, // existing
		contactHeader,     // existing (M4.1 A-leg Contact)
		sessionExpiresHeader(negotiated, "uac"),
		sip.NewHeader("Supported", "timer"),
	}
	// ... aLeg.Respond(200, "OK", aAnswer, aHeaders...) ...
```

Verify the exact variadic shape of the M4.1 `aLeg.Respond(...)` call and append rather than replace the existing Content-Type/Contact headers.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -race -v`
Expected: PASS (headers present on both legs; happy path + all prior tests still green).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): advertise session timers on A-leg 200 (refresher=uac) and B-leg INVITE (refresher=uas)"
```

---

### Task 5: B-leg 422 retry with the carrier's Min-SE

**Files:**
- Modify: `sig/b2bua.go` (`dialTarget`)
- Test: `sig/b2bua_test.go`

**Interfaces:**
- Consumes: the B-leg answer (`bLeg.InviteResponse`), `headerSeconds` (Task 2), the Task 4 B-leg header build.
- Produces: a target that answers `422` with a `Min-SE` is retried once with `Session-Expires = carrier Min-SE`; a second 422 is a normal `failReal` → failover.

- [ ] **Step 1: Write the failing test**

Add `TestBridgeBLeg422RetriesWithMinSE`: a stub carrier that 422s the first INVITE (with `Min-SE: 1800`) if the INVITE's Session-Expires is below 1800, then 200s the retry that meets it. Assert the call bridges (200 to caller) and the carrier saw two INVITEs, the second with `Session-Expires: 1800` (or higher). Use a low test `session_expires` (e.g. 600s) so the first attempt is below the carrier's Min-SE. Fresh ports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestBridgeBLeg422RetriesWithMinSE -v`
Expected: FAIL — a 422 currently classifies as `failReal` → failover/last-code, no retry.

- [ ] **Step 3: Implement**

In `dialTarget`, after `WaitAnswer` when the final response is `422` (before the M4.1 `failReal` classification), read the carrier's `Min-SE` and, if this attempt hasn't already retried, rebuild the B-leg INVITE with `Session-Expires = carrier Min-SE` and place it once more:

```go
	if bLeg.InviteResponse != nil && bLeg.InviteResponse.StatusCode == 422 && !retried422 {
		carrierMinSE := headerSeconds(bLeg.InviteResponse, "Min-SE")
		if carrierMinSE > 0 {
			retried422 = true
			bLeg.Close()
			// rebuild bHeaders with sessionExpiresHeader(carrierMinSE, "uas") replacing the SE header,
			// re-Invite, re-WaitAnswer, and fall through to normal classification.
			... place the B-leg again with the larger Session-Expires ...
		}
	}
```

Structure this as a bounded retry loop inside `dialTarget` (at most one 422 retry per target) or a small helper, so the winning 200 flows into the existing bridge path and a second 422 flows into `failReal`. Keep the M4.1 answered-B-leg teardown rules (a 422 is a non-2xx final — un-answered, so just `Close`, no ACK/BYE). Verify `bLeg.InviteResponse` holds the 422 after `WaitAnswer` returns its error (M4.1's guard pattern).

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -race -v`
Expected: PASS (422→retry→bridge; a persistent 422 still fails over; all prior tests green). Timing-based — re-run once before flake.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): retry the B-leg INVITE once with the carrier's Min-SE on 422"
```

---

### Task 6: Refresh re-INVITE — local 200 answer (SPIKE with 501 fallback)

**Files:**
- Modify: `sig/b2bua.go` (the in-dialog re-INVITE branch in `onInvite`; store the established SDP per call)
- Test: `sig/b2bua_test.go`

**Interfaces:**
- Consumes: `isRefreshReInvite` (Task 2), the established call's SDP, `sessionExpiresHeader`; the M3.3 in-dialog (To-tag) re-INVITE detection.
- Produces: a session-timer refresh re-INVITE is answered with a local `200 OK` (echoing the established SDP + a refreshed `Session-Expires`), instead of the M3.3 blanket 501. A media-changing re-INVITE still gets 501.

**This is a spike.** M3.3 found *bridging* a re-INVITE infeasible; *locally answering* one (no forwarding, no `DialogServerSession.ReadInvite`) is the smaller bet. Verify against sipgo whether a bare `tx.Respond(200)` on an in-dialog INVITE server transaction is accepted and its ACK routes without error/corruption. **If it is not clean** (ACK mis-routing, dialog-state complaints, retransmission issues), STOP and report: keep the 501 for refresh re-INVITEs too and document the limitation — that is an acceptable outcome, not a failure. Do NOT force a fragile hack.

- [ ] **Step 1: Write the failing test**

Add `TestBridgeAnswersSessionTimerRefresh`: establish a call (M3.3 harness), then send an in-dialog re-INVITE from the UAC carrying `Session-Expires` and the SAME SDP as the established call (a timer refresh). Assert the response is `200 OK` (not 501) with a `Session-Expires` header, and that the established call still works afterward (BYE completes, registry empties). Also assert a re-INVITE with a CHANGED SDP still gets 501. Reuse the established-call + real-To-tag technique from M3.3's `TestBridgeReInviteDuringCallDoesNotBreakCall`. Fresh ports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestBridgeAnswersSessionTimerRefresh -v`
Expected: FAIL — the refresh re-INVITE currently gets 501.

- [ ] **Step 3: Implement**

The bridge must remember each established call's SDP so `isRefreshReInvite` can compare. Store it where the call is bridged (e.g. on the call's state alongside the registry entry, keyed by Call-ID, or on a per-call struct the `onInvite` goroutine holds). In `onInvite`'s in-dialog re-INVITE branch (currently: To-tag present → 501), branch instead:

```go
	if hasToTag {
		if establishedSDP, ok := b.s.callSDP(callID(req)); ok && isRefreshReInvite(req, establishedSDP) {
			res := sip.NewResponseFromRequest(req, 200, "OK", establishedSDP)
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			res.AppendHeader(sessionExpiresHeader(headerSeconds(req, "Session-Expires"), refresherOf(req)))
			if err := tx.Respond(res); err != nil {
				b.reject(req, tx, 501, "Not Implemented") // fallback
			}
			return
		}
		b.reject(req, tx, 501, "Not Implemented") // media-change or unknown re-INVITE (M3.3)
		return
	}
```

Add the per-call SDP lookup (`Server.callSDP(callID) ([]byte, bool)` backed by a small map populated at bridge time and cleared at teardown, or reuse the callstate registry by adding the SDP to the `Call` record — but callstate must stay dependency-free; a separate map in `sig` is cleaner). Add `refresherOf(req)` returning the refresher the SBC expects (`uac` for the A-leg, `uas` for the B-leg — determine from which dialog the re-INVITE matched; if ambiguous, echo the request's own refresher). If the ACK-routing spike fails, this whole branch reverts to the M3.3 501 and the test asserts the documented fallback instead.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -race -v`
Expected: PASS — refresh re-INVITE → 200, call survives; media-change re-INVITE → 501; all prior tests green. If BLOCKED (sipgo can't cleanly answer the re-INVITE), the committed state keeps 501 and the test asserts 501 with a documented limitation in the report.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "feat(sig): locally answer session-timer refresh re-INVITEs with 200 (fallback 501 if infeasible)"
```

---

### Task 7: REGISTER 423 retry with Min-Expires (M4.2 carry-over)

**Files:**
- Modify: `sig/register.go` (`registerOnce`)
- Test: `sig/register_test.go`

**Interfaces:**
- Consumes: `registerOnce` (M4.2), `headerSeconds` (Task 2).
- Produces: on a `423 Interval Too Brief`, `registerOnce` reads `Min-Expires` and retries once requesting that value.

- [ ] **Step 1: Write the failing test**

Add to `sig/register_test.go`: extend the stub registrar so it 423s (with `Min-Expires: 3600`) any REGISTER whose Expires is below 3600, then 200s a REGISTER meeting it. Test that `registerOnce` requesting 1800s succeeds with a granted 3600s (proving the 423 retry):

```go
func TestRegisterOnceRetriesOn423(t *testing.T) {
	reg := startStubRegistrarMinExpires(t, 45340, "u", "p", 3600) // 423 below 3600, then grant
	client := reg.client(t)
	p := regParams{
		Name: "carrier", RegistrarHost: "127.0.0.1", RegistrarPort: 45340,
		Transport: "udp", Username: "u", Password: "p",
		ContactIP: netip.MustParseAddr("127.0.0.1"), ContactPort: 45995,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	granted, err := registerOnce(ctx, client, p, 1800*time.Second) // below Min-Expires 3600
	if err != nil {
		t.Fatalf("registerOnce: %v", err)
	}
	if granted != 3600*time.Second {
		t.Errorf("granted = %v, want 3600s (retried with Min-Expires)", granted)
	}
}
```

Write the `startStubRegistrarMinExpires` variant (or extend the Task 3-of-M4.2 stub registrar to enforce a Min-Expires). No placeholders. Fresh port.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./sig/ -run TestRegisterOnceRetriesOn423 -v`
Expected: FAIL — a 423 currently returns an error (`register rejected: 423`), no retry.

- [ ] **Step 3: Implement**

In `sig/register.go` `registerOnce`, after the digest step, before the final `res.StatusCode != 200` error, handle 423:

```go
	if res.StatusCode == sip.StatusIntervalToBrief {
		minExp := headerSeconds(res, "Min-Expires")
		if minExp > expires && minExp > 0 {
			// Rebuild and resend once with the registrar's minimum.
			return registerOnceNoRetry(ctx, client, p, minExp)
		}
	}
```

Refactor so the single-attempt body (build → Do → digest → parse) is a helper `registerOnceNoRetry(ctx, client, p, expires)` and `registerOnce` calls it, then applies the one 423 retry — avoiding unbounded recursion (the retry uses `registerOnceNoRetry`, which does not itself retry). Read `Min-Expires` from the 423 response via `headerSeconds`. Verify `sip.StatusIntervalToBrief` == 423.

- [ ] **Step 4: Run the tests (race on)**

Run: `go test ./sig/ -run 'TestRegister|TestRegistrar' -race -v`
Expected: PASS (423 retry succeeds; all M4.2 registration tests still green).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && git add sig/ && git commit -m "fix(sig): retry REGISTER once with Min-Expires on 423 Interval Too Brief"
```

---

### Task 8: Roadmap + full verification

**Files:**
- Modify: `README.md`
- Test: full-suite + CLI smoke

**Interfaces:**
- Consumes: everything above.
- Produces: M4.3 marked done; whole repo green.

- [ ] **Step 1: Update the README roadmap**

Mark M4.3 done and M4.4 next (change only these two sub-rows):

```markdown
| ├ M4.3 | Session timers (RFC 4028) + 100rel/PRACK | ✅ done |
| └ M4.4 | DNS SRV + peer health/cooldown | next |
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

Expected: startup logs (`media plane ready`, `sip server listening`, `freesbc started`, an expected `register failed` WARN for `sip.carrier-a.com`); clean `shutting down`; `exit=0`. (Use the scratchpad high-port copy if 5060/5061 are busy.)

- [ ] **Step 3: Commit**

```bash
gofmt -l . && git add README.md && git commit -m "docs: mark M4.3 done in roadmap"
```

---

## Spec Coverage (M4.3)

| Spec section | Task |
|---|---|
| §1.1/§3 session-timer negotiation, refresher designation | 4 |
| §1.2 100rel decline (420) | 3 |
| §1.3 config session_expires/min_se, Min-SE 422 | 1, 3 |
| §1.4 REGISTER 423 retry | 7 |
| §2 sig/timers.go pure logic | 2 |
| §3 B-leg 422 retry | 5 |
| §4 refresh re-INVITE local answer (spike) | 6 |
| §6 error handling | 3, 4, 5, 6, 7 |
| §7 testing | 2–7 |

Deferred (spec §8): real 100rel/PRACK reliable provisionals; media-renegotiation re-INVITE (still 501); SBC-side session-timer expiry teardown (RTP watchdog remains); per-peer session-timer config; a carrier forcing refresher=uac on the B-leg; UPDATE-method refresh. If Task 6's spike is BLOCKED, refresh re-INVITEs also stay 501 (documented).
