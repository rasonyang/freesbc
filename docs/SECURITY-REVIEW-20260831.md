# FreeSBC Focused Security Code Review (post-audit increment)

- Review date: 2026-08-31
- Review baseline: `b998f0883c363f4890f950f576d9de99d52c5630` (the review HEAD of `docs/SECURITY-AUDIT-20260826.md`)
- Scope: all changes in `b998f08..HEAD` (3 commits) plus re-verification of the audit's High findings against the current HEAD
- Review HEAD: `7fe89d9` (fix(sig): honor ring_timeout against silent targets)
- Method: line-by-line diff review + line-level cross-checking of the `WaitAnswer`/`inviteCancel` behavior the new code depends on against the sipgo v1.4.3 upstream sources (local module cache copy) + actual build/vet/test runs on Go 1.27.0 (this closes the largest evidence gap listed in audit §6/§8 — "no Go toolchain available")
- Authorization: the repository owner authorized this review. Read-only review plus local test verification (including baseline tests in a temporary git worktree); no production code was modified.

> Structure: §1 change overview; §2 focused review of the ring_timeout fix (7fe89d9) — the main subject of this review; §3 webui change (7c99323); §4 interop test assets (13a5d93); §5 re-verification of audit findings against the current HEAD; §6 overall conclusion and P0 classification. The audit's original numbering scheme (F-01…F-21, the D series, T-01…T-37) is carried over unchanged.

---

## 1. Change Overview

| commit | Content | Initial security assessment |
|---|---|---|
| `7fe89d9` fix(sig): honor ring_timeout | In `dialTarget`, `WaitAnswer` races the per-attempt deadline, the attempt is abandoned after a 250ms grace window, and an orphan goroutine acts as the backstop that tears down a late 2xx with ACK+BYE | **Main review subject** (§2) |
| `7c99323` fix(admin): Config tab auto-load | The webui now fetches `/api/config/raw` automatically the first time the Config tab is opened (with a re-entrancy guard) | Clean (§3) |
| `13a5d93` test(interop) | SIPp+FreeSWITCH real-world scenario suite + `test/interop/sbc.yaml` + sipp scenario XML + RTP pcap | Clean (§4) |

## 2. Focused Review of the ring_timeout Fix (7fe89d9)

### 2.1 What was fixed and why

When a target **never sends any response**, sipgo v1.4.3's `WaitAnswer` enters `inviteCancel`, and per RFC 3261 §9.1 (no CANCEL may be sent without a provisional response) `inviteCancel` blocks until the INVITE transaction dies at Timer_B (~32s) — so a blackhole target pinned every dial attempt for ~32s and `ring_timeout`/failover were completely ineffective (interop report F1).

The fix (`sig/b2bua.go:818-919`) moves `WaitAnswer` into a derived goroutine racing `attemptCtx` (the per-attempt ring budget). If the deadline fires first, a 250ms grace window waits for `waited` to deliver; if nothing is delivered, `abandoned` is set, `cancel()` is called, and the attempt returns classified as failRing. A late 2xx is torn down by the orphan goroutine via `ackThenBye`. Measured (interop T4b), failover away from the blackhole carrier-a dropped from 32.004s to 4.256s.

### 2.2 New Findings

#### [S-01] Orphan goroutine escapes recoverCall protection: a panic kills the whole process — Medium
- Location: sig/b2bua.go:848-866 (`go func(bLeg, attemptCtx) { WaitAnswer...; ackThenBye... }`)
- Facts: before the fix, `WaitAnswer`/`relay` (relayProvisional→processAnswerSDP→aLeg.Respond)/teardown all ran inline on the onInvite goroutine, protected by `recoverCall` (b2bua.go:1437, the sole line of defense per audit D1-8) — a panic lost only one call. After the fix this code runs on an **orphan goroutine with no recover**, spawned per dial attempt: a panic anywhere (including a nil-deref induced by a concurrency race, see S-02) means process exit (Go semantics), taking down every in-flight call and the media plane with it. sipgo's `inviteCancel`/`Do(CANCEL)`/`WriteAck` paths had never before run unguarded on a FreeSBC-side goroutine.
- Fix: add `defer recover()` inside the goroutine (Error log + normal exit); add a regression test that injects a panic and asserts the process survives.

#### [S-02] The 250ms grace window is a heuristic: after the timeout two goroutines touch dialog and media state concurrently — Low-Medium
- Location: sig/b2bua.go:888-918 (grace select); :849-853 (OnResponse→relay)
- Mechanism 1 (grace timeout race): if the orphan goroutine's `relay` does not finish within the grace window — A-leg TCP write blocking (F-02: SIP TCP connections have no write timeout), or a response arriving just before the deadline with slow SDP/SRTP processing — the main path abandons the attempt, dials the next target as usual, and calls `aLeg.Respond`, **calling the same `DialogServerSession.Respond` concurrently** with the orphan relay. Confirmed: sipgo dialog_server.go:264-283 `WriteResponse` takes no lock at all (it writes `s.Dialog.InviteResponse` directly) → a data race on dialog state, which can in turn induce a panic (feeding S-01). The `media.Session` side (SetSRTP atomic pointer, Relatch under lock) is safe in isolation, but the semantic overwrite (last writer wins) is unprotected.
- Mechanism 2 (select randomness): in sipgo dialog_client.go:246-261, the `WaitAnswer` main loop's `select` picks at random when `tx.Responses()` and `ctx.Done()` are both ready — so even after the deadline it may take the response branch and relay several more rounds (stretched further under a response flood).
- One-line fix (closes both entry points at once):
  ```go
  OnResponse: func(res *sip.Response) error {
      if abandoned.Load() { return nil }   // the main path has already abandoned this attempt
      responded.Store(true)
      return relay(res)
  }
  ```
- Regression: inject a late 18x and assert aLeg.Respond is not invoked; assert the grace-window edge is clean under -race.

#### [S-03] Live transactions against silent targets go from serial to parallel (an amplifier for F-06/F-19) — Low
- Location: sig/b2bua.go:862-866, 897-918 (abandon path)
- Mechanism: every abandoned silent target leaves behind a live INVITE transaction plus a goroutine that survives until Timer_B (~32s) (before the fix there was a single serially-blocked onInvite goroutine) → K silent targets = K concurrent transactions/goroutines per INVITE. At the same time, media port hold time rises from 32s to `ring_timeout` (**60s by default**, config/schema.go:162-163) — the 60s hold time estimated in audit F-06 only now actually holds for silent targets.
- Impact: under an INVITE flood with spoofed peer source IPs (F-07, fully exempt from rate limiting), transaction-layer memory and goroutine count are multiplied by K.
- Conclusion: **T-06 (per-peer concurrency quota) and T-18 (lax peer rate limiting) rise in priority** — they were already in the audit's first/second tier, and this finding is additional justification.

#### [S-04] The Ack in ackThenBye has no timeout: the orphan goroutine can linger forever — Low
- Location: sig/b2bua.go:1412-1423 (ackThenBye); :863, :995 (both pass `context.Background()`)
- Mechanism: BYE has a 5s ceiling via `byeContext` (:384-386), but `bLeg.Ack(ctx)` uses the caller's ctx — and both the orphan path and the raced-2xx main path pass `context.Background()`. If the B-leg TCP connection blackholes, the Ack write blocks (outbound connections likewise have no write timeout) → permanent goroutine leak.
- Fix: use a 5s-scale `byeContext` for Ack as well.

#### [S-05] A 100 Trying already sets responded: a target that only sends 100 and then goes silent is never cooled down — Info
- Location: sig/b2bua.go:850-852 (`responded.Store(true)` fires for any response)
- Impact: `penalize: !responded.Load()` (:909) means a target that sends only a 100 Trying and then goes silent is never cooled down, adding noise to the endpoint health mechanism. Not a security issue; recorded for the record.

### 2.3 Suspicions Ruled Out (verified against the sipgo sources)

1. **Late-18x media hijacking — unreachable**. The concern was that the orphan goroutine might relay a late 18x within the ~32s window after abandonment: `processAnswerSDP` would call `SetSRTP(SideB, attacker context)` + `Relatch(SideB, attacker address)`, letting a malicious carrier (an already configured peer) swap the media of an established call for its own audio (call injection on par with F-08). Verified against sipgo dialog_client.go:251-257 and 349-401: after ctx.Done, `WaitAnswer` goes straight into `inviteCancel`, and **`OnResponse` is never invoked inside inviteCancel** (with `InviteResponse==nil` it only waits for the first response to decide whether to CANCEL; with a provisional present, loop_487 only waits for a 487/64×T1 and no longer calls back for responses in between). The only residual exposure is the select randomness in §S-02 (millisecond scale).
2. Double ackThenBye — unreachable (teardown happens on either the abandon path or the main path, never both: the `abandoned.Load()` gate and the main path's unconditional teardown are mutually exclusive).
3. The buffered `waited` channel means the orphan goroutine's send never blocks, so an early return from the main path is not a leak.
4. Orphan goroutine lifetime is bounded: ≤~64s (Timer_B + CANCEL transaction Timer_F + loop_487 64×T1) — this is the concurrency amplification of §S-03, not a leak.
5. `bLeg`/`attemptCtx` are passed as parameters rather than captured by closure (:848), avoiding a data race on shared return slots (the commit message says as much, and -race confirms it).

### 2.4 Test Reality (first full run after the audit's evidence gap was closed)

| Command | Result |
|---|---|
| `go build ./...` | ✅ Passed (go1.27.0, `~/go-toolchain`) |
| `go vet ./...` | ✅ No warnings |
| `go test ./...` | admin/callstate/config/media/shield all green; **the sig package is flaky** (see below) |
| `go test ./sig/ -race` | Passed once (the flake did not reproduce in this run) |

- **The flakiness is pre-existing at the baseline, not introduced here**: baseline `b998f08` (in a temporary worktree) failed the same way across three runs — `TestBridgeAnswersSessionTimerRefresh` / `TestBridgeBrokenAnswerSDPGets502` / `TestBridgeSRTPRequiredBNoCryptoFailsOver` / `TestBridgeDigestAuth`, with a failure signature of ~3.16-3.26s (the 3s in-test timeout), and a different set of failing tests each run; the same happens at HEAD. The commit message's claim that "full suite passes with -race" does not reproduce on this machine (environment difference). The ~82 `WARN UDP ref went negative on try close` lines per run (sipgo connection-pool refcount noise) are likewise pre-existing at the baseline.
- New test coverage: successful failover (asserted within 2s) + caller-cancel classification. **Not covered**: raced-2xx teardown, the grace-window edge, and late responses after abandonment — these three regressions should be added when S-01/S-02 are fixed.

## 3. webui Change (7c99323): clean

- The new code only assigns via `textContent`/`.value` (`configText.value = text`), with no new innerHTML/eval sinks; the fetch is a GET with `credentials: same-origin`, inside the existing Basic Auth boundary; the `configLoading` re-entrancy guard is correct (unconditional reset at the tail of the `.then` chain).
- One note: opening the Config tab now automatically renders the raw config, which contains plaintext credentials (the same exposure boundary as the existing Load button, so not a new vulnerability) — but it makes the browser disk-cache problem in **F-18 (T-16 Cache-Control: no-store)** more concrete.

## 4. interop Test Assets (13a5d93): clean

- The `password_hash` in `test/interop/sbc.yaml` was verified with bcrypt to match **testpass123** (a test password, not a production credential); `g711a.pcap` is an upstream SIPp sample (a strings scan found no Authorization/password or other sensitive fields); the sipp scenario XML contains no sensitive information.
- The file header correctly warns that 5070 conflicts with the sig package integration test port (stop the instance before running the suite); no security concerns.

## 5. Re-verification of Audit Findings Against the Current HEAD

- **Change surface**: `git diff b998f08..HEAD --name-only` covers only `admin/webui/index.html` and `sig/b2bua.go` (plus tests, docs and interop assets) — the other 70 .go files are unchanged since the audit, so all of the audit's line-number-based conclusions still hold as written.
- **High findings re-verified item by item (grep/Read done directly for this review)**:
  - F-03: shield/shield.go:81-86 still applies the scanner ban before the rate limit at :87-92 ✔
  - F-04: shield/nftables.go:62-63 `ip saddr @banned4 drop` still has no dport/protocol qualifier; there is no unban route ✔
  - F-06: sig/b2bua.go:276-285 still allocates 2 port pairs per INVITE with no admission control ✔
  - F-07: sig/identify.go:17-30 still matches on source IP only (first AllowedIPs match in lexical order) ✔
  - F-14: admin/server.go:102-105 runs bcrypt unconditionally (including with no Authorization header); :80 sets only ReadHeaderTimeout ✔
  - F-01/F-02/F-05 are in unchanged files (sig/server.go, shield/banlist.go) ✔
- **None of T-01..T-37 is implemented**: there is no `sig/readfilter.go`, `sig/listenerlimit.go` or any other remediation file; shield/config/media/admin production code is unchanged.
- **Line-number drift**: the b2bua.go dialTarget region shifted by +96 (e.g. buildFrom 1089→1185, relayProvisional now starting at 1272); the earlier line numbers cited by the audit (:127 refresh re-INVITE, :276 port allocation, :80 onInvite) are unchanged.
- **F-06 parameter update**: silent-target hold time 32s → `ring_timeout` (60s by default) — see §S-03.

## 6. Overall Conclusion and P0 Classification

1. **The audit's conclusions hold in full at the current HEAD**: neither the internet-facing deployment blockers (F-01…F-06) nor the trust model defect (F-07) has been remediated; none of the three commits in `b998f08..HEAD` is a security fix (one call-reliability fix, one test suite, one UI improvement).
2. The ring_timeout fix itself is sound — media hijacking chains are ruled out and failover semantics are correct — but it introduces S-01…S-05, which need follow-up. Of those, the S-02 one-line short-circuit, the S-01 recover and the S-04 Ack timeout should be merged with the first/second tier batch.

### P0 (internet-facing deployment blockers, must be done before release)

| Level | Item | Task | Rationale |
|---|---|---|---|
| P0 | F-01/F-10 ingress pre-filter | T-01 | Bytes from unauthenticated sources reach the parser/connection pool/logs ahead of any protection (OOM, log flooding) |
| P0 | F-02 TCP/TLS connection cap + idle/read timeouts | T-05 | Unauthenticated Slowloris reliably causes OOM/fd exhaustion |
| P0 | F-03 scanner ban before rate limiting + nft storm | T-04 | Unauthenticated fork/exec storm (CPU/PID/memory) |
| P0 | F-05 banList has no cap | T-03 | An unauthenticated flood of unique sources costs gigabytes of memory |
| P0 | F-04 spoofed-source kernel blackhole + all-protocol rule | T-02 | One packet per hour blackholes any third-party IP (including the SBC's own DNS) with no way to undo it |
| P0 | F-06 unauthenticated INVITE exhausts the port pool + places real outbound calls | T-06 | Unauthenticated toll fraud + 503 for legitimate calls |
| P0 (deployment gate) | F-07 mitigation: internet-facing tcp/tls only, or upstream ACL+uRPF | Ops item (code fix on hold) | Over UDP, source IP spoofing = full peer trust (toll fraud) |
| P0 (deployment gate) | F-14 mitigation: bind admin to loopback only | Ops item (until T-09/T-26 land) | Plaintext Basic auth plus all SIP credentials exposed on one port |

> The P0 definition follows the audit §2 standard of "blocks internet-facing deployment": a service outage or resource exhaustion an unauthenticated attacker can reliably achieve, or unauthenticated toll fraud. The code-level fixes for F-07/F-14 (inbound digest challenge, admin TLS) are new product capabilities; in the short term they are closed off with deployment gates, hence P0 (deployment gate) rather than P0 (code).

### P1 (immediately after, batch within 7 days)

- F-08 (T-07): refresh re-INVITE has no dialog validation — a configured peer can probe the other leg's SDES master key
- F-09 (T-08): SRTP replay protection (violates an RFC 3711 MUST)
- F-19 (T-18): peers are fully exempt from rate limiting + TerminateGracefully pins resources — S-03 makes this more urgent
- F-14 code side (T-09): skip the KDF when the header is missing + rate-limit failures
- F-15 (T-15): admin credentials take effect on reload (password revocation gap)
- **New in this review**: S-01 (orphan recover), S-02 (abandoned short-circuit), S-04 (Ack timeout) — recommended for the same batch as T-06/T-18

### P2 (everything else, per the third/fourth tiers of REMEDIATION-PLAN)

F-10 residual (T-12), F-11 (T-14), F-12 (T-13), F-13 (T-17), F-16..F-21, all Low/defense-in-depth items (T-20…T-37), and S-05 (recorded for the record).

---

> Appendix: artifacts added/updated by this review: this document; memory updates (the test suite flakiness is pre-existing at the baseline; the Go toolchain is available). No production code was modified; the temporary baseline worktree has been deleted.
