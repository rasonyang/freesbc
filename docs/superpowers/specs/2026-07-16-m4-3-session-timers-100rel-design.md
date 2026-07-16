# FreeSBC M4.3 — Session Timers + 100rel Handling Design

The third M4 (trunk interop) slice. Pragmatic, sipgo-realistic handling of the carrier-mandated mid-dialog features: negotiate RFC 4028 session timers (pushing refresh duty to the endpoints), gracefully decline 100rel, and best-effort answer session-timer refresh re-INVITEs. Parent spec: `freesbc-allinone-design.md` (interop baseline: session timers + 100rel/PRACK). M1–M4.2 complete and merged.

## 0. sipgo v1.4.3 reality (investigated) — why this scope

sipgo provides **no** session-timer machinery (Session-Expires/Min-SE appear only in its test files; no 422; `sip.UPDATE`/`sip.PRACK` exist only as method constants) and **no** reliable-provisional/PRACK logic (only `srv.OnPrack` to register a raw handler). Critically, M3.3 established that sipgo's `DialogServerSession` cannot *bridge* a mid-dialog re-INVITE without corrupting the dialog. Full session-timer/100rel support would require hand-rolled reliable provisionals plus self-generated refresh re-INVITEs on the raw transaction layer — effectively a bridge rewrite, out of scope for a slice. M4.3 therefore does what sipgo *can* express: header-level negotiation at setup, endpoint-driven refresh, honest decline of what it can't do.

## 1. Decisions (confirmed 2026-07-16)

1. **Pragmatic interop, not full support.** Negotiate session timers at setup; push refresh duty to both endpoints so the SBC never *sends* a mid-dialog re-INVITE; best-effort *answer* incoming refresh re-INVITEs locally.
2. **100rel: decline honestly.** Inbound `Require: 100rel` → `420 Bad Extension` + `Unsupported: 100rel`. Never advertise `Supported: 100rel` outbound. Carriers that *offer* 100rel still work (unreliable provisionals); carriers that *mandate* it don't complete (documented).
3. **Session-timer config: global with RFC defaults.** `session_expires` (advertise/accept, default 1800s) + `min_se` (minimum accepted, default 90s). Enforce Min-SE: a requested Session-Expires below `min_se` → `422 Session Interval Too Small` + `Min-SE` header.
4. **M4.2 carry-over: 423 on REGISTER.** On `423 Interval Too Brief`, read `Min-Expires` and retry once requesting ≥ that value (RFC 3261 §10.2.8).

## 2. Components & module layout

| File | Change |
|---|---|
| `config/schema.go`, `validate.go` | `SessionExpires Duration` (yaml `session_expires`, default 1800s) + `MinSE Duration` (yaml `min_se`, default 90s); validate `min_se ≥ 1s`, `session_expires ≥ min_se`. |
| `sig/timers.go` (new) | Pure session-timer logic: parse Session-Expires/Min-SE from a request; `tooSmall(reqSE, minSE) bool`; `negotiate(peerSE, sessionExpires, minSE) time.Duration`; build the `Session-Expires;refresher=…` header value; `isRefreshReInvite(req) bool`. |
| `sig/b2bua.go` | Inbound `Require:100rel` → 420; Session-Expires < min_se → 422; A-leg 200 gets `Session-Expires;refresher=uac` + `Supported: timer`; B-leg INVITE gets `Supported: timer` + `Session-Expires;refresher=uas` + `Min-SE` (no `Supported: 100rel`); B-leg 422 → retry with carrier Min-SE; refresh re-INVITE → local 200 answer. |
| `sig/register.go` | 423 → retry with Min-Expires. |
| `sbc.example.yaml` | Document `session_expires` / `min_se`. |

Session-Expires/Min-SE/Supported/Require/Unsupported are not typed in sipgo — read via `req.GetHeader(name).Value()` and write via generic headers (exact API verified in the plan).

## 3. Session-timer negotiation (setup)

```
Inbound INVITE:
  Require: 100rel present?  → 420 Bad Extension + Unsupported: 100rel   (done)
  parse Session-Expires (SE), Min-SE
  SE present and SE < our min_se?  → 422 Session Interval Too Small + Min-SE: <min_se>   (done)
  else bridge the call (M3.3/M4.1 flow), and:

A-leg 200 OK (SBC = UAS toward caller):
  negotiated = negotiate(caller SE, session_expires, min_se)   // min(caller SE, session_expires), floored at min_se
  add  Session-Expires: <negotiated>;refresher=uac             // the CALLER refreshes toward us
  add  Supported: timer

B-leg INVITE (SBC = UAC toward carrier):
  add  Supported: timer
  add  Session-Expires: <session_expires>;refresher=uas        // request the CARRIER refresh
  add  Min-SE: <min_se>
  (do NOT add Supported: 100rel)
  carrier answers 422 (its Min-SE > ours)?  → retry the B-leg INVITE ONCE with Session-Expires = carrier Min-SE
```

A single 422 retry per target: if the carrier 422s again (or 422s without a usable Min-SE), it is classified as a normal `failReal` and the M4.1 failover loop moves to the next target.

Designating `refresher=uac` on the A-leg and requesting `refresher=uas` on the B-leg means both refresh re-INVITEs arrive *at* the SBC — it only ever *answers* them, never sends. A carrier that ignores the preference and forces `refresher=uac` on the B-leg would expect the SBC to refresh; the SBC can't, so that call lapses at the interval — a documented limitation, mitigated by a large `session_expires`.

## 4. Refresh re-INVITE — local answer (plan-level spike)

M3.3 blanket-501s every in-dialog re-INVITE (safe: RFC 3261 §14.1 keeps the call up). M4.3 refines this: a re-INVITE that `isRefreshReInvite` (in-dialog, carries Session-Expires, no meaningful SDP change) is answered **locally** — `tx.Respond(200 OK)` on the re-INVITE's *own* live server transaction (never the corruption-prone `DialogServerSession.ReadInvite` path), echoing the established SDP and a refreshed `Session-Expires;refresher=<same>`. This is a **spike**: bridging a re-INVITE was infeasible in M3.3, but *locally answering* one (no cross-leg forwarding, no dialog-session mutation) is a much smaller ask. The plan investigates whether sipgo routes the subsequent ACK cleanly and whether a bare `tx.Respond` on an in-dialog INVITE tx is accepted; **if infeasible, it falls back to the current 501** with a documented limitation (session-timer calls then lapse at the interval). A re-INVITE that changes media stays 501 (media renegotiation deferred).

## 5. 423 on REGISTER (M4.2 carry-over)

`registerOnce`: on `423 Interval Too Brief`, read the `Min-Expires` header; if present and larger than requested, rebuild the REGISTER with `Expires = Min-Expires` and resend once (reusing the existing digest path). A second 423, or a 423 without a usable Min-Expires, is a normal failure → backoff (the lifecycle loop's job).

## 6. Error handling

| Scenario | Behavior |
|---|---|
| Inbound INVITE `Require: 100rel` | 420 Bad Extension + Unsupported: 100rel |
| Inbound Session-Expires < min_se | 422 Session Interval Too Small + Min-SE: <min_se> |
| B-leg 422 (carrier Min-SE > ours) | retry B-leg INVITE ONCE with Session-Expires = carrier Min-SE; a second 422 → failReal → failover |
| Refresh re-INVITE (session timer) | local 200 OK (spike) / 501 fallback |
| Media-change re-INVITE | 501 (deferred, M3.3 behavior) |
| Carrier forces refresher=uac on B-leg | documented limitation; call lapses at interval (RTP watchdog still reclaims media) |
| REGISTER 423 | retry once with Min-Expires |

## 7. Testing

- **Pure `timers.go`**: parse Session-Expires/Min-SE (present/absent/with-params); `tooSmall`; `negotiate` (caller-lower, ours-lower, floor at min_se); `isRefreshReInvite` (in-dialog+SE vs media-change vs initial).
- **Integration** (stub carrier/registrar harness): inbound `Require:100rel` → 420+Unsupported; inbound low Session-Expires → 422+Min-SE; the bridged A-leg 200 carries `Session-Expires;refresher=uac`+`Supported:timer`; the B-leg INVITE carries `Supported:timer`+`Session-Expires;refresher=uas`+`Min-SE` and no `Supported:100rel`; a stub carrier that 422s → B-leg retried with its Min-SE and bridges; a refresh re-INVITE → 200 (or documented-501); a stub registrar 423 → REGISTER retried with Min-Expires and succeeds.
- Full `go vet ./... && go test ./... -race` stays green; no regression to M3.3/M4.1/M4.2 (happy path, early media, failover, ring cap, response codes, registration).

## 8. Scope

**In M4.3:** RFC 4028 session-timer negotiation (Min-SE 422, refresher designation, B-leg 422 retry), config `session_expires`/`min_se`, best-effort local answer of refresh re-INVITEs, 100rel honest decline (420), REGISTER 423 retry.

**Deferred:** real 100rel/PRACK reliable provisionals (needs raw-transaction work — a later milestone or non-goal); media-renegotiation re-INVITE forwarding (still 501, M-later); SBC-side session-timer expiry teardown (RTP-silence watchdog remains the liveness backstop); per-peer session-timer config; a carrier forcing refresher=uac on the B-leg. UPDATE-method refresh (we negotiate re-INVITE-based refresh only). Session timers over the A-leg when the caller doesn't offer them are simply not added (we don't force `Require: timer` on endpoints that didn't ask).
