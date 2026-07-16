# FreeSBC M4.1 — Outbound-INVITE Realism Design

The first of four M4 (trunk interop) slices. Makes the existing B2BUA bridge's outbound INVITE acceptable to a real carrier: propagate calling identity, cap ring time, and return truthful response codes. Parent spec: `freesbc-allinone-design.md` (§5 routing/failover, §7 error handling, interop baseline). Prior milestones M1–M3 complete and merged.

**M4 decomposition (confirmed):** M4.1 outbound-INVITE realism → M4.2 outbound REGISTER → M4.3 session timers + 100rel/PRACK → M4.4 DNS SRV + peer health/cooldown. M4.1 is the smallest slice that lets a real trunk accept our calls; everything else builds on a working outbound call.

## 1. Decisions (confirmed 2026-07-16)

1. **From/CLI: pass-through, our host.** The B-leg INVITE's `From` carries the A-leg caller's From user (calling number / CLI) and display name, with the host rewritten to our signaling IP (`ourIP`, topology hiding) and a fresh tag. Per-peer CLI override and P-Asserted-Identity are deferred (later M4 slice or opt-in).
2. **Ring cap: global, failover, then 408.** A new global `ring_timeout` (default 60s). A target that rings (18x) past it without a final answer is CANCELed and treated as a retryable failure — the failover loop tries the next target; when targets are exhausted the caller gets `408 Request Timeout`.
3. **Response-code fidelity.** A target's genuine SIP final failure (486 Busy, 480 Unavailable, 404, 603 Decline, 403, 488, …) propagates verbatim to the caller. Synthetic codes are reserved for *our own* failures: `503` (no target reachable / dial or transport error), `408` (ring timeout, no more targets), `502` (a target answered but its response is unusable, e.g. missing/unparseable SDP). After failover exhausts, the caller sees the last target's real final code.
4. **Correct in-dialog codes** (M3.3 carry-overs): a BYE matching no dialog → `481 Call/Transaction Does Not Exist` (was silent); a malformed INVITE (`ReadInvite` failure — no Contact/CSeq) → `400 Bad Request` (was 500).

## 2. Components & module layout

No new packages. Corrections to the existing bridge plus one config field.

| File | Change |
|---|---|
| `config/schema.go`, `validate.go` | Add global `ring_timeout` (Duration, yaml `ring_timeout`, default 60s, must be > 0). |
| `sig/b2bua.go` | Build+attach the B-leg `From` header; per-attempt ring-timeout deadline that CANCELs and fails over; classify each target failure (real-final-code / dial-error / ring-timeout / unusable) so `placeCall` returns the right caller code. Per-transport Contact on the B-leg INVITE. |
| `sig/server.go` | `onBye` no-dialog → 481; `ReadInvite` failure → 400. A-leg response Contact matched to the inbound transport (see §5). |
| `sbc.example.yaml` | Document `ring_timeout`. |

## 3. Data flow changes

Within `dialTarget` (per target attempt) and `placeCall` (the failover loop):

1. **From header** — before `dialogCli.Invite`, build `fromHeader` from the A-leg request's `From()`: `DisplayName` and URI `User` copied from the caller; URI `Host`/`Port` set to `ourIP` + our signaling port; a fresh `tag` param. Pass it (and the per-transport Contact, §5) via `Invite`'s variadic headers — verified: sipgo's `DialogUA.Invite` appends passed headers and only synthesizes a default From/Contact when absent (`dialog_ua.go:106-127`), so our headers win.
2. **Ring timeout** — wrap each attempt's `WaitAnswer` context with `context.WithTimeout(aLeg.Context(), ring_timeout)`. On expiry, the existing sipgo path (`WaitAnswer` ctx-done → `inviteCancel`) sends CANCEL to the target; `dialTarget` distinguishes "our ring-timeout cancel" from "caller CANCEL" (the latter cancels `aLeg.Context()` — already handled by M3.3's post-CANCEL guard) and reports ring-timeout as a retryable failure with code 408.
3. **Failure classification** — `dialTarget` returns a small result the loop can map: a real final response → its `StatusCode`; a dial/transport error (Invite error, or WaitAnswer transaction error with no final) → 503; ring timeout → 408; a 2xx whose SDP is unusable → 502. When every target has failed, `placeCall` picks the caller's code by this precedence: (a) the **last real final response** code seen across all attempts (486/480/… — the most informative for the caller); else (b) `408` if any attempt ring-timed-out; else (c) `503` (all dial/transport errors). So a mix of "target-a 486, target-b timeout" yields 486 (a real carrier verdict outranks our synthetic timeout), while "all rang out" yields 408 and "none reachable" yields 503.

The happy-path, early-media, digest-auth, latch-arming, and teardown behavior from M3.3 is unchanged.

## 4. Config

`ring_timeout` is a global signaling-setup timeout, parallel to `listen.media.rtp_timeout`. Placed top-level:

```yaml
ring_timeout: 60s   # cancel a target that rings this long without answering, then failover
```

Default 60s when omitted; validation rejects ≤ 0. It bounds pre-answer ring time only; established calls are governed by `rtp_timeout` (M2).

## 5. Contact (per-transport)

The M3.3 whole-branch review flagged the dialog Contact pinned to one listener regardless of transport. M4.1 corrects it per leg:

- **B-leg (outbound INVITE):** pass a `Contact` header matching the target peer's transport (`ourIP` + our listening port for that transport + `transport` param). Confirmed workable — `WriteInvite` uses the cache default only when no Contact is present, so a per-Invite Contact overrides it.
- **A-leg (responses to the caller):** the Contact in our 200 OK / provisionals should reflect the transport the INVITE arrived on. sipgo's `DialogServerCache` holds one fixed `ContactHDR`; the plan investigates the cleanest mechanism (per-`Respond` header override — `DialogServerSession.Respond` takes variadic headers — versus one `DialogServerCache` per listener transport). **Fallback if neither is clean:** set the single A-leg Contact to `ourIP` + the primary listener's transport/port and document multi-transport A-leg Contact as a residual — the host is already routable (M3.3 fix), so this degrades to a transport-param mismatch only when a peer uses a non-primary transport, not a blackhole.

## 6. Error handling

| Scenario | Caller sees |
|---|---|
| Target returns real 4xx/5xx/6xx final (486/480/404/603/403/488…) | that exact code (verbatim), after failover exhausts |
| No target reachable (Invite error / transport / no response) | 503 Service Unavailable |
| Target rings past `ring_timeout`, no more targets | 408 Request Timeout |
| Target answers 2xx but SDP missing/unparseable | 502 Bad Gateway |
| BYE matches no dialog | 481 Call/Transaction Does Not Exist |
| Malformed INVITE (ReadInvite: no Contact/CSeq) | 400 Bad Request |
| Caller CANCEL mid-setup | failover stops (M3.3); B-leg CANCELed |

## 7. Testing

Extend the M3.3 stub-carrier harness:
- **From/CLI** — the stub carrier captures its received INVITE; assert `From` user = the caller's number and host = `ourIP` (not the caller's IP), display name preserved, a tag present.
- **Response fidelity** — a carrier returning 486 → the caller receives 486 (not 502); a two-target config where the first 486s and the second 200s still bridges (486 is a real failure that triggers failover, and the winning 200 answers).
- **Ring cap** — a carrier that sends 180 and never answers, with a short test `ring_timeout` → the bridge CANCELs it and (single target) returns 408; (two targets) fails over to the second.
- **Per-transport Contact** — assert the B-leg INVITE's Contact transport param matches the target peer's transport.
- **In-dialog codes** — a BYE with an unknown dialog → 481; a malformed INVITE (strip Contact) → 400.
- Full `go vet ./... && go test ./... -race` stays green.

## 8. Scope

**In M4.1:** From/CLI pass-through, global `ring_timeout` with failover + 408, faithful response codes, per-transport B-leg Contact (+ best-effort A-leg Contact), 481/400 in-dialog codes.

**Deferred:** outbound REGISTER (M4.2); session timers + 100rel/PRACK (M4.3); DNS SRV + cross-call peer health/cooldown + configurable uniform failover code (M4.4); per-peer CLI override + P-Asserted-Identity; full multi-transport A-leg Contact if the mechanism proves unclean; declined-section SDP attribute scrub (M4/M5); registry Call-ID uniqueness (M7).

**Interop note:** From/CLI makes an outbound call *acceptable*; a carrier that also mandates 100rel or session timers still needs M4.3, and a registration trunk needs M4.2 before we can send it anything.
