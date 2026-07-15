# FreeSBC M3.3 — B2BUA Bridge Design

The signaling bridge that ties routing + media + SDP rewrite into the first genuine end-to-end call. Third and final M3 slice (M3.1 front door ✅, M3.2 routing ✅). Parent spec: `freesbc-allinone-design.md` (§3 topology hiding, §4 module layout, §6 call data flow, §7 error handling).

## 1. Decisions (confirmed 2026-07-15)

1. **Build on sipgo's dialog layer**, not raw transactions. A-leg = `DialogServerSession` (UAS toward the caller), B-leg = `DialogClientSession` (UAC toward the target). The library provides CSeq management, dialog matching, ACK/BYE/CANCEL routing, re-INVITE transactions, and outbound digest auth; we own routing, media, SDP rewrite, response mapping, and failover.
2. **Outbound INVITE digest auth is in M3.3** (was slated M4). `DialogClientSession.WaitAnswer` performs the 401/407 retry automatically when handed the target peer's credentials via `AnswerOptions{Username, Password}`. Outbound REGISTER itself stays M4.
3. **Full early media in M3.3.** A provisional (18x) carrying SDP arms the media session and its rewritten SDP is relayed to the A-leg, so the caller hears ringback/announcements before 200 OK. `WaitAnswer`'s `OnResponse` callback surfaces provisionals.
4. **Minimal in-memory call registry in M3.3** (`callstate/`). Maps call-id → paired legs + media session + peers + start time; populated on bridge, cleared on teardown. Backs a Prometheus active-call gauge and the future M7 query/kick API. Kick-call itself stays M7.
5. **SDP rewrite via `github.com/pion/sdp/v3`** (design §4 dependency list). A relay rewrites the connection address and media ports only; no transcoding, no codec filtering in M3.3.

## 2. Components & module layout

Extends the `sig` package and adds `callstate/`. Changes to `media` and `config` are folded in where the bridge needs them.

| File | Responsibility |
|---|---|
| `sig/b2bua.go` | The bridge: INVITE handling, leg pairing, failover loop, response mapping, BYE/re-INVITE forwarding, per-call panic recovery. |
| `sig/sdp.go` | SDP parse/rewrite (pion/sdp): rewrite `c=`/`m=` to our media ports; extract the remote media IP for latch arming. |
| `sig/server.go` (mod) | Construct `DialogServerCache` + `DialogClientCache`; route `OnInvite`/`OnAck`/`OnBye` through them into the bridge. `NewServer` gains a `*media.Pool` argument. |
| `callstate/registry.go` | In-memory call table (call-id → call record); active-call count. |
| `media/session.go` (mod) | Strict per-side latch arming (reject until armed) + `Relatch(side, ip)` for authorized re-latch. Implements the post-M2 latch-arming decision. |
| `config/validate.go` (mod) | Reject transform templates referencing nonexistent capture groups (M3.2 carry-over). |
| `main.go` (mod) | Pass the media pool into `sig.NewServer`. |

### Key sipgo v1.4.3 primitives (verified against the module cache)

- `DialogServerCache.ReadInvite(req, tx) (*DialogServerSession, error)` — creates the A-leg session; `ReadAck`/`ReadBye` route in-dialog requests.
- A-leg: `RespondSDP([]byte)`, `Respond(code, reason, body, headers...)`, `Bye(ctx)`, `Close()`.
- `DialogClientCache.Invite(ctx, recipient sip.Uri, body []byte, headers...) (*DialogClientSession, error)` — places the B-leg with the rewritten SDP as `body`.
- B-leg: `WaitAnswer(ctx, AnswerOptions{OnResponse, Username, Password})`, `Ack(ctx)`, `Bye(ctx)`, `Close()`. `WaitAnswer` loops responses: `OnResponse` fires for each (provisional relay hook), 401/407 auto-retries with creds, 2xx breaks, ctx-cancel sends CANCEL.
- Dialed number: `req.Recipient.User` (the Request-URI user part).

## 3. Call data flow

```
1.  INVITE arrives → identify from-peer by transport source IP (M3.1)
                     unknown source → silent drop (M3.1 shield seam)
2.  dialogServer.ReadInvite(req, tx) → A-leg DialogServerSession
3.  number = req.Recipient.User
    routing.Resolve(cfg, fromPeer, number) → Decision   (no route → 404 to A)
    empty OutNumber → reject with 404   [M3.2 seam note]
4.  parse A-leg offer SDP → caller media IP/port
    media.Allocate(SessionConfig{per-side latch modes from peers}) → Session
    arm A-side latch from caller's signaled media IP (SetExpectedRemote)
5.  failover loop over Decision.Targets (in order, each tried once per call):
      build B-leg offer SDP → c=/m= point at our B-side port
      dialogClient.Invite(ctx, target.Uri, bOfferSDP, ...)  with peer transport
      WaitAnswer(ctx, {Username,Password from peer.auth, OnResponse: relayProvisional})
        · 18x + SDP (early media): rewrite answer SDP → arm/Relatch B-side →
                                    A.Respond(18x, rewrittenSDP)
        · 18x no SDP:              A.Respond(18x, nil)   (180 Ringing passthrough)
        · 2xx: rewrite answer SDP → arm B-side → A.RespondSDP(200) →
               await A ACK → Session.Start() → registry.Add → BRIDGED; break
        · non-2xx / timeout / dial error: close B-leg; mark peer failure;
               try next target
      all targets failed → A.Respond(lastCode or configured failover code)
6.  BRIDGED: media relays both directions (M2). Registry holds the call.
7.  BYE (either leg) → forward to the other (A.Bye / B.Bye) →
       Session.Close() → registry.Remove
8.  re-INVITE (hold/resume/codec) → forward through the paired dialog →
       re-rewrite SDP → authorized Relatch on the changed side
```

### Latch arming (strict per-side)

Implements the decision recorded in `freesbc-allinone-design.md` §3 decision 5. A strict-mode latch **rejects all packets until `SetExpectedRemote` arms it** with the SDP-signaled IP (closing the early-media hijack+DoS window M2's review found). The A-side is armed at step 4 from the caller's offer; the B-side at step 5 from the target's answer (18x-with-SDP or 2xx). A re-INVITE that changes a media address calls `Session.Relatch(side, newIP)` — the only sanctioned way the latch moves after establishment; local media ports persist across re-INVITEs. `loose` mode (per-peer, for hard NAT) keeps M2's accept-first behavior.

### Media allocation & failover interaction

One `media.Session` is allocated per call (step 4) and reused across failover attempts — local ports stay stable, so an A-leg that already received our A-side port in an early-media 18x keeps it. Only the B-side's armed remote changes per target, via `Relatch`. `media.ErrPortsExhausted` at step 4 → 503 to the A-leg.

## 4. SDP rewrite

`sig/sdp.go` uses pion/sdp to parse, mutate, and re-marshal. Two operations:

- **Rewrite offer/answer for our side:** set the session-level `c=` connection address to our public media IP (`listen.media.public_ip`, or the listener IP until STUN lands in a later milestone), and each audio `m=` line's port to our allocated RTP port for that side (A-side port in the answer to the caller; B-side port in the offer to the target). RTCP follows RTP+1 (M2 convention); rewrite `a=rtcp` if present.
- **Extract the remote media endpoint:** read the peer's signaled `c=`/`m=` to get the IP used to arm the latch.

Codecs pass through unchanged (payload-agnostic relay). Per-peer codec filtering is a documented non-goal for M3.3. SDP with no audio `m=` line, or `c=` at media level overriding session level, is handled by pion/sdp's model; a malformed/unparseable SDP → reject the call (488 Not Acceptable Here).

## 5. Call registry

`callstate/registry.go`: a mutex-guarded map keyed by A-leg Call-ID. A `Call` record holds the from-peer name, chosen target name, the A/B dialog sessions, the media session, and the start time (passed in — no wall-clock in library code beyond what sipgo/stdlib already use). API: `Add(call)`, `Remove(callID)`, `Count() int`, `Snapshot() []CallInfo` (for the future admin API). M3.3 uses `Count()` for the Prometheus `freesbc_active_calls` gauge; enumerate/kick is M7. The registry is the single owner of the paired-leg references so teardown (BYE, timeout, panic) has one place to release everything.

## 6. Error handling (spec §7)

| Scenario | Behavior |
|---|---|
| No route matched | 404 to A-leg |
| Empty transformed number | 404 to A-leg |
| All targets failed failover | Last upstream final code to A-leg (configurable uniform code deferred to M4 with the health-check work) |
| Media ports exhausted | 503 to A-leg |
| B-leg unparseable/again media-less answer SDP | 488 to A-leg, tear down |
| Caller CANCEL / A BYE during setup | CANCEL the in-flight B-leg (ctx cancel → WaitAnswer sends CANCEL) |
| Per-call panic | `recover` in the bridge goroutine: close both legs + media, registry remove, process survives |
| Half-dead call (BYE lost) | M2 RTP silence watchdog tears the media session down; bridge observes `Session.Done()` and closes both legs |

## 7. Testing

- **SDP rewrite** — table tests on `sig/sdp.go`: c=/m= rewrite for representative offers/answers, remote-IP extraction, media-less and media-level-c= edge cases. Pure functions.
- **Latch arming** — `media` unit tests: strict rejects before arming, accepts the armed IP after, `Relatch` moves it; `loose` unchanged.
- **B2BUA integration** — sipgo UAC + a stub "carrier" UAS in-process over real UDP loopback: place a call, assert the bridged 200 + rewritten SDP pointing at our ports, push RTP through the relay both ways and assert delivery, then BYE and assert both legs + media are released and the registry empties. Early media asserted via a stub UAS that sends 183+SDP before 200. Failover asserted with a first target that returns 503 and a second that answers. Digest auth asserted with a stub UAS that challenges once (401) then accepts.
- **Full suite** `go vet ./... && go test ./... -race` stays green; this is the milestone where an end-to-end call first exists, so the integration test is the milestone's proof.

## 8. Scope

**In M3.3:** B2BUA bridge (dialog-layer leg pairing, response mapping, failover execution), SDP rewrite (c=/m=), media integration with strict per-side latch arming + `Relatch`, early media, outbound INVITE digest auth, BYE + re-INVITE forwarding, minimal call registry + active-call gauge, the M3.2 group-ref config validation.

**Deferred:** outbound REGISTER, session timers (RFC 4028), 100rel/PRACK, DNS SRV, cross-call peer health/failure-cooldown + active OPTIONS probing + configurable uniform failover code (all M4); SRTP/SDES (M5); shield verdicts replacing the drop seam (M6); admin API enumerate/kick + full metrics + WebUI (M7); STUN for `public_ip: auto`; per-peer SDP codec filtering. M3.3's failover is in-call only — each target tried once in order, no cross-call memory.

**Interop caveat:** a target that requires 100rel (`Require: 100rel`) or session timers may reject or drop calls until M4. M3.3 targets the common IP-auth / digest-auth trunk without those mandates.
