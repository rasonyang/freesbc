# Phase 2 — internal/trunk semantic review

Scope: `internal/trunk/*.go` (non-test, ~4100 lines). Method: reading the code and
the vendored `github.com/emiago/sipgo@v1.4.3` sources. No tests were run. Every
finding below is **INFERENCE** unless marked FACT. The only FACT label is used for
docs line-number drift, which was checked mechanically with `grep -n`.

Severity: P0 = crash / leak / security on a public path; P1 = SIP/SDP/media
correctness; P2 = maintainability / dead code / docs-code drift.

## Findings

### P2-TRK-001 — TCP/TLS connection cap is consumed by non-peer sources (P0, transport, INFERENCE)
- Location: `internal/trunk/listenerlimit.go:35-54`, `internal/trunk/server.go:352-358`, `:381-387`
- Evidence: `Accept()` only compares `l.count.Load()` against `l.max` (1024) and wraps the conn. It never checks the remote IP against `allowed_ips`. The peer check happens later, in the read filter, on bytes. For TLS, `tls.Listen` performs the handshake on first Read, which happens before the filter sees any plaintext.
- Invariant: non-peer sources are dropped before they cost anything (`docs/design.md` §6.1 "bytes from a non-peer source never reach … the connection pool"). The global cap is shared by every tcp/tls listener.
- Impact: any Internet host can open 1024 idle TCP connections, or run slow TLS handshakes. Each connection is held for up to the 120 s idle deadline, which is refreshed per read. After that, every carrier TCP/TLS connection is closed on accept. `RecordUnidentified` never fires for these sources, because the filter drops them before identification (`server.go:455-459`), so the shield never bans them.
- Confirm: test that opens `tcpMaxConns` raw TCP connections from a non-peer loopback address (for example 127.0.0.3 with an alias, or a lowered `tcpMaxConns` from a non-allowed IP), then asserts that a peer TCP INVITE still gets a response. Expected to fail.
- Action: fix. Check `RemoteAddr` against `IdentifyPeer` in `Accept` before counting the connection.

### P2-TRK-002 — Call store keyed by Call-ID alone (P1, dialog, INFERENCE)
- Location: `internal/trunk/calls.go:116-125` (`s.calls[c.id]`, `s.legs[c.id]`, `s.legs[c.bID]`), `:132-145`, `:151-162`, `:170-179`; `internal/trunk/server.go:41-42`
- Evidence: `registerCall` does `s.calls[c.id] = c; s.legs[c.id] = c; s.legs[c.bID] = c` with no collision check. `endCall` does `delete(s.calls, c.id)` unconditionally.
- RFC: RFC 3261 §12 defines a dialog by Call-ID + local tag + remote tag. §8.2.2.2 (merged requests) says a UAS SHOULD answer 482 to a second INVITE with the same Call-ID/From-tag/CSeq that arrives on a different branch. No merged-request detection exists.
- Impact: two live calls with the same A-leg Call-ID overwrite each other. This happens with an upstream proxy that forks the same INVITE to two SBC addresses, or with a peer that reuses a Call-ID, including one equal to another call's B-leg Call-ID, which the carrier knows. When the first call ends, `endCall` deletes the second call's entries. The second call then disappears from `/api/calls`, `KillCall` cannot reach it, and its session refreshes get 501. `KillCall(id)` can also kill the wrong call. The tag check at `b2bua.go:191` prevents a key leak but does not fix ownership.
- Confirm: test that sends two INVITEs with an identical Call-ID and From-tag and different Via branches, then asserts either 482 on the second INVITE or that both calls appear in `Calls()` and `ActiveCalls()==2` until each one ends.
- Action: rewrite. Key the store by the dialog ID (Call-ID + both tags), keep the admin ID separate, and reject merged requests.

### P2-TRK-003 — `recoverCall` swallows panics without a final response or BYE (P1, dialog, INFERENCE)
- Location: `internal/trunk/b2bua.go:128`, `:1663-1668`; `internal/trunk/server.go:431-438`
- Evidence: `recoverCall` only logs. It runs before `withShield`'s outer recover (the inner recover runs first), so the outer "best-effort 500" never fires for INVITE. The deferred `aLeg.Close` / `bLeg.Close` / `sess.Close` only drop local state. `DialogServerSession.Close` and `DialogClientSession.Close` send nothing (sipgo `dialog_server.go:189-194`, `dialog_client.go:171-180`).
- RFC: RFC 3261 §8.2 / §17.2.1 (every INVITE needs a final response); §15 (a confirmed dialog is ended by BYE).
- Impact: a panic during setup leaves the caller's INVITE with no final response. A panic while bridged leaves both remote parties in a confirmed dialog with dead media, and no BYE is ever sent.
- Confirm: unit test using an injected panic (for example a nil `media.Session` path, or reflection) that asserts the caller receives a 5xx. Alternatively, document it as untestable without a production hook.
- Action: fix. In recoverCall, respond 500 when no final response has been sent, and BYE both legs when bridged.

### P2-TRK-004 — Hot reload changes advertised Contact/From/REGISTER ports for restart-only listeners (P1, config/lifecycle, INFERENCE)
- Location: `internal/trunk/server.go:490-510` (`advertisedIP` step 3 reads `cfg.Listen.SIP`), `:539-552` (`ourSigPort` reads `cfg.Listen.SIP`); used per call at `b2bua.go:204`, `:857-859`, `:991-992`, and per reconcile at `register.go:387-391`
- Evidence: listeners are bound once in `Run` (`server.go:290-302`), and the listener set is restart-only (`docs/design.md:337-345`). `ourSigPort(cfg, …)` and `sigIP(cfg)` still resolve from the current snapshot. `Registrar.reconcile` recomputes `regParams` (which include `ContactPort`/`ContactIP`) on every publication, and a change restarts the registration.
- Invariant: hot reload must not act on restart-only settings.
- Impact: editing `listen.sip` port/host without a restart makes new calls advertise a Contact on a port nothing is bound to, and re-REGISTERs every register:true peer with that unbound Contact. Inbound calls from that carrier then fail.
- Confirm: test that starts the server, replaces the config with a different `listen.sip` port, waits for reconcile, and asserts the REGISTER Contact port still equals the bound port. Expected to fail.
- Action: fix. Capture the bound listener set and ports at `Run` and resolve the advertised port from it.

### P2-TRK-005 — Multiple config snapshots per call (P1, config/lifecycle, INFERENCE; docs drift)
- Location: `internal/trunk/server.go:411` (identify → `store.Current()`), `internal/trunk/b2bua.go:220` (`cfg`), `:572` (`expandTargets` → `store.Current()`), `:653` (`placeCall` → `store.Current()`), plus the per-allocation read in `NewMediaPool` (`mediapool.go:17`)
- Evidence: `fromPeer` comes from snapshot 1, routing and quota from snapshot 2 (`cfg`), SRV TTL from snapshot 3, and ring timeout, cooldown and the headers used by `dialTarget` from snapshot 4 (`placeCall`'s `cfg` is what is passed to `dialTarget`).
- Invariant/docs: CLAUDE.md says "the trunk takes one snapshot per call". `docs/design.md` §6.4 says "the rest of the call runs on onInvite's per-call snapshot", but `placeCall` takes its own. The mismatch is docs-code drift.
- Impact: a reload during setup can mix peer policy from one config with timers and headers from another, for example `session_expires`/`min_se` from different snapshots.
- Confirm: test with a `config.Store` wrapper, or `Replace` from inside a fake target's INVITE handler, that asserts the ring timeout/min_se in effect equal the snapshot at INVITE arrival.
- Action: fix. Pass `cfg` from `onInvite` down, and resolve `fromPeer` from the same snapshot.

### P2-TRK-006 — SDP pass-through leaks the other leg's topology (P1, SDP, INFERENCE; docs contradiction)
- Location: `internal/trunk/sdp.go:126-195` (`rewriteSDPCrypto`); used for B-offer `b2bua.go:826`, `:844`, A-answer `:942`, `:956`, early media `:1489`, `:1496`
- Evidence: only session `c=`, the `o=` address fields, the relayed `m=` port/proto, `a=crypto` and `a=rtcp` are rewritten. Every other attribute on the relayed audio section and at session level passes through, including `a=candidate` (peer IPs and ports), `a=ice-ufrag/pwd`, `a=fingerprint`, `a=setup`, `a=ssrc` (with cname), `a=rtcp` in its `port IN IP4 addr` form (overwritten, which is fine), and `o=` username/session-id.
- Invariant/docs: `docs/trunk.md:65-66` advertises "B2BUA with topology hiding … and full SDP rewrite". `docs/design.md` §6.7 admits that `candidate`, `fingerprint` and `ice-*` pass through. The two docs contradict each other, and the code matches only design.md.
- Impact: the caller's ICE candidates (private and public IPs) reach the carrier and vice versa. A peer that honours ICE may send media directly to the other peer and bypass the anchor (`a=candidate` with ICE-lite peers).
- Confirm: SDP leak property test on `rewriteSDPCrypto`. Seed the input with a sentinel IP/port in `a=candidate`, `a=rtcp:… IN IP4 <sentinel>`, `o=` and `c=`, randomize the other fields, and assert that the sentinel never appears in the output. Expected to fail on `a=candidate`.
- Action: rewrite. Build the relayed SDP from an allow-list (as the edge plane does with `sdp.Build`) instead of editing the peer's body in place.

### P2-TRK-007 — A-leg answer `o=` taken from whichever carrier answered (P1, SDP, INFERENCE)
- Location: `internal/trunk/sdp.go:137-139` (only the address fields of `o=` are replaced); `b2bua.go:942`, `:956`, `:1489`, `:1496`
- Evidence: the A-leg's early-media SDP (18x) and its final 200 SDP are each derived from the B-leg's current response body. After failover, or with forked 18x (see 008), the caller sees SDP bodies with different `o=` session-id/username/version inside one offer/answer exchange.
- RFC: RFC 3264 §8 (an `o=` version changes only by +1 and only when the session changes; the session-id is stable for the session); RFC 6337 §3.1 (18x and 2xx SDP answers should be identical).
- Confirm: fake carrier 1 sends 183+SDP (o= sess 111) and then 486; carrier 2 answers 200 (o= sess 222). Assert that the A-leg 183 and the A-leg 200 carry the same `o=` session-id/version. Expected to fail.
- Action: rewrite (same fix as 006). The SBC owns its own `o=` per leg.

### P2-TRK-008 — Forked B-leg responses are not handled (P1, dialog, INFERENCE)
- Location: `internal/trunk/b2bua.go:1121-1162` (single `WaitAnswer`), `:1464-1511` (`relayProvisional`), `:1561-1600` (`processAnswerSDP` → `Relatch`)
- Evidence: all 18x responses are relayed to the one A-leg early dialog regardless of their To-tag. Each 18x with SDP calls `processAnswerSDP`, which `Relatch`es side B to that fork's address. Only the first 2xx is consumed by `WaitAnswer`. A second 2xx from another fork (a different To-tag) is never ACKed or BYEd.
- RFC: RFC 3261 §13.2.2.4 (the UAC must ACK every 2xx and SHOULD BYE extra dialogs); §12.1 / §19.3 (each To-tag is a distinct early dialog).
- Impact: early media flips between forks (whichever 183 arrived last). A second answering fork keeps ringing and billing until its own 64·T1 timeout.
- Confirm: fake carrier that sends two 183s with different To-tags and SDP addresses and then two 200s with different To-tags. Assert that the second 200 gets ACK+BYE and that media latches only to the winning fork.
- Action: fix (track forks by To-tag, and tear down extra 2xx dialogs).

### P2-TRK-009 — Session-timer negotiation violates RFC 4028 and the SBC never refreshes (P1, dialog, INFERENCE)
- Location: `internal/trunk/b2bua.go:993-1000` (A-leg 200: `sessionExpiresHeader(negotiatedSE, "uac")`, no `Require: timer`, no check of the caller's `Supported: timer`); `:867-873` (B-leg `refresher=uas`, and the carrier's 2xx `Session-Expires`/refresher is never read); `:206-209` (refresh 200 echoes Session-Expires with no `Require`)
- Evidence: `grep -n "Require" internal/trunk/*.go` finds only `requires100rel`. There is no refresh sender and no expiry timer (`docs/design.md` §6.3: "no session-expiry enforcement").
- RFC: RFC 4028 §9 (a UAS may set `refresher=uac` only when the UAC indicated `Supported: timer`, and must then add `Require: timer`); §7.2/§10 (when the 2xx names the UAC as refresher, the UAC must refresh or the peer BYEs at expiry).
- Impact: (a) a caller without timer support is told it is the refresher. (b) A carrier that answers `Session-Expires: N;refresher=uac` expects the SBC to refresh. The SBC never does, so the carrier BYEs every call after N seconds.
- Confirm: (a) an INVITE without `Supported: timer`; assert the 200 does not say `refresher=uac`. (b) A fake carrier answers `Session-Expires: 90;refresher=uac` + `Require: timer`; assert the SBC sends a refresh within 90 s.
- Action: fix.

### P2-TRK-010 — Compact `Session-Expires` (`x`) and `Supported` (`k`) are not recognized (P1, transport, INFERENCE)
- Location: `internal/trunk/timers.go:14-29` (`m.GetHeaders(name)` with long names), used at `b2bua.go:252`, `:209`, `:994-995`, `:1251`, `timers.go:113`
- Evidence: sipgo's `GetHeaders` lower-cases names but does not expand compact forms. Its parser maps only `c f t m i v l` (`sipgo/sip/parse_header.go:40-61`). A header `x: 30` stays named `x`.
- RFC: RFC 4028 §4 defines compact form `x` for Session-Expires; RFC 3261 §7.3.3 / §20 (`k` = Supported).
- Impact: `x: 30` bypasses the 422 Min-SE floor, a compact-form refresh re-INVITE is not recognized (it gets 501), and `negotiateSE` ignores the caller's value.
- Confirm: an INVITE with `x: 30` and `min_se: 90`; assert 422. Expected to fail.
- Action: fix (normalize compact names in `headerSeconds`).

### P2-TRK-011 — Digest realm pinning can be bypassed by substring match (P1, transport/security, INFERENCE)
- Location: `internal/trunk/timers.go:37-65` (`strings.Index(v, "realm=")`), used at `b2bua.go:1152-1156` and `register.go:103`
- Evidence: this finds the first `realm=` substring anywhere, including inside another parameter name (`xrealm=`) or a quoted value. The comparison is also case-sensitive, although parameter names are case-insensitive (RFC 3261 §25.1, RFC 2617 §1.2).
- Impact: a rogue or compromised server sends `WWW-Authenticate: Digest xrealm="<pinned>", realm="rogue", nonce="n"`. `challengeRealm` returns `<pinned>`, so the pin passes, and sipgo then computes the digest over `realm="rogue"`. That is the offline-cracking exposure the pin exists to prevent (comment at `b2bua.go:1142-1151`).
- Confirm: pure unit test `challengeRealm(res with header 'Digest xrealm="trusted", realm="rogue", nonce="n"')`; assert it returns `"rogue"`. It will return `"trusted"`.
- Action: fix (parse the auth-params properly).

### P2-TRK-012 — SDES lines with MKI, lifetime or session parameters are accepted as if plain (P1, SDP/media, INFERENCE)
- Location: `internal/trunk/crypto.go:40-55` (`b64 = b64[:i] // drop MKI / lifetime`), `:27-38` (`fields[3:]` session params are ignored)
- RFC: RFC 4568 §6.1 (with an MKI, every SRTP packet carries the MKI; the lifetime bounds key use), §6.3 (session params such as `UNENCRYPTED_SRTP` change processing and must be understood or the line rejected).
- Impact: an offer with `inline:KEY|2^20|1:4` is accepted, but the peer's packets carry a 4-byte MKI the SRTP context does not expect, so authentication fails and audio is one-way or silent. An unknown session param is silently ignored.
- Confirm: unit test that `parseCryptoAttrs(["1 AES_CM_128_HMAC_SHA1_80 inline:<key>|2^20|1:4"])` returns no usable line. It currently returns one.
- Action: fix (reject lines with MKI or unknown session params, or support them).

### P2-TRK-013 — In-dialog INVITE to an unknown dialog gets 501, not 481; non-refresh re-INVITE gets 501 (P1, dialog, INFERENCE; documented)
- Location: `internal/trunk/b2bua.go:189-218`
- Evidence: when `known == false` the code falls to `s.reject(req, tx, 501, …)` at `:216`.
- RFC: RFC 3261 §12.2.2 (a request with a To-tag that matches no dialog → 481); §14.2 (a UAS rejecting a re-INVITE offer uses 488; 501 means the method is not implemented, and INVITE is implemented).
- Impact: a UA whose dialog was lost keeps it open, because 481 is the teardown trigger (§12.2.1.2). Hold/resume and target-refresh re-INVITEs are refused, so a caller that changes its media address gets one-way audio. This is documented in `docs/design.md` §6.2.
- Confirm: a re-INVITE with a random Call-ID and To-tag; assert 481.
- Action: fix (481 for an unknown dialog, 488 for an unsupported offer).

### P2-TRK-014 — Unmatched CANCEL and all other methods get 405 without `Allow` (P2, transaction, INFERENCE; documented)
- Location: `internal/trunk/server.go:640-650` (`onNoRoute`); sipgo `sip/transaction_layer.go:154-185` hands an unmatched CANCEL to the handler
- RFC: RFC 3261 §9.2 (CANCEL matching no transaction → 481); §21.4.6 (a 405 MUST include `Allow`).
- Confirm: send a CANCEL with an unknown branch from a peer IP; assert 481.
- Action: fix.

### P2-TRK-015 — Refresh 200 on the raw transaction is never retransmitted (P1, transaction, INFERENCE; documented)
- Location: `internal/trunk/b2bua.go:183-188`, `:206-214`
- RFC: RFC 3261 §13.3.1.4 (the UAS core retransmits a 2xx to INVITE until the ACK arrives).
- Impact: on UDP, one lost 200 causes the refresher's transaction to time out, and RFC 4028 §10 then lets it BYE the call.
- Confirm: a UDP refresh re-INVITE where the test harness drops the first 200; assert that a retransmission arrives within T1·2.
- Action: fix.

### P2-TRK-016 — Outbound TLS trust and client certs merged across peers (P1, transport/security, INFERENCE)
- Location: `internal/trunk/tlscert.go:61-97`, installed UA-wide at `server.go:167-182`
- Evidence: every peer's `tls_ca` is appended to one `RootCAs` pool (together with the system roots), and every peer's client cert goes into one `Certificates` slice.
- Impact: a certificate issued by carrier A's private CA, or any public CA, is accepted when dialing carrier B. Go's TLS client presents the first acceptable entry in `Certificates`, so carrier B may receive carrier A's client certificate (a cross-peer identity leak) or the wrong one (a failed mTLS).
- Confirm: two TLS peers with distinct private CAs; the peer-B endpoint serves a cert signed by peer A's CA; assert that the dial fails. It will succeed.
- Action: rewrite (per-peer `tls.Config` selected by target).

### P2-TRK-017 — Graceful shutdown leaves bridged calls without BYE and onInvite goroutines parked (P1, config/lifecycle, INFERENCE)
- Location: `internal/trunk/server.go:305-318` (Run returns after closing the listeners); `internal/trunk/b2bua.go:467-483` (the select waits only on the leg contexts, `sess.Done` and `killCtx`); `internal/app/app.go:55` (the pool is never closed)
- Evidence: nothing cancels live calls on `Run` return. `ua.Close()` and `client.Close()` run while bridged `onInvite` goroutines are still parked, and no BYE is sent to either leg.
- Invariant: dialogs, legs, ports and goroutines are released on shutdown.
- Confirm: resource-balance test. Bridge N calls, cancel `Run`'s ctx, then assert that both fake peers received BYE, that `ActiveCalls()==0`, that pool `Stats` shows 0 allocated, and that `runtime.NumGoroutine` returns to baseline within a bounded retry.
- Action: fix (on stop, kill every call with byeBoth before closing transports).

### P2-TRK-018 — `headerSeconds` overflows on large values (P2, transport, INFERENCE)
- Location: `internal/trunk/timers.go:24-28`
- Evidence: `time.Duration(n) * time.Second` with `n` up to MaxInt64. For example `Session-Expires: 10000000000000` wraps around. The result feeds `negotiateSE`, the 422 test and `sessionExpiresHeader` (`int(d.Seconds())`).
- RFC: RFC 4028 §4 (delta-seconds); RFC 3261 §25.1 (delta-seconds values larger than 2**32-1 should be treated as 2**32-1).
- Confirm: unit test `headerSeconds` with `9223372036854775807`; assert a non-negative, clamped result.
- Action: fix (clamp).

### P2-TRK-019 — Early-media relay can race the main path after abandonment (P2, dialog, INFERENCE)
- Location: `internal/trunk/b2bua.go:1139-1158` (check `abandoned`, then `relay(res)` → `aLeg.Respond`), `:1194-1222` (the main path sets `abandoned` after a 250 ms grace, then placeCall continues: next target, or final `aLeg.Respond`)
- Evidence: this is a TOCTOU window. An `OnResponse` that passed the `abandoned.Load()` check before the flag was set can still be inside `aLeg.Respond(18x)` while the main path sends the final response, or while the next attempt's waiter relays. That is concurrent `WriteResponse` on one `DialogServerSession`.
- Confirm: stress test with a fake carrier that delays its 180 so it arrives exactly at ring_timeout+250 ms, run under `-race` with `-count=200`.
- Action: fix (serialize A-leg responses through one owner goroutine).

### P2-TRK-020 — `lookupSRVTimeout` abandons a goroutine per timed-out lookup; `time.After` in loops (P2, transport, INFERENCE)
- Location: `internal/trunk/resolve.go:82-101` (the goroutine blocked in `net.LookupSRV` keeps running after the 3 s timeout); `internal/trunk/register.go:179` (`time.After(wait)` per iteration, harmless on Go ≥1.23, `go.mod` says 1.25.7)
- Action: fix (use `net.Resolver.LookupSRV(ctx, …)`). The `time.After` issue: no action.

### P2-TRK-021 — REGISTER uses a new Call-ID and CSeq=1 on every refresh (P2, transaction, INFERENCE)
- Location: `internal/trunk/register.go:69-92` (`sip.NewRequest` per call, `ClientRequestRegisterBuild` generates a fresh Call-ID)
- RFC: RFC 3261 §10.2 (a UA SHOULD use the same Call-ID for all registrations to a registrar during a boot cycle, and increment CSeq).
- Impact: strict registrars may treat each refresh as out of order or as a new binding.
- Confirm: fake registrar that records Call-IDs across two refreshes; assert they are equal.
- Action: fix.

### P2-TRK-022 — Crypto proto detection ignores SAVPF; `remoteMediaIP` rejects FQDN `c=` (P2, SDP, INFERENCE)
- Location: `internal/trunk/sdp.go:92-97` (`p == "SAVP"` only), `:38-41` (`netip.ParseAddr` on `c=`)
- RFC: RFC 5124 (RTP/SAVPF); RFC 4566 §5.7 (`c=` may carry an FQDN).
- Impact: a secure `RTP/SAVPF` offer is treated as insecure under `srtp: required` and gets 488. An FQDN `c=` gets 488.
- Action: fix.

### P2-TRK-023 — Ignored errors on response/BYE sends (P2, dialog, INFERENCE)
- Location: `internal/trunk/b2bua.go:248`, `:261`, `:288`, `:306`, `:341`, `:376`, `:470`, `:474`, `:493`, `:496`, `:649`, `:701-705`, `:928`, `:959`, `:970`, `:1007`, `:1355`, `:1653`; `server.go:286`, `:436`
- Evidence: `_ = aLeg.Respond(...)`, `_ = c.bLeg.Bye(...)`, `_ = tx.Respond(...)`, `_ = s.registrar.Run(regCtx)`. Teardown BYE failures are invisible in logs (only `ackThenBye` logs them).
- Action: fix (log at Debug at least). This is style-adjacent, but it hides lost teardowns.

### P2-TRK-024 — docs/design.md §6 line citations are stale (P2, docs, FACT via `grep -n`)
Checked with `grep -n` against the current tree:
- `expandTargets` cited `b2bua.go:579-602` → actual `b2bua.go:571-594`
- `placeCall` cited `:649-716` → actual `:641-708`
- teardown `select` cited `:471-487` → actual `:467-483`
- `byeBoth` cited `:495-502` → actual `:491-498`
- `onInvite` cited `:127-488` → actual `:127-484`
- `callDialing` literal cited `:404` → actual `:400`
- `carrierAnswered` cited `:1332` → actual `:1366`
- waiter teardown cited `:1015-1017` → actual `:1168-1170`
- unconditional teardown cited `:1144-1146` → actual `:1295-1297`
- SRTP mismatch cited `:1220-1233` → actual `:911-923`
- `negotiateSE` call cited `:1303-1306` → actual `:993-996`
- `processAnswerSDP` cited `:1528-1567` → actual `:1561-1600`
- handler registration `server.go:236-240` → actual `:235-239`
- tcp fields `server.go:84-86` / `:117-118` → actual `:83-85` / `:116-117`
- reconcile condition `register.go:312-316` → actual `:292`
- `requestedExpires` `:418-423` → actual `:397-402`
- `stopAll` `:377-389` → actual `:356-368`

Action: fix the docs.

### P2-TRK-025 — docs/trunk.md contradicts design.md and the code on SDP rewriting (P2, docs, INFERENCE)
- `docs/trunk.md:65-66` says "full SDP rewrite". `docs/design.md` §6.7 and `sdp.go:126-195` say in-place editing with pass-through of everything except the listed fields. See 006.
- Action: fix the docs (or fix the code per 006).

### P2-TRK-026 — Shield auto-ban is unreachable on the trunk plane (P2, transport, INFERENCE; documented)
- Location: `internal/trunk/server.go:455-471` (`dropUnidentified` is unreachable over udp/tcp/tls because `readfilter.go:22-33` drops first)
- Impact: `RecordUnidentified` is dead code on this plane in production. Scanning sources are never banned, which is why 001 has no kernel-level mitigation.
- Action: delete or rewire (count read-filter rejections).

## Checklist items found clean (one line each)
- Transaction keying: delegated to sipgo (branch + method); the trunk adds no transaction map.
- ACK layer: ACK to non-2xx is absorbed by the sipgo server tx; ACK to 2xx goes to the TU via `dialogSrv.ReadAck` (`server.go:569-577`) (RFC 3261 §17.1.1.3, §13.2.2.4).
- INVITE retransmissions: absorbed by the sipgo server transaction; the trunk handles each INVITE once.
- CANCEL before a provisional on the B-leg: sipgo holds CANCEL until a 1xx; the ring budget is kept by the 250 ms grace/abandon path (RFC 3261 §9.1).
- CANCEL vs 2xx race on the B-leg: every raced 2xx gets `ackThenBye` (`b2bua.go:1168-1170`, `:1295-1297`).
- CANCEL vs A-leg 200: a failed `aLeg.Respond` BYEs the B-leg (`b2bua.go:1001-1009`).
- BYE matching: both dialog caches are tried, 481 only if neither matches (`server.go:594-614`).
- Glare/491: the SBC never originates a re-INVITE, so there is no glare path.
- Shield: `withShield` Drop is silent (`server.go:441-443`); unidentified sources get silence, including in `onNoRoute`.
- Dialog-client cache: every B-leg path ends in `Close` or `Bye` (whose `WriteBye` defers `Close`), so there is no sipgo cache leak.
- Quota slot: released by defer on every exit, including a panic (`b2bua.go:229-234`).
- Media session: allocated once, `defer sess.Close()` on every onInvite exit (`b2bua.go:369-379`).
- a=crypto: stripped from every inbound m-line and at session level; declined m-lines lose all attributes (`sdp.go:141-189`).
- SDP answer m-line count/order: the B-offer keeps every offered m-line (declined ones set to port 0), so a compliant answer matches (RFC 3264 §6). The carrier answer is not validated, so a non-compliant carrier answer passes through unchecked (minor, not filed).
- Port 0: `firstAudio` skips port-0 sections; non-relayed sections are forced to port 0.
- Credentials: the trunk holds outbound digest credentials only (by design, peers.*.auth); there is no inbound credential inspection and no ESL/call-center logic.
- Lock across I/O: `callMu`, `callQuota.mu`, `Registrar.mu` and `Resolver.mu` are never held across network I/O or a channel send (`resolve.go:138-177` does the lookup outside the lock).
- Maps: `calls`, `legs`, quota, health, resolver cache and registrar maps are all mutex-guarded.
- `time.Sleep` for synchronization: none in production trunk code.
- Single-implementation interfaces / `any`: none, except `singleflight` `any` with a forced assertion at `resolve.go:178` (safe; the fn never returns another type).
- Defer in loops: none.
- Per-RTP-packet work: none in this package (media lives in `internal/media`).
- Latching: the trunk passes IP-only expected remotes (`SetExpectedRemote`/`Relatch` with `netip.Addr`). Whether any source port is accepted is decided in `internal/media` (out of scope; see the media review).
