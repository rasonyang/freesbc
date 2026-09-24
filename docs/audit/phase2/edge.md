# Phase 2 — semantic review: `internal/edge`

Scope: production files of `internal/edge` at commit 1e63913 (codecs.go, cooldown.go,
dialog.go, edge.go, forward.go, invite.go, location.go, media.go, mediapool.go,
metrics.go, plane.go, register.go, topology.go). Method: reading, plus reading
sipgo v1.4.3 sources in the module cache to confirm how the transaction layer
behaves. No tests were run. Every finding below is **INFERENCE** unless it says
otherwise. `go vet ./internal/edge` is clean.

sipgo references use `$SIPGO = $(go env GOMODCACHE)/github.com/emiago/sipgo@v1.4.3`.

## Findings (highest severity first)

### P2-EDG-001 · P0 · media · INFERENCE — the public RTP leg latches to the first packet from any source
- Evidence: `internal/edge/media.go:190` and `internal/edge/media.go:343` allocate every plain-RTP session with `Latch: [2]media.LatchMode{media.LatchLoose, media.LatchStrict}`. In `internal/media/session.go:106-129`, `accept` in loose mode skips the `expected` check, and the first accepted packet sets `latched = true` for good (the comment at `session.go:33-34` says it "never moves afterwards").
- Impact: anyone who sends RTP to the SBC's public port first owns the media leg. Ports come from a sequential pool, so they are guessable. Packets sent after `AllocateAcross` binds the socket wait in the kernel buffer and are read first when `Start()` runs. From then on the attacker receives the FreeSWITCH→phone audio, and the real phone's packets are dropped as a hijack. This applies to phones (`allocateRTP`) and to FS→client and PSTN carrier legs (`buildPublicOffer`). The seeded expected IP (`SetRemote` → `latch.seed`) is ignored in loose mode.
- Invariant: "NAT latching that accepts media from arbitrary sources". This is also a docs drift: `docs/edge.md:67` says "Strict source latching resists off-path hijacking".
- Test to confirm: in the harness, place a phone call. Before the phone sends any RTP, send one RTP packet from a third UDP socket to the advertised public port. Then send phone RTP and assert it is not forwarded to fake FS, and that fake-FS RTP arrives at the third socket.
- Action: **fix**. Use strict mode seeded from SDP, and allow relatching only to a source that proves itself (for example, the SSRC or the address in the SDP).

### P2-EDG-002 · P0 · transport · INFERENCE — metrics key on an attacker-chosen method name, with no bound
- Evidence: `internal/edge/edge.go:512` calls `s.metrics.RequestIn(req.Method.String(), req.Transport())` before the shield check at `edge.go:516-519`. `internal/edge/metrics.go:53` creates a new `sync.Map` entry for every distinct `method/transport` (`metrics.go:45-51`) and never removes one. sipgo accepts any request-line token as a method (`$SIPGO/sip/parser.go:413`). Unknown methods then reach `onNoRoute` (405), after they have already been counted. The map is exported to admin/Prometheus (`internal/admin/metrics.go:134`, `internal/admin/server.go:81`).
- Impact: a public client can grow memory without limit, and grow Prometheus label cardinality, by sending requests with random method names. This happens even when the shield would drop them.
- Test to confirm: send 5 000 UDP requests with distinct methods (`X0001 sip:a@h SIP/2.0`…) to the public listener, then assert `len(Metrics().Snapshot().RequestsIn)` stays bounded (for example, ≤ the known-method count × transports + 1).
- Action: **fix**. Bucket unknown methods into `OTHER`, and count after the shield.

### P2-EDG-003 · P0 · transport · INFERENCE — a packet on the public socket is trusted as FreeSWITCH based on its source address alone
- Evidence:
  - `isPSTNBridgeInvite` (`invite.go:110-127`) trusts `topo.fromUpstream(src.Addr())` for a request that arrived on the **public** socket.
  - `arrivedOnPrivate` (`plane.go:88-97`) asks `privSources`, which is keyed by source `addr:port` only (`plane.go:48-62`). A public-socket packet whose source is `FS-IP:5060` therefore counts as private once genuine private traffic from that address:port has been seen in the last 10 minutes.
  - `guard` then skips the shield (`edge.go:516`).
- Impact: a blind UDP packet with a spoofed source (the upstream IP) sent to the public listener leads to one of these:
  - With the Request-URI set to `sip.pstn.match`, FreeSBC dials the PSTN gateway. This is toll fraud: the carrier answers, and the call lives until the unACKed 200 times out, around 32 s.
  - Classified as private, the packet reaches `inviteToClient`, which falls back to AoR and rings any registered user (`invite.go:1408-1416`) with no shield applied.
- Precondition: the host accepts spoofed private-range sources on its public NIC. Linux `rp_filter=2` (loose) accepts them whenever the source is routable through any interface, and the upstream LAN is. The read filter guards only the private socket (`edge.go:475-487`).
- Test to confirm: in the loopback harness, where the upstream IP is 127.0.0.1, send an INVITE with the Request-URI set to the match address **to the public listener from an ephemeral client socket**. Assert that a gateway is dialed. This shows the classification ignores which local socket the packet arrived on.
- Action: **rewrite** the plane/trust classification so it is keyed by local socket. For example, have FreeSWITCH bridge PSTN calls to the private socket or to a dedicated trusted listener, and record the local address per message rather than per source.

### P2-EDG-004 · P1 · transaction · INFERENCE — retransmitted 2xx and forked 2xx are never relayed
- Evidence: the client transaction is terminated as soon as the first final response arrives: `invite.go:248` (`clTx.Terminate()` after `pumpInvite`), `invite.go:373` (deferred, runs right after `commit`) and `invite.go:574`. In sipgo, a 2xx moves the INVITE client transaction to Accepted, where retransmissions are passed up (`$SIPGO/sip/transaction_client_tx_fsm.go:84-110`). `Terminate` deletes the transaction (`transaction_client_tx.go:119-129`), so later 2xx go to `unRespHandler`, which only logs (`$SIPGO/sip/transaction_layer.go:282-288,18-19`). The server transaction toward the caller does not retransmit 2xx itself (`$SIPGO/sip/transaction_server_tx_fsm.go:70-83`, RFC 6026 §7.1).
- Impact: if one 200 OK is lost on the public UDP leg, the call fails. The caller never gets a 200 and the callee never gets an ACK, so the callee BYEs after 64·T1. A 2xx from a second fork is also dropped: it is never ACKed, and the forked UAS retransmits it and then tears down.
- RFC: 3261 §16.7 step 10 and §13.3.1.4; RFC 6026 §7.2/§8.
- Test to confirm: have fake FS answer the client's INVITE with 200 and retransmit the same 200 after 500 ms and 1.5 s. Have the test UAC withhold its ACK and count the 200s it receives. Expect ≥ 2; the inference predicts 1.
- Action: **fix**. Keep the client transaction until Timer M and relay 2xx retransmissions statelessly.

### P2-EDG-005 · P1 · dialog · INFERENCE — a BYE with the wrong tags, from any source, tears down the call's media
- Evidence: `dialogTable` is keyed by Call-ID alone (`dialog.go:131-152`). `onInDialog` calls `s.teardown(callID)` for **every** BYE after `forwardAndRelay`, whatever the far end's final response was or whether the forward failed (`invite.go:1300-1302`, `invite.go:1308-1312`). The only check is that `directionFor` resolves, and for public sources it never fails (`invite.go:1342-1367`). Neither the tags nor the source address are compared against the dialog record.
- Impact: anyone who knows a Call-ID (Call-IDs cross the internet in cleartext on UDP) can send a BYE with made-up tags. The endpoint answers 481, but FreeSBC has already closed the media and dropped the dialog record, so the call carries no audio and later in-dialog requests from FS get 481.
- RFC: 3261 §12 (dialog id = Call-ID + local tag + remote tag), §12.2.2 (481 for an unmatched dialog), §15.1.2.
- Test to confirm: establish a phone→FS call. From a different UDP socket, send `BYE` with the same Call-ID and random From/To tags. Assert that `ActiveCalls()` is still 1 after fake FS answers 481, and that RTP is still relayed.
- Action: **rewrite** the dialog identity model: key on Call-ID plus both tags, store the tags at commit, and tear down only on a 2xx to a tag-matched BYE.

### P2-EDG-006 · P1 · dialog · INFERENCE — forked early dialogs share one answer body and one latch
- Evidence: `pumpInvite` negotiates only the first body-bearing response and replays `lastAnswer()` for every later one, whatever its To tag (`invite.go:986-1007`). `pumpPSTNAttempt` does the same (`invite.go:708-733`). There is one `mediaSession` per Call-ID (`dialog.go:145-149`).
- Impact: a carrier or downstream proxy that forks (183 from fork A, 200 from fork B) gets fork A's answer relayed for fork B, and the media stays latched to fork A's address. The result is one-way audio or none.
- RFC: 3261 §13.2.2.4 and §19.3; RFC 3264 §6 (every fork's answer is its own). This is documented as a limitation (`docs/edge.md:200-201`), but the code does not reject the second To tag; it silently misrelays it.
- Test to confirm: fake gateway sends 183+SDP (tag A, port X), then 200+SDP (tag B, port Y). Assert the 200 relayed to FS carries an answer derived from Y, or that the call is rejected.
- Action: **rewrite** (same identity-model root cause as P2-EDG-005).

### P2-EDG-007 · P1 · transaction · INFERENCE — in a CANCEL/2xx race, the dialog is committed for a caller that is gone
- Evidence: `pumpInvite` does not check `ctx.Err()` before it relays and returns a 2xx (`invite.go:978-1029`). Its callers then `commit` it (`invite.go:250-259`, `invite.go:387-390`). When sipgo matches the CANCEL it has already answered 487 to the caller (`$SIPGO/sip/transaction_server_tx_fsm.go:296-315`), so the relayed 200 is swallowed by the Completed state, but `commit` still confirms the dialog and pins the media. Nobody ACKs or BYEs the callee. The PSTN pump handles this case (`invite.go:674-689`: `ackThenBye`); the upstream and client pumps do not.
- RFC: 3261 §9.1, §16.7 step 10 (a 2xx after CANCEL must be forwarded), §16.10 (the proxy should not generate the 487 itself).
- Test to confirm: set the fake FS INVITE hook to answer 200 only after it receives the CANCEL. Have the client CANCEL. Assert that fake FS receives ACK and BYE from FreeSBC, and that `ActiveCalls()` returns to 0 within 1 s.
- Action: **fix**. Check ctx, then `ackThenBye`, as the PSTN pump does.

### P2-EDG-008 · P1 · transaction · INFERENCE — an INVITE sent inside the ctx-check→track window is never CANCELled
- Evidence: `inviteToUpstream` checks `ctx.Err()` at `invite.go:197`, sends at `invite.go:230` and only `track`s the attempt at `invite.go:245`. PSTN has the same shape at `invite.go:520/557/571`. If a CANCEL lands in that window, `cancelPending` finds either no attempt or the previous, already-dead one (`dialog.go:302-311`). It cancels the series context, but the INVITE just sent gets no CANCEL. `pumpInvite` then drains for 300 ms and returns (`invite.go:1035-1043`).
- Impact: the next hop keeps ringing a call the caller has abandoned. If that hop answers, the 200 hits a deleted transaction and is never ACKed.
- RFC: 3261 §9.1, §16.10.
- Test to confirm: this is a race and hard to force. One approach: make the first upstream node fail with a transport error (closed port), then send the CANCEL in the gap between attempts, and assert whether node 2 ever receives an INVITE without a CANCEL.
- Action: **fix**. Track before sending, or re-check ctx after `track` and send the CANCEL.

### P2-EDG-009 · P1 · transaction · INFERENCE — backstop or no-answer expiry sends neither a CANCEL nor a final response
- Evidence:
  - When `pumpInvite`'s `ctx.Done()` arm fires because the 5-min `inviteTimeout` expired, it assumes "the CANCEL is on the wire" and only drains (`invite.go:1035-1043`). `inviteToUpstream` then returns silently (`invite.go:282-284`).
  - `inviteToClient` sends no final response when `pumpInvite` returns nil, whether from the backstop or from `clTx.Done()` with nothing relayed (`invite.go:387-391`). If the forward to a WS client fails on the transport, FreeSWITCH gets no final at all.
- RFC: 3261 §16.6 step 11 (Timer C), §16.7 step 6 (the proxy must generate 408 or the best response), §16.8 (on Timer C, CANCEL a branch that has a provisional response, else terminate it with 408). The client path is documented at `docs/design.md` §7.12, but it is still an RFC violation.
- Test to confirm: register a UDP client that never answers INVITEs, have fake FS call it, and assert FS receives a final (408/480) from FreeSBC and not only its own Timer B. `inviteTimeout` is a const, so the 5-min path cannot be tested without a code change. Record it under "could not verify".
- Action: **fix**.

### P2-EDG-010 · P1 · transaction · INFERENCE — PRACK and UPDATE are answered 405, but `Supported: 100rel`/`timer` and `Allow: UPDATE,PRACK` pass through
- Evidence: `allowedMethods` (`edge.go:539`) and `onNoRoute` (`edge.go:544-548`) answer PRACK and UPDATE with 405. `prepareForward` (`forward.go:40-89`) forwards `Supported`, `Require` and `Allow` unchanged.
- Impact:
  - A callee that sees `Supported: 100rel` may send a reliable 183. The caller's PRACK gets 405, so the 183 is retransmitted and the UAS fails the call after 64·T1 (RFC 3262 §3).
  - A session-timer refresher that uses UPDATE (RFC 4028 §7.4/§9, which is allowed because the caller advertised UPDATE) gets 405, and the call is torn down at session expiry.
  - `docs/edge.md:211` lists UPDATE as 405 but not these consequences.
- Test to confirm: send an INVITE with `Supported: 100rel` from the client, have fake FS send `183` with `Require: 100rel` and `RSeq: 1`, then send a PRACK from the client and assert it is not answered 405.
- Action: **fix**. Either strip `100rel`/`timer` from `Supported` and PRACK/UPDATE from `Allow`, or proxy both methods.

### P2-EDG-011 · P1 · SDP · INFERENCE — a re-INVITE offer toward a WebRTC browser is built as plain RTP/AVP
- Evidence: `rebuildInDialogOffer` (`media.go:506-531`) always builds `sdp.Build{...}.Marshal()` without DTLS, ICE or fingerprint, including when `to.plane == planePublic` and the session is WebRTC. Only the answer path calls `setWebRTCAnswer` (`media.go:558-560`).
- Impact: a FreeSWITCH-originated re-INVITE toward a browser (hold, session-timer refresh) carries `RTP/AVP` with no `a=fingerprint` or `a=ice-*`. The browser rejects it, and hold or the refresh fails; with session timers, the call drops. This is docs drift: `docs/edge.md:70` says a WebRTC leg keeps its ICE credentials, fingerprint and DTLS role across re-INVITE.
- RFC: RFC 3264 §8 (an offer must describe the same stream), RFC 5763 §5.
- Test to confirm: in the WebRTC harness, after the browser→FS call is up, have fake FS send a re-INVITE. Assert the body forwarded to the browser contains `UDP/TLS/RTP/SAVPF`, `a=fingerprint` and the same `a=ice-ufrag`.
- Action: **fix**.

### P2-EDG-012 · P1 · media · INFERENCE — a re-INVITE never applies the far end's new media address or port
- Evidence: `rebuildInDialogOffer` and `rebuildInDialogAnswer` (`media.go:506-562`) parse the peer's body, update codecs, and never call `SetRemote`, `Relatch` or `SetPrivateRemote`. `media.Session.Relatch` exists for exactly this case (`internal/media/session.go:276-283`: "for an authorized media-address change signalled by a re-INVITE") and has no edge caller.
- Impact: when FreeSWITCH moves its RTP port, or a phone changes IP (Wi-Fi→LTE) and re-INVITEs, the latched side stays on the old address and audio stops. A re-offer with port 0 or `c=0.0.0.0` hold is also not reflected: the SBC keeps sending to the old address.
- RFC: RFC 3264 §8.3.1 and §8.3.2.
- Test to confirm: after a call is up, have fake FS re-INVITE with a new `m=` port and then send RTP from that port. Assert it reaches the phone and the phone's RTP reaches the new port.
- Action: **fix**.

### P2-EDG-013 · P1 · transaction · INFERENCE — a re-INVITE 2xx that cannot be anchored is never ACKed or BYEd
- Evidence: on an adapt error, `onReInvite` answers 488 to the requester and returns (`invite.go:1205-1208`). There is no `ackThenBye` call, unlike the initial INVITE path (`invite.go:1021-1023`). An answer with the audio stream rejected (port 0) also fails `sdp.Parse` with `ErrNoAudio` (`internal/sip/sdp/sdp.go:204-213`) and takes this same path.
- Impact: the far end has a 200 that nobody ACKs. It retransmits and then BYEs the whole call (RFC 3261 §13.3.1.4), while the near end got 488 and believes the old session still stands.
- Test to confirm: have fake FS answer a client re-INVITE with 200 and a renumbered payload type. Assert fake FS receives an ACK.
- Action: **fix**.

### P2-EDG-014 · P1 · transaction · INFERENCE — PSTN failover retries on 6xx
- Evidence: `pumpPSTNAttempt` holds and retries on `res.StatusCode >= 500 || res.StatusCode == 408` (`invite.go:694-697`), which includes 600–699.
- RFC: 3261 §16.7 step 5 and §21.6: a 6xx means no other location should be tried, and the proxy must CANCEL pending branches. A 603 Decline therefore re-rings the number on the next gateway. This is also docs drift: `docs/edge.md` says failover happens on "a 5xx/408".
- Test to confirm: gw-a answers 603 and gw-b uses `answerHook(200)`. Assert gw-b receives no INVITE and fake FS receives 603.
- Action: **fix**.

### P2-EDG-015 · P1 · transaction · INFERENCE — a provisional response in the post-expiry drain becomes the synthesised final
- Evidence: in `expirePSTNAttempt`'s drain, every forwardable non-200 response goes to `default` and is classified `failReal` with its own code (`invite.go:832-854`). That includes a 180/183 and any 2xx other than 200. At exhaustion, `s.reject(req, tx, lastRealCode, ...)` (`invite.go:622-623`) can then send a **1xx** as the "final", so FreeSWITCH never gets one. A 202 is neither ACKed nor BYEd.
- RFC: 3261 §16.7 step 6; §17.1.1.3.
- Test to confirm: use one gateway with `attempt_timeout: 1s`. The gateway stays silent until it receives the CANCEL, then sends 180 followed by 487. Assert fake FS receives a final (408), not a 180.
- Action: **fix**.

### P2-EDG-016 · P1 · SDP · INFERENCE — the answer's m-line order and media types do not mirror the offer
- Evidence: `sdp.Parse` relays the first live audio section at any index (`internal/sip/sdp/sdp.go:204-209`). `MarshalDeclining` always writes that section first and declines the rest as `m=audio 0` (`internal/sip/sdp/build.go:74-80,195-205`). The edge uses it for every answer: `media.go:315,404,462,561`.
- Impact: an offer of `m=video …` followed by `m=audio …` gets an answer of `m=audio <port>` followed by `m=audio 0`. The order is wrong and the declined section has the wrong media type.
- RFC: RFC 3264 §6 (same number and order of m-lines, and each answered m-line has the offered media type). The `sip/sdp` owner should also review this.
- Test to confirm: send a browser offer with the audio section second and assert the answer's first m-line is `m=video 0`.
- Action: **fix**.

### P2-EDG-017 · P1 · media · INFERENCE — the DTLS peer fingerprint is checked after the SRTP relay has started
- Evidence: `allocateWebRTC` calls `sess.Start` (`media.go:239`), and `Start` launches the relay goroutines (`internal/media/webrtcsession.go:179-183`). Only afterwards does `leg.VerifyFingerprint` run (`media.go:248-257`).
- Impact: for a short window, decrypted FreeSWITCH audio is re-encrypted toward a peer whose certificate has not been checked. The attacker must also know the ICE credentials, which lowers the practical risk. The invariant "peer certificate is checked against a=fingerprint" (`docs/edge.md:68`) should hold before any keying material is used.
- Test to confirm: unit test in media or edge. Complete ICE/DTLS with a certificate that does not match the offered fingerprint, and assert that no SRTP packet is written to the peer socket.
- Action: **fix**. Verify inside establishment, for example with `VerifyPeerCertificate`.

### P2-EDG-018 · P1 · dialog · INFERENCE — an ACK can race the commit
- Evidence: the 2xx is relayed inside `pumpInvite` (`invite.go:978-1028`) before `commit` → `d.confirm` runs (`invite.go:259, 389, 582`). In that window:
  - An ACK from FreeSWITCH (private plane) has no dialog record, and its Request-URI names the SBC with no `fsbc` token, so `directionFor` fails and the ACK is dropped silently (`invite.go:1325-1335`, `invite.go:1227-1230`).
  - A public ACK falls back to hashing, which picks a different node from the failover winner when the winner was not the hash head (`invite.go:1363-1366`).
- Impact: the callee never sees the ACK and drops the call after 64·T1.
- RFC: 3261 §13.2.2.4 and §17.1.1.3. The comment at `invite.go:1355` acknowledges the race.
- Test to confirm: run many FS→client calls in a loop, with the client ACKing immediately, and assert that the client or FS saw every ACK.
- Action: **fix**. Confirm the dialog before relaying the 2xx.

### P2-EDG-019 · P1 · leg/binding · INFERENCE — the binding expiry is read from the wrong Contact
- Evidence: `recordBinding` (`register.go:262`) uses `fsip.GrantedExpires` (`internal/sip/register.go:14-31`), which returns the `expires` of the **first** Contact in the 200 that has one. A registrar's 200 lists every binding of the AoR (RFC 3261 §10.3 step 8), so the first Contact can be a different device's.
- Impact: this device's binding expires too early, so inbound calls fail, or it outlives the registrar's binding.
- RFC: 3261 §10.2.4 and §10.3.
- Test to confirm: have fake FS answer REGISTER with `Contact: <other>;expires=30` followed by `Contact: <ours;fsbc=tok>;expires=3600`. Assert the binding is still resolvable at 31 s, or check `ExpiresAt` directly.
- Action: **fix**. Match the Contact that carries this binding's `fsbc` token.

### P2-EDG-020 · P2 · config/lifecycle · INFERENCE — the OnCancel hook blocks for up to 5 s inside sipgo's transaction FSM lock
- Evidence: sipgo runs the OnCancel callback inside `actCancel` while holding `fsmMu`, and only after that returns does it send the 487 (`$SIPGO/sip/transaction_server_tx_fsm.go:296-315`, `$SIPGO/sip/transaction.go:249-260`). The edge callback is `cancelPending`, which sends the CANCEL and waits up to 5 s for the response (`invite.go:1511-1525`).
- Impact: while that lock is held, the 487 to the caller is delayed and every `tx.Respond` from the response pump blocks. This is a lock held across network I/O.
- Test to confirm: fake FS never answers the CANCEL. Measure the latency between the client's CANCEL and the 487 it receives; the inference predicts about 5 s.
- Action: **fix**. Run `cancelPending` asynchronously from the hook.

### P2-EDG-021 · P2 · transport · INFERENCE — the shield exemption for FreeSWITCH's PSTN INVITEs depends on a 10-minute cache
- Evidence: a PSTN bridge INVITE arrives on the public socket and skips the shield only if `privSources` still holds FS's `addr:port` from private traffic seen within `ttl` (`plane.go:42,65-70`; `edge.go:516`). If FreeSWITCH has sent no private traffic in the last 10 minutes, its PSTN INVITEs are rate-limited like an attacker's, and a Drop is silent.
- Test to confirm: wait out the TTL (or unit-test with a short TTL) and assert `arrivedOnPrivate` returns false for the same source.
- Action: **fix**. Fold into the P2-EDG-003 rewrite.

### P2-EDG-022 · P2 · transport · INFERENCE — shield-banned public sources still get responses
- Evidence: the edge read filter checks only the size and the private socket (`edge.go:467-489`); it does not consult shield bans. sipgo answers malformed requests with a stateless 400 (`$SIPGO/sip/transaction_layer.go`, `rejectMalformedRequest`) and answers a CANCEL that matches a transaction with 200 (`transaction_layer.go:154-181`), both before `guard` runs.
- Impact: a banned address still gets responses. Invariant: shield denials must be silent drops.
- Test to confirm: ban an IP through the shield, send a request with no CSeq from it, and assert that no response is received.
- Action: **fix**.

### P2-EDG-023 · P2 · transaction · INFERENCE — two finals on one transaction
- Evidence: when `pumpInvite` has already sent 488 (`invite.go:1024-1025`) and returns `(nil, true)`, `inviteToUpstream` breaks out of the loop (`invite.go:271-272`) and calls `s.reject(req, tx, 503, …)` (`invite.go:288`). sipgo drops the second final in the Completed state, but `metrics.ResponseOut(503)` still counts it (`edge.go:557`).
- Test to confirm: fake FS answers 200 with an unanchorable SDP. Assert `ResponsesOut["5xx"] == 0`.
- Action: **fix**.

### P2-EDG-024 · P2 · media · INFERENCE — unsynchronised writes to `mediaSession.codecs`, and one `answer` shared by concurrent re-INVITEs
- Evidence: `sess.codecs` is written with no lock at `media.go:288,389,446,546`. Re-INVITE glare from both sides runs two `onReInvite` goroutines against the same `dialog`. `d.lastAnswer()` (`invite.go:1188-1190`) can then restate the **other** direction's body, which carries the wrong plane's address and, for WebRTC, ICE/DTLS toward FreeSWITCH. The codecs race is acknowledged in `docs/design.md` §7.7.
- Test to confirm: send simultaneous re-INVITEs from the client and fake FS under `-race`.
- Action: **fix**.

### P2-EDG-025 · P2 · config/lifecycle · INFERENCE — reloading the RTP bind IP takes effect, but the advertised media IP does not
- Evidence: the media pools re-read `BindIP` and port ranges on every allocation (`mediapool.go:15-30`). The advertised media IPs are fixed in the topology at startup (`topology.go:331-332`).
- Impact:
  - A reload that changes `rtp.public.bind_ip` or `advertised_ip` binds new sockets but keeps advertising the old IP in SDP, so media is black-holed.
  - `docs/design.md:337-345` lists "RTP port ranges and bind IPs" as hot and does not list `rtp.*.advertised_ip` or `network.*.advertised_ip` as restart-only. This is docs drift.
  - `AllocateAcross` reads the config twice per call (once per pool), so the two legs of one call can come from different snapshots.
- Test to confirm: after `Store.Replace` with a new `rtp.public.bind_ip`, place a call and assert the SDP `c=` matches the new bind.
- Action: **fix**.

### P2-EDG-026 · P2 · leg/binding · INFERENCE — the teardown ACK/BYE is not pinned to a listener socket
- Evidence: `ackThenBye` builds its requests with `fsip.TeardownRequest` (`internal/sip/request.go:69-81`), which never sets `Laddr` (`invite.go:1054,1060-1063`). `prepareForward` pins `Laddr` (`forward.go:77-87`), and the `Run` comment (`edge.go:231-248`) says unpinned or mismatched sends made sipgo open a second socket (EADDRINUSE). The existing test `TestPSTNUnanchorableAnswerFailsOver` passes with explicit bind IPs; wildcard binds are not covered.
- Test to confirm: repeat the unanchorable-answer test with a harness public bind of `0.0.0.0` (`startHarnessOn`).
- Action: **fix**.

### P2-EDG-027 · P2 · dialog · INFERENCE — an in-flight INVITE can outlive shutdown and allocate media after `closeAll`
- Evidence: `Run` calls `s.dialogs.closeAll()` (`edge.go:307`) before the deferred `client.Close()`/`ua.Close()` (`edge.go:174,185`) and never waits for handler goroutines. A handler that is already past the read loop can `begin()` and allocate media after `closeAll`. Those ports are freed only when its client transaction dies. Handler, `ackThenBye` and WebRTC `Start` goroutines can outlive `Run`.
- Test to confirm: goroutine and port balance test. Cancel the ctx while an INVITE is mid-allocation, then assert pool usage is 0 and `runtime.NumGoroutine` returns to baseline (with a bounded retry).
- Action: **fix**.

### P2-EDG-028 · P2 · leg/binding · INFERENCE — `Contact: *` un-REGISTER is rewritten into a single token contact
- Evidence: `onRegister` replaces whatever Contact arrived with `registeredContact(user, token)` (`register.go:107-109`), including the wildcard. `recordBinding` removes only the (AoR, Call-ID) binding (`register.go:263-265`).
- Impact: the other bindings of the AoR survive both upstream and locally.
- RFC: 3261 §10.2.2.
- Test to confirm: register twice with different Call-IDs, then send `Contact: *` with `Expires: 0`. Assert that both local bindings are gone.
- Action: **fix**.

### P2-EDG-029 · P2 · transaction · INFERENCE — an orphan CANCEL is answered 481 instead of being forwarded statelessly
- Evidence: `invite.go:1245-1254`. RFC 3261 §16.10 says that when there is no response context, the proxy MUST forward the CANCEL statelessly. Impact is low, because FreeSBC is the only hop that holds the context.
- Action: **fix** (or document).

### P2-EDG-030 · P2 · SDP · INFERENCE — the fmtp value is copied verbatim from the other leg
- Evidence: the codec list, including `FMTP`, is taken from the peer's body (`media.go:135,152`, `codecs.go:34-42`) and written unchanged by `build.go` (`fmtp` attribute). A sentinel string placed in fmtp therefore appears in the edge's output. The property "constructed, never derived" (`docs/edge.md:65`) holds for addresses in structured fields, but not for free text.
- Test to confirm: the Phase 3 SDP leak property test, with the sentinel also placed in fmtp.
- Action: **fix**. Allowlist fmtp parameters per codec.

### P2-EDG-031 · P2 · media · INFERENCE — media is allocated before the upstream authenticates the caller
- Evidence: `buildUpstreamOffer` allocates the RTP pair, or a WebRTC leg with its ICE agent and a 30 s establishment goroutine, before the INVITE is forwarded (`invite.go:157` versus `invite.go:230`).
- Impact: an unauthenticated flood holds 4 ports per INVITE for the duration of FS's 407 round trip, or up to Timer B when the upstream is silent. There is no edge call quota.
- Action: **fix**. Add a per-source quota, or allocate lazily.

### P2-EDG-032 · P2 · dialog · INFERENCE — a media-driven teardown sends no signaling
- Evidence: the watchdog and fingerprint-mismatch paths call `d.end()` (`dialog.go:340-343`, `media.go:255`), which closes the media and removes the record but sends no BYE to either side. A later BYE from FreeSWITCH then gets 481 (`invite.go:1332-1334`), because private-plane in-dialog requests carry no token.
- Action: **fix** (or document as a limitation).

### P2-EDG-033 · P2 · docs · INFERENCE — docs and code comments that no longer match the code
- `docs/design.md` §7.7 line citations are off by 1–2 lines: begin `dialog.go:168-178` is really 167-177; confirm `321-345` is 320-344; endUnlessUp `350-357` is 348-355; end `366-398` is 364-396.
- `docs/design.md` §7.8 cites the OnCancel hook at `invite.go:500-502`. The hooks are at `invite.go:172-185`, `383` and `490-504`.
- The same section says sipgo "finalises … with 487 … and fires the OnCancel hook". sipgo actually runs the hook first and sends the 487 afterwards (see P2-EDG-020).
- Stale identifiers in comments: `forwardInboundInvite`/`PrivateRemote` (`invite.go:1347-1348`) and `commitCall` (`invite.go:1355`). None of these exist; the real names are `inviteToClient`, `privateRemote` and `commit`.
- The docs drifts from P2-EDG-001 (`edge.md:67`), P2-EDG-011 (`edge.md:70`), P2-EDG-014 (`edge.md` PSTN failover) and P2-EDG-025 (`design.md:337-345`) also belong in this list.
- Action: **fix docs**.

### P2-EDG-034 · P2 · transport · INFERENCE — the `guard` recover() hides handler panics
- Evidence: `edge.go:500-506` logs the panic and sends 500, even if a final has already gone out. It is an intentional umbrella, but after a panic the dialog and media state are whatever the deferred calls left behind, and the process keeps running. Nothing counts these panics, so tests and operators cannot see them.
- Action: **fix**. Add a panic counter metric, and do not send a 500 once the transaction is finalised.

## Checklist items found clean (one line each)
- Goroutines have exit paths: the per-call `<-sess.Done()` watcher (`dialog.go:340`), the listener closers (`edge.go:255`), the prune ticker (`edge.go:283-292`), `ackThenBye` (5 s ctx) and the WebRTC `Start` goroutine (unblocked by `Close` through `s.done`).
- There is no `time.Sleep` for synchronisation and no `time.After` in a loop; every loop uses `time.NewTimer` with `Stop`.
- `dialogTable.mu` is never held across I/O or a channel send (`begin` calls `prev.end()` after unlocking).
- Every shared map is behind a mutex or a `sync.Map`: dialogTable, Location, privateSources, cooldownTable and metrics.
- Every `_ =` discard is on a Close, a best-effort Respond or `hash.Write`; none discards an error that matters, except those noted in P2-EDG-023 and P2-EDG-034.
- No interface with a single implementation and no `any` where a concrete type fits (`any` appears only in `sync.Map.Range` callbacks).
- There is no `defer` inside a loop.
- The edge package does no per-RTP-packet work; the packet path belongs to `internal/media`.
- Server transactions are keyed by sipgo on the top Via branch + sent-by + method (`$SIPGO/sip/transaction.go:306-346`), and a 2xx ACK (new branch) is forwarded statelessly in `onAck` — the right layer (RFC 3261 §17.1.1.3).
- The non-2xx ACK is generated and absorbed by sipgo's transaction layer (RFC 3261 §17.1.1.3/§17.2.1).
- INVITE retransmissions are absorbed by the sipgo server transaction and never reach `onInvite`.
- Compact header forms `i f t v m l c` are mapped by the sipgo parser (`$SIPGO/sip/parse_header.go:42-57`); the edge only looks headers up by canonical name.
- Every edge-built SDP address comes from the topology (`publicMediaIP`, `privateMediaIP`), never from the peer. `o=` is FreeSBC's own id, and the version is incremented for every body generated on a dialog (`dialog.go:86-95`, RFC 3264 §8). The fmtp exception is P2-EDG-030.
- Contact is rewritten toward each side on INVITE, responses and in-dialog requests. The `fsbc` token is length-capped (`invite.go:1444`) and resolved only through `Location`.
- FreeSBC never reads, stores or logs Authorization, nonces or passwords: REGISTER is forwarded verbatim and only the Contact changes (`register.go:107-115`, `register.go:225-241`).
- There is no call-centre, ESL or AICC logic in the package.
- A shield denial in `guard` is a silent `return` (`edge.go:517-519`). The exceptions that happen before `guard` are P2-EDG-022.
- On the edge, the topology, the WebRTC switch and identity, the listener set and the private read-filter address are startup-only and never re-read on reload. Cooldown and PSTN budgets are re-read once per call, as documented.
- On every INVITE exit path the dialog is released by `defer d.endUnlessUp()`, and `end()` is idempotent and ownership-checked. The confirmed-dialog leaks under specific races are listed in P2-EDG-005/007/027.
- `Location` and `privateSources` are bounded (20 000/10 per AoR; 256 entries).

## Could not verify
- The 5-min `inviteTimeout` backstop path (P2-EDG-009) needs a code change to shorten the const, or a >5 min test.
- P2-EDG-003 depends on the network: a spoofed-source packet cannot be produced on loopback without raw sockets and root.
- Whether sipgo splits comma-joined `Route` values into separate headers. The parser returns `errComaDetected` (`$SIPGO/sip/parse_address.go:364-365`); the split is handled by the caller, which the `sip` package reviewer owns.
