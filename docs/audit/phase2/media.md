# Phase 2 — internal/media

Scope: `internal/media` only (portpool.go, session.go, relay.go, srtp.go,
stats.go, mux.go, webrtcleg.go, webrtcsession.go, dtlscert.go). Reading plus
`go build -gcflags='-m -m' ./internal/media/`. No tests were run. Every
finding below is INFERENCE (from reading) unless it says otherwise.

## Findings

### P2-MED-001 — WebRTCLeg: Close racing establish leaks the ICE agent (goroutines)
- Severity: P0 (leak on a public path; the race window is narrow)
- Layer: leg/binding
- Label: INFERENCE
- Location: `internal/media/webrtcleg.go:239-252`, `:269-293`, `:515-545`
- Evidence: `Start` sets `legEstablishing` (`:239`) and spawns `establish`.
  `establish` builds the mux and agent, then stores them with no
  closed-state check:
  `l.mu.Lock(); l.agent = agent; l.mu.Unlock()` (`:291-293`), and the same
  for `l.mux` (`:270-272`). `Close` snapshots
  `dm, agent, mux := l.demux, l.agent, l.mux` once (`:525`), under the same
  lock that sets `legClosed`. If `Close` runs before `:291`, it sees
  `agent == nil`. `establish` then stores a live agent that nobody will ever
  close. `agent.Accept(ctx, …)` (`:307`) blocks until the establishment
  deadline (30 s by default; the edge passes
  `context.WithoutCancel(ctx)`, `edge/media.go:236`, so request
  cancellation does not help). It then returns an error. `Start`'s goroutine
  calls `setState(legFailed)`, which is ignored because the state is
  terminal (`:107`), and then `Close()`, which returns immediately (`:520`).
  The pion `ice.Agent` task loop and timers are never stopped. A mux created
  after `Close` is similarly never closed. Its socket was closed, so its
  reader probably exits.
- Trigger: a browser INVITE that is CANCELed or BYE'd (or a failed
  `NewWebRTCSession` → `leg.Close`) while `establish` is between `:239`
  and `:293`.
- Reference: invariant "port-pool, dialog, leg, binding or timer not released
  on every exit path" (task checklist); docs/design.md §8.7 state diagram
  (`legEstablishing --> legClosed: Close`) implies full teardown.
- Suggested test (Phase 3): in a loop of N (for example 200): `NewWebRTCLeg`,
  `Start(ctx, 200*time.Millisecond)`, then `Close()` immediately (optionally
  after `runtime.Gosched()` or a random 0-500 µs spin). Wait past the
  timeout, then assert `runtime.NumGoroutine()` returns to baseline within a
  bounded retry. Also assert `pool.Stats()` inUse == 0.
- Action: fix. Check `l.state == legClosed` under `mu` when storing
  `mux/agent/demux`, and close the handle there if the leg is already
  closed. Or make `establish` own the teardown of whatever it created.

### P2-MED-002 — Relay launches before the DTLS fingerprint is verified
- Severity: P1
- Layer: media
- Label: INFERENCE
- Location: `internal/media/webrtcsession.go:141-174`; caller
  `internal/edge/media.go:239-257`
- Evidence: `WebRTCSession.start` launches `publicToPrivate`,
  `privateToPublic` ×2 and the watchdog as soon as `leg.Ready()` fires
  (`:169-172`). `VerifyFingerprint` is a separate call that the edge makes
  only after `sess.Start` returns (`edge/media.go:249`). Until then, SRTP
  from an unverified DTLS peer is decrypted and forwarded to FreeSWITCH, and
  FreeSWITCH audio is encrypted and sent to it. The media API has no way to
  refuse relaying for an unverified leg; the security property depends on
  caller ordering.
- Reference: RFC 5763 §5 / RFC 8122 §5 (the fingerprint binds the DTLS peer
  to the signalled session, and media must not flow over an unverified
  association); docs/design.md §8.7 "Fingerprint verification … is the only
  binding".
- Mitigation: the attacker must also know our ICE pwd (from signaling), so
  exploitability is low.
- Suggested test: construct a leg whose peer presents a certificate that
  differs from the signalled fingerprint. Send one SRTP packet immediately
  after the handshake. Assert that nothing arrives on the private pair
  before `VerifyFingerprint` has run (expected to fail today).
- Action: fix. Pass the expected fingerprint into
  `WebRTCSessionConfig`/`WebRTCLegConfig`, and verify it inside `establish`
  before `legEstablished`.

### P2-MED-003 — `latch.seed` accepts any destination (loopback, 0.0.0.0, multicast, internal)
- Severity: P1
- Layer: media
- Label: INFERENCE
- Location: `internal/media/session.go:91-102` (`seed`), used by `SetRemote`
  (`:254-259`), `SetRTCPRemote` (`:273-275`) and
  `WebRTCSession.SetPrivateRemote`. The edge seeds the PUBLIC side from the
  client's own SDP (`edge/media.go:198-200`, `:390-392`, `:450-452`).
- Evidence: the only guard is
  `if !addr.IsValid() || addr.Port() == 0 { return }`. Neither
  `internal/sip/sdp` nor `internal/edge` rejects unspecified, loopback,
  multicast or private media addresses (a grep for
  `IsUnspecified|IsLoopback|IsMulticast|IsPrivate` finds nothing in either
  package). After `Start`, the relay writes to the seeded destination
  (`relay.go:90-93`) until a packet latches. The public leg is loose
  (`edge/media.go:190`), so an authenticated client that never sends RTP
  keeps the seed forever. Two consequences follow:
  - An authenticated public client can make the SBC's public media socket
    send a stream of relayed RTP to `127.0.0.1:<any port>`, to an internal
    RFC 1918 host, or to a multicast group.
  - `c=0.0.0.0` (legacy hold, RFC 3264 §8.4) makes Linux deliver to the
    local host.
- Reference: RFC 3264 §8.4 (0.0.0.0 means hold, not a destination); the
  project's topology-hiding and anti-reflection intent (mux.go:141-143
  comment "would make this a UDP reflector (spec §16)").
- Suggested test: seed side A with `127.0.0.1:<listener port>`, where the
  listener never sends. Start the session and send RTP from side B's
  expected source. Assert that the listener receives nothing. Repeat with
  `0.0.0.0:<port>`. Today the packets are delivered.
- Action: fix. Reject unspecified, loopback, multicast and link-local
  destinations in `seed` or in edge SDP validation. Treat `0.0.0.0` as
  "no destination".

### P2-MED-004 — Silence watchdog cannot reclaim a one-way-dead call
- Severity: P1
- Layer: media
- Label: INFERENCE
- Location: `internal/media/relay.go:77`, `:99-122`;
  `internal/media/webrtcsession.go:202`, `:241`
- Evidence: one `lastRx` per session is refreshed by genuine packets from
  EITHER side. If one endpoint vanishes (its BYE is lost) while the other
  keeps streaming, `time.Since(lastRx)` never exceeds the timeout. Examples
  of an endpoint that keeps streaming:
  - FreeSWITCH playing MOH or prompts;
  - a carrier sending comfort noise;
  - an ongoing stream to a dead browser.

  The relay.go:100 comment claims "a half-dead call never keeps its ports
  reserved". The CLAUDE.md and design.md §8.5 claim is that the watchdog is
  "the only automatic reclaim for a confirmed call whose BYE was lost". Both
  hold only when both directions are silent.
- Reference: CLAUDE.md "Media … silence watchdog … the only automatic
  reclaim"; design.md §8.5.
- Suggested test: allocate a Session with a `Timeout` of 200 ms and Start
  it. Send RTP from side B's expected source every 20 ms for 1 s, and never
  from side A. Assert that `Done()` closes. Expected to fail today (docs vs
  behaviour).
- Action: fix (per-direction `lastRx`, closing on silence in either
  direction), or document it and drop the "half-dead" claim.

### P2-MED-005 — `Relatch` forgets the destination, so a non-sending side gets no media
- Severity: P1
- Layer: media
- Label: INFERENCE (cross-package; the caller is trunk)
- Location: `internal/media/session.go:68-74` (`relatch` sets
  `l.remote = nil`); `internal/trunk/b2bua.go:1597-1598` calls
  `sess.Relatch(side, remote); sess.Start()` and never `SetRemote`
  (design.md §8.4 "The trunk plane … never `SetRemote`").
- Evidence: after a relatch, `target()` returns nil until the far side sends
  first (`relay.go:90`, design.md §8.3 "A nil destination … packet is
  dropped"). A peer that answers `a=recvonly`, or a recorder or IVR that
  waits for audio before speaking, never sends, so it never receives. The
  seed doc comment (`session.go:78-82`) describes exactly this deadlock and
  says seeding exists to prevent it, but the trunk path does not seed.
- Reference: RFC 3264 §6.1 (a recvonly stream still has to receive media);
  RFC 4961 symmetric RTP assumes both sides send.
- Suggested test: Allocate, `SetExpectedRemote(A, …)`, `Relatch(B, ip)`,
  `Start`. Send from A only and never from B. Assert that B's listener
  receives packets.
- Action: fix (the trunk should seed from the answer's c=/m=, or relatch
  should take an AddrPort and seed). This is flagged for the trunk
  reviewer.

### P2-MED-006 — LatchLoose accepts the first packet from any Internet source (RTP-bleed window)
- Severity: P1
- Layer: media
- Label: INFERENCE
- Location: `internal/media/session.go:112-127`; used for every edge public
  RTP leg (`edge/media.go:190`, `:343`) and for trunk peers with
  `media_latch: loose`.
- Evidence: when `mode == LatchLoose`, a not-yet-latched latch skips the
  source check entirely and latches `src`. Between `Start` and the real
  endpoint's first packet, any host that sprays the public port range wins
  the latch permanently. After that:
  - `accept` rejects the real phone forever (`:109-110`);
  - FreeSWITCH audio goes to the attacker;
  - the attacker's audio goes to FreeSWITCH.

  The only recovery is a re-INVITE relatch. The design documents the
  behaviour (design.md §8.4), but the checklist flags "NAT latching that
  accepts media from arbitrary sources" explicitly. The edge's own comment
  (`edge/media.go:180-185`) says the real risk is a phone that "puts an
  unroutable fake IP in c=". A mitigation that keeps NAT support, such as
  preferring the signalled IP or accepting a later packet from the signalled
  IP, is absent.
- Reference: task invariant "NAT latching that accepts media from arbitrary
  sources"; RTP-bleed class (the latch never re-evaluates).
- Suggested test: allocate with `Latch{LatchLoose, LatchStrict}` and
  `SetRemote(A, legitIP:port)`, then Start. Send one RTP packet to side A's
  port from a different loopback source (the attacker), then send from the
  legit source. Assert that the legit source's packets are forwarded.
  Expected to fail today.
- Action: fix (for example, prefer a source matching the signalled IP and
  allow re-latch to the signalled IP), or record this as an accepted risk
  in docs/edge.md.

### P2-MED-007 — Per-packet heap allocations in SRTP protect/unprotect
- Severity: P2
- Layer: media
- Label: INFERENCE (from pion source; the escape analysis covers only this
  package)
- Location: `internal/media/srtp.go:118`, `:125`, `:132`, `:139`
- Evidence: `c.ctx.EncryptRTP(nil, pkt, nil)` and
  `DecryptRTP(nil, pkt, nil)` pass `dst == nil` and `header == nil`. pion
  srtp v3.0.12 (`srtp.go:109-110`, `:126-127`) then allocates
  `&rtp.Header{}` per call and grows a fresh output buffer, so there are at
  least 2 heap allocations per SRTP packet per hop. On a trunk SRTP↔SRTP
  call that is decrypt plus encrypt per packet. The relay's own buffers are
  per-goroutine (`relay.go:47`, `webrtcsession.go:185`, `:230`: `make`
  escapes once per goroutine, not per packet). `ReadFromUDP`'s
  `&net.UDPAddr{}` does not escape (`relay.go:49:33`,
  `webrtcsession.go:232:34`, from the `-gcflags='-m -m'` output).
- Suggested test: a `BenchmarkRelaySRTP` with `b.ReportAllocs()` over
  `protectRTP` and `unprotectRTP`.
- Action: fix (a per-goroutine dst buffer and `rtp.Header`).

### P2-MED-008 — Code comment contradicts the implementation of LatchStrict with no expectation
- Severity: P2
- Layer: docs
- Label: INFERENCE
- Location: `internal/media/session.go:24-26` vs `:112-115`
- Evidence: the comment says: "With no expectation set, the first packet is
  accepted from anywhere." The code does
  `if !l.expected.IsValid() { return false // strict: reject until SetExpectedRemote arms the latch }`.
  design.md §8.4 matches the code; the comment is stale.
- Action: fix the comment.

### P2-MED-009 — One allocation reads the config snapshot up to three times
- Severity: P2
- Layer: config/lifecycle
- Label: INFERENCE
- Location: `internal/media/session.go:213-220`, `portpool.go:84`, `:180`;
  `webrtcsession.go:76-82`
- Evidence: `AllocateAcross` calls `poolA.timeout()`, which is `params()`.
  Then `poolA.allocatePair()` calls `params()` and `poolB.allocatePair()`
  calls `params()` again. Each call re-reads `store.Current()` (design.md
  §8.2). A reload between these calls can give one session a timeout from
  snapshot N and port ranges from snapshot N+1. The practical impact is
  small, but it violates the "one snapshot per call" rule in CLAUDE.md.
- Action: fix (read `PlaneParams` once per allocation and pass it down).

### P2-MED-010 — Pool mutex held across the whole bind sweep
- Severity: P2
- Layer: media
- Label: INFERENCE
- Location: `internal/media/portpool.go:90-111`, `:127-148`
- Evidence: `p.mu` is held for up to `(hi-lo+1)/2` pairs of
  `net.ListenUDP` syscalls. When another process occupies much of the
  range, every call setup, and `Stats()` (`:166`, which admin metrics
  read), serializes behind a sweep of thousands of binds. design.md §8.2
  documents this as deliberate. The same guarantee is available by
  reserving `inUse[port]` under the lock and binding outside it.
- Action: fix (low priority).

### P2-MED-011 — `Stats()` inUse can exceed total after a hot-reload shrink
- Severity: P2
- Layer: media
- Label: INFERENCE
- Location: `internal/media/portpool.go:154-170`
- Evidence: `inUse` counts every reserved port, including ports outside
  the new range, while `total` is computed from the new range. Admin
  metrics then show more than 100% utilisation until the old calls end.
  This is cosmetic.
- Action: fix or document.

### P2-MED-012 — `WebRTCLeg.Start` is not idempotent and not guarded after Close
- Severity: P2
- Layer: leg/binding
- Label: INFERENCE
- Location: `internal/media/webrtcleg.go:235-253`
- Evidence: every call spawns a new `establish` goroutine. A second `Start`
  runs two ICE agents over one socket. `Start` after `Close` still spawns
  `establish`, which builds a mux and an agent on a closed socket and
  leaks the agent (see P2-MED-001). `Session.Start` and
  `WebRTCSession.Start` both use a CAS; the leg does not. The only current
  caller (`edge/media.go:236`) calls it once, so this is latent.
- Action: fix (a state CAS `legAllocated→legEstablishing` in `Start`).

### P2-MED-013 — Stats labels trunk legs "public/private"
- Severity: P2
- Layer: media
- Label: INFERENCE
- Location: `internal/media/stats.go:51-65`
- Evidence: side A (the inbound leg) is reported as `Public*` and side B as
  `Private*` for trunk calls too, where neither leg is public or private.
  design.md §8.10 should be checked for how admin presents this. This is
  maintainability only.
- Action: rewrite the naming (A/B or inbound/outbound).

## Dropped (not findings)
- RFC 7983 / RFC 9443 demux ranges (`mux.go:33-45`): 20-63 → DTLS and
  128-191 → RTP/RTCP are correct. STUN (0-3) is consumed by pion before the
  conn, and TURN channel data (64-79) is correctly dropped.
- RFC 5761 §4 RTP/RTCP split (`stats.go:71-77`, PT 64-95): correct, and the
  header byte is cleartext in SRTCP.
- RFC 5764 §4.2 key split (`webrtcleg.go:398-418`): the order is
  client_key ‖ server_key ‖ client_salt ‖ server_salt, and the role-based
  assignment is correct.
- ICE-Lite (RFC 8445 §2.5): the agent is `Lite: true`, host candidates only,
  and uses `Accept` (controlled). STUN MESSAGE-INTEGRITY and FINGERPRINT are
  checked inside pion. Non-STUN traffic from unvalidated remotes is dropped
  by pion.
- ICE credential length (`webrtcleg.go:554-561`): the 4-char ufrag and
  24-char pwd meet RFC 8839 §5.4 (ufrag ≥ 4 chars, pwd ≥ 22 chars).
- SRTP replay protection is enabled (`srtp.go:93-95`), as RFC 3711 §3.3.2
  requires.
- The shared SRTPContext is mutex-serialised (`srtp.go:115-141`); there is
  no data race.
- `recoverRelayPanic` (`relay.go:127-137`) logs the panic and stack and
  closes the session. It does not swallow the panic silently. It only
  allocates on a panic.
- `demux` full buffer (`mux.go:102`, `_, _ = dst.buf.Write`): the drop is
  intentional and documented (design.md §8.7). This is not a swallowed
  error defect.
- Session close ordering (`session.go:325-336`): sockets close before the
  port is released, so no window exists in which a still-bound port is
  handed out. Idempotency comes from `Swap`, so there is no double release.
- `AllocateAcross` partial failure (`session.go:220-225`) releases pair A.
  `NewWebRTCLeg`'s error path (`webrtcleg.go:181-185`) releases the port.
  `NewWebRTCSession`'s error path returns before reserving anything.

## Clean checklist items
- Goroutine exit paths: the relay loops exit on socket close, the watchdog on
  `done`, `demux.readLoop` on conn close, and the DTLS closer on
  `l.closed`. The one exception is P2-MED-001.
- `time.Sleep` for synchronisation: none in production code.
- `time.After` in loops: none. The watchdog uses one `time.Ticker` with
  `defer Stop`.
- Lock held across network I/O or channel send: none on the per-packet path
  (latch and SRTP locks cover CPU work only). The bind-sweep syscall is
  covered by P2-MED-010.
- Maps shared across goroutines: `PlanePool.inUse` is always under `p.mu`.
  No other maps.
- `_ = err`: only on `Close()` return values and the documented drop in
  `demux`. None hides a defect.
- Interfaces with a single implementation: none declared in this package.
- `any` where a concrete type fits: none.
- `defer` in loops: none.
- Per-packet `fmt.Sprintf`, `string(buf)` or logging: none. Allocation is
  covered by P2-MED-007.
- Unsynchronised fields: `srtpIn/srtpOut` are `atomic.Pointer`, the leg
  fields are under `mu`, and the counters are atomic.
- Credentials: ICE pwd and SRTP keys are never logged in this package.
  No SIP credentials are handled.
- design.md §8 vs code: §8.2–§8.7 match the code (line citations checked
  for `session.go:106-128`, `:325-336`, `:68-74`, `relay.go:19-22`,
  `webrtcleg.go:239`, `:246-247`, `:250`, `:524`). The only drift found is
  the code-comment one in P2-MED-008. The claim in P2-MED-004 is a doc
  claim that is stronger than the behaviour.
