# FreeSBC Real-World Integration Test Report (SIPp + FreeSWITCH)

**Test date**: 2026-08-31 · **System under test**: FreeSBC (repo HEAD `b998f08`, version `dev`)
**Tester**: Claude Code automated testing · **Test type**: real end-to-end interoperability verification

## 1. Executive Summary

SIPp was used to emulate PSTN carrier-a (and carrier-b), and a local FreeSWITCH to emulate internal-pbx.
Twelve end-to-end scenarios were run against FreeSBC, covering basic outbound/inbound calls, ring timeout,
failover, 486 pass-through, no-route 404, RTP silence timeout teardown, admin call kill, OPTIONS / shield
auto-ban, a 30-call concurrency run, and config hot reload during an active call.

**Result: 11 passed / 0 failed / 1 skipped (SRTP, environment limitation). Two issues worth fixing were found (F1, F2).**

| Item | Result |
|---|---|
| Basic call (SIP B2BUA + RTP relay) | ✅ Media flowing in all four directions; number translation, CLI pass-through and SDP rewrite all correct |
| ring_timeout failover | ✅ Exact 4s CANCEL and failover when the target rings without answering (4.001s) |
| **Blackhole target (zero response) failover** | ⚠️ **~32s delay (Timer_B); ring_timeout has no effect → issue F1** |
| Call teardown (BYE/CANCEL/timeout/kill) | ✅ All converge cleanly; resources (ports/registry) return to zero |
| Concurrency (30 calls @ 5cps) | ✅ 30/30 successful, peak 29 concurrent calls / 58 ports, no leaks |
| Observability (admin API/metrics/logs) | ✅ /api/calls lifecycle correct; metrics strictly consistent with call state |
| Config hot reload | ✅ Reload during a call does not interrupt existing calls |
| SRTP (SDES) interop | ⏭️ Skipped: this FreeSWITCH build has no libsrtp (see §10) |

## 2. Environment and Topology

Single-host deployment (192.168.31.5, Ubuntu 24.04, WiFi wlp3s0):

```
 SIPp (carrier-a)  127.0.0.2:5090 ─┐
 SIPp (carrier-b)  127.0.0.2:5092 ─┼─lo──▶ FreeSBC 0.0.0.0:5070 ──lan──▶ FreeSWITCH 192.168.31.5:5060
                                   │      media pool 16384-32768              (internal-pbx, internal profile)
 SIPp (UAC, caller) 127.0.0.2 ─────┘      public_ip=192.168.31.5              dialplan: 9196=echo, 9197=milliwatt
```

- **Peer identification relies purely on source IP** (`sig/identify.go`): FreeSWITCH sends from 192.168.31.5 → internal-pbx;
  SIPp binds to the loopback alias **127.0.0.2** (`ip addr add 127.0.0.2/8 dev lo`) → carrier-a/carrier-b.
- **FreeSWITCH integrated with zero changes**: inbound goes through the internal profile (5060), with
  `apply-inbound-acl=domains` exempting 192.168.31.0/24 from authentication; outbound uses `originate sofia/external/sip:9XXX@192.168.31.5:5070 …`.
- **Versions**: FreeSBC `dev` (HEAD b998f08) · FreeSWITCH 1.11.2-release (built 2026-08-16)
  · SIPp c496186-TLS-PCAP (built from source) · Go 1.27.0.
- Test assets: `test/interop/sbc.yaml` (test config), `test/interop/sipp/*.xml` (scenarios),
  `test/interop/sipp/g711a.pcap` (RTP sample, from the SIPp sources). Raw evidence: /tmp/freesbc-test/ (pcap, SIPp traces, API snapshots).

## 3. Key Test Configuration (test/interop/sbc.yaml)

| Parameter | Value | Notes |
|---|---|---|
| `listen.sip` | `udp://0.0.0.0:5070` | 5060 is taken by FreeSWITCH |
| `listen.media.public_ip` | `192.168.31.5` | **Must be a real address** (`auto` is not implemented; a placeholder breaks media) |
| `rtp_timeout` | 20s | Used by T7 |
| `ring_timeout` | 4s | Speeds up T3/T4 |
| `carrier-a/b` | 127.0.0.2:5090/5092, `allowed_ips [127.0.0.2/32]` | |
| `internal-pbx` | 192.168.31.5:5060, `allowed_ips [192.168.31.5/32]` | |
| routes | outbound: `^9(\d+)$`→`$1` → [carrier-a, carrier-b]; inbound: carrier-a → internal-pbx | |
| shield | `rate_limit 200/s`, `auto_ban 10/60s/1h`, `nftables off` | |
| admin | 192.168.31.5:8080 (admin/testpass123) | |

## 4. Scenario Details

### T1 Basic outbound call ✅ PASS

- **Steps**: SIPp UAS (carrier-a, 5090, `-rtp_echo` + pcap playback) → FS
  `originate … sofia/external/sip:92001@192.168.31.5:5070 9197 XML default` → 7s call → `hupall`.
- **Assertions and evidence**:
  - B-leg INVITE: `sip:2001@127.0.0.2:5090` (**leading 9 stripped**); From `"PBX-1000" <sip:1000@192.168.31.5:5070>`
    (**CLI passed through**); Contact `sip:192.168.31.5:5070` (no user); carries Session-Expires/Min-SE (t1_uas_msg.log)
  - SDP rewrite: B-leg INVITE `c=IN IP4 192.168.31.5`, `m=audio 16390` (pool port), codec list passed through,
    `m=video 0` rejected (non-audio sections declared correctly)
  - During the call `/api/calls`=1 (from=internal-pbx→carrier-a), `freesbc_active_calls 1`, `media_ports_in_use 2`;
    everything returns to zero after hangup (t1_calls_mid/end.json)
  - RTP flowing in all four directions (lo pcap): FS leg 597/362 both ways, SIPp leg 362/362 both ways
  - FS channel PCMU/8000, milliwatt tone; SIPp 1 successful / 0 failed

### T2 Basic inbound call ✅ PASS (with an observation)

- **Steps**: SIPp UAC (127.0.0.2) INVITE `9197` → SBC → FS milliwatt answers → SIPp sends BYE after 6s.
- **Assertions and evidence**: the SDP in the 200 was rewritten to `c=192.168.31.5`, `m=audio 16400` (pool port);
  FS received INVITE with number 9197 (public→default dialplan matched milliwatt); polling `/api/calls` showed the full
  lifecycle (registered at 15.1s → torn down at 21.4s, from=carrier-a→internal-pbx); RTP both ways (FS leg 500/300,
  SIPp leg 300/300); SIPp 1 successful.
- **Observation**: SIPp custom scenarios containing an `<exec>` action **do not send ACK automatically**, so the SBC
  retransmitted the 200 at T1 intervals until it received ACK/BYE; the call was unaffected — the SBC's tolerance of a
  missing ACK is correct behavior (robustness, recorded as a positive).

### T3 Ring timeout ✅ PASS

- **Steps**: two ring-forever UAS instances occupy 5090/5092; FS dials 92001.
- **Evidence**: carrier-a: INVITE→180→**CANCEL at 4.002s**; failover to carrier-b (within 2ms), then CANCEL 4.005s
  later; two SBC log entries `b-leg not answered: context deadline exceeded` (4s/8s); the FS channel was destroyed
  immediately after the second CANCEL (received 408). `/api/calls` had no entry at any point (unanswered calls are not
  registered, as designed).

### T4 Failover ✅ PASS + issue F1

- **T4a (target rings without answering) ✅**: carrier-a ring-forever + carrier-b answers. carrier-a was CANCELed at
  **4.001s**, carrier-b took over immediately, `/api/calls` showed `to=carrier-b`, RTP flowed both ways, and the call was
  established and torn down normally.
- **T4b (blackhole target) ⚠️ issue F1 → fixed and re-verified**: nothing listening on 5090 + carrier-b answers.
  **Before the fix**, the caller (SIPp posing as internal-pbx) received the 200 only **32.004s** after INVITE (expected
  ~4s); **after the fix, measured 4.256s** (4s ring_timeout + 250ms grace + 6ms), with carrier-b receiving the INVITE
  2ms after the deadline. Three independent lines of evidence:
  - SBC log before the fix: `b-leg not answered err="transaction terminated … Timer_B timed out" target=carrier-a` (03:30:35.062);
    after the fix: `b-leg not answered err="context deadline exceeded" target=carrier-a` (04:13:01.624)
  - Before the fix, carrier-b's INVITE arrived only at 03:30:35.062 (failover happened only after the blackhole leg died at Timer_B);
    after the fix it arrived 2ms after the deadline (04:13:01.625)
  - **Root cause** (confirmed by reading the code): sipgo v1.4.3 `dialog_client.go:355-366` `inviteCancel()` — when the
    target sends no response at all, `s.InviteResponse == nil` and it blocks waiting for any response or `tx.Done()`
    (Timer_B=32s), **sending no CANCEL and never returning**; the comment on FreeSBC's ring budget explicitly assumes a
    timeout always produces a CANCEL, which contradicts the actual behavior.
  - **Fix** (commit referenced in §6 F1): `dialTarget` now runs WaitAnswer in a goroutine racing `attemptCtx`. On
    timeout it first allows a 250ms grace window (ringing/cancel scenarios still take the original sequential
    classification path, guaranteeing `aLeg.Respond` is never called concurrently from two goroutines); when the grace
    window expires the leg is abandoned, classified as failRing, and failover proceeds. The goroutine then runs to
    completion on its own (a late response goes through the CANCEL path; a late 2xx is torn down by that goroutine with
    ACK+BYE; in the blackhole case RFC 3261 §9.1 permits no CANCEL, so the transaction expires on its own at Timer_B —
    the same background resource usage as before the fix, but no longer blocking the main flow).
    Regression tests: `TestBridgeFailoverSilentTarget`, `TestBridgeCancelSilentTarget` (sig/b2bua_test.go).

### T5 486 pass-through ✅ PASS (hunt semantics confirmed)

- carrier-a returned 486 → the SBC **continued to the next target** (sequential hunting, by design: the real code is
  passed through only after all targets are exhausted) → carrier-b also returned 486 → the 486 was passed back to the
  caller within milliseconds (the FS channel was destroyed within ~3s).
- Evidence: both UAS instances received the INVITE and returned 486; two SBC log entries `Invite failed with response: 486 Busy Here` (same millisecond).
- Note: if a later target is a blackhole, 486 pass-through is subject to the same 32s delay from F1 (observed once: the FS channel was destroyed only after 32s).

### T6 No-route 404 ✅ PASS

- FS dialed 82001 (no matching route) → SBC `rejected invite code=404 reason="Not Found" source=192.168.31.5:5080`
  (log); FS channel hangup cause **UNALLOCATED_NUMBER** (the correct mapping for 404).

### T7 RTP silence timeout teardown ✅ PASS

- A silent SIPp UAC (no RTP/RTCP) → 9196 (FS echo, which does not originate audio) → completely silent media.
- **BYE arrived 20.012s after call setup** (rtp_timeout=20s); the SBC tore down both legs and resources returned to zero.

### T8 Admin call kill ✅ PASS

- `DELETE /api/calls/{id}` during a call → **204**; SIPp received BYE, the FS channel was destroyed, and `/api/calls` was emptied.

### T9 OPTIONS and shield auto-ban ✅ PASS

- OPTIONS from a known peer (127.0.0.2) → **200 OK**.
- OPTIONS ×11 from an unknown source (127.0.0.1) → **all silently dropped** (SBC log `dropping request from
  unidentified source`); the 10th triggered `shield auto-banned source=127.0.0.1 failures=10
  duration=1h`; metrics `freesbc_shield_banned_current 0→1` and `drops_total{reason="banned"} 0→1` (11th packet).

### T10 Concurrency load ✅ PASS

- SIPp UAC, 30 calls @ 5cps → 9197. **30/30 successful, 0 failed.**
- Peak curve: `calls=29 / ports=58` (03:37:23), ramping 10→21→29 and draining 19→8→0;
  port usage was exactly 2× the call count and returned to zero at the end (no leaks).

### T11 SRTP (SDES) interop ⏭️ SKIP (environment limitation)

- Pre-check: `ldd /usr/local/freeswitch/bin/freeswitch` shows no libsrtp2; the binary and mod_sofia contain no srtp
  symbols — this FreeSWITCH build does not support SDES SRTP. Testing would require rebuilding FS (libsrtp2-dev).
- The SBC-side SRTP capability (SDES negotiation, SRTP↔RTP relay) is covered by unit tests (the SRTP cases in
  sig/b2bua_test.go and the media/srtp tests); no real interop verification was done this round.

### T12 Hot reload during a call ✅ PASS

- Changed `peer_cooldown: 30s→60s` while a call was up → log `config reloaded`; the same call (unchanged call-id)
  stayed up, RTP was not interrupted, and it hung up normally. The config was restored afterwards.

## 5. Summary Table

| # | Scenario | Result | Key data |
|---|---|---|---|
| T1 | Basic outbound call | ✅ | 9 stripped, CLI pass-through, SDP rewrite, RTP all four directions, metrics back to zero |
| T2 | Basic inbound call | ✅ | Complete registry lifecycle, RTP both ways |
| T3 | Ring timeout | ✅ | CANCEL at 4.002s/4.005s, 408 back to the caller |
| T4a | Failover (ringing) | ✅ | Next target reached 2ms after the 4.001s CANCEL |
| T4b | Failover (blackhole) | ✅ (re-verified after fix) | 32.004s before the fix → **4.256s** after |
| T5 | 486 pass-through | ✅ | Hunt semantics; millisecond pass-through once all targets have responded |
| T6 | No-route 404 | ✅ | FS hangup cause UNALLOCATED_NUMBER |
| T7 | RTP silence timeout | ✅ | SBC-initiated BYE at 20.012s |
| T8 | Admin call kill | ✅ | DELETE 204, BYE on both legs |
| T9 | OPTIONS/shield | ✅ | Known peer 200; unknown silently dropped; ban applied after 10 attempts |
| T10 | 30 concurrent calls | ✅ | 30/30, peak 29 calls / 58 ports, no leaks |
| T11 | SRTP interop | ⏭️ | FS has no libsrtp, environment limitation |
| T12 | Hot reload | ✅ | Reload during a call causes no interruption |

## 6. Issues Found

### F1 (important, fixed): failover against a blackhole (zero-response) target takes ~32s; ring_timeout has no effect

- **Symptom**: T4b measured 32.004s before the fix; the incidental observation in T5 agrees. After the fix, T4b re-verified at **4.256s**.
- **Root cause**: sipgo v1.4.3 `inviteCancel()` (dialog_client.go:355-366) blocks until the transaction dies at Timer_B
  when the target never sends any response, sending no CANCEL and never returning ctx.Err(); FreeSBC's 4s ring budget
  in `placeCall` (b2bua.go:817) is therefore ineffective. As soon as the target sends any 1xx (even a 100 Trying), the
  behavior is normal (verified by T3/T4a).
- **Fix** (`sig/b2bua.go` `dialTarget`): WaitAnswer moved into a goroutine; the main flow `select`s between
  `waited` and `attemptCtx.Done()`. If the deadline fires first, a 250ms grace window allows the goroutine to deliver
  (in the ringing case delivery is within milliseconds and classification follows the original sequential path,
  avoiding two goroutines calling `aLeg.Respond` concurrently); once the grace window expires the leg is abandoned and
  classified as failRing (a blackhole endpoint is cooled down per the original semantics). The goroutine keeps the
  ackThenBye logic to tear down a phantom call from a late 2xx. Regression tests: `TestBridgeFailoverSilentTarget`
  (with a 2s ring_timeout, failover completes in ~2.3s and asserts that the blackhole endpoint is cooled down and RTP
  flows), `TestBridgeCancelSilentTarget` (caller cancel yields a fast 487, the loop stops, and the endpoint is not cooled down).
- **Note**: for a blackhole, RFC 3261 §9.1 forbids sending CANCEL before any response, so the abandoned INVITE
  transaction still retransmits in the background until Timer_B (~32s) — the same resource usage as before the fix, but
  it no longer blocks failover.

### F2 (informational): media latch is fail-closed and does not forward toward a leg that has not latched

- **Symptom**: on the first T1 run, the SBC dropped 361 RTP packets from FS→SBC (0 packets in the SBC→SIPp direction),
  because SIPp (`-rtp_echo`) waits passively and never sends RTP first, so the B-leg latch was never established.
- **Where in the code**: `media/relay.go:72` (`if dst := outLatch.target(); dst != nil`) — forwards only toward an
  already-latched remote; `media/session.go:71-92` establishes the latch on the first packet. This is a **deliberate
  hardening choice** (fail-closed against RTP hijacking), but it differs from the common SBC behavior of forwarding to
  the SDP address first and switching after latching.
- **Impact**: if one side is a fully passive endpoint that waits for the other to send media first (for example a pure
  echo responder), it receives no media until the other side starts sending. Real phones normally send silence or
  comfort noise immediately after answering, so the impact is limited.
- **Recommendation**: keep the current behavior (security first) or document the semantics explicitly.

### Observations (not defects)

- SIPp custom scenarios containing `<exec>` do not send ACK on their own; the SBC responds by retransmitting the 200, which is correct.
- FS `originate` cancels on its own after ~7-8s when there is no progress from the callee (its own behavior, unrelated to the SBC).
- SIPp occasionally emits `Failed to delete FD from epoll, errno = 1` at teardown (SIPp's own noise, does not affect results).
- An abandoned INVITE client transaction keeps retransmitting in the background until Timer_B (32s) before it dies, holding a small amount of resources in the meantime (same root cause as F1).

## 7. Commands Run and Actual Results (selected)

```sh
# Environment setup
sudo apt install -y build-essential cmake libpcap-dev libssl-dev libncurses-dev
git clone --depth 1 https://github.com/SIPp/sipp /tmp/sipp && cd /tmp/sipp \
  && git submodule update --init && cmake -B build . && cmake --build build -j   # → sipp c496186-TLS-PCAP
sudo ip addr add 127.0.0.2/8 dev lo
./freesbc check -c test/interop/sbc.yaml                                        # → config OK

# T1 (representative) actual output:
#   /api/calls (mid): [{"duration_seconds":7,"from":"internal-pbx","to":"carrier-a",…}]
#   metrics (mid): freesbc_active_calls 1 / media_ports_in_use 2
#   RTP (lo pcap): FS leg 597/362 both ways; SIPp leg 362/362 both ways
#   sipp: Successful call 1 / Failed call 0

# T7 actual output: BYE arrived 20.012s after call setup (rtp_timeout=20s)
# T10 actual output: Successful 30 / Failed 0; peak calls=29 ports=58; final 0/0
```

## 8. Coverage

- Bidirectional SIP-over-UDP calls; B2BUA number translation, CLI pass-through and SDP rewrite; RTP relay (bidirectional,
  latching); RTCP port pairing; ring timeout, sequential failover (ringing and blackhole variants), real-code pass-through
  (486/404) and hunt semantics; 408/404/486/487 returned to the caller; four teardown paths (CANCEL/BYE/admin kill/RTP
  timeout); shield (silent drop of unknown sources, auto-ban); admin API and metrics; 30 concurrent calls; hot reload.

## 9. Not Covered and Evidence Gaps

- **SRTP (SDES) interop** (T11): FreeSWITCH has no libsrtp; requires rebuilding FS or using an SRTP-capable peer.
- TLS/TCP transport and WS were not tested (FreeSWITCH supports TLS/TCP, so these are candidates for later scenarios).
- Registration-based trunks (outbound REGISTER + digest authentication) were not tested (SIPp supports digest; can be added later).
- Session timer refresh (4028) and real 100rel/PRACK interop were not tested (only the 420/422 gating code path was verified).
- Behavior after media exceeds rtp_timeout, and behavior at large scale (hundreds of calls), were not load-tested.
- Everything ran on a single host over loopback/local routing; cross-host and real NAT scenarios are not covered.
- `public_ip: auto` (STUN) is not implemented, so it is untested by definition.

## 10. Recommendations

1. ~~Fix F1 first~~ ✅ **Fixed and regression-tested** (sig/b2bua.go dialTarget race + 250ms grace,
   `TestBridgeFailoverSilentTarget`/`TestBridgeCancelSilentTarget`, T4b re-verified live at 4.256s).
2. Rebuild FS (libsrtp2-dev) and then run the T11 SRTP scenario; alternatively use Asterisk/Kamailio as the SRTP peer.
3. Consider adding this scenario suite to CI (a stated goal in design document freesbc-allinone-design.md §8): the SIPp XML and
   test config are already committed to the repo, and the only dependencies are the SIPp binary and one FreeSWITCH/Asterisk instance.
