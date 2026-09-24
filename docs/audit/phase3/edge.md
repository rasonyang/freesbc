# Phase 3: `internal/edge` confirmation tests

The tests were run twice, with identical results both times:

```
docker run --rm -v "$PWD":/src -v freesbc-gocache:/root/.cache -v freesbc-gomod:/go/pkg/mod \
  -w /src golang:1.25.7 go test -race -count=1 -timeout 15m -run '^TestAudit' -v ./internal/edge
```

- Raw output is in `docs/audit/raw/phase3-edge-run1.txt` and `docs/audit/raw/phase3-edge-run2.txt`.
- Neither run reported a data race.
- The Linux container is required because the PSTN tests need 127.0.0.2.

How to read the results:
- **FAIL** means the finding is confirmed (FACT).
- **PASS** means the finding is refuted, or not reproduced in the form tested.
- The tests assert the behaviour that should hold. Do not make a failing test pass by editing the test.

| Test | file:line | Finding | Result | Key output |
|---|---|---|---|---|
| TestAuditLooseLatchHijack | internal/edge/audit_findings_test.go:37 | P2-EDG-001 | FAIL → FACT | an off-path source that sent first to public port 47000 receives FreeSWITCH's audio; the signalled phone's RTP is dropped |
| TestAuditByeWrongTagsTearsDownCall | internal/edge/audit_findings_test.go:96 | P2-EDG-005 | FAIL → FACT | forged BYE answered 481 … ActiveCalls = 0, want 1; media no longer relayed |
| TestAuditMethodNameMetricsUnbounded | internal/edge/audit_findings_test.go:149 | P2-EDG-002 | FAIL → FACT | RequestsIn has 300 keys after 300 distinct invented methods |
| TestAuditRetransmitted2xxRelayed | internal/edge/audit_findings_test.go:192 | P2-EDG-004 | FAIL → FACT | phone received 1 copies of the 200 (FreeSWITCH sent 3) |
| TestAuditForked2xxMediaFollowsAnswer | internal/edge/audit_findings_test.go:247 | P2-EDG-006 | FAIL → FACT | phone RTP reached fork A=true fork B=false (the dialog is fork B's) |
| TestAuditReInviteTowardBrowserKeepsDTLS | internal/edge/audit_findings_test.go:295 | P2-EDG-011 | FAIL → FACT | re-offer toward the browser lacks [UDP/TLS/RTP/SAVPF a=fingerprint: a=ice-ufrag: a=ice-pwd:] |
| TestAuditReInviteNewPortApplied | internal/edge/audit_findings_test.go:343 | P2-EDG-012 | FAIL → FACT | re-INVITE moving FreeSWITCH media to a new port not applied (to new=false, from new=false) |
| TestAuditReInvite2xxUnanchorableIsACKed | internal/edge/audit_findings_test.go:403 | P2-EDG-013 | FAIL → FACT | FreeSWITCH's 200 to the re-INVITE was never ACKed; the phone got 488 |
| TestAuditMediaTimeoutSendsBye | internal/edge/audit_findings_test.go:443 | P2-EDG-032 | FAIL → FACT | media timeout ended the call silently (BYE to FreeSWITCH: 0, BYE to phone: false) |
| TestAuditAckRacesCommit | internal/edge/audit_findings_test.go:485 | P2-EDG-018 | PASS → not reproduced | 0 of 20 ACKs never reached the phone (race window not hit on loopback) |
| TestAuditPSTN6xxStopsFailover | internal/edge/audit_pstn_test.go:21 | P2-EDG-014 | FAIL → FACT | after gw-a's 603 Decline FreeSWITCH got 200 and gw-b saw 1 INVITE |
| TestAuditPSTNProvisionalInDrainNotFinal | internal/edge/audit_pstn_test.go:97 | P2-EDG-015 | FAIL → FACT | FreeSWITCH never received a final response; the gateway's 180 in the drain became the synthesised "final" |
| TestAuditSDPLeakProperty | internal/edge/audit_sdpleak_test.go:230 | P2-EDG-030, P2-SDP-003 | FAIL → FACT (fmtp only) | leaks only `a=fmtp text` / `a=fmtp port text`, in all 7 directions checked, including re-INVITE and browser→FS; no leak of c=, o=, m= port, a=rtcp, a=candidate, a=tool or video section (120 bodies) |
| TestAuditBalanceShutdownWithLiveDialogs | internal/edge/audit_balance_test.go:26 | P2-EDG-027 | PASS → not reproduced | 3 confirmed calls and 1 ringing INVITE: ports, dialog table and owned goroutines return to baseline after Run returns |
| TestAuditBalanceNormalBye | internal/edge/audit_balance_test.go:105 | resource-balance baseline | PASS | 5 phone→FS and 5 FS→phone calls with register/un-register: balanced, bindings 0 |
| TestAuditBalanceCancelRaces200 | internal/edge/audit_balance_test.go:153 | P2-EDG-007 | PASS → refuted in this form | the SBC ACKed and BYEd the 200 that crossed the CANCEL, and resources were released (the logs show "ACK missed" on the caller-side server transaction) |
| TestAuditBalanceMediaTimeout | internal/edge/audit_balance_test.go:232 | P2-EDG-032 (resources) | PASS | the watchdog releases ports and records under a hot-reloaded 1 s rtp_timeout |
| TestAuditBalanceReloadMidCall | internal/edge/audit_balance_test.go:251 | P2-MED-011 | PASS → not reproduced | after the reload, inUse=3 total=50; all ports released and pre-reload ports re-bindable |

## Not tested

- **P2-EDG-003**: a spoofed source IP cannot be produced on loopback without raw sockets and root.
- **P2-EDG-009**: the 5-minute `inviteTimeout` is a const. Testing it needs a production-code change or a test longer than 5 minutes.
- **P2-EDG-008**: not attempted. The race window between `ctx.Err()` and `track` cannot be forced from outside.
- **P2-EDG-010, P2-EDG-016, P2-EDG-017, P2-EDG-019–026, P2-EDG-028, P2-EDG-029, P2-EDG-031, P2-EDG-034**: not attempted in this pass. They are lower priority, or already covered by another package's Phase 3.

## Notes

- P2-EDG-018 is still an INFERENCE. It is a timing race, and 20 loopback iterations did not hit it.
- P2-EDG-027 is still an INFERENCE for its specific claim, an INVITE caught mid-allocation at shutdown. The live-dialog shutdown path is clean.
- P2-EDG-007 did not reproduce in the tested shape: a 200 sent after the CANCEL reached FreeSWITCH, with a 180 already relayed. The SBC tore the dialog down.
