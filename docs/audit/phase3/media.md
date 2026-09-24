# Phase 3 — internal/media (tests only)

The socket tests were run in Linux (`golang:1.25.7` in Docker, which has
its own network namespace and routes all of 127/8) with
`go test -race -count=1 -v ./internal/media`. Raw output is in
`docs/audit/raw/phase3-media-tests-race-docker.txt`. Every audit test uses
ports 47000-47999, a range no earlier suite uses. No production `.go`
file was changed.

A FAIL confirms the finding, which becomes a FACT. A PASS refutes it.

## Finding tests

| Test | File:line | Finding | Result | Key output |
|---|---|---|---|---|
| TestAuditMED001CloseRacingEstablishLeaksICEAgent | internal/media/audit_findings_test.go:22 | P2-MED-001 | FAIL → FACT | `goroutines did not return to baseline after 40 Close-during-establish legs: baseline=2 now=242 (+240); stacks mentioning map[pion/ice:60]` |
| TestAuditMED002MediaFlowsBeforeFingerprintVerified | internal/media/audit_findings_test.go:83 | P2-MED-002 | FAIL → FACT | `SRTP from a DTLS peer whose certificate does not match the signalled fingerprint was decrypted and delivered to the private side before VerifyFingerprint ran` |
| TestAuditMED003SeedAcceptsNonUnicastDestinations | internal/media/audit_findings_test.go:120 | P2-MED-003 | FAIL → FACT | `seed(0.0.0.0:4000) installed 0.0.0.0:4000 as the relay destination`; the same happens for `::`, 224.0.0.1, 239.1.2.3, 255.255.255.255, 169.254.1.1, ff02::1 and fe80::1 |
| TestAuditMED003SeedReflectsToLocalService | internal/media/audit_findings_test.go:149 | P2-MED-003 | FAIL → FACT | `relay sent RTP to 127.0.0.1:49500` and `relay sent RTP to 0.0.0.0:40309`, both taken verbatim from the public side's SDP |
| TestAuditMED004OneWaySilenceNeverReclaimed | internal/media/audit_findings_test.go:192 | P2-MED-004 | FAIL → FACT | `side A silent for 1.6s (rtp_timeout 200ms) while side B streams; session was never reclaimed` |
| TestAuditMED006LooseLatchFirstPacketHijack | internal/media/audit_findings_test.go:236 | P2-MED-006 | FAIL → FACT | `after one packet from 127.0.0.2, the signalled phone (127.0.0.1:50355) is never relayed to FreeSWITCH` and `FreeSWITCH audio is delivered to the attacker 127.0.0.2` |
| TestAuditMED011StatsInUseExceedsTotalAfterShrink | internal/media/audit_findings_test.go:290 | P2-MED-011 | FAIL → FACT | `Stats after range shrink reports inUse=3 > total=2` |
| TestAuditMED007SRTPAllocsPerPacket | internal/media/audit_findings_test.go:318 | P2-MED-007 | FAIL → FACT | `allocs/packet protectRTP=2.0 unprotectRTP=3.0` |
| TestAuditMED_P3_001SRTPRoundTripEmptyHeaderExtension | internal/media/audit_findings_test.go:369 | P3-MED-001 (new, from fuzz) | FAIL → FACT | `RTP with a zero-length 0xC2DE header extension: protectRTP ok, unprotectRTP ok=false` |
| TestAuditMediaPortPoolAndGoroutineBalance (8 subtests) | internal/media/audit_balance_test.go:19 | balance check | PASS | Both pools are back to 0 in use, and the goroutine count is back to baseline, after each of these paths: Session Close, Close before Start, Start after Close, AllocateAcross partial failure, silence timeout, WebRTC handshake timeout, NewWebRTCSession with the private pool exhausted, WebRTCSession Start with a cancelled context, and Close while Start waits. The Close-during-establish path is the exception; it is P2-MED-001. |

Notes:
- P2-MED-001:
  - The leak happens on almost every iteration, not only in a narrow window. `Close` right after `Start` runs before `establish` has stored anything, so `establish` then creates the mux and agent on a leg that is already closed.
  - About 6 goroutines leak per leg.
  - Per-leg port accounting stays correct: the pool is back to 0.
- P2-MED-002: the test does exactly what the edge does at `edge/media.go:239-257`, which is `Start` first and `VerifyFingerprint` afterwards. The peer's certificate does not match the signalled fingerprint, and one SRTP packet from it still reaches the private socket as plaintext.
- P2-MED-003, loopback subtest: lab setups and this package's own tests legitimately relay to loopback, so a fix has to be scoped by policy. Unspecified, multicast, broadcast and link-local destinations are never valid unicast RTP destinations.
- P2-MED-006: needs 127.0.0.2. It runs in Linux and skips on a stock macOS host.
- P2-MED-007: the numbers come from the race build. They are allocations inside pion caused by passing `nil` for dst and header (`srtp.go:118-139`).

## New finding from fuzzing

**P3-MED-001** (P2, media, FACT). The input is a plaintext RTP packet, version 2 with the X bit set, whose header extension uses profile 0xC2DE (neither RFC 8285 one-byte nor two-byte) with length 0 and a 1-byte payload.
- `SRTPContext.protectRTP` (`internal/media/srtp.go:118`) accepts this packet.
- The SRTP it produces fails `unprotectRTP` (`srtp.go:125`) under the same key.
- On an RTP→SRTP interworking call, the relay (`relay.go:80-89`) therefore forwards such packets as SRTP the receiver cannot decrypt.
- With the RFC 8285 profile 0xBEDE and length 0, the round trip works.
- The cause is in pion's header re-marshal; the probe showed the same for first bytes 0x30, 0x90, 0xb0 and 0x10.

Minimised input: `docs/audit/raw/phase3-media-fuzz-srtp-roundtrip-input.txt`, kept as corpus entry `internal/media/testdata/fuzz/FuzzAuditSRTPRoundTrip/666d63480a603d0b`.

Impact: an affected packet is lost; nothing crashes. Action: fix, either by rejecting before protect any packet that fails a local round trip, or by reporting the issue upstream to pion.

## Fuzz results (60 s each, Docker, no race)

| Target | File:line | Execs | Result |
|---|---|---|---|
| FuzzAuditClassify: RFC 7983 first-byte classifier and RFC 5761 isRTCP | audit_fuzz_test.go:43 | 4,087,562 | no crash, no property failure |
| FuzzAuditDemux: WebRTC demux routing and truncation over a fake conn | audit_fuzz_test.go:100 | 8,287 | no crash; every datagram routed to the correct endpoint |
| FuzzAuditSRTPUnprotect: SRTP/SRTCP unprotect and protect on arbitrary bytes, both suites | audit_fuzz_test.go:154 | 3,561,119 | no crash, and no input buffer mutated |
| FuzzAuditSRTPRoundTrip: protect then unprotect | audit_fuzz_test.go:178 | failed at about 56 s (in the first run, when this check was part of FuzzAuditSRTPUnprotect) | round-trip failure, P3-MED-001; not a crash |
| FuzzAuditWebRTCLegPreICE: datagram to an ICE-Lite socket before ICE (pion UDP-mux STUN parsing) | audit_fuzz_test.go:197 | 2,678,771 | no crash, and the leg never failed |
| FuzzAuditWebRTCEstablished: datagram over an established ICE conn into demux, then DTLS or SRTP relay | audit_fuzz_test.go:235 | 3,500,123 | no crash, and the session never ended |

No crash was found, so there is no P0 from fuzzing.

Harness fix during the run: pion's `ice.Conn.Write` refuses payloads that look like STUN ("failed to write STUN message to ICE connection"). The established-leg fuzz now skips those inputs. This does not count as a finding.

Raw fuzz output:
- `docs/audit/raw/phase3-media-fuzz.txt` (first run)
- `docs/audit/raw/phase3-media-fuzz-rerun.txt` (the SRTP unprotect and established-leg targets after the harness split and fix)

## Observed flake (existing test, not an audit test)

In 1 of 4 full `-race` package runs, the existing test `TestPoolAllocateReleaseCycle` failed with `pair 3: media: RTP port range exhausted: no free pair in test range 40000-40007`. It did not fail in the next 3 full runs, nor in 3 runs with audit tests skipped (`docs/audit/raw/phase3-media-preexisting-check.txt`).

INFERENCE: the cause is a collision with a Linux ephemeral port (32768-60999). The existing WebRTC tests and the audit tests' full-ICE "browser" agents bind ephemeral host-candidate ports, and one of them landed inside the fixed test range. This is the fixed-port fragility already described in CLAUDE.md.
