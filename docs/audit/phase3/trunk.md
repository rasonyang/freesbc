# Phase 3 — internal/trunk: confirming findings with tests

Scope: tests only, `internal/trunk/audit_*_test.go`. No production file was modified.

How the tests were run:
- Socket-binding and unit tests ran in a Linux container, `golang:1.25.7`, with its own network namespace. The container has 127.0.0.2, which `TestAuditTCPCapExhaustedByNonPeers` needs:
  `docker run --rm -v "$PWD":/src -v $GOMODCACHE:/go/pkg/mod:ro -v freesbc-gocache:/root/.cache -e GOFLAGS=-mod=mod -e GOPROXY=off -w /src golang:1.25.7 go test -race -count=1 -v -run '^TestAudit' ./internal/trunk`
  - Raw output of the final run: `docs/audit/raw/phase3-trunk-docker-final.txt`.
  - Earlier runs: `phase3-trunk-docker-run1.txt`, `-resource2.txt` and `-cancelrace.txt`, described under "Harness corrections".
- Fuzzing ran locally on macOS: `go test ./internal/trunk -run '^$' -fuzz '^<Name>$' -fuzztime=60s`. Output is in `docs/audit/raw/phase3-trunk-fuzz.txt`.

Result semantics:
- FAIL confirms the finding, so it becomes FACT.
- PASS refutes the finding, or does not reproduce it under the stated conditions.

## Results

| Test | file:line | Finding | Result | Key output line |
|---|---|---|---|---|
| TestAuditTCPCapExhaustedByNonPeers | internal/trunk/audit_transport_test.go:63 | P2-TRK-001 | **FAIL → FACT** | `after 4 idle TCP connections from non-peer 127.0.0.2, peer OPTIONS got "read error: EOF"` (control before the flood: SIP response received) |
| TestAuditCallStoreSameCallIDOverwrite | internal/trunk/audit_callstore_test.go:23 | P2-TRK-002 | **FAIL → FACT** | `ActiveCalls = 1, want 2` … `after ending call 1: ActiveCalls = 0, want 1` … `KillCall cannot reach live call 2 after call 1 ended` |
| TestAuditCallStoreFirstCallUnkillable | internal/trunk/audit_callstore_test.go:60 | P2-TRK-002 | **FAIL → FACT** | `Calls() lists 1 records, want 2 live calls` / `call 1 is still bridged but no KillCall can reach it` |
| TestAuditReloadListenPortNotAdvertised | internal/trunk/audit_resource_test.go:663 | P2-TRK-004 | **FAIL → FACT** | `after reloading listen.sip to :47799 (not bound; restart-only), the B-leg INVITE advertises Contact <sip:127.0.0.1:47799>` (control before the reload: port 47750) |
| TestAuditSDPLeakProperty/candidate | internal/trunk/audit_sdpleak_test.go:95 | P2-TRK-006 | **FAIL → FACT** | `a=candidate:1 1 UDP 2130706431 198.51.100.77 31337 typ host` relayed verbatim |
| TestAuditSDPLeakProperty/remote-candidates | same | P2-TRK-006 | **FAIL → FACT** | `a=remote-candidates:1 198.51.100.77 31337` |
| TestAuditSDPLeakProperty/ice | same | P2-TRK-006 | **FAIL → FACT** | `a=ice-ufrag:…`, `a=ice-pwd:…` of the other leg relayed |
| TestAuditSDPLeakProperty/ssrc | same | P2-TRK-006 | **FAIL → FACT** | `a=ssrc:… cname:cn@198.51.100.77` |
| TestAuditSDPLeakProperty/fmtp | same | P2-TRK-006 | **FAIL → FACT** | `a=fmtp:101 0-15;x-host=198.51.100.77` |
| TestAuditSDPLeakProperty/session-attr | same | P2-TRK-006 | **FAIL → FACT** | session-level `a=x-peer-addr:198.51.100.77:31337` |
| TestAuditSDPLeakProperty/origin-user | same | P2-TRK-006 / 007 | **FAIL → FACT** | `o=sentinelorigin 690964 690964 IN IP4 192.0.2.10`: the other leg's o= username and session-id are kept |
| TestAuditSDPLeakProperty/base | same | P2-TRK-006 | PASS | c=, o= address and m= port are rewritten in 300 random bodies × {plain, SRTP} |
| TestAuditSDPLeakProperty/rtcp | same | P2-TRK-006 | PASS | `a=rtcp:<port> IN IP4 <addr>` is rewritten to our port only |
| TestAuditCompactSessionExpiresBypassesMinSE | internal/trunk/audit_transport_test.go:114 | P2-TRK-010 | **FAIL → FACT** | control `Session-Expires: 30` → 422; `x: 30` → `SIP/2.0 488 Not Acceptable Here`, want 422 |
| TestAuditHeaderSecondsCompactSessionExpires | internal/trunk/audit_units_test.go:76 | P2-TRK-010 | **FAIL → FACT** | `headerSeconds(Session-Expires) on compact 'x: 30' = 0s, want 30s` |
| TestAuditHeaderSecondsLongFormControl | internal/trunk/audit_units_test.go:86 | P2-TRK-010 (control) | PASS | long form parses as 30s |
| TestAuditChallengeRealmSubstringBypass | internal/trunk/audit_units_test.go:53 | P2-TRK-011 | **FAIL → FACT** | `challengeRealm = "trusted", want "rogue"` for `Digest xrealm="trusted", realm="rogue"` |
| TestAuditChallengeRealmCaseInsensitiveName | internal/trunk/audit_units_test.go:65 | P2-TRK-011 | **FAIL → FACT** | `challengeRealm = "", want "carrier"` for `REALM="carrier"`, so a legitimate challenge fails the pin (fails closed) |
| TestAuditSDESLineWithMKIRejected | internal/trunk/audit_units_test.go:110 | P2-TRK-012 | **FAIL → FACT** | `parseCryptoAttrs accepted an MKI-bearing key as plain` |
| TestAuditSDESLineWithSessionParamRejected | internal/trunk/audit_units_test.go:122 | P2-TRK-012 | **FAIL → FACT** | `parseCryptoAttrs ignored session param UNENCRYPTED_SRTP` |
| TestAuditResourceBalanceShutdownWithLiveCalls | internal/trunk/audit_resource_test.go:637 | P2-TRK-017, P2-APP-001 | **FAIL → FACT** | after `Run` returns: `ActiveCalls = 4`, `calls=4 legs=8`, `media pool in use = 8 of 20 pairs`, `carrier received 0 BYEs, want 4`, `4 of 4 callers never received a BYE`, `goroutines = 31 after 20s, baseline 3`; parked goroutines: `(*Server).onInvite` ×4, `media.watchdog` ×4, `(*Session).forward.func1` ×16 |
| TestAuditHeaderSecondsOverflow | internal/trunk/audit_units_test.go:96 | P2-TRK-018 | **FAIL → FACT** | `headerSeconds(9223372036854775807) = -1s`; `headerSeconds(9223372037) = -2562047h47m16.7s` |
| TestAuditOfferedCryptoSAVPF | internal/trunk/audit_units_test.go:132 | P2-TRK-022 | **FAIL → FACT** | `offeredCrypto(RTP/SAVPF) secure = false, want true (lines=1)` |
| TestAuditRemoteMediaIPFQDN | internal/trunk/audit_units_test.go:145 | P2-TRK-022 | **FAIL → FACT** | `bad connection address "media.example.com"` |
| TestAuditT38ImageSectionAccepted | internal/trunk/audit_units_test.go:159 | **P3-TRK-N01 (new)** | **FAIL → FACT** | `validAudioSDP rejected an audio+T.38 offer: parse sdp: sdp: invalid value 'image'` |
| TestAuditResourceBalanceReloadMidCall | internal/trunk/audit_resource_test.go:609 | P2-MED-011 (and P2-TRK-004/005 lifecycle) | **FAIL → FACT for P2-MED-011 only** | `after reload shrinking the range: pool reports inUse=8 > total=2`. Every other assertion passed: ports, call store, carrier BYEs, goroutines back to baseline, and a call placed in the new range afterwards. |
| TestAuditResourceBalanceNormalBye | internal/trunk/audit_resource_test.go:528 | P2-TRK-017 (control) | PASS | 4 calls with caller BYE: pool 0, store empty, carrier BYEs 5/5, goroutines back to baseline |
| TestAuditResourceBalanceCancelRace | internal/trunk/audit_resource_test.go:544 | RFC 3261 §9.1 CANCEL/2xx race | PASS (not reproduced) | `final INVITE responses across 20 races: map[200:13 487:7]`; every carrier dialog that was answered got ACK and BYE; pool 0 and goroutines back to baseline. The CANCEL was swept across the carrier's 300 ms answer instant in 10 ms steps. |
| TestAuditResourceBalanceMediaTimeout | internal/trunk/audit_resource_test.go:588 | P2-TRK-017 (media-silence path) | PASS | with `rtp_timeout: 1s` and no RTP: both legs got BYE, pool 0, store empty, goroutines back to baseline. P2-MED-004 (one-way silence) is not covered, because both directions were silent. |

### New finding from Phase 3

**P3-TRK-N01: the trunk rejects any SDP containing an `m=image` section, for example T.38 fax (P1, SDP, FACT).**
- Where: `internal/trunk/sdp.go:23-24` and `:55-56`, `:84-85`, `:126-129`. Every trunk SDP helper calls pion/sdp v3.0.19 `Unmarshal`, and its `unmarshal.go:846` accepts only `audio|video|text|application|message`.
- Evidence: `TestAuditT38ImageSectionAccepted`.
- Impact (INFERENCE from reading `placeCall`, which runs `validAudioSDP` before dialing): an INVITE whose offer lists audio plus `m=image … udptl t38` is refused rather than having the image section declined with port 0. RFC 3264 §6 requires declining it. A T.38 re-offer could not be parsed either, though re-INVITEs are already rejected (P2-TRK-013).
- Action: fix. Declined sections need tolerant parsing, or the bounded `internal/sip/sdp` parser.

### Findings not turned into tests

- **P2-TRK-003 (`recoverCall`)**: forcing a panic inside `onInvite` needs a production hook. Nothing reachable from a test panics deterministically. It stays INFERENCE.
- **P2-TRK-005 (several snapshots per call)**: the reads at `server.go:411`, `b2bua.go:220`, `:572` and `:653` are microseconds apart on one goroutine. `config.Store` is a concrete type with no seam for injection, so a reload cannot land between them deterministically. It stays INFERENCE. The adjacent restart-only effect, P2-TRK-004, is FACT.
- **P2-TRK-007/008/009/013/014/015/016/019/020/021**: not attempted in this pass. Each needs a fork-capable or TLS multi-CA stub carrier, beyond the time box. The `origin-user` subtest above covers the `o=` session-id pass-through part of 007.

## Fuzz results (60 s each, 4 workers, macOS, local)

| Target | file:line | Finding | Execs | Result |
|---|---|---|---|---|
| FuzzAuditChallengeRealm | internal/trunk/audit_fuzz_test.go:20 | P2-TRK-011 | 2,211,196 | no crash |
| FuzzAuditSIPHeaderHelpers (sipgo `ParseMessage` → `headerSeconds`, `requires100rel`, `refresherOf`, `isRefreshReInvite`) | internal/trunk/audit_fuzz_test.go:46 | P2-TRK-010/018 | 1,116,755 | no crash |
| FuzzAuditParseCryptoAttrs | internal/trunk/audit_fuzz_test.go:68 | P2-TRK-012 | 2,372,312 | no crash; accepted keys are always 30 bytes |
| FuzzAuditTrunkSDP (`validAudioSDP`, `remoteMediaIP`, `offeredCrypto`, `rewriteSDPCrypto`; property: when the rewrite succeeds, its output re-parses, points at our IP and, when plaintext, has no `a=crypto`) | internal/trunk/audit_fuzz_test.go:87 | P2-TRK-006/022 | 2,324,805 | no crash, and the property holds after the correction below |

No P0 crash was found in any trunk-local parser.

## Harness corrections (recorded so the raw files can be read correctly)

- **First container run (`phase3-trunk-docker-run1.txt`)**: all 5 resource-balance scenarios failed the goroutine check by exactly one goroutine, `sip.(*UDPConnection).ReadFrom`. That goroutine is sipgo's outbound client connection, which is created lazily on the first call and lives for the whole process. It is not a per-call leak. The baseline is now taken after one warm-up call (`auditWarmBaseline`), and the control scenario passes.
- **First two `FuzzAuditTrunkSDP` failures in the fuzz log**: these were caused by the test itself. It string-matched `inline:` and then `a=crypto`, and the fuzzer placed those strings inside the `m=` format list. The check now parses the output's attributes. The two crash-corpus files were test bugs and were deleted; no `testdata/` remains.

## New files

- internal/trunk/audit_units_test.go
- internal/trunk/audit_callstore_test.go
- internal/trunk/audit_sdpleak_test.go
- internal/trunk/audit_transport_test.go
- internal/trunk/audit_resource_test.go
- internal/trunk/audit_fuzz_test.go
- docs/audit/phase3/trunk.md
- docs/audit/raw/phase3-trunk-{fuzz,docker-run1,docker-resource2,docker-cancelrace,docker-final}.txt (gitignored)
