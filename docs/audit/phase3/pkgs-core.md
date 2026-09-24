# Phase 3 — tests for sip, sip/sdp, config, shield, admin

Scope: the five packages above only. The only files added are `audit_*_test.go` files and the fuzz corpora that `go test -fuzz` wrote. No production `.go` file was modified.

Commands:
- unit tests: `go test -race -count=1 -run '^TestAudit' -v ./internal/<pkg>`
- fuzz targets: `go test -run '^$' -fuzz '^<Name>$' -fuzztime=60s ./internal/<pkg>`

Raw output is in `docs/audit/raw/phase3-core-*.txt`.

Result key:
- **FAIL** — the defect is confirmed; the finding is now a FACT.
- **PASS** — the finding is refuted.
- **crash** — a panic.

The failing tests are the deliverable. Do not change them to make them pass.

Every unit test run was on macOS (darwin). None of these tests binds the contested fixed ports.

## Unit tests

| Test | file:line | Finding | Result | Key output |
|---|---|---|---|---|
| TestAuditMarshalDecliningPreservesOrder | internal/sip/sdp/audit_sdp_test.go:31 | P2-SDP-001 | FAIL | `m-line 0 media = "audio", offer had "video"`; live audio emitted at index 0, offer index 1 |
| TestAuditFmtpDoesNotCarryOtherLegText | internal/sip/sdp/audit_sdp_test.go:89 | P2-SDP-003 | FAIL | emitted `a=fmtp:0 x=1\rc=IN IP4 203.0.113.77` (other-leg address + bare CR) |
| TestAuditParseRejectsNonUnicastDestination | internal/sip/sdp/audit_sdp_test.go:121 | P2-SDP-004 | FAIL | `Parse returned 127.0.0.1 / 0.0.0.0 / 224.1.1.1 / 169.254.1.1 / ::1 as a media destination` |
| TestAuditNegotiateDuplicateKeyNotRenumbered | internal/sip/sdp/audit_sdp_test.go:141 | P2-SDP-005 | FAIL | `identical offer and answer reported as renumbered: offered 96 opus/48000/2, answered 111` |
| TestAuditFingerprintRejectsControlBytes | internal/sip/sdp/audit_sdp_test.go:158 | P2-SDP-006 | FAIL | `isHexByte accepts control bytes 0x10/0x19`; parseFingerprint accepted it |
| TestAuditParseSkipsPayloadTypeAbove255 | internal/sip/sdp/audit_sdp_test.go:174 | P2-SDP-009 | FAIL | `sdp: bad payload type "300"` |
| TestAuditICEPwdMinimumLength | internal/sip/sdp/audit_sdp_test.go:188 | P2-SDP-012 | FAIL | `a 4-character ice-pwd "abcd" was accepted` |
| TestAuditGrantedExpiresRejectsNegativeAndOverflow | internal/sip/audit_sip_test.go:43 | P2-SIP-001 (negative/overflow part) | FAIL | `expires=-1 → -1s`; `expires=9223372037 → -2562047h47m16.7s`. The subtest with `99999999999` passes, because that value happens to wrap to a positive number |
| TestAuditReadFilterCapIsReachable | internal/sip/audit_sip_test.go:58 | P2-SIP-002 | FAIL | `sipgo reads at most 32768 bytes per read; the 65536-byte filter cap can never fire` |
| TestAuditTeardownRequestHonoursRouteSet | internal/sip/audit_sip_test.go:69 | P2-SIP-005 | FAIL | `ACK Route = ""`, want p2, p1 |
| TestAuditSetSDPBodyTypedContentType | internal/sip/audit_sip_test.go:91 | P2-SIP-006 | **PASS, refuted** | `ContentType()` is non-nil after `SetSDPBody` on a fresh request |
| TestAuditParseNullEntriesDoNotPanic | internal/config/audit_config_test.go:50 | P2-CFG-001 | FAIL (panic, recovered) | all 4 cases: `nil pointer dereference` |
| TestAuditWatchSurvivesNullEntryReload | internal/config/audit_config_test.go:75 | P2-CFG-001 | FAIL (process crash) | child process running `Watch` died: `exit status 2`, SIGSEGV on reload of `peers: {a: }` |
| TestAuditValidationErrorDoesNotEchoEnv | internal/config/audit_config_test.go:126 | P2-CFG-003 | FAIL | `listen.media.public_ip: "audit-sentinel-s3cr3t" is neither "auto" nor a valid IP` |
| TestAuditCheckRejectsWhatRunRejects | internal/config/audit_config_test.go:141 | P2-CFG-004 | FAIL | all 4 accepted by Parse: upstream hostname, pstn.match hostname, duplicate listen.sip, and trunk and edge on the same UDP port |
| TestAuditNamedGroupNotExpandedAsEnv | internal/config/audit_config_test.go:163 | P2-CFG-005 | FAIL | `undefined environment variable(s) referenced in config: [num]`; with `num=EVIL` set, the transform becomes `+EVIL` |
| TestAudit4in6AllowedIPsMatchOrReject | internal/config/audit_config_test.go:182 | P2-CFG-008 | FAIL | `::ffff:10.0.0.1` and `::ffff:0:0/96` validate but never match 10.0.0.1 |
| TestAuditTrunkPortRangeHoldsOneCall | internal/config/audit_config_test.go:200 | P2-CFG-009 | FAIL | 2-port trunk range validates |
| TestAuditUDPScannerVerdictDoesNotBanVictim | internal/shield/audit_shield_test.go:31 | P2-SHD-001 | FAIL | `one forged UDP scanner datagram banned 198.51.100.20 from the edge plane` |
| TestAuditForgedUDPFloodFillsBanTable | internal/shield/audit_shield_test.go:45 | P2-SHD-001 | FAIL | `after 65536 forged UDP scanner datagrams a real TCP scanner could not be banned (overflow=1)` |
| TestAuditRateLimiterBucketMapBounded | internal/shield/audit_shield_test.go:67 | P2-SHD-002 | FAIL | `bucket map holds 200000 entries after 200000 distinct sources` |
| TestAuditPruneDoesNotResetHourlyBucket | internal/shield/audit_shield_test.go:88 | P2-SHD-003 | FAIL | `after 61 s idle and a prune, 10 of 10 requests allowed` |
| TestAuditReBanDoesNotShorten | internal/shield/audit_shield_test.go:117 | P2-SHD-008 | FAIL | `a 1 h ban was cut to 1 min by a later shorter ban` |
| TestAuditShieldCloseReleasesGoroutines | internal/shield/audit_shield_test.go:132 | resource balance (shield) | PASS | the prune goroutine exits on `Close` |
| TestAuditConfigPutDoesNotEchoEnv | internal/admin/audit_admin_test.go:28 | P2-ADM-001 | FAIL | the 400 body contains the env value, through the real PUT handler |
| TestAuditAuthLimiterHoldsUnderConcurrency | internal/admin/audit_admin_test.go:46 | P2-ADM-002 | FAIL | `50 concurrent wrong-password requests … (401)`, limit 10; `codes=map[401:50]` |
| TestAuditAuthLimiterCapDoesNotResetAttacker | internal/admin/audit_admin_test.go:87 | P2-ADM-003 (table-clear part) | FAIL | `4096 fresh source IPs reset the attacker's exhausted budget` |
| TestAuditConfigPutIfMatchIsAtomic | internal/admin/audit_admin_test.go:108 | P2-ADM-004 | FAIL | `7 PUTs with the same If-Match all succeeded` (the count varies between runs; it is timing-dependent) |
| TestAuditConfigPutFollowsSymlink | internal/admin/audit_admin_test.go:144 | P2-ADM-005 (symlink part) | FAIL | the symlink was replaced by a regular file, and the target was not updated |

## Fuzz results

| Target | file:line | Execs | Crashes (panic) | Property failures | Corpus / crasher |
|---|---|---|---|---|---|
| FuzzAuditSIPMessageHelpers (sipgo `ParseSIP` + every `internal/sip` helper + `ReadFilter`) | internal/sip/audit_sip_test.go:102 | 11,822,816 / 60 s | 0 | 0 | — |
| FuzzAuditParseBuild (`sdp.Parse` → `Negotiate` → `MarshalDeclining` → re-`Parse`) | internal/sip/sdp/audit_sdp_test.go:202 | 23,106,732 / 60 s | 0 | 0 | — |
| FuzzAuditBuildNoSentinelLeak (sentinel c=/o= address and port, fuzzed attributes) | internal/sip/sdp/audit_sdp_test.go:244 | ~3.0 M, stopped at 10 s on the first failure | 0 | 1 | `internal/sip/sdp/testdata/fuzz/FuzzAuditBuildNoSentinelLeak/6bbf2d3780c31ebc`: `a=fmtp:0 0\r0` reaches the output with a bare CR. This is found independently of the P2-SDP-003 unit test. It is not a panic, so it is P1, not P0 |
| FuzzAuditConfigParse (strict) | internal/config/audit_config_test.go:220 | 5,068 / 1.5 s | **1** | — | `internal/config/testdata/fuzz/FuzzAuditConfigParse/91d97c0654fe6f3e` = `"listen:\n sip: !00000000000000000000000000000000000 00"`. Nil dereference in **goccy/go-yaml v1.19.2** `ast.(*ArrayNodeIter).Len` (decode.go:1593), reached from `config.Parse` → `yaml.UnmarshalWithOptions`. **New finding P3-CORE-001**, below |
| FuzzAuditConfigParse with `AUDIT_FUZZ_SKIP_KNOWN=1` | same | 2,255,200 / 61 s | 0 new | — | Known signatures skipped: go-yaml, `withDefaults`, `proxyWithDefaults`, `validate`, `validateProxy`. The run ended with `context deadline exceeded` from the fuzz engine (a worker was still busy at the deadline). No failing input was written. A slow input is possible but was not investigated |

## New finding

### P3-CORE-001 — A crafted YAML tag crashes config.Parse inside goccy/go-yaml
- Severity: P1. `config.Parse` is not on a public SIP path. It does run in the reload goroutine, which has no `recover`, the same exposure as P2-CFG-001. Treat it as P0 if a config crash counts as "crash".
- Layer: config/lifecycle. Label: FACT (reproduced by the fuzzer).
- Location: `internal/config/loader.go:32` calls `yaml.UnmarshalWithOptions`, which panics in `github.com/goccy/go-yaml@v1.19.2/ast/ast.go:1543` via `decode.go:1593` (`decodeSlice`).
- Input: `listen:\n sip: !00000000000000000000000000000000000 00`. This is a local custom tag on the `listen.sip` sequence.
- Effect: a file saved with this content kills the running process on hot reload (`config.Watch` → `Load` → `Parse`, no recover). Through `PUT /api/config`, net/http's per-connection recover drops the connection instead.
- Repro: `go test -run 'FuzzAuditConfigParse/91d97c0654fe6f3e' ./internal/config`.
- Action: fix. Recover around the unmarshal in `Parse` and turn a panic into an error. Report the bug upstream to goccy/go-yaml, or pin a fixed version.

## Not expressible in these packages (left to other owners or not tested)
- P2-SIP-001, multi-Contact part: `GrantedExpires` has no parameter that says which Contact is ours, so only the edge harness can show the wrong-device lifetime. Only the negative/overflow part was tested.
- P2-SIP-004: `SameAddr` has no transport parameter; the defect is in how edge uses it.
- P2-SDP-002 (the o= version shared across legs) and P2-SDP-011 (rtcp-mux): both are defects in edge code.
- P2-CFG-002 (reload zeroes the PSTN budget): the failure happens in edge.
- P2-ADM-006 (no stack trace in the panic log): logging only, not tested.
- P2-SHD-009 (unban does not unmap IPv4-mapped input): the code is in app.

## Side effect on the normal test run

`go test ./...` replays the corpus under `testdata/fuzz/` as seed inputs. Because the two crasher files above are kept, both targets now fail in a plain `go test` run:
- `FuzzAuditConfigParse` panics on the go-yaml crasher.
- `FuzzAuditBuildNoSentinelLeak` fails its property on the bare-CR input.

All `TestAudit*` tests listed as FAIL also fail in a plain run. All tests that existed before the audit still pass in these five packages: after filtering out the `Audit` names, `go test -count=1` shows no other `--- FAIL`.
