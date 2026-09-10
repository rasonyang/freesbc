# FreeSBC Security Remediation Task List

- Created: 2026-08-31 | Baseline HEAD: `7fe89d9`
- Source documents: `docs/SECURITY-AUDIT-20260826.md` (finding IDs F-xx/D-xx), `docs/REMEDIATION-PLAN.md` (task cards T-01…T-37, each with a full spec: red test / permitted changes / symbols involved), `docs/SECURITY-REVIEW-20260831.md` (new findings S-01…S-05)
- This file defines only the **execution order, priority and dependencies**; the full spec for each card is in REMEDIATION-PLAN §3.
- Status: `[ ]` not started | `[x]` done
- Common acceptance criteria (all cards): the red test turns green + `go test ./... -race` + `go vet ./...` with no new warnings.
  ⚠️ Note that `go test ./sig/` is known to be flaky on this machine at the baseline too (see SECURITY-REVIEW §2.4, ~3.2s signature; not introduced by these fixes) — accept individual cards with a targeted `-run`, and compare against the baseline first when the full suite fails.

---

## P0 — Internet-facing deployment blockers (code, must be done before release)

**Ordering constraints**: T-01 first (converging the ingress shrinks the attack surface for everything that follows); the shield chain T-03 → T-04 → T-02 is strictly ordered (same file, same function area); the sig chain T-05 and T-06 **can run in parallel** with the shield chain (different files); T-06 comes before T-18 in P1.

1. `[x]` **T-01** (F-01/F-10) SIP ingress pre-filter: drop bytes from non-peer sources before parsing (`WithTransportLayerReadFilter`)
   - Files: sig/server.go, new sig/readfilter.go
   - Depends on: nothing (do this first)
2. `[x]` **T-03** (F-05) hard cap on banList (suggested 64k; reject and count beyond the cap)
   - Files: shield/banlist.go, shield/shield.go
   - Depends on: T-01 (tests are more stable once the attack surface is converged; not a hard dependency)
3. `[x]` **T-04** (F-03) move the scanner decision after rate limiting + single-worker bounded queue for nft exec + 2s timeout
   - Files: shield/shield.go, shield/banlist.go, shield/nftables.go
   - Depends on: T-03 (same Check function area; avoids conflicting refactors)
4. `[x]` **T-02** (F-04) qualify nft rules by SIP port/protocol + in-memory-only ban for single-packet UDP decisions + `DELETE /api/bans/{ip}` unban
   - Files: shield/nftables.go, shield/shield.go (Check gains a transport type parameter), admin/server.go, admin/api.go
   - Depends on: T-04 (the Check signature change lands on top of the T-04 reordering)
5. `[x]` **T-05** (F-02) wrap the SIP TCP/TLS listener: global connection cap + per-connection idle/read timeouts
   - Files: sig/server.go, new sig/listenerlimit.go
   - Depends on: nothing (parallel with 2-4)
6. `[x]` **T-06** (F-06, incl. D6-8) `peers.<name>.max_concurrent_calls` + a global cap; 503+Retry-After beyond the cap
   - Files: config/schema.go, config/validate.go, sig/b2bua.go, sig/server.go
   - Depends on: nothing (parallel with 2-4); T-18 is only meaningful once this is done

### P0 — Deployment gates (ops items, delivered together with the P0 code; no code dependencies, can be written at any time)

7. `[x]` **G-1** (F-07 mitigation) internet exposure policy doc: listen on tcp/tls only when internet-facing (or upstream ACL+uRPF); state explicitly that "over UDP, source IP spoofing = full peer trust". The code-level fix (inbound digest challenge) is in the later backlog and needs a product decision.
8. `[x]` **G-2** (F-14 mitigation) admin deployment baseline doc: bind to loopback only; the non-loopback deployment checklist (TLS reverse proxy / firewall) serves as the interim gate until T-26 lands.

---

## P1 — Immediately after (batch within 7 days)

**Ordering constraints**: T-07 first (it is the key-leak entry point); the S-batch touches the same file as T-07 (b2bua.go), so merge it after T-07 in order; T-08 also requires reworking the pumpTransform test pump.

9. `[x]` **T-07** (F-08) add dialog validation to refresh re-INVITE (Call-ID + both tags); 481 on mismatch
   - Files: sig/b2bua.go:127-151, sig/callsdp.go, sig/timers.go
10. `[x]` **S-batch** (new in this review, see SECURITY-REVIEW §2.2):
    - **S-02** OnResponse checks `abandoned` first and returns nil on a hit (a one-line short-circuit that closes both the grace race and the select randomness) + regressions: a late 18x does not trigger aLeg.Respond; the grace-window edge is clean under -race
    - **S-01** add `defer recover()` to the orphan goroutine (Error log) so a panic no longer kills the process + a panic-injection test asserting the process survives
    - **S-04** switch the Ack in `ackThenBye` to a 5s-scale `byeContext` (no longer accepting a Background ctx)
    - Files: sig/b2bua.go (dialTarget/ackThenBye area); all three cards touch the same function area, so merge in the order S-02 → S-01 → S-04
    - Depends on: T-06 (upstream in the same file; reduces conflicts); add tests for raced-2xx teardown, the grace-window edge, and late responses after abandonment
11. `[x]` **T-08** (F-09) SRTP/SRTCP replay protection (window 64/128); rework the pumpTransform retransmit pump accordingly
    - Files: media/srtp.go, media/srtp_relay_test.go, media/srtp_test.go
12. `[x]` **T-09** (F-14 code side) admin authentication: return 401 immediately and skip bcrypt when the Authorization header is missing + per-IP failure rate limiting (10/minute → 429)
    - Files: admin/server.go
13. `[x]` **T-15** (F-15) read admin credentials from `store.Current()` on every request (hot reload revokes the old password)
    - Files: admin/server.go, main.go (if needed)
    - Depends on: after T-09 (same requireAuth function)
14. `[x]` **T-18** (F-19) lax peer rate limiting (configurable `shield.peer_rate_limit`, defaulting to 200/s per_ip), preserving the scanner/ban exemption semantics
    - Files: shield/shield.go, shield/ratelimit.go, config
    - Depends on: T-06 already landed (quota before rate limit); S-03 (silent-target transactions ×K in parallel) is the justification for its urgency
15. `[x]` **T-26** (D4-6) reject a non-loopback admin.listen by default (`admin.allow_remote` to opt in explicitly) + enforce bcrypt cost ≥10
    - Files: config/validate.go, config/schema.go
    - Depends on: nothing; once it lands, G-2 is upgraded from a documentation gate to a code gate
16. `[x]` **T-26b** (new here, beyond the review plan — driven by a LAN access requirement) native admin TLS: `admin.tls_cert`/`tls_key` optional (both set or both unset), HTTPS as soon as they are configured (MinVersion 1.2); a prominent WARN at startup when allow_remote is set without TLS
    - Files: config/schema.go, config/validate.go, admin/server.go, sbc.example.yaml
    - Note: the originally planned T-17 (SIP signaling plane TLS) is unaffected and remains in the third tier; admin TLS previously had only the "TLS reverse proxy" route from the G-2 doc, and this card is the native implementation

---

## P2 — Third tier (injection / disclosure / configuration surface)

**Ordering constraints**: T-12 depends on T-01; T-17 comes before T-19 (schema convention).

17. `[ ]` **T-10** (F-17) end-to-end IP normalization (uniform Unmap on sourceAddr + nft set selection as a second safeguard)
18. `[x]` **T-11** (F-16) allowed_ips validation: non-empty + width cap + canonical prefix (stored Masked)
    - The implemented width floor is **IPv4 /8, IPv6 /32** (relaxed from the /16 and /48 suggested by the review: this repo's example config ships a 10.0.0.0/8 peer, and tightening would break the official example; /8 and /32 are real allocation boundaries, while catastrophic widths such as 0.0.0.0/0 are still rejected)
    - Fixtures affected: admin minimalConfigYAML, sig skipUnregisteredCfg / register_test templates need allowed_ips added (in the register tests the carrier must use a prefix that does not overlap the caller's, otherwise identify crosses the wires)
19. `[ ]` **T-13** (F-12) identity field sanitization: strip CR/LF and quote-breaking characters; allowlist for called numbers
20. `[ ]` **T-14** (F-11) allowlist of attributes in relayed SDP sections (strip candidate/fingerprint/ice-*), rewrite the o= identifier
21. `[ ]` **T-12** (F-10 residual) count stray responses silently (UnhandledResponseHandler) — depends on T-01
22. `[x]` **T-16** (F-18) `Cache-Control: no-store` on sensitive responses (injected centrally by recoverMW, /healthz exempt)
23. `[x]` **T-17** (F-13) TLS credential configuration surface: inbound tls_cert/tls_key/client_ca (mTLS optional) + outbound per-peer CA/client certificate + explicit TLS 1.2
24. `[x]` **T-19** (F-20) pin the digest realm (authentication fails when PeerAuth.realm does not match) — depends on T-17

---

## P2 — Fourth tier (Low list, can run in parallel)

25. `[x]` T-20 (D1-8) panic recover on all SIP handlers + required header validation (400 when To/From is missing)
26. `[ ]` T-21 (D7-9) lower dropUnidentified logging to Debug + periodic aggregation
27. `[x]` T-22 (D5-4) the watchdog refreshes lastRx only after SRTP authentication
28. `[ ]` T-23 (D6-9) return 482 for a second call with a duplicate Call-ID
29. `[x]` T-24 (D3-4) add Idle/Read/WriteTimeout to the admin http.Server
30. `[ ]` T-25 (D3-2) security response header baseline (nosniff/XFO/Referrer-Policy/minimal CSP)
31. `[ ]` T-27 (D7-11) validate shield parameter bounds (rate ≤1000, ban duration ≥1s)
32. `[x]` T-28 (D8-1) DNS resolution timeout + singleflight + short negative cache ┐
33. `[x]` T-29 (D8-2) SRV semantic filtering (Target ".", port 0)                  ├ same file sig/resolve.go, one batch
34. `[x]` T-30 (D8-4) fall back to port 5061 for the tls transport                 ┘
35. `[ ]` T-31 (D4-7) 1MiB size cap on Load                    ┐ same file config/loader.go, one batch
36. `[ ]` T-32 (D8-7) config file permission check (reject group/other readable when it contains credentials) ┘
37. `[ ]` T-33 (D4-3) tighten written-back file permissions to 0600 ┐ same file admin/config_write.go, one batch
38. `[ ]` T-34 (D4-5) refuse to write through a symlink + fsync the directory      ┘
39. `[ ]` T-36 (D7-7) isolate the nft table instance ┐
40. `[ ]` T-37 (D7-8) make the nft binary path configurable ├ same file shield/nftables.go, and the same file as T-02 — best done after T-02 lands, in the order T-36 → T-37 → T-35
41. `[ ]` T-35 (D7-6) make nftables mode take effect on hot reload ┘

---

## Later consideration (uncertain / low priority / needs a product decision; not scheduled)

> Full rationale in the on-hold and rejected lists of REMEDIATION-PLAN §5.

| Item | Status | What is needed to schedule it |
|---|---|---|
| F-07 code level (inbound digest challenge / mTLS) | On hold | Product decision: schema and challenge flow definition |
| F-21 (DNS trust chain / pinning) | On hold | Re-assess the observation points once T-17 lands |
| D4-2 (goccy alias bomb) | On hold | A Go-environment PoC confirming the crash reproduces (the toolchain is now available, so this can be added) |
| D4-4 (PUT TOCTOU) | On hold | Serialization design decision |
| D4-8 (fsnotify dying silently) | On hold | Requires a refactor to expose an injection point |
| D3-5 (no length cap on Call-ID) | On hold | Re-assess the residual attack surface once T-01 lands |
| D5-3 (strict arming on IP only) | On hold | Product trade-off between SSRC pre-learning and NAT compatibility |
| D5-7 (RTCP CNAME pass-through) | On hold | Carrier interoperability verification |
| D7-10 (sipsak false positives) | On hold | Fingerprinting policy decision |
| D8-6 (root / privilege-dropping systemd sample) | On hold | A deployment documentation work item, to be delivered with G-1/G-2 |
| S-05 (100 Trying sets responded) | Recorded | Not a security issue; noise in the health mechanism |
| Root cause of sig package flakiness | Recorded | Pre-existing at the baseline, environment-related; work around it with `-run` for per-card acceptance, but it must be resolved before CI is introduced |
| D8-5 (CI/SBOM/signing), D2-7 (SSRF-by-config) | Rejected | See REMEDIATION-PLAN §4 (the former is better tracked as a separate ops task) |

---

## Execution Overview

```
P0:  T-01 ──▶ T-03 ──▶ T-04 ──▶ T-02          (shield chain, serial)
             └──(parallel)──▶ T-05            (sig listener)
             └──(parallel)──▶ T-06            (per-peer quota)
     G-1 / G-2 docs can run in parallel at any time
P1:  T-07 ──▶ S-02 ──▶ S-01 ──▶ S-04 ──▶ T-08 ──▶ T-09 ──▶ T-15 ──▶ T-18 ──▶ T-26
P2:  Third tier T-10…T-19 (T-12 depends on T-01; T-17→T-19)
     Fourth tier T-20…T-37 (grouped by file: resolve.go ×3, loader.go ×2, config_write.go ×2, nftables.go ×3)
```

> Data sources and per-card specs: `docs/REMEDIATION-PLAN.md`; new findings from this round: `docs/SECURITY-REVIEW-20260831.md` §2.2.
