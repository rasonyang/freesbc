# FreeSBC code-smell / correctness audit — REPORT

- Branch `audit/smell-2026-09-24`, baseline HEAD `1e63913`. No non-test `.go` file was modified; the only tracked change is one line in `.gitignore` (`docs/audit/raw/`).
- Supporting detail: per-package Phase 2 reviews in [`phase2/`](phase2/) (`sip.md`, `sdp.md`, `trunk.md`, `edge.md`, `media.md`, `shield.md`, `config.md`, `admin.md`, `app.md`), Phase 3 test results in [`phase3/`](phase3/) (`pkgs-core.md`, `media.md`, `trunk.md`, `edge.md`). Raw tool and test output is in `docs/audit/raw/` (gitignored, local only).
- Labels: **FACT** = reproduced by a tool or a test in this audit (the test name or raw file is cited). **INFERENCE** = from reading code. **FACT (partial)** = one part of the claim is reproduced, the rest is INFERENCE; the details say which.
- Severity: **P0** = crash / leak / security on a public path (unauthenticated network input). **P1** = SIP/SDP/media correctness (and, where noted, security defects reachable only through an authenticated or operator path). **P2** = maintainability / dead code / docs-code drift / latent or low-impact defects.
- Layer: transport | transaction | dialog | leg/binding | SDP | media | config/lifecycle | admin | docs.
- Action: delete | rewrite | fix. `rewrite` is used only where the module's identity model (keys, state ownership) is wrong; see section 4.
- Maintainer decisions (2026-09-24): P2-SHD-004 → delete; P2-TRK-016 → rewrite with option (c) (per-peer selection through `tls.Config` callbacks). Each is recorded as a "Decision (2026-09-24)" line at the finding's detail entry.
- Repro shorthand: `DKR` = `docker run --rm -v "$PWD":/src -w /src golang:1.25.7`. Tests that bind sockets or need 127.0.0.2 (edge, trunk, media) are run through `DKR`; the pure unit tests in sip, sip/sdp, config, shield and admin run locally. Phase 3 agents also mounted Go module/build caches (`-v freesbc-gomod:/go/pkg/mod -v freesbc-gocache:/root/.cache`), which only speeds the run up.

# 1. Extracted invariants (from docs/)

Sources: CLAUDE.md, README.md, docs/design.md (all 3013 lines), docs/edge.md, docs/trunk.md, go.mod, package tree. `D` = docs/design.md, `C` = CLAUDE.md. Every line reference was checked with `grep -n`/`sed -n`.

## A. Architecture and import rules
1. Imports run one way: `cmd/freesbc → app → {trunk, edge, admin}`. Checked with `go list`: trunk imports config, media, shield, sip and sip/sdp; edge imports the same set; admin and shield import only config. (C:25; D:82-102)
2. `config`, `media`, `sip` and `sip/sdp` import nothing from this module. (D:104-107; C:25)
3. `trunk` and `edge` never import each other. There is no shared call table, dialog concept or cross-plane routing. A message is handled only by the plane whose listener received it. (D:111-113)
4. `media` knows nothing about SIP or SDP. It receives addresses, ports, latch modes and SRTP keys. (D:114-115; D:3009)
5. `config` is the only package that both planes and shield read, and it is read-only after publication. (D:116-117)
6. `admin` reads plane state only through `admin.Deps` closures built in `internal/app`. (D:3013; C:25)
7. `internal/sip` and `internal/sip/sdp` contain no mutexes, atomics, channels, goroutines or timers. They are pure functions. (D:2248-2250)
8. `internal/sip` holds RFC primitives and no policy. Codec policy lives in `edge/codecs.go`, not in `sdp`. (D:3007; D:1830-1834)
9. The trunk plane runs only when `len(Peers) > 0`. The edge plane runs only when `ProxyEnabled()` (`sip.upstream.address` or `sip.upstreams.nodes` is set). If neither runs, `app.Run` refuses to start. (D:23-28; C:20)
10. The trunk emits no metrics of its own. It exposes accessors, which `app` wires into `admin.Deps`. (D:2532-2535)

## B. Topology hiding
11. Every SDP body on the edge plane is built from scratch by `sdp.Build` and never copied from the other leg's body. A private FreeSWITCH address can never reach a public body, and browser ICE candidates can never reach FreeSWITCH. (D:34-36; D:1841-1844; C:42)
12. A declined section on the edge is `m=audio 0 RTP/AVP 0` with no attributes and no `c=` line. (D:1861-1865)
13. The trunk gives each leg its own Call-ID, From-tag, Via and Contact. It strips every inbound `a=crypto` and clears all attributes on declined or non-relayed `m=` sections, on both the secure and plaintext paths. (D:43-45; D:822-827; D:2739-2741)
14. The trunk builds the B-leg offer with `rewriteSDPCrypto` every time, never with a port-only rewrite, so a secure caller's key cannot leak to a plaintext carrier. (D:731-733)
15. Edge: SDP, Contact and Request-URI never give FreeSWITCH a public client's address and never give a client FreeSWITCH's address. The Via `received=` does expose the client address to FreeSWITCH. (edge.md:41-47; C:24)
16. The contact registered toward FreeSWITCH is `sip:<user>@<private adv IP>:<port>;transport=udp;fsbc=<token>`. The REGISTER Request-URI is never changed, because the digest covers it. (D:1110-1111; D:1119-1121)
17. The edge `sdp` parser accepts only literal-IP connection addresses. Hostnames are rejected and never resolved. (D:1808-1811)
18. The edge plane never parses or emits `a=crypto`. Only the trunk handles SDES. (D:1817-1819; C:31)
19. ICE tokens are sanitised to `[A-Za-z0-9+/_-]` with a length of 4-256. Fingerprints must be sha-256, sha-384 or sha-512. (D:1821-1826)
20. Edge OPTIONS is answered locally and never forwarded. 100 Trying is never forwarded on either plane. (D:1066; D:789-790; D:1327-1329)
21. Every outbound edge request uses `noBuild`, so sipgo adds no Via, From, To, Call-ID or CSeq of its own. (D:1316-1319)

## C. Transaction and dialog keying
22. The edge `dialogTable` is keyed by Call-ID alone, which means one media session per Call-ID. (D:1231-1236; C:41)
23. `begin(callID)` `end()`s any previous record for that Call-ID. `end()` is idempotent and deletes the map entry only if the entry is still this dialog. (D:1256-1265)
24. `confirm` moves only early to confirmed, and refuses when no media was ever anchored. (D:1258-1259)
25. `takeAttempt` requires the CANCEL's From tag to match the INVITE's. On a match it removes the attempt, so exactly one caller ever cancels. An `inviteAttempt` holds the request as forwarded and the series cancel. (D:1277-1284; D:1346-1352)
26. A trunk `call` enters the `calls`/`legs` maps only through `registerCall`, which sets `callBridged` under `callMu`. `callEnded` is set only by `endCall`. Only bridged calls are visible to `/api/calls` and `KillCall`. (D:950-957; D:987-988)
27. sipgo `DialogServerCache.ReadInvite` is single-use. A trunk in-dialog INVITE never touches `dialogSrv`: it gets 481 on a tag mismatch, 200 on the raw tx for a refresh, and 501 for anything else, including an unknown Call-ID. (D:593; D:614-617; D:2244-2247)
28. The `fsbc` token stays the same for the whole registration lifetime: refreshes reuse it for the same (AoR, Call-ID). (D:1094-1098; D:1141-1144)
29. An edge binding's expiry always comes from the registrar's response. `granted <= 0` or an un-REGISTER removes the binding. (D:1134-1137)
30. `Binding.Source` is the transport source of the REGISTER, never the Contact host. (D:1166-1169)
31. `Location` caps are compile-time: 20000 total and 10 per AoR. `Put` prunes only that AoR. Expired bindings are invisible to lookups. (D:1139-1146)
32. Edge INVITE fails over to the next upstream only when `final == nil && !responded && clTx.Err() != nil`. A 486 is never retried. (D:1222-1227)
33. Edge REGISTER fails over whenever there was no final response. Any final response ends the series. The cooldown penalty applies only when there were zero responses. (D:1124-1132)
34. Upstream choice is FNV-1a 64 over the lower-cased user part, applied to a sorted name list. Map order must never leak into routing. (D:1040-1042; D:1196-1198)
35. In-dialog routing on the edge: the dialog record wins over the hash. The public-client fallback never answers 481. (D:1375-1377; edge.md:162-168)
36. Cooldown is skip-if-alternatives and never a hard block. The edge keys it by name, the trunk by endpoint (`host:port/transport`). (D:683-684; D:717-719; D:1209-1211; D:1217-1221)
37. `arrivedOnPrivate` requires all three: udp transport, a source IP in the upstream set, and the exact addr:port present in `privateSources`. (D:1026-1028)

## D. Media anchoring, latching and watchdog
38. Every stream is anchored on SBC ports. There is no SDP or media pass-through, and a missing body is answered 488. (D:47-49; D:1872-1873; C:29)
39. There is no transcoding. The offerer's PT numbers are preserved, and a renumbering answer is rejected with `sdp.ErrRenumbered`. (D:66-69; D:1834-1839)
40. RTP is always on an even port and RTCP on RTP+1. `allocateSingle` reserves the odd port without binding it. (D:1532-1538)
41. The pool mutex is held across the whole bind sweep, which is what prevents duplicate allocation. (D:1540-1542)
42. `Session.Start` is a single CAS, so the relay starts at most once. `Close` is a single Swap: idempotent and forward-only. (D:1566-1571)
43. A session that was allocated but never started has no watchdog. (D:1574-1576)
44. Latch rules: once latched, IP and port must both match exactly. Strict and unarmed rejects everything. Strict and armed requires an IP match but allows a different port. Loose accepts the first packet. `relatch` clears remote and latched from any state. (D:1612-1629)
45. The trunk never calls `SetRemote` (no seeding). The edge seeds both sides from SDP. (D:1650-1652)
46. Plane latch defaults: trunk A is the caller peer's `media_latch`; trunk B is the target's, re-applied per attempt; edge public is loose; edge private is strict; the WebRTC private leg is strict. (D:1641-1648)
47. The watchdog ticks at timeout/4, floored at 10 ms, and closes the session after `timeout` of silence. The timeout comes from pool A. (D:1656-1660)
48. `lastRx` is refreshed only after a packet is proven genuine: latch accept for plaintext, successful SRTP unprotect for secure. (D:1662-1665; D:2728-2729)
49. The watchdog is the only automatic reclaim for a confirmed call whose BYE was lost. The edge media watcher goroutine exists only for confirmed dialogs; early dialogs are bounded by `inviteTimeout`. (D:1667-1672; D:1286-1289; C:32)
50. `SetSRTP` with a plaintext outcome installs `(nil, nil)`, and is a silent no-op on a closed session. (D:796-802; D:1685-1693)
51. SRTP is terminated and re-originated per leg, and keys are never copied across legs. The replay windows are 64 for SRTP and 128 for SRTCP. (D:854-857; D:1678-1679)
52. A WebRTC leg's keys are set exactly once: no re-keying and no ICE restart. Fingerprint verification accepts sha-256 only, and a mismatch tears the session down. (D:1763-1765; D:1772-1777)
53. The RFC 7983 demux drops everything that is not DTLS (20-63) or SRTP (128-191). (D:1747-1752)
54. Edge ports return to the pool only via `mediaSession.Close()` inside `dialog.end()`. (D:1913-1914)
55. A relay panic closes only that session. (D:1594-1595)

## E. Read-filter rules
56. A read filter must never return an error, because sipgo treats one as fatal to the read loop. A rejection returns `(nil, nil)`. (D:563-565; D:2644-2645; C:52)
57. The trunk filter has no size cap (0). It admits only sources whose IP matches `IdentifyPeer` against the current snapshot. The port is discarded, and the address is `Unmap`ped. (D:557-575)
58. The edge filter caps reads at 64 KiB. On the private bind it requires an upstream source IP and records addr:port in `privateSources`. Other local addresses are accepted. (D:1012-1018)
59. `privateSources` holds at most 256 entries with a 10 min TTL. When full it prunes, and if still full it refuses the insert. (D:1020-1024)
60. Peer identity is the transport source IP only. Via and From are never used. Ties go to the lexicographically smallest peer name. (D:567-575)

## F. Shield behaviour
61. Every shield denial is a silent drop. The trunk overrides `onNoRoute` so unknown sources get silence and known peers get 405. (D:610-612; D:2690-2692; C:53)
62. `Check` order: a configured peer gets only the peer rate limit. Otherwise: ban table, then `rate_limit`, then the scanner UA check (ban and drop), which runs after the limiter. (D:2655-2667)
63. There are 11 exact case-insensitive UA substrings, and the check is User-Agent only. (D:2669-2673)
64. The ban table is capped at 65536 with an overflow counter. A refused ban also skips the kernel. The in-memory table is authoritative. (D:2677-2679; D:2700-2702)
65. A single-packet UDP scanner verdict never reaches nftables. (D:2695-2698)
66. Only the trunk shield manages nftables. The edge uses `shield.NewNoKernel`. (D:2407-2411; C:54)
67. The edge private plane is exempt from the shield. `guard` drops an unparseable source before metrics, shield and handler. (D:1030-1034; C:54)
68. The nft queue holds 256. A full queue drops the kernel sync only. Unban is synchronous and bypasses the queue. (D:2427-2431; D:2318-2321)
69. Admin kick, unban and shield metrics are wired to the trunk only. Edge bans are not exported. (D:2528-2530; D:2628-2631; C:54)

## G. Config parse order and snapshot immutability
70. `Parse` runs strict YAML unmarshal (unknown keys are errors), then `${VAR}` expansion, then `withDefaults`, then `validate` (all errors joined). (D:400-406; C:45)
71. Expansion runs after unmarshal, so parse errors never echo secrets. Only `${NAME}` is accepted, `${1}` passes through, and expanded values are never re-scanned or written back. (D:408-413; D:2746-2747)
72. `Store.Replace` stores atomically and then does coalescing non-blocking sends to subscribers. `Current()` is lock-free and never nil. A published `*Config` is never mutated, and compiled fields are filled in during `validate`. (D:326-331; C:46)
73. `config.Watch` is the only caller of `Store.Replace`. It watches the parent directory, filters on base name and Write|Create|Rename, debounces 200 ms, and on a bad file keeps the previous snapshot. (D:308-320; C:46)
74. Admin `PUT /api/config` only writes the file atomically and verbatim. It never calls `Replace`. (D:2584-2593)
75. Code reads `store.Current()` at the point of use. The trunk takes one snapshot per call; media pools read it per allocation. (C:46; D:1524-1527; D:2893-2897)
76. A trunk listener with no peers is a validation error when the proxy is on. Edge keys without an upstream are a validation error. (D:423-425; C:49)

## H. Hot vs restart-only
77. The hot/restart table is authoritative. Restart-only: the listener set, trunk dialog-cache Contact, nftables mode and port scope, `admin.listen`/`tls_*` and whether an admin section exists, edge topology, outbound per-peer TLS, inbound TLS certs. (D:337-345; C:47)
78. The only `Store.Subscribe()` consumers are `Registrar.Run` and `admin.watchListenChange`. There is no unsubscribe. (D:347-351)
79. If a reloaded config has no `admin:` section, the construction-time credentials still apply. (D:353-356)
80. No certificate is hot-rotated. (D:2457)
81. Advertised addresses are re-resolved per INVITE, except the dialog-cache default Contact, which is frozen at `Run`. (D:2354-2359)

## I. Timeouts (design.md §15.2, D:2809-2831)
82. `ring_timeout` 60 s per trunk dial attempt. (D:2811)
83. 250 ms grace after the ring deadline. (D:2812)
84. `byeContext` 5 s for every trunk teardown BYE and `ackThenBye` ACK. (D:2813)
85. un-REGISTER 2 s on its own root context. (D:2814)
86. Registrar backoff 5 s, doubling, capped at 60 s. (D:2815)
87. Registrar refresh at 0.9 × granted, floored at 10 s. (D:2816)
88. SRV lookup 3 s. Negative cache `min(srv_cache_ttl, 10 s)`. (D:2817-2818)
89. Trunk TCP idle read deadline 120 s; conn cap 1024. (D:2819; D:553-555)
90. `registerTimeout` 32 s for a whole edge REGISTER series. (D:2820)
91. `inviteTimeout` 5 min for a whole edge call (all three paths and re-INVITE). (D:2821)
92. `sip.pstn.attempt_timeout` 32 s. `pstnDrain` 300 ms. (D:2822-2823)
93. Edge CANCEL and `ackThenBye` BYE 5 s each. Edge in-dialog BYE/INFO 32 s. (D:2824-2825)
94. `listen.media.rtp_timeout` 5 min. WebRTC establishment 30 s. (D:2826-2827)
95. Config reload debounce 200 ms. (D:2828)
96. Admin read-header/read/write/idle 5/30/30/30 s. Shutdown drain 5 s. nft exec 2 s. (D:2829-2831)

## J. Security and admin
97. `admin.listen` must be loopback unless `admin.allow_remote: true`. Violating this is a hard validation error. (D:495; D:2713-2715; C:55)
98. bcrypt cost ≥ 10 is enforced at config load. (D:499; D:2711-2712; C:55)
99. `requireAuth` order: IP from `RemoteAddr` (never XFF), then 429 if over budget, then 401 with no bcrypt if there is no Authorization header, then a constant-time username compare and bcrypt password compare, both always evaluated. (D:2597-2611)
100. Limiter: 10 failures per minute per IP, tracking 4096 IPs. (D:2613-2615)
101. `/healthz` is the only unauthenticated route. `Cache-Control: no-store` is set on everything else. (D:2554-2559; D:2716)
102. `GET /api/config` is a whitelist. `GET /api/config/raw` is unredacted on purpose. (D:2570-2579; C:55)
103. PUT accepts at most 1 MiB, uses If-Match (409 on mismatch), and writes atomically in the same directory with mode 0600 or the existing file's mode. (D:2581-2589)
104. Credentials, nonces, ICE passwords and DTLS fingerprints are never logged. (D:2547-2548; D:1122; D:1779-1782)
105. Every TLS surface has a TLS 1.2 minimum. Trunk mTLS uses `RequireAndVerifyClientCert`. Digest realm pinning aborts before any Authorization header is sent. (D:2440-2446; D:2718-2722)

## K. sipgo v1.4.3 workarounds
106. Listeners bypass `ListenAndServe*`, because their unsynchronised close is a race; the code calls `ServeUDP`/`ServeTCP`/`ServeTLS`/`Serve` directly. (D:289-293; C:58)
107. `ReadInvite` is single-use, so the trunk answers in-dialog refreshes on the raw transaction. That path does not retransmit the refresh 200. (D:614-618; C:59)
108. `edge.New` raises the process-wide `sip.UDPMTUSize` to 8192 once, and only when it is lower. This also affects the trunk plane. (D:119-124; C:60)
109. The edge topology is re-pinned to the sockets' real local addresses before any goroutine reads it, because sipgo keys its connection pool by the real local address. (D:295-304)
110. The registrar must un-REGISTER before the listeners close, because sipgo reuses pooled listener conns for outbound requests. (D:373-376)
111. `WaitAnswer`/`inviteCancel` blocks until Timer_B on a silent target. That is why the 250 ms grace timer exists, and why `bLeg`/`attemptCtx` are passed as goroutine arguments (a `-race` finding). (D:747-757)
112. sipgo refuses an ACK in `TransactionRequest`, so the edge forwards a 2xx ACK statelessly with `WriteRequest`. (D:1331-1333)
113. sipgo never closes the response channel. Loops set `responses = nil` on `!ok`. (D:2299-2302)
114. `drainCancelledInvite` exists so a post-CANCEL 487 still matches a live client tx and gets ACKed. (D:1354-1358; D:1450-1453)
115. sipgo accepts one UA-wide client `tls.Config`, so every peer's client cert and CA are merged. (D:2443)

# 2. Summary table

One row per deduplicated finding, sorted by severity, then package. Aliases are the IDs of the same defect reported by another phase or reviewer; the details section is under the primary ID. Counts: **133 findings**: P0 8, P1 47, P2 78; FACT 65 (5 of them partial), INFERENCE 68. Two further findings were refuted by passing tests (table 2b).

| ID | Severity | Package | Layer | FACT/INFERENCE | Action |
|---|---|---|---|---|---|
| P2-EDG-001 (aka P2-MED-006) | P0 | edge, media | media | FACT | fix |
| P2-EDG-002 | P0 | edge | transport | FACT | fix |
| P2-EDG-003 | P0 | edge | transport | INFERENCE | rewrite |
| P2-EDG-005 | P0 | edge | dialog | FACT | rewrite |
| P2-MED-001 | P0 | media | leg/binding | FACT | fix |
| P2-SHD-001 | P0 | shield | transport | FACT | fix |
| P2-SHD-002 | P0 | shield | transport | FACT | fix |
| P2-TRK-001 | P0 | trunk | transport | FACT | fix |
| P2-ADM-001 (aka P2-CFG-003) | P1 | admin, config | admin | FACT | fix |
| P2-ADM-002 | P1 | admin | admin | FACT | fix |
| P2-CFG-001 | P1 | config | config/lifecycle | FACT | fix |
| P2-CFG-002 | P1 | config, edge | config/lifecycle | INFERENCE | fix |
| P3-CORE-001 | P1 | config | config/lifecycle | FACT | fix |
| P2-EDG-004 | P1 | edge | transaction | FACT | rewrite |
| P2-EDG-006 | P1 | edge | dialog | FACT | rewrite |
| P2-EDG-008 | P1 | edge | transaction | INFERENCE | fix |
| P2-EDG-009 | P1 | edge | transaction | INFERENCE | fix |
| P2-EDG-010 | P1 | edge | transaction | INFERENCE | fix |
| P2-EDG-011 | P1 | edge | SDP | FACT | fix |
| P2-EDG-012 | P1 | edge | media | FACT | fix |
| P2-EDG-013 | P1 | edge | transaction | FACT | fix |
| P2-EDG-014 | P1 | edge | transaction | FACT | fix |
| P2-EDG-015 | P1 | edge | transaction | FACT | fix |
| P2-EDG-018 | P1 | edge | dialog | INFERENCE | fix |
| P2-EDG-028 | P1 | edge | leg/binding | INFERENCE | fix |
| P2-EDG-032 | P1 | edge | dialog | FACT | fix |
| P2-MED-002 (aka P2-EDG-017, P1-001) | P1 | media, edge | media | FACT | fix |
| P2-MED-003 (aka P2-SDP-004) | P1 | media, sip/sdp | media | FACT | fix |
| P2-MED-004 | P1 | media | media | FACT | fix |
| P2-MED-005 | P1 | media, trunk | media | INFERENCE | fix |
| P3-MED-001 | P1 | media | media | FACT | fix |
| P2-SHD-003 | P1 | shield | transport | FACT | fix |
| P2-SIP-001 (aka P2-EDG-019, PH0-007) | P1 | sip | leg/binding | FACT (partial) | fix |
| P2-SIP-005 | P1 | sip | dialog | FACT | fix |
| P2-SDP-001 (aka P2-EDG-016) | P1 | sip/sdp | SDP | FACT | fix |
| P2-SDP-002 | P1 | sip/sdp, edge | SDP | INFERENCE | fix |
| P2-SDP-003 (aka P2-EDG-030) | P1 | sip/sdp | SDP | FACT | fix |
| P2-SDP-005 | P1 | sip/sdp | SDP | FACT | fix |
| P2-TRK-002 | P1 | trunk | dialog | FACT | rewrite |
| P2-TRK-003 | P1 | trunk | dialog | INFERENCE | fix |
| P2-TRK-004 | P1 | trunk | config/lifecycle | FACT | fix |
| P2-TRK-005 | P1 | trunk | config/lifecycle | INFERENCE | fix |
| P2-TRK-006 | P1 | trunk | SDP | FACT | rewrite |
| P2-TRK-007 | P1 | trunk | SDP | FACT (partial) | rewrite |
| P2-TRK-008 | P1 | trunk | dialog | INFERENCE | fix |
| P2-TRK-009 | P1 | trunk | dialog | INFERENCE | fix |
| P2-TRK-010 | P1 | trunk | transport | FACT | fix |
| P2-TRK-011 | P1 | trunk | transport | FACT | fix |
| P2-TRK-012 | P1 | trunk | SDP | FACT | fix |
| P2-TRK-013 | P1 | trunk | dialog | INFERENCE | fix |
| P2-TRK-015 | P1 | trunk | transaction | INFERENCE | fix |
| P2-TRK-016 | P1 | trunk | transport | INFERENCE | rewrite: option (c) (decided 2026-09-24) |
| P2-TRK-017 (aka P2-APP-001) | P1 | trunk, app | config/lifecycle | FACT | fix |
| P2-TRK-022 | P1 | trunk | SDP | FACT | fix |
| P3-TRK-N01 | P1 | trunk | SDP | FACT | rewrite |
| P2-ADM-003 | P2 | admin | admin | FACT (partial) | fix |
| P2-ADM-004 | P2 | admin | admin | FACT | fix |
| P2-ADM-005 | P2 | admin | admin | FACT (partial) | fix |
| P2-ADM-006 | P2 | admin | admin | INFERENCE | fix |
| P2-ADM-008 | P2 | admin | docs | INFERENCE | fix |
| P2-APP-002 | P2 | app, trunk | admin | INFERENCE | fix |
| P2-APP-003 | P2 | app | config/lifecycle | INFERENCE | fix |
| P2-APP-004 | P2 | app | config/lifecycle | INFERENCE | fix |
| P2-APP-005 (aka P2-ADM-007, PH0-002) | P2 | app, admin | admin | INFERENCE | fix |
| P2-APP-007 | P2 | cmd/freesbc | config/lifecycle | INFERENCE | fix |
| P2-APP-008 | P2 | cmd/freesbc | config/lifecycle | INFERENCE | fix |
| P2-APP-009 | P2 | app (tests) | config/lifecycle | INFERENCE | fix |
| P2-CFG-004 (aka P2-APP-006, PH0-003) | P2 | config, app | config/lifecycle | FACT | fix |
| P2-CFG-005 | P2 | config | config/lifecycle | FACT | fix |
| P2-CFG-006 | P2 | config | docs | FACT | fix |
| P2-CFG-007 | P2 | config | config/lifecycle | INFERENCE | fix |
| P2-CFG-008 | P2 | config | config/lifecycle | FACT | fix |
| P2-CFG-009 | P2 | config | config/lifecycle | FACT | fix |
| P2-CFG-010 | P2 | config | config/lifecycle | INFERENCE | delete |
| P2-CFG-011 | P2 | config | config/lifecycle | INFERENCE | fix |
| P1-008 | P2 | config, edge, trunk, media | config/lifecycle | FACT | fix |
| P1-003 | P2 | edge (tests) | media | FACT | fix |
| P1-009 | P2 | edge | config/lifecycle | FACT | delete |
| P2-EDG-020 | P2 | edge | transaction | INFERENCE | fix |
| P2-EDG-021 | P2 | edge | transport | INFERENCE | rewrite |
| P2-EDG-022 | P2 | edge | transport | INFERENCE | fix |
| P2-EDG-023 | P2 | edge | transaction | INFERENCE | fix |
| P2-EDG-024 | P2 | edge | media | INFERENCE | fix |
| P2-EDG-025 | P2 | edge | config/lifecycle | INFERENCE | fix |
| P2-EDG-026 | P2 | edge | leg/binding | INFERENCE | fix |
| P2-EDG-027 | P2 | edge | dialog | INFERENCE | fix |
| P2-EDG-029 | P2 | edge | transaction | INFERENCE | fix |
| P2-EDG-031 | P2 | edge | media | INFERENCE | fix |
| P2-EDG-033 | P2 | edge | docs | INFERENCE | fix |
| P2-EDG-034 | P2 | edge | transport | INFERENCE | fix |
| P1-007 | P2 | media | media | FACT | fix |
| P1-012 | P2 | media | media | INFERENCE | fix |
| P2-MED-007 (aka P1-011) | P2 | media | media | FACT | fix |
| P2-MED-008 | P2 | media | docs | INFERENCE | fix |
| P2-MED-009 | P2 | media | config/lifecycle | INFERENCE | fix |
| P2-MED-010 | P2 | media | media | INFERENCE | fix |
| P2-MED-011 | P2 | media | admin | FACT | fix |
| P2-MED-012 | P2 | media | leg/binding | INFERENCE | fix |
| P2-MED-013 | P2 | media | admin | INFERENCE | fix |
| P2-SHD-004 (aka P1-002, P2-TRK-026) | P2 | shield, trunk | transport | FACT (partial) | delete (decided 2026-09-24) |
| P2-SHD-005 | P2 | shield | transport | INFERENCE | fix |
| P2-SHD-006 | P2 | shield, edge | transport | INFERENCE | fix |
| P2-SHD-007 | P2 | shield | config/lifecycle | INFERENCE | moot (P2-SHD-004 delete) |
| P2-SHD-008 | P2 | shield | docs | FACT | fix |
| P2-SHD-009 | P2 | shield, app | admin | INFERENCE | fix |
| P2-SHD-010 | P2 | shield | config/lifecycle | INFERENCE | moot (P2-SHD-004 delete) |
| P2-SIP-002 (aka P2-SIP-003) | P2 | sip | transport | FACT | fix |
| P2-SIP-004 | P2 | sip | transport | INFERENCE | fix |
| P2-SIP-007 | P2 | sip | transport | INFERENCE | fix |
| P2-SIP-008 | P2 | sip | config/lifecycle | INFERENCE | fix |
| P2-SIP-009 | P2 | sip | dialog | INFERENCE | fix |
| P2-SDP-006 | P2 | sip/sdp | SDP | FACT | fix |
| P2-SDP-007 | P2 | sip/sdp | docs | INFERENCE | fix |
| P2-SDP-008 | P2 | sip/sdp | docs | INFERENCE | fix |
| P2-SDP-009 | P2 | sip/sdp | SDP | FACT | fix |
| P2-SDP-010 | P2 | sip/sdp | SDP | INFERENCE | fix |
| P2-SDP-011 | P2 | sip/sdp, edge | SDP | INFERENCE | fix |
| P2-SDP-012 | P2 | sip/sdp | SDP | FACT | fix |
| P1-004 | P2 | trunk (tests) | media | FACT | fix |
| P1-005 | P2 | trunk (tests) | media | FACT | fix |
| P1-006 | P2 | trunk (tests) | dialog | FACT | fix |
| P2-TRK-014 | P2 | trunk | transaction | INFERENCE | fix |
| P2-TRK-018 | P2 | trunk | transport | FACT | fix |
| P2-TRK-019 | P2 | trunk | dialog | INFERENCE | fix |
| P2-TRK-020 | P2 | trunk | transport | INFERENCE | fix |
| P2-TRK-021 | P2 | trunk | transaction | INFERENCE | fix |
| P2-TRK-023 | P2 | trunk | dialog | INFERENCE | fix |
| P2-TRK-025 | P2 | trunk | docs | INFERENCE | fix |
| P1-010 | P2 | sip, media, edge, trunk, admin | config/lifecycle | FACT | fix |
| PH0-001 | P2 | docs | docs | INFERENCE | fix |
| PH0-004 | P2 | docs | docs | INFERENCE | fix |
| PH0-005 | P2 | docs | docs | INFERENCE | fix |
| PH0-006 (aka P2-TRK-024) | P2 | docs | docs | FACT | fix |

## 2b. Refuted by a passing test (not in the table above)

| ID | Claim | Test (PASS) | Verdict |
|---|---|---|---|
| P2-SIP-006 | `SetSDPBody` leaves `msg.ContentType()` nil | `TestAuditSetSDPBodyTypedContentType` (`internal/sip/audit_sip_test.go:91`) | refuted: `ContentType()` is non-nil after `SetSDPBody` |
| P2-EDG-007 | a 2xx that crosses a CANCEL is committed, and the callee gets no ACK/BYE | `TestAuditBalanceCancelRaces200` (`internal/edge/audit_balance_test.go:153`) | refuted in the tested shape (200 sent after the CANCEL reached FreeSWITCH, with a 180 already relayed): the SBC ACKed and BYEd it and released resources |

Checks that passed and are not findings: edge `TestAuditBalanceNormalBye`, `TestAuditBalanceMediaTimeout`, `TestAuditBalanceShutdownWithLiveDialogs` (live-dialog part of P2-EDG-027); trunk `TestAuditResourceBalanceNormalBye`, `TestAuditResourceBalanceCancelRace` (RFC 3261 §9.1 CANCEL/2xx race: every answered carrier dialog got ACK+BYE over 20 races), `TestAuditResourceBalanceMediaTimeout`, `TestAuditSDPLeakProperty/base` and `/rtcp`; media `TestAuditMediaPortPoolAndGoroutineBalance` (8 subtests); shield `TestAuditShieldCloseReleasesGoroutines`; trunk `TestAuditHeaderSecondsLongFormControl`.

## 2c. Severity changes from the reviewers' grades

- P2-EDG-005 P1 → **P0**: a forged BYE from any source (unauthenticated public input, Call-ID sniffable on UDP) tears down a live call's media; that is security on a public path.
- P2-MED-006 P1 → **P0** (merged into P2-EDG-001, which the edge reviewer already graded P0): unauthenticated first-packet media hijack.
- P2-MED-003 / P2-SDP-004 stay **P1**: exploiting the seeded destination needs a call that FreeSWITCH accepted (authenticated client), so not "unauthenticated input".
- P2-SHD-003 stays **P1** (not P0): it weakens a throttle, and only when a `/h` rate limit is configured (non-default); it does not by itself crash, leak, or compromise.
- P2-CFG-001 and P3-CORE-001 stay **P1** (not P0): the crash is reachable only by writing the config file (operator path). Via admin `PUT /api/config` the panic happens inside `config.Parse` before the file is written, and net/http recovers it (the connection drops), so no network client can kill the process.
- P2-ADM-001 / P2-CFG-003 P2 (admin reviewer) → **P1**: disclosure of any process environment variable, reachable only by an authenticated admin, hence not P0.
- P2-ADM-002 P2 → **P1**: the brute-force limiter is a pre-authentication control and is bypassed (50/50 guesses reach bcrypt); admin is loopback by default, hence not P0.
- P2-EDG-028 P2 → **P1**: `Contact: *` un-REGISTER leaves bindings alive (RFC 3261 §10.2.2), observable routing to dead devices.
- P2-EDG-032 P2 → **P1**: a media-driven teardown leaves both endpoints in a confirmed dialog with no BYE (RFC 3261 §15), FACT.
- P2-SIP-005 P2 → **P1**: ACK/BYE ignore the route set (RFC 3261 §12.1.2, §13.2.2.4); observable when a far end record-routes.
- P2-TRK-022 P2 → **P1**: valid `RTP/SAVPF` and FQDN `c=` offers get 488 (FACT); SDP correctness.
- P3-MED-001 P2 (reporter) → **P1**: SRTP packets with an unusual header-extension profile are silently lost on RTP→SRTP interworking (media correctness).
- P2-EDG-031 stays **P2** (not P0): the ports are held only for the 407 round trip, and the shield per-IP rate limit bounds the rate.
- P2-EDG-022 stays **P2**: the responses precede the shield (malformed-request 400, CANCEL 200 from sipgo) and disclose only that the SBC is alive.
- P2-SHD-005 stays **P2**: needs a spoofed trunk-peer source and both planes configured, and only lifts throttles.
- P2-TRK-014 and P2-EDG-029 stay **P2**: RFC MUST violations with low observable impact (documented in design.md for TRK-014; FreeSBC is the only hop holding CANCEL context for EDG-029).
- P2-SDP-011 stays **P2**: RFC 5761 §5.1.1 violation, but every browser offers `a=rtcp-mux`.

# 3. Details per finding

Format: **Location** · **Evidence** · **Reference** (RFC or invariant; invariant numbers refer to section 1) · **Repro** · **Action**. The full reasoning of each reviewer is in `phase2/<pkg>.md`; the full test output summary is in `phase3/<pkg>.md`.

## 3.1 P0

### P2-EDG-001 (aka P2-MED-006) — Public RTP leg latches to the first packet from any source (media hijack)
- Location: `internal/edge/media.go:190`, `:343` (`Latch: {LatchLoose, LatchStrict}`); `internal/media/session.go:106-129` (loose `accept` skips the expected-source check; latch never moves).
- Evidence: FACT. `TestAuditLooseLatchHijack`: an off-path source that sends first to the public port receives FreeSWITCH's audio, and the signalled phone's RTP is dropped. `TestAuditMED006LooseLatchFirstPacketHijack`: after one packet from 127.0.0.2, the signalled phone is never relayed and FreeSWITCH audio goes to the attacker.
- Reference: task invariant "NAT latching that accepts media from arbitrary sources"; invariant 44/46; docs drift: `docs/edge.md:67` says "Strict source latching resists off-path hijacking".
- Repro: `DKR go test -race -count=1 -run '^TestAuditLooseLatchHijack$' ./internal/edge`; `DKR go test -race -count=1 -run '^TestAuditMED006LooseLatchFirstPacketHijack$' ./internal/media`.
- Action: fix. Seed strict latching from the SDP address, or prefer (and allow re-latch to) a source matching the signalled IP; fix the docs.

### P2-EDG-002 — Metrics keyed on attacker-chosen method names, unbounded
- Location: `internal/edge/edge.go:512` (`RequestIn(req.Method.String(), …)` before the shield at `:516-519`); `internal/edge/metrics.go:45-53` (new `sync.Map` entry per method/transport, never removed); exported via `internal/admin/metrics.go:134`.
- Evidence: FACT. `TestAuditMethodNameMetricsUnbounded`: `RequestsIn` has 300 keys after 300 invented methods.
- Reference: task invariant (unbounded state from public input); memory and Prometheus label cardinality.
- Repro: `DKR go test -race -count=1 -run '^TestAuditMethodNameMetricsUnbounded$' ./internal/edge`.
- Action: fix. Bucket unknown methods into `OTHER`; count after the shield.

### P2-EDG-003 — Public-socket packet trusted as FreeSWITCH by source address alone
- Location: `internal/edge/invite.go:110-127` (`isPSTNBridgeInvite` trusts `topo.fromUpstream(src)`); `internal/edge/plane.go:48-62`, `:88-97` (`privSources` keyed by addr:port only); `internal/edge/edge.go:516` (shield skipped).
- Evidence: INFERENCE. A spoofed-source UDP INVITE to the public listener, with the Request-URI equal to `sip.pstn.match`, dials the PSTN gateway (toll fraud); classified as private, it rings a registered user with no shield.
- Reference: invariant 37 (`arrivedOnPrivate` needs the private socket); CLAUDE.md "the private plane is trusted"; the trust should be keyed by the local socket.
- Repro: not reproducible on loopback without raw sockets and root (section 5). A partial test (send the INVITE to the public listener from an ephemeral socket in a harness where the upstream IP is 127.0.0.1) was proposed but not written.
- Action: rewrite the plane/trust classification to key on the local socket (section 4).

### P2-EDG-005 — BYE with wrong tags, from any source, tears down the call
- Location: `internal/edge/dialog.go:131-152` (`dialogTable` keyed by Call-ID); `internal/edge/invite.go:1300-1312` (`teardown(callID)` after every BYE, whatever the far-end response); `:1342-1367` (`directionFor` never fails for public sources).
- Evidence: FACT. `TestAuditByeWrongTagsTearsDownCall`: the forged BYE is answered 481, yet `ActiveCalls = 0` and media stops.
- Reference: RFC 3261 §12 (dialog id = Call-ID + local tag + remote tag), §12.2.2, §15.1.2; invariant 22.
- Repro: `DKR go test -race -count=1 -run '^TestAuditByeWrongTagsTearsDownCall$' ./internal/edge`.
- Action: rewrite the edge dialog identity (section 4): key on Call-ID + both tags, tear down only on a 2xx to a tag-matched BYE.

### P2-MED-001 — WebRTCLeg: Close during establish leaks the ICE agent
- Location: `internal/media/webrtcleg.go:239-252` (`Start`), `:269-293` (`establish` stores mux/agent with no closed-state check), `:515-545` (`Close` snapshots handles once).
- Evidence: FACT. `TestAuditMED001CloseRacingEstablishLeaksICEAgent`: goroutines baseline 2 → 242 after 40 legs (+240, 60 stacks in pion/ice). Not a narrow race: `Close` right after `Start` leaks on almost every iteration, about 6 goroutines per leg; the port accounting stays correct.
- Reference: task invariant "leg … not released on every exit path"; design.md §8.7 (`legEstablishing → legClosed: Close`). Trigger on the public path: a browser INVITE that is CANCELed/BYE'd during ICE establishment.
- Repro: `DKR go test -race -count=1 -run '^TestAuditMED001CloseRacingEstablishLeaksICEAgent$' ./internal/media`.
- Action: fix. Check `legClosed` under `mu` when storing mux/agent/demux and close them there; make `Start` a CAS (also P2-MED-012).

### P2-SHD-001 — One forged UDP datagram bans a victim IP from the edge plane; the ban table can be filled
- Location: `internal/shield/shield.go:129-136`, `:141-150` (UDP verdict is memory-only but still enforced); `internal/shield/banlist.go:59-73` (65536 cap); `internal/app/app.go:166` (edge `Unban` is a no-op).
- Evidence: FACT. `TestAuditUDPScannerVerdictDoesNotBanVictim`: one forged UDP scanner datagram bans 198.51.100.20. `TestAuditForgedUDPFloodFillsBanTable`: after 65536 forged sources a real TCP scanner cannot be banned (overflow=1).
- Reference: invariant 65 (a UDP verdict must not blackhole a third party — the docs protect only the kernel layer); invariant 64, 69.
- Repro: `go test -race -count=1 -run '^TestAuditUDPScannerVerdictDoesNotBanVictim$|^TestAuditForgedUDPFloodFillsBanTable$' ./internal/shield`.
- Action: fix. UDP scanner verdicts drop without banning (or ban the source port); wire an edge unban/metrics path.

### P2-SHD-002 — Rate-limit bucket map has no cap
- Location: `internal/shield/ratelimit.go:20-25`, `:41-46` (bucket per new source), `:66-77` (only eviction: idle ≥ 1 min, O(n) under the same mutex as `allow`); `internal/shield/shield.go:268-306` (`failCounter`, same shape, unfed).
- Evidence: FACT. `TestAuditRateLimiterBucketMapBounded`: 200000 buckets after 200000 distinct sources.
- Reference: `banlist.go:10-13` rationale ("must not grow the table without bound"); docs/design.md:2215 ("no cap on the map").
- Repro: `go test -race -count=1 -run '^TestAuditRateLimiterBucketMapBounded$' ./internal/shield`.
- Action: fix. Capped LRU or fixed-size table; key IPv6 by /64; add an aggregate ceiling.

### P2-TRK-001 — Trunk TCP/TLS connection cap is consumed by non-peers
- Location: `internal/trunk/listenerlimit.go:35-54` (`Accept` counts before any peer check); `internal/trunk/server.go:352-358`, `:381-387`.
- Evidence: FACT. `TestAuditTCPCapExhaustedByNonPeers`: once 4 idle TCP connections from non-peer 127.0.0.2 hold the (test-lowered) cap, the peer's OPTIONS gets `read error: EOF`; control before the flood gets a SIP response.
- Reference: invariant 57 and 89; design.md §6.1 (non-peer bytes never reach the connection pool). The shield never bans these sources (P2-SHD-004).
- Repro: `DKR go test -race -count=1 -run '^TestAuditTCPCapExhaustedByNonPeers$' ./internal/trunk`.
- Action: fix. Check `RemoteAddr` against `IdentifyPeer` in `Accept` before counting.

## 3.2 P1

### P2-ADM-001 (aka P2-CFG-003) — Validation errors echo expanded `${VAR}` values; admin PUT turns this into an env-var read oracle
- Location: `internal/admin/config_write.go:109-110` (`"invalid config: "+err.Error()` returned to the client); `internal/config/validate.go:40`, `:268` and other `%q` echoes after `expandEnv`; `internal/config/loader.go:23-27` (claims errors never echo secrets).
- Evidence: FACT. `TestAuditConfigPutDoesNotEchoEnv`: the 400 body of the real PUT handler contains the env value. `TestAuditValidationErrorDoesNotEchoEnv`: `listen.media.public_ip: "audit-sentinel-s3cr3t" is neither "auto" nor a valid IP`. Also reproduced with the binary (`freesbc check`).
- Reference: invariant 71; design.md §14.2 names `${ENV}` as the mitigation for `/api/config/raw`.
- Repro: `go test -race -count=1 -run '^TestAuditConfigPutDoesNotEchoEnv$' ./internal/admin`; `go test -race -count=1 -run '^TestAuditValidationErrorDoesNotEchoEnv$' ./internal/config`.
- Action: fix. Never echo values of fields that contained `${`; or redact field values in errors returned over HTTP.

### P2-ADM-002 — Admin auth limiter is check-then-act; concurrency bypasses the 10/min budget
- Location: `internal/admin/server.go:193-211` (`over()` → bcrypt → `recordFail()` with no reservation under the lock).
- Evidence: FACT. `TestAuditAuthLimiterHoldsUnderConcurrency`: 50 of 50 concurrent wrong-password requests reach bcrypt and get 401 (limit 10).
- Reference: invariant 99/100; design.md §13.4.
- Repro: `go test -race -count=1 -run '^TestAuditAuthLimiterHoldsUnderConcurrency$' ./internal/admin`.
- Action: fix. Reserve an attempt slot under the lock before bcrypt.

### P2-CFG-001 — Null map/list entries panic in Parse; hot reload kills the process
- Location: `internal/config/schema.go:295-296`, `internal/config/proxy.go:395-396`, `internal/config/validate.go:204-205`, `internal/config/validate_proxy.go:144-146` (nil `*Peer`/`*Gateway`/`*Route`/`*PstnRoute` dereferenced).
- Evidence: FACT. `TestAuditParseNullEntriesDoNotPanic` (all 4 cases nil-pointer panic); `TestAuditWatchSurvivesNullEntryReload` (child process running `Watch` dies with SIGSEGV, exit status 2, on reload of `peers: {a: }`). Also reproduced with `freesbc check`.
- Reference: invariant 73; `reload.go:16-18` and design.md:316-318 ("the process never dies from a bad reload").
- Repro: `go test -race -count=1 -run '^TestAuditParseNullEntriesDoNotPanic$|^TestAuditWatchSurvivesNullEntryReload$' ./internal/config`.
- Action: fix. Nil guards, or reject null entries right after unmarshal; also recover in `Parse` (see P3-CORE-001).

### P2-CFG-002 — Reload that removes `sip.pstn` zeroes the running PSTN attempt budget
- Location: `internal/config/proxy.go:387-394` (defaults only when `pstn.configured()`); `internal/edge/invite.go:468-470`, `:653` (`time.NewTimer(budget)` from the live store); same for `sip.upstreams.cooldown` (`proxy.go:364-367`; `invite.go:191`, `register.go:78`).
- Evidence: INFERENCE. Topology is a startup snapshot, but the budget is re-read per call; with the section removed, the budget is 0 and every PSTN attempt is cancelled immediately.
- Reference: invariant 77 (hot reload must not act on restart-only sections).
- Repro: not tested (the failure is in edge). Proposed: edge harness with PSTN, `Store.Replace` with the config minus `sip.pstn`, drive a PSTN INVITE, assert the gateway receives it.
- Action: fix. Read budgets from the topology snapshot, or validate a reload against the running restart-only snapshot.

### P3-CORE-001 — Crafted YAML tag crashes `config.Parse` inside goccy/go-yaml
- Location: `internal/config/loader.go:32` → `yaml.UnmarshalWithOptions` → `github.com/goccy/go-yaml@v1.19.2` `decode.go:1593` → `ast.(*ArrayNodeIter).Len` (`ast/ast.go:1543`) nil dereference.
- Evidence: FACT. `FuzzAuditConfigParse` crashed after 1.5 s; input `listen:\n sip: !00000000000000000000000000000000000 00`, saved at `internal/config/testdata/fuzz/FuzzAuditConfigParse/91d97c0654fe6f3e`.
- Reference: same invariant as P2-CFG-001 (the reload goroutine has no `recover`).
- Repro: `go test -count=1 -run 'FuzzAuditConfigParse/91d97c0654fe6f3e' ./internal/config`.
- Action: fix. Recover around unmarshal in `Parse`; report upstream / pin a fixed go-yaml.

### P2-EDG-004 — Retransmitted and forked 2xx are never relayed
- Location: `internal/edge/invite.go:248`, `:373`, `:574` (`clTx.Terminate()` right after the first final); sipgo `transaction_client_tx.go:119-129`, `transaction_layer.go:282-288` (later 2xx only logged).
- Evidence: FACT. `TestAuditRetransmitted2xxRelayed`: the phone received 1 copy of the 200; FreeSWITCH sent 3.
- Reference: RFC 3261 §16.7 step 10, §13.3.1.4; RFC 6026 §7.2/§8. One lost 200 on UDP fails the call.
- Repro: `DKR go test -race -count=1 -run '^TestAuditRetransmitted2xxRelayed$' ./internal/edge`.
- Action: rewrite as part of the edge transaction/dialog model (section 4): keep the client transaction until Timer M and relay 2xx retransmissions.

### P2-EDG-006 — Forked early dialogs share one answer body and one latch
- Location: `internal/edge/invite.go:986-1007` (`pumpInvite` replays `lastAnswer()` for every To-tag), `:708-733` (PSTN pump); `internal/edge/dialog.go:145-149` (one `mediaSession` per Call-ID).
- Evidence: FACT. `TestAuditForked2xxMediaFollowsAnswer`: phone RTP reached fork A=true, fork B=false, although the 200 came from fork B.
- Reference: RFC 3261 §13.2.2.4, §19.3; RFC 3264 §6. docs/edge.md:200-201 documents "no forking", but the code silently misrelays instead of rejecting.
- Repro: `DKR go test -race -count=1 -run '^TestAuditForked2xxMediaFollowsAnswer$' ./internal/edge`.
- Action: rewrite (section 4).

### P2-EDG-008 — INVITE sent in the ctx-check → track window is never CANCELled
- Location: `internal/edge/invite.go:197`, `:230`, `:245` (upstream); `:520`, `:557`, `:571` (PSTN); `internal/edge/dialog.go:302-311`.
- Evidence: INFERENCE. A CANCEL landing between `ctx.Err()` and `track` cancels only the series context; the new INVITE gets no CANCEL and keeps ringing.
- Reference: RFC 3261 §9.1, §16.10.
- Repro: not tested (race cannot be forced from outside; section 5).
- Action: fix. Track before sending, or re-check ctx after `track` and CANCEL.
- Resolution (issue #26): fixed by tracking before sending. The window still cannot be forced over a socket (it lies inside one handler goroutine), so it is covered by `TestAuditCancelBeforeInviteSentIsNotLost`, which drives the dialog's attempt protocol directly (`track` → CANCEL → `markSent`) rather than failing on main first.

### P2-EDG-009 — Backstop or no-answer expiry sends neither CANCEL nor a final response
- Location: `internal/edge/invite.go:1035-1043`, `:282-284` (5-min `inviteTimeout` path drains only); `:387-391` (`inviteToClient` sends no final when `pumpInvite` returns nil).
- Evidence: INFERENCE.
- Reference: RFC 3261 §16.6 step 11 (Timer C), §16.7 step 6, §16.8. design.md §7.12 documents the client path.
- Repro: not tested (`inviteTimeout` is a const; section 5).
- Action: fix. Generate 408/480 and CANCEL pending branches.

### P2-EDG-010 — PRACK/UPDATE answered 405 while `Supported: 100rel,timer` and `Allow: UPDATE,PRACK` pass through
- Location: `internal/edge/edge.go:539`, `:544-548`; `internal/edge/forward.go:40-89`.
- Evidence: INFERENCE.
- Reference: RFC 3262 §3; RFC 4028 §7.4/§9.
- Repro: not tested. Proposed: INVITE with `Supported: 100rel`, fake FS sends reliable 183, client PRACKs; assert not 405.
- Action: fix. Strip `100rel`/`timer` and PRACK/UPDATE from forwarded headers, or proxy both methods.

### P2-EDG-011 — Re-INVITE offer toward a WebRTC browser is plain RTP/AVP
- Location: `internal/edge/media.go:506-531` (`rebuildInDialogOffer` never sets DTLS/ICE); `internal/edge/invite.go:1141`. Also raised by the sdp reviewer (`phase2/sdp.md`, out-of-package note).
- Evidence: FACT. `TestAuditReInviteTowardBrowserKeepsDTLS`: the re-offer lacks `UDP/TLS/RTP/SAVPF`, `a=fingerprint`, `a=ice-ufrag`, `a=ice-pwd`.
- Reference: RFC 3264 §8; RFC 5763 §5; docs drift: `docs/edge.md:70` says the WebRTC leg keeps ICE/DTLS across re-INVITE.
- Repro: `DKR go test -race -count=1 -run '^TestAuditReInviteTowardBrowserKeepsDTLS$' ./internal/edge`.
- Action: fix.

### P2-EDG-012 — Re-INVITE never applies a new media address/port
- Location: `internal/edge/media.go:506-562` (no `SetRemote`/`Relatch`/`SetPrivateRemote`); `internal/media/session.go:276-283` (`Relatch` exists for this, no edge caller).
- Evidence: FACT. `TestAuditReInviteNewPortApplied`: after a re-INVITE moving FreeSWITCH media to a new port, no media reaches or leaves the new port.
- Reference: RFC 3264 §8.3.1, §8.3.2.
- Repro: `DKR go test -race -count=1 -run '^TestAuditReInviteNewPortApplied$' ./internal/edge`.
- Action: fix.

### P2-EDG-013 — Unanchorable re-INVITE 2xx is never ACKed or BYEd
- Location: `internal/edge/invite.go:1205-1208` (488 to requester, no `ackThenBye`, unlike `:1021-1023`).
- Evidence: FACT. `TestAuditReInvite2xxUnanchorableIsACKed`: FreeSWITCH's 200 is never ACKed; the phone gets 488.
- Reference: RFC 3261 §13.3.1.4, §13.2.2.4.
- Repro: `DKR go test -race -count=1 -run '^TestAuditReInvite2xxUnanchorableIsACKed$' ./internal/edge`.
- Action: fix.

### P2-EDG-014 — PSTN failover retries after 6xx
- Location: `internal/edge/invite.go:694-697` (`>= 500 || == 408` includes 600-699).
- Evidence: FACT. `TestAuditPSTN6xxStopsFailover`: after gw-a's 603 Decline, FreeSWITCH gets 200 because gw-b was dialed.
- Reference: RFC 3261 §16.7 step 5, §21.6; docs drift: docs/edge.md says failover on "a 5xx/408".
- Repro: `DKR go test -race -count=1 -run '^TestAuditPSTN6xxStopsFailover$' ./internal/edge`.
- Action: fix.

### P2-EDG-015 — A provisional in the post-expiry drain becomes the synthesised "final"
- Location: `internal/edge/invite.go:832-854` (`expirePSTNAttempt` classifies any forwardable non-200 as `failReal`), `:622-623` (`reject` with `lastRealCode`).
- Evidence: FACT. `TestAuditPSTNProvisionalInDrainNotFinal`: FreeSWITCH never gets a final response; the gateway's 180 became the "final". Phase 0 flagged the related `:836` check (only 200 is a raced answer).
- Reference: RFC 3261 §16.7 step 6, §17.1.1.3.
- Repro: `DKR go test -race -count=1 -run '^TestAuditPSTNProvisionalInDrainNotFinal$' ./internal/edge`.
- Action: fix.

### P2-EDG-018 — ACK can race the commit
- Location: `internal/edge/invite.go:978-1028` (2xx relayed before `commit` at `:259`, `:389`, `:582`); `:1325-1335`, `:1227-1230`, `:1363-1366`; the comment at `:1355` acknowledges the race.
- Evidence: INFERENCE. `TestAuditAckRacesCommit` passed (0 of 20 ACKs lost): the window was not hit on loopback; this does not refute the ordering defect.
- Reference: RFC 3261 §13.2.2.4, §17.1.1.3.
- Repro: `DKR go test -race -count=1 -run '^TestAuditAckRacesCommit$' ./internal/edge` (currently passes).
- Action: fix. Confirm the dialog before relaying the 2xx.

### P2-EDG-028 — `Contact: *` un-REGISTER removes only one binding
- Location: `internal/edge/register.go:107-109` (wildcard replaced by a token contact), `:263-265`.
- Evidence: INFERENCE.
- Reference: RFC 3261 §10.2.2.
- Repro: not tested. Proposed: two registrations with different Call-IDs, then `Contact: *`/`Expires: 0`; assert both bindings removed.
- Action: fix.

### P2-EDG-032 — Media-driven teardown sends no BYE
- Location: `internal/edge/dialog.go:340-343` (watchdog → `d.end()`), `internal/edge/media.go:255` (fingerprint mismatch); later FreeSWITCH BYE gets 481 (`invite.go:1332-1334`).
- Evidence: FACT. `TestAuditMediaTimeoutSendsBye`: media timeout ends the call with 0 BYEs to FreeSWITCH and none to the phone. (Resources are released: `TestAuditBalanceMediaTimeout` passes.)
- Reference: RFC 3261 §15; invariant 49.
- Repro: `DKR go test -race -count=1 -run '^TestAuditMediaTimeoutSendsBye$' ./internal/edge`.
- Action: fix (send BYE to both sides), or document as a limitation.

### P2-MED-002 (aka P2-EDG-017, P1-001) — Relay runs before the DTLS fingerprint is verified
- Location: `internal/media/webrtcsession.go:141-174` (relay goroutines start on `leg.Ready()`); `internal/edge/media.go:238-257` (`VerifyFingerprint` after `sess.Start`); `internal/media/webrtcleg.go:319-331` (`InsecureSkipVerify`, no `VerifyPeerCertificate`).
- Evidence: FACT. `TestAuditMED002MediaFlowsBeforeFingerprintVerified`: SRTP from a peer whose certificate does not match the signalled fingerprint is decrypted and delivered to the private side before `VerifyFingerprint` runs. Exploitation needs the ICE credentials from signalling.
- Reference: RFC 5763 §5, RFC 8122 §5; invariant 52; design.md §8.7.
- Repro: `DKR go test -race -count=1 -run '^TestAuditMED002MediaFlowsBeforeFingerprintVerified$' ./internal/media`.
- Action: fix. Verify inside the handshake (`VerifyPeerCertificate`) before `legEstablished`.

### P2-MED-003 (aka P2-SDP-004) — Seeded media destination accepts loopback/unspecified/multicast/link-local
- Location: `internal/media/session.go:91-102` (`seed` checks only validity and port 0); `internal/sip/sdp/sdp.go:249-253` (only `netip.ParseAddr`); `internal/edge/media.go:188-200`, `:390-392`, `:450-452`.
- Evidence: FACT. `TestAuditMED003SeedAcceptsNonUnicastDestinations` (0.0.0.0, ::, 224.0.0.1, 239.1.2.3, 255.255.255.255, 169.254.1.1, ff02::1, fe80::1 installed); `TestAuditMED003SeedReflectsToLocalService` (RTP sent to 127.0.0.1:49500 and 0.0.0.0:40309); `TestAuditParseRejectsNonUnicastDestination` (Parse returns 127.0.0.1/0.0.0.0/224.1.1.1/169.254.1.1/::1 as destinations). Loopback is legitimately used in labs and tests, so the loopback case needs a policy switch; unspecified/multicast/broadcast/link-local are never valid unicast RTP destinations.
- Reference: RFC 3264 §8.4 (0.0.0.0 = hold); `mux.go:141-143` anti-reflection intent.
- Repro: `DKR go test -race -count=1 -run '^TestAuditMED003' ./internal/media`; `go test -race -count=1 -run '^TestAuditParseRejectsNonUnicastDestination$' ./internal/sip/sdp`.
- Action: fix.

### P2-MED-004 — Silence watchdog cannot reclaim a one-way-dead call
- Location: `internal/media/relay.go:77`, `:99-122`; `internal/media/webrtcsession.go:202`, `:241` (one `lastRx` for both directions).
- Evidence: FACT. `TestAuditMED004OneWaySilenceNeverReclaimed`: side A silent 1.6 s with `rtp_timeout` 200 ms while side B streams; never reclaimed.
- Reference: invariant 49 ("the only automatic reclaim for a confirmed call whose BYE was lost"); `relay.go:100` comment.
- Repro: `DKR go test -race -count=1 -run '^TestAuditMED004OneWaySilenceNeverReclaimed$' ./internal/media`.
- Action: fix (per-direction `lastRx`) or correct the docs.

### P2-MED-005 — `Relatch` forgets the destination; trunk never re-seeds
- Location: `internal/media/session.go:68-74`; `internal/trunk/b2bua.go:1597-1598`.
- Evidence: INFERENCE. A recvonly peer or an IVR that waits for audio never receives media after a relatch.
- Reference: RFC 3264 §6.1; invariant 44/45.
- Repro: not tested. Proposed: Allocate, `SetExpectedRemote(A)`, `Relatch(B, ip)`, Start; send from A only; assert B receives.
- Action: fix (seed from the answer's `c=`/`m=`).

### P3-MED-001 — SRTP round trip fails for a zero-length non-RFC 8285 header extension
- Location: `internal/media/srtp.go:118` (`protectRTP` accepts), `:125` (`unprotectRTP` fails); relay `internal/media/relay.go:80-89`. Cause is in pion's header re-marshal.
- Evidence: FACT. Found by `FuzzAuditSRTPRoundTrip`; `TestAuditMED_P3_001SRTPRoundTripEmptyHeaderExtension`: profile 0xC2DE length 0 → protect ok, unprotect fails; 0xBEDE works. Minimised input `internal/media/testdata/fuzz/FuzzAuditSRTPRoundTrip/666d63480a603d0b`.
- Reference: RFC 3550 §5.3.1, RFC 3711 (SRTP must round-trip any valid RTP header).
- Repro: `DKR go test -race -count=1 -run '^TestAuditMED_P3_001SRTPRoundTripEmptyHeaderExtension$' ./internal/media`.
- Action: fix (report to pion; reject or normalise before protect).

### P2-SHD-003 — Prune resets partly drained buckets, bypassing `N/h` limits
- Location: `internal/shield/ratelimit.go:63-77` (delete when idle ≥ 1 min, regardless of the bucket's interval); `internal/config/types.go:142-143` (`h` unit accepted).
- Evidence: FACT. `TestAuditPruneDoesNotResetHourlyBucket`: after 61 s idle and a prune, 10 of 10 requests allowed on a `10/h` limit.
- Reference: design.md §5.3, §14.1 (token bucket, capacity equals rate).
- Repro: `go test -race -count=1 -run '^TestAuditPruneDoesNotResetHourlyBucket$' ./internal/shield`.
- Action: fix. Evict only when idle ≥ the bucket's own interval.

### P2-SIP-001 (aka P2-EDG-019, PH0-007) — `GrantedExpires` takes the first Contact with `expires=`, accepts negatives, overflows
- Location: `internal/sip/register.go:14-32`; callers `internal/edge/register.go:262`, `internal/trunk/register.go:114`; the value is echoed to the client in `restoreContact` (`edge/register.go:323-328`).
- Evidence: FACT (partial). `TestAuditGrantedExpiresRejectsNegativeAndOverflow`: `expires=-1` → -1s, `expires=9223372037` → -2562047h47m16.7s. The wrong-device part (first Contact belongs to another device of the same AoR) is INFERENCE: `GrantedExpires` has no parameter naming our Contact, so it can only be shown through the edge harness, which was not done.
- Reference: RFC 3261 §10.2.4, §10.3 step 8; invariant 29.
- Repro: `go test -race -count=1 -run '^TestAuditGrantedExpiresRejectsNegativeAndOverflow$' ./internal/sip`.
- Action: fix. Match the Contact carrying this binding's `fsbc` token; clamp.

### P2-SIP-005 — `TeardownRequest` ignores the route set
- Location: `internal/sip/request.go:69-81`; caller `internal/edge/invite.go:1052-1073` (`ackThenBye`).
- Evidence: FACT. `TestAuditTeardownRequestHonoursRouteSet`: ACK `Route` is empty, want `p2, p1`.
- Reference: RFC 3261 §12.1.2, §13.2.2.4, §15.1.1.
- Repro: `go test -race -count=1 -run '^TestAuditTeardownRequestHonoursRouteSet$' ./internal/sip`.
- Action: fix.

### P2-SDP-001 (aka P2-EDG-016) — Answer m-line order and media type do not match the offer
- Location: `internal/sip/sdp/build.go:74-80`, `:163-167`, `:197-206`; `internal/sip/sdp/sdp.go:172-178`, `:199-210` (`Session` keeps only `MediaCount`); edge callers `internal/edge/media.go:315`, `:404`, `:462`, `:561`.
- Evidence: FACT. `TestAuditMarshalDecliningPreservesOrder`: offer video,audio → answer has audio at index 0.
- Reference: RFC 3264 §6; invariant 12; docs drift design.md:1861-1864, 2918-2920.
- Repro: `go test -race -count=1 -run '^TestAuditMarshalDecliningPreservesOrder$' ./internal/sip/sdp`.
- Action: fix (record the relayed index and per-section media/proto; emit in offer order).

### P2-SDP-002 — One `o=` counter shared by both legs; versions jump by more than one per leg
- Location: `internal/edge/dialog.go:81-95`, `:258-262`; callers `internal/edge/media.go:161`, `:303`, `:362`, `:396`, `:454`, `:516`, `:549`; contract `internal/sip/sdp/build.go:36-39`.
- Evidence: INFERENCE. The edge reviewer's clean list says the version is incremented per body (true); the defect is that the counter is per dialog, not per leg, so FS sees 1 → 3.
- Reference: RFC 3264 §8 ("MUST increment by one"); RFC 4566 §5.2.
- Repro: not tested. Proposed: edge test asserting consecutive `o=` versions on one leg across a re-INVITE.
- Action: fix (one `sdpOrigin` per leg).

### P2-SDP-003 (aka P2-EDG-030) — fmtp text is copied verbatim from the other leg, bare CR included
- Location: `internal/sip/sdp/sdp.go:310-313`; `internal/sip/sdp/codec.go:60-62`; `internal/sip/sdp/build.go:146-148`; edge flows `internal/edge/media.go:162-169`, `:284`, `:304-315`.
- Evidence: FACT. `TestAuditFmtpDoesNotCarryOtherLegText`: output contains `a=fmtp:0 x=1\rc=IN IP4 203.0.113.77`. `FuzzAuditBuildNoSentinelLeak` independently found `a=fmtp:0 0\r0` reaching output (corpus `internal/sip/sdp/testdata/fuzz/FuzzAuditBuildNoSentinelLeak/6bbf2d3780c31ebc`). Edge `TestAuditSDPLeakProperty`: fmtp text leaks in all 7 directions checked (incl. re-INVITE, browser→FS); c=, o=, m= port, a=rtcp, a=candidate, a=tool and video sections do not leak (120 bodies). The trunk equivalent is part of P2-TRK-006.
- Reference: invariant 11 ("never copied from the other leg's body"); RFC 4566 §5; docs contradict themselves (design.md:1855 admits "a=fmtp verbatim").
- Repro: `go test -race -count=1 -run '^TestAuditFmtpDoesNotCarryOtherLegText$' ./internal/sip/sdp`; `go test -count=1 -run 'FuzzAuditBuildNoSentinelLeak/6bbf2d3780c31ebc' ./internal/sip/sdp`; `DKR go test -race -count=1 -run '^TestAuditSDPLeakProperty$' ./internal/edge`.
- Action: fix (validate fmtp against the RFC 4566 byte-string grammar; per-codec allowlist); fix the docs.

### P2-SDP-005 — Duplicate codec identities in the offer cause a false `ErrRenumbered`
- Location: `internal/sip/sdp/codec.go:45-59` (`byKey` keeps the first answer codec per key); edge maps the error to 488 (`internal/edge/media.go:113-120`).
- Evidence: FACT. `TestAuditNegotiateDuplicateKeyNotRenumbered`: identical offer and answer reported as renumbered (offered 96 opus/48000/2, answered 111).
- Reference: RFC 3264 §6.1; RFC 3551 §3; invariant 39.
- Repro: `go test -race -count=1 -run '^TestAuditNegotiateDuplicateKeyNotRenumbered$' ./internal/sip/sdp`.
- Action: fix (match on the offered PT first).

### P2-TRK-002 — Trunk call store keyed by Call-ID alone
- Location: `internal/trunk/calls.go:116-125`, `:132-145`, `:151-162`, `:170-179`; `internal/trunk/server.go:41-42`.
- Evidence: FACT. `TestAuditCallStoreSameCallIDOverwrite`: `ActiveCalls = 1, want 2`; after call 1 ends, `ActiveCalls = 0, want 1`; KillCall cannot reach call 2. `TestAuditCallStoreFirstCallUnkillable`: call 1 is still bridged but no KillCall can reach it.
- Reference: RFC 3261 §12, §8.2.2.2 (merged requests → 482); invariant 26.
- Repro: `DKR go test -race -count=1 -run '^TestAuditCallStore' ./internal/trunk`.
- Action: rewrite (section 4).

### P2-TRK-003 — `recoverCall` swallows panics without a final response or BYE
- Location: `internal/trunk/b2bua.go:128`, `:1663-1668`; `internal/trunk/server.go:431-438` (outer 500 never fires for INVITE).
- Evidence: INFERENCE.
- Reference: RFC 3261 §8.2, §17.2.1, §15.
- Repro: not tested (needs a production hook to force a panic; section 5).
- Action: fix (500 if no final sent; BYE both legs if bridged).

### P2-TRK-004 — Reload changes advertised Contact/REGISTER port for restart-only listeners
- Location: `internal/trunk/server.go:490-510`, `:539-552` (resolve from the current snapshot); `internal/trunk/register.go:387-391`; used at `b2bua.go:204`, `:857-859`, `:991-992`.
- Evidence: FACT. `TestAuditReloadListenPortNotAdvertised`: after reloading `listen.sip` to `:47799` (not bound), the B-leg INVITE advertises `Contact <sip:127.0.0.1:47799>` (control before reload: 47750).
- Reference: invariant 77, 81.
- Repro: `DKR go test -race -count=1 -run '^TestAuditReloadListenPortNotAdvertised$' ./internal/trunk`.
- Action: fix (capture the bound listener set at `Run`).

### P2-TRK-005 — Several config snapshots per call
- Location: `internal/trunk/server.go:411`; `internal/trunk/b2bua.go:220`, `:572`, `:653`; `internal/trunk/mediapool.go:17`.
- Evidence: INFERENCE. No test seam exists to land a reload between the reads (section 5).
- Reference: invariant 75 ("the trunk takes one snapshot per call"); design.md §6.4 drift.
- Repro: not tested.
- Action: fix (pass `cfg` from `onInvite` down).

### P2-TRK-006 — Trunk SDP editing passes the other leg's attributes through (topology leak)
- Location: `internal/trunk/sdp.go:126-195` (`rewriteSDPCrypto` edits in place); callers `internal/trunk/b2bua.go:826`, `:844`, `:942`, `:956`, `:1489`, `:1496`.
- Evidence: FACT. `TestAuditSDPLeakProperty` (trunk) subtests `candidate`, `remote-candidates`, `ice`, `ssrc`, `fmtp`, `session-attr`, `origin-user` fail (sentinel 198.51.100.77:31337 relayed verbatim); `base` and `rtcp` pass (c=, o= address, m= port, a=rtcp rewritten over 300 random bodies × plain/SRTP).
- Reference: invariant 13; task invariant (topology hiding); docs contradiction `docs/trunk.md:65-66` ("full SDP rewrite") vs design.md §6.7 (P2-TRK-025).
- Repro: `DKR go test -race -count=1 -run '^TestAuditSDPLeakProperty$' ./internal/trunk`.
- Action: rewrite (section 4).

### P2-TRK-007 — A-leg `o=` is taken from whichever carrier answered
- Location: `internal/trunk/sdp.go:137-139`; `internal/trunk/b2bua.go:942`, `:956`, `:1489`, `:1496`.
- Evidence: FACT (partial). `TestAuditSDPLeakProperty/origin-user`: the other leg's `o=` username and session-id are kept. The change of `o=` between 18x and 200 / across failover is INFERENCE (needs a failover stub; not written).
- Reference: RFC 3264 §8; RFC 6337 §3.1.
- Repro: `DKR go test -race -count=1 -run '^TestAuditSDPLeakProperty$/^origin-user$' ./internal/trunk`.
- Action: rewrite (the SBC owns its own `o=` per leg; part of the P2-TRK-006 rewrite).

### P2-TRK-008 — Forked B-leg responses are not handled
- Location: `internal/trunk/b2bua.go:1121-1162`, `:1464-1511`, `:1561-1600`.
- Evidence: INFERENCE. Early media re-latches to whichever fork's 183 arrived last; a second fork's 2xx is never ACKed or BYEd.
- Reference: RFC 3261 §13.2.2.4, §12.1, §19.3.
- Repro: not tested (needs a fork-capable stub carrier; section 5).
- Action: fix (track forks by To-tag; ACK+BYE extra 2xx).

### P2-TRK-009 — Session-timer negotiation violates RFC 4028; SBC never refreshes
- Location: `internal/trunk/b2bua.go:993-1000`, `:867-873`, `:206-209`.
- Evidence: INFERENCE. `refresher=uac` without `Require: timer` or checking `Supported: timer`; carrier's `refresher=uac` ignored.
- Reference: RFC 4028 §7.2, §9, §10.
- Repro: not tested.
- Action: fix.

### P2-TRK-010 — Compact `x` (Session-Expires) and `k` (Supported) not recognised
- Location: `internal/trunk/timers.go:14-29`; used at `internal/trunk/b2bua.go:209`, `:252`, `:994-995`, `:1251`, `timers.go:113`. sipgo maps only `c f t m i v l` (`sip/parse_header.go:40-61`).
- Evidence: FACT. `TestAuditCompactSessionExpiresBypassesMinSE`: long form → 422; `x: 30` → 488 (want 422). `TestAuditHeaderSecondsCompactSessionExpires`: `x: 30` parses as 0s. Control `TestAuditHeaderSecondsLongFormControl` passes.
- Reference: RFC 4028 §4; RFC 3261 §7.3.3, §20.
- Repro: `DKR go test -race -count=1 -run '^TestAuditCompactSessionExpiresBypassesMinSE$|^TestAuditHeaderSecondsCompactSessionExpires$' ./internal/trunk`.
- Action: fix.

### P2-TRK-011 — Digest realm pinning bypassable by substring match; case-sensitive name
- Location: `internal/trunk/timers.go:37-65` (`strings.Index(v, "realm=")`); used at `internal/trunk/b2bua.go:1152-1156`, `internal/trunk/register.go:103`.
- Evidence: FACT. `TestAuditChallengeRealmSubstringBypass`: returns `"trusted"` for `Digest xrealm="trusted", realm="rogue"`. `TestAuditChallengeRealmCaseInsensitiveName`: `REALM="carrier"` yields `""` (fails closed).
- Reference: invariant 105 (realm pinning aborts before any Authorization header); RFC 3261 §25.1; RFC 2617 §1.2.
- Repro: `go test -race -count=1 -run '^TestAuditChallengeRealm' ./internal/trunk`.
- Action: fix (parse auth-params).

### P2-TRK-012 — SDES lines with MKI or session params accepted as plain
- Location: `internal/trunk/crypto.go:27-38`, `:40-55`.
- Evidence: FACT. `TestAuditSDESLineWithMKIRejected` (MKI-bearing key accepted as plain); `TestAuditSDESLineWithSessionParamRejected` (`UNENCRYPTED_SRTP` ignored).
- Reference: RFC 4568 §6.1, §6.3.
- Repro: `go test -race -count=1 -run '^TestAuditSDESLine' ./internal/trunk`.
- Action: fix (reject or support).

### P2-TRK-013 — In-dialog INVITE for an unknown dialog gets 501, not 481; hold re-INVITE gets 501, not 488
- Location: `internal/trunk/b2bua.go:189-218` (`:216`).
- Evidence: INFERENCE; documented in design.md §6.2 (invariant 27).
- Reference: RFC 3261 §12.2.2, §14.2.
- Repro: not tested.
- Action: fix.

### P2-TRK-015 — Refresh 200 on the raw transaction is never retransmitted
- Location: `internal/trunk/b2bua.go:183-188`, `:206-214`.
- Evidence: INFERENCE; documented (invariant 107).
- Reference: RFC 3261 §13.3.1.4; RFC 4028 §10.
- Repro: not tested.
- Action: fix.

### P2-TRK-016 — Outbound TLS trust and client certificates merged across peers
- Location: `internal/trunk/tlscert.go:61-97`; installed UA-wide at `internal/trunk/server.go:167-182`.
- Evidence: INFERENCE; documented as a sipgo constraint (invariant 115).
- Reference: per-peer trust; mTLS identity.
- Repro: not tested (needs a multi-CA stub; section 5).
- Action: rewrite (section 4).
- Decision (2026-09-24): rewrite with option (c). Keep one UA-wide `tls.Config` and select per peer through callbacks. Set `InsecureSkipVerify: true` and a `VerifyConnection` that verifies `cs.PeerCertificates` against the pool of the peer matched by `cs.ServerName` (that peer's `tls_ca`, or the system roots if it has none) and fails when no peer matches. Set a `GetClientCertificate` that returns the certificate of the peer carried in the handshake ctx (`cri.Context()`; sipgo passes the dial ctx to `HandshakeContext` at `sip/transport_tls.go:73`); the trunk puts the peer into that ctx on `TransactionRequest` and on the dialog Invite. With no peer key in the ctx it returns no certificate.
  - Rejected: (a) one sipgo UA per TLS peer (needs per-UA servers, handlers, read filter, dialog caches, transaction routing and shutdown); (b) a custom dialer (in sipgo v1.4.3 `tlsClient` is an unexported field of `TransportTLS`, set in the unexported `(*TransportTLS).init` method, `sip/transport_tls.go:17-33`; needs a fork or a `replace`).
  - Known limits: peers that share a hostname or IP:port cannot be distinguished (plan: reject in validation); dials on background-ctx paths get no client certificate; no per-peer SNI override. For a peer dialled by IP literal, `cs.ServerName` is empty (sipgo passes the IP as `hostname`, and Go's `crypto/tls` omits IPs from SNI, `hostnameInSNI`), so matching by `cs.ServerName` needs a fallback for IP-addressed peers. `InsecureSkipVerify` also disables the hostname/IP-SAN check, so `VerifyConnection` must perform it.
  - Test plan: a loopback self-signed test with two peers that have distinct private CAs, where peer B's endpoint presents a certificate signed by A's CA; the dial must fail after the fix (it succeeds today). An mTLS test asserts that B receives only B's client certificate. Both reuse `genCertKey` (`internal/trunk/tls_test.go:23`).

### P2-TRK-017 (aka P2-APP-001) — Shutdown leaves bridged trunk calls without BYE; goroutines, sessions and ports leak
- Location: `internal/trunk/server.go:302-319` (Run waits only for listeners); `internal/trunk/b2bua.go:459-484` (select has no shutdown arm; `killCtx` from `context.Background()`); `internal/app/app.go:55`, `:137-139`.
- Evidence: FACT. `TestAuditResourceBalanceShutdownWithLiveCalls`: after `Run` returns, `ActiveCalls = 4`, `calls=4 legs=8`, pool in use 8 of 20 pairs, 0 BYEs to the carrier, 4/4 callers got no BYE, goroutines 31 vs baseline 3 (`onInvite` ×4, `media.watchdog` ×4, `forward.func1` ×16). The edge equivalent passes (`TestAuditBalanceShutdownWithLiveDialogs`).
- Reference: task invariant (release on shutdown); design.md §4.5 is silent on trunk calls.
- Repro: `DKR go test -race -count=1 -run '^TestAuditResourceBalanceShutdownWithLiveCalls$' ./internal/trunk`.
- Action: fix (kill every call with `byeBoth` before closing transports).

### P2-TRK-022 — `RTP/SAVPF` not treated as secure; FQDN `c=` rejected
- Location: `internal/trunk/sdp.go:92-97`, `:38-41`.
- Evidence: FACT. `TestAuditOfferedCryptoSAVPF`: secure=false for `RTP/SAVPF`. `TestAuditRemoteMediaIPFQDN`: `bad connection address "media.example.com"`.
- Reference: RFC 5124; RFC 4566 §5.7.
- Repro: `go test -race -count=1 -run '^TestAuditOfferedCryptoSAVPF$|^TestAuditRemoteMediaIPFQDN$' ./internal/trunk`.
- Action: fix.

### P3-TRK-N01 — Trunk rejects any SDP with an `m=image` (T.38) section
- Location: `internal/trunk/sdp.go:23-24`, `:55-56`, `:84-85`, `:126-129` (pion/sdp v3.0.19 `Unmarshal` accepts only audio|video|text|application|message).
- Evidence: FACT. `TestAuditT38ImageSectionAccepted`: `parse sdp: sdp: invalid value 'image'`. That `placeCall` refuses the INVITE is INFERENCE from reading.
- Reference: RFC 3264 §6 (decline an unsupported section with port 0).
- Repro: `go test -race -count=1 -run '^TestAuditT38ImageSectionAccepted$' ./internal/trunk`.
- Action: rewrite (covered by the trunk SDP rewrite; or parse with the bounded `internal/sip/sdp` parser).

## 3.3 P2

Compact format for P2: Location · Evidence · Reference · Repro · Action. "Repro: —" means no test or tool run was made; the proposed confirming test is in `phase2/<pkg>.md`.

### admin
- **P2-ADM-003 — Limiter keyed by exact IP string.** `internal/admin/server.go:183-198`, `:320-346`, `:355-361`. FACT (partial): `TestAuditAuthLimiterCapDoesNotResetAttacker` — 4096 fresh source IPs clear the table and reset an attacker's exhausted budget. INFERENCE: on loopback/behind a proxy, 10 bad requests lock out operators and the Prometheus scrape (valid credentials get 429); unauthenticated first GETs count as failures; IPv6 keys per /128. Ref: invariant 99/100. Repro: `go test -race -count=1 -run '^TestAuditAuthLimiterCapDoesNotResetAttacker$' ./internal/admin`. Action: fix (do not deny valid credentials; /64 keys; evict oldest).
- **P2-ADM-004 — PUT /api/config lost update.** `internal/admin/config_write.go:97-107`, `:117` (If-Match optional; check and rename not serialised). FACT: `TestAuditConfigPutIfMatchIsAtomic` — 7 PUTs with the same If-Match all succeed (count is timing-dependent, always > 1 observed). Ref: invariant 103. Repro: `go test -race -count=1 -run '^TestAuditConfigPutIfMatchIsAtomic$' ./internal/admin`. Action: fix (mutex around check+write; optionally require If-Match).
- **P2-ADM-005 — `writeFileAtomic` replaces a symlinked config; no directory fsync.** `internal/admin/config_write.go:26-57` (rename at `:52`). FACT (partial): `TestAuditConfigPutFollowsSymlink` — the symlink becomes a regular file and the target is not updated. The missing directory fsync is INFERENCE. Ref: invariant 103 (atomic write). Repro: `go test -race -count=1 -run '^TestAuditConfigPutFollowsSymlink$' ./internal/admin`. Action: fix (`EvalSymlinks`; sync the directory).
- **P2-ADM-006 — Panic umbrella logs no stack.** `internal/admin/server.go:375-386`. INFERENCE. Repro: —. Action: fix (log `debug.Stack()`).
- **P2-ADM-008 — Admin docs drift.** design.md:356 cites `admin/server.go:255-260` (actual `:252-257`); design.md §13.4 limiter-sweep description differs from `server.go:336-347`; `server.go:1-2` calls the API "read-only" although it serves PUT/DELETE. INFERENCE. Action: fix (docs).

### app / cmd
- **P2-APP-002 — Data race on `trunk.Server.registrar`.** Write `internal/trunk/server.go:284` (Run goroutine); read `server.go:131` via `internal/app/app.go:199` from admin handlers (`internal/admin/api.go:53`) and the collector (`internal/admin/metrics.go:103`). `s.shield` is already an `atomic.Pointer` for this reason. INFERENCE (no `-race` test written). Action: fix.
- **P2-APP-003 — Plane existence decided once at startup, not listed as restart-only.** `internal/app/app.go:69`, `:78`; docs/design.md:337-345. A reload that adds/removes peers or upstreams is accepted silently. INFERENCE. Ref: invariant 9, 77. Action: fix (docs; optionally reject such reloads). Related: P2-CFG-007.
- **P2-APP-004 — `app.Run` reads new snapshots after the watcher starts.** `internal/app/app.go:120`, `:134-135` vs `cfg` at `:49`. INFERENCE. Ref: invariant 75. Action: fix (use `cfg`).
- **P2-APP-005 (aka P2-ADM-007, PH0-002) — Admin reports trunk-only or configured state.** `internal/app/app.go:146-204`: `ActiveCalls` sums both planes but `Calls` lists trunk only (`:155-180`); `Ports` is the trunk pool even when no trunk runs (`:152`); `internal/admin/api.go:19-22` lists listeners from the hot-reloaded config although listeners are restart-only; `app.go:57-60` logs the legacy `Listen.Media.PortRange` (prints `0-0` when `rtp.port_min/max` is used; design.md:247 says it logs the trunk range). INFERENCE. Ref: invariant 69, 77. Action: fix.
- **P2-APP-007 — Positional arguments silently ignored.** `cmd/freesbc/main.go:39`: `freesbc run edge.yaml` runs `./sbc.yaml` with exit 0. Documented (design.md:233-235). INFERENCE. Action: fix (exit 2 when `NArg() > 0`).
- **P2-APP-008 — Second SIGINT cannot force-exit a hung shutdown.** `cmd/freesbc/main.go:49-50` (`stop()` only when `main` returns). INFERENCE. Action: fix.
- **P2-APP-009 — App test syncs with `time.Sleep` and a racy free-port helper.** `internal/app/app_test.go:61`, `:85-93`; the test never checks that startup succeeded. INFERENCE. Action: fix (test only).

### config
- **P2-CFG-004 (aka P2-APP-006, PH0-003) — `check` accepts configs that `run` rejects.** Validation uses `checkHostPort` (`internal/config/validate_proxy.go:366-379`) while `run` requires literal IPs (`internal/edge/topology.go:126-134`, `:275-276`); no socket-collision check across trunk and edge listeners (`validate_proxy.go:204-222`); `app.Check` is `config.Load` only (`internal/app/app.go:31-34`), so DTLS certs (`internal/edge/edge.go:132`) and peer TLS files (`internal/trunk/tlscert.go:69`, `:84`) are never read by `check`. FACT: `TestAuditCheckRejectsWhatRunRejects` — upstream hostname, `sip.pstn.match` hostname, duplicate `listen.sip`, trunk and edge on the same UDP port all pass `Parse`; the `run` failures for pstn.match and the shared port were reproduced with the binary. The cert/TLS-file part is INFERENCE. Docs drift: design.md:511, 528-529, 2474, 2476 say "Enforced". Repro: `go test -race -count=1 -run '^TestAuditCheckRejectsWhatRunRejects$' ./internal/config`. Action: fix.
- **P2-CFG-005 — Named capture group `${num}` in a route transform is expanded as an env var.** `internal/config/expand.go:15`, `:21`, `:116-127`; `validate.go:315-365` supports named refs. FACT: `TestAuditNamedGroupNotExpandedAsEnv` — `undefined environment variable(s) referenced in config: [num]`; with `num=EVIL`, the transform becomes `+EVIL`. Ref: invariant 71. Repro: `go test -race -count=1 -run '^TestAuditNamedGroupNotExpandedAsEnv$' ./internal/config`. Action: fix.
- **P2-CFG-006 — `${VAR}` cannot be used in typed scalars (durations, port ranges, listeners, host:port).** `internal/config/types.go:30-106`, `internal/config/proxy.go:33-51`, `expand.go:104`. FACT (binary: `ring_timeout: ${RT}` → `invalid duration "${RT}"`; see `phase2/config.md`). Undocumented in design.md §5. Action: fix (docs).
- **P2-CFG-007 — Reload silently accepts changes to restart-only settings.** `internal/config/reload.go:73-80`. INFERENCE (P2-TRK-004 and P2-CFG-002 are concrete consequences). Ref: invariant 77. Action: fix (diff restart-only fields; reject or warn).
- **P2-CFG-008 — IPv4-mapped `allowed_ips` validate but never match.** `internal/config/validate.go:175-201`; sources are `Unmap`ped (`internal/sip/addr.go:34`, `:47`). FACT: `TestAudit4in6AllowedIPsMatchOrReject`. Repro: `go test -race -count=1 -run '^TestAudit4in6AllowedIPsMatchOrReject$' ./internal/config`. Action: fix.
- **P2-CFG-009 — 2-port trunk range validates but holds no call.** `internal/config/types.go:68`, `validate.go:417-429`. FACT: `TestAuditTrunkPortRangeHoldsOneCall`. Repro: `go test -race -count=1 -run '^TestAuditTrunkPortRangeHoldsOneCall$' ./internal/config`. Action: fix (≥ 4 ports for trunk).
- **P2-CFG-010 — Dead "bind required" validation branches.** `internal/config/validate_proxy.go:207-209`, `:235-236` (defaults always fill the bind, `proxy.go:404-424`). INFERENCE. Action: delete.
- **P2-CFG-011 — Watch misses Kubernetes ConfigMap symlink swaps.** `internal/config/reload.go:61-63`. INFERENCE. Action: fix or document.
- **P1-008 — Very high cognitive complexity.** gocognit: `validateProxy` 133 (`internal/config/validate_proxy.go:19`), `validate` 121 (`internal/config/validate.go:21`), `pumpPSTNAttempt` 48 (`internal/edge/invite.go:646`), `onInvite` 45 (`internal/trunk/b2bua.go:127`), plus 7 more > 30. FACT (`raw/03-golangci-lint.txt`). Repro: `golangci-lint run -c docs/audit/raw/.golangci.yml ./... | grep gocognit`. Action: fix (split by section). The Phase 1 grade said "rewrite"; changed to fix because the identity model is not at fault.

### edge
- **P1-003 — Edge test harness media windows never wrap.** `internal/edge/harness_test.go:74-76`; `./internal/edge` fails every run with `-count>1`. FACT (`raw/02-test-count10-full.txt`). Repro: `DKR go test -race -count=2 ./internal/edge`. Action: fix (test infra).
- **P1-009 — `edge.(*Server).Ready` reachable only from tests.** `internal/edge/edge.go:146`. FACT (`raw/04-deadcode.txt`). Repro: `deadcode ./...`. Action: delete (or move behind a test helper).
- **P2-EDG-020 — OnCancel hook blocks up to 5 s inside sipgo's FSM lock.** `internal/edge/invite.go:1511-1525`; sipgo `transaction_server_tx_fsm.go:296-315`. INFERENCE. Lock held across network I/O. Action: fix (run `cancelPending` asynchronously).
- **P2-EDG-021 — Shield exemption for FreeSWITCH's PSTN INVITEs depends on a 10-minute cache.** `internal/edge/plane.go:42`, `:65-70`; `edge.go:516`. INFERENCE. Action: rewrite together with P2-EDG-003.
- **P2-EDG-022 — Shield-banned sources still get responses (sipgo stateless 400, CANCEL 200).** `internal/edge/edge.go:467-489`; sipgo `transaction_layer.go:154-181`. INFERENCE. Ref: invariant 61 (silent drops). Action: fix (consult bans in the read filter).
- **P2-EDG-023 — Two finals on one transaction (488 then 503); metrics count the second.** `internal/edge/invite.go:1024-1025`, `:271-272`, `:288`; `edge.go:557`. INFERENCE. Action: fix.
- **P2-EDG-024 — Unsynchronised `mediaSession.codecs`; one stored answer shared by concurrent re-INVITEs.** `internal/edge/media.go:288`, `:389`, `:446`, `:546`; `invite.go:1188-1190`. INFERENCE (codecs race acknowledged in design.md §7.7). Action: fix.
- **P2-EDG-025 — Reloading RTP bind IP takes effect; advertised media IP does not.** `internal/edge/mediapool.go:15-30` vs `internal/edge/topology.go:331-332`; `AllocateAcross` reads config twice per call (see P2-MED-009). INFERENCE. Docs drift: design.md:337-345 does not list `advertised_ip` as restart-only. Action: fix.
- **P2-EDG-026 — Teardown ACK/BYE not pinned to a listener socket.** `internal/sip/request.go:69-81` via `internal/edge/invite.go:1054`, `:1060-1063` vs `forward.go:77-87`. INFERENCE (wildcard binds untested). Action: fix.
- **P2-EDG-027 — In-flight INVITE can outlive shutdown and allocate after `closeAll`.** `internal/edge/edge.go:307`, `:174`, `:185`. INFERENCE. `TestAuditBalanceShutdownWithLiveDialogs` passed for 3 confirmed calls + 1 ringing INVITE; the mid-allocation window was not hit. Repro: `DKR go test -race -count=1 -run '^TestAuditBalanceShutdownWithLiveDialogs$' ./internal/edge` (passes). Action: fix (wait for handler goroutines).
- **P2-EDG-029 — Orphan CANCEL answered 481 instead of forwarded statelessly.** `internal/edge/invite.go:1245-1254`. INFERENCE. Ref: RFC 3261 §16.10. Action: fix or document.
  - Resolution (issue #26): documented, not changed. Every INVITE the edge forwards has a dialog record, so an orphan CANCEL that matches none (by Call-ID and From tag) has nothing downstream to cancel; forwarding it would let any source that knows a Call-ID inject CANCELs toward FreeSWITCH. It keeps its 481 (`TestOrphanCancelWrongFromTagDoesNotCancel`); the deviation is recorded in docs/design.md §7.8.
- **P2-EDG-031 — Media allocated before the upstream authenticates the caller.** `internal/edge/invite.go:157` vs `:230`; no edge call quota. INFERENCE. Action: fix (quota or lazy allocation).
- **P2-EDG-033 — Edge docs and comments drift.** design.md §7.7 citations off by 1-2 lines (see appendix table rows 38-41); §7.8 cites the OnCancel hook at `invite.go:500-502` (hooks at `:172-185`, `:383`, `:490-504`); §7.8 says sipgo sends 487 then fires OnCancel (the reverse is true); stale identifiers `forwardInboundInvite`/`PrivateRemote` (`invite.go:1347-1348`) and `commitCall` (`:1355`). INFERENCE. Action: fix (docs).
- **P2-EDG-034 — `guard` recover hides handler panics and can send 500 after a final.** `internal/edge/edge.go:500-506`. INFERENCE. Action: fix (panic counter; no 500 once finalised).

### media
- **P1-007 — WebRTC leg uses pion APIs marked for removal.** `internal/media/webrtcleg.go:273`, `:319`, `:335`, `:337`. FACT (staticcheck SA1019, `raw/03-golangci-lint.txt`). Action: fix (migrate to the options-based constructors). Phase 1 said "rewrite"; changed to fix (API migration, not an identity-model problem).
- **P1-012 — Trunk relay buffer 1500 bytes vs WebRTC 1508.** `internal/media/relay.go:47` vs `internal/media/mux.go:54`. INFERENCE. Larger datagrams are silently truncated. Action: fix.
- **P2-MED-007 (aka P1-011) — Per-packet heap allocations in SRTP protect/unprotect.** `internal/media/srtp.go:118`, `:125`, `:132`, `:139` (nil `dst` and header). FACT: `TestAuditMED007SRTPAllocsPerPacket` — protectRTP 2.0, unprotectRTP 3.0 allocs/packet (race build). Repro: `DKR go test -race -count=1 -run '^TestAuditMED007SRTPAllocsPerPacket$' ./internal/media`. Action: fix (per-goroutine dst buffer and header).
- **P2-MED-008 — `LatchStrict` comment contradicts code.** `internal/media/session.go:24-26` vs `:112-115`. INFERENCE. Action: fix the comment.
- **P2-MED-009 — One allocation reads the config snapshot up to 3 times.** `internal/media/session.go:213-220`; `portpool.go:84`, `:180`; `webrtcsession.go:76-82`. INFERENCE. Ref: invariant 75. Action: fix.
- **P2-MED-010 — Pool mutex held across the whole bind sweep.** `internal/media/portpool.go:90-111`, `:127-148` (documented as deliberate, invariant 41). INFERENCE. Action: fix (reserve under lock, bind outside), low priority.
- **P2-MED-011 — `Stats()` inUse can exceed total after a range-shrinking reload.** `internal/media/portpool.go:154-170`. FACT: `TestAuditMED011StatsInUseExceedsTotalAfterShrink` (inUse=3 > total=2) and trunk `TestAuditResourceBalanceReloadMidCall` (inUse=8 > total=2). The edge `TestAuditBalanceReloadMidCall` passes (inUse=3, total=50) and does not contradict this: it moves the public range to 100 new ports (50 pairs) while only 3 pairs are in use, so the new total never drops below inUse; the media and trunk tests shrink the range below the live reservation count. All three tests confirm that the old ports are released correctly; the defect is only the reported ratio. Repro: `DKR go test -race -count=1 -run '^TestAuditMED011StatsInUseExceedsTotalAfterShrink$' ./internal/media`. Action: fix (count only in-range ports, or report old reservations separately).
- **P2-MED-012 — `WebRTCLeg.Start` not idempotent, not guarded after Close.** `internal/media/webrtcleg.go:235-253`. INFERENCE (latent; one caller). Action: fix (state CAS).
- **P2-MED-013 — Trunk legs labelled "public/private" in stats.** `internal/media/stats.go:51-65`. INFERENCE. Action: fix (naming).

### shield
- **P2-SHD-004 (aka P1-002, P2-TRK-026) — Trunk auto-ban, trunk ban table, admin unban and the nftables backend never act in production.** `internal/trunk/server.go:460`, `:468`, `:150`; `internal/shield/shield.go:176-191`, `:198`, `:268-306`; `internal/shield/nftables.go` (whole file); `internal/app/app.go:182-187`. FACT (partial): 0% coverage across all tests with `-coverpkg=./...` (`raw/05-cover-func-coverpkg-all.txt`); unreachability in production is INFERENCE (the trunk read filter drops non-peer bytes, and peers are exempt from bans). Documented in design.md:2681-2688 and README.md:132, yet the backend still installs a table and needs CAP_NET_ADMIN. Repro: `go test -p 1 ./... -count=1 -coverpkg=./... -coverprofile=c.out && go tool cover -func=c.out | grep -E 'dropUnidentified|Unban|unban'`. Action: delete (or move the ban/kernel plane to the edge shield).
  - Decision (2026-09-24): delete; the ban/kernel plane is not moved to the edge shield. Remove the trunk nftables backend (`internal/shield/nftables.go`, the `shield.nftables` config key, the `inet freesbc` table, the CAP_NET_ADMIN requirement), `RecordUnidentified` (`shield.go:176-191`), `failCounter` (`shield.go:268-306`, and its prune call at `:253`), `dropUnidentified` (`trunk/server.go:460-471`; its call sites at `server.go:557`, `:571`, `:596`, `:643` and `b2bua.go:132` keep a silent drop), and `shield.auto_ban.failures` / `auto_ban.window` (`config/schema.go:313-318`, `config/validate.go:255-260`). Keep `auto_ban.duration`: the edge scanner ban uses it (`shield.go:130`). The in-memory ban list, both rate limiters and scanner detection stay; the edge shield (`NewNoKernel`, `edge/edge.go:188`) is unchanged. Rationale: the trunk pre-parse filter (`trunk/readfilter.go:22-33`) admits only `allowed_ips` peers, and `Check` returns before the ban and scanner branches for peers (`shield.go:110-118`), so the trunk plane never calls `ban` and the kernel set never gets an element; deletion removes no production protection. Consequence: P2-SHD-007 and P2-SHD-010 become moot. Open follow-up: `DELETE /api/bans/{ip}` (`admin/server.go:121`) and the ban metrics are wired to the trunk shield only (`app/app.go:182-192`), so they always report no bans (`BannedCurrent` and `BanAddsRejected` stay 0); decide separately whether to remove them or wire them to the edge shield.
- **P2-SHD-005 — Trunk peer `allowed_ips` exempt from the edge plane's ban/scanner checks.** `internal/shield/shield.go:108-118`, `:259-266`; `internal/edge/edge.go:516-517`. INFERENCE. Ref: invariant 62, 67. Action: fix (per-plane exemption predicate).
- **P2-SHD-006 — A ban does not close an existing TCP/WS/WSS connection.** `internal/shield/shield.go:119-137`; `internal/edge/edge.go:517-519`. INFERENCE. Action: fix.
- **P2-SHD-007 — Failed nftables setup leaves a partial `inet freesbc` table.** `internal/shield/nftables.go:80-85`, `:173-177`. INFERENCE. Action: fix. Moot after the P2-SHD-004 decision (2026-09-24: delete `nftables.go`).
- **P2-SHD-008 — Re-ban overwrites and can shorten the expiry; docs say "extend".** `internal/shield/banlist.go:47` vs `:75`; design.md:2214. FACT: `TestAuditReBanDoesNotShorten` (1 h ban cut to 1 min). Repro: `go test -race -count=1 -run '^TestAuditReBanDoesNotShorten$' ./internal/shield`. Action: fix (use max) or correct the docs.
- **P2-SHD-009 — Admin unban does not unmap IPv4-mapped input.** `internal/app/app.go:183-187`; `internal/shield/shield.go:198-204`. INFERENCE. Action: fix.
- **P2-SHD-010 — `auto_ban.duration` < 1 s becomes nft `timeout 0s`.** `internal/shield/nftables.go:212`; `internal/config/validate.go:261-262`. INFERENCE (unreachable today, P2-SHD-004). Action: fix. Moot after the P2-SHD-004 decision (2026-09-24: delete `nftables.go`).

### sip
- **P2-SIP-002 (aka P2-SIP-003) — The 64 KiB read-filter cap can never fire.** `internal/sip/readfilter.go:8-10`, `:23`; `internal/edge/edge.go:459-469`; sipgo `transport.go:18` (`TransportBufferReadSize = 32768`). FACT: `TestAuditReadFilterCapIsReachable`. Docs drift: design.md:1012-1013, 2642-2644, 2704 and the `edge.go:459-461` comment say the cap is enforced (invariant 58). Repro: `go test -race -count=1 -run '^TestAuditReadFilterCapIsReachable$' ./internal/sip`. Action: fix (lower the cap or document sipgo's `ParseMaxMessageLength`).
- **P2-SIP-004 — `SameAddr` ignores transport and treats a wildcard as any host.** `internal/sip/addr.go:62-79`; caller `internal/edge/edge.go:475`. INFERENCE; fails closed (public stream clients on the private bind's port dropped). Action: fix.
- **P2-SIP-007 — `DefaultPort` maps `wss` to 5061 against its own RFC 7118 rationale.** `internal/sip/addr.go:81-94`; caller `internal/edge/topology.go:452`. INFERENCE (latent). Action: fix.
- **P2-SIP-008 — `ParseBindIP` falls back to all interfaces on a parse error.** `internal/sip/register.go:39-48`. INFERENCE (validation catches bad values today). Action: fix.
- **P2-SIP-009 — `ContactOrSource` exported but used only in-package.** `internal/sip/request.go:87`. INFERENCE. Action: fix (unexport).

### sip/sdp
- **P2-SDP-006 — `isHexByte` accepts control bytes 0x10-0x19.** `internal/sip/sdp/sdp.go:458-465`. FACT: `TestAuditFingerprintRejectsControlBytes`. Ref: RFC 8122 §5. Repro: `go test -race -count=1 -run '^TestAuditFingerprintRejectsControlBytes$' ./internal/sip/sdp`. Action: fix.
- **P2-SDP-007 — Comments claim RFC 3264 requires PT reuse (it is SHOULD).** `internal/sip/sdp/codec.go:28-31`, `sdp.go:20-23`. INFERENCE. Action: fix (docs; list the 488-on-renumber policy in docs/edge.md limitations).
- **P2-SDP-008 — `Describe` comment claims codec names are alphanumeric; `parseRTPMap` does not enforce it.** `internal/sip/sdp/codec.go:73-77` vs `sdp.go:367-370`. INFERENCE. Action: fix.
- **P2-SDP-009 — PT > 255 fails the whole Parse while 128-255 are skipped.** `internal/sip/sdp/sdp.go:319-329`. FACT: `TestAuditParseSkipsPayloadTypeAbove255` (`sdp: bad payload type "300"`). Repro: `go test -race -count=1 -run '^TestAuditParseSkipsPayloadTypeAbove255$' ./internal/sip/sdp`. Action: fix.
- **P2-SDP-010 — `ErrNoAudio` does not distinguish a declined audio stream from an absent one.** `internal/sip/sdp/sdp.go:207-213`. INFERENCE. Action: fix (`ErrAudioDeclined`).
- **P2-SDP-011 — Browser answer always carries `a=rtcp-mux`.** `internal/edge/media.go:482-485`; `internal/sip/sdp/sdp.go:260-295` does not parse `rtcp-mux`. INFERENCE. Ref: RFC 5761 §5.1.1. Action: fix.
- **P2-SDP-012 — 4-character `ice-pwd` accepted.** `internal/sip/sdp/sdp.go:410-413`. FACT: `TestAuditICEPwdMinimumLength`. Ref: RFC 5245 §15.4 (22-256). Repro: `go test -race -count=1 -run '^TestAuditICEPwdMinimumLength$' ./internal/sip/sdp`. Action: fix.

### trunk
- **P1-004 — `TestBridgePassesRealFinalCode` fails 10/10 in the full-module run (edge/trunk test ports overlap).** Pool `46240-46243` (`internal/trunk/b2bua_test.go:3885`) inside the edge harness window (`harness_test.go:76`). FACT for the failure (`raw/02-test-count10-full.txt`), INFERENCE for the cause; no production defect. Repro: `DKR go test -race ./... -count=10 -shuffle=on`. Action: fix (test infra).
- **P1-005 — Trunk tests share or overlap fixed media ranges.** `internal/trunk/b2bua_test.go:2049`/`:5071`, `:4357`/`:5103`, `:4047`/`:2298`, and others. FACT (`raw/02d-per-package-p1.txt`: `TestBridgeDigestAuth` 3/5, `TestBridgeCancelStopsFailover` 3/5, `TestBridgeEarlyMedia` 1/5; all 5/5 alone). Repro: `DKR go test -race -p 1 ./internal/trunk -count=5 -shuffle=1790222459610835843`. Action: fix (test infra).
- **P1-006 — `TestBridgeBrokenAnswerSDPGets502` flaky; stub carrier never closes `byeDone` on its broken-answer error path.** `internal/trunk/b2bua_test.go:604-609` vs `:612-620`. FACT for the flake (`raw/02e-broken-answer-repro.txt`), INFERENCE for the cause. Action: fix (test harness).
- **P2-TRK-014 — Unmatched CANCEL gets 405 (not 481); 405 carries no `Allow`.** `internal/trunk/server.go:640-650`. INFERENCE; documented. Ref: RFC 3261 §9.2, §21.4.6. Action: fix.
- **P2-TRK-018 — `headerSeconds` overflows on huge delta-seconds.** `internal/trunk/timers.go:24-28`. FACT: `TestAuditHeaderSecondsOverflow` (`9223372036854775807` → -1s). Ref: RFC 3261 §25.1; RFC 4028 §4. Repro: `go test -race -count=1 -run '^TestAuditHeaderSecondsOverflow$' ./internal/trunk`. Action: fix (clamp).
- **P2-TRK-019 — Early-media relay can race the main path after abandonment (concurrent A-leg writes).** `internal/trunk/b2bua.go:1139-1158`, `:1194-1222`. INFERENCE. Action: fix (one owner for A-leg responses).
- **P2-TRK-020 — Timed-out SRV lookup abandons its goroutine.** `internal/trunk/resolve.go:82-101`. INFERENCE. Action: fix (`net.Resolver.LookupSRV(ctx, …)`).
- **P2-TRK-021 — REGISTER uses a new Call-ID and CSeq=1 on every refresh.** `internal/trunk/register.go:69-92`. INFERENCE. Ref: RFC 3261 §10.2 (SHOULD). Action: fix.
- **P2-TRK-023 — Ignored errors on response/BYE sends.** `internal/trunk/b2bua.go:248`, `:261`, `:288`, `:306`, `:341`, `:376`, `:470`, `:474`, `:493`, `:496`, `:649`, `:701-705`, `:928`, `:959`, `:970`, `:1007`, `:1355`, `:1653`; `server.go:286`, `:436`. INFERENCE; hides lost teardowns. Action: fix (log at Debug).
- **P2-TRK-025 — `docs/trunk.md` contradicts design.md and code on SDP rewriting.** `docs/trunk.md:65-66` ("full SDP rewrite") vs design.md §6.7 and `internal/trunk/sdp.go:126-195`. INFERENCE. Action: fix (docs, or the code per P2-TRK-006).

### docs (Phase 0)
- **PH0-001 — Trunk REGISTER lifetime precedence documented in reverse.** design.md:885-886 (Expires header first) vs `internal/sip/register.go:12-31` (Contact param first); design.md:1135-1136 has the correct order for edge. INFERENCE. Action: fix (docs).
- **PH0-004 — design.md §6.5 credits `dialTarget` with the dial loop now in `dialAttempt`.** design.md:721-767, :190, :2230-2234, :2293; `internal/trunk/b2bua.go:1041-1357`; stale comment `b2bua.go:1103`. INFERENCE. Action: fix.
- **PH0-005 — README names one of the two loopback aliases.** README.md:153 names 127.0.0.2 only; `internal/trunk/server_preparse_test.go` also binds 127.0.0.9. INFERENCE. Action: fix.
- **PH0-006 (aka P2-TRK-024) — 43 stale file:line citations in design.md (behaviour unchanged).** Full cited→actual table in Appendix B. FACT (checked with `grep -n`/`sed -n`). Action: fix (docs).

### cross-package
- **P1-010 — Production paths with 0% coverage across all tests.** `media.LoadDTLSIdentity` (`internal/media/dtlscert.go:53`), `(*Session).SetRTCPRemote` (`internal/media/session.go:273`), `edge.(*Server).onNoRoute` (`internal/edge/edge.go:544`), `privateSources.pruneLocked` (`internal/edge/plane.go:72`), `trunk.(*Server).Calls` (`internal/trunk/calls.go:201`), `edge.(*Server).Metrics`/`Describe` (`edge.go:149`, `:320`), `Metrics.RegistrationFailed` (`internal/edge/metrics.go:63`). `internal/sip` has 9.9% coverage from its own tests (27 exported functions at 0% per package; all covered from trunk/edge). FACT (`raw/05-cover-func-coverpkg-all.txt`, `raw/05-cover-func.txt`). Repro: `go test -p 1 ./... -count=1 -coverpkg=./... -coverprofile=c.out && go tool cover -func=c.out | awk '$NF=="0.0%"'`. Action: fix (add tests).

# 4. Modules recommended for rewrite

Rewrite is recommended only where the identity model (keys, state ownership) is wrong, so point fixes cannot make the module correct.

1. **Edge dialog/transaction model** (`internal/edge/dialog.go` `dialogTable`, and the client-transaction handling in `internal/edge/invite.go` `pumpInvite` / `pumpPSTNAttempt`). Decisive reason: the dialog is keyed by Call-ID alone, with one media session per Call-ID, and the client transaction is terminated at the first final response. That model cannot represent a tag-scoped dialog, a second fork, or a 2xx retransmission, and FACT tests fail on all three: P2-EDG-005 (BYE with wrong tags tears the call down), P2-EDG-006 (fork B's 200 gets fork A's media), P2-EDG-004 (retransmitted 200 dropped). P2-EDG-018 and P2-SDP-002 (one `o=` counter per dialog, not per leg) come from the same ownership model. Target: dialog key = Call-ID + local tag + remote tag, per-fork early-dialog state, client transaction held until Timer M, per-leg SDP origin.
2. **Trunk call store** (`internal/trunk/calls.go`). Decisive reason: `calls`/`legs` are keyed by Call-ID and the admin ID is the dialog key, with no collision check, so a second call with the same Call-ID overwrites the first and `endCall` deletes the survivor (FACT: `TestAuditCallStoreSameCallIDOverwrite`, `TestAuditCallStoreFirstCallUnkillable`). Target: key by dialog ID (Call-ID + tags), separate admin ID, 482 for merged requests (RFC 3261 §8.2.2.2).
3. **Trunk SDP editing** (`internal/trunk/sdp.go` `rewriteSDPCrypto` and the pion-based helpers). Decisive reason: the output is the peer's body edited in place, so the default for every attribute is pass-through; every new attribute is a potential topology leak (FACT: 7 failing subtests of trunk `TestAuditSDPLeakProperty`), the `o=` belongs to the other leg (P2-TRK-007), and the pion parser rejects `m=image` outright (P3-TRK-N01). Target: construct the body from an allow-list, as the edge does with `internal/sip/sdp` `Build`, with the SBC owning `o=` per leg.
4. **Edge trust classification** (`internal/edge/plane.go` `privateSources`/`arrivedOnPrivate`, `internal/edge/invite.go` `isPSTNBridgeInvite`). Decisive reason: "is this FreeSWITCH" is keyed by source address, not by the local socket the packet arrived on (P2-EDG-003, P2-EDG-021). This one is INFERENCE; it is recommended because the fix changes what the trust key is, not a check.
5. **Trunk outbound TLS wiring** (`internal/trunk/tlscert.go`, `server.go:167-182`). Decisive reason: trust roots and client certificates are owned by one UA-wide `tls.Config` rather than per peer (P2-TRK-016, INFERENCE). Because sipgo v1.4.3 accepts one client `tls.Config` per UA (invariant 115), per-peer TLS needs either a per-peer UA/transport or a `GetClientCertificate`/`VerifyConnection` keyed by the dialled target. Decision (2026-09-24): the callback approach, option (c); see the P2-TRK-016 detail entry.

Evaluated and **not** recommended for rewrite:
- **Shield rate limiter / ban table** (P2-SHD-001/002/003). The key (source IP) is acceptable; the defects are a missing cap, a wrong eviction rule and a UDP ban policy. Patchable: capped LRU with /64 IPv6 keys, store the interval per bucket, no ban (or port-scoped ban) for UDP verdicts. Delete the unreachable trunk ban/nft plane (P2-SHD-004; decided 2026-09-24).
- **Admin auth limiter** (P2-ADM-002/003). Patchable: reserve the attempt under the lock before bcrypt, evict oldest instead of clearing, key IPv6 by /64, never answer valid credentials with 429.
- **Media latch** (P2-EDG-001/P2-MED-006). The latch model supports strict/armed modes already; the defect is the edge choosing loose mode with no preference for the signalled source. Patchable.

# 5. Things that could not be verified, and why

- **P2-EDG-003** (spoofed source trusted as FreeSWITCH): producing a spoofed-source datagram on loopback needs raw sockets and root. Whether the host accepts it also depends on `rp_filter`.
- **P2-EDG-009** (5-min backstop): `inviteTimeout` is a const; testing needs a production-code change or a test longer than 5 minutes.
- **P2-EDG-008** (INVITE sent between ctx check and track): the race window cannot be forced from outside the code.
- **P2-EDG-018** (ACK races commit): `TestAuditAckRacesCommit` passed 20/20 on loopback; the window was not hit. Not refuted.
- **P2-EDG-027** (INVITE mid-allocation at shutdown): the live-dialog shutdown path passes (`TestAuditBalanceShutdownWithLiveDialogs`); the mid-allocation window was not hit.
- **P2-TRK-003** (`recoverCall`): forcing a panic inside `onInvite` needs a production hook.
- **P2-TRK-005** (several snapshots per call): `config.Store` is concrete with no seam; the reads are microseconds apart on one goroutine, so a reload cannot land between them deterministically.
- **Not attempted in Phase 3** (stay INFERENCE): P2-TRK-007 (18x vs 200 part), 008, 009, 013, 014, 015, 016, 019, 020, 021, 023 (need fork-capable or multi-CA stubs); P2-EDG-010, 020-026, 028, 029, 031, 033, 034; P2-SDP-002, 007, 008, 010, 011; P2-SIP-001 (wrong-device part; needs the edge harness), 004, 007, 008, 009; P2-CFG-002 (failure is in edge), 007, 010, 011; P2-SHD-005, 006, 007, 009, 010; P2-ADM-005 (fsync part), 006, 008; all P2-APP findings except P2-APP-001 (P2-APP-002 was not run under `-race`); P2-MED-005, 008, 009, 010, 012, 013; P1-012; PH0-001/004/005.
- **P2-CFG-004 case 3** (default public UDP and private binds both `0.0.0.0:5060`): the `run` failure could not be isolated because a local FreeSWITCH held port 5060 on the review host.
- **Fuzz**: the `FuzzAuditConfigParse` re-run with known crash signatures skipped (`AUDIT_FUZZ_SKIP_KNOWN=1`) ended with `context deadline exceeded` from the fuzz engine and wrote no input; a slow input is possible and was not investigated. P3-MED-001's root cause is in pion and was not confirmed upstream. The trunk fuzzers ran on macOS without `-race`; media fuzzers ran in Docker without `-race`.
- **macOS limitations**: tests that need 127.0.0.2/127.0.0.9 skip or fail on a stock macOS host (`TestAuditMED006LooseLatchFirstPacketHijack`, `TestAuditTCPCapExhaustedByNonPeers`, the edge PSTN audit tests, and the 20 pre-existing tests listed in CLAUDE.md). All Phase 1 and Phase 3 socket runs used the Linux container.
- **Repeated-run flake detection for edge** is impossible while P1-003 stands (`-count>1` always fails). Pre-existing `TestPoolAllocateReleaseCycle` (media) failed 1 of 4 full runs with a port-exhaustion error; the cause (an ephemeral-port collision) is INFERENCE.
- **P2-ADM-004**: the number of PUTs that succeed with one If-Match is timing-dependent (7 in the recorded run); the FACT is that more than one succeeds.
- **sipgo comma-joined `Route` headers**: whether the caller splits them was not checked by any reviewer.
- **Phase 0 incidental observations**, not verified: `internal/edge/invite.go:836` (only 200 treated as a raced answer; related to P2-EDG-015); `internal/trunk/register.go:47-57` (423 retry also true for the `Expires: 0` un-REGISTER); `internal/edge/media.go:390-394` (`sess.rtp` dereferenced instead of `rtpLeg()`); `internal/edge/invite.go:1275-1299` (failed INFO forward sends no response); `internal/shield/banlist.go:21` (`sweepEvery` undocumented).
- **`// audit:` markers**: every `Test*`/`Fuzz*` in the new files carries a marker, with these deviations: the six media fuzz targets in `internal/media/audit_fuzz_test.go` (`FuzzAuditClassify` :43, `FuzzAuditDemux` :100, `FuzzAuditSRTPUnprotect` :154, `FuzzAuditSRTPRoundTrip` :178, `FuzzAuditWebRTCLegPreICE` :197, `FuzzAuditWebRTCEstablished` :235) share one file-level `// audit: P3-MED-FUZZ` at line 15 instead of a per-function marker; several markers name no finding ID (`P3-RB-bye` on edge `TestAuditBalanceNormalBye`, `P3-MED-BALANCE` on `TestAuditMediaPortPoolAndGoroutineBalance`, `resource balance (shield)` on `TestAuditShieldCloseReleasesGoroutines`, `fuzz (crash hunt)` on `FuzzAuditSIPMessageHelpers` and `FuzzAuditParseBuild`). Tests were not edited.

# 6. Test suite impact

The branch intentionally fails `go test ./...`. The failing `TestAudit*` tests are the deliverable and must not be changed to pass. In addition, `go test` replays saved fuzz corpora as seeds, so these targets also fail in a plain run:
- `internal/config/testdata/fuzz/FuzzAuditConfigParse/91d97c0654fe6f3e` → `FuzzAuditConfigParse` panics (P3-CORE-001).
- `internal/sip/sdp/testdata/fuzz/FuzzAuditBuildNoSentinelLeak/6bbf2d3780c31ebc` → `FuzzAuditBuildNoSentinelLeak` property failure (P2-SDP-003).
- `internal/media/testdata/fuzz/FuzzAuditSRTPRoundTrip/666d63480a603d0b` → `FuzzAuditSRTPRoundTrip` round-trip failure (P3-MED-001).

To run only the pre-existing suite: `go test ./... -race -skip 'Audit'`. The Phase 3 agents confirmed that all pre-existing tests in sip, sip/sdp, config, shield and admin still pass with the audit tests present.

# Appendix A — Phase 1 mechanical summary

All test runs used the Linux container `golang:1.25.7` (`docker run --rm -v "$PWD":/src -v freesbc-gomod:/go/pkg/mod -w /src golang:1.25.7 ...`), so the 127.0.0.2/127.0.0.9 loopback-alias failures of macOS do not appear. The worktree contained no untracked or modified `.go` files during any run (`git status --short` showed only `.gitignore` and `docs/audit/`), so every run measured baseline HEAD `1e63913`. The Phase 3 `audit_*_test.go` files appeared later (earliest birth time 12:07:12; the last Phase 1 run finished 12:05:41), so no Phase 1 result includes them.

## A.1 Per-step summary

| Step | Command | Raw output | Result |
|---|---|---|---|
| 1 vet | `go vet ./...` | `raw/01-vet.txt` | clean (exit 0) |
| 2 tests | `go test ./... -race -count=10 -shuffle=on -timeout 60m` | `raw/02-test-count10-full.txt` | exit 1. Shuffle seeds printed: `1790221595764090616`, `1790221597144029025` (one per failing package, edge and trunk). admin, app, config, media, shield, sip, sip/sdp: ok. edge: FAIL (all failures are the known `-count>1` port-window exhaustion). trunk: FAIL (4 tests, see P1-004..P1-006). |
| 2b | isolated re-runs `-run '^Name$' -count=1` x3, edge `-count=1 -shuffle=on` | `raw/02b-test-isolated-reruns.txt` | every failing trunk test passes alone 3/3; edge passes with `-count=1`. |
| 2c | trunk package `-count=1` (no shuffle and seed `1790221597144029025`), single test `-count=2` | `raw/02c-trunk-reruns.txt` | no-shuffle run: `TestBridgeEarlyMedia` fails ("media ports not released"); seeded run: ok. |
| 2d | per-package `-p 1`: other packages `-count=10 -shuffle=on`; trunk alone `-count=5 -shuffle=on` (seed `1790222459610835843`) | `raw/02d-per-package-p1.txt` | all non-edge/non-trunk packages ok x10. trunk alone: `TestBridgeDigestAuth` 3/5 (503), `TestBridgeCancelStopsFailover` 3/5, `TestBridgeEarlyMedia` 1/5. |
| 2e | trunk package `-count=1 -v` looped until `TestBridgeBrokenAnswerSDPGets502` failed | `raw/02e-broken-answer-repro.txt` | reproduced on iteration 2. |
| 2f | each flaky trunk test alone `-count=5` | `raw/02f-trunk-single-count5.txt` | all 5 tests pass 5/5 alone. |
| 3 lint | `golangci-lint run -c docs/audit/raw/.golangci.yml ./...` (v2.13.2; 14 linters, gocognit min 30, tests included) | `raw/03-golangci-lint.txt`, config `raw/.golangci.yml` | 426 issues: 73 in production files (contextcheck 18, errcheck 18, gocognit 11, staticcheck 8, forcetypeassert 7, gocritic 4, errorlint 3, exhaustive 3, wastedassign 1), 353 in `_test.go` (errcheck 270, forcetypeassert 67, gocognit 8, staticcheck 4, dupl 2, errorlint 1, exhaustive 1). No new dependencies; go.mod/go.sum untouched. |
| 4 deadcode | `deadcode ./...`, `deadcode -test ./...` | `raw/04-deadcode.txt`, `raw/04-deadcode-test.txt` | one function unreachable from `main` (`edge.Server.Ready`); nothing unreachable when tests count as roots. |
| 5 coverage | `go test -p 1 ./... -count=1 -coverprofile=...` then `go tool cover -func`; repeated with `-coverpkg=./...` | `raw/cover.out`, `raw/05-cover-func.txt`, `raw/05-cover-run.txt`; `raw/cover-pkgall.out`, `raw/05-cover-func-coverpkg-all.txt`, `raw/05-cover-run-coverpkg-all.txt` | per-package total 81.2%; cross-package total 83.8%. `internal/sip` is 9.9% on its own tests and is covered almost entirely by trunk/edge tests. The per-package run also hit `TestBridgeBrokenAnswerSDPGets502` (P1-006). |
| 6 architecture | `go list -f '{{.ImportPath}} {{.Imports}}'`, `go list -deps`, test imports | `raw/06-arch.txt` | all rules hold (details below). |
| 7 escapes | `go build -gcflags=-m ./internal/media/...` | `raw/07-escape-media.txt` | no per-packet heap escape in FreeSBC's own relay code; per-packet allocation happens inside pion SRTP (P1-011). |

## A.2 Step 6 architecture result (FACT, `raw/06-arch.txt`)
- Direct module-internal imports: `cmd/freesbc → app`; `app → admin, config, edge, media, trunk`; `trunk → config, media, shield, sip, sip/sdp`; `edge →` the same set; `admin → config`; `shield → config`; `config`, `media`, `sip`, `sip/sdp` → nothing.
- trunk does not import edge and edge does not import trunk (direct, transitive, and in test imports).
- sip and sip/sdp import no plane, media, shield, config, admin or app.
- Only `app` imports trunk, edge and admin. `app` also imports `media` directly, only for the `*media.PlanePool` parameter type of `adminDeps` (`internal/app/app.go:150`); CLAUDE.md's `cmd → app → {trunk, edge, admin}` is accurate as a direction rule, and `app → media` does not violate it.
- `shield → config` is consistent with design.md:116-117 ("config is the only package both planes and shield read").

## A.3 Step 7 per-packet path (FACT for the escape lines, `raw/07-escape-media.txt`)
Per-packet functions, identified by reading: `(*Session).forward` goroutine loop (`internal/media/relay.go:45-100`), `(*latch).accept`/`target` (`session.go:106-135`), `SRTPContext.protect*/unprotect*` (`srtp.go:115-140`), `(*WebRTCSession).publicToPrivate`/`privateToPublic` (`webrtcsession.go:183-261`), `demux.readLoop`/`classify` (`mux.go:33-105`), `counters.recordRx/recordTx` (`stats.go:35-50`).
- Escapes on those paths are once-per-goroutine or once-per-latch, not per packet: `make([]byte, 1500)` (`relay.go:47`), `make([]byte, 1508)` (`webrtcsession.go:185`, `:230`, `mux.go:80`), the goroutine closure (`relay.go:45`), and `&net.UDPAddr{...}` + `append` in `latch.accept` (`session.go:121-122`), which run only on the first accepted packet.
- `ReadFromUDP`'s internal `&net.UDPAddr{}` does not escape (`relay.go:49:33`, `webrtcsession.go:232:34`).
- Per-packet allocation that `-m` on this package cannot show: see P1-011.

## A.4 Dropped (false positives / not actionable)

Lint (production files):
- `wastedassign` `internal/trunk/b2bua.go:302` (`secureA := false`): every switch branch assigns it; the initializer is harmless.
- `gocritic exitAfterDefer` `cmd/freesbc/main.go:58`: the skipped `defer stop()` only unregisters signal handlers, and the process is exiting.
- `gocritic offBy1` `internal/config/expand.go:156`: guarded by `strings.Contains(stripped, "${")` at `:153`, so `Index` cannot be -1.
- `gocritic appendAssign` `internal/trunk/resolve.go:254`: `group = append(zeros, nonzeros...)` is the intended zero-weight-first reorder (RFC 2782).
- `gocritic ifElseChain` `internal/config/validate_proxy.go:176`: style only.
- `errorlint` `internal/admin/server.go:381`: `rec` is a `recover()` value compared with the `http.ErrAbortHandler` sentinel, which is the stdlib convention.
- `errorlint` `internal/edge/media.go:117,119`: `%w` wraps the proxy sentinel and `%v` deliberately flattens the inner error; `errors.Is` on the sentinel is what callers use.
- `exhaustive` `internal/edge/invite.go:597` (`failDial`): failDial intentionally sets no flag and falls to the 503 default at `:626-627`.
- `exhaustive` `internal/media/mux.go:90` (`muxUnknown`): handled by `default: continue` (RFC 7983 drop).
- `exhaustive` `internal/config/expand.go:59` (`reflect.Kind`): only string/struct/slice/map/ptr/interface carry `${VAR}`; other kinds are correctly ignored.
- `staticcheck` QF1001/QF1002/QF1008 (`sdp.go:461`, `invite.go:835`, `b2bua.go:1566`, `listenerlimit.go:70`): style quick-fixes.
- `forcetypeassert` x7: `LocalAddr().(*net.UDPAddr)` on `*net.UDPConn` (`portpool.go:29`, `webrtcleg.go:184,187`), `sync.Map` values that only ever hold `*atomic.Uint64`/`string` (`edge/metrics.go:50,152,156`), and a `singleflight` result that only ever holds `[]Endpoint` (`trunk/resolve.go:178`) — the type is fixed by construction.
- `errcheck` x18 on `Close()` (`admin/config_write.go:35,40`, `config/reload.go:28`, `edge/edge.go:174,185,189`, `media/mux.go:79`, `trunk/b2bua.go:284,379,407,1252`, `trunk/listenerlimit.go:46`, `trunk/server.go:187,197,232,356,385,397`): teardown or already-failing error paths where there is nothing to do with a close error; the success path of `writeFileAtomic` does check `tmp.Close()` (`config_write.go:44-47`).
- `contextcheck` x18 (`admin/server.go:164`, `app/app.go:121`, `edge/edge.go:156,188`, `edge/invite.go:682,685,748,783,809,843,1022,1042`, `edge/media.go:238`, `trunk/b2bua.go:1169`, `trunk/register.go:177,182`, `trunk/server.go:161,231`): detached contexts are deliberate — teardown ACK/BYE/CANCEL and un-REGISTER must outlive the cancelled request/shutdown context, and each site carries its own timeout (design.md §15.2). The one site with a real consequence is reported as P1-001.

Lint (test files): 353 issues (errcheck 270, forcetypeassert 67, gocognit 8, staticcheck SA1019 4 — covered by P1-007, dupl 2 at `b2bua_test.go:3904-3949`/`4387-4432`, errorlint 1, exhaustive 1): test idioms (unchecked `Close`, asserted types in fixtures, long table tests); none hides a defect.

Tests:
- 40+ edge failures in the count=10 run: all `rtp.*.port_*: must be 1024-65535` from the harness window overflow (P1-003); none reproduces with `-count=1`.
- `TestBridgePlacesCallAndBridges` 1/10 (`b2bua_test.go:943: media ports not released after teardown`): passes 3/3 alone; the documented "released late" timing class (CLAUDE.md), same mechanism as P1-005.
- `WARN UDP ref went negative on try close`: sipgo v1.4.3 log noise (CLAUDE.md).

Deadcode/escape:
- Escape lines on per-packet functions (`relay.go:45,47`, `webrtcsession.go:185,230`, `mux.go:80`, `session.go:121-122`): once per goroutine or once per latch, not per packet.

# Appendix B — Phase 0 citation check details

Citation check: 144 file:line citations checked (140 in design.md, 4 in CLAUDE.md): 101 match (B.3), 43 are stale line references with unchanged behaviour (PH0-006, B.1), 5 are behaviour or attribution mismatches (PH0-001 to PH0-005). 49 numeric constants all match the code (B.2).

## B.1 Stale line references only (behaviour matches)

The top of b2bua.go has shifted by about -4 to -8 lines. The middle section was restructured by the `dialAttempt` split, and the bottom section shifted by +33 to +68. trunk/register.go shifted by about -21, and edge/dialog.go and trunk/server.go by -1 to -2.

| # | Doc line | Cited | Actual location | Note |
|---|---|---|---|---|
| 1 | design.md:141 | server.go:285 | internal/trunk/server.go:284 | `NewRegistrar` |
| 2 | design.md:185 | server.go:291-303 | server.go:290-302 | listener goroutine loop |
| 3 | design.md:187 | server.go:287 | server.go:286 | `go registrar.Run` |
| 4 | design.md:276 | server.go:349-402 | server.go:348-401 | `bindListener` |
| 5 | design.md:586 | server.go:236-240 | server.go:235-239 | handler registration |
| 6 | design.md:2682 | server.go:467 | server.go:468 | `RecordUnidentified` call |
| 7 | design.md:322 | reload.go:21,26,30 | internal/config/reload.go:20,24,29 (calls); error returns at 22,26,30 | mixed: 21 is an `if`, 26/30 are returns |
| 8 | design.md:356 | admin/server.go:255-260 | internal/admin/server.go:252-257 | `adminAuth` |
| 9 | design.md:190 | b2bua.go:956 (in `dialTarget`) | internal/trunk/b2bua.go:1109 in `dialAttempt` | B-leg waiter goroutine |
| 10 | design.md:624 | b2bua.go:214-217 | b2bua.go:210-213 | 501 fallback on failed `tx.Respond`; 214-217 is now the non-refresh 501 |
| 11 | design.md:628 | b2bua.go:127-488 | b2bua.go:127-484 | `onInvite` |
| 12 | design.md:672 | b2bua.go:579-602 | b2bua.go:571-594 | `expandTargets` |
| 13 | design.md:685 | b2bua.go:580 | b2bua.go:572 | fresh snapshot |
| 14 | design.md:688 | b2bua.go:649-716 | b2bua.go:641-708 | `placeCall` |
| 15 | design.md:708 | b2bua.go:986-1004 | b2bua.go:1122-1159 (`dialAttempt`) | `OnResponse` callback |
| 16 | design.md:711 | b2bua.go:518-524 | b2bua.go:514-520 | `failKind` consts |
| 17 | design.md:714 | b2bua.go:1220-1233 | b2bua.go:910-923 | `errSRTPRequiredMismatch` retry |
| 18 | design.md:715 | b2bua.go:1238-1241 | b2bua.go:928-930 | 502 + ackThenBye |
| 19 | design.md:715 | b2bua.go:1268-1282 | b2bua.go:958-962 | 502 on A-answer rewrite failure |
| 20 | design.md:715 | b2bua.go:1307-1320 | b2bua.go:964-972 / 997-1010 | ACK failure / A-leg respond failure |
| 21 | design.md:762 | b2bua.go:1332 | b2bua.go:1366 | `carrierAnswered` |
| 22 | design.md:764 | b2bua.go:1015-1017 | b2bua.go:1168-1170 | waiter-side raced-2xx teardown |
| 23 | design.md:765 | b2bua.go:1144-1146 | b2bua.go:1295-1297 | unconditional teardown above switch |
| 24 | design.md:782 | b2bua.go:1303-1306 | b2bua.go:993-996 | `negotiateSE` call |
| 25 | design.md:800 | b2bua.go:1499-1507 | b2bua.go:1567-1568 | plaintext nil/nil (bsrtp==nil) |
| 26 | design.md:800-801 | b2bua.go:1534-1535, :1561 | b2bua.go:1594 (and 1561 is now the `processAnswerSDP` func line) | optional-downgrade nil/nil |
| 27 | design.md:847 | b2bua.go:1528-1567 | b2bua.go:1561-1600 | `processAnswerSDP` |
| 28 | design.md:951 | b2bua.go:404 | b2bua.go:400 | `state: callDialing` |
| 29 | design.md:975 | b2bua.go:471-487 | b2bua.go:467-483 | teardown select |
| 30 | design.md:976 | b2bua.go:495-502 | b2bua.go:491-498 | `byeBoth` |
| 31 | design.md:2202 | b2bua.go:398-405 | b2bua.go:394-401 | call literal |
| 32 | design.md:2202 | b2bua.go:466-467 | b2bua.go:462-463 | registerCall + defer endCall |
| 33 | design.md:874 | register.go:312-316 | internal/trunk/register.go:291-295 | register && auth filter |
| 34 | design.md:876 | register.go:418-423 | register.go:397-402 | `requestedExpires` (file is 402 lines) |
| 35 | design.md:903 | register.go:377-389 | register.go:356-368 | `stopAll` |
| 36 | design.md:2204 | register.go:309-372 | register.go:288-351 | `reconcile` |
| 37 | design.md:201 | dialog.go:341 | internal/edge/dialog.go:340-343 | media watcher goroutine |
| 38 | design.md:1256 | dialog.go:168-178 | dialog.go:167-177 | `begin` |
| 39 | design.md:1258 | dialog.go:321-345 | dialog.go:320-344 | `confirm` |
| 40 | design.md:1260 | dialog.go:350-357 | dialog.go:348-355 | `endUnlessUp` |
| 41 | design.md:1261 | dialog.go:366-398 | dialog.go:364-396 | `end` |
| 42 | design.md:1671 | dialog.go:338-344 | dialog.go:337-343 | watcher launch |
| 43 | design.md:1340 | invite.go:500-502 | internal/edge/invite.go:490 (PSTN `tx.OnCancel`) / :383 (client) | 500-502 is a comment in `inviteToPSTN`'s "CANCEL beat us" branch, not the hook |

## B.2 Numeric constants verified (all match)

| Constant | Code location | Value |
|---|---|---|
| Edge read cap | internal/edge/edge.go:461 | `maxMessageSize = 64 << 10` |
| UDP MTU | edge.go:96-97 | 8192, raised only if lower |
| bcrypt cost | internal/config/validate.go:279-285 | cost < 10 rejected |
| Reload debounce | internal/config/reload.go:13 | 200 ms |
| `rtp_timeout` default | internal/config/schema.go:284 | 5m |
| Port range default | schema.go:278 | 16384-32768 |
| Trunk defaults | schema.go:326-341 | ring_timeout 60s, register_expires 3600s, session_expires 1800s, min_se 90s, peer_cooldown 30s, srv_cache_ttl 300s |
| Shield defaults | schema.go:307-324 | 20/s, 200/s, 5, 60s, 1h, auto |
| Edge defaults | internal/config/proxy.go:366, :390, :393 | upstreams.cooldown 30s, pstn attempt 32s, pstn cooldown 30s |
| Default public binds | proxy.go:414-416 | 5060 / 5066 / 5061 |
| Trunk TCP limits | internal/trunk/server.go:116-117 | 1024 conns, 120s idle |
| Grace timer | internal/trunk/b2bua.go:1194 | 250 ms |
| `byeContext` | b2bua.go:505 | 5s |
| Quota Retry-After | b2bua.go:231 | 30 |
| Registrar timings | internal/trunk/register.go:127, :129, :133, :169, :192 | backoff 5s/60s, refresh floor 10s, 0.9×, un-REGISTER 2s |
| SRV timings | internal/trunk/resolve.go:23, :28 | lookup 3s, negative cache 10s |
| Edge timers | internal/edge/invite.go:23, :31, :807, :1061, :1512, :1273 | inviteTimeout 5m, pstnDrain 300ms, 5s CANCEL/ackThenBye, 32s in-dialog |
| `registerTimeout` | internal/edge/register.go:17 | 32s |
| `aorOf` caps | register.go:340, :344 | user 128, host 255 |
| Binding token | internal/sip/random.go:29 | 12 bytes |
| `fsbc` token cap | invite.go:1444 | 64 |
| Location caps | internal/edge/location.go:69-70 | 20000 / 10 |
| Prune ticker | internal/edge/edge.go:281 | 30s |
| `privateSources` | internal/edge/plane.go:42-43 | 10 min / 256 |
| Watchdog floor | internal/media/relay.go:105-107 | timeout/4, floor 10 ms |
| Relay buffer | relay.go:47 | 1500 |
| `maxPacketSize` | internal/media/mux.go:54 | 1508 |
| Demux buffers | mux.go:52-53 | 64 KiB / 1 MiB |
| WebRTC establish | internal/media/webrtcleg.go:237 | 30s |
| ICE credentials | webrtcleg.go:555 | 3 + 18 bytes |
| SRTP replay windows | internal/media/srtp.go:109-110 | 64 / 128 |
| `SDESKeyLen` | srtp.go:14 | 30 |
| SDP limits | internal/sip/sdp/sdp.go:45-53 | 16 KiB / 16 / 256 / 128 |
| ICE token length | sdp.go:411 | 4-256 |
| ICE-lite priority | internal/sip/sdp/build.go:176 | `126<<24 \| 65535<<8 \| 255` |
| Ban cap | internal/shield/banlist.go:14 | 65536 |
| Shield prune | internal/shield/shield.go:243 | 1 min |
| nft queue | internal/shield/nftables.go:22 | 256 |
| nft exec timeout | nftables.go:26 | 2s |
| Scanner signatures | internal/shield/scanner.go:11-23 | 11 |
| Admin limiter | internal/admin/server.go:293-295 | 10 / 1 min / 4096 |
| Admin HTTP timeouts | server.go:227-230 | 5/30/30/30s |
| Admin shutdown drain | server.go:162 | 5s |
| PUT body limit | internal/admin/config_write.go:59 | 1 MiB |
| Config file mode | config_write.go:113 | 0600 |
| TLS minimum | internal/sip/tls.go:72; internal/trunk/tlscert.go:23, :93; admin/server.go:156; edge/edge.go:382 | 1.2 |
| Self-signed certs | sip/tls.go:44-48; media/dtlscert.go:73-79 | P-256, -1h to +365d, trunk CN "FreeSBC self-signed" with no SANs, DTLS CN "FreeSBC" |
| Metric descriptors | internal/admin/metrics.go:47-72 | 23 |

One constant is not described in design.md: internal/shield/banlist.go:21 `sweepEvery = time.Second`. At the 65536 cap, a full sweep for expired entries runs at most once per second before a ban is refused. design.md:2214 and 2677-2679 do not mention it. This is an omission, not a contradiction.

## B.3 Citations that matched (101)

design.md:
- 23 app.go:69
- 24 proxy.go:271
- 28 app.go:85
- 106 sip/doc.go:1-12
- 120 edge.go:94-100
- 124 edge.go:90-93
- 136 app.go:53
- 137 app.go:55
- 139 app.go:68-71
- 140 app.go:77-83
- 144, 296 edge.go:249
- 146 edge.go:129
- 147 edge.go:123-124
- 151 app.go:120-122
- 173 app.go:91-129
- 176, 323 app.go:93-99
- 191 resolve.go:90
- 199 edge.go:251-263
- 200 edge.go:279-293
- 202 media.go:238
- 228 main.go:37
- 233 main.go:39
- 261 app.go:93-118
- 265 app.go:120-130
- 283 edge.go:204-263
- 308 reload.go:19-83
- 364 server.go:266-313 (approximately; the block is 265-318)
- 400 loader.go:31-43
- 423 validate_proxy.go:28-30
- 425 validate_proxy.go:41-43 and :266-292
- 459-461 schema.go:286-288, 289-291, 292-294 (3 citations)
- 464 validate.go:51-104
- 508 proxy.go:418-424 and validate_proxy.go:236
- 553 server.go:84-86 and :117-118
- 604 server.go:461-471 (function starts at 460)
- 608 server.go:448-452 and readfilter.go:22-33
- 621 timers.go:158-177
- 623 b2bua.go:206-213
- 782 timers.go:87-100
- 809 trunk sdp.go:17-21
- 953 calls.go:119
- 955 calls.go:134
- 1089 register.go:371
- 1092 register.go:263
- 1101 register.go:78
- 1112 register.go:200-202
- 1124 register.go:129-150
- 1127 invite.go:271
- 1159 register.go:261-286
- 1160 location.go:97-131
- 1161 location.go:48
- 1162 location.go:219
- 1164 location.go:153
- 1244 media.go:288, 389, 446, 546
- 1272 edge.go:152
- 1274 edge/metrics.go:67-68
- 1275 admin/metrics.go:57,129
- 1357 invite.go:1035-1043
- 1403 invite.go:1151
- 1421 invite.go:479
- 1424 topology.go:559-561
- 1478 invite.go:41-66
- 1479 invite.go:646-790
- 1480 invite.go:799-867
- 1482 invite.go:271-273
- 1490 invite.go:314, 322, 330, 350, 370, 1024
- 1500 relay.go:60-89
- 1566 relay.go:19-22
- 1569 session.go:325-336
- 1612 session.go:48-52
- 1613 session.go:91-102
- 1615 session.go:106-128
- 1617 session.go:68-74
- 1692 session.go:312-318
- 1723 webrtcleg.go:187-203
- 1724 webrtcleg.go:239
- 1726 webrtcleg.go:246-247 and :250
- 1727 webrtcleg.go:524 and :107-109
- 1791 mux.go:54
- 1822 sdp.go:410-422
- 1823 webrtcleg.go:554-560
- 1831 codecs.go:9-42
- 1834 sdp.go:8-10
- 1857 build.go:155-157 and edge/media.go:484
- 1895 media.go:379-405
- 1923 relay.go:91-93
- 1925 webrtcsession.go:242
- 2364 proxy.go:306-311
- 2368 proxy.go:342-347
- 2369 topology.go:325
- 2524 shield.go:109-118
- 2527 edge.go:517
- 2529 app.go:166-193
- 2570 redact.go:18-35
- 2631 app.go:146-150

CLAUDE.md:
- 47 design.md:337-345
- 48 validate_proxy.go:366-379
- 48 topology.go:126-134
- 49 validate_proxy.go:41-43
