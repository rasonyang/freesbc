# FreeSBC Remediation Task List (REMEDIATION-PLAN)

## 1. Baseline

- Generated: 2026-08-26
- HEAD: `b998f0883c363f4890f950f576d9de99d52c5630` (same commit as the audit; code unchanged)
- Working tree: `git status --short` shows only `?? docs/SECURITY-AUDIT-20260826.md` (the audit report) and this file; no production code changes
- Input report: `docs/SECURITY-AUDIT-20260826.md` (F-01…F-21 plus 28 Low / defense-in-depth / to-be-verified items)
- Review method: every finding was re-located at the current HEAD using Read/Grep (no Go toolchain on this machine, so the review is source-level; sipgo evidence was checked against the v1.4.3 sources pinned by go.sum)
- Rejection rate: 2/50 ≈ 4% (well under one third, so there is no systemic reliability problem with the original report)

## 2. Review Summary Table

Legend: ✅ = verified (task opened) | 🅿 = on hold | ❌ = rejected | ⊕ = merged (the fix is the same work as another task, so no separate card)

| Finding | Verdict | One-line rationale (evidence re-located in this review) |
|------|------|------|
| F-01 | ✅ | sipgo transport_udp.go:177-184 calls `pool.Add` for every new remote before parsing; sig/server.go:324-358 has no readFilter |
| F-02 | ✅ | sig/server.go:328-345 uses a bare Listen; sipgo parser_stream.go Write accumulates unconditionally and ignores partial input |
| F-03 | ✅ | shield/shield.go:81-86 runs the scanner ban ahead of the rate limit at :87-92; banlist.go:26-33 execs nft synchronously outside the lock |
| F-04 | ✅ | shield/nftables.go:62-63 has no dport qualifier on the rule; admin/server.go:63-75 has no unban route |
| F-05 | ✅ | shield/banlist.go:13-22 map has no cap, and prune(:60-69) only clears expired entries |
| F-06 | ✅ | sig/b2bua.go:276-286 allocates 2 port pairs on INVITE; media/portpool.go:54-84 has no per-peer quota; the schema has no max_calls field |
| F-07 | 🅿 | The finding holds (sig/identify.go:17-30 uses source IP only), but the fix — inbound digest/mTLS — is a new product capability; a product decision must define the expected behavior before a failing test can be written against existing code |
| F-08 | ✅ | sig/b2bua.go:127-151 only checks that a To-tag exists plus a Call-ID lookup (callsdp.go:67-72); From/To tags are never compared |
| F-09 | ✅ | media/srtp.go:52 CreateContext takes no options; srtp_relay_test.go:10-13 acknowledges no-replay in the repo itself |
| F-10 | ✅ | sipgo transaction_layer.go:214-226 sends a transaction-layer 400, :18-20 logs stray responses at Info, transport_udp.go:229 logs full bytes — none of it goes through the handler |
| F-11 | ✅ | sig/sdp.go:176-190 keeps every attribute except crypto/rtcp on relay sections (only declined sections at :198-200 are cleared) |
| F-12 | ✅ | sig/b2bua.go:1089-1103 buildFrom passes DisplayName/User through verbatim; routing.go:44-50 passes the number through unchanged when no match applies |
| F-13 | ✅ | sig/tlscert.go:21-54 always self-signs and has no certificate configuration fields; schema.go contains no tls_cert-style field anywhere |
| F-14 | ✅ | admin/server.go:102-105 runs bcrypt unconditionally (including for requests with no Authorization header); there is no failure rate limit |
| F-15 | ✅ | main.go:104,127 freezes the admin config at startup; admin/server.go:59,103-104 uses the stale credentials on every request (store.Replace exists, but admin never reads it) |
| F-16 | ✅ | config/validate.go:98-106 has no width or non-empty check (0.0.0.0/0 passes); parsePrefixOrAddr(:257-266) does not call Masked |
| F-17 | ✅ | sig/server.go:391-401 sourceAddr never calls Unmap (the only Unmap in the repo is media/session.go:82) |
| F-18 | ✅ | admin/config_write.go:64-79 sets only Content-Type and ETag; the admin package sets no Cache-Control at all |
| F-19 | ✅ | shield/shield.go:74-76 allows peers outright, bypassing the rate limit path |
| F-20 | ✅ | sig/register.go:~101 DoDigestAuth consumes the remote realm/nonce directly, with no pinning field (PeerAuth carries only Username/Password, schema.go:75-78) |
| F-21 | 🅿 | The finding holds, but A/AAAA resolution happens inside sipgo at send time (resolve.go only emits hostname endpoints, :71,99), so there is no observation point in this repo for an alert; the pinning configuration overlaps T-17 — reassess once T-17 lands |
| D1-8 | ✅ | sig/server.go:488-582 has four handlers with no recover; b2bua.go:127 nil-derefs on a missing To header (caught by recoverCall at :81, with no 400 sent) |
| D3-2 | ✅ | No admin response carries nosniff/CSP/XFO (server.go:63-75 and recoverMW :115-132 inject no headers) |
| D3-4 | ✅ | admin/server.go:80 sets only ReadHeaderTimeout (no Idle/Read/WriteTimeout, no connection cap) |
| D3-5 | 🅿 | The premise (no length limit on Call-ID) holds, but the impact ceiling is unproven; the attack surface shrinks once T-01 lands the pre-parse filter, so reassess then whether to open a task |
| D4-2 | 🅿 | The mechanism was verified against goccy v1.19.2 upstream sources (the BytesUnmarshaler path's formatAlias is unbounded), but reproducing the crash needs a Go environment to run the PoC — the red test cannot be confirmed FAIL on this machine |
| D4-3 | ✅ | admin/config_write.go:113-116 inherits the original file's Perm (0644 is preserved) |
| D4-4 | 🅿 | The TOCTOU window is real (config_write.go:97-117 takes no lock), but the assertion "one of two concurrent PUTs gets 409" depends on race timing, so no deterministic red test can be written; the serialization design must be settled first |
| D4-5 | ✅ | writeFileAtomic does not fsync the directory; :52 os.Rename replaces the symlink itself (os semantics; the code has no Lstat check) |
| D4-6 | ✅ | validate.go:167-170 silently accepts a non-loopback admin.listen; :174-176 sets no floor on bcrypt.Cost |
| D4-7 | ✅ | config/loader.go:11-17 reads the whole file with os.ReadFile and no cap (compare config_write.go:59, which enforces 1 MiB) |
| D4-8 | 🅿 | reload.go:57-59 `!ok → return nil` holds, but the trigger condition (the fsnotify Events channel closing other than via Close) cannot be injected in a test — it needs a refactor to expose an injection point |
| D5-3 | 🅿 | Holds (media/session.go:77-84 pre-latch compares IP only), but the fix — SSRC pre-learning or documentation — is a design trade-off requiring a product decision |
| D5-4 | ✅ | media/relay.go:45 refreshes lastRx before the unprotect at :50-60 |
| D5-7 | 🅿 | Holds (relay.go:28-33,72-74 passes RTCP through), but stripping or rewriting CNAME is optional hardening and needs an interop decision |
| D6-8 | ⊕ | The report already folds this into F-06 (no max_calls); covered by T-06 |
| D6-9 | ✅ | callstate/registry.go:28-32 Add overwrites on a duplicate ID; b2bua.go:303-327 keys all three tables on the bare Call-ID |
| D7-5 | ⊕ | The actionable fix for "shield sits at the handler layer" is the pre-parse readFilter — identical to F-01, so T-01 covers it (a separate card would duplicate the same test) |
| D7-6 | ✅ | shield/shield.go:26-47 fixes the nftables mode at construction time (the comment admits it) and never rebuilds the backend after Replace |
| D7-7 | ✅ | shield/nftables.go:56 setup unconditionally runs `delete table inet freesbc`, with no instance isolation |
| D7-8 | ✅ | shield/nftables.go:32 uses exec.LookPath("nft") with no path configuration field |
| D7-9 | ✅ | sig/server.go:419-421 dropUnidentified logs at Info on every request (compare the rate branch at shield.go:89, which uses Debug) |
| D7-10 | 🅿 | The fingerprint list is real (scanner.go:11-23 includes sipsak); downgrading to a counted ban is a policy decision |
| D7-11 | ✅ | config/types.go:132-135 puts no ceiling on rate ("1000000/s" is valid); validate.go:163-165 allows sub-second durations |
| D8-1 | ✅ | sig/resolve.go:46 the lookupSRV field takes no ctx; :76-105 has no deduplication and caches errors with the same TTL (the field is injectable, so a test can be written) |
| D8-2 | ✅ | sig/resolve.go:143-206 orderSRV does not filter Target "." or Port 0 (:198 TrimSuffix turns "." into an empty string) |
| D8-4 | ✅ | sig/resolve.go:99 and :111 always fall back to port 5060 (tls should be 5061, RFC 3263 §4.1) |
| D8-5 | ❌ | Not "the report is wrong" but not actionable as a task: CI/SBOM/signing are process work items with no failing test to write against this repo's code (track separately as an ops task) |
| D8-6 | 🅿 | A deployment/documentation work item (systemd example) with no failing code test; ship the docs alongside T-17 |
| D8-7 | ✅ | config/loader.go:11-17 does not check the file mode (the write path, config_write.go:113, already preserves 0600 or inherits) |
| D2-7 | ❌ | The report itself states "recorded for reference, no code change required" — there is no fix action, so there is no task |

## 3. Task Cards

> Common acceptance criteria (apply to every card and are not repeated inside them): the red test turns green, `go test ./... -race` is fully green, and `go vet ./...` reports no new warnings. Only the listed files may be changed. For cards that introduce new configuration field names (T-06/T-17/T-19/T-37), the field name is a design decision owned by that task; review may rename it, and the red test is updated accordingly.

### T-01 (F-01) SIP ingress pre-parse filter: drop non-peer source bytes before parsing
- Review conclusion: verified
- Current location: sig/server.go:166-169 (NewUA is not given a readFilter option); sipgo v1.4.3 transport_udp.go:177-184 (`pool.Add` runs before parseAndHandle but after readFilter, so the hook is usable)
- Current behavior: bytes from any source enter the sipgo parser and fill the connection pool without bound, one entry per unique source address; shield only intervenes at the handler layer
- Expected behavior: inject a filter via sipgo `WithTransportLayerReadFilter` so that UDP/TCP/TLS bytes whose source IP is in no peer.allowed_ips are dropped outright (return an empty slice) and never reach parsing, transactions, logs, or the connection pool
- Red test: sig/server_preparse_test.go :: TestPreParseFilterDropsNonPeerBytes :: listen on 127.0.0.2 with peer allowed_ips containing only 127.0.0.9, send a parseable request with no Via from 127.0.0.1 → assert the client receives no response bytes within 2s (today the sipgo transaction layer replies 400, so the test FAILs)
- Allowed changes: sig/server.go, new file sig/readfilter.go, sig/server_test.go (if the test wiring helpers need adjusting)
- Explicitly out of scope: no changes to the shield package; no per-IP rate limiting (that belongs to shield); no fix for peer source spoofing (F-07 is on hold)
- Symbols involved: sipgo.WithUserAgentTransportLayerOptions (ua.go:76), sip.WithTransportLayerReadFilter (sip/transport_layer.go:72), config.Peer.AllowsIP (config/schema.go:66), Server.store (sig/server.go:29)

### T-02 (F-04) Scope nft bans to SIP ports, keep single-packet UDP verdicts in memory only, add admin unban
- Review conclusion: verified
- Current location: shield/nftables.go:62-63 (the rule `ip saddr @banned4 drop` has no dport or protocol qualifier); shield.go:81-86 (a single scanner packet writes to the kernel); admin/server.go:63-75 (no unban route)
- Current behavior: any non-peer IP can be written into the kernel input chain as an all-protocol 1h blackhole, with no endpoint to lift it
- Expected behavior: (1) scope the kernel rule to the configured SIP listen ports and the udp/tcp protocols; (2) a single-packet verdict on UDP transport (scanner) writes only the in-memory ban table and does not touch nft (only a multi-packet auto-ban or a TCP/TLS source may sync to the kernel); (3) add DELETE /api/bans/{ip} (behind requireAuth) that clears both the in-memory table and the nft element
- Red test (primary): shield/nftables_test.go :: TestNFTBanRulesScopedToSIPPorts :: run setup() through the existing newTestNFT (nftables_test.go:18) → assert the rule argv contains a port qualifier (there is no dport today, so FAIL)
- Red test (secondary): shield/shield_test.go :: TestUDPScannerSinglePacketMemoryOnly :: Check a scanner UA once from a UDP source → assert no nft run was recorded (today an add element is issued, so FAIL)
- Allowed changes: shield/nftables.go, shield/shield.go (Check needs to know the transport type — the signature change is part of this task), shield/banlist.go, admin/server.go, admin/api.go
- Explicitly out of scope: no change to auto-ban threshold semantics; no flipping of the nftables default (a separate deployment-policy decision)
- Symbols involved: nftBackend.setup (nftables.go:53), nftBackend.ban (:75), Shield.Check (shield.go:72), withShield (sig/server.go:377 — the call site that will pass the transport type), the mux route table (admin/server.go:63-75)

### T-03 (F-05) Hard cap on banList
- Review conclusion: verified
- Current location: shield/banlist.go:13-22 (the until map has no cap), :60-69 (prune only deletes expired entries)
- Current behavior: a flood of unique sources accumulates entries without bound over the auto_ban.duration window (1h by default)
- Expected behavior: give the ban table a hard cap (a constant or a shield config field; 65536 suggested). On overflow, lazily prune expired entries first; if it is still full, refuse the insertion and expose a counter in Stats (the rate-limit Drop branch is unaffected)
- Red test: shield/banlist_test.go :: TestBanListCap :: with an injected fake clock (banList.now is replaceable), ban more unique IPs than the cap → assert len(until) ≤ cap and the overflow counter is > 0 (today it grows without bound, so FAIL)
- Allowed changes: shield/banlist.go, shield/shield.go (add the overflow counter to Stats), admin/metrics.go (expose the counter, optional)
- Explicitly out of scope: no prefix-aggregation fallback (a later optimization); do not touch the failCounter/ratelimit maps (the former is bounded by the ban short-circuit ahead of it, the latter is assessed under the T-04 scenario)
- Symbols involved: banList.until/ban/banned/prune (banlist.go:15,26,37,60), Shield.Stats (shield.go:103)

### T-04 (F-03) Move the scanner verdict after the rate limit, and serialize/bound the nft exec
- Review conclusion: verified
- Current location: shield/shield.go:81-86 (isScanner→ban runs before the rate limit at :87-92); shield/banlist.go:26-33 (synchronous exec outside the lock with no concurrency cap); shield/nftables.go:39-41 (exec.Command with no timeout)
- Current behavior: a UA-controlled instant ban signal bypasses the rate limit, and each unique source costs one fork+exec with no throttling
- Expected behavior: (1) move the scanner verdict inside Check to after limiter.allow; (2) change nftBackend to a single worker consuming a bounded queue serially (when full, drop the kernel sync and fall back to the in-memory ban); (3) switch exec to CommandContext (2s timeout suggested)
- Red test (primary): shield/shield_test.go :: TestScannerBanRespectsRateLimit :: from one IP, send rate+1 ordinary packets to exhaust the tokens, then send a scanner UA packet → assert no new ban was created (today it still bans, so FAIL)
- Red test (secondary): shield/nftables_test.go :: TestNFTExecBoundedAndSerialized :: trigger bans concurrently for 1000 unique IPs → assert the number of recorded runs ≤ the queue cap and that concurrency is 1 at all times (today there are 1000 synchronous execs, so FAIL)
- Allowed changes: shield/shield.go, shield/banlist.go, shield/nftables.go, shield/nftables_test.go
- Explicitly out of scope: no aggregation beyond same-IP deduplication; no change to the scanner fingerprint set (D7-10 is on hold)
- Symbols involved: Shield.Check (shield.go:72-94), isScanner (scanner.go:27), banList.ban (banlist.go:26), nftBackend.run (nftables.go:18,39)

### T-05 (F-02) SIP TCP/TLS: connection cap plus idle/read timeouts
- Review conclusion: verified
- Current location: sig/server.go:328-345 (a bare net.Listen/tls.Listen handed to sipgo); sipgo v1.4.3 transport_tcp.go:62-72 (accept has no cap), :135-143 (no read timeout), parser_stream.go Write/partial is unbounded
- Current behavior: both the connection count and the per-connection accumulated memory are unbounded, and slow-feed or silent connections are never reclaimed
- Expected behavior: wrap the listener — a global cap on concurrent connections (over the cap, Close the accepted conn immediately and continue the Accept loop; never return a nil conn to sipgo) — and refresh the read deadline before each per-connection Read (idle timeout, 120s suggested; the value can move into configuration later)
- Red test: sig/server_tcplimit_test.go :: TestTCPIdleTimeoutClosesConn :: connect to the TCP listener, send half a request line, then go silent → assert the server closes the connection within the idle timeout plus margin (today the connection is never closed, so the test times out and FAILs)
- Allowed changes: sig/server.go (bindListener), new file sig/listenerlimit.go, sig/server_test.go
- Explicitly out of scope: no changes inside sipgo (the streaming accumulation cap goes upstream); no per-IP connection limit (later)
- Symbols involved: Server.bindListener (sig/server.go:324), the tl.ServeTCP/ServeTLS call sites (:333,345)

### T-06 (F-06, includes D6-8) Per-peer concurrent-call and INVITE rate caps
- Review conclusion: verified
- Current location: sig/b2bua.go:276-286 (ports are allocated on INVITE with no admission control); media/portpool.go:54-84; config/schema.go (no max/limit field at all — confirmed by grep)
- Current behavior: a single peer source (which can be spoofed) can consume the entire port quota at ~70 INVITE/s and trigger real outbound traffic
- Expected behavior: add configuration `peers.<name>.max_concurrent_calls` (0 = unlimited) and a global `max_concurrent_calls`; the bridge checks the quota once Identify passes and replies 503 + Retry-After when over the cap; the quota is released when the call ends (including on failure paths)
- Red test (primary): config/schema_test.go :: TestPeerMaxConcurrentCallsParses :: YAML containing the new field passes Parse (today strict parsing rejects unknown keys, so FAIL)
- Red test (secondary): sig/b2bua_test.go :: TestPeerCallCapRejectsWith503 :: reuse the existing call test wiring (the session-setup pattern at b2bua_test.go:2033), set the peer cap to 1, and send a second INVITE → assert 503 (today it is accepted, so FAIL)
- Allowed changes: config/schema.go, config/validate.go, sig/b2bua.go, sig/server.go (if a global counter needs mounting)
- Explicitly out of scope: no deferred dialing until the A-leg ACK (an architectural change, handled separately); no change to when media ports are allocated
- Symbols involved: bridge.onInvite (b2bua.go:80), pool.Allocate (session.go:140), config.Peer (schema.go:43)

### T-07 (F-08) Add dialog validation (Call-ID + both tags) to refresh re-INVITE
- Review conclusion: verified
- Current location: sig/b2bua.go:127-151 (only checks that a To-tag exists plus a Call-ID lookup in callSDPStore); sig/callsdp.go:67-72; sig/timers.go:76-81
- Current behavior: any identified peer can retrieve that leg's 200 OK answer (including the SDES master key) with just the Call-ID and a matching compare SDP
- Expected behavior: the in-dialog branch validates that the request really belongs to that leg's dialog using the dialog ID (Call-ID + From-tag + To-tag, compared under UAS rules for the A leg and UAC rules for the B leg); on mismatch, reply 481. Record the dialog identity in callSDP when the leg is established
- Red test: sig/b2bua_test.go :: TestRefreshReInviteWrongTagsGet481 :: set up a call following the TestBridgeAnswersSessionTimerRefresh pattern (b2bua_test.go:2033), then from another allowed peer send a refresh INVITE with the same Call-ID and compare body but wrong From/To tags → assert 481 and that the response carries no SDP body (today it is 200 + answer, so FAIL)
- Allowed changes: sig/b2bua.go, sig/callsdp.go, sig/timers.go (if needed)
- Explicitly out of scope: no support for media-changing re-INVITE (keep 501); no change to the isRefreshReInvite comparison algorithm itself
- Symbols involved: bridge.onInvite (b2bua.go:127-151), callSDPStore.get (callsdp.go:67), isRefreshReInvite (timers.go:76), sip.DialogIDFromRequestUAS/UAC (sipgo sip/sip.go — existence confirmed in the sipgo sources; follow that version's API when implementing)

### T-08 (F-09) Enable SRTP/SRTCP replay protection
- Review conclusion: verified
- Current location: media/srtp.go:52 (srtp.CreateContext with no ContextOption); media/srtp_relay_test.go:10-13 (the comment acknowledges the default is no-replay)
- Current behavior: decrypting the same SRTP packet repeatedly succeeds every time (replay is allowed), violating RFC 3711 §3.3.2/§3.4.2
- Expected behavior: pass pion's SRTP/SRTCP replay-protection options to NewSRTPContext (window 64/128 suggested); a replayed packet fails unprotect and the relay drops it (the existing fail-closed path at relay.go:50-60 is unchanged)
- Red test: media/srtp_test.go :: TestSRTPReplayDropped :: unprotect the same ciphertext twice → assert the second call returns ok == false (today it returns true, so FAIL)
- Allowed changes: media/srtp.go, media/srtp_relay_test.go (the resend pump at pumpTransform :14 depends on no-replay and must be reworked to send once and then verify), media/srtp_test.go
- Explicitly out of scope: do not touch latch/SRTP context management (session.go SetSRTP); no change to suite support
- Symbols involved: NewSRTPContext (srtp.go:46), unprotectRTP/unprotectRTCP (srtp.go:68,82), pumpTransform (srtp_relay_test.go:14)

### T-09 (F-14, includes the admin side of D3-3/D2-4/D6-7) Harden admin authentication: failure rate limit plus skipping the KDF when no header is present
- Review conclusion: verified
- Current location: admin/server.go:102-105 (r.BasicAuth() reaches bcrypt unconditionally, including for requests with no Authorization header); :100-112 (no failure counter or rate limit)
- Current behavior: every unauthenticated request pays the full bcrypt cost, and there is no cap on failures (CPU DoS plus unlimited brute force)
- Expected behavior: (1) return 401 immediately without running bcrypt when the Authorization header is missing; (2) apply a per-IP failure rate limit (for example 10 per minute, replying 429 over the cap) whose state is bounded and periodically cleaned
- Red test (primary): admin/server_test.go :: TestAdminAuthFailureRateLimit :: send 11 wrong-password requests in a row from the same RemoteAddr → assert the 11th is 429 (today all are 401, so FAIL; the wiring from the existing TestAuthRequired :99 can be reused)
- Red test (secondary): admin/server_test.go :: TestRequireAuthSkipsKDFOnMissingHeader :: P99 latency for requests with no Authorization header is < 5 ms (against a bcrypt reference of 60 ms+; the threshold is generous to absorb jitter; FAILs today)
- Allowed changes: admin/server.go, admin/server_test.go
- Explicitly out of scope: no account lockout (single-administrator model); no session or CSRF tokens; TLS is covered by T-17
- Symbols involved: Server.requireAuth (server.go:100), recoverMW (:115), the http.Server configuration (:80 — IdleTimeout belongs to T-24 and is not touched here)

### T-10 (F-17) End-to-end IP normalization (Unmap)
- Review conclusion: verified
- Current location: sig/server.go:391-401 (sourceAddr does not Unmap; the only Unmap in the repo is media/session.go:82)
- Current behavior: a 4-in-6 source address fails to match v4 prefixes in all three places — identify, ban, and rate limit — causing fail-closed call rejection, duplicate ban keys, and mistaken writes into banned6
- Expected behavior: call .Unmap() at the sourceAddr exit; defensively Unmap at the shield.Check entry; when the nft ban picks a set, test Is4In6 for 4-in-6 addresses (belt and braces)
- Red test: sig/identify_test.go :: TestIdentifyPeerUnmaps4in6 :: with cfg.allowed_ips containing 203.0.113.0/24, call IdentifyPeer(cfg, ::ffff:203.0.113.7) → assert ok == true (today it is false, so FAIL; IdentifyPeer is already exported, identify.go:17)
- Allowed changes: sig/server.go, shield/shield.go, shield/nftables.go, sig/identify_test.go
- Explicitly out of scope: no change to config prefix parsing (validate.go:257-266); no listen-host validation (handled separately)
- Symbols involved: sourceAddr (server.go:391), Shield.Check (shield.go:72), IdentifyPeer (identify.go:17), netip.Addr.Unmap (standard library)

### T-11 (F-16) allowed_ips validation: non-empty, width ceiling, canonical prefixes
- Review conclusion: verified
- Current location: config/validate.go:98-106 (no non-empty, width, or canonicality check); :257-266 (no Masked)
- Current behavior: `allowed_ips: [0.0.0.0/0]` passes silently (combined with source-IP trust, that means toll fraud from any source); an empty list silently fails closed
- Expected behavior: validate rejects (1) an empty allowed_ips; (2) an overly wide prefix (suggested thresholds: error on IPv4 wider than /16 and IPv6 wider than /48, with a configurable override); (3) a non-canonical prefix (either store pfx.Masked() or error out — the implementation picks one and documents it)
- Red test: config/validate_test.go :: TestValidateRejectsWildcardPrefix :: YAML with allowed_ips=["0.0.0.0/0"] → assert Parse returns an error whose message contains "allowed_ips" (today it parses successfully, so FAIL)
- Allowed changes: config/validate.go, config/validate_test.go, config/schema.go (if a threshold field is needed)
- Explicitly out of scope: no peer-level allowlist stacking semantics; no change to IdentifyPeer matching logic
- Symbols involved: Config.validate (validate.go:21), parsePrefixOrAddr (:257), Peer.AllowedIPs (schema.go:48)

### T-12 (F-10) Handle stray responses silently (UnhandledResponseHandler)
- Review conclusion: verified
- Current location: sig/server.go:179 (sipgo.NewClient sets no UnhandledResponseHandler); sipgo transaction_layer.go:18-20 (the default logs every packet at Info)
- Current behavior: any source can send stray SIP responses, and each packet costs a goroutine plus an Info log line (an unauthenticated log flood)
- Expected behavior: set UnhandledResponseHandler on NewClient to count silently (optionally exposed as a metric) rather than logging per packet. Note: the full-byte parse-failure log and the transaction-layer 400 are contained by T-01's pre-parse filter; this task covers only the response path
- Red test: sig/server_test.go :: TestStrayResponseNotLoggedPerPacket :: capture slog output and send one stray response → assert no Info-level log is produced (today defaultUnhandledRespHandler logs Info per packet, so FAIL)
- Allowed changes: sig/server.go, sig/server_test.go
- Explicitly out of scope: no wrapping of sipgo transaction-layer logging (upstream); do not touch the 400 path (covered by T-01)
- Symbols involved: sipgo.NewClient (sig/server.go:179), the sipgo client options (follow the v1.4.3 API; existence confirmed)

### T-13 (F-12) Sanitize identity fields: reject bare LF and quote breaking
- Review conclusion: verified
- Current location: sig/b2bua.go:1089-1103 (buildFrom passes DisplayName/User through verbatim); :752-753 (outNumber → Request-URI user); routing.go:44-50
- Current behavior: the display name and user of the A-leg From, and the called number, can carry a bare \n and unpaired `"` straight into B-leg serialization (header injection against a lenient stack)
- Expected behavior: strip or reject CR/LF before writing buildFrom and the Request-URI user (stripping the characters is the suggested approach); additionally strip `"`, `<`, and `>` from the display name; validate the called number against a character allowlist (400 on mismatch)
- Red test: sig/b2bua_test.go :: TestBuildFromStripsLFAndQuotes :: build a request whose From display name contains "\nX-Evil: 1" and an embedded `"`, run it through buildFrom → assert the serialized From header contains no \n and has balanced quotes (today the bytes pass through verbatim, so FAIL)
- Allowed changes: sig/b2bua.go, sig/routing.go, sig/b2bua_test.go
- Explicitly out of scope: no full RFC 3261 quoted-string escaper (stripping is enough); do not touch sipgo serialization
- Symbols involved: bridge.buildFrom (b2bua.go:1089), the bTarget.User assignment site (:753), transformNumber (routing.go:44)

### T-14 (F-11, includes D5-5) Attribute allowlist for SDP relay sections
- Review conclusion: verified
- Current location: sig/sdp.go:176-190 (rewriteSDPCrypto keeps everything except crypto/rtcp on relay sections); :59-61 (o= only has its address changed)
- Current behavior: a=candidate, a=fingerprint, a=ice-*, and the o= session identifiers cross between legs (internal topology disclosure)
- Expected behavior: switch relay sections to an attribute allowlist (rtpmap/fmtp/ptime/maxptime/sendrecv/sendonly/recvonly/inactive and the direction attributes), dropping anything outside it; rewrite the o= username and sess-id to SBC-generated values (preserving version-increment semantics); declined-section behavior is unchanged (:198-200)
- Red test: sig/sdp_test.go :: TestRewriteDropsCandidateAndFingerprint :: run an offer containing a=candidate, a=fingerprint, and a=ice-ufrag through rewriteSDPCrypto → assert the output contains none of those attribute lines (today they pass through, so FAIL)
- Allowed changes: sig/sdp.go, sig/sdp_test.go
- Explicitly out of scope: no address-rewriting ICE support; do not touch crypto line handling (already correct)
- Symbols involved: rewriteSDPCrypto (sdp.go:149), rewriteSDP (:45), firstAudio (:222)

### T-15 (F-15) Hot-apply admin credentials and listen address
- Review conclusion: verified
- Current location: main.go:104,127 (frozen at startup); admin/server.go:59 (the cfg field is never updated), :103-104
- Current behavior: after a hot reload replaces password_hash, the old password keeps working until restart; removing the admin section does not shut down the admin API
- Expected behavior: requireAuth reads the Admin config from store.Current() on every request (the bcrypt cost is unchanged, so there is no extra cost); a change to the Run listen address still requires a restart (log a prominent WARN in that case and keep the old listener)
- Red test: admin/server_test.go :: TestAdminAuthHotReloadRevokesOldPassword :: after admin.New, call store.Replace with a new hash → assert a request with the old password returns 401 (today it is 200, so FAIL; store.Replace exists at config/store.go:29)
- Allowed changes: admin/server.go, admin/server_test.go, main.go (if a store reference must be passed — it already is)
- Explicitly out of scope: no hot restart of the listener; no multi-administrator support
- Symbols involved: Server.cfg (server.go:47), config.Store.Current/Replace (store.go:25,29), requireAuth (server.go:100)

### T-16 (F-18) Cache-Control: no-store on sensitive responses
- Review conclusion: verified
- Current location: admin/config_write.go:64-79 (/api/config/raw sets only Content-Type and ETag); admin/api.go:11-14 (writeJSON)
- Current behavior: the raw configuration, including plaintext credentials, can land in the browser's on-disk cache
- Expected behavior: recoverMW injects `Cache-Control: no-store` uniformly (/healthz may be exempt); existing ETag semantics are preserved
- Red test: admin/server_test.go :: TestSensitiveResponsesNoStore :: authenticated GET of /api/config/raw and /api/config → assert the response headers contain Cache-Control: no-store (missing today, so FAIL)
- Allowed changes: admin/server.go (recoverMW), admin/server_test.go
- Explicitly out of scope: no CSP or other headers (covered by T-25); do not touch the ETag/If-Match logic
- Symbols involved: recoverMW (server.go:115), handleConfigRaw (config_write.go:64), writeJSON (api.go:11)

### T-17 (F-13, includes D1-11) TLS credential configuration surface
- Review conclusion: verified
- Current location: sig/tlscert.go:21-54 (always self-signed; the comment admits there is no certificate configuration); sig/server.go:334-345 (always calls selfSignedTLSConfig); config/schema.go (no TLS fields at all)
- Current behavior: inbound TLS cannot be given a real certificate or mTLS; outbound has no way to configure a trust anchor (a self-signed carrier is unreachable); transport=tls raises no warning
- Expected behavior: add configuration — inbound `listen.tls_cert`/`listen.tls_key`/`listen.tls_client_ca` (mTLS optional; when unset, keep self-signing but log a WARN for tls listeners) and outbound `peers.<name>.tls_ca`/`tls_client_cert`/`tls_client_key`; set MinVersion=TLS1.2 explicitly
- Red test (primary): config/schema_test.go :: TestTLSConfigFieldsParse :: YAML containing the fields above passes Parse (today strict parsing rejects them, so FAIL)
- Red test (secondary): sig/server_test.go :: TestTLSListenerUsesConfiguredCert :: start a TLS listener with a configured certificate; a client (TLSClientConfig that does not skip verification, with RootCAs containing that certificate) completes the handshake and the peer certificate's CN is not "FreeSBC self-signed" (today the self-signed handshake fails verification, so FAIL)
- Allowed changes: config/schema.go, config/validate.go, sig/tlscert.go, sig/server.go, main.go (if needed)
- Explicitly out of scope: no DTLS/SRTP; no certificate hot rotation (restart-to-apply is acceptable, and this must be documented); pinning (the on-hold F-21) is not part of this task
- Symbols involved: selfSignedTLSConfig (tlscert.go:21), the tls branch of bindListener (server.go:334), SIPListen (config/types.go:76), Peer (schema.go:43)

### T-18 (F-19) Loose rate limit for peers (replacing the blanket exemption)
- Review conclusion: verified
- Current location: shield/shield.go:74-76 (isConfiguredPeer allows outright)
- Current behavior: peer sources are entirely exempt from rate limiting, so a flood from a spoofed peer IP has no rate ceiling (compounding F-06/D6-6 handled by T-06)
- Expected behavior: peer sources go through a loose rate limit (a separate high threshold, for example a configurable `shield.peer_rate_limit` defaulting to 200/s per_ip); Drop over the threshold
- Red test: shield/shield_test.go :: TestShieldCheckAppliesPeerRateLimit :: Check a peer IP repeatedly past the threshold → assert the return is Drop (today it always Allows, so FAIL)
- Allowed changes: shield/shield.go, shield/ratelimit.go, config (if a new field is added), shield/shield_test.go
- Explicitly out of scope: do not apply scanner/ban logic to peers (keep the exemption semantics); no per-peer threshold matrix
- Symbols involved: Shield.Check (shield.go:72), rateLimiter.allow (ratelimit.go:33), isConfiguredPeer (shield.go:167)

### T-19 (F-20) Pin the digest realm
- Review conclusion: verified
- Current location: sig/register.go:~101 (DoDigestAuth consumes the remote challenge directly); config/schema.go:75-78 (PeerAuth carries only Username/Password)
- Current behavior: realm, nonce, and algorithm are entirely controlled by the remote end, and a challenge can name any realm
- Expected behavior: add an optional `realm` field to PeerAuth; when set, do not compute a digest response for a 401/407 challenge on REGISTER/INVITE whose realm does not match (treat it as an authentication failure)
- Red test (primary): config/schema_test.go :: TestPeerAuthRealmParses :: the auth.realm field passes Parse (rejected today, so FAIL)
- Red test (secondary): sig/register_test.go :: TestRegisterRejectsUnexpectedRealm :: a fake registrar (the existing test-stub pattern; register_test.go already has a fake server) returns realm="evil" → assert no retry carrying Authorization is sent (today it responds unconditionally, so FAIL)
- Allowed changes: config/schema.go, sig/register.go, sig/b2bua.go (the WaitAnswer credential path, if needed), sig/register_test.go
- Explicitly out of scope: no enforced algorithm allowlist (later); no change to qop handling (internal to sipgo)
- Symbols involved: PeerAuth (schema.go:75), the DoDigestAuth call in registerOnce (register.go:~96-105), sipgo.DigestAuth (v1.4.3)

### T-20 (D1-8) Panic recovery on every SIP handler plus mandatory header validation
- Review conclusion: verified
- Current location: sig/server.go:488-582 (onOptions/onAck/onBye/onNoRoute have no recover); b2bua.go:127 (nil-deref on a missing To header, today swallowed silently by the recover at :81 with no 400 sent)
- Current behavior: a panic in any handler other than onInvite (or in the sipgo dialog code it calls) exits the process; an INVITE missing To or From is dropped silently with no 400
- Expected behavior: (1) a single deferred recover in withShield (log at Error and make a best-effort 500); (2) onInvite explicitly validates that From, To, and Call-ID are present and replies 400 when one is missing
- Red test: sig/b2bua_test.go :: TestInviteMissingToGets400 :: send an INVITE with no To header from a peer source → assert a 400 is received (today there is no response at all, so FAIL)
- Allowed changes: sig/server.go, sig/b2bua.go, sig/b2bua_test.go
- Explicitly out of scope: no recover added to the sipgo transaction layer (upstream); no hand-written validation in each handler (do it once at the entry point)
- Symbols involved: withShield (server.go:377), recoverCall (b2bua.go:1341), onInvite (b2bua.go:80)

### T-21 (D7-9) Downgrade the dropUnidentified log level
- Review conclusion: verified
- Current location: sig/server.go:419-421 (one Info line per request)
- Current behavior: a flood from unidentified sources produces one Info line per packet (on the order of 260 GB/day at 20k lines/s)
- Expected behavior: downgrade to Debug plus periodic aggregation (for example one count summary per minute, hung off the existing pruneLoop or its own ticker); the shield.Scan counter is retained
- Red test: sig/server_test.go :: TestDropUnidentifiedNotInfoPerPacket :: capture slog and send one unidentified request → assert there is no Info-level "dropping request from unidentified source" (today it is Info, so FAIL)
- Allowed changes: sig/server.go, sig/server_test.go
- Explicitly out of scope: do not remove the log (keep Debug plus aggregation); do not touch shield-side logging (T-04 covers Warn sampling as part of its work)
- Symbols involved: dropUnidentified (server.go:418), the RecordUnidentified call site (:424-428)

### T-22 (D5-4) The watchdog refreshes lastRx only after SRTP authentication passes
- Review conclusion: verified
- Current location: media/relay.go:45 (lastRx.Store runs before the unprotect at :50-60)
- Current behavior: anyone who knows the latched address can keep renewing rtp_timeout indefinitely with garbage packets
- Expected behavior: refresh lastRx only after unprotect succeeds (when SRTP is configured) or the plaintext path accepts the packet; garbage packets no longer reset the watchdog
- Red test: media/relay_test.go :: TestWatchdogIgnolesUnauthKeepalive :: a session with a short timeout (for example 80 ms) and SRTP wired on SideA, sending a garbage packet every 20 ms from the already-latched address → assert Done() closes within 3× the timeout (today it is renewed indefinitely, so FAIL; the timing margin is already generous)
- Allowed changes: media/relay.go, media/relay_test.go
- Explicitly out of scope: no change to the watchdog interval algorithm; no per-packet logging
- Symbols involved: Session.lastRx (read and written at relay.go:45), forward (relay.go:27), watchdog (relay.go:81)

### T-23 (D6-9, includes D1-9/D2-6) Reject duplicate Call-ID calls (482)
- Review conclusion: verified
- Current location: callstate/registry.go:28-32 (Add overwrites); sig/b2bua.go:303-327 (killers/registry/sdps all key on the same value, so entries overwrite and are wrongly deleted)
- Current behavior: a concurrent second call with the same Call-ID overwrites entries in all three tables, and whichever call ends first deletes the other's killer, leaving the survivor impossible for an administrator to disconnect
- Expected behavior: before registerKiller, onInvite detects that a call with the same Call-ID is already registered and rejects the second one with 482 Loop Detected (rejecting rather than moving to a composite key is the smallest change and is semantically correct)
- Red test: sig/b2bua_test.go :: TestDuplicateCallIDSecondInviteGets482 :: establish call A (with a known Call-ID), then send another INVITE with the same Call-ID from the same source → assert 482 (today it proceeds through the normal call flow, so FAIL)
- Allowed changes: sig/b2bua.go, callstate/registry.go (if an Exists query is needed), sig/b2bua_test.go
- Explicitly out of scope: no change to the key structure of the three tables; no Call-ID format validation (D3-5 is on hold)
- Symbols involved: the registration block of bridge.onInvite (b2bua.go:303-327), Registry.Add/Remove (registry.go:28,35), registerKiller (server.go:98)

### T-24 (D3-4) Complete the admin http.Server timeouts
- Review conclusion: verified
- Current location: admin/server.go:80 (only ReadHeaderTimeout=5s)
- Current behavior: idle keep-alive connections are never reclaimed and there is no connection cap (an army hitting the unauthenticated /healthz can exhaust fds and goroutines)
- Expected behavior: add IdleTimeout (30s suggested), ReadTimeout (30s suggested, allowing enough time for a 1 MiB PUT), and WriteTimeout (30s suggested); /healthz stays unauthenticated
- Red test: admin/server_test.go :: TestAdminIdleTimeoutClosesConn :: connect to admin over raw TCP, send one complete request, then go silent → assert the server closes the connection within IdleTimeout plus margin (today it is never closed, so FAIL)
- Allowed changes: admin/server.go, admin/server_test.go
- Explicitly out of scope: no connection cap (it can be added later; it is not the minimum fix for this finding); do not change /healthz semantics
- Symbols involved: the http.Server in Server.Run (server.go:80)

### T-25 (D3-2) Baseline security response headers
- Review conclusion: verified
- Current location: admin/server.go:115-132 (recoverMW is the only uniform injection point and currently sets no security headers)
- Current behavior: HTML/JSON/YAML responses carry no nosniff/CSP/XFO/Referrer-Policy
- Expected behavior: recoverMW injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`; `/` (webui.go:14) additionally gets a minimal CSP (default-src 'self', with inline scripts handled either by a nonce or by a transitional script-src 'unsafe-inline' given the current index.html — the implementation picks one and documents the trade-off)
- Red test: admin/server_test.go :: TestSecurityHeadersPresent :: authenticated GET of / and /api/config/raw → assert nosniff and XFO are present (missing today, so FAIL)
- Allowed changes: admin/server.go, admin/webui_test.go (if needed), admin/server_test.go
- Explicitly out of scope: no HSTS (there is no TLS yet; revisit after T-17); no WebUI refactor to remove inline scripts
- Symbols involved: recoverMW (server.go:115), handleUI (webui.go:14)

### T-26 (D4-6) Validate the admin listen address and the bcrypt cost
- Review conclusion: verified
- Current location: config/validate.go:167-170 (non-loopback passes silently), :174-176 (no floor on bcrypt.Cost)
- Current behavior: 0.0.0.0:8080 with plaintext Basic auth passes silently; a cost-4 hash is accepted (roughly 50× cheaper to brute force)
- Expected behavior: (1) reject a non-loopback admin.listen by default and add an explicit `admin.allow_remote: true` opt-in (the validation error message should recommend TLS when opting in); (2) reject a bcrypt cost below 10
- Red test (primary): config/validate_test.go :: TestValidateRejectsNonLoopbackAdmin :: admin.listen=0.0.0.0:8080 with no allow_remote → assert Parse errors (today it passes, so FAIL)
- Red test (secondary): config/validate_test.go :: TestValidateRejectsLowBcryptCost :: a cost-4 hash → assert an error (today it passes, so FAIL)
- Allowed changes: config/validate.go, config/schema.go, config/validate_test.go
- Explicitly out of scope: no admin TLS (T-17); no runtime listen warning (catching it at validation is enough)
- Symbols involved: AdminConfig (schema.go:115), the admin section of validate (validate.go:167-176), bcrypt.Cost (x/crypto)

### T-27 (D7-11) Validate shield parameter ceilings
- Review conclusion: verified
- Current location: config/types.go:132-135 (no ceiling on the rate value); config/validate.go:163-165 (sub-second durations are allowed, so the nft timeout truncates to "0s")
- Current behavior: `rate_limit: "1000000/s per_ip"` is valid (amplifying failCounter memory); a 500 ms ban duration turns the kernel timeout into 0s
- Expected behavior: validate on top of ParseRateLimit that rate ≤ a ceiling (1000 suggested); require auto_ban.duration ≥ 1s (or round the nft timeout up to whole seconds)
- Red test (primary): config/types_test.go :: TestParseRateLimitCapOrValidateRejectsHuge :: a full config containing "1000000/s per_ip" → assert Parse errors (today it passes, so FAIL)
- Red test (secondary): config/validate_test.go :: TestAutoBanDurationAtLeastOneSecond :: duration=500ms → assert an error (today it passes, so FAIL)
- Allowed changes: config/types.go, config/validate.go, the corresponding _test.go files
- Explicitly out of scope: do not touch the ratelimit.go algorithm; no restructuring of failCounter (T-03 already caps it)
- Symbols involved: ParseRateLimit (types.go:116), the AutoBan validation block (validate.go:160-165)

### T-28 (D8-1) DNS resolution timeout, singleflight, and short-lived negative caching
- Review conclusion: verified
- Current location: sig/resolve.go:46 (the lookupSRV field takes no ctx), :76-105 (concurrent direct lookups outside the lock with no deduplication; errors and empty results are cached with the same TTL at :103)
- Current behavior: slow DNS blocks a goroutine per call; the instant a cache entry expires, N concurrent callers cause N lookups; a transient failure is negatively cached for the full 300s
- Expected behavior: lookupSRV uses a context-aware query (WithTimeout, 2-3s suggested); concurrent lookups for the same host are deduplicated (x/sync/singleflight is already an indirect dependency); failures and empty results are cached separately with a short TTL (5-10s suggested)
- Red test (primary): sig/resolve_test.go :: TestResolveHonorsTimeout :: inject a stub lookupSRV (the field is injectable, resolve.go:46) that sleeps 300 ms → assert Resolve returns the fallback endpoint within 200 ms (today it blocks for 300 ms, so FAIL)
- Red test (secondary): sig/resolve_test.go :: TestResolveSingleflight :: 10 concurrent Resolve calls for the same host against a counting stub → assert the stub was called once (today it is 10, so FAIL)
- Allowed changes: sig/resolve.go, sig/resolve_test.go, go.mod (promoting singleflight to a direct dependency — needs review sign-off; go.sum semantics are unchanged)
- Explicitly out of scope: no DNSSEC; no custom resolver Dial; do not touch the health cooldown
- Symbols involved: Resolver.lookupSRV/now (resolve.go:46-47), resolveSRV (:76), srv_cache_ttl (schema.go:28)

### T-29 (D8-2) Semantic filtering of SRV records
- Review conclusion: verified
- Current location: sig/resolve.go:143-206 (orderSRV does no filtering; :198 turns Target "." into an empty string and :199 accepts Port as-is)
- Current behavior: Target "." (RFC 2782: service unavailable) and port-0 records produce bad endpoints that enter the failover chain
- Expected behavior: orderSRV (or its caller) skips records with Target == "." or Port == 0; if nothing remains after filtering, fall back as if there were no SRV records
- Red test: sig/resolve_test.go :: TestResolveSkipsNullTargetAndPortZero :: the stub returns [".":5060, "a.example.":0, "ok.example.":5061] → assert the endpoint list contains only ok.example.:5061 (today it includes the empty-Host and port-0 entries, so FAIL)
- Allowed changes: sig/resolve.go, sig/resolve_test.go
- Explicitly out of scope: no port range validation (1-65535 is reported by the dial layer); no weight correction
- Symbols involved: orderSRV (resolve.go:143), Endpoint (:19), resolveSRV (:76)

### T-30 (D8-4) Fall back to port 5061 for tls transport
- Review conclusion: verified
- Current location: sig/resolve.go:99 (the missing/failed-SRV fallback is {Port:5060} regardless of transport), :111 (classifyAddress defaults to 5060)
- Current behavior: a peer with transport=tls and no SRV record is dialed at host:5060 over TLS (RFC 3263 §4.1 says the sips fallback should be 5061), so the call fails on the wrong port
- Expected behavior: map both the fallback and the default port by transport: tls → 5061, udp/tcp → 5060
- Red test: sig/resolve_test.go :: TestTLSPeerFallsBackTo5061 :: peer{address:"host.example", transport:"tls"} with a stub returning no SRV → assert the endpoint Port == 5061 (today it is 5060, so FAIL)
- Allowed changes: sig/resolve.go, sig/resolve_test.go, sig/register.go:390 (fix the 5060 default in splitHostPortDefault at the same time)
- Explicitly out of scope: no configurable port mapping; do not touch SRV ordering
- Symbols involved: the resolveSRV fallback (resolve.go:98-99), classifyAddress (:110), splitHostPortDefault (register.go — existence confirmed)

### T-31 (D4-7) Size cap on Load
- Review conclusion: verified
- Current location: config/loader.go:11-17 (os.ReadFile reads the whole file with no cap; compare the 1 MiB limit at config_write.go:59)
- Current behavior: if the configuration path is swapped for a huge file, the whole thing is read into memory (a local threat surface)
- Expected behavior: Load uses io.LimitReader (suggested to match the PUT limit at 1 MiB + 1 and error out beyond it)
- Red test: config/loader_test.go :: TestLoadRejectsOversizedFile :: write a temporary file larger than 1 MiB → assert Load returns an error (today it reads normally, so FAIL)
- Allowed changes: config/loader.go, config/loader_test.go
- Explicitly out of scope: no permission check (T-32); do not touch Parse
- Symbols involved: Load (loader.go:11), maxConfigBytes (admin/config_write.go:59 — if the constant is reused it must move to a shared location; the implementation decides)

### T-32 (D8-7) Configuration file permission check
- Review conclusion: verified
- Current location: config/loader.go:11-17 (does not check the mode; on the write side, config_write.go:113-117 preserves 0644 → 0644 by inheritance, which T-33 handles)
- Current behavior: an sbc.yaml copied with `cp` at 0644 that contains a plaintext password is world-readable, and loading it produces no warning at all
- Expected behavior: when the file mode has the group or other read bit set and the configuration contains credential fields, Load returns a clear error suggesting chmod 600 — fail-closed (more testable and safer than a warning; if review prefers a warning, Load first needs a logging channel, which is a separate decision)
- Red test: config/loader_test.go :: TestLoadRejectsWorldReadableConfigWithSecrets :: a 0644 file containing auth.password → assert Load errors; the same content at 0600 → assert success (today 0644 also succeeds, so FAIL)
- Allowed changes: config/loader.go, config/loader_test.go
- Explicitly out of scope: no automatic chmod; no owner check
- Symbols involved: Load (loader.go:11), PeerAuth.Password (schema.go:77)

### T-33 (D4-3) Tighten permissions on the written-back file
- Review conclusion: verified
- Current location: admin/config_write.go:113-116 (Stat follows the symlink, takes the target mode, and inherits it)
- Current behavior: an original file at 0644 stays 0644 after write-back (readable by local users when it contains plaintext credentials)
- Expected behavior: the write-back target is always 0600 (permissive bits are no longer inherited; if the original mode is stricter, keep the stricter one)
- Red test: admin/config_write_test.go :: TestConfigWriteResultMode0600 :: PUT against a preexisting 0644 configuration file → assert Perm() == 0600 after write-back (today it is 0644, so FAIL; the existing test at :274-298 locks in the inheritance behavior and must be updated — an expected change)
- Allowed changes: admin/config_write.go, admin/config_write_test.go
- Explicitly out of scope: no recursive directory permission changes; no Lstat (symlinks are covered by T-34)
- Symbols involved: handleConfigWrite (config_write.go:86), writeFileAtomic (:26), the os.Chmod call (:48)

### T-34 (D4-5) Refuse to write through symlinks, and fsync the directory
- Review conclusion: verified
- Current location: admin/config_write.go:26-57 (writeFileAtomic: no Lstat check, no directory fsync after rename)
- Current behavior: when cfgPath is a symlink, a PUT replaces the link with a regular file (silently changing the deployment layout); after a crash the rename may be lost (durability)
- Expected behavior: Lstat before writing to detect a symlink and refuse (409, stating that symlinked deployments are unsupported); fsync the directory after a successful rename
- Red test: admin/config_write_test.go :: TestConfigWriteRefusesSymlinkPath :: PUT against an sbc.yaml → real.yaml symlink → assert 409 and that neither the link nor the target was replaced (today the link is replaced by a regular file, so FAIL)
- Allowed changes: admin/config_write.go, admin/config_write_test.go
- Explicitly out of scope: no standalone assertion for the directory fsync (there is no reliable failure injection); it is an implementation requirement accepted through code review
- Symbols involved: writeFileAtomic (config_write.go:26), os.Rename (:52), os.CreateTemp (:28)

### T-35 (D7-6) Make the nftables mode take effect on hot reload
- Review conclusion: verified
- Current location: shield/shield.go:26-47 (the nft backend is fixed at construction time; the comment admits it); config.Store.Replace exists, but shield does not subscribe
- Current behavior: after an on/auto → off hot reload, bans still reach the kernel; off → on silently has no effect
- Expected behavior: shield subscribes to Store changes (store.Subscribe, store.go:45) and rebuilds or tears down the backend when the nftables mode changes (teardown = close plus clearing elements; setup = setup); on failure, fall back to memory and log at Error
- Red test: shield/shield_test.go :: TestNFTablesModeHotReloadStopsKernelWrites :: build a Shield in memory (constructible directly from the same package) with a recording backend attached, call store.Replace(nftables:"off"), then trigger a ban → assert no nft call was made (today it still calls, so FAIL)
- Allowed changes: shield/shield.go, shield/nftables.go, shield/shield_test.go
- Explicitly out of scope: no per-element migration (a mode change means a full rebuild); Listen changes are not handled
- Symbols involved: Shield.New/Close (shield.go:51,129), Store.Subscribe (store.go:45), newNFTBackend (nftables.go:28)

### T-36 (D7-7) Instance isolation for the nft table
- Review conclusion: verified
- Current location: shield/nftables.go:56 (setup unconditionally runs `delete table inet freesbc`), :57-64 (fixed table name)
- Current behavior: two instances in the same netns delete each other's table; an operator's table with the same name is deleted; a partially failed setup leaves residue
- Expected behavior: include an instance component in the table name (for example `freesbc-<instance id>`) or probe for a creator marker before setup; close deletes only its own table; a failed setup rolls back the objects it created
- Red test: shield/nftables_test.go :: TestNFTSetupDoesNotBlindDeleteSharedTable :: run setup through newTestNFT → assert the delete in the argv targets only this instance's table name (today it deletes `inet freesbc` unconditionally, so FAIL)
- Allowed changes: shield/nftables.go, shield/nftables_test.go
- Explicitly out of scope: no cross-netns coordination; no migration of tables left under the old name (the first run cleans up after itself, and this must be documented)
- Symbols involved: nftBackend.setup/close (nftables.go:53,88), newTestNFT (nftables_test.go:18)

### T-37 (D7-8) Make the nft binary path configurable
- Review conclusion: verified
- Current location: shield/nftables.go:32 (exec.LookPath("nft") with no configuration)
- Current behavior: the binary location depends on the process PATH (a root process plus a writable PATH directory is a local hijack surface)
- Expected behavior: add `shield.nftables_path` (defaulting to /usr/sbin/nft, or empty to keep the LookPath behavior with a WARN); validate owner and permissions at startup
- Red test: config/schema_test.go :: TestShieldNftablesPathParses :: YAML containing shield.nftables_path passes Parse (today strict parsing rejects it, so FAIL)
- Allowed changes: config/schema.go, config/validate.go, shield/nftables.go, shield/nftables_test.go
- Explicitly out of scope: no signature verification; no setuid handling
- Symbols involved: newNFTBackend (nftables.go:28), exec.LookPath (:32), ShieldConfig (schema.go:103)

## 4. Rejected List

| ID | Why it does not hold / cannot be opened as a task | Locations checked |
|------|---------------------|------------|
| D8-5 (supply chain: CI/SBOM/signing) | Not "the report is wrong" but not actionable: the work item is new CI configuration and a release process, and there is no test assertion against existing code that would FAIL today. Track it as a separate ops task (report §9.18 already covers it) | find across the repo shows no Makefile/CI/Dockerfile (confirmed in review); README.md:30 uses a bare go build |
| D2-7 (SSRF-by-config) | The report classifies it itself as "recorded for reference, no code change required" (verbatim from the report's domain-two section): outbound targets can only be changed by local configuration, an authenticated PUT, or DNS, so there is no unauthenticated reachable path and no fix action to define | sig/register.go:389-397, sig/resolve.go:64-105, sig/b2bua.go:752-758 |

## 5. On-Hold List

| ID | What is missing before a verdict is possible |
|------|----------------|
| F-07 (source IP as identity) | A product decision on whether to implement an inbound digest challenge or mTLS (a new capability; the schema and challenge flow must be defined before a red test can be written). Deployment-side mitigation (tcp/tls only plus uRPF) is an operations documentation item |
| F-21 (DNS trust chain) | There is no implementable observation point: A/AAAA resolution happens inside sipgo at send time (resolve.go:71,99 only produces hostname endpoints), so this repo has nowhere to hook a "resolved to a private address" alert; the pinning configuration overlaps T-17 — reassess the remainder once T-17 lands |
| D4-2 (goccy alias bomb) | Confirmation that the crash reproduces by running the PoC in a Go environment (the mechanism was already verified against goccy v1.19.2 upstream sources); once confirmed, a task can be opened (red test: parsing a self-referential alias YAML must return an error rather than crash) |
| D4-4 (PUT TOCTOU) | A serialization design decision (server-level mutex vs. mandatory If-Match); race timing makes a deterministic red test impossible, so open the task as "exactly one of two concurrent PUTs gets 409" once the design is settled |
| D4-8 (silent watcher death) | reload.go must be refactored to expose an fsnotify injection point (an abnormal close of Events cannot be triggered from outside), or the trigger path must be reproduced in a Go environment |
| D3-5 (unbounded Call-ID) | The impact ceiling is unproven (the report itself rates the preconditions as demanding); once T-01 lands, non-peer sources are already dropped ahead of parsing, so reassess the residual attack surface then |
| D5-3 (strict arming on IP only) | A design trade-off (SSRC pre-learning vs. NAT compatibility) requiring a product decision; the documentation portion is a documentation work item |
| D5-7 (RTCP CNAME pass-through) | The interop impact of stripping or rewriting CNAME needs carrier-side verification; this is optional hardening |
| D7-10 (sipsak false positives) | A policy decision: whether dual-use tools should be downgraded to a counted ban, and whether fingerprinting should be disableable per peer |
| D8-6 (running as root / dropping privileges) | A deployment documentation work item (a systemd AmbientCapabilities example) with no failing code test; ship it with the T-17 documentation |

## 6. Execution Order and Dependencies

**Tier one (blockers for internet-facing deployment; do these first)**: T-01 → T-03 → T-04 → T-02 → T-05 → T-06
- T-01 comes first: the pre-parse filter removes the main trigger surface for both F-01 and F-10 and substantially narrows the attack entry for T-02 and T-04.
- T-04 → T-02 in that order: both modify Shield.Check (T-02 adds a transport-type parameter to Check), so land T-04's reordering and queue first and T-02's per-transport ban policy second, avoiding two conflicting refactors of the same function.
- T-02/T-35/T-36/T-37 touch the same file (shield/nftables.go): merge them in batches in the order T-02 → T-36 → T-37 → T-35.
- T-06 and T-18 (tier two) together cover the flood surface of F-06/F-19; T-06 goes first (a quota is more direct than a rate limit where the port pool is concerned).

**Tier two (authentication and cross-tenant isolation)**: T-07 → T-08 → T-09 → T-15 → T-26
- T-07 takes priority over all media plane work: it is a key-disclosure entry point. T-08 requires reworking the pumpTransform test pump at the same time (srtp_relay_test.go:14).

**Tier three (injection, disclosure, configuration surface)**: T-10 → T-11 → T-13 → T-14 → T-12 → T-16 → T-17 → T-19
- T-12 depends on T-01 landing first (its red test observation point is only stable afterwards); T-17 should come before T-19 (establish the schema convention first).

**Tier four (the Low list, parallelizable)**: T-20…T-37 have no interdependencies. The only ordering constraint is that T-30 shares a file with T-28/T-29 (sig/resolve.go), so batch them together, and T-33 shares a file with T-34 (config_write.go), so batch those together as well.

---

**37 tasks opened / 2 rejected / 10 on hold (plus 2 findings whose fixes are the same work as T-01/T-06 and were merged into them, for 51 findings in total). The rejection rate is 4%, so there is no systemic reliability problem with the original report.**

> Review erratum: the Low summary count of "28 items" in §3 of the audit report omits D4-7 (Load has no file size cap — present in the domain-four detail but not counted in the summary table); the actual Low count is 30 ("D7-11+D8-4" on one of the 28 rows is two items). This plan works from the full domain-level detail, and both items have tasks opened (T-27/T-30/T-31).
