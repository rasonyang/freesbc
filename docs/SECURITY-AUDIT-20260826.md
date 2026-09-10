# FreeSBC In-Depth Security Code Review for Internet-Facing Deployment

- Review date: 2026-08-26
- Branch reviewed: `master`
- HEAD commit: `b998f0883c363f4890f950f576d9de99d52c5630` (`chore: ignore local .superpowers/ tooling state`, 2026-07-20)
- Working tree state: clean (`git status --short` produced no output)
- Reviewer: Go / VoIP security audit (automated + manual verification)
- Repository rule files: CLAUDE.md / AGENTS.md / SECURITY.md / CONTRIBUTING.md / .claude/ are all **absent**, so there are no rule conflicts; docs/superpowers/ contains development planning documents (not security rules).
- Authorization: the repository owner authorized this review. Read-only review plus local verification; no production code was modified.

> Structure: §1-§3 are the final conclusions (Phase F consolidated version); §4 (starting from "Phase A baseline") is the process record and the per-domain detailed evidence (embedded in the order the subagents finished, not in numeric order); §5-§10 cover defense in depth, command records, coverage, evidence gaps, the remediation plan, and the test checklist.

---

# Final Report (Phase F Consolidated)

## 1. Executive Summary

FreeSBC (master @ b998f088, 17,320 lines of Go including tests) received a full security review aimed at internet-facing deployment: eight domains reviewed in depth in parallel, plus line-by-line re-verification of every High finding by the main agent and derivation of cross-module exploitation chains. sipgo v1.4.3 and pion/sdp v3.0.19 sources were downloaded from their official tags and checked locally line by line (evidence is reproducible and kept in /tmp/freesbc-audit/). No Go toolchain is present on this machine, so all build/test/scan commands are recorded faithfully as skipped (see §6); every conclusion is a source-level static verification.

**Overall assessment**: this codebase is engineered well above the level typical of an early-stage open-source SBC. The configuration surface (strict YAML, ${ENV} discipline, atomic write-back, fail-closed hot reload), the handling of cryptographic material (SDES key lifecycle, crypto/rand, no cross-leg reuse), the B2BUA resource reclamation paths (every error path verified leak-free), and header-level topology hiding (zero header copying) all show solid implementation and test discipline. Several high-value attack chains were ruled out with evidence (XSS, CSRF, CRLF injection, request smuggling, cross-call BYE hijacking, redaction leakage, nft command injection).

**However, the product is not yet safe to deploy on the public internet.** The problems cluster into two structural themes:

1. **Unauthenticated resource-exhaustion surface (F-01/02/03/05, four purely unauthenticated vectors, plus F-06 peer source-port exhaustion)**: the protection plane (shield) sits at the handler layer, while the sipgo transport and transaction layers contain several unbounded resource-consumption points that occur before, or entirely bypass, the shield. The UDP connection pool grows without bound per unique source (ahead of every protection), the TCP stream parse buffer is unbounded, and scanner-UA-triggered bans happen before rate limiting (one nft fork/exec per packet, an unbounded ban table, and a flood of Warn logs). Any one of these vectors is enough for an unauthenticated attacker to OOM the process or drag down the media plane running inside it.
2. **Trust and ban decisions are bound to the UDP source address (systemic)**: peer identity = source IP (spoofing over UDP yields full peer trust, hence toll fraud), and the ban target is the claimed source IP (a single spoofed packet puts any third-party IP, including the system DNS resolver, into a kernel-level all-protocol 1h blackhole with no way to lift it). The default configuration (udp://0.0.0.0:5060 + nftables:auto) is the worst-case combination on both counts.

There are also 14 Medium findings, including a cross-tenant isolation defect (refresh re-INVITE with no dialog validation lets an attacker probe out the other leg's SDES master key), SRTP replay protection not enabled (an RFC 3711 MUST violation, acknowledged in the repository's own tests), and a missing TLS credential surface (inbound is always self-signed, outbound has no configurable trust anchor).

**Confirmed vulnerability count: 7 High, 14 Medium, 28 Low / defense-in-depth / unverified** (see the summary table in §3 and the per-domain evidence in §4).

## 2. Release Decision

### **Block internet-facing deployment (current state)**

Until the "immediate" remediation items (§9) are complete and verified, FreeSBC should not be exposed to untrusted networks either directly or indirectly (relying on the default shield alone). The core blocking reasons: six remote DoS / service-interruption vectors (F-01-F-06, of which F-01/02/03/05 are fully unauthenticated, F-04 requires only UDP source spoofing, and F-06 requires a peer source IP), plus spoofed-source bans that can kernel-blackhole any third-party IP (including the host's own DNS resolver), plus forgeable peer identity over UDP (toll fraud, F-07).

### Preconditions for conditional deployment (all must be met before release can be assessed)

1. **Signaling plane**: expose only tcp/tls listeners to the internet (or an upstream ACL allowlist plus uRPF); alternatively, enable digest challenge for inbound INVITEs.
2. **Resource plane**: fix F-01/F-02/F-03/F-05 (pre-filtering or pool caps, TCP connection limits plus timeouts, ban-path throttling and caps).
3. **Ban plane**: downgrade single-packet UDP decisions to in-memory bans only; scope nft rules to SIP ports; provide unban; make nftables off by default (explicit opt-in).
4. **Admin plane**: bind to loopback only (or add TLS/a reverse proxy plus failure rate limiting plus a loud startup warning for non-loopback binds).
5. **Media plane (if SRTP is enabled)**: enable replay protection (F-09) plus a verifiable signaling channel (F-13: real certificates must be configurable).
6. **Runtime environment**: run as non-root with CAP_NET_BIND_SERVICE[+CAP_NET_ADMIN] (see the systemd sample suggested in D8-6); configuration file mode 0600.
7. Multi-tenant scenarios (several mutually untrusting peers): F-08 must be fixed first.

## 3. Findings Summary (by severity; F-xx are the post-merge IDs, detailed evidence in the corresponding domain section of §4)

### High (7 findings, all remotely reachable; 4 of them fully unauthenticated, F-04 requires only UDP source spoofing, F-06/F-07 require a peer source IP)

| ID | Merged from | Title | Attacker | One-line impact | Confidence |
|------|--------|------|--------|------------|--------|
| F-01 | D6-1+D1-12 | sipgo UDP connection pool grows unbounded per unique source (before parsing, before shield) | Unauthenticated (an IPv6 /64 needs no spoofing) | 10k pps x 1h ~ 4-6GB never released -> OOM, all calls dropped | High |
| F-02 | D1-3+D6-5 | SIP TCP/TLS: no connection cap, no read/idle timeout, unbounded stream buffer accumulation | Unauthenticated | fd/goroutine exhaustion + 1:1 memory per connection -> reliable OOM | High |
| F-03 | D7-1+D6-2+D1-6+D6-10 | scanner-UA ban runs before rate limiting: unthrottled nft fork/exec storm | Unauthenticated (unique sources) | thousands of concurrent nft processes -> CPU/PID/memory exhaustion + Warn log flooding | High |
| F-04 | D7-2+D1-6 | Spoofed-source UDP ban injection: any third-party IP put into a kernel-level all-protocol 1h blackhole | UDP spoofing required (1 packet/hour) | blackhole the system DNS resolver -> all outbound resolution times out -> routing collapse; no way to lift it | Med-High |
| F-05 | D7-3+D6-3 | banList has no capacity cap (prune only removes expired entries) | Unauthenticated (unique sources + scanner UA) | tens of millions of entries in a 1h window -> several GB -> OOM | High |
| F-06 | D1-1+D5-6/X3 | Unauthenticated INVITE -> media port pool exhaustion + real carrier outdials | peer source IP (blind UDP spoofing possible) | legitimate calls get 503 + **toll fraud** (B-leg ACKs first; blind spoofing yields ~32s-5m of billable call time) + self-loop amplification | High |
| F-07 | D1-2+D2-1 | SIP identity = source IP with no challenge: spoofing a source IP over UDP grants full peer trust | UDP spoofing or a malicious peer | toll fraud (via outbound routing) + complete rate-limit exemption; TCP/TLS unaffected | High |

### Medium (14 findings)

| ID | Merged from | Title | One-line impact |
|------|--------|------|------------|
| F-08 | D5-2+X1+D1-10 | Refresh re-INVITE matched on Call-ID alone, with no dialog tag validation | A malicious or compromised peer can probe out the other leg's 200 OK answer (**including the SDES master key**), then combine it with sniffing or UDP spoofing to decrypt and inject media; treat as High in multi-tenant deployments |
| F-09 | D5-1 | SRTP/SRTCP replay protection not enabled (pion defaults to no-replay; the repository's own tests acknowledge it) | Violates an RFC 3711 MUST; on-path replay of valid media injection |
| F-10 | D6-4+D1-7 | Transaction-layer shield blind spot: one goroutine plus one Info log per stray response, full-byte Error logging of parse failures, unsolicited 400 responses to malformed requests | Unauthenticated log flooding (disk exhaustion) + breaks the "silent for unknown sources" promise + 1:1 reflection probing |
| F-11 | D1-4+D5-5 | SDP relay sections pass through a=candidate/fingerprint/ice-*/o= session identifiers | Internal topology leaks across the SBC (the topology-hiding promise is not met) + ICE endpoint interoperability failures |
| F-12 | D1-5 | Bare-LF header injection: From DisplayName/User and Request-URI user pass through unsanitized | Against lenient SIP stacks this means injecting arbitrary trailing lines toward the carrier (header injection / smuggling); CR/CRLF already ruled out |
| F-13 | D2-3+D1-11+X2 | Missing TLS credential surface: inbound is always self-signed (no certificate/mTLS configuration) and outbound has no configurable trust anchor | Active MITM can read or swap SDES keys; carriers with self-signed certificates are forced back to cleartext; real impact is High when SRTP is enabled |
| F-14 | D3-3+D2-4+D6-7 | Admin: cleartext Basic auth, no failure rate limiting, and full bcrypt executed even without an Authorization header | High when exposed: sniffing -> /api/config/raw returns every SIP credential in cleartext -> a complete toll-fraud chain; unauthenticated CPU-DoS amplified by sharing the process |
| F-15 | D4-1 | Admin credentials and listener do not take effect on hot reload | After a password rotation the old password stays valid until restart (revocation gap) |
| F-16 | D2-2 | allowed_ips has no width, non-empty, or canonicality validation (0.0.0.0/0 is accepted) | A misconfiguration immediately opens a toll-fraud relay (compounds F-07) |
| F-17 | D7-4 | IP normalization (Unmap) missing throughout; bans land in banned6 and never match | Fail-closed call drops on dual-stack listeners + silent kernel ban failure + duplicate table entries |
| F-18 | D3-1 | Sensitive admin responses lack Cache-Control: no-store | The raw configuration, including cleartext credentials, persists in the browser disk cache |
| F-19 | D6-6 | Peer rate-limit exemption + TerminateGracefully blocking up to 32s | Spoofed peer-source INVITE flood -> 1.6 million concurrent goroutines -> tens of GB |
| F-20 | D2-5 | Outbound digest challenge parameters are entirely remote-controlled; captured Authorization headers allow offline dictionary attacks | Passwords for non-tls peers can be cracked by a passive capture; without qop, REGISTER can be replayed |
| F-21 | D8-3 | No hardening of the DNS trust chain (no DNSSEC, no pinning, no address-class warnings) | Peer domain takeover -> B-leg redirection -> harvesting of digest responses and SDES keys (tls peers can be bypassed with a CA-issued certificate; no pinning) |

### Low / defense in depth / unverified hypotheses (28 findings, detailed evidence in the domain sections)

**Confirmed Low (11)**: D1-8 (onOptions/onAck/onBye/onNoRoute have no panic recovery; nil-deref evidence for missing To/From headers); D3-4 (/healthz keep-alive army); D4-3 (PUT inherits 0644 permissions); D4-5 (no directory fsync; a symlink is replaced by rename); D4-8 (fsnotify dies silently); D5-4 (the watchdog refreshes lastRx before authentication, so rtp_timeout can be extended indefinitely); D6-9+D1-9+D2-6 (Call-ID-keyed collisions across three maps -> kick fails, listings become inaccurate); D7-6 (nft mode changes do not take effect on hot reload); D7-7 (nft tables have no instance isolation and delete each other); D7-9 (dropUnidentified logs at Info per packet); D8-1 (DNS has no timeout, no singleflight, and negative caching for the full TTL).

**Defense in depth (12)**: D3-2 (no CSP/nosniff/XFO); D5-3 (strict arms on IP only, with no SSRC/PT validation); D5-7 (RTCP passes CNAME through in cleartext); D6-8 -> merged into F-06 (no max_calls); D7-5 (shield sits at the handler layer); D7-8 (nft resolved via PATH); D7-10 (legitimate tools such as sipsak get caught for 1h); D8-5 (no CI/SBOM/signing; CVE conclusions need govulncheck corroboration); D8-6 (no privilege dropping; root-level capabilities are actually required); D8-7 (configuration file permissions are not checked); D2-7 (SSRF-by-config); D4-4 (PUT TOCTOU).

**Configuration risk (2)**: D4-6 (0.0.0.0 admin bind + no minimum bcrypt cost); D7-11+D8-4 (no upper bound on rate, sub-1s bans truncate to "0s", tls fallback always uses 5060).

**Unverified hypotheses (3)**: D4-2 (goccy alias bomb -> fatal stack overflow / OOM; the mechanism is source-verified but not demonstrated at runtime); D8-2 (SRV "." and port 0 endpoints, shown to be bounded and non-panicking); D3-5 (unbounded Call-ID reaching /api/calls).

## 4. Process Record and Detailed Per-Domain Findings

> This section contains: Phase A/B/E process records -> detailed evidence for domains three, five, seven, four, six, eight, one -> Phase D data flows -> detailed evidence for domain two (embedded in the order the subagents finished). The D-series IDs are the merge sources listed in the §3 summary table. Each finding is presented in the Section 4 format (severity / confidence / type / CWE / line numbers / chain / impact / fix / regression), with Low items condensed to key points (full text in /tmp/freesbc-audit/domain-*-notes.md).

### Phase A Baseline

(See the metadata block at the top of this report: branch / HEAD / working tree / date.)

## Phase B - Architecture and Trust Boundary Model

### Module Structure (17,320 lines of Go, including tests)

```
main.go        entry point orchestration (run/check)
config/        YAML parsing (Loader/Parse), ${ENV} expansion, validation, Store (atomic.Pointer), fsnotify hot reload
sig/           sipgo assembly (UDP/TCP/TLS), identify (source IP -> peer), bridge (B2BUA), routing, SDP rewriting,
               register (outbound REGISTER + digest), resolve (DNS SRV), health (endpoint cooldown), timers (RFC 4028),
               tlscert (self-signed TLS), crypto (SDES)
media/         portpool (RTP port pool), relay (UDP forwarding + latching), session, srtp (pion SRTP <-> RTP)
shield/        ratelimit (per-IP token bucket), scanner (UA fingerprinting), banlist (in-memory bans + nftables integration), shield (assembly)
admin/         server (Basic Auth middleware), api (JSON status), config_write (PUT /api/config atomic write-back),
               metrics (private Prometheus registry), webui (embedded SPA), redact
callstate/     in-memory call registry
```

### External Entry Point Inventory

| # | Entry point | Protocol/port | Binding source | Authentication | First parse point | Rate limited before parsing? |
|---|------|-----------|----------|------|------------|--------------|
| E1 | SIP UDP | UDP `listen.sip` (default/example `udp://0.0.0.0:5060`) | Configuration file | Source IP in peer.allowed_ips (`sig/server.go:363` identify; the trust boundary is the transport-layer Source(), not Via/From) | sipgo transport layer parses the complete SIP message -> `withShield` -> handler (`sig/server.go:377`) | **No**: rate limiting happens at the handler entry (shield.Check), but full sipgo parsing happens **before** it |
| E2 | SIP TCP | TCP, same as above | Same as above | Same as above | Same as above (`bindListener` -> `tl.ServeTCP`, `sig/server.go:328`) | No (same as above) |
| E3 | SIP TLS | TLS `tls://...:5061` | Same as above | Same as above, plus TLS (**always self-signed**, `sig/tlscert.go:21`, no certificate configuration option) | Same as above (`sig/server.go:335`) | No (same as above) |
| E4 | RTP/RTCP | UDP `listen.media.port_range` (example 16384-32768) | Configuration file | None (first-packet latching + strict/loose) | `media/relay.go` RTP header parsing | No (the media plane has no shield) |
| E5 | Admin HTTP | HTTP `admin.listen` (example comment 127.0.0.1:8080, **can be set to 0.0.0.0**, no TLS) | Configuration file | bcrypt Basic Auth (`admin/server.go:100`); **`/healthz` is unauthenticated** (`admin/server.go:65`) | net/http (ReadHeaderTimeout=5s, `admin/server.go:80`; no Read/Write/IdleTimeout, no custom MaxHeaderBytes) | No (bcrypt at ~50-100ms per attempt is itself a brute-force slowdown) |
| E6 | Configuration file | Local file + fsnotify | CLI `-c` | None (local file permissions) | `config/loader.go` (goccy/go-yaml) | No |
| E7 | nftables | Local exec | `shield.nftables` mode (auto/on/off) | None (external command) | `shield/nftables.go` | - |
| E8 | Outbound DNS | UDP/TCP 53 -> net.Resolver | peer.address | - | `sig/resolve.go` (SRV + A/AAAA, cached for srv_cache_ttl) | - |
| E9 | Outbound SIP | UDP/TCP/TLS -> peer endpoint | peers[].address | digest (401/407 challenge) | `sig/register.go` / `sig/b2bua.go` (the digest client is sipgo's own DoDigestAuth/WaitAnswer; icholy/digest is test-only; sig/crypto.go is SDES and unrelated to digest, corrected by domain two) | - |

### Trust Boundary Conclusions

1. **The SIP plane (E1-E3) identifies peers purely by source IP**: matching `allowed_ips` grants every inbound-call privilege of that peer (there is no SIP-level digest challenge). `IdentifyPeer` (`sig/identify.go:17`) takes the first match in lexicographic order. The normalization inside `AllowsIP` (IPv4-mapped IPv6 and similar) is the critical validation point.
2. **The shield sits at the handler layer, not the transport layer** (`sig/server.go:377-386`): sipgo has already completed full SIP parsing and transaction creation before `shield.Check` is called. Parsing cost is not protected by rate limiting (a domain one/six review point).
3. **The admin plane (E5) serves everything on one port**: the WebUI (`/`), `/metrics`, and `/api/*` (including PUT /api/config atomic write-back and DELETE /api/calls/{id}), all behind the same Basic Auth, with `/healthz` as the exception. The write-back path `admin/config_write.go` enforces a 1 MiB limit and If-Match optimistic concurrency.
4. **The media plane (E4) has no application-layer rate limiting**; its security depends on latching semantics (strict is the default: the first packet must come from the SDP signaling IP; relatching is authorized only by the SIP state machine, and the `Relatch` call sites are the core of the call-hijacking review).
5. **TLS is always self-signed** (`sig/server.go:335` + `sig/tlscert.go`): the signaling plane's TLS offers no peer verifiability, so the confidentiality of SDES keys rests on a channel that is not protected by authentication (a cross-analysis focus).
6. The configuration is the single source of truth: a local unprivileged user who can write the configuration file fully controls the SBC (expected, but check the default file permissions and the permission inheritance in the write-back path, `admin/config_write.go:113-116`).

## Phase E - Verification Commands and Actual Results

Executed in `/home/rason/freesbc` on 2026-08-26, with the following results (**all recorded faithfully**):

| Command | Actual output | Conclusion |
|------|----------|------|
| `go build ./...` | `go: command not found` (exit 127) | **Skipped: no Go toolchain installed on this machine** (neither PATH nor a full-disk search found go/gofmt; no /usr/local/go, no snap, no dpkg golang) |
| `go vet ./...` | Same as above (exit 127) | Skipped, same reason |
| `go test ./...` | Same as above (exit 127) | Skipped, same reason |
| `go test ./... -race` | Same as above (exit 127) | Skipped, same reason |
| `govulncheck ./...` | `govulncheck: command not found` (exit 127) | Skipped: not installed, and installation was out of scope |
| `gosec ./...` | `gosec: command not found` (exit 127) | Skipped: not installed, and installation was out of scope |

Additional environment facts: no `GOMODCACHE` (~/go/pkg/mod does not exist) and no vendor/ directory in the repository, so third-party dependency sources were **initially unreadable**. (Correction: domains one and six subsequently downloaded the official tag sources for sipgo v1.4.3 and pion/sdp v3.0.19 into local copies under /tmp/freesbc-audit/, so from that point on every sipgo/pion-sdp internal conclusion is based on line-by-line checks of real source; see the head of the domain six section. goccy/go-yaml and pion/srtp were verified against upstream source by the corresponding subagents and marked [source-verified].)

### Fuzz Coverage Check (the part verifiable locally)

`grep -rn "func Fuzz" --include='*.go' .` -> **zero matches**: the repository currently has no Go fuzz targets.

## Domain Three Findings (subagent report + main agent review)

> Method: purely static (no Go toolchain). Every file under admin/, including all 522 lines of webui/index.html, was read line by line. The main agent personally re-verified D3-3's unconditional bcrypt execution (admin/server.go:102-105) and D3-1's missing response headers (config_write.go:64-79).

### [D3-1] Sensitive admin responses lack Cache-Control: no-store (the raw configuration can persist in the browser disk cache)
- Severity: Medium / Confidence: High / Type: confirmed vulnerability / CWE-525
- Affected files and line numbers: admin/config_write.go:64-79 (/api/config/raw sets only Content-Type and ETag); admin/api.go:11-14,62-64; admin/webui.go:14-22 (counter-evidence: every Header().Set in the admin package sets only Content-Type/ETag/Allow/WWW-Authenticate, and Cache-Control appears nowhere in the repository)
- Source -> sink: os.ReadFile(cfgPath) (config_write.go:70) -> unredacted original emitted directly (:78, which may contain literal cleartext trunk passwords) -> served with an ETag and no cache headers -> persisted in the browser disk cache; Basic Auth has no logout.
- Impact: the complete configuration (including cleartext passwords, if the operator did not use ${ENV}) stays resident in the disk cache and can be read by anyone who later uses the same system account.
- Fix: have recoverMW inject Cache-Control: no-store uniformly. Regression test: assert that every sensitive route carries no-store.

### [D3-3] No rate limiting or lockout on authentication, and bcrypt runs even without an Authorization header, giving unauthenticated CPU-DoS and unlimited online brute force
- Severity: Medium / Confidence: High / Type: confirmed vulnerability (precondition: admin.listen bound to a non-loopback address; the example comments out admin and states "bind PRIVATE") / CWE-307 (+CWE-770)
- Affected files and line numbers: admin/server.go:100-112 (no counting, delay, or banning); server.go:104 (bcrypt runs unconditionally, so even a request with no Authorization header executes a full bcrypt); server.go:80 (no connection cap); config/validate.go:174-176 (only requires a valid bcrypt hash, with no minimum cost, so cost 4 is accepted)
- Attack chain: the shield covers SIP only (its sole call site is sig/server.go:381) and admin 401s never trigger a ban -> every unauthenticated request costs one bcrypt (cost 10 ~ 60-130ms per attempt, per published figures) -> 10-16 concurrent requests saturate a core, in the same process as the SIP and media planes (main.go:90-135); the online brute-force rate is limited only by CPU, with no failure lockout; there is no TLS option (schema.go:115-123), so credentials can be intercepted in transit when bound to the internet.
- Fix: add per-IP rate limiting to 401s and feed admin failures into the shield; return 401 immediately when the Authorization header is missing, skipping bcrypt; enforce a minimum cost; support and document admin TLS.
- Main agent review: admin/server.go:102-105 confirmed that both userOK and passOK are computed unconditionally. Verified.

### [D3-4] http.Server sets no Read/Write/Idle timeouts and no connection cap (partially mitigated; one confirmed low-severity vector)
- Severity: Low / Confidence: High (for the missing settings) / Medium (for the argued impact) / Type: defense in depth + one confirmed low-severity vector (the /healthz keep-alive army: unauthenticated, unrated, and uncapped, server.go:65,80) / CWE-400
- Location: admin/server.go:80 (only ReadHeaderTimeout=5s). A slow-body PUT must pass authentication first (config_write.go:87 runs after requireAuth); the largest unauthenticated response is the 19 bytes of /healthz.
- Fix: set Idle/Read/Write timeouts explicitly; put /healthz behind lightweight rate limiting or a connection cap.

### [D3-5] Inbound SIP Call-ID reaches the registry and /api/calls with no length limit (unverified hypothesis)
- Severity: Low / Confidence: Medium / Type: unverified hypothesis
- Chain: Call-ID taken verbatim (sig/b2bua.go:1350-1355, no length validation) -> callstate.Call.ID (b2bua.go:303-308) -> registry.Add (:326) -> /api/calls JSON (api.go:41). The preconditions are demanding (an allowed_ips source, a connected call, and the media pool limit). Fix: bound Call-ID length at the SIP entry point; truncate output in /api/calls.

### Domain Three Defense in Depth (not vulnerabilities)
- [D3-2] No CSP / X-Frame-Options / X-Content-Type-Options (admin/webui.go:20, config_write.go:76; no injection chain currently reaches them, so this is defense in depth only). CWE-693.

### High-Value Suspicions Ruled Out in Domain Three (key points; full text in /tmp/freesbc-audit/domain-3-notes.md)
1. **Stored XSS, verified unreachable**: every dynamic rendering path in index.html uses createElement + textContent (:365-373,390-403,348-356,447,437); only 4 innerHTML sites exist and all take static literals (:360,362,385,387); there is no eval, insertAdjacentHTML, document.write, or on* assignment. **The SIP Call-ID -> XSS -> PUT /api/config takeover chain does not hold.** Go's json HTML-escaping by default adds another layer.
2. **CSRF/CORS, not exploitable**: no CORS headers at all; PUT/DELETE always trigger a preflight and preflight requests carry no credentials, so they are blocked with 401; GET raw is protected by the same-origin policy; Basic Auth is not cookie-based.
3. **DNS rebinding**: it is true that Host is not validated (server.go:63-75), but Basic Auth credentials are keyed to the real origin and do not follow the rebinding, so sensitive routes return 401. A Host allowlist is suggested as defense in depth.
4. Prometheus label injection / high cardinality: ruled out (peer/reason/version are all outside attacker control; /metrics sits behind authentication).
5. Redaction is complete (redact.go:20-22,31-33, with tests; there are only two secret fields and both are covered).
6. PUT 400 responses do not leak (the YAML source lines come from the submitter's own body; ${ENV} errors echo only the variable name).
7. handleKickCall has no injection surface; /healthz returns only {"status":"ok"}; the WebUI loads no external resources and uses no eval.

## Domain Five Findings (subagent report + main agent review/merge)

> Method: local code, repository test assertions, and offline cross-checking against upstream pion/srtp v3.0.12 and sipgo v1.4.3 sources. D5-2 and the main agent's chain X1 converged independently (mutually corroborating); D5-6 was merged with the main agent's chain X3.

### [D5-1] SRTP/SRTCP replay protection not enabled (pion defaults to no-replay; no ContextOption is passed)
- Severity: Medium / Confidence: High / Type: confirmed vulnerability / CWE-294, CWE-358
- Affected files and line numbers: media/srtp.go:52 (CreateContext called with no options); media/srtp_relay_test.go:11-13 (**the repository's own test comment acknowledges it**: "CreateContext defaults to NO replay protection... resending decrypts every time"); docs/superpowers/specs/2026-07-17-m5-srtp-sdes-design.md:173 (the design claims replay resistance, which was never delivered)
- Upstream evidence: pion/srtp v3.0.12 CreateContext injects SRTPNoReplayProtection()/SRTCPNoReplayProtection() by default, and nopReplayDetector.Check always passes.
- Chain: replay the ciphertext -> pass the latch (IP:port match) -> unprotect authenticates and decrypts successfully (replay does not change validity) -> re-protect and forward -> the far end receives valid duplicate media. The authentication tag still prevents forgery, but receiver-side replay protection is a MUST in RFC 3711 §3.3.2/§3.4.2. Both srtp=optional and srtp=required legs are affected.
- Precondition: on-path capture (no key required).
- Fix: pass srtp.SRTPReplayProtection(64) and srtp.SRTCPReplayProtection(128) to NewSRTPContext. Regression: assert that a second replay is dropped (the existing pumpTransform retry pump relies on no-replay and must be adjusted accordingly).

### [D5-2/X1 merged] In-dialog refresh re-INVITE is matched on Call-ID alone with no dialog tag validation, so an identified peer can probe out the SDES master key of an active leg
- Severity: Medium (close to High when the conditions are met; see the escalation note) / Confidence: High / Type: confirmed vulnerability / CWE-863
- Affected files and line numbers: sig/b2bua.go:127 (only requires a non-empty To-tag, never compares its value, and never looks at the From-tag, so two of the three RFC 3261 §12.2.2 elements are missing); :128 (the only match is a Call-ID lookup in callSDPStore, sig/callsdp.go:42-72); :139 (the 200 OK returns entry.answer verbatim, which on an SRTP leg contains the SBC's own outbound master key for that leg); sig/timers.go:76-81,102-112 (the gate: Session-Expires plus a byte-for-byte comparison of the body against compare after stripping o=); sig/server.go:363-369 + sig/identify.go:17-30 (the preceding identify only verifies that the source IP belongs to **some** peer, not to the peer of this dialog); shield/shield.go:74 (configured peers are exempt from all rate limiting, so the probing oracle can run at full speed)
- Source -> sink: far-end INVITE (To-tag + Session-Expires + forged compare SDP) -> callSDP(callID) hit -> tx.Respond(200, entry.answer)
- Exploitation scenarios (joint assessment by the main agent and the subagent):
  - The direct party (a participant in the original dialog) already knows the key, so there is no gain;
  - **A third configured peer (a malicious or compromised cross-tenant far end)**: a G.711 offer SDP is highly predictable (the o= line is stripped and excluded from the comparison), so the only unknown is the media IP:port (~2^15); if the Call-ID is visible or guessable and rate limiting is waived, this becomes a high-speed oracle to brute force (200 vs 501) -> obtain that leg's SDES master key -> (1) decrypt that leg's media with sniffing; (2) **inject arbitrary audio in real time using UDP source spoofing (impersonating that leg's media IP:port)**, since the latch checks only IP and port and SRTP auth passes with the known key.
- Escalation note: the disclosure surface (an SRTP master key) plus the injection surface (injecting call content) reach a High impact level, but the precondition is that the attacker is a configured peer or can spoof its source IP persistently, so it is rated Medium as a cross-tenant isolation defect and should be treated as High in multi-tenant operation.
- Fix: in the in-dialog branch, use sip.DialogIDFromRequestUAS/UAC (Call-ID plus both tags) against the dialog ID recorded when the leg was established, and return 481 on mismatch. Regression: with a different peer source IP, a correct Call-ID and compare but wrong tags -> 481 and no answer returned.
- Main agent review: b2bua.go:127-150, timers.go:76-112, and callsdp.go verified line by line. (Contrast: the BYE path in onBye performs full dialog matching with tag protection, which shows this gap is an implementation oversight rather than a design trade-off.)

### [D5-4] The watchdog refreshes lastRx before SRTP authentication (rtp_timeout can be extended indefinitely with garbage packets)
- Severity: Low / Confidence: High / Type: defense in depth / spec deviation
- Location: media/relay.go:45 (lastRx.Store happens before the unprotect at :50-60); the specification at docs/superpowers/specs/2026-07-17-m5-srtp-sdes-design.md:166-170 states the opposite order.
- Impact: anyone who knows the latched IP:port can keep a session alive with garbage packets that never authenticate, so half-open sessions escape rtp_timeout reclamation (5m by default) and extend the port occupation described in D5-6. Fix: move lastRx after both crypto steps succeed.

### [D5-5] Topology hiding gap: the relay's audio m= section keeps every non-crypto attribute from the far end (a=candidate and others)
- Severity: Low / Confidence: High / Type: information disclosure / CWE-212
- Location: sig/sdp.go:176-190 (rewriteSDPCrypto "keep everything except crypto/rtcp"), :69-73 (rewriteSDP); by contrast, attributes in declined sections are cleared (:198-200).
- Impact: ICE candidates (often containing RFC 1918 internal addresses) leak across the SBC to the other leg, contradicting the topology-hiding goal stated in sdp.go:38-44. An attribute allowlist is suggested.

### [D5-6/X3 merged] Media port pool exhaustion + spoofed-source INVITEs holding ports and triggering real carrier traffic
- Severity: Medium (**-> escalated to High and merged into F-06**: after domain one's independent analysis added the self-loop amplification and blind-spoofing billing chains, the main agent ruled for escalation; see [D1-1] in the domain one section) / Confidence: High (for the code path) / Type: configuration risk + confirmed resource surface / CWE-400
- Location: media/portpool.go:54-84 + media/session.go:140-165 (each INVITE takes 2 pairs = 4 sockets); the default pool of 4096 pairs caps concurrency at 2048 calls (config/schema.go:127-128); **there is no max_calls or per-peer concurrency quota field at all** (verified by grepping the whole schema); the hold time is either ring 60s per target (b2bua.go:817) or 5m for an answered call with no media (the watchdog, which D5-4 can extend); signaling rate limiting of 20/s/IP does apply to INVITEs, but identify uses source IP alone (server.go:363-369), so **an INVITE with a spoofed peer source IP holds 2 port pairs for up to ~5 minutes and triggers an outdial to a real carrier (a billing / toll-fraud surface: the B-leg is dialed before the A-leg ACK and can be answered and billed, b2bua.go:782-997)**.
- Reclamation paths verified leak-free one by one: CANCEL (b2bua.go:902,589), ring timeout (817/926), all targets failed (594-602), BYE (server.go:528-548 -> select 346-356), RTP timeout, kick, panic (relay.go:105-112, b2bua.go:1341-1346), and partial Allocate failure (session.go:148-153).
- Recommendations: per-peer concurrency and port quotas; a separate short timer (30-60s) for "answered with zero media"; evaluate anti-spoofing measures for the first UDP INVITE (such as TCP/TLS-only or a digest challenge mode).

### Domain Five Defense in Depth (not vulnerabilities)
- [D5-3] strict arms on IP only: a same-IP race to claim the latch, and no SSRC/PT/seq validation (media/session.go:77-84 compares only the IP pre-latch, a deliberate NAT tolerance; :74-75 checks both IP and port post-latch). Cleartext legs carry RTP's inherent weakness; SRTP legs are backstopped by the auth tag (injection from the same IP on a different port fails). Document that "multi-tenant deployments sharing a public IP require srtp". CWE-346, CWE-290.
- [D5-7] RTCP on cleartext legs is forwarded verbatim (SDES CNAME/SR/RR leak far-end identity and topology, media/relay.go:28-33,72-74), which is normal for an SBC; optionally strip or rewrite CNAME.

### High-Value Suspicions Ruled Out in Domain Five (key points; full text in /tmp/freesbc-audit/domain-5-notes.md)
1. **Media redirection hijacking via re-INVITE, unreachable**: the only production call site for Relatch is b2bua.go:1306 (B-leg 2xx/18x only, matched via the client transaction's Via branch); re-INVITEs that change media always get 501 (b2bua.go:149, asserted in tests). The design document's phrasing "re-INVITE authorizes Relatch" overstates the implementation, which is more conservative.
2. strict drops every packet before arming: confirmed (session.go:77-84 plus tests).
3. RTP parsing out-of-bounds: the cleartext path does not parse (pure byte copying); on the SRTP path pion returns an error for an invalid header, so the packet is dropped fail-closed.
4. SDES keys passing straight through across legs or leaking in declined sections: properly guarded (sdp.go:177-180,198-214; all three cleartext outbound paths call rewriteSDPCrypto(...,nil)).
5. Key exposure surface is clean: 30 bytes from crypto/rand per leg per call; no key reaches logs, metrics, or the admin API.
6. required does not downgrade (the A-leg gets 488, the B-leg fails over); a=crypto parsing is robust (suite allowlist, strict base64, 30 bytes, MKI truncation).
7. Dialog tag entropy: the A-leg To-tag is sipgo's uuid.NewRandom (cryptographic randomness, verified upstream); the B-leg From-tag is 24 hex characters from crypto/rand.
8. The 1500B truncation, the loose default, and stale failover contexts (atomic pointers) raise no security issues.

## Domain Seven Findings (subagent report + line-by-line main agent review of every High)

> Main agent review record: the ordering inside shield.go Check (peer exemption :74 -> banned :77 -> scanner ban :81-86 -> rate limiting :87-92), banlist.go:26-33 (the mutex is released before the nft call, so there is no serialization), nftables.go:39-41 (synchronous exec with no semaphore), :62-63 (the input chain drops all protocols), :76-79 (Is6 treats 4-in-6 as IPv6 -> banned6), and the unboundedness of the banlist, ratelimit, and failCounter maps: all personally read and confirmed.

### [D7-1] scanner-UA bans run before rate limiting: an unthrottled nft fork+exec storm (no concurrency cap, queue, or deduplication)
- Severity: High / Confidence: High / Type: confirmed vulnerability / CWE-770, CWE-405
- Affected files and line numbers: shield/shield.go:81-86 (the scanner ban precedes the rate limiting at :87-92); shield/banlist.go:26-33 (the nft call happens outside the lock, with no concurrency control); shield/nftables.go:39-41,75-85 (exec.Command(path,...).Run() blocks synchronously, with no lock, semaphore, or queue)
- Source -> sink: withShield (sig/server.go:377-386) -> Check -> not a peer -> not banned -> isScanner (the UA is attacker-controlled, sig/server.go:404-410) -> bans.ban -> nftBackend.ban -> fork+exec("nft","add","element",...), **all without passing through rateLimiter.allow**.
- Exploitation scenario: a UDP flood from unique sources (spoofed or a botnet) with `User-Agent: friendly-scanner` -> one fork+exec per packet (sipgo spawns one goroutine per request, each blocking) -> thousands of concurrent nft processes -> CPU/PID/memory exhaustion, plus one Warn log line per packet (shield.go:83). Precondition: nft is active (the default is auto, meaning it activates whenever the binary exists and setup succeeds, which is usually true for root deployments). When nft is not active this degrades to D7-3.
- Fix: move the scanner check after rate limiting, or apply a separate global rate limit to the ban write path (writing only the in-memory table when over the limit); give nftBackend a serialized worker with a bounded queue; deduplicate by IP. Regression: inject a run recorder, ban 1000 IPs concurrently, and assert caps on both concurrency and total exec count.

### [D7-2] Spoofed-source UDP ban injection: any non-peer IP can be written into the kernel nftables set, all-protocol for 1h with no way to lift it
- Severity: High / Confidence: Medium-High (the code path is certain; exploitation depends on UDP source spoofing capability) / Type: confirmed vulnerability (design flaw) / CWE-290, CWE-345
- Affected files and line numbers: shield/shield.go:81-86 (the scanner path bans on **a single packet**); shield.go:116-126 + sig/server.go:418-429 (the auto-ban path takes 5 packets); shield/nftables.go:61-63 (the input chain rule has no port or protocol filter, so it covers all protocols); config/schema.go:159-161 (the default is auto)
- Source -> sink: a single UDP OPTIONS with a spoofed source of VICTIM (and a UA containing sipvicious) -> `nft add element inet freesbc banned4 { VICTIM timeout 3600s }` -> the kernel drops **all** inbound packets from VICTIM (any protocol, any port) for one hour, with no admin unban endpoint (every admin route is read-only or kicks calls, admin/server.go:63-75), leaving only a restart or manual nft.
- Exploitation scenario (impact quantified): VICTIM = the system DNS resolver -> the SBC's outbound DNS responses are dropped by the kernel -> all SRV/A resolution times out -> routing collapses (a reliable remote service outage, sustained with one spoofed packet per hour); VICTIM = an operations workstation, a new carrier signaling source, or monitoring -> blackholed the same way. The only exemption is IPs inside peer.allowed_ips (spoofing a peer IP will not get it banned, and the ordering has been verified).
- Fix: over UDP, only perform kernel bans against sources that have completed a round trip (single-packet decisions should only produce in-memory bans); scope the kernel rule to SIP ports and protocols; provide admin unban/flush; change the nftables default to off or require an explicit on.
- Main agent review: nftables.go:62-63 confirmed that the rule text `ip saddr @banned4 drop` has no dport qualifier; confirmed that admin has no unban route.

### [D7-3] banList has no capacity cap: a unique-source flood exhausts memory (prune only removes expired entries)
- Severity: High / Confidence: High / Type: confirmed vulnerability / CWE-770
- Affected files and line numbers: shield/banlist.go:13-22,26-33 (the map has no cap); :60-69 (prune deletes only already-expired entries; entry lifetime = auto_ban.duration, 1h by default); secondary: shield/ratelimit.go:66-78 (the bucket map is unbounded within the minute window), shield/shield.go:188-202 (failCounter appends without bound within the window)
- Root cause: the M6 specification (docs/superpowers/specs/2026-07-17-m6-shield-design.md:193) claims bounded memory, but the implementation's boundedness is the product of "new source injection rate x Duration", a quantity entirely under attacker control.
- Exploitation scenario: spoofed unique sources plus a scanner UA (1 packet per source, no rate limiting) -> sustained 10k/s -> tens of millions of entries within the 1h window (~100-150B each) -> several GB -> OOM; when nft is active the kernel set grows by the same order of magnitude and compounds D7-1.
- Fix: enforce a hard cap on the ban table (for example 64k, degrading to /24 or /48 prefix aggregation past the cap, as carriers do); set maxsize on the nft set; make the over-limit policy explicit and alert on it. Regression: under a fake clock, ban more IPs than the cap and assert that the table size is clamped.

### [D7-4] IP normalization (Unmap) missing throughout: peer identification breaks on dual-stack listeners, kernel bans are written to banned6 and never match, and table entries are duplicated
- Severity: Medium / Confidence: Medium-High (netip/nftables semantics rest on the standard library documentation and domain knowledge; with no Go toolchain this could not be re-verified at runtime) / Type: confirmed (missing normalization) + configuration risk / CWE-706
- Affected files and line numbers: sig/server.go:391-401 (sourceAddr does not call .Unmap(); the only Unmap in the repository is in media/session.go:82); shield/nftables.go:76-79 (Is6() returns true for ::ffff:a.b.c.d, so the entry is wrongly written to banned6 as the element string `::ffff:x.y.z.w`, while real IPv4 packets never evaluate ip6 saddr, making the **kernel ban silently ineffective**); config/types.go:96-99 (the listen host accepts "", and `udp://:5060` is the natural way to write it; an empty host in Go means a dual-stack [::] socket, so IPv4 peers appear as 4-in-6)
- Impact: (1) on a dual-stack listener, no IPv4 peer is identified (netip's cross-family Contains returns false, and the fail-closed behavior drops every call, which surfaces immediately); (2) kernel bans for those sources are all ineffective (the in-memory layer still works, and the logs look identical); (3) the v4 and 4-in-6 forms of the same IP are different map keys, so ban tables, buckets, and counters each hold two entries per IP.
- Fix: have sourceAddr call Unmap() before returning (or do it at the Check/ban entry points); have the validation layer reject an empty host, or document that a single stack must be written explicitly. Regression: `Check(::ffff:203.0.113.10)` should be exempt when allowed_ips contains 203.0.113.0/24; the ban argv should select banned4.
- Main agent cross-check: consistent with the main agent's independent verification (there is no bypass in the identify fail-closed direction; this finding adds the two increments of kernel-layer ineffectiveness and doubled quota entries).

### Domain Seven Medium and Low Findings (key points; full text in /tmp/freesbc-audit/domain-7-notes.md)
- [D7-5] Medium (defense in depth): the shield sits at the handler layer (sig/server.go:377-386), so the cost of full sipgo parsing is unprotected; when nft is absent, already-banned sources still pay full parsing per packet (nftables.go:28-49 silently falls back to memory-only when auto probing fails). CWE-400.
- [D7-6] Low: changes to shield.nftables do not take effect on hot reload (the mode is fixed at construction, shield.go:26-47, so on -> off still writes to the kernel). CWE-665.
- [D7-7] Low: the nft table name `inet freesbc` has no instance isolation (nftables.go:56 deletes the table unconditionally, so two instances delete each other's table, or an operator's identically named table is deleted). CWE-667.
- [D7-8] Low (defense in depth): nft is resolved through PATH with no absolute-path configuration (nftables.go:32,39-41; the argv itself is injection-free). CWE-426.
- [D7-9] Low: dropUnidentified logs one Info line per request (sig/server.go:418-421), so a 1000-IP botnet produces roughly 20,000 lines per second (~260GB/day); by contrast the rate-limit branch logs at Debug, and this is the only site at Info. CWE-400.
- [D7-10] Low: the scanner fingerprints include legitimate operations tools such as sipsak (scanner.go:11-23), so a single packet earns a 1h kernel blackhole with no way to lift it (compounding D7-2). CWE-697.
- [D7-11] Low (partly unverified): rate_limit values have no upper bound (types.go:132-135, so "1000000/s" is accepted, giving a 1.4GB failCounter per IP); a sub-1s ban duration truncates to "0s" in the nft timeout integer (nftables.go:80, and nft's behavior for 0s was not verified). CWE-1284.

### Suspicions Ruled Out in Domain Seven (key points)
1. **nft command injection, verified unreachable**: no shell is involved; exec.Command takes an argv array (nftables.go:39-41, the only exec site in the repository); the only non-constant argv elements are ip.String() (netip's canonical output) and Itoa numbers; table, chain, and set names are all compile-time constants; the tests assert the exact argv.
2. **ParseRateLimit failure being fail-open (ratelimit.go:34-36 allows everything when rate <= 0), verified unreachable**: Load -> Parse -> validate rejects invalid strings (loader.go:31-44, validate.go:145-147), and hot reload goes through the same Load; the only way in is a hand-built Config in a unit test.
3. Spoofing a peer IP to gain full shield exemption: true, but it belongs to the identify domain (see D5-6 and domain two), and the ordering guarantees that spoofing a peer IP cannot get the real peer banned.
4. PerIP=false global bucket collateral damage: the only traffic rate-limited is non-peer sources that would be silently dropped anyway; the specification states this design explicitly.
5. Bypassing the shield when sourceAddr fails: req.Source() is always the socket address, so this is unreachable in practice.
6. Log injection (the UA reaching a Warn line): SIP header values cannot contain CRLF (a parser-layer constraint), and slog escapes quotes.
7. A race between Close and an in-flight Check: the defer ordering is guaranteed by wg.Wait (server.go:216 vs :296).

## Domain Four Findings (subagent report + main agent review)

> goccy/go-yaml v1.19.2 behavior was verified against upstream source (marked [source-verified]). **Overall conclusion for this domain: the configuration surface is well designed.** Strict parsing (both unknown and duplicate keys are rejected, so a misspelled allowed_ips is fail-closed), a missing ${ENV} rejects the whole file (no fail-open empty password), write-back preserves ${ENV} verbatim, a bad hot reload keeps the old configuration, and the Store swaps a single pointer atomically. **No configuration-surface vulnerability exploitable by an unauthenticated remote attacker was found.**

### [D4-1] Admin credentials and listen address do not take effect on hot reload: an old password stays valid after rotation
- Severity: Medium / Confidence: High / Type: configuration risk / CWE-613, CWE-1188
- Location: main.go:104,:127 (`store.Current().Admin` is read once at startup and frozen into admin.New); admin/server.go:59,:80,:103-104 (requireAuth uses the startup credentials on every request); by contrast api.go:63 (GET /api/config reads the current configuration from the store); acknowledged in the design document docs/superpowers/specs/2026-07-17-m7-1-admin-api-metrics-design.md:177-179.
- Exploitation scenario: the admin password is suspected to be leaked, so the operator changes password_hash via hot reload or the WebUI. GET /api/config shows the new configuration and the save succeeds, but **the old password remains valid until restart** (the attacker keeps every admin privilege: reading the unredacted /api/config/raw, changing routing, kicking calls). Conversely, deleting the entire admin: section does not shut down the admin API either.
- Fix: have requireAuth read from store.Current() on every request (bcrypt already costs ~50ms per attempt, so there is no added cost); alternatively, detect changes to admin.auth/listen and reject them (409 with a restart-required message) or emit a high-visibility WARN. Regression: after hot-swapping admin.auth, the old credentials must return 401.
- Main agent review: main.go:104-136 and admin/server.go:59 confirmed that cfg is frozen at startup.

### Domain Four Medium and Low Findings (key points; full text in /tmp/freesbc-audit/domain-4-notes.md)
- [D4-2] Low (unverified hypothesis, mechanism [source-verified]): goccy's alias expansion is unbounded on BytesUnmarshaler fields (the three custom scalar types at config/types.go:30,51,82), so a self-referential alias `&a [*a]` sends formatAlias into unbounded recursion and produces an **unrecoverable fatal stack overflow** that kills the process along with every in-flight call; an alias bomb yields OOM. The precondition is control over configuration content (which the threat model already equates with controlling the SBC), hence Low. Fix (a one-liner): reject configurations containing anchors or aliases before loading (an SBC configuration does not need them).
- [D4-3] Low (local threat): PUT write-back inherits the original file's permission bits (config_write.go:113-116), so a 0644 configuration containing literal cleartext credentials is readable by other local users; there is no chmod guidance anywhere. CWE-732.
- [D4-4] Low: PUT If-Match TOCTOU and concurrent PUT races (config_write.go:97-117 has no lock), which can lose updates between trusted principals but grants no privilege escalation. CWE-367.
- [D4-5] Low: writeFileAtomic does not fsync the directory (a durability rather than atomicity issue, so no empty or partial file can appear); when cfgPath is a symlink, rename replaces the link itself (silently changing the deployment layout).
- [D4-6] Low (configuration risk): validation allows admin.listen to bind 0.0.0.0 with no warning (validate.go:167-170) over cleartext HTTP Basic Auth; bcrypt has no minimum cost (:174-176, so cost 4 is accepted). CWE-668, CWE-916.
- [D4-7] Low: Load has no file size limit (loader.go:11-17 reads the whole file; the PUT path already has a 1MiB limit).
- [D4-8] Low: when the fsnotify Events channel closes abnormally, Watch returns nil and main stays silent (reload.go:57-59 + main.go:78), so hot reload dies silently: the running configuration never changes again while PUT keeps returning 200.

### Key Suspicions Ruled Out in Domain Four
1. A misspelled allowed_ips matching all sources: **does not hold**: yaml.Strict() rejects the whole file on an unknown key (loader.go:33 plus tests), and an empty allowed_ips makes AllowsIP always false (fail-closed).
2. Duplicate keys overriding: does not hold; goccy rejects duplicate map keys by default [source-verified].
3. A missing ${ENV} yielding an empty password: does not hold; a missing or malformed variable rejects the whole file (expand.go:116-124,37-39).
4. Expanded secrets reaching disk, errors, or the API: does not hold (write-back is verbatim; parse errors precede expansion; redaction covers both secret fields).
5. A bad hot reload being fail-open or half-applied: does not hold (reload.go:73-78 keeps the old configuration, and a single atomic.Pointer swaps the whole thing).
6. fsnotify storms: already mitigated (200ms debounce + directory watching + temp files filtered by basename).
7. ReDoS: does not hold (compiled at load time, RE2 is linear, group references are validated).
8. transform CRLF injection: no untrusted path was found (the OutNumber input is an already-parsed SIP URI user, which cannot contain CR or LF after parsing).

## Domain Six Findings (subagent report + line-by-line main agent review of every High)

> Key evidence upgrade: the subagent downloaded the complete sipgo v1.4.3 source to /tmp/freesbc-audit/sipgo-1.4.3/, so every sipgo internal conclusion rests on real source. The main agent personally re-verified D6-1 (transport_udp.go:177-184 + transport_connection_pool.go:108-118) and D6-4 (transaction_layer.go:18-20,165,190,214-226 + transport_udp.go:229).

### [D6-1] The sipgo UDP connection pool grows unbounded per unique source address, before parsing and before the shield
- Severity: High / Confidence: High / Type: confirmed vulnerability (inherited from a dependency, which FreeSBC exposes directly to the internet) / CWE-770
- Affected files and line numbers: sip/transport_udp.go:177-184 (readListenerConnection calls `t.pool.Add(rastr, conn)` for every new remote address, before parseAndHandle); sip/transport_connection_pool.go:108-118 (Add only inserts, with no eviction; UDP pool entries are cleared only when the listener closes, meaning never during the process lifetime); attachment point sig/server.go:324-358 (bindListener -> tl.ServeUDP with no pre-filtering; sipgo offers a readFilter hook that FreeSBC does not use).
- Attacker capability / preconditions: only the ability to send arbitrary packets to 5060/udp (they need not parse as SIP). An IPv6 attacker can use any source address inside their own /64 (a 2^64 key space, no spoofing needed); IPv4 requires spoofing in the absence of uRPF. The shield never sees any of it (Check runs at the handler layer).
- Quantified: each entry is ~100-180B. 10k pps x 1h ~ 36 million entries ~ 4-6 GB that is never released -> OOM, all calls dropped.
- Fix: an upstream patch (pool cap plus LRU); in the short term, use sipgo's readFilter hook for pre-filtering, or drop non-allowlisted sources early with nftables.
- Main agent review: source read line by line confirming that pool.Add is unbounded and precedes parsing.

### [D6-4] Transaction- and transport-layer shield blind spots: one goroutine plus one log per stray response, full-byte Error logging of parse failures, and unsolicited 400 responses to malformed requests (breaking the "silent for unknown sources" promise)
- Severity: Medium / Confidence: High / Type: confirmed vulnerability (log flooding + fingerprint disclosure + reflection) / CWE-400
- Affected files and line numbers (none of these pass through withShield, which wraps only the request handler, sig/server.go:219-223):
  1. Any SIP response packet -> sipgo transaction_layer.go:133-146 spawns a goroutine per packet -> no matching client transaction -> defaultUnhandledRespHandler (:18-20) writes one Info log per packet; FreeSBC's sipgo.NewClient (sig/server.go:179) does not set UnhandledResponseHandler.
  2. Parse failure: transport_udp.go:229 calls `Error("failed to parse", "data", string(data))`, so **the attacker's raw bytes land verbatim in the Error log**, one entry per packet (64KB per packet at a high rate fills the log disk with GBs within seconds).
  3. Parseable but missing Via/CSeq: rejectMalformedRequest (transaction_layer.go:214-226) **actively returns 400** before the shield and identify, so any unauthenticated source can get a response, breaking the "silently drop unknown sources" promise (stated in sig/server.go:572-582) and providing roughly 1:1 reflection.
- Newline injection was verified as not exploitable (slog's TextHandler quotes and escapes values containing newlines).
- Fix: set UnhandledResponseHandler on NewClient (silent counting); downsample sipgo logging; fix the parse-failure log upstream.
- Main agent review: all three sipgo source sites confirmed verbatim. This finding also corrects the Phase B trust-boundary conclusion that "unidentified sources always get silence".

### [D6-5] SIP TCP/TLS listeners have no connection cap and no idle/read timeout (Slowloris) - WARNING: part of this finding was overturned by the main agent
- Severity: Medium (**-> merged with D1-3 and escalated to High as F-02**) / Confidence: High / Type: confirmed vulnerability / CWE-400
- **Main agent ruling (see the head of the domain one section)**: this finding's original claim that "per-connection memory is bounded (a 64KB parse limit)" **does not hold**: sipgo parser_stream.go:117-121 Write appends unconditionally, the 65535 limit at :125-139 is checked only after a complete parse, and transport_tcp.go:227-240 keeps reading on partial errors, so per-connection memory is unbounded. The "no connection cap, no timeout" part of this finding still stands.
- Location: sig/server.go:324-345 (bare net.Listen plus ServeTCP/ServeTLS); sipgo transport_tcp.go:60-70 (accept is unrestricted), :135-143 (no SetReadDeadline or idle handling; keepalive is commented out at :108-116). Each idle connection costs 1 goroutine, 1 fd, and a pool entry, none of which are ever reclaimed; fd exhaustion takes down UDP and the media ports with it. ~~per-connection memory is bounded (a 64KB parse limit)~~ **overturned**: a single complete message does have a 65535 limit (parser.go:33, parser_stream.go:196-198), but accumulation across reads while slow-feeding an incomplete message is unbounded (D1-3, parser_stream.go:117-121), so the problem is both connection count and per-connection memory.
- Fix: wrap the listener to limit total and per-IP connections.

### [D6-6] Peer rate-limit exemption plus TerminateGracefully blocking after an answer: an INVITE flood with a spoofed peer source IP pins goroutines for up to 32s
- Severity: Medium / Confidence: Medium (requires spoofing a peer IP or a malicious peer) / Type: confirmed vulnerability (conditional) / CWE-770
- Location: shield/shield.go:72-76 (peers are exempt from all rate limiting) -> b2bua.go:188-190 answers -> sipgo server.go handleRequest -> tx.TerminateGracefully -> transaction_server_tx.go:165-182 blocks on `<-tx.Done()` until the ACK or Timer H = 32s (transaction.go:64). Each packet costs 1 goroutine plus a few KB of transaction state: spoofing 50k pps yields 1.6 million concurrent goroutines and tens of GB. The attacker does not need to see the responses.
- Fix: apply a loose rate limit to peers as well; cap concurrent INVITEs per peer.

### [D6-9] Call-ID key collisions across calls (the killers, registry, and sdps maps)
- Severity: Low / Confidence: High / Type: confirmed vulnerability (requires a peer to reuse a Call-ID) / CWE-667
- Location: sig/server.go:98-110, b2bua.go:303-342 (all three collections are keyed by the A-leg Call-ID). A second concurrent call with the same Call-ID overwrites the entry, and whichever ends first deletes the other's entry in its defer, so the survivor becomes invisible to /api/calls and KillCall returns 404. Fix: add the From-tag to the key, or return 482 for a duplicate Call-ID.

### Items Merged Elsewhere from Domain Six
- D6-5 (no TCP connection cap or timeout; the "per-connection memory is bounded" conclusion overturned) -> merged with D1-3 into **F-02 (High)**.
- D6-2 (quantification of scanner bans bypassing rate limiting, plus the failCounter variant) -> merged into [D7-1] and [D7-3].
- D6-3 (the rate-limit bucket map has no cap; steady state is roughly the number of unique sources in the last 1-2 minutes, ~60-120MB at 10k pps) -> merged into [D7-3] as a secondary surface.
- D6-7 (admin runs full bcrypt per request, with no IdleTimeout and no connection cap) -> merged into [D3-3] and [D3-4].
- D6-8 (no max_calls; roughly 68 INVITE/s x 60s fills every port slot, and calls still in setup are absent from the registry and cannot be kicked) -> merged into [D5-6].
- D6-10 (nft exec has no timeout and sits on the hot path, so request goroutines pile up without bound when nft stalls) -> merged into [D7-1].

### Suspicions Ruled Out in Domain Six (key points)
1. Silent drops causing transaction table buildup: unreachable (sipgo handleRequest immediately terminates and drops transactions that were never finalized).
2. relay goroutine leaks or double Close: ruled out (forward exits when the socket closes; Close is idempotent via closeOnce; the panic path closes the session; onInvite has a defer for every resource).
3. Races between kick and natural termination, or double BYE: ruled out (a single select branch; cancel is idempotent; registerKiller runs before registry.Add).
4. registrar deadlocks or leaks: ruled out (stopAll cancels first and then waits on each done; unregister has a 2s timeout).
5. Unbounded per-connection body over TCP: ruled out (a 64KB parse limit; the connection-count problem belongs to D6-5).
6. Blocking I/O while holding a lock: ruled out (ban unlocks before exec; DNS runs outside the lock; portpool does only O(1) work under its lock).
7. Unbounded growth of a single IP's failCounter slice: ruled out (with the default configuration the fifth packet triggers a ban, and the banned branch runs first).
8. Torn store snapshots: ruled out (atomic.Pointer holds an immutable snapshot).

## Domain Eight Findings (subagent report + main agent review)

> **Overall conclusion for this domain: the supply-chain fundamentals are solid.** No replace or exclude directives; go.sum carries complete double hashes for all 22 dependencies; zero hardcoded secrets (the examples all use ${ENV} or placeholders that the mechanism rejects); no sbc.yaml anywhere in git history; the embed surface is clean (a single file with no external resources); exec uses no shell; there is no unsafe or cgo; and icholy/digest is a test-only import that never reaches the shipped binary. **No Critical or High findings.**
> **Key clarification (resolving the main agent's chain X2)**: outbound TLS certificate verification is on by default. There is no InsecureSkipVerify anywhere in sipgo, and outbound connections use a zero-value tls.Config (ServerName = hostname, system CAs; transport_layer.go:129-132, transport_tls.go:24-31). Therefore SDES over outbound TLS is protected against far ends that hold a CA-issued certificate, and chain X2 narrows to "inbound is always self-signed with no certificate configuration option, and there is no pinning capability".

### [D8-3] The far-end DNS trust chain is unhardened (no DNSSEC, pinning, or address-class warnings): control of DNS can redirect the B-leg and harvest digest responses and SDES keys
- Severity: Medium / Confidence: Medium / Type: defense in depth (strong preconditions) / CWE-345
- Location: sig/resolve.go:54 (the system default resolver, cleartext port 53, no DNSSEC); :97-104 (SRV results become endpoints directly, with no warning for loopback or private addresses); b2bua.go:752-822 (INVITE/WaitAnswer carry digest credentials); register.go:101 (the REGISTER digest response); SDES keys go to the B-leg in cleartext.
- Grading: a lapsed and re-registered domain or a compromised registrar -> SRV points at the attacker -> **the digest response can be dictionary-attacked offline for the peer password, SDES keys leak, and toll fraud follows**; tls peers are not immune either (the domain holder can obtain a public CA certificate that passes verification, and no pinning is configurable); on-path UDP/53 poisoning -> the same redirection, though the tls peer handshake fails (outbound verification is on, verified in source).
- Fix: document the trust assumption that peer domains must not lapse; add CA/pin configuration for outbound TLS; log a warning when resolution yields loopback or link-local addresses; enable DNSSEC on the local recursive resolver operationally.

### [D8-1] SRV resolution has no timeout, no singleflight, and caches error results for the full TTL
- Severity: Low / Confidence: High / Type: configuration risk (availability) / CWE-400
- Location: sig/resolve.go:46,54 (the package-level net.LookupSRV takes no ctx), :86-104 (no concurrent deduplication; failures and empty results are cached for the same 300s), call site b2bua.go:469 (synchronous inside the onInvite goroutine and not interruptible by CANCEL).
- Impact: during DNS instability every call's goroutine blocks; at the instant a cache entry expires, N concurrent calls trigger N queries; a single transient failure leaves that peer on the bare-hostname fallback for a full 300s. Fix: Resolver.LookupSRV(ctx) with WithTimeout, singleflight (x/sync is already an indirect dependency), and a short TTL for failures.

### Domain Eight Medium and Low Findings (key points)
- [D8-2] Low (unverified): SRV results receive no semantic validation, so Target "." (RFC 2782's "service unavailable") and port 0 produce endpoints with an empty host (resolve.go:143-206). **Verified against sipgo source as bounded and non-panicking**; the only cost is wasted attempts and cooldown noise. CWE-20.
- [D8-4] Low: the DNS fallback port is always 5060, whereas transport:tls should fall back to 5061 (RFC 3263 §4.1; resolve.go:98-99); the REGISTER path calls splitHostPortDefault(address,5060) and bypasses the SRV resolver entirely (register.go:390). This is an availability issue (dialing the wrong port), not a downgrade. CWE-440.
- [D8-5] Low (defense in depth): there is no CI, Makefile, or Dockerfile, and releases have no -trimpath, SBOM, or signing; offline CVE assessment: x/crypto v0.54.0 (all known CVEs are well past their fix lines and only bcrypt is used), and the remaining dependencies have no known CVEs offline, but **machine corroboration with govulncheck is needed**. CWE-1357.
- [D8-6] Low (defense in depth): there is no privilege-dropping logic, and 5060/5061 plus CAP_NET_ADMIN effectively require root; a systemd AmbientCapabilities sample is recommended. CWE-250.
- [D8-7] Low (defense in depth): Load does not check the configuration file's permissions (loader.go:11-17), so an sbc.yaml copied out at 0644 with cleartext passwords is world-readable. CWE-732.

### Suspicions Ruled Out in Domain Eight (key points)
1. nft exec injection: not exploitable (same conclusion as domain seven; ip.String() has no controllable zone). 2. The go:embed surface: clean. 3. unsafe/cgo: zero occurrences repository-wide. 4. reflect has a single use (${ENV} expansion only). 5. An unbounded Resolver.cache: unreachable (keys come only from configuration). 6. Hardcoded secrets: none (including across all git history). 7. Outbound TLS verification is on by default (a key positive result). 8. Recursive SRV re-resolution: does not exist. 9. fsnotify reloading on a temp file: unreachable (filtered by basename).

## Domain One Findings (subagent report + main agent review and conflict adjudication)

> Evidence: sipgo v1.4.3 and pion/sdp v3.0.19 sources (official GitHub tag tarballs, stored in /tmp/freesbc-audit/). Main agent adjudication record: (1) the D6-5 vs D1-3 conflict was resolved by personally reading parser_stream.go:117-121 (Write appends unconditionally), :125-139 (MaxMessageLength is checked only after a complete parse), and transport_tcp.go:227-240 (ErrParseSipPartial -> return and keep reading), concluding that **D1-3 is correct and TCP per-connection memory is unbounded**; (2) the D1-5 parser semantics were verified personally (parser.go:341-365: lines are split at the first \r, a bare \n survives inside header values, and a \r can never survive).

### [D1-1 + D5-6/X3 merged, escalated to High] Unauthenticated INVITE -> media port pool exhaustion + real carrier outdials (DoS + toll fraud)
- Severity: **High** (domains one and five converged independently; the main agent accepted domain one's escalation rationale) / Confidence: High / Type: confirmed vulnerability / CWE-770, CWE-799
- Location: sig/b2bua.go:80-87 (no authorization after identify), :276-285 (every INVITE takes 2 port pairs = 4 sockets first), :553-592,801-964 (the full failover chain, with ring 60s stretching the hold time), shield/shield.go:74-76 (peer source IPs are completely exempt from rate limiting), media/portpool.go:54-84 (exhaustion -> 503), config/schema.go:127-129,162-163 (the default pool allows ~4096 concurrent calls)
- Precondition: the source IP of any configured peer (a malicious or compromised carrier, or UDP spoofing; see D1-2).
- Exploitation scenarios: (1) a single peer at ~70 INVITE/s (one target, 60s hold) fills every concurrent session, so legitimate calls get 503; (2) each attacking INVITE triggers an outdial to a real carrier (with automatic digest retry), producing **toll fraud**; (3) when routing sends from == to, self-loop amplification runs until the ports are exhausted; (4) **blind spoofing** (no need to see responses): when the A-leg ACK never arrives, aLeg.Respond fails after 64 x T1 ~ 32s, but the B-leg has already been ACKed as a genuinely connected, billable call (the ordering at b2bua.go:1065-1077 is: ACK the B-leg first, and BYE only after Respond fails); (5) RTP silence takes 5m to reclaim, and D5-4's garbage-packet keepalive stretches the hold time further.
- Fix: per-peer INVITE rate and concurrent-call caps; a global half-call cap (503 + Retry-After); require digest for register-type peers; defer media port allocation or share ports with a time limit; monitor and alert on the half-call count. Regression: under an INVITE flood from one peer, assert that other peers' calls are unaffected; for a spoofed-source INVITE, assert that the B-leg gets a BYE after the ACK timeout.

### [D1-2] Peer identification by source IP alone: over UDP, spoofing a source IP grants full peer trust (a systemic trust boundary defect)
- Severity: High (a trust model defect; exploitation requires spoofing capability or a malicious peer) / Confidence: High (the code path is certain; exploitability depends on network position, uRPF, and BCP 38) / Type: configuration risk / CWE-345, CWE-348
- Location: sig/identify.go:17-30 (the only credential is an allowed_ips match against the source address); sig/server.go:360-401,488-582 (this is the only authorization in every handler)
- Chain: any SIP request with a spoofed source IP equal to a peer IP -> peer exemption -> identify hit -> full privileges of that peer (every consequence of D1-1, plus receiving responses). TCP/TLS is unaffected (three-way handshake).
- Fix: document the trust boundary and recommend enabling only tcp/tls listeners on the internet; require digest for register-type peers and sensitive routes (IP plus credentials as two factors); uRPF on the carrier side; bind From validation to high-value operations. Regression: a spoofed-source INVITE against a digest-enabled peer is answered with 401.

### [D1-3 + D6-5 merged, escalated to High] SIP TCP/TLS: no connection cap + no read/idle timeout + unbounded stream parse buffer accumulation
- Severity: **High** / Confidence: High / Type: confirmed vulnerability (upstream-dependent, with zero mitigation in FreeSBC) / CWE-400, CWE-779
- Location: sig/server.go:324-358 (bare net.Listen/tls.Listen with no wrapper; sipgo's WithTransportLayerReadFilter hook is unused); sipgo transport_tcp.go:62-72 (accept has no cap), :151-168 (the read loop has no SetReadDeadline or idle handling), parser_stream.go:117-121 (Write appends unconditionally), :125-139 (MaxMessageLength is checked only after a complete parse), transport_tcp.go:227-240 (ErrParseSipPartial is ignored and reading continues)
- Source -> sink: open a connection -> slow-feed bytes with no CRLF -> parseSingle keeps returning ErrUnexpectedEOF -> the partial error is ignored -> **the buffer grows without bound across reads (1:1 memory)**; alternatively, M idle connections each hold a goroutine and an fd forever -> fd/goroutine exhaustion takes down UDP and the media ports with it.
- Fix: immediately actionable on the FreeSBC side, wrap the listener (maximum connections, per-connection idle timeout, handshake timeout); upstream, add an accumulation cap to ParserStream. Regression: slow-feed 1MB over a half-open connection and assert bounded memory or a disconnect; open more than the cap and assert the excess is refused.

### [D1-4 + D5-5 merged] Topology hiding gap: the relay's audio m= section passes through a=candidate / a=fingerprint / a=ice-* / the o= session identifier / s=
- Severity: Medium / Confidence: High / Type: confirmed vulnerability / CWE-200
- Location: sig/sdp.go:63-87 (rewriteSDP), :163-201 (rewriteSDPCrypto keeps every attribute in the relay section except crypto and rtcp, :176-190), :59-61,159-161 (o= has only its address rewritten; username, sess-id, and version pass through unchanged); by contrast declined sections are cleared (:198-200). The comment at sdp.go:144-148 admits the candidate leak is known, but only the declined sections were fixed.
- Impact: the carrier side observes the caller's internal topology (host candidate internal IP:port for WebRTC-enabled PBXs, DTLS fingerprints, ICE credentials), and the reverse holds too, which is exactly what an SBC's topology hiding is meant to block. ICE-enabled endpoints will also try to reach media at internal addresses (an interoperability failure).
- Fix: apply an attribute allowlist to relay sections (rtpmap/fmtp/ptime/sendrecv/...), stripping candidate/fingerprint/ice-*/setup/extmap; rewrite the o= username and sess-id to SBC-generated values. Regression: for an offer containing a=candidate and a=fingerprint, assert the B-leg offer contains neither.

### [D1-5] Bare-LF header injection: A-leg identity fields and the called number reach the B-leg unsanitized, and serialization does not escape them
- Severity: Medium / Confidence: High (the injection path was verified against sipgo source; the far-end damage depends on the peer's parser) / Type: confirmed vulnerability / CWE-93
- Location: sig/b2bua.go:1089-1103 (buildFrom passes DisplayName and User through verbatim), :752-753 (outNumber -> Request-URI user), sig/routing.go:44-50 (with no route match, the called number passes through verbatim); sipgo headers.go:605-621 (FromHeader emits any character inside the quotes verbatim), uri.go:72-79 (Uri emits User verbatim), parser.go:341-365 (**a bare \n survives in header values, URIs, and display names; a \r can never survive**, personally verified by the main agent)
- Chain: an A-leg `From: "x\n<forged-header>: y" <sip:a@h>` -> parsing keeps the \n -> buildFrom -> the B-leg serializes it verbatim -> against a lenient SIP stack that treats a bare LF as a line terminator (common in practice), this **injects arbitrary trailing lines toward the carrier** (header injection / request smuggling); an embedded `"` inside the display name breaks quote pairing. CR/CRLF injection is ruled out (see ruled-out item 1), and strict stacks are unaffected.
- Fix: strip \r and \n in buildFrom and the Request-URI user, and additionally strip `"`, `<`, and `>` from the display name (or apply quoted-pair escaping); apply a character allowlist to the called number. Regression: for an INVITE whose From, user, and URI user contain \n and ", assert the B-leg contains no verbatim bytes or the request is rejected with 400.

### [D1-8] Every SIP handler except onInvite, and the sipgo dispatch goroutine, lack panic recovery
- Severity: Medium-Low / Confidence: High (the absence of recover is verified; no concrete panic site was found in onBye/onAck) / Type: defense-in-depth recommendation / CWE-248
- Location: sipgo transaction_layer.go:140 (handleRequestBackground has no recover), server.go:258-269; FreeSBC has only three recover sites (b2bua.go:81, relay.go:106, admin/server.go:118); onOptions/onAck/onBye/onNoRoute (sig/server.go:488-582) are unprotected, so any panic there means **the whole process exits** (Go semantics).
- Corroboration (a real panic already exists and is currently swallowed by onInvite's recover): an INVITE with no To header -> nil dereference at b2bua.go:127 `req.To().Params`; with no From header -> nil dereference after `req.From()` at :1090 (sipgo's makeServerTxKey with a magic-cookie branch does not require From, transaction.go:312-315; ReadInvite checks only Contact and CSeq). Today the consequence is a reliability issue (the call is silently dropped with no 400), but the same class of nil dereference inside sipgo dialog code called from onBye or onAck would kill the process.
- Fix: add a uniform defer recover plus 500 in withShield; explicitly validate the presence of From, To, and Call-ID before onInvite and return 400. Regression: assert 400 for INVITEs missing To or From; inject a panic into onBye and assert the process survives.

### Remaining Domain One Items (merged into other domains, cross-referenced)
- [D1-6] (spoofed-source ban injection / nft storm) -> merged into [D7-1] and [D7-2] (identical conclusions).
- [D1-7] (transaction-layer 400 / CANCEL-200 / auto-100 bypassing the silence promise) -> merged into [D6-4], with the addition that a CANCEL matching an INVITE transaction is answered 200 directly (transaction_layer.go:155-184) and an INVITE transaction sends an automatic 100 Trying after 200ms (transaction_server_tx.go:41-71).
- [D1-9] (Call-ID collisions) -> merged into [D6-9].
- [D1-10] (refresh re-INVITE with no tag validation) -> merged into [D5-2/X1]. **Note**: that subagent held a more conservative view (that a third party would struggle to obtain the compare SDP and that a 200 has no side effects); the main agent kept the Medium rating, on the grounds that the SDP is highly predictable (o= is stripped), that the peer rate-limit exemption lets the 200-vs-501 oracle be brute forced at full speed, and that the answer containing an SRTP master key is genuinely sensitive output.
- [D1-11] (TLS is always self-signed) -> merged into the final report's TLS configuration risk item (combined with the main agent's chain X2 and domain eight's outbound verification conclusion).
- [D1-12] (unbounded UDP pool + single read loop as a single-core bottleneck) -> merged into [D6-1] (two subagents derived the same mechanism independently from the same code; the severity follows D6-1's High).

### High-Value Suspicions Ruled Out in Domain One (all verified against sipgo/pion source)
1. **CR/CRLF header injection: not feasible** (only bare LF is, already filed as D1-5): nextLine splits at the first \r within the line and requires \r\n pairing, so a \r can never survive inside a header value, URI, display name, or Call-ID; folded headers are joined with a single space.
2. **Content-Length smuggling: not feasible**: both the stream and datagram paths take "the last Content-Length wins"; every outbound FreeSBC message goes through SetBody, which recomputes Content-Length and re-serializes the whole message, so the attacker's raw bytes are never echoed back.
3. **A forged oversized Content-Length causing a large allocation: not feasible**: there is a totalRead + CL > 65535 pre-check before make (parser_stream.go:190-198), and the UDP read buffer is 32768.
4. **Cross-call BYE/ACK/CANCEL hijacking by a third party: not feasible**: the dialog key is Call-ID plus both tags; the A-leg To-tag is a sipgo uuid v4 (cryptographic randomness, dialog_ua.go:35-45) and the B-leg From-tag is 12 bytes from crypto/rand (b2bua.go:1127-1137); a CANCEL requires the 16 random characters of the branch. The guessing space is at least 2^96.
5. **Header-level topology leakage: does not exist**: every header on the B-leg INVITE is newly constructed by the SBC or sipgo (From/Contact/Supported/SE/Min-SE plus fresh Via/Call-ID/CSeq/To); the A-leg's Via, From host, Call-ID, P-Asserted-Identity, Remote-Party-ID, History-Info, Record-Route, and Route are **never copied**. SDP attribute-level leakage is the exception (D1-4).
6. **Integer overflow (CSeq, Max-Forwards, duration headers): not feasible** (32-bit ParseUint with bound checks; headerSeconds yields 0 when Atoi fails).
7. **UDP reflection amplification: roughly 1:1, not a useful amplifier** (the response is about the size of the request, and its destination IP is fixed to the packet's source IP, so it cannot be aimed at an arbitrary third party).
8. **pion/sdp v3.0.19 crashes or exponential amplification: low risk** (a line-by-line state machine, linear in body size, with an upstream fuzz harness).

## Phase D - Untrusted Input Data Flow Tracing (source -> validation -> sink summary)

Each chain below is annotated with the line where validation is missing. Yes = validated, Partial = validation exists but has a gap, No = no validation.

| # | Source | Validation | Sink | Gap |
|---|--------|-----------|------|------|
| F1 | UDP/TCP/TLS SIP bytes | sipgo parser: 65535 datagram limit Yes; **TCP stream accumulation unbounded No** (parser_stream.go:117-121, D1-3) | parse -> transaction -> handler | Per-connection TCP memory is unbounded; parsing happens before the shield, so its cost is unprotected (D7-5) |
| F2 | Transport-layer source address | net.SplitHostPort + ParseAddr Yes; **no Unmap No** (sig/server.go:391-401, D7-4) | identify (allowed_ips match) -> peer trust; shield exemption; banList/nft key | Fail-closed on dual-stack listeners (no bypass), but kernel bans go to the wrong set; identify uses IP alone with no second credential (D1-2) |
| F3 | From header DisplayName/User | No sanitization at all No (b2bua.go:1089-1103 buildFrom passes through verbatim) | B-leg From header serialization | Bare LF and quote injection into the far end (D1-5); a missing From header causes a nil-deref panic (D1-8) |
| F4 | Request-URI user (called number) | Routing regex match Yes (when a route matches); **passes through verbatim with no match No** (routing.go:44-50); no character allowlist No | transformNumber -> B-leg Request-URI user | LF injection surface (D1-5); ReDoS does not apply (RE2) |
| F5 | Call-ID header | No length or character validation No (b2bua.go:1350-1355) | Keys of the registry, killers, and sdps maps (an attacker-controlled primary key); /api/calls JSON; WebUI textContent rendering | Key collisions interfere across calls (D6-9); XSS is ruled out (domain three ruled-out item 1); no length cap (D3-5) |
| F6 | User-Agent header | isScanner substring match Yes (11 fingerprints) | **Ban decision -> nft exec + kernel rule** (shield.go:81-86 -> nftables.go:75-85) | The decision runs before rate limiting No (D7-1); the ban target is the claimed source IP with no authenticity check No (D7-2) |
| F7 | INVITE body (SDP) | pion/sdp parsing + audio check Yes; remoteMediaIP rejects hostnames Yes (netip.ParseAddr, no DNS resolution) | SetExpectedRemote / latch arming; rewriteSDPCrypto rewriting | Attributes such as a=candidate pass through and leak (D1-4); the B-leg answer's c= is not cross-checked against the source IP (acceptable, since it is matched by transaction) |
| F8 | a=crypto line | parseCryptoAttrs validates strictly Yes (suite allowlist, base64, 30 bytes, MKI truncation, crypto.go:45-83) | NewSRTPContext | No gap; but replay protection is not enabled (D5-1, a library configuration issue on the sink side) |
| F9 | RTP/RTCP packets | latch.accept: strict IP match plus post-latch IP:port Yes; SSRC/PT/seq No (accepted by design, D5-3) | Cleartext forwarded verbatim (not parsed) Yes; SRTP pion unprotect Yes fail-closed | lastRx is refreshed before authentication (D5-4) |
| F10 | Admin HTTP requests | Basic Auth (bcrypt + constant time) Yes; bcrypt runs even without an Authorization header Partial (server.go:102-105, D3-3) | /api/* (including PUT configuration write-back: 1MiB limit + Parse validation + atomic write Yes), DELETE kick, /metrics | No failure rate limiting (D3-3); no Cache-Control (D3-1); missing response headers (D3-2) |
| F11 | PUT configuration body | 1MiB limit Yes, If-Match Yes (optional), config.Parse strict validation Yes (strict YAML + ENV + validate) | writeFileAtomic atomic write-back Yes | Permission bit inheritance (D4-3); TOCTOU (D4-4); alias bomb (D4-2, at the goccy layer) |
| F12 | Configuration file (local) | Load -> Parse -> validate Yes, strict; **no file size limit No** (loader.go:11-17, D4-7) | Store atomic publish Yes | Permissions unchecked (D8-7); fsnotify dies silently (D4-8) |
| F13 | DNS answers | SRV/A results become endpoints directly Partial (no filtering of Target "." or port 0, D8-2; no address-class warning, D8-3) | Outbound INVITE/REGISTER targets | No DNSSEC or pinning (D8-3); resolution has no ctx timeout (D8-1) |
| F14 | Stray SIP responses / malformed requests | Bypass the shield and identify entirely No (handled directly by the transaction layer) | One goroutine plus one Info log per packet; 400 responses; full-byte Error logs (D6-4) | Log flooding + broken silence promise + 1:1 reflection |
| F15 | Environment variables (${ENV} expansion) | Strict syntax; a missing variable rejects the whole file Yes (expand.go) | In-memory Config; logs, errors, and the API were all verified not to echo expanded values Yes | Resident in memory only (readable in-process, amplified by the root surface in D8-6) |

**Conclusion**: the configuration surface (F10-F12, F15) and the handling of cryptographic material (F8, the SDES lifecycle) show the best data-flow discipline; **validation on the signaling plane (F1-F6) is not pushed early enough** (parsing, identification, and ban decisions all happen at unprotected layers); the media plane (F7, F9) largely matches its design but has two library-level gaps (D5-1 replay protection and D5-4 timing before authentication).

### Suggested Fuzz Targets (the repository currently has zero fuzz coverage; these are suggestions only, and no files were added to the repository)

| Target | Suggested signature | Seed corpus | Motivation |
|------|----------|----------|------|
| SIP parsing boundaries | `func FuzzSipgoParser(f *testing.F)` (feeding both sipgo sip.ParseFSM and the stream parser) | RFC 3261 example messages; mutations with missing headers, bad Content-Length, bare LF, oversized headers, and malformed URIs | The parser-layer gaps behind D1-3/D1-5/D1-8; upstream sipgo has no public fuzz harness |
| SDP rewriting | `func FuzzRewriteSDP(f *testing.F)` (the sig package: input []byte -> rewriteSDP/rewriteSDPCrypto, asserting no panic and that the output re-parses) | pion/sdp test corpus + a=candidate/fingerprint, multiple m= sections, malformed c= | The attribute pass-through and rewriting paths of D1-4 |
| a=crypto parsing | `func FuzzParseCryptoAttrs(f *testing.F)` (the sig package, asserting no panic and either exactly 30 bytes or a discard) | RFC 4568 examples + bad base64/MKI, oversized input, empty suite | Robustness of SDES key handling |
| Configuration parsing | `func FuzzConfigParse(f *testing.F)` (the config package: input YAML -> Parse, asserting either an error or success and never a panic or hang) | sbc.example.yaml + anchor/alias bombs, deep nesting, duplicate keys, huge scalars | The goccy alias expansion gap in D4-2 (fuzzing can catch the stack overflow at the same time) |
| ${ENV} expansion | `func FuzzExpand(f *testing.F)` (the config package) | `${A}`, `${`, `$}`, nesting, empty names, oversized names | The reflect traversal in expand.go |
| RTP latch decisions | `func FuzzLatchAccept(f *testing.F)` (the media package: input source address bytes plus the expected address) | v4/v6/4-in-6/zone/invalid strings | Regression coverage for the normalization gap in D7-4 |
| Rate limiter | `func FuzzParseRateLimit(f *testing.F)` | Mutations of "20/s per_ip", empty strings, huge numbers | ParseRateLimit boundaries |

## Domain Two Findings (subagent report + main agent review)

> Main agent final verification: the one open link in D2-3 is now closed: sig/server.go:166-169 (NewUA with no TLS option) -> sipgo ua.go:14 (tlsConfig is the nil zero value), :100 -> transport_layer.go:130-132 (nil -> &tlsEmptyConf, a zero-value configuration) -> **outbound TLS peer certificate verification is confirmed enabled (system CAs, ServerName = hostname, TLS 1.2+ by default)**. The whole chain was verified against the local sipgo source. A model correction was also confirmed: the outbound digest client is sipgo's own (DoDigestAuth/WaitAnswer), and icholy/digest is test-only.

### [D2-1 + D1-2 merged] SIP identity = source IP with no challenge: over UDP, spoofing a peer IP grants full peer trust (toll fraud + rate-limit exemption)
- Severity: High (a trust model defect; exploitation requires spoofing capability or a malicious peer) / Confidence: High / Type: configuration risk / CWE-290, CWE-345
- Evidence: sig/server.go:363-369 (identify trusts only req.Source(); verified against sipgo transport_udp.go source that SetSource comes from the socket peer and is unrelated to Via); shield/shield.go:72-94 (peer exemption); sig/b2bua.go:83-87,186,297 (passing identify routes the call outbound).
- Impact: (1) toll fraud (the SBC ACKs the B-leg itself, so blind spoofing can produce a genuinely billable call of up to 5m); (2) spoofed-source OPTIONS reflection at roughly 1:1 (weak); (3) spoofed traffic has no rate ceiling. TCP/TLS is unaffected (a handshake must complete).
- Fix: use tcp/tls for inbound traffic from the internet; optionally add per-peer digest challenge or mTLS (tied to the TLS configuration items); have the shield keep a high quota for peers rather than exempting them entirely; document the uRPF requirement.

### [D2-2] allowed_ips validation has no width, non-empty, or canonicality constraint
- Severity: Medium / Confidence: High (width and non-emptiness verified; non-canonical prefixes unverified) / Type: configuration risk / CWE-129, CWE-284
- Location: config/validate.go:98-106 (each entry is parsed with no non-empty, width, or canonicality check), :257-266 (parsePrefixOrAddr does not call Masked()).
- Chain: `allowed_ips:[0.0.0.0/0]` -> validation does not reject it -> IdentifyPeer returns that peer for any IPv4 source -> combined with D1-2, any internet source can commit toll fraud. An empty allowed_ips makes AllowsIP always false (fail-closed, but still a footgun). `203.0.113.7/24` (intended as a single host) takes effect as a /24 (netip semantics).
- Fix: reject or warn on overly wide prefixes (on the order of IPv4 /16 and IPv6 /48); require non-empty; error on non-canonical prefixes or store Masked(). Regression: TestValidateRejectsWildcardPrefix and similar.

### [D2-3 + D1-11 + X2 merged] Missing TLS credential configuration surface: inbound is always self-signed (SDES has no protection against active MITM) and outbound has no configurable trust anchor
- Severity: Medium (the real impact is High when srtp is enabled and signaling is not verified TLS) / Confidence: High / Type: configuration risk, defense in depth / CWE-295, CWE-319
- Location: sig/tlscert.go:16-53 (a new self-signed certificate per process, with a comment acknowledging the absence of certificate configuration); sig/server.go:334-345; sig/b2bua.go:259-267,688-697 (warns only for non-TLS, so **transport=tls produces no warning at all**, and the self-signed certificate provides false reassurance); outbound verification is confirmed enabled but there is no per-peer CA or client certificate configuration.
- Key points: (a) inbound self-signing means the far end cannot verify the SBC, so an active MITM terminating TLS on both sides can read or replace a=crypto and decrypt "SRTP" media in real time; (b) outbound verification is enabled but no trust anchor can be configured, so carriers with self-signed or private CAs are unreachable (handshake failure -> 503) and operators are forced back to udp/tcp, putting SDES keys and digest credentials in cleartext while also closing off mTLS as a mitigation for D2-1; (c) MinVersion is not set explicitly (Go 1.25 already disables 1.0/1.1 by default, so this is not currently exploitable, but an explicit setting is recommended).
- Fix: add tls_cert/tls_key/client_ca (inbound) and peers.tls_ca/tls_client_cert (outbound); warn for self-signed certificates on tls transport too; set VersionTLS12 explicitly. Regression: TestOutboundTLSRejectsSelfSignedPeer.

### [D2-4 + D3-3 + D6-7 merged] Three compounding admin-plane weaknesses: cleartext HTTP Basic + no failure rate limiting + unconditional bcrypt
- Severity: Medium (High when admin.listen is exposed to an untrusted network) / Confidence: High / Type: confirmed vulnerability (when exposed) / CWE-319, CWE-307, CWE-770
- Full chain: sniff the cleartext Basic credentials -> `GET /api/config/raw` returns the entire configuration byte for byte (**every peer's cleartext SIP password**, ${ENV} references, the admin hash) -> `PUT /api/config` changes allowed_ips and routing -> combined with D1-2 and D2-2 this is a complete toll-fraud chain. CPU-DoS: full bcrypt runs even without an Authorization header (admin/server.go:102-105); online brute force has no lockout. validate.go:167-170 lets 0.0.0.0:8080 pass silently.
- Fix: Fatal or a loud Warn at startup for a non-loopback bind without TLS; admin TLS or a unix socket; return 401 immediately when the Authorization header is missing, skipping the KDF; per-IP failure rate limiting fed into the shield; fill in the missing timeouts.

### [D2-5] Outbound digest: challenge parameters are entirely remote-controlled, and a captured Authorization header allows offline dictionary attacks
- Severity: Medium / Confidence: Medium-High / Type: configuration risk, defense in depth / CWE-522, CWE-319
- Location: sig/register.go:96-105 (a single DoDigestAuth for REGISTER); sig/b2bua.go:819-823 (INVITE credentials go through WaitAnswer). realm, nonce, algorithm, and qop all come from the far end's 401/407; without TLS (udp by default) a passive capture can mount an offline dictionary attack against the RFC 2617 response value (MD5); without qop, a REGISTER with the same method and URI can be replayed while the nonce is valid. Credentials stay resident in memory in cleartext after ${ENV} expansion.
- Fix: pin auth.realm per peer; document password strength requirements; run signaling over TLS.

### [D2-6 -> merged into D6-9] (Call-ID-keyed overwrite semantics across three maps, the same finding as D6-9/D1-9; domain two adds that authentication on the DELETE route was verified and that an administrator kicking any call is by design)

### [D2-7] Outbound targets are determined by configuration plus DNS (SSRF-by-config, Low, with no unauthorized path to reach it; recorded for reference, connecting to the DNS poisoning chain in D2-5/D8-3)

### Suspicions Ruled Out in Domain Two (key points)
1. IPv4-mapped IPv6 bypassing AllowsIP: does not hold and is fail-closed (sipgo's raddr.String() canonicalizes 4-in-6 to dotted decimal -> ParseAddr yields Is4 -> it matches neither prefix family -> drop).
2. Via received/rport participating in identification: unreachable (identify reads only req.Source(); received and rport are never read anywhere in the repository).
3. Admin route authentication gaps (trailing slashes, %2F, method mismatches): checked one by one, and every route lands on requireAuth or an identically authenticated catch-all; covered by tests.
4. Basic Auth username enumeration: implemented correctly (constant-time comparison plus unconditional verification of both fields with bcrypt).
5. Outbound InsecureSkipVerify: zero occurrences, and the outbound path was verified in source to have verification enabled.
6. PUT write-back persisting expanded ${ENV}: it does not (verbatim). 7. handleUI path traversal: unreachable (the embedded filename is fixed). 8. CSRF triggering PUT: blocked by preflight (low-confidence reasoning, not verified in a browser). 9. /healthz: a fixed 19-byte JSON response.

## 5. Defense-in-Depth Recommendations (kept separate from vulnerabilities; a summary of the items marked "defense in depth" in the sections above)

1. **Pre-filter at the SIP entry point** (mitigates F-01/F-03/F-04/F-10 at once): use sipgo's `WithTransportLayerReadFilter` (transport_layer.go:72-77, currently unused) or drop non-allowlisted sources early with nftables, so that every byte from a non-peer source is blocked before parsing, transactions, and logging.
2. Uniform panic recovery across all SIP handlers (in the withShield wrapper) plus an explicit 400 for missing mandatory headers (D1-8).
3. Response header baseline: nosniff, X-Frame-Options: DENY, Referrer-Policy, and a minimal CSP; no-store on sensitive routes (to be done alongside the F-18 fix).
4. Admin: Host/Origin validation (defense in depth against DNS rebinding), a connection cap, and an evaluation of a session mechanism beyond cached credentials.
5. Cryptography: set MinVersion=TLS1.2 explicitly; pin the per-peer digest realm; optional a=ssrc pre-learning for SRTP sessions (D5-3); strip or rewrite RTCP CNAME (D5-7).
6. Operations and deployment: a least-privilege systemd sample (CAP_NET_BIND_SERVICE + CAP_NET_ADMIN, NoNewPrivileges, ProtectSystem, DynamicUser, D8-6); a 0600 configuration permission check with a warning (D8-7/D4-3); documentation on keeping peer domains from lapsing (F-21).
7. Supply chain: minimal CI (vet, test -race, govulncheck, a go.sum freeze check); releases built with -trimpath plus SBOM and signing (D8-5).
8. Observability: nft backend activation status, ban table watermark, per-peer concurrency and INVITE rate, and half-call count, all wired into metrics alerting.

## 6. Commands Run and Actual Results

See "Phase E - Verification Commands and Actual Results" above (go build/vet/test/-race/govulncheck/gosec all returned `command not found` with exit 127; this machine has no Go toolchain, and the skips are recorded faithfully; fuzz coverage check: zero fuzz targets).

## 7. Coverage

- **Code**: all 72 .go files in the repository (17,320 lines, of which 36 are production files and 36 are tests) were in scope across the eight domains, not just the recent diff. Distribution: main.go 1; admin 13 (6 production); callstate 2 (1 production); config 13 (7 production); media 9 (4 production); shield 10 (5 production); sig 24 (12 production). admin/webui/index.html (embedded, 522 lines) was also read line by line.
- **External entry points**: the Phase B inventory E1-E9 (SIP UDP/TCP/TLS, the RTP port pool, admin HTTP, the configuration file plus fsnotify, nftables exec, outbound DNS, outbound SIP/REGISTER) was reviewed in full.
- **Third party**: sipgo v1.4.3 (every key transport, transaction, parsing, dialog, and client file read line by line from the local copy), pion/sdp v3.0.19 (structural review), pion/srtp v3.0.12 (CreateContext default behavior verified upstream), goccy/go-yaml v1.19.2 (four key files: option, decode, parser, format, verified upstream), icholy/digest (confirmed test-only import), and a full text review of go.sum.
- **Data flows**: all fifteen classes of untrusted input in Phase D (F1-F15) were walked source -> validation -> sink.
- **High-value attack chains ruled out** (negative results matter too): stored and reflected XSS (complete textContent discipline), CSRF/CORS, CRLF/CR header injection (only bare LF works), Content-Length smuggling, cross-call BYE/ACK/CANCEL hijacking (tag entropy of at least 2^96), header-level topology leakage (zero header copying), ${ENV} expanded values reaching disk, logs, or the API, nft argv injection, Prometheus label injection, redaction gaps, IPv4-mapped IPv6 identification bypass (fail-closed), admin route authentication gaps (checked one by one), ReDoS (RE2), silent acceptance of duplicate or unknown YAML keys (strict rejection), media resource reclamation leaks (every error path verified), and recursive DNS SRV re-resolution.

## 8. Out of Scope and Evidence Gaps (including every ambiguity recorded)

1. **No Go toolchain** (the most important gap): build, vet, test, -race, govulncheck, and gosec were never run, so every concurrency-correctness and CVE conclusion is a source-level static judgment. `go test ./... -race` and govulncheck are the first priority once the toolchain is restored.
2. **Semantics not verified at runtime**: netip 4-in-6 behavior (the verification program for D7-4 is written and waiting to run: /tmp/freesbc-audit/netip-check/), the nft CLI's behavior for timeout "0s" and for ip6 saddr against IPv4 packets (blocked by the no-execution constraint), the actual behavior of the goccy alias bomb (D4-2), measured bcrypt timing (estimated at 60-130ms from published figures), and browser CSRF/preflight behavior (ruled out by reasoning).
3. **Parts of sipgo not read line by line**: the full transaction FSM table (panics and deadlocks under malformed or out-of-order input were not exhaustively explored) and TLS edge cases beyond ua.go -> transport (the verified chain is sufficient to support the conclusions).
4. **Unknown deployment surface** (assessed under the worst-case assumption): whether the target machine has the nft binary and the privileges for it (which determines whether F-03/F-04 are active); whether it runs as root; whether admin is bound to loopback as in the example; whether upstream uRPF exists (which determines how exploitable F-07 really is); and whether the deployment is multi-tenant (which determines the F-08 rating).
5. **Ambiguity resolution record**: (1) "does the shield rate limit before parsing?" - the implementation is at the handler layer, recorded as fact and filed as the F-10/D7-5 gap; (2) the design document's "re-INVITE authorizes Relatch" conflicts with the implementation (always 501) - assessed against the more conservative implementation, with the documentation accuracy issue recorded; (3) domains one and five disagreed on the F-06 precondition (how reachable spoofed sources are) and domains one and two disagreed on F-08 exploitability - the main agent adjudicated with reasons given (see the individual findings); (4) a subagent downloaded the sipgo and pion/sdp sources from their official GitHub tags for offline verification (read-only evidence gathering; no attack traffic was sent; domain two reported that its network degraded mid-review, after which it used the local copies).
5b. **Positive conclusions that depend on external source** (marked in the body): pion/srtp defaults to no-replay, sipgo's outbound TLS zero-value verification, and unbounded goccy alias expansion. All three have line-level evidence in local or upstream source, but none is in this repository's own code.

## 9. Remediation Plan

### Immediate (blockers for internet-facing deployment; complete before release)
1. F-01/F-10: readFilter pre-filtering or an equivalent (drop bytes from non-peer sources before parsing).
2. F-02: wrap the TCP/TLS listener with a maximum connection count, idle/read timeouts, and a stream accumulation cap.
3. F-03/F-05: move the scanner check after rate limiting, add a global cap or serialized queue on the ban write path, and enforce a hard cap on the ban table.
4. F-04: single-packet UDP decisions produce in-memory bans only; scope nft rules to SIP ports and protocols; add admin unban; change the nftables default to off.
5. F-06: per-peer concurrent-call and INVITE rate caps; validate the A-leg against spoofing (an ACK confirmation or digest) before dialing the B-leg.
6. F-07 mitigation (deployment strategy): expose only tcp/tls on the internet, or use an upstream allowlist plus uRPF; document the spoofing boundary of UDP plus IP-based authentication explicitly.
7. F-14 mitigation (deployment strategy): bind admin to loopback only; emit a loud warning at startup for a non-loopback bind without TLS.

### Within 7 days
8. F-08: validate the dialog ID (Call-ID plus both tags) in the refresh branch, returning 481 on mismatch.
9. F-09: SRTPReplayProtection(64)/SRTCPReplayProtection(128) (adjusting the pumpTransform test pump accordingly).
10. F-05 follow-up: set maxsize on the nft set. F-03 follow-up: use exec.CommandContext.
11. F-16: width and non-empty validation for allowed_ips. F-17: call Unmap uniformly in sourceAddr.
12. F-18: no-store on sensitive routes. F-14 follow-up: skip bcrypt when the Authorization header is missing, and add failure rate limiting. F-15: make admin credentials take effect on hot reload, or reject the change.
13. F-12: sanitize or allowlist characters in identity fields. F-11: apply an SDP attribute allowlist.

### Within 30 days
14. F-13: a TLS certificate, trust anchor, and mTLS configuration surface.
15. F-19: loose rate limiting for peers plus a per-peer INVITE cap. F-20: digest realm pinning and documentation.
16. F-21: an outbound TLS pinning option; DNS address-class warnings; singleflight plus timeouts (D8-1).
17. All Low and defense-in-depth items (the §5 list); full panic recovery coverage (D1-8); runtime verification of netip/nft behavior plus regression tests.
18. Establish CI (vet, test -race, govulncheck, go.sum freeze) and the §10 fuzz targets; re-run every command in §6 of this report once the Go environment is restored.

## 10. Highest-Priority Regression Tests and Fuzz Target List

**Regression tests (in fix priority order)**:
1. TestUDPPoolBoundedUnderUniqueSourceFlood (F-01; assert on the RSS curve)
2. TestTCPConnLimitAndIdleTimeout / TestTCPStreamAccumulationCap (F-02; slow-feed 1MB with no CRLF and assert a disconnect or bounded memory)
3. TestScannerBanRateLimited / TestNFTExecBounded (F-03; inject a run recorder, ban 1000 IPs concurrently, and assert the caps)
4. TestBanListCap (F-05; with a fake clock, inject more IPs than the cap and assert the table is clamped)
5. TestUDPScannerSinglePacketInMemoryBanOnly (F-04; assert nft is not invoked) plus TestAdminUnban
6. TestPeerInviteRateLimit / TestBlindSpoofInviteBYEsBlegOnAckTimeout (F-06)
7. TestRefreshReInviteWrongTagGets481 (F-08; with a wrong tag or wrong source, assert no answer is returned)
8. TestSRTPReplayDropped (F-09; replay the same packet twice and assert the second is dropped)
9. TestRequireAuthSkipsKDFOnMissingHeader / TestAdminAuthFailureRateLimit (F-14)
10. TestAdminAuthHotReloadRevokesOldPassword (F-15)
11. TestValidateRejectsWildcardPrefix / TestSourceAddrUnmaps4in6 (F-16/F-17)
12. TestBuildFromStripsLFAndQuotes / TestBInviteHasNoCandidateAttrs (F-12/F-11)
13. TestConfigNoStoreHeaders (F-18); TestMissingToFromInviteGets400 (D1-8)

**Fuzz targets**: see the "Suggested Fuzz Targets" table above (seven targets covering SIP parsing, SDP rewriting, a=crypto, configuration parsing, ${ENV} expansion, latch decisions, and the rate limiter, with signatures and seed corpora).

## Appendix: Inventory of Artifacts in /tmp/freesbc-audit/

| File/directory | Contents |
|-----------|------|
| main-agent-notes.md | Main agent cross-analysis notes (chains X1-X3, main verification record) |
| domain-1-notes.md ... domain-8-notes.md | The complete subagent reports for the eight domains (including every ruled-out item and its rationale) |
| sipgo-1.4.3/ (plus sipgo-1.4.3.tar.gz, sipgo-src/, sipgo.tgz) | A copy of the sipgo v1.4.3 official tag source (evidence for domains six and one, and the basis for the line-number references) |
| sdp-src/ (plus sdp-3.0.19.tar.gz) | A copy of the pion/sdp v3.0.19 source (evidence for domain one) |
| netip-check/ | The netip semantics verification program for D7-4 (written and waiting for a Go environment) |
| sipgo-transport.go | An early evidence excerpt from domain two |
| fixes/ (README + drafts 01-03) | Draft remediation patches (produced late in the session from a misread instruction: F-01/F-10 readFilter, F-02 TCP throttling, F-03/F-05 shield throttling and caps; **uncompiled and unreviewed reference drafts**, not part of this audit's deliverables) |

(The only new file inside the repository is this report, SECURITY-AUDIT-20260826.md; no production code was modified.)

> Note: the Phase A/B/E process records, the detailed evidence for domains one through eight, and the Phase D data flow table together constitute §4 (embedded in the order the subagents finished, not in numeric order); the D-series IDs are the merge sources listed in the §3 summary table and can be traced item by item.
