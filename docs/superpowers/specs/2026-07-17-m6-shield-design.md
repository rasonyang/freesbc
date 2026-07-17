# FreeSBC M6 — Shield (Rate Limiting, Scanner Detection, Auto-Ban) Design

The security-hardening milestone: a front-door shield that rate-limits per source
IP, fingerprints known SIP scanners by User-Agent, and auto-bans abusive sources
via an in-memory ban table with optional nftables kernel-level enforcement. Every
inbound SIP request passes the shield before anything else, and every denial is a
silent drop. Parent spec: `freesbc-allinone-design.md` (§68: 每 IP 限速、扫描器 UA
指纹、失败阈值自动封禁、内存封禁表、可选联动 nftables，nftables 非硬依赖; §117:
`shield.Check(srcIP, msg) Verdict` middleware). M1–M5 complete and merged.

## 0. Reality baseline (existing code)

- Every inbound request reaches a handler that calls `identify(req)` (source-IP →
  peer via `IdentifyPeer`/`allowed_ips`): `onOptions`, `onInvite` (identify
  inside), `onAck`, `onBye`, and `onNoRoute` (the catch-all for every other
  method). An unidentified source → `dropUnidentified(req)` (silent drop, logs
  Info). `dropUnidentified` is already tagged "the shield seam (M6)".
- Config is scaffolded and validated: `ShieldConfig{RateLimit string, AutoBan
  {Failures int, Window, Duration}, NFTables string}`. `ParseRateLimit` parses
  `"<n>/<s|m|h> [per_ip]"` into `RateLimit{Rate, Interval, PerIP}`. Defaults:
  `rate_limit: 20/s per_ip`, `auto_ban: {failures:5, window:60s, duration:1h}`,
  `nftables: auto`. Validation already bounds `failures>=1`, `window>0`,
  `duration>0`, `nftables ∈ {auto,on,off}`.
- `Server` is built in `Run` and holds `store`, `resolver`, `health`, `registrar`
  etc.; hot-reload via `store.Current()`; deterministic shutdown sequencing.
- Dependencies: no rate-limiter or firewall library. M6 adds NO new Go dependency
  (hand-rolled token bucket; nftables via `os/exec` shell-out).

## 1. Decisions (confirmed 2026-07-17)

1. **Configured peers are fully exempt from the shield.** A source whose IP
   matches any peer's `allowed_ips` is allowed immediately — no rate limit, no
   scanner-UA ban, no failure counting. Trusted trunks legitimately burst and
   must never be throttled or banned. (Rejected: uniform rate limiting.)
2. **Ban signals.** A request from an unidentified (non-configured) source
   increments that IP's failure counter; N failures in the window → ban. A
   matched scanner User-Agent is a definitive attacker → **instant ban**, no
   counting. A rate-limit violation is a **silent drop only**, NOT a ban signal.
3. **Verdict = Allow | Drop, always silent.** A denied request gets no SIP
   response — a scanner receives no confirmation the SBC exists.
4. **nftables is an optional accelerator, in-process is the baseline.** Bans are
   always enforced in-process (cross-platform). `off`/`on`/`auto` controls a thin
   `nft` shell-out that also drops banned sources at the kernel. `nft` calls go
   through an injectable exec function.
5. **No new dependency.** Hand-rolled per-IP token bucket; nftables via `os/exec`.

## 2. Components & module layout

| File | Responsibility |
|---|---|
| `shield/shield.go` (new) | `Shield` type; `New(cfg, log) *Shield`; `Check(src netip.Addr, userAgent string) Verdict`; `RecordUnidentified(src netip.Addr)`; `Close() error`; `Reload(cfg)`. Owns the rate limiter, failure counter, ban table, scanner matcher. |
| `shield/ratelimit.go` (new) | `rateLimiter`: per-IP (or global) token bucket; `allow(src) bool`; injectable clock. |
| `shield/banlist.go` (new) | `banList`: in-memory `map[netip.Addr]time.Time` (ban-until, lazy expiry, injectable clock) + the nftables backend (setup / add-ban / teardown via an injectable `exec` func). `ban(ip, dur)`, `banned(ip) bool`. |
| `shield/scanner.go` (new) | Built-in scanner User-Agent substring list; `isScanner(ua string) bool` (case-insensitive). |
| `sig/server.go` | Construct the `Shield` in `Run`; call `Check` at the top of each handler before `identify`; `RecordUnidentified` in `dropUnidentified`; `Close()` on shutdown; re-read config on hot-reload. |

`Verdict` is a small enum (`Allow`, `Drop`). The failure counter (auto-ban) lives
in `shield.go` (a per-IP sliding-window count keyed to `AutoBan.Window`).

## 3. The Check flow

`Check` runs at the very front of every inbound request, before `identify`:

```
Check(src, ua) Verdict:
    if isConfiguredPeer(src):  return Allow      // §1: trusted trunk, fully exempt
    if banList.banned(src):    return Drop        // kernel also drops if nftables on
    if scanner.isScanner(ua):  banList.ban(src, cfg.AutoBan.Duration); return Drop  // §2 instant
    if !rateLimiter.allow(src): return Drop       // §2 throttle, NOT a ban signal
    return Allow
```

`isConfiguredPeer(src)` is a cheap lookup over the current config's peers'
`allowed_ips` (the shield holds a config snapshot; reused/mirrors
`IdentifyPeer`'s check). Then the normal handler runs `identify(req)`. A
non-configured source that Check allowed fails identify → `dropUnidentified` →
`RecordUnidentified(src)`:

```
RecordUnidentified(src):
    n := failure count for src within cfg.AutoBan.Window (incremented now)
    if n >= cfg.AutoBan.Failures:
        banList.ban(src, cfg.AutoBan.Duration)
        log Warn "auto-banned source" src, failures, duration
```

**Self-reinforcing:** a slow scanner (1 req/s from an unknown IP) is not
rate-limited, so every request is unidentified and counted → banned after
`failures` within `window`. A flood (1000 req/s) is throttled to the rate limit
(excess dropped, not counted), and the requests that pass the throttle are
unidentified and counted → banned within the window. Once banned, Check drops
every further request before it reaches a handler.

Rate-limit drops happen in Check BEFORE `identify`/`dropUnidentified`, so they
never increment the failure counter (decision 2: rate-exceeded is a drop, not a
ban signal).

## 4. Rate limiter (`ratelimit.go`)

A token bucket per source IP (`per_ip` true) or one global bucket (`per_ip`
false), from `RateLimit{Rate, Interval, PerIP}`:

- Bucket capacity = `Rate` (the burst); refill = `Rate` tokens per `Interval`
  (e.g. 20 tokens/second). `allow(src)`: lazily create the bucket, refill by
  elapsed time since last check (`min(cap, tokens + elapsed/Interval*Rate)`),
  consume one token if available (return true) else false.
- `map[netip.Addr]*bucket` under a mutex (global bucket = a single `*bucket`).
  Injectable `now func() time.Time` for deterministic tests. A periodic/lazy
  prune drops buckets untouched for a while (bounded memory).
- Configured-peer exemption in `Check` means trunk IPs never reach the limiter.

## 5. Ban table + nftables (`banlist.go`)

**In-memory (authoritative, always on):** `map[netip.Addr]time.Time` (ban-until)
under a mutex, lazy expiry on read (`banned(ip)` returns false and deletes once
`now >= until`), injectable clock. `ban(ip, dur)` sets `until = now + dur` and,
if nftables is active, calls the backend.

**nftables backend (optional, `off`/`on`/`auto`):** a thin `os/exec` wrapper
around the `nft` binary, all commands routed through an injectable
`run func(args ...string) error` (tests inject a recorder; production runs `nft`).

- **Setup** (at `New`, if enabled+available): create a managed ruleset —
  `nft add table inet freesbc`; `nft add set inet freesbc banned4 { type
  ipv4_addr; flags timeout; }`; `nft add set inet freesbc banned6 { type
  ipv6_addr; flags timeout; }`; `nft add chain inet freesbc input { type filter
  hook input priority -1; }`; `nft add rule inet freesbc input ip saddr @banned4
  drop`; `nft add rule inet freesbc input ip6 saddr @banned6 drop`. Idempotent
  (delete-then-add the table, or tolerate "exists").
- **Ban:** `nft add element inet freesbc banned{4,6} { <ip> timeout <dur>s }` —
  the kernel drops the source before the process parses its packets, and the
  element's timeout auto-expires the kernel ban in step with the in-memory one.
- **Teardown** (`Close`): `nft delete table inet freesbc` — remove our entire
  ruleset, leave no residue.

**Availability & mode:**

- `off` → never touch nft; in-process only.
- `on` → require nft; if the `nft` binary is missing or a setup command fails
  (no permission), log an error and continue in-process-only (never fail server
  startup). Bans are still enforced in-process.
- `auto` → enable only when the `nft` binary is found (`exec.LookPath`) and setup
  succeeds; otherwise silently in-process only (the normal case on macOS/dev and
  unprivileged Linux).

nftables enforcement is best-effort hardening layered on top of the always-present
in-memory ban; a failure anywhere in the nft path never breaks banning or the SBC.

## 6. Scanner detection (`scanner.go`)

A package-level list of known SIP-scanner User-Agent substrings (lowercased),
matched case-insensitively against the request's `User-Agent` header value:
`friendly-scanner`, `sipvicious`, `sipcli`, `sip-scan`, `sundayddr`,
`vaxsipuseragent`, `sipsak`, `iwar`, `sivus`, `smap`, `pplsip` (well-known
signatures only — deliberately no overly-generic substring like bare "scanner"
that could match a legitimate product's UA). `isScanner(ua)` returns true on any
substring match; an absent/empty UA is not a match. A match → instant ban (§3).
The list is a constant for M6; config-extendable patterns are deferred.

## 7. Wiring (`sig/server.go`)

- Build the `Shield` in `Run` (after the config snapshot, alongside
  resolver/health/registrar): `s.shield = shield.New(cfg, s.log)`. `defer
  s.shield.Close()` for nftables teardown.
- At the top of each handler (`onOptions`, `onInvite`, `onAck`, `onBye`,
  `onNoRoute`), before `identify`:
  ```go
  src := sourceAddr(req)                       // parse req.Source() → netip.Addr
  if s.shield.Check(src, userAgent(req)) == shield.Drop {
      return                                     // silent
  }
  ```
  `userAgent(req)` reads the `User-Agent` header (empty if absent).
- `dropUnidentified(req)` calls `s.shield.RecordUnidentified(src)` (in addition
  to its existing Info log).
- Hot-reload: on a config change, `s.shield.Reload(newCfg)` updates the rate
  limit, auto_ban params, nftables mode, and peer-exemption snapshot. (A change
  of nftables mode across reload re-runs setup/teardown as needed; keep it simple
  — the common case is params changing, not the mode.)
- Ban and scanner-match events log at Warn; rate-limit drops at Debug (avoid a
  log flood under attack — the drop itself is the mitigation).

## 8. Error handling

| Scenario | Behavior |
|---|---|
| `nftables: on`, `nft` missing / no permission | Log error; in-process ban still enforced; startup continues |
| `nftables: auto`, no `nft` / not privileged | Silently in-process only |
| `nft` element-add fails at ban time | Log Debug; keep the in-memory ban (kernel drop skipped) |
| `nft` teardown fails at shutdown | Log; continue shutdown |
| Absent/malformed `User-Agent` | Not a scanner match; no crash |
| Unparseable `req.Source()` | The shield can't make an IP-based decision, so it returns Allow and defers to `identify` (which also can't resolve the source and will `dropUnidentified` it) — never panic |
| Ban table / bucket / counter growth | Lazy expiry on read + periodic prune; bounded memory |
| Configured-peer source | Exempt from rate limit, scanner ban, and failure counting |

## 9. Testing

- **`ratelimit.go`:** token-bucket refill/exhaustion/burst with an injectable
  clock; per_ip isolation (one IP's exhaustion doesn't throttle another); global
  (`per_ip:false`) single bucket.
- **`scanner.go`:** each known scanner UA matches (case-insensitive); legit UAs
  (a real softphone/carrier UA) don't; empty UA doesn't.
- **`banlist.go`:** ban → `banned` true; expiry (injectable clock) → false +
  entry pruned; nftables backend with an injected `run` recorder — assert the
  exact `nft` argv for setup/ban(with timeout)/teardown; `off`→zero calls;
  `on`-unavailable→error surfaced but in-process ban intact; `auto`-unavailable→
  silent, in-process only.
- **`shield.go`:** the `Check` verdict matrix — configured-peer→Allow;
  banned→Drop; scanner-UA→Drop (and now banned); rate-exceeded→Drop; otherwise
  Allow. `RecordUnidentified` → ban exactly at the Nth failure within the window;
  failures aging out of the window don't trip the ban.
- **Integration** (`sig` front door): a burst of unidentified requests from one
  IP → after `failures` the source is banned and further requests are dropped by
  Check before reaching a handler (observable: no 404/405, silence); a
  scanner-UA request → instant ban; a configured peer at high rate → never
  throttled and its calls bridge (regression); a normal identified call is
  unaffected. nftables mode `off` in tests (no kernel interaction).
- Full `go vet ./... && go test ./... -race` stays green; no regression to
  M3–M5 (identify/drop guarantee, bridge, SRTP, DNS-SRV/health).

## 10. Scope

**In M6:** per-IP (and global) rate limiting with configured-peer exemption;
scanner User-Agent fingerprint instant-ban (built-in list); failure-threshold
auto-ban (unidentified-source counter, N-in-window) with an in-memory,
lazy-expiring ban table; optional nftables shell-out linkage (`off`/`on`/`auto`,
managed ruleset, per-element timeout expiry, shutdown cleanup, injectable exec);
`Shield.Check` wired before `identify` on all five handler paths; silent-drop
verdicts; hot-reload of shield params.

**Deferred (documented non-goals):**
- Config-extendable / per-peer scanner list (built-in list only).
- Per-peer shield overrides.
- Persistent (across-restart) ban table (in-memory only; nftables kernel bans
  persist in the kernel until teardown/timeout).
- nftables via a netlink library (shell-out to `nft` only).
- Rate-limiting identified/configured peers (they are exempt).
- Prometheus metrics / an admin view of shield decisions (M7).
- Distributed/shared ban state across instances.
- Any SIP-level response to an attacker (all denials are silent drops).
- Deep-packet / content heuristics beyond UA fingerprinting and the
  unidentified-source signal.
