# Phase 2 — internal/shield

Scope: `internal/shield/*.go` (production files: `shield.go`, `banlist.go`,
`ratelimit.go`, `scanner.go`, `nftables.go`) and its call sites
(`internal/trunk/server.go:423-471`, `internal/edge/edge.go:188,506-521`,
`internal/app/app.go:166-193`, `internal/admin/server.go:410-418`).
Method: reading only (every finding below is INFERENCE). `go vet ./internal/shield/` is clean.

## Findings

### P2-SHD-001 — A single spoofed UDP datagram bans any IP from the edge plane for 1 h, and nothing can lift the ban
- Severity: P0 (security on a public path: third-party denial of service)
- Layer: transport
- Label: INFERENCE
- Location: `internal/shield/shield.go:129-136`, `internal/shield/shield.go:147-150`, `internal/edge/edge.go:516-519`, `internal/app/app.go:166,182-188`
- Evidence:
  ```go
  // shield.go:129
  if isScanner(userAgent) {
      if !s.bans.ban(src, cfg.Shield.AutoBan.Duration.Std(), kernelSync(transport)) {
  ```
  ```go
  // shield.go:141-145
  // A UDP verdict rests on one forgable datagram, so it
  // stays memory-only — a spoofed packet must not be able to kernel-blackhole
  // a victim's IP.
  ```
  ```go
  // app.go:166 — edge-only / default wiring
  Unban:    func(string) bool { return false },
  ```
- Description: `kernelSync` keeps a UDP scanner verdict out of nftables because
  the source can be forged. The in-memory ban is still recorded, though, and on
  the edge plane that ban is enforced for every later request from the IP
  (`guard` → `Check` → `bans.banned` → silent Drop). One spoofed UDP packet with
  `User-Agent: friendly-scanner` and the source address of a customer's NAT
  therefore cuts off every phone behind that address (REGISTER refreshes,
  INVITE, BYE) for `shield.auto_ban.duration` (default 1 h,
  `internal/config/schema.go:319-320`). The kernel-only safeguard stops the
  wrong layer. The ban cannot be lifted: the edge shield is not wired into
  `admin.Deps` (`app.go:166-193`, and docs/design.md §14.2 says so). Because
  every forged source is new, 65,536 forged datagrams also fill the ban table
  (`banlist.go:59-73`), after which every real scanner ban is refused for the
  rest of the ban window.
- Invariant/doc reference: docs/design.md §14.1 ("a forgeable datagram must
  not kernel-blackhole a third party"). The docs treat the kernel as the only
  thing to protect and do not mention that a memory ban has the same effect on
  the edge.
- Confirming test: a shield unit test calling
  `Check(victim, "friendly-scanner", "udp")` and then
  `Check(victim, "Yealink SIP-T46S", "udp")` and expecting `Allow`, which will
  fail. An edge harness test that sends one scanner-UA OPTIONS over UDP from
  127.0.0.1 and then a normal REGISTER from 127.0.0.1, expecting a response,
  which will time out.
- Action: fix (make UDP scanner verdicts drop-only with no ban, or ban the
  source port rather than the IP; wire an edge unban/metrics path).

### P2-SHD-002 — Per-IP rate-limit bucket map and fail-counter map have no size cap; a unique-source flood grows them for up to one minute per entry
- Severity: P0 (memory growth driven by attackers on the public edge path)
- Layer: transport
- Label: INFERENCE
- Location: `internal/shield/ratelimit.go:20-25,41-46,66-77`, `internal/shield/shield.go:268-306`, `internal/shield/shield.go:241-255`
- Evidence:
  ```go
  // ratelimit.go:41
  if perIP {
      b = r.buckets[src]
      if b == nil {
          b = &bucket{tokens: float64(rate), last: now}
          r.buckets[src] = b
  ```
  ```go
  // ratelimit.go:73 — the only eviction, run once a minute from pruneLoop
  if now.Sub(b.last) >= time.Minute {
      delete(r.buckets, ip)
  ```
- Description: every distinct source that passes the ban check allocates a
  bucket (a map entry plus a heap `*bucket`). Nothing removes it until it has
  been idle for at least 1 minute and the next minute tick runs, so an entry
  can live for close to 2 minutes. `banList` has a hard cap (`banCap`), but the
  bucket map does not, and docs/design.md:2215 confirms "no cap on the map".
  On the edge public UDP listener, source addresses are forgeable. On IPv6, a
  single attacker controls a /64 of distinct legitimate sources, which needs
  no spoofing at all. So memory grows linearly with packet rate: 100 kpps of
  unique sources gives about 6–12 M live entries. `prune` is O(n) under
  `r.mu`, the same mutex that `allow` takes on every request, so each tick
  also stalls all SIP handling for the length of a full-map scan. The
  per-IP limit also has no aggregate ceiling, so a /64 bypasses it entirely.
  `failCounter.hits` (`shield.go:271`) has the same shape, but no production
  code path feeds it (see SHD-004).
- Invariant/doc reference: docs/design.md:2215. The `banCap` rationale at
  `banlist.go:10-13` says the table "must not grow the table without bound",
  and the rate limiter breaks that rationale.
- Confirming test: a shield unit test that calls `Check` with 200,000
  distinct IPv6 addresses from one /64 and asserts
  `len(s.limiter.buckets) <= banCap`, which will fail. An optional variant
  measures `runtime.MemStats.HeapAlloc` before and after.
- Action: fix (a capped LRU or a sharded fixed-size table; key IPv6 by /64;
  add a global ceiling on non-peer traffic).

### P2-SHD-003 — `prune` resets partly drained buckets for intervals longer than 1 minute, bypassing `N/h` limits
- Severity: P1 (security control weaker than configured; P0 criteria apply only with a non-default `/h` config)
- Layer: transport
- Label: INFERENCE
- Location: `internal/shield/ratelimit.go:63-77`, `internal/config/types.go:142-143`
- Evidence:
  ```go
  // ratelimit.go:71-75
  // (recomputing here avoids needing a stored rate — a bucket last
  // touched long ago is full regardless of rate.)
  if now.Sub(b.last) >= time.Minute {
      delete(r.buckets, ip)
  ```
- Description: `ParseRateLimit` accepts the `h` unit (`Interval = time.Hour`).
  With `rate_limit: "10/h per_ip"`, a source that spends all 10 tokens and
  then idles for 1–2 minutes has refilled only about 0.17–0.33 tokens. `prune`
  deletes the bucket anyway, and the next `allow` creates a fresh bucket with
  10 tokens. The effective limit becomes about 10 per 1–2 minutes instead of
  10 per hour, a 30–60× bypass. The code comment's premise ("full regardless
  of rate") is false whenever `interval > 1m`. For `/s` and `/m` it holds.
- Invariant/doc reference: docs/design.md §5.3 and §14.1 (token bucket,
  "capacity equals the rate").
- Confirming test: inject `now` into `rateLimiter`. Drain a `10/h` bucket,
  advance the clock 61 s, call `prune()`, then expect `allow` to return false,
  which will fail.
- Action: fix (evict only when `elapsed >= interval` for the bucket's own
  interval, by storing the interval in the bucket).

### P2-SHD-004 — The auto-ban counter, trunk ban/scanner branches and the whole nftables backend never act in production
- Severity: P2 (dead code; also gives a false sense of security)
- Layer: transport
- Label: INFERENCE (docs/design.md:2523-2530 and §14.1 state the same thing)
- Location: `internal/shield/shield.go:176-191` (`RecordUnidentified`), `internal/shield/shield.go:268-306` (`failCounter`), `internal/shield/nftables.go:1-245`, `internal/trunk/server.go:461-471`
- Evidence:
  ```go
  // trunk/server.go:448-452
  // This handler never runs for udp/tcp/tls traffic: the
  // pre-parse read filter drops non-peer bytes before parsing, ...
  ```
  `RecordUnidentified` has one caller, `trunk.dropUnidentified`, which is
  unreachable. Only the trunk shield has a kernel backend (`shield.go:77-79`),
  but the trunk shield only ever sees configured peers. Peers are exempt from
  `ban` (`shield.go:110-118`), so `nftBackend.ban` is never called in a
  deployed system.
- Description: `shield.auto_ban.failures/window` configure nothing reachable.
  On `nftables: auto|on` the trunk plane still installs an `inet freesbc`
  table with an input chain at priority -1, starts a worker goroutine,
  requires CAP_NET_ADMIN, and on every startup deletes any pre-existing
  `inet freesbc` table (`nftables.go:135`). None of it ever adds an element.
  The plane that does ban (edge) has no kernel path and no admin surface.
- Invariant/doc reference: docs/design.md §12.4, §14.1 (documented as a
  limitation, so this is not docs drift).
- Confirming test: `deadcode`-style reachability; an integration test that
  sends N unidentified packets to a trunk listener and expects
  `ShieldStats().BannedCurrent == 1` (will stay 0).
- Action: delete (the trunk kernel backend and `RecordUnidentified`), or
  rewrite so the edge shield owns the ban/kernel plane.
- Decision (2026-09-24): delete; the ban/kernel plane is not moved to the
  edge shield. Remove `nftables.go`, the `shield.nftables` key, the
  `inet freesbc` table and the CAP_NET_ADMIN requirement,
  `RecordUnidentified`, `failCounter` (and its prune call at
  `shield.go:253`), `trunk.dropUnidentified` (its call sites keep a silent
  drop), and `shield.auto_ban.failures` / `auto_ban.window`. Keep
  `auto_ban.duration`, which the edge scanner ban uses (`shield.go:130`).
  The in-memory ban list, both rate limiters and scanner detection stay;
  the edge shield (`NewNoKernel`) is unchanged. Rationale: the trunk
  pre-parse filter admits only `allowed_ips` peers and peers are exempt
  from bans, so the kernel ban is never called; deletion removes no
  production protection. SHD-007 and SHD-010 become moot. Open follow-up:
  `DELETE /api/bans/{ip}` and the ban metrics stay wired to the trunk
  shield only (always empty); decide separately whether to remove them or
  wire them to the edge shield.

### P2-SHD-005 — Trunk peer `allowed_ips` are exempt from the edge plane's ban and scanner checks
- Severity: P2
- Layer: transport
- Label: INFERENCE
- Location: `internal/shield/shield.go:108-118`, `internal/shield/shield.go:259-266`, `internal/edge/edge.go:516-517`
- Evidence:
  ```go
  cfg := s.store.Current()
  if isConfiguredPeer(cfg, src) {   // cfg.Peers = trunk peers
      rl := s.peerRateLimit(cfg)
  ```
- Description: `Check` is shared by both planes, and its peer test reads
  `cfg.Peers`, the trunk plane's peer list. When both planes are configured,
  a source inside any trunk peer's `allowed_ips` reaching the edge public
  listener skips the ban and scanner checks and gets the looser 200/s limit.
  Over UDP that source is forgeable (docs/design.md §14.2 already notes that a
  forged peer IP inherits trust on the trunk). Edge trust should not follow
  from trunk peer membership.
- Invariant/doc reference: CLAUDE.md "Edge private plane is trusted and exempt
  from the shield". Only the private plane is meant to be exempt on the edge.
  docs/design.md §14.1 item 1 describes the peer exemption without saying which
  plane it applies to.
- Confirming test: a config with both planes where a peer's `allowed_ips`
  includes 127.0.0.1. Send a scanner-UA request to the edge public UDP
  listener from 127.0.0.1 and assert that a following request is dropped
  (it will not be).
- Action: fix (pass the plane's exemption predicate into `Shield`, or use
  `NewNoKernel` with no peer exemption).

### P2-SHD-006 — A ban does not close an existing TCP/WS/WSS connection
- Severity: P2
- Layer: transport
- Label: INFERENCE
- Location: `internal/shield/shield.go:119-137` (verdict only), `internal/edge/edge.go:517-519`
- Description: `Check` returns a verdict. Callers return silently and do not
  close the stream, so a banned WS/WSS client keeps its connection. With no
  connection cap and no idle timeout on ws/wss (docs/design.md §14.2), every
  message it sends is still read, parsed and checked. On the edge, where
  there is no kernel backend, the ban saves the handler cost but not the
  connection or parse cost.
- Confirming test: an edge WS harness that sends a scanner UA and then
  asserts the server closes the socket within 1 s (it will not).
- Action: fix (on Drop for a stream transport, close the connection).

### P2-SHD-007 — A failed nftables setup leaves a partial `inet freesbc` table behind
- Severity: P2
- Layer: config/lifecycle
- Label: INFERENCE
- Location: `internal/shield/nftables.go:80-85`, `internal/shield/nftables.go:173-177`
- Evidence:
  ```go
  if err := n.setup(); err != nil {
      if mode == "on" { log.Error(...) }
      return nil
  }
  ```
- Description: `setup` runs its commands in order and returns on the first
  error. The table, the sets, or the priority -1 input chain may already
  exist at that point. `newNFTBackend` returns nil without running
  `delete table`, and because the backend is nil, `Shield.Close` never tears
  anything down (`shield.go:210`). The leftover table survives process exit.
  Its sets are empty so it drops nothing, but it contradicts §12.4's
  statement that kernel state does not survive a restart. In `auto` mode the
  failure is not logged at all.
- Confirming test: inject `run` so the 5th command fails, then assert a
  `delete table` call was issued (it will not be).
- Action: fix.
- Decision (2026-09-24): moot; SHD-004 deletes the nftables backend.

### P2-SHD-008 — Code comment and design doc say bans are "extended"; code overwrites the expiry and can shorten it
- Severity: P2 (docs-code drift)
- Layer: docs
- Label: INFERENCE
- Location: `internal/shield/banlist.go:47` ("extending any existing ban") vs `internal/shield/banlist.go:75`; docs/design.md:2214 ("banned (extendable)")
- Evidence: `b.until[ip] = b.now().Add(dur)` sets the expiry unconditionally.
  After a hot reload that lowers `auto_ban.duration`, a re-ban shortens an
  existing ban. Any re-ban also resets the expiry rather than taking
  `max(old, new)`. The kernel element is re-added with `add element`, which
  does not refresh an existing element's timeout, so memory and kernel expiry
  diverge.
- Action: fix (use max) or correct the doc.

### P2-SHD-009 — Admin unban does not unmap IPv4-mapped IPv6 input
- Severity: P2
- Layer: admin
- Label: INFERENCE
- Location: `internal/app/app.go:183-187`, `internal/shield/shield.go:198-204`
- Description: ban keys are unmapped (`fsip.ParseHostPortAddr` →
  `addr.Unmap()`, `internal/sip/addr.go:47`). `DELETE /api/bans/::ffff:1.2.3.4`
  parses to a mapped address, misses the entry, returns 404, and issues an nft
  delete against `banned6`. Minor, because a correct IPv4 literal works.
- Action: fix (`addr.Unmap()` in the dep or in `Shield.Unban`).

### P2-SHD-010 — An `auto_ban.duration` under 1 s becomes nft `timeout 0s`
- Severity: P2
- Layer: config/lifecycle
- Label: INFERENCE
- Location: `internal/shield/nftables.go:212`, `internal/config/validate.go:261-262` (validation checks only `> 0`)
- Description: `strconv.Itoa(int(dur.Seconds()))` truncates, so `500ms` gives
  `"0s"`. nft either rejects the element (logged at Debug and swallowed) or
  treats 0 as no timeout, depending on the version. The memory and kernel
  copies disagree either way. Unreachable today because of SHD-004.
- Action: fix (round up, or validate `>= 1s`).
- Decision (2026-09-24): moot; SHD-004 deletes the nftables backend.

## Checklist items found clean
- Denials are silent drops. `trunk.withShield` (`trunk/server.go:441-443`)
  and `edge.guard` (`edge/edge.go:516-519`) both `return` with no response on
  `Drop`. The only response in those wrappers is the panic 500, which is not
  a denial.
- Goroutine exit paths: `pruneLoop` exits on ctx cancel and closes `done`
  (`shield.go:241-255`). The nft `worker` exits on ctx cancel (`nftables.go:103-112`).
  Both are joined in `Close`/`stopWorker`. `Close` is idempotent.
- Locks across I/O: `banList.ban` releases `b.mu` before enqueuing the nft
  request (`banlist.go:76-79`). No exec runs under any shield mutex.
  `Shield.Unban` execs synchronously for up to 2 s with no lock held, as
  documented in design §11.4.
- Channel send under lock: none. The nft enqueue is a non-blocking `select`
  with `default` (`nftables.go:198-202`).
- `time.After` in loops or `time.Sleep` for sync: none. A single `time.Ticker` is stopped by defer.
- Unsynchronised shared maps: none. Every map is guarded by its struct's mutex. Counters are atomic.
- nft command injection: none. It uses `exec.CommandContext` with argv (no
  shell), and the only interpolated values are `netip.Addr.String()` and
  integers.
- nft exec timeout: every call goes through `execWithTimeout` (2 s).
- Ban table bound: `banCap` 65536 with a rate-limited sweep (`banlist.go:59-73`). See SHD-001 for how it fills.
- `_ = err`: only `nftables.go:135` (best-effort `delete table` before setup), which is intentional and commented.
- `recover()`: none in this package.
- Single-implementation interfaces, `any`/`interface{}`, defer in loops: none.
- Config snapshot: `Check` and `RecordUnidentified` each read `store.Current()` once per request.
- Hot reload vs restart-only: `rate_limit`, `peer_rate_limit` and `auto_ban.*`
  are read per call. The nftables mode and port scope are fixed at
  construction, which matches design §4 (docs/design.md:341) and §12.4.
- `NewNoKernel`: builds identical in-process structures with `bl.nft == nil`,
  so `ban` never enqueues, and `Unban`/`Close` nil-guard the backend. It is
  correct as documented. Its weaknesses are SHD-001 and SHD-005.
- Per-RTP-packet work: not applicable. The shield runs per SIP request only.
- SIP/SDP RFC checklist items (transactions, dialogs, ACK, CANCEL, forking,
  SDP): not applicable to this package.

## Out of scope, noted
- `kernelSync("ws"/"wss")` returns false even though WS is connection-oriented.
  This has no effect today because the edge shield has no kernel backend.
