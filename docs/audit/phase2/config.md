# Phase 2 — internal/config

Scope: `internal/config` (loader.go, expand.go, schema.go, types.go, proxy.go,
validate.go, validate_proxy.go, store.go, reload.go). Read-only review; no
`go test` was run. FACT items were reproduced with a binary built from this
tree (`go build -o <scratch>/freesbc ./cmd/freesbc`) and `freesbc check|run -c
<probe>.yaml`. The probe YAML files are quoted inline under each finding.

## Findings

### P2-CFG-001 — Null map/list entries crash Parse (check, run and hot reload)
- Severity: P1 (process crash on reload; not reachable from a public socket)
- Layer: config/lifecycle
- Label: FACT
- Location:
  - `internal/config/schema.go:295-296`: `for _, p := range c.Peers { if p.Transport == "" {`. The nil check is missing.
  - `internal/config/proxy.go:395-396`: `for _, g := range pstn.Gateways { if g.Transport == "" {`. The nil check is missing. The same loop for upstream nodes at `proxy.go:371` does guard with `n != nil`, and validation guards it at `validate_proxy.go:134`.
  - `internal/config/validate.go:204-205`: `for i, r := range c.Routes { label := r.Name`. A nil `*Route` panics.
  - `internal/config/validate_proxy.go:144-146`: `for i, r := range pstn.Routes { ... len(r.To)`. A nil `*PstnRoute` panics.
- Evidence (`freesbc check`, all four probes):
  - `peers: {a: }` gives `panic: runtime error: invalid memory address or nil pointer dereference` at `config.withDefaults ... schema.go:296`.
  - `routes: [ ~ ]` panics at `(*Config).validate ... validate.go:205`.
  - `sip.pstn.gateways: {gw1: }` panics at `config.proxyWithDefaults ... proxy.go:396`.
  - `sip.pstn.routes: [ ~ ]` panics at `(*Config).validateProxy ... validate_proxy.go:146`.
- Invariant violated: "An invalid config is logged and the previous one stays active — the process never dies from a bad reload" (`reload.go:16-18`, `docs/design.md:316-318`). `config.Watch` calls `Load` in the app's errgroup goroutine (`app.go:93-99`), which has no `recover`. A hand-edited file with an empty `peers.x:` entry therefore kills the running process on reload. The admin `PUT /api/config` path calls `config.Parse` inside an HTTP handler (`admin/config_write.go:109`), where net/http recovers the panic, so that path drops the connection instead of returning a 400. It never writes the file.
- Confirming test: `TestParseNullEntriesDoNotPanic`. It is table-driven over the four YAML snippets above and asserts that `Parse` returns an error rather than panicking. A second test, `TestWatchSurvivesNullEntryReload`, writes a valid file, starts `Watch`, overwrites the file with `peers: {a: }` and asserts that the goroutine is still alive and `store.Current()` is unchanged.
- Action: fix. Add nil guards in `withDefaults`/`proxyWithDefaults`/`validate`, or reject null entries in one place right after unmarshal.

### P2-CFG-002 — A hot reload that removes `sip.pstn` gives the still-running PSTN topology a zero attempt budget
- Severity: P1
- Layer: config/lifecycle
- Label: INFERENCE
- Location:
  - `internal/config/proxy.go:387-394`: the `attempt_timeout`/`cooldown` defaults apply only when `pstn.configured()`.
  - `internal/edge/invite.go:468-470`: `cfg := s.store.Current().SIP.Pstn; budget := cfg.AttemptTimeout.Std()`.
  - `internal/edge/invite.go:653`: `timer := time.NewTimer(budget)`.
- Evidence: gateways, routes and match come from the startup topology snapshot (`s.topo.pstn`). The budgets are re-read per call from the live store. A reload that deletes or comments out `sip.pstn` validates on its own terms, because validation only sees the new file. `AttemptTimeout` then becomes 0, and every subsequent PSTN attempt gets `time.NewTimer(0)`: it is cancelled immediately and the gateway is penalised. The same applies to `sip.upstreams.cooldown`: dropping the upstream alias makes `Cooldown` 0 (`proxy.go:364-367`, read at `edge/invite.go:191` and `edge/register.go:78`), which turns `Penalize` into a no-op. The `proxy.go:357-362` comment names this exact failure mode as the reason for the default.
- Invariant: hot reload must not change restart-only settings (docs/design.md:337-345). Here a hot value is derived from whether a restart-only section is present.
- Confirming test: an edge harness test that sets up PSTN, replaces the store with an otherwise identical config minus `sip.pstn`, drives a FreeSWITCH→PSTN INVITE, and asserts that the gateway received it (expected result: CANCEL/503 without a real attempt).
- Action: fix. Validate a reload against the running restart-only snapshot, or have the edge plane read the budgets from its topology snapshot.

### P2-CFG-003 — Validation errors echo expanded `${VAR}` values; with the admin PUT endpoint this reads any process environment variable
- Severity: P1 (credential disclosure over the authenticated admin path)
- Layer: config/lifecycle, admin
- Label: FACT for the echo; INFERENCE for the admin path
- Location: `internal/config/loader.go:23-27` claims that parse errors never echo secrets, but `validate()` runs after `expandEnv` and formats values with `%q`. For example, `validate.go:40` prints `listen.media.public_ip: %q is neither "auto" nor a valid IP`, and many other `fail(... %q ...)` calls do the same. `admin/config_write.go:109-111` returns `"invalid config: "+err.Error()` to the HTTP client.
- Evidence: `SECRET=hunter2-s3cr3t freesbc check -c secret.yaml` with `listen.media.public_ip: "${SECRET}"` prints `listen.media.public_ip: "hunter2-s3cr3t" is neither "auto" nor a valid IP`.
- Impact: `GET /api/config/raw` returns the file with literal `${VAR}` text, so the env secrets themselves are not exposed that way. An authenticated admin can still `PUT` a body that references any environment variable of the process in an IP-typed field and read the value back from the 400 response. This works for variables the config never uses.
- Invariant: CLAUDE.md "parse errors never echo a secret"; design.md:406-408.
- Confirming test: a `Parse` test with `t.Setenv("X","sentinel")` and `public_ip: "${X}"` that asserts that the error does not contain `sentinel`, plus an admin handler test for the PUT path.
- Action: fix. Do not echo values of fields that contained `${`, or restrict expansion to an allow-list of credential fields.

### P2-CFG-004 — `check` accepts configs that `run` rejects (more than the documented checkHostPort gap)
- Severity: P2
- Layer: config/lifecycle, docs
- Label: FACT
- Cases (each probe prints `config OK` from `check`):
  1. `sip.upstream.address: fs.example.com:5060` (known gap). `validate_proxy.go:55` uses `checkHostPort` (`:368-380`), which accepts any host. `run` rejects it in `edge/topology.go` `parseEndpoint`. `docs/design.md` §5.5 states "upstream/gateway addresses must be **literal IP:port**" as a validation rule.
  2. `sip.pstn.match: fs.example.invalid:5060`. `validatePSTNMatch` (`validate_proxy.go:319-342`) never checks that the host is an IP. `run` fails with `edge proxy: proxy: sip.pstn.match must be a literal IP, got fs.example.invalid` (`edge/topology.go:275-276`). Reproduced.
  3. Default public UDP and private binds collide. With `network.*.bind_ip: 0.0.0.0` and `sip.public.udp.enabled: true` without `bind`, `proxyWithDefaults` gives public UDP `0.0.0.0:5060` (`proxy.go:414`) and private `0.0.0.0:5060` (`proxy.go:418-424`). Validation has no public-vs-private or trunk-vs-edge socket collision check. `run` failed with `proxy listen udp://0.0.0.0:5060: bind: address already in use`. That run was not isolated because a local FreeSWITCH also holds `192.168.31.55:5060`, so this case is INFERENCE.
  4. The trunk `listen.sip` and edge `sip.public.udp` share a socket. `listen.sip: ["udp://0.0.0.0:16060"]` plus `sip.public.udp.bind: 0.0.0.0:16060` passes `check`, and `run` fails with `listen udp 0.0.0.0:16060: bind: address already in use`. Nothing else held 16060 (checked with `lsof`). The public-listener duplicate check (`validate_proxy.go:204-222`) only compares edge listeners with each other.
  5. Duplicate `listen.sip` entries (`["udp://127.0.0.1:5070","udp://127.0.0.1:5070"]`) pass `check`. `run` was not attempted for this case.
- Confirming test: a table test that asserts `Parse` returns an error for each probe.
- Action: fix. Add a socket-collision check across trunk listeners, edge public listeners and the private bind, and require literal IPs where the topology requires them.

### P2-CFG-005 — `${name}` in `routes[].transform.to` is expanded as an env var, which breaks named capture groups
- Severity: P2
- Layer: config/lifecycle
- Label: FACT
- Location: `expand.go:15`, `expand.go:116-127`. `numericGroupRef` (`expand.go:21`) exempts only `${123}`.
- Evidence: `match.to: "^(?P<num>[0-9]+)$"` with `transform.to: "+${num}"` fails with `undefined environment variable(s) referenced in config: [num]`. If an env var `num` exists, its value is substituted into the template without any warning. `maxGroupRef` (`validate.go:315-365`) deliberately supports named references, so the two mechanisms disagree. design.md:410-412 documents only the numeric exemption.
- Action: fix. Do not expand inside route templates, or exempt names that match a named group of `match.to`.

### P2-CFG-006 — `${VAR}` cannot be used in typed scalars (durations, port ranges, listeners, host:port)
- Severity: P2
- Layer: config/lifecycle, docs
- Label: FACT
- Location: `types.go:30-41` (`Duration`), `types.go:51-73` (`PortRange`), `types.go:82-106` (`SIPListen`), `proxy.go:33-51` (`HostPort`). These unmarshal during the strict YAML step, before `expandEnv` runs (`loader.go:33-36`), and `expandEnv` only rewrites `reflect.String` kinds (`expand.go:104`).
- Evidence: `RT=30s freesbc check` with `ring_timeout: ${RT}` fails with `invalid duration "${RT}"`. The `expand.go:23-26` comment says "every exported string field", which is accurate. design.md §5 does not state the limitation.
- Action: fix (docs). State that expansion applies only to plain string keys.

### P2-CFG-007 — Reload silently accepts changes to restart-only settings
- Severity: P2
- Layer: config/lifecycle
- Label: INFERENCE
- Location: `reload.go:73-80` calls `store.Replace(cfg)` unconditionally. The only restart-only diff anyone reports is `admin.listen` (design.md:347-350).
- Evidence: listeners, the edge topology, TLS material, `shield.nftables` and the presence of `admin:` (design.md:337-345) can all change in the file. The reload logs `config reloaded`, and `GET /api/config` then serves a snapshot whose listener and topology values are not what is bound. Validation of the new file also checks cross-key rules against restart-only values that are not running, for example `validatePSTNMatch` against a `sip.private.bind` that was never re-bound (`validate_proxy.go:320-325`). P2-CFG-002 is the concrete failure of this model.
- Confirming test: a `Watch` test that changes `listen.sip` and asserts that some signal (log, metric or rejection) is emitted.
- Action: fix. Diff the restart-only fields on reload and either reject the reload or log a warning per changed key.

### P2-CFG-008 — IPv4-mapped IPv6 `allowed_ips` entries validate but can never match
- Severity: P2
- Layer: config/lifecycle
- Label: INFERENCE. `check` and `run` accept the config (FACT). That no packet ever matches is inferred from the code.
- Location: `validate.go:175-201` computes `minBits` for 4in6 addresses as 32, so `::ffff:0:0/96` and `::ffff:10.0.0.1` pass. The transport source is always `Unmap()`ed (`sip/addr.go:34,47`), and `netip.Prefix.Contains` never matches an IPv4 address against an IPv6 prefix.
- Evidence: `peers.a.allowed_ips: ["::ffff:10.0.0.1", "::ffff:0:0/96"]` gives `config OK`, and `run` starts. The peer is unidentifiable. This is the silent fail-closed that `validate.go:170-173` explicitly refuses for the empty-list case. There is no security bypass, because sources are unmapped before the check.
- Action: fix. Unmap the prefix, or reject 4in6 prefixes.

### P2-CFG-009 — The trunk port range can be valid yet hold no call
- Severity: P2
- Layer: config/lifecycle
- Label: INFERENCE
- Location: `types.go:68` (`minP >= maxP`) and `validate.go:429` (`min >= max`) accept a 2-port range. `checkPortRange`'s comment (`validate.go:417-421`) says every session needs an RTP+RTCP pair. CLAUDE.md says trunk `Allocate` binds 2 pairs (4 ports) per call.
- Evidence: `rtp.port_min: 30000, port_max: 30001` validates, but by construction it cannot fit one trunk call. Every INVITE would get a 503 (`media: RTP port range exhausted`). Not run.
- Action: fix. Require at least 4 ports (aligned to pairs) for the trunk range and 2 for each edge range.

### P2-CFG-010 — Dead validation branches
- Severity: P2
- Layer: config/lifecycle
- Label: INFERENCE (the design doc agrees for the first case)
- Location:
  - `validate_proxy.go:235-236`: `sip.private.bind: required` cannot fire, because `proxy.go:418-424` always defaults the bind when the proxy is on. design.md §5.5 says so.
  - `validate_proxy.go:207-209`: `sip.public.<t>.bind: required` cannot fire for an enabled listener, because `defBind` (`proxy.go:404-416`) fills every enabled listener with a zero bind.
- Action: delete. Alternatively, drop the defaults if a required bind is the intent.

### P2-CFG-011 — `Watch` misses Kubernetes ConfigMap-style symlink swaps
- Severity: P2
- Layer: config/lifecycle
- Label: INFERENCE
- Location: `reload.go:61-63` filters events by `filepath.Base(ev.Name) != base`.
- Evidence: a ConfigMap mount updates `..data` (a symlink rename) in the directory. The visible `sbc.yaml` symlink itself never gets an event, so no reload fires. design.md §4.4 describes only atomic-rename editors.
- Action: fix (or document). Also react to events on `..data` and re-stat the target, or document the limitation.

## Clean checklist items
- Parse order is strict YAML, then `expandEnv`, then `withDefaults`, then `validate`. It matches design.md §5 (`loader.go:31-43`), and parse errors cannot echo expanded values because expansion runs later. See P2-CFG-003 for validation errors.
- Snapshot immutability: every `Load` builds a fresh `Config`, so no pointer, map or slice is shared between snapshots. Compiled fields (`allowedNets`, `matchTo`) are set before publication. A grep of non-test code outside config found no writes to snapshot fields.
- `Store`: `atomic.Pointer` publish and `Current` are race-free. `Replace` stores before it notifies. Subscriber sends are non-blocking under `mu`. There is no network I/O or blocking channel send under a lock.
- `Watch` goroutine: it exits on `ctx.Done()` or when fsnotify closes a channel. `defer w.Close()` and `timer.Stop()` run on exit. The `AfterFunc` callback does a non-blocking send. `timer` is touched only by the loop goroutine. There is no `time.After` in a loop and no `time.Sleep` sync.
- A bad file keeps the previous snapshot (`reload.go:74-77`), except when it panics (P2-CFG-001).
- There is no `_ = err`, no `recover`, no single-implementation interface, no `defer` in a loop and no per-packet code in the package. `go vet ./internal/config` is clean.
- Credentials: `PeerAuth` is plain data. The edge plane holds no credentials in config. Admin uses a bcrypt hash with cost ≥ 10 enforced (`validate.go:279-286`).
- Snapshot per call: config itself does not read the store. Per-call reads belong to the plane reviewers.
- Env expansion does not re-scan expanded values (`expand.go:116-127`). Missing variables are reported once (`seenMissing`).

## Docs vs code
- design.md:316-318 ("the process never dies from a bad reload") is false for null entries (P2-CFG-001).
- design.md §5.5 ("addresses must be literal IP:port") describes a rule that validation does not enforce. Only `run` enforces it (P2-CFG-004).
- design.md §5 leaves out that `${VAR}` works only in plain string fields (P2-CFG-006) and that non-numeric `${name}` in route transforms is treated as an env var (P2-CFG-005).
