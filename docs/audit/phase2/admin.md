# Phase 2 — internal/admin

Reviewer scope: `internal/admin` only (server.go, api.go, config_write.go, redact.go, metrics.go, webui.go).
Wiring in `internal/app/app.go` was read only to confirm how Deps arrive. No production file was modified.
Method: reading, plus one reproduction with the built binary (`freesbc check`, which runs the same `config.Parse` as `PUT /api/config`).

## Findings

### P2-ADM-001 — PUT /api/config validation error echoes expanded `${ENV}` values (env-var read oracle)
- Severity: P2 (security, authenticated-only; admin surface is not a public path — flag for triage upgrade)
- Layer: admin
- Label: FACT for the echo (reproduced via `freesbc check`); the PUT path reaching it is INFERENCE (direct call, by reading)
- Location: `internal/admin/config_write.go:109-110`, `internal/config/validate.go:268`, `internal/config/expand.go:23-44`
- Evidence:
  ```go
  // config_write.go:109
  if _, err := config.Parse(body); err != nil {
      http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
  // validate.go:268 (runs after expansion)
  fail("admin.listen: %q is not host:port", c.Admin.Listen)
  ```
  Repro: `AUDIT_SECRET=s3cr3t-value freesbc check -c leak.yaml` with `admin.listen: ${AUDIT_SECRET}` prints
  `admin.listen: "s3cr3t-value" is not host:port`.
- Invariant: design.md §14.2 names `${ENV}` references as the mitigation for `GET /api/config/raw` exposing credentials ("The mitigation is `${ENV}` references…"); loader.go:24 promises errors never echo secrets. An admin (or anyone holding the admin password) can read any process environment variable (e.g. `CARRIER_A_PASS`, cloud credentials) by PUTting a config that places `${VAR}` in any `%q`-echoed field; the file is not written because validation fails, so the probe leaves no trace except a 400. The same values also appear in `GET /api/config` for peers' `address`/`auth.username` and `routes` after a successful write (redact.go:13-38 echoes post-expansion values).
- Suggested test: admin test that sets `t.Setenv("AUDIT_SECRET", sentinel)`, PUTs a body with `admin.listen: ${AUDIT_SECRET}`, asserts the 400 body does not contain the sentinel (expected to fail today).
- Action: fix (validate/echo against the pre-expansion literal, or redact field values in validation errors returned over HTTP).

### P2-ADM-002 — Auth limiter check-then-act race: concurrent requests bypass the 10/min budget
- Severity: P2 · Layer: admin · Label: INFERENCE
- Location: `internal/admin/server.go:193-211`
- Evidence: `over()` (read, lock released) → `bcrypt.CompareHashAndPassword` (~50–100 ms at cost 10) → `recordFail()`. N requests from one IP arriving within one bcrypt duration all pass `over()` before any failure is recorded, so each "round" admits an unbounded number of password guesses and bcrypt computations, not 10.
- Invariant: design.md §13.4 "10 failures per 1 minute per IP"; server.go:182-185 comment "bounding both brute-force attempts and the bcrypt CPU a single address can demand".
- Suggested test: 50 concurrent requests with a wrong password from one client; assert the number of 401s ≤ 10 (expect > 10 today).
- Action: fix (reserve a slot atomically before bcrypt, e.g. increment an in-flight/attempt counter under the lock).

### P2-ADM-003 — Limiter keyed by exact source IP: shared-IP lockout of legitimate operators, and per-/128 keys for IPv6
- Severity: P2 · Layer: admin · Label: INFERENCE
- Location: `internal/admin/server.go:192-196`, `:320-325`, `:344-346`, `:355-361`
- Evidence: once an IP has 10 failures, "every further request from it — even with valid credentials — gets 429" (server.go:183-184). The default deployment is loopback (all local clients share 127.0.0.1) and the README (line 123) recommends a reverse proxy (all operators share the proxy IP). Any local process, or any client of the proxy, can send 10 bad requests per minute and lock out the WebUI and the Prometheus scrape (`/metrics` behind the same `requireAuth`). A request with no `Authorization` header also counts as a failure (server.go:197-198), so every fresh browser session's first unauthenticated GET costs one. Conversely, with `allow_remote`, keys are exact strings: an IPv6 attacker gets a fresh budget per /128 address, and once 4096 IPs are tracked the whole table is cleared (`clear(l.perIP)`), resetting every attacker's count.
- Suggested test: 10 bad-auth requests from 127.0.0.1, then a valid-credential request: asserts 429 (documents the lockout); a second test with 4097 distinct RemoteAddr values then the first IP again: asserts its budget was reset.
- Action: fix (do not deny valid credentials; key IPv6 by /64; evict oldest instead of clearing).

### P2-ADM-004 — PUT /api/config lost-update and TOCTOU: If-Match optional and not atomic with the rename
- Severity: P2 · Layer: admin · Label: INFERENCE
- Location: `internal/admin/config_write.go:97-107`, `:117`
- Evidence: `If-Match` is checked only when present (blind overwrite otherwise), and the check (`os.ReadFile` + compare) and `writeFileAtomic` are not serialized by any mutex; two concurrent PUTs carrying the same valid ETag can both pass the check and the second rename silently discards the first. Also no 428 when If-Match is missing.
- Suggested test: two goroutines PUT different valid bodies with the same ETag, gated so both pass the If-Match read before either renames (requires a test hook) — or at minimum a test documenting that a PUT without If-Match overwrites a concurrent change.
- Action: fix (mutex around check+write; optionally require If-Match).

### P2-ADM-005 — writeFileAtomic replaces a symlinked config with a regular file and does not fsync the directory
- Severity: P2 · Layer: admin · Label: INFERENCE
- Location: `internal/admin/config_write.go:26-57` (rename at :52)
- Evidence: `os.Rename(tmpName, path)` where `path` is `s.cfgPath` as given. If the operator's `-c` path is a symlink (e.g. `/etc/freesbc/sbc.yaml -> /srv/conf/sbc.yaml`, or a Kubernetes ConfigMap mount), the symlink is replaced by a regular file and the target is never updated; the temp file is created next to the link, not the target. The parent directory is not fsynced after rename, so the rename is not durable across power loss (doc §13.3 calls the write "atomic", which holds, but not durable).
- Suggested test: create target + symlink in `t.TempDir()`, construct Server with the symlink path, PUT, assert the target file content changed and the link is still a symlink (expected to fail).
- Action: fix (`filepath.EvalSymlinks` before writing; `Sync` the directory).

### P2-ADM-006 — Panic umbrella logs no stack trace
- Severity: P2 · Layer: admin · Label: INFERENCE
- Location: `internal/admin/server.go:375-386`
- Evidence: `s.log.Error("admin handler panic", "err", rec, "path", r.URL.Path)` — no `debug.Stack()`. The panic is contained (intended, design §11.5) but the diagnostic is discarded, so a handler panic is unlocatable from logs. After a panic that happens once a handler already wrote headers, `http.Error` issues a superfluous WriteHeader.
- Action: fix (log `debug.Stack()`).

### P2-ADM-007 — /api/status and media-port gauges report configured/trunk-only state, not live state
- Severity: P2 · Layer: admin · Label: INFERENCE
- Location: `internal/admin/api.go:19-22`, `internal/admin/metrics.go:100-102`, `internal/app/app.go:152` (`Ports: pool.Stats`)
- Evidence: `listeners` is built from `s.store.Current().Listeners()` — the hot-reloaded config — while the listener set is restart-only (design.md:338), so after a reload that edits `listen.sip`, `/api/status` lists listeners that are not bound. `Ports` is the trunk `PlanePool` even on an edge-only deployment, where it reports a non-zero `total` from `listen.media.port_range` defaults for a pool nothing uses (the gap is documented in design.md §15 "Proxy-only admin gaps", but the value is misleading, not absent). `active_calls` sums both planes (app.go:156-164) while `/api/calls` lists only trunk calls, so the two endpoints disagree on an edge deployment.
- Action: fix (report bound listeners captured at startup; omit or split port gauges per plane).

### P2-ADM-008 — Docs vs code drift (admin)
- Severity: P2 · Layer: docs · Label: INFERENCE
- `docs/design.md:356` cites `admin/server.go:255-260` for the `adminAuth` fallback; the function is at `internal/admin/server.go:252-257`.
- `docs/design.md` §13.4 (limiter paragraph): "when the table reaches that size, `recordFail` sweeps expired entries and, if it is still full, clears every count." Code (`server.go:336-347`) sweeps expired entries on every new-window failure regardless of table size, and the cap check runs only on that path.
- `server.go:1-2` package comment calls the surface "read-only"; it serves `PUT /api/config`, `DELETE /api/calls/{id}` and `DELETE /api/bans/{ip}`.
- Action: fix (docs).

## Checklist items found clean
- bcrypt cost ≥ 10: enforced at validation (`internal/config/validate.go:279-285`); applies to hot reload too since reload runs `validate`.
- Constant-time compare: username via `subtle.ConstantTimeCompare`, both checks evaluated before deciding (`server.go:205-207`). Username length leaks via early length check — accepted, not a secret.
- Auth hot reload reads `store.Current()` per request (`server.go:252-257`); fallback when `admin:` removed is documented.
- Auth bypass: every route except `/healthz` is wrapped (`server.go:116-125`); Go 1.22 mux patterns — the method-specific `DELETE /api/calls/{id}` does not shadow `/api/calls`; unknown paths hit the authenticated SPA catch-all.
- Loopback determination: `netip.ParseAddrPort` + `IsLoopback` (`validate.go:266-269`); hostnames (e.g. `localhost`) are rejected; `::1` accepted; `::ffff:127.0.0.1` is unmapped by `netip.Addr.IsLoopback` and accepted (still loopback); `0.0.0.0`/`::` rejected.
- X-Forwarded-For is never consulted (`remoteIP`, `server.go:355-361`) — no spoofing path.
- PUT body limit 1 MiB via `io.LimitReader` (`config_write.go:87-95`); validation runs before write; path is fixed (`s.cfgPath`), no user-controlled path → no traversal; temp file removed on every failure path.
- GET /api/config/raw unredacted by design (design.md §13.3, §14.2); GET /api/config is a whitelist and redacts `password` / `password_hash` (`redact.go:9-40`); no other secret fields exist in the schema (`schema.go:199`, `:268` are the only credential fields).
- HTTP timeouts set (ReadHeader 5 s, Read/Write/Idle 30 s) — slowloris bounded (`server.go:223-232`).
- Shutdown: serve goroutine sends to a buffered chan and exits; `watchListenChange` goroutine exits on ctx/done; Store subscriber sends are non-blocking (`config/store.go:32-36`) so the leaked subscription cannot block `Replace`.
- No goroutine without exit path, no `time.Sleep`/`time.After` loops, no lock across I/O (limiter lock only guards map ops), no `defer` in loops, no maps shared without sync (limiter map under mutex; metrics `sync.Once`).
- `_ =` uses are HTTP body writes/JSON encode to a ResponseWriter and a temp-file removal — acceptable.
- KillCall / Unban / Shield / Calls wired only to the trunk plane (`app.go:171-190`), nil-guarded with no-op defaults for edge-only; `Proxy` nil-checked in `Collect` (`metrics.go:121`).
- Metrics labels bounded (method/transport/class/peer/reason); no Call-ID label.
- No credential storage beyond the bcrypt hash; no call-center/ESL logic.
- Interfaces with a single implementation / `any` misuse: `writeJSON(v any)` and `redactConfig` returning `any` are JSON boundaries — acceptable.
