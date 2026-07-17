# FreeSBC — Kick-Call Design (`DELETE /api/calls/{id}`)

The M7 follow-on that completes the admin surface: an operator can tear down a
live call by its Call-ID (BYE both legs). Needs a bridge teardown-by-Call-ID
mechanism. Builds on M7.1 (admin API + auth) and the M3.3/M4 B2BUA teardown.
M1–M7 complete and merged.

## 0. Reality baseline

- The B2BUA `onInvite` goroutine owns each call's lifecycle: after bridging it
  registers the call (`registry.Add(call)` / `defer Remove`), then blocks on a
  `select` (`sig/b2bua.go:329`) over `aLeg.Context().Done()` (caller ended),
  `bLeg.Context().Done()` (carrier ended), `sess.Done()` (media silence) — each
  case BYEs the still-live leg(s) via `byeContext()` (a 5s-bounded teardown
  BYE), then the deferred cleanup unwinds (registry.Remove, sdps.delete,
  sess.Close, aLeg/bLeg.Close). This teardown path is the M3.3/M4-reviewed,
  race-handled one.
- `callstate.Registry` indexes active calls by Call-ID (`Call.ID = callID(req)`,
  the A-leg Call-ID) with metadata only — no dialog/cancel handles.
- `sig.Server` (built in `NewServer`) holds `registry`, `store`, etc.
- M7.1 admin: `Deps` closures adapt `sig.Server`; `GET /api/calls` lists
  `{id, from, to, ...}`; routes behind bcrypt Basic Auth.

## 1. Design

Add a **fourth `select` case**, a per-call kill context, so an external kick
reuses the existing teardown rather than adding a new BYE path.

- Each call gets `killCtx, killCancel := context.WithCancel(context.Background())`
  registered in a mutex-guarded `map[string]context.CancelFunc` on `sig.Server`,
  keyed by the A-leg Call-ID, right after `registry.Add`; `defer` unregisters +
  cancels (cleanup).
- The `select` gains `case <-killCtx.Done():` which BYEs BOTH legs (identical to
  `sess.Done()` — neither leg initiated, so both must be BYE'd). Extract the
  duplicated body into `byeBoth(aLeg, bLeg)` used by both cases.
- `Server.KillCall(id string) bool`: look up the call's `killCancel`, invoke it
  (idempotent), return whether found. A cancelled `killCtx` fires the select →
  normal teardown → deferred unregister removes it; a second `KillCall` (or one
  for an unknown/ended call) returns `false`.

**Concurrency:** `killCancel` (context cancel) is idempotent and thread-safe;
the map is mutex-guarded. A kick racing a natural end (caller hangup) is safe —
`select` fires exactly once, both paths BYE the right legs, and BYE on an
already-terminated dialog is a harmless no-op. Tiny window between `registry.Add`
and `registerKiller` where a kick 404s a just-started call (operator retries) —
acceptable.

## 2. Components

| File | Change |
|---|---|
| `sig/server.go` | `killers map[string]context.CancelFunc` + `killMu sync.Mutex` (init in `NewServer`); `registerKiller`/`unregisterKiller`; `func (s *Server) KillCall(id string) bool`. |
| `sig/b2bua.go` | Per-call `killCtx` + register/unregister/cancel in `onInvite`; the 4th `select` case; `byeBoth(aLeg, bLeg)` helper (dedups the sess.Done + kill bodies). |
| `admin/server.go` | `Deps` gains `KillCall func(id string) bool`; register `DELETE /api/calls/{id}` (auth-wrapped); `handleKickCall`. |
| `main.go` | `Deps.KillCall = sipServer.KillCall`. |

Go 1.22 `http.ServeMux` method+wildcard patterns: `mux.HandleFunc("DELETE
/api/calls/{id}", s.requireAuth(s.handleKickCall))`, `r.PathValue("id")`.

## 3. Endpoint — `DELETE /api/calls/{id}` (auth)

- `id := r.PathValue("id")` (the A-leg Call-ID, as listed by `/api/calls`).
- `if s.deps.KillCall(id)` → `204 No Content` (teardown initiated).
- else → `404 Not Found` (no such active call — already gone or never existed).
- Behind the M7.1 Basic Auth. Idempotent from the client's view (double-kick →
  204 then 404).

## 4. Error handling

| Scenario | Behavior |
|---|---|
| Kick a live call | 204; both legs BYE'd, call removed from the registry |
| Kick an unknown / already-ended id | 404 |
| Double-kick | first 204, second 404 |
| Kick racing a natural hangup | safe (select fires once; idempotent cancel; no double-teardown) |
| `{id}` with a slash | won't match the single-segment wildcard → 404 (URL-encode; Call-IDs rarely contain '/') |
| Unauthenticated | 401 (behind auth) |

Never: a leaked leg (teardown BYEs both), a double-BYE beyond the harmless
already-terminated no-op, or a new un-reviewed teardown path.

## 5. Testing

- **sig** (bridge harness): bridge a real call (A-leg UAC + stub carrier);
  `srv.KillCall(callID)` → assert BOTH legs receive a BYE (the stub carrier's
  byeDone fires AND the UAC's dialog ends) and the call is removed from the
  registry (`ActiveCalls()` → 0); `KillCall("nonexistent")` → `false`;
  `KillCall` after the call already ended → `false`. Race-clean under `-race`.
- **admin**: `DELETE /api/calls/{id}` with a `Deps.KillCall` stub returning true
  → 204; stub returning false → 404; without creds → 401; `GET /api/calls/{id}`
  (wrong method) → 405.
- Full `go vet ./... && go test ./... -race` green (known M5 SRTP flake aside).

## 6. Scope

**In:** the per-call kill mechanism (`Server.KillCall`, killCtx select case,
`byeBoth`), `DELETE /api/calls/{id}` (204/404, behind auth), the `Deps.KillCall`
wiring. Reuses the existing race-handled teardown.

**Deferred:** bulk kick / kick-by-peer; a kick reason/cause in the BYE; a
kick button in the WebUI (the endpoint exists; the UI can add it trivially
later); a graceful "kick after N seconds" or "kick with a specific SIP cause".
