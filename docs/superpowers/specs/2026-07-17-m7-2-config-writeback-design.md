# FreeSBC M7.2 — Config Write-Back Design

The second M7 slice: let the admin API write the config file back to disk —
validated, atomically, preserving comments and `${ENV}` literal references,
never writing expanded secrets — so a hot-reload picks it up. Builds on M7.1
(admin server + auth). Parent spec: `freesbc-allinone-design.md` §178 (WebUI
reads/writes the same YAML; `${ENV}` stored as-is; never write expanded
plaintext). M1–M6, M7.1 complete and merged.

## 0. Reality baseline

- `config.Parse(data []byte) (*Config, error)` unmarshals (goccy/go-yaml,
  strict) → `expandEnv` (post-parse `${VAR}` expansion) → validate. It returns a
  NEW `*Config` and has NO side effect on any live `Store` — so it is a pure
  validator for a candidate document. The raw file on disk holds `${ENV}`
  literals; only the in-memory `*Config` has expanded values.
- `config.Watch(ctx, path, store, log)` (M1) watches `filepath.Dir(path)` and
  reloads on `Write|Create|Rename` events, debounced 200ms, keeping the previous
  config on a bad reload. Because it watches the DIRECTORY and handles `Rename`,
  an atomic temp-file+rename write is observed and hot-reloaded.
- M7.1 admin: `admin.Server{cfg, store, deps, log}`; bcrypt Basic Auth on all
  routes except `/healthz`; `GET /api/config` returns a REDACTED parsed JSON
  view (for display, not editing). `admin.New(cfg, store, deps, log)`.
- `main.run(cfgPath)` holds the config path; builds `admin.New(...)`.

## 1. Design decision — full-document round-trip (not field-level AST-patch)

**Chosen:** the client sends/receives the WHOLE YAML document as text.
`GET /api/config/raw` returns the exact on-disk bytes; `PUT /api/config` takes
the full YAML text, validates it, and atomically writes it verbatim.

**Why this over the parent design's §178 field-level AST-patch:** writing the
client's literal bytes preserves comments, formatting, and `${ENV}` references
**trivially and completely** — there is no re-serialization and no AST-node
navigation to get wrong. "Never write expanded plaintext" holds by
construction: the server never expands on the write path (it writes the
submitted bytes, which carry `${ENV}` refs). This is simpler and more robust
than AST surgery, and it pairs with a **text-editor WebUI** (M7.3) rather than a
structured form. Field-level AST-patch (goccy `ast`) is deferred as unnecessary
complexity; if a structured-form WebUI is ever wanted, it can send the full
document it reconstructed, or AST-patch can be added then.

**Consequence for M7.3:** the WebUI edits the raw YAML (a code editor), which
naturally round-trips comments/`${ENV}`. Noted, not decided here.

## 2. Components & module layout

| File | Change |
|---|---|
| `admin/config_write.go` (new) | `handleConfigRaw` (GET raw bytes + ETag) and `handleConfigWrite` (PUT: If-Match, validate, atomic write); `etag(bytes) string`; the atomic-write helper. |
| `admin/server.go` | `Server` gains `cfgPath string`; `New` takes it; register `GET /api/config/raw` and `PUT /api/config` (both auth-wrapped). Since `/api/config` now has two methods (GET redacted view from M7.1, PUT write), route by method. |
| `main.go` | Pass `cfgPath` into `admin.New`. |

No new dependency (stdlib `os`/`crypto/sha256`/`io`; `config.Parse` for
validation).

## 3. Endpoints

### `GET /api/config/raw` (auth)
Returns the exact on-disk config bytes, `Content-Type: application/x-yaml`, with
an `ETag: "<hex>"` header (`sha256` of the bytes, hex). This is the editor's
read — it returns `${ENV}` literals UNEXPANDED and the file's real content
(comments, formatting intact). Operators keep secrets in `${ENV}` refs so the
file (and this endpoint) never carries a literal secret; the endpoint is
auth-gated and the listener private-bound. (The M7.1 `GET /api/config` redacted
JSON view stays, for display.)

### `PUT /api/config` (auth)
Body: the full YAML document (text). Flow:
1. Read the body with a size cap (e.g. 1 MiB) — over → `413`.
2. If an `If-Match` header is present, compare it to the CURRENT on-disk file's
   ETag; mismatch → `409 Conflict` (the file changed since the client read it —
   stale edit, no write). Absent `If-Match` → skip the check (blind write).
3. Validate: `config.Parse(body)`. Error → `400 Bad Request` with the validation
   error text in the body (the editor surfaces it); NO write.
4. On success: **atomic write** — create a temp file in the SAME directory as
   the config, write the bytes, `Sync`, `Close`, `chmod` to the original file's
   mode, then `Rename` over the config path (atomic on one filesystem). On any
   step's failure, remove the temp file and return `500`; the original file is
   untouched (rename is all-or-nothing).
5. Respond `200` with the new `ETag`. The existing `config.Watch` observes the
   rename and hot-reloads (re-validating and atomically swapping the live
   config); a bad reload can't happen because step 3 already validated.

Method routing on `/api/config`: `GET` → the M7.1 redacted view;
`PUT` → this handler; other methods → `405`.

## 4. Error handling

| Scenario | Behavior |
|---|---|
| Body > cap | `413 Request Entity Too Large`, no write |
| `If-Match` mismatch (stale) | `409 Conflict`, no write |
| Invalid YAML / fails validation | `400` + error text, no write (file untouched) |
| Undefined `${ENV}` ref in submission | `400` (config.Parse errors on missing env), no write |
| Temp-write / rename failure | `500`, temp removed, original file intact |
| Config path not writable | `500` (atomic write fails cleanly; original intact) |
| Concurrent PUTs | last-writer-wins at the OS rename; each validated independently (ETag mitigates accidental clobber) |

Never: a partial/corrupt config file (atomic rename), an unvalidated file on
disk (validate precedes write), or an expanded secret written to disk (verbatim
bytes).

## 5. Testing

- **atomic-write helper**: writes bytes + preserves mode; a mid-write failure
  (inject via a bad dir/perm) leaves the original intact and cleans the temp.
- **`GET /api/config/raw`**: returns the file bytes verbatim + a correct ETag;
  behind auth (401 without creds); `${ENV}` literal preserved in the output.
- **`PUT /api/config`** (httptest against `handler()`, a temp config file):
  - valid new config → `200`, file on disk updated to the submitted bytes,
    new ETag; comments/`${ENV}` in the submitted body are on disk verbatim.
  - invalid config → `400`, file UNCHANGED (read back, byte-identical to before).
  - stale `If-Match` → `409`, file unchanged.
  - body over cap → `413`.
  - never-expand: submit a body with `password: ${SECRET}` and a set SECRET env;
    assert the on-disk file still contains the literal `${SECRET}` (not the
    expanded value).
- **method routing**: `GET /api/config` still returns the redacted view; a
  `DELETE /api/config` → `405`.
- Full `go vet ./... && go test ./... -race` green (the known M5 SRTP-teardown
  flake aside).

## 6. Scope

**In M7.2:** `GET /api/config/raw` (raw bytes + ETag), `PUT /api/config`
(size-cap, If-Match optimistic concurrency, validate-before-write via
config.Parse, atomic temp+rename write preserving mode and `${ENV}`/comments,
new ETag), `cfgPath` wiring; the existing hot-reload observes the write.

**Deferred (non-goals):**
- Field-level structured AST-patch (goccy `ast`) — full-document round-trip
  chosen instead.
- Config diff/preview, backup/rollback history, multi-version rollback.
- A distinct write audit log (a Warn log line on each successful write is enough).
- Redacting literal secrets in `GET /api/config/raw` (would break round-trip;
  the answer is `${ENV}` refs + auth + private bind).
- Waiting for / confirming the hot-reload synchronously in the PUT response
  (fire-and-forget; the watcher reloads within its debounce; the client can
  GET /api/status to confirm).
- Config write via the WebUI (that's M7.3, which consumes these endpoints).
