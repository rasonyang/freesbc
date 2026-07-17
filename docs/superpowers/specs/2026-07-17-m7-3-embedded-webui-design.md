# FreeSBC M7.3 — Embedded WebUI Design

The final M7 slice (completes the operability milestone): a `go:embed`'d static
web UI — a live dashboard + a raw-config editor — served by the admin server,
consuming the M7.1/M7.2 JSON API. Parent spec: `freesbc-allinone-design.md`
(§109 `admin/webui/` go:embed; §32 "WebUI/API 是配置文件的编辑器"; §15 静态 JS
管理界面). M1–M6, M7.1, M7.2 complete and merged.

## 0. Reality baseline

- M7.1 admin server (`admin/server.go`): bcrypt HTTP Basic Auth on all routes
  except `/healthz`; JSON API `/api/status`, `/api/calls`, `/api/peers`,
  `/api/config` (GET redacted). Prometheus `/metrics`. Mux uses explicit
  `mux.HandleFunc` registrations in `handler()`.
- M7.2: `GET /api/config/raw` (raw YAML + ETag), `PUT /api/config` (validate +
  atomic write + If-Match). These are exactly the editor's read/write endpoints.
- No frontend, no static-file serving, no `go:embed` anywhere yet.

## 1. Design decisions (mine, per the delegated goal)

1. **Vanilla-JS single-page app, no framework, no build step.** One
   `index.html` with inline CSS + JS (or a tiny `webui/` dir), `go:embed`'d into
   the binary. No npm/bundler — consistent with "true single binary, zero
   dependencies". The API is small enough that vanilla `fetch` suffices.
2. **Served at `/` behind the same Basic Auth.** The static assets sit behind
   the M7.1 auth middleware (everything except `/healthz`). The browser's native
   Basic Auth dialog handles login — no separate login form or session/cookie —
   and the browser reuses the credential for the SPA's `fetch` calls to `/api/*`
   on the same origin/realm.
3. **Two views:** a **Dashboard** (auto-refreshing status / active calls /
   peers, read from `/api/status`, `/api/calls`, `/api/peers`) and a **Config**
   editor (a `<textarea>` loaded from `/api/config/raw`, saved via
   `PUT /api/config` with `If-Match` for optimistic concurrency; shows the 400
   validation error text on failure, prompts to reload on 409). A raw-YAML
   editor round-trips comments/`${ENV}` (the M7.2 design pairing).
4. **No new dependency.** `embed` + `net/http` file serving, stdlib only.

## 2. Components & module layout

| File | Change |
|---|---|
| `admin/webui/index.html` (new) | The SPA: dashboard + config editor, inline CSS/JS, vanilla `fetch`. |
| `admin/webui.go` (new) | `//go:embed webui` `embed.FS`; a handler serving the embedded files (SPA at `/`). |
| `admin/server.go` | Register the UI handler at `/` (auth-wrapped); it must NOT shadow the explicit `/api/*`, `/metrics`, `/healthz` routes (ServeMux longest-prefix wins, so `/` is the catch-all). |

## 3. Serving

- `//go:embed webui/index.html` (or `//go:embed webui`) into an `embed.FS`.
- Register `mux.HandleFunc("/", s.requireAuth(s.handleUI))`. In Go's
  `http.ServeMux`, the more specific patterns (`/healthz`, `/metrics`,
  `/api/status`, ...) win; `/` catches everything else (`/`, `/index.html`, any
  unknown path).
- `handleUI`: serve `webui/index.html` for `/` (and, if a `webui/` dir with
  multiple assets, `http.FileServerFS` over the sub-FS; otherwise serve the one
  file). `Content-Type: text/html; charset=utf-8`. A path that isn't a real
  embedded asset → serve `index.html` (SPA fallback) or `404` — either is fine
  since the SPA is one page; keep it simple (serve index.html for `/`, 404 for
  other non-asset paths, or FileServerFS's natural 404).
- Behind auth: the browser prompts once; the SPA's subsequent `fetch('/api/...')`
  reuse the credential automatically.

## 4. The SPA (index.html)

Minimal but functional, vanilla JS:

- **Layout:** a header (FreeSBC + version from `/api/status`), two tabs
  (Dashboard / Config).
- **Dashboard:** on load and every ~5s, `fetch` `/api/status`, `/api/calls`,
  `/api/peers`; render — status summary (version, uptime, active calls, ports
  in-use/total), a calls table (id / from / to / duration), a peers table
  (name / address / transport / srtp / register / registered). Read-only.
- **Config editor:** a "Load" that `fetch`es `/api/config/raw` into the
  `<textarea>` and stores the `ETag`; a "Save" that `PUT`s the textarea content
  to `/api/config` with `If-Match: <etag>`; on `200` show "saved" + update the
  ETag; on `400` show the validation error body (so the operator sees what's
  wrong); on `409` show "changed on disk — reload" and offer a reload. A note
  that secrets should be `${ENV}` refs.
- **Auth handling:** `fetch` uses same-origin credentials automatically after
  the browser's Basic Auth prompt; a `401` from `fetch` (e.g. creds cleared)
  shows a "re-authenticate (reload)" message.
- No external assets (no CDN — CSP-safe, offline-capable); all CSS/JS inline.

## 5. Error handling

| Scenario | Behavior |
|---|---|
| Unauthenticated page load | Browser Basic Auth prompt (401 from the auth middleware) |
| `/api/*` fetch 401 | SPA shows "re-authenticate (reload the page)" |
| Config save 400 (invalid) | SPA shows the validation error text; file not written |
| Config save 409 (stale) | SPA shows "changed on disk"; offers reload |
| Config save 200 | SPA shows "saved"; updates the ETag |
| A dashboard fetch fails (network) | SPA shows a transient error, keeps the last data, retries next tick |
| `/healthz` | still unauthenticated (unchanged) |

## 6. Testing

Frontend JS isn't unit-tested (no JS runtime in the Go test harness); the Go
surface is:

- **`admin/webui.go` + serving** (`httptest`): `GET /` WITHOUT creds → `401`
  (behind auth); `GET /` WITH creds → `200`, `Content-Type text/html`, body
  contains a known marker (e.g. `<title>FreeSBC` or a `data-app="freesbc"`
  attribute); the embedded HTML is non-empty. `/healthz` still `200` without
  creds; `/api/status` still routes to the JSON handler (not shadowed by `/`).
- **Embed integrity:** a test asserts the embedded `index.html` is present and
  non-trivial (length > some bytes, contains `/api/config/raw` and
  `/api/status` — so the SPA actually wires the endpoints).
- **Manual smoke:** build; run with an admin block; open `http://127.0.0.1:8080/`
  in a browser (Basic Auth prompt → dashboard renders; edit config → save →
  reload shows the change) — documented in the report (a `curl -u admin:secret
  /` returning the HTML is the automatable part).
- Full `go vet ./... && go test ./... -race` green (known M5 SRTP flake aside).

## 7. Scope

**In M7.3:** an embedded (`go:embed`) vanilla-JS SPA — dashboard (status/calls/
peers, auto-refresh) + raw-config editor (load/save via `/api/config/raw` +
`PUT /api/config` with If-Match, error/conflict handling) — served at `/` behind
the admin Basic Auth; no new dependency.

**Deferred (non-goals):**
- A JS framework / build pipeline / bundler (vanilla + inline only).
- A structured (form-based) config editor (raw-YAML textarea; that's the M7.2
  round-trip design).
- Live metrics charts / historical graphs (the dashboard shows current values;
  Prometheus + Grafana is the graphing path).
- WebSocket / server-sent live updates (polling every ~5s).
- Kick-call button in the UI (kick-call is its own slice; the UI can add the
  button once the endpoint exists).
- Cookie/session login, CSRF tokens (Basic Auth over a private-bound listener;
  no cookies means no CSRF surface for these idempotent+PUT endpoints — and a
  PUT with Basic Auth isn't CSRF-exploitable without the credential).
- Theming, i18n, accessibility polish beyond basic semantic HTML.
