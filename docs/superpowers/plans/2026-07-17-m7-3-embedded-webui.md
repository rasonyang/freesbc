# FreeSBC M7.3 — Embedded WebUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A `go:embed`'d vanilla-JS SPA (dashboard + raw-config editor) served by the admin server at `/` behind the existing bcrypt Basic Auth, consuming the M7.1/M7.2 JSON API. Completes M7 and the MVP.

**Architecture:** One `admin/webui/index.html` (inline CSS/JS, vanilla `fetch`, no framework/build) embedded via `embed.FS`; a `handleUI` handler serves it at `/` (auth-wrapped, catch-all — the explicit `/api/*`, `/metrics`, `/healthz` routes win). The browser's native Basic Auth handles login; the SPA's `fetch` reuse the credential.

**Tech Stack:** Go stdlib `embed` + `net/http`; vanilla HTML/CSS/JS. No new dependency.

## Global Constraints

- **No new dependency, no build step.** Inline CSS/JS in a single `index.html`, `go:embed`'d. No CDN/external assets (offline-capable, CSP-safe). (spec §1)
- **Served behind the M7.1 Basic Auth** (all routes except `/healthz`). The `/` catch-all must NOT shadow the explicit `/api/*`, `/metrics`, `/healthz` routes (ServeMux longest-prefix wins). (spec §2, §3)
- **Read/write via the existing API only:** dashboard reads `/api/status`, `/api/calls`, `/api/peers`; editor reads `/api/config/raw` (+ETag) and writes `PUT /api/config` (If-Match). No new backend endpoints. (spec §4)
- `admin` still imports only config + callstate + prometheus + stdlib + bcrypt (embed is stdlib). English identifiers/comments; `gofmt -l .` clean; gate `go test ./... -race` (known M5 SRTP flake aside — if it's the only failure, re-run it).

## Verified facts
- `admin/server.go` `handler()` registers explicit routes via `mux.HandleFunc`; `requireAuth` wraps all but `/healthz`. `Server` has `store`, `deps`, `cfgPath`.
- Endpoints exist and are shaped: `/api/status` (version, uptime_seconds, active_calls, ports{in_use,total}, listeners), `/api/calls` ([{id,from,to,started,duration_seconds}]), `/api/peers` ([{Name,Address,Transport,SRTP,Register,Registered}] — note Go-cased JSON keys from the struct), `/api/config/raw` (raw YAML + ETag), `PUT /api/config` (200/400/409/413).
- Go 1.25 `embed`.

---

### Task 1: the WebUI — embed + serve + the SPA

**Files:** Create `admin/webui/index.html`, `admin/webui.go`; Modify `admin/server.go` (register `/`); Test `admin/webui_test.go`.

**Interfaces:**
- Produces: `//go:embed webui` `embed.FS`; `func (s *Server) handleUI(w, r)`; the `/` route.

- [ ] **Step 1: Write the failing test** — `admin/webui_test.go`:

```go
package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUIServedBehindAuth(t *testing.T) {
	s := testServer(t)
	// no creds → 401
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET / no creds: %d want 401", rr.Code)
	}
	// with creds → 200 HTML
	rr = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET / with creds: %d want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "FreeSBC") {
		t.Error("UI body missing FreeSBC marker")
	}
	// the SPA must actually wire the API endpoints it depends on
	for _, ep := range []string{"/api/status", "/api/config/raw", "/api/config"} {
		if !strings.Contains(body, ep) {
			t.Errorf("UI does not reference %q — is the SPA wired?", ep)
		}
	}
}

func TestUIDoesNotShadowAPI(t *testing.T) {
	s := testServer(t)
	// /api/status must still hit the JSON handler, not the UI catch-all.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("/api/status Content-Type = %q, want application/json (UI shadowed it?)", ct)
	}
	// /healthz still open (no auth)
	rr = httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz: %d want 200", rr.Code)
	}
}
```

- [ ] **Step 2: Run to verify fail** — `go test ./admin/ -run TestUI -v` → FAIL (undefined / no embed / no route).

- [ ] **Step 3: Create `admin/webui/index.html`** — a self-contained vanilla-JS SPA. Requirements (the deliverable; write real, working HTML/CSS/JS — no external assets):
  - `<title>FreeSBC` and a visible "FreeSBC" header showing the version (from `/api/status`).
  - Two tabs: **Dashboard** and **Config**.
  - **Dashboard** (default): on load + every 5s, `fetch('/api/status')`, `fetch('/api/calls')`, `fetch('/api/peers')` (same-origin, credentials reused by the browser). Render: a status line (version, uptime_seconds, active_calls, ports in_use/total); a calls `<table>` (id, from, to, duration_seconds); a peers `<table>` (Name, Address, Transport, SRTP, Register, Registered — the API returns Go-cased keys). On a fetch error, keep last data + show a small "connection error, retrying" note.
  - **Config**: a "Load" button → `fetch('/api/config/raw')`, put the text into a `<textarea>` (monospace, full-width), save the response `ETag`. A "Save" button → `fetch('/api/config', {method:'PUT', headers:{'If-Match': etag}, body: textarea.value})`; on 200 → "Saved ✓" + update etag from the response ETag; on 400 → show the response text (the validation error) in an error box; on 409 → "Config changed on disk — click Load to refresh"; on 413 → "Config too large". A hint: "keep secrets as ${ENV} references".
  - On any `fetch` returning 401 → show "Session expired — reload the page to re-authenticate".
  - Inline `<style>` and `<script>` — no external files, no CDN. Keep it clean and readable; this is real UI an operator uses.
  - The literal strings `/api/status`, `/api/config/raw`, `/api/config` MUST appear in the source (the test checks the SPA is wired).

- [ ] **Step 4: Create `admin/webui.go`**

```go
package admin

import (
	"embed"
	"net/http"
)

//go:embed webui/index.html
var webuiFS embed.FS

// handleUI serves the embedded single-page web UI. It is the catch-all route
// ("/"), so the explicit /api/*, /metrics, and /healthz routes take precedence
// in the mux; any other path serves the SPA (one page).
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	data, err := webuiFS.ReadFile("webui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
```

- [ ] **Step 5: Register the route** — in `admin/server.go` `handler()`, after the explicit routes, add:

```go
	mux.HandleFunc("/", s.requireAuth(s.handleUI)) // SPA catch-all (behind auth)
```

- [ ] **Step 6: Run to verify pass** — `go test ./admin/ -race -v` → GREEN (UI tests + all M7.1/M7.2 admin tests: `/` behind auth serves HTML with the endpoint markers, `/api/status` not shadowed, `/healthz` open). `gofmt`/`vet`/`build` clean.

- [ ] **Step 7: Commit**

```bash
git add admin/webui admin/webui.go admin/server.go admin/webui_test.go
git commit -m "feat(admin): embedded vanilla-JS WebUI (dashboard + config editor) served at / behind auth"
```

---

### Task 2: README + example note + verification

- [ ] **Step 1: Roadmap** — in `README.md`, mark M7.3 done and the M7 parent done:

```
| M7 | Operability: admin API, metrics, embedded WebUI | ✅ done |
| ├ M7.3 | Embedded WebUI (dashboard + config editor) | ✅ done |
```

Also add a short "Admin & WebUI" note near the run instructions: enable the `admin` block (with a bcrypt `password_hash`), then browse `http://<listen>/` (Basic Auth) for the dashboard + config editor, or scrape `/metrics`.

- [ ] **Step 2: gofmt/vet/build + full race suite** — `gofmt -l . && go vet ./... && go build ./... && go test ./... -race -count=1` → green (known M5 SRTP flake aside).

- [ ] **Step 3: Smoke** — build with the admin block; `curl -u admin:secret http://127.0.0.1:8080/` returns the HTML (contains `FreeSBC`); `curl http://127.0.0.1:8080/` (no creds) → 401. Optionally note a browser check. Document in the report.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: mark M7.3 (embedded WebUI) and M7 done"
```

---

## Notes for the implementer

- **The UI is behind auth via the `/` catch-all.** ServeMux gives the explicit routes precedence, so `/api/*`, `/metrics`, `/healthz` are unaffected; `/` serves the SPA. The browser's Basic Auth prompt covers the page and all its `fetch` calls (same origin).
- **No new backend.** The SPA only calls existing endpoints. Do not add API routes here.
- **Vanilla only.** No framework, no bundler, no CDN — inline CSS/JS, offline-capable. It's real UI, so make it usable, but keep it single-file.
- **The `/api/peers` JSON keys are Go-cased** (`Name`, `Address`, `Register`, `Registered`, ...) — the SPA must read those exact keys.
- **Deferred:** JS framework/build, form-based config editor, metric charts, WebSockets, kick-call button, cookie/session login, i18n.
```
