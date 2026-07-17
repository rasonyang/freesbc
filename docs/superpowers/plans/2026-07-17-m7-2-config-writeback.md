# FreeSBC M7.2 — Config Write-Back Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** `PUT /api/config` writes a validated config to disk atomically, preserving comments and `${ENV}` references; `GET /api/config/raw` returns the raw file for editing. The existing hot-reload picks up the change.

**Architecture:** Full-document round-trip (no AST-patch): the server writes the client's literal YAML bytes verbatim (comments/`${ENV}` preserved by construction, never expanded), after `config.Parse` validation, via an atomic temp-file+rename. ETag optimistic concurrency guards against clobbering concurrent edits.

**Tech Stack:** Go stdlib (`os`, `io`, `crypto/sha256`, `net/http`), `config.Parse` for validation. No new dependency.

## Global Constraints

- **Full document, verbatim, never expanded.** PUT writes the exact submitted bytes; the server never expands `${ENV}` on the write path. (spec §1)
- **Validate before write.** `config.Parse(body)` must succeed (returns a `*Config`, no side effects) before any disk write; on error → `400` with the error text, file untouched. (spec §3)
- **Atomic write.** Temp file in the SAME directory → write → Sync → chmod to original mode → Rename over the config path. Never a partial/corrupt file. (spec §3)
- **ETag optimistic concurrency.** `GET /api/config/raw` returns `ETag: "<sha256hex>"`; `PUT` with a non-matching `If-Match` → `409`. Absent `If-Match` → blind write. (spec §3)
- **Auth.** Both new routes are behind the M7.1 bcrypt Basic Auth. `admin` still imports only config + callstate + prometheus + stdlib + bcrypt (no sig).
- Body size cap (1 MiB) → `413`. English identifiers/comments; stdlib `testing` + `httptest`; `gofmt -l .` clean; gate `go test ./... -race` (the known M5 `TestBridgeSRTPRequiredBNoCryptoFailsOver` flake aside — if it's the ONLY failure, re-run it; everything else must be green).

## Verified facts

- `config.Parse(data []byte) (*Config, error)` (config/loader.go:31) — pure validator, no live-store side effect.
- `config.Watch` watches `filepath.Dir(path)` and reloads on `Write|Create|Rename` (debounced 200ms) — observes an atomic rename.
- `admin.New(cfg *config.AdminConfig, store *config.Store, deps Deps, log *slog.Logger) *Server` (admin/server.go:56); routes registered in `handler()` (server.go:62-68); `/api/config` currently `GET`-only via `handleConfig` (the M7.1 redacted view).
- Go 1.25 — `http.ServeMux` supports method patterns, but the M7.1 mux uses path-only patterns; this plan keeps that style and dispatches by `r.Method` inside `handleConfig`.

---

### Task 1: thread `cfgPath` + the atomic-write primitive

**Files:** Modify `admin/server.go` (New signature + `cfgPath` field), `main.go` (pass cfgPath); Create `admin/config_write.go` (atomic write + etag helpers); Test `admin/config_write_test.go`. Update all `admin.New(...)` call sites in tests (add the cfgPath arg).

**Interfaces:**
- Produces: `Server.cfgPath string`; `New(cfg, store, deps, log, cfgPath string)`; `func etagOf(b []byte) string` (`"\"" + hex(sha256(b)) + "\""`); `func writeFileAtomic(path string, data []byte, mode os.FileMode) error` (temp in same dir → write → Sync → chmod → Rename; remove temp on error).

- [ ] **Step 1: Write the failing test** — `admin/config_write_test.go`:

```go
package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("old: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new: 2\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new: 2\n" {
		t.Fatalf("content = %q, want new", got)
	}
	// no leftover temp files in the dir
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected only cfg.yaml, got %d entries (temp leak?)", len(entries))
	}
}

func TestWriteFileAtomicBadDirLeavesOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(path, []byte("keep\n"), 0o600)
	// point at a non-existent directory → CreateTemp fails → original intact
	bad := filepath.Join(dir, "nope", "cfg.yaml")
	if err := writeFileAtomic(bad, []byte("x"), 0o600); err == nil {
		t.Fatal("expected error writing into a missing dir")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "keep\n" {
		t.Fatalf("original mutated: %q", got)
	}
}

func TestEtagOf(t *testing.T) {
	a := etagOf([]byte("hello"))
	b := etagOf([]byte("hello"))
	c := etagOf([]byte("world"))
	if a != b {
		t.Error("etag not deterministic")
	}
	if a == c {
		t.Error("different content → same etag")
	}
	if !strings.HasPrefix(a, `"`) || !strings.HasSuffix(a, `"`) {
		t.Errorf("etag must be quoted: %s", a)
	}
}
```

- [ ] **Step 2: Run to verify fail** — `go test ./admin/ -run 'TestWriteFileAtomic|TestEtagOf' -v` → FAIL (undefined).

- [ ] **Step 3: Implement `admin/config_write.go`** (helpers only for this task):

```go
package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// etagOf returns a quoted strong ETag (sha256 hex) for data.
func etagOf(data []byte) string {
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// writeFileAtomic writes data to path atomically: a temp file in the same
// directory is written, synced, chmod'd to mode, then renamed over path
// (atomic on one filesystem). On any failure the temp file is removed and the
// original path is left untouched. The submitted bytes are written verbatim —
// no transformation, so comments and ${ENV} references are preserved.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Add `cfgPath` to Server + New** — in `admin/server.go`: add `cfgPath string` to the `Server` struct; change `New` to `func New(cfg *config.AdminConfig, store *config.Store, deps Deps, log *slog.Logger, cfgPath string) *Server` and set `cfgPath: cfgPath`. Update every `New(...)` call in the admin tests (the `newTestServer` helper) to pass a cfgPath (a temp file path — tests that write config will need a real temp file; tests that don't can pass `""`).

- [ ] **Step 5: Wire cfgPath in main.go** — pass the `cfgPath` variable (the config path `run()` already has) into `admin.New(adminCfg, store, deps, log, cfgPath)`.

- [ ] **Step 6: Run to verify pass** — `go test ./admin/ -race -v` (helpers + all M7.1 admin tests still pass with the new signature), `go build ./...`, `gofmt`/`vet` clean.

- [ ] **Step 7: Commit**

```bash
git add admin/config_write.go admin/config_write_test.go admin/server.go main.go
git commit -m "feat(admin): atomic config-file write helper + etag; thread cfgPath into the admin server"
```

---

### Task 2: `GET /api/config/raw` + `PUT /api/config`

**Files:** Modify `admin/config_write.go` (add the two handlers), `admin/server.go` (register `/api/config/raw`; make `/api/config` method-dispatch); Test `admin/config_write_test.go`.

**Interfaces:**
- Consumes: `writeFileAtomic`, `etagOf`, `s.cfgPath`, `config.Parse` (validation).
- Produces: `handleConfigRaw` (GET), `handleConfigWrite` (PUT); `handleConfig` becomes a method dispatcher (GET → the M7.1 redacted view, now `handleConfigGet`; PUT → `handleConfigWrite`; else 405).

- [ ] **Step 1: Write the failing tests** — add to `admin/config_write_test.go`. Use a server built over a real temp config file (extend `newTestServer` or a new helper `newTestServerWithFile(t, yaml)` that writes `yaml` to a temp path and passes it as cfgPath + builds the store from it):

```go
const validCfg = `
listen:
  sip: [udp://127.0.0.1:5060]
  media:
    port_range: 16384-32768
    public_ip: 127.0.0.1
peers:
  p:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: r
    from: p
    to: [p]
`

func TestConfigRawReturnsFileAndEtag(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	_ = path
	rr := authGETraw(t, s, "/api/config/raw") // helper: basic-auth GET, returns *httptest.ResponseRecorder
	if rr.Code != 200 {
		t.Fatalf("raw GET: %d", rr.Code)
	}
	if rr.Body.String() != validCfg {
		t.Fatalf("raw body not verbatim")
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatal("missing ETag")
	}
}

func TestConfigWriteValidUpdatesFile(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	// a valid edited config (add a comment + a second route target is overkill;
	// just append a harmless comment to prove verbatim write)
	edited := validCfg + "# edited via API\n"
	rr := authPUT(t, s, "/api/config", edited, "") // helper: basic-auth PUT with body, optional If-Match
	if rr.Code != 200 {
		t.Fatalf("PUT valid: %d body=%s", rr.Code, rr.Body.String())
	}
	got, _ := os.ReadFile(path)
	if string(got) != edited {
		t.Fatalf("file not updated verbatim:\n%s", got)
	}
}

func TestConfigWriteInvalidRejectedFileUnchanged(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	rr := authPUT(t, s, "/api/config", "not: [valid yaml: for: this: schema", "")
	if rr.Code != 400 {
		t.Fatalf("PUT invalid: %d, want 400", rr.Code)
	}
	got, _ := os.ReadFile(path)
	if string(got) != validCfg {
		t.Fatal("invalid PUT must not touch the file")
	}
}

func TestConfigWriteStaleIfMatch409(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	_ = path
	rr := authPUT(t, s, "/api/config", validCfg+"# x\n", `"deadbeef"`) // wrong etag
	if rr.Code != 409 {
		t.Fatalf("stale If-Match: %d, want 409", rr.Code)
	}
}

func TestConfigWritePreservesEnvRef(t *testing.T) {
	t.Setenv("CFGTEST_PW", "s3cr3t")
	base := strings.Replace(validCfg,
		"    allowed_ips: [127.0.0.1/32]",
		"    allowed_ips: [127.0.0.1/32]\n    auth: { username: u, password: ${CFGTEST_PW} }", 1)
	s, path := newTestServerWithFile(t, validCfg)
	rr := authPUT(t, s, "/api/config", base, "")
	if rr.Code != 200 {
		t.Fatalf("PUT with env ref: %d body=%s", rr.Code, rr.Body.String())
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "${CFGTEST_PW}") {
		t.Fatal("env ref not preserved on disk (expansion leaked to file!)")
	}
	if strings.Contains(string(got), "s3cr3t") {
		t.Fatal("EXPANDED secret written to disk")
	}
}

func TestConfigMethodRouting(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	// GET → redacted view (200); DELETE → 405
	if rr := authGETraw(t, s, "/api/config"); rr.Code != 200 {
		t.Fatalf("GET /api/config: %d", rr.Code)
	}
	rr := authREQ(t, s, "DELETE", "/api/config", "", "")
	if rr.Code != 405 {
		t.Fatalf("DELETE /api/config: %d, want 405", rr.Code)
	}
}
```

Write the helpers `newTestServerWithFile(t, yaml) (*Server, path)`, `authGETraw`, `authPUT(t, s, path, body, ifMatch)`, `authREQ(t, s, method, path, body, ifMatch)` — all do `SetBasicAuth("admin","secret")` and drive `s.handler()`.

- [ ] **Step 2: Run to verify fail** — `go test ./admin/ -run TestConfig -v` → FAIL.

- [ ] **Step 3: Implement the handlers** — in `admin/config_write.go`:

```go
const maxConfigBytes = 1 << 20 // 1 MiB

func (s *Server) handleConfigRaw(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.cfgPath)
	if err != nil {
		s.log.Error("read config for raw view", "err", err)
		http.Error(w, "cannot read config", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("ETag", etagOf(data))
	_, _ = w.Write(data)
}

func (s *Server) handleConfigWrite(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigBytes+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxConfigBytes {
		http.Error(w, "config too large", http.StatusRequestEntityTooLarge)
		return
	}
	// optimistic concurrency: compare If-Match to the CURRENT file's etag.
	if want := r.Header.Get("If-Match"); want != "" {
		cur, err := os.ReadFile(s.cfgPath)
		if err != nil {
			http.Error(w, "cannot read current config", http.StatusInternalServerError)
			return
		}
		if want != etagOf(cur) {
			http.Error(w, "config changed since read (stale If-Match)", http.StatusConflict)
			return
		}
	}
	// validate before writing — Parse expands ${ENV} and validates a COPY.
	if _, err := config.Parse(body); err != nil {
		http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
		return
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(s.cfgPath); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileAtomic(s.cfgPath, body, mode); err != nil {
		s.log.Error("write config", "err", err)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	s.log.Warn("config written via admin API", "path", s.cfgPath, "bytes", len(body))
	w.Header().Set("ETag", etagOf(body))
	w.WriteHeader(http.StatusOK)
}
```

Add `"io"`, `"os"`, and `"github.com/freesbc/freesbc/config"` imports as needed (config already imported).

Rename the M7.1 `handleConfig` (the redacted view) to `handleConfigGet`, and make `handleConfig` a dispatcher:

```go
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleConfigGet(w, r) // the M7.1 redacted view
	case http.MethodPut:
		s.handleConfigWrite(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
```

In `handler()` (server.go), register the raw route: `mux.HandleFunc("/api/config/raw", s.requireAuth(s.handleConfigRaw))` (keep `/api/config` → `s.requireAuth(s.handleConfig)`).

- [ ] **Step 4: Run to verify pass** — `go test ./admin/ -race -v` → GREEN (all config-write tests + M7.1 admin tests). `gofmt`/`vet`/`build` clean.

- [ ] **Step 5: Commit**

```bash
git add admin/config_write.go admin/server.go admin/config_write_test.go
git commit -m "feat(admin): GET /api/config/raw + PUT /api/config (validate, ETag, atomic write, env-ref preserved)"
```

---

### Task 3: README + verification

- [ ] **Step 1: Roadmap** — in `README.md`, mark M7.2 done, M7.3 next:

```
| ├ M7.2 | Config write-back (`PUT /api/config`, atomic, `${ENV}`-preserving) | ✅ done |
| └ M7.3 | Embedded WebUI | next |
```

- [ ] **Step 2: gofmt/vet/build + full race suite** — `gofmt -l . && go vet ./... && go build ./... && go test ./... -race -count=1` → green (the known M5 SRTP flake aside — if it's the only failure, re-run it).

- [ ] **Step 3: Smoke** — build; run with an admin block (real bcrypt hash); `curl` `GET /api/config/raw` (200 + ETag, body = the file), `PUT /api/config` with a valid edited body (200), then GET again to see the edit; PUT an invalid body (400, file unchanged). Document in the report.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: mark M7.2 (config write-back) done, M7.3 next"
```

---

## Notes for the implementer

- **Never expand on write.** PUT writes the submitted bytes verbatim; `config.Parse` is used ONLY to validate (it returns a throwaway `*Config`). The on-disk file keeps `${ENV}` refs — the env-ref test asserts the literal `${...}` survives and the expanded value does NOT appear.
- **Validate before touching disk.** A bad config never reaches `writeFileAtomic`; the file is byte-identical after a rejected PUT (a test asserts this).
- **Atomic = all-or-nothing.** Temp+rename in the same dir; a failure removes the temp and leaves the original. No partial writes.
- **ETag** is optional protection: absent `If-Match` → blind write (still validated + atomic); present + stale → 409.
- **Deferred:** field-level AST-patch, diff/preview, rollback history, synchronous reload confirmation in the response, redaction of `/api/config/raw` (keep secrets in `${ENV}`).
