package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/config"
	"golang.org/x/crypto/bcrypt"
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

// newTestServerWithFile writes yaml to a temp config file, builds a Store
// from it (via config.Parse, same as production startup), and returns a
// Server whose cfgPath points at that file, plus the file's path.
func newTestServerWithFile(t *testing.T, yaml string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sbc.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse test config: %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	admincfg := &config.AdminConfig{Listen: "127.0.0.1:0"}
	admincfg.Auth.Username = "admin"
	admincfg.Auth.PasswordHash = string(hash)
	store := config.NewStore(cfg)
	s := New(admincfg, store, emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), path)
	return s, path
}

// authGETraw performs an authenticated GET against s.handler() and returns
// the raw ResponseRecorder (unlike authGET, it does not assert on status so
// callers can check non-200 outcomes too).
func authGETraw(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	return rr
}

// authPUT performs an authenticated PUT with the given body and optional
// If-Match header against s.handler().
func authPUT(t *testing.T, s *Server, path, body, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	return authREQ(t, s, http.MethodPut, path, body, ifMatch)
}

// authREQ performs an authenticated request of the given method, body, and
// optional If-Match header against s.handler().
func authREQ(t *testing.T, s *Server, method, path, body, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.SetBasicAuth("admin", "secret")
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	s.handler().ServeHTTP(rr, req)
	return rr
}

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
	// Block style, not flow style: an unquoted ${VAR} contains '{' and '}',
	// which are flow indicators forbidden inside a flow-mapping plain scalar
	// (YAML spec, ns-plain-safe-in) — `{ password: ${CFGTEST_PW} }` fails to
	// parse. Block style has no such restriction.
	base := strings.Replace(validCfg,
		"    allowed_ips: [127.0.0.1/32]",
		"    allowed_ips: [127.0.0.1/32]\n    auth:\n      username: u\n      password: ${CFGTEST_PW}", 1)
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

// TestConfigWriteTooLargeRejectedFileUnchanged proves the maxConfigBytes cap
// is enforced BEFORE any write is attempted: a >1MiB body must come back 413
// and must never touch the file, not even a truncated write. If the size
// check in handleConfigWrite were removed or reordered after
// writeFileAtomic, this test would fail (either a non-413 status, or a
// mutated file).
func TestConfigWriteTooLargeRejectedFileUnchanged(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	oversized := validCfg + strings.Repeat(" ", 1<<20) // > maxConfigBytes (1<<20)
	rr := authPUT(t, s, "/api/config", oversized, "")
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("PUT oversized: %d, want 413", rr.Code)
	}
	got, _ := os.ReadFile(path)
	if string(got) != validCfg {
		t.Fatal("oversized PUT must not touch the file")
	}
}

// TestConfigRawRequiresAuth proves the write-adjacent read route is behind
// auth too (TestAuthRequired in server_test.go only covers /api/status).
func TestConfigRawRequiresAuth(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	// no credentials set
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/config/raw no creds: %d, want 401", rr.Code)
	}
}

// TestConfigRawRejectsNonGET proves handleConfigRaw's method guard: a PUT to
// /api/config/raw must never be mistaken for a successful write — it should
// 405, not silently return the (unwritten) file with a 200.
func TestConfigRawRejectsNonGET(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	rr := authPUT(t, s, "/api/config/raw", validCfg+"# edited\n", "")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /api/config/raw: %d, want 405", rr.Code)
	}
	if allow := rr.Header().Get("Allow"); allow != "GET" {
		t.Errorf("Allow header = %q, want %q", allow, "GET")
	}
}

// TestConfigWritePreservesFileMode proves a valid PUT preserves the
// pre-existing file's permission bits rather than overwriting them with a
// hardcoded default.
func TestConfigWritePreservesFileMode(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := validCfg + "# mode-preserved\n"
	rr := authPUT(t, s, "/api/config", edited, "")
	if rr.Code != 200 {
		t.Fatalf("PUT valid: %d body=%s", rr.Code, rr.Body.String())
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("mode changed: before=%v after=%v", before.Mode().Perm(), after.Mode().Perm())
	}
	if after.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", after.Mode().Perm())
	}
}
