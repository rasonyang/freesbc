package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// newTestServerWithFile writes yaml to a temp config file, builds a Store
// from it (via config.Parse, same as production startup), and returns a
// Server whose cfgPath points at that file, plus the file's path.
func newTestServerWithFile(t *testing.T, yaml string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "freesbc.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse test config: %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	admincfg := &config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: string(hash)}
	store := config.NewStore(cfg)
	s := New(admincfg, nil, store, emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), path)
	return s, path
}

// authGETraw performs an authenticated GET against s.handler() and returns
// the raw ResponseRecorder (unlike authGET, it does not assert on status so
// callers can check non-200 outcomes too).
func authGETraw(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := newReq(http.MethodGet, path, nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	return rr
}

// authREQ performs an authenticated request of the given method and body
// against s.handler(), with a same-origin Origin header (newReq).
func authREQ(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := newReq(method, path, strings.NewReader(body))
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	return rr
}

const validCfg = `
public: { ip: 127.0.0.1 }
private: { ip: 10.77.0.2 }
edge:
  switch: [10.77.0.10:5060]
  listen: { udp: 5060 }
`

func TestConfigRawReturnsFile(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	rr := authGETraw(t, s, "/api/config/raw")
	if rr.Code != 200 {
		t.Fatalf("raw GET: %d", rr.Code)
	}
	if rr.Body.String() != validCfg {
		t.Errorf("raw body differs from the file")
	}
	if rr.Header().Get("ETag") != "" {
		t.Error("raw GET must not advertise an ETag: the API has no conditional write")
	}
}

func TestConfigRawRejectsNonGET(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	rr := authREQ(t, s, http.MethodPut, "/api/config/raw", validCfg+"# edited\n")
	if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != "GET" {
		t.Fatalf("PUT /api/config/raw: %d Allow=%q, want 405 GET", rr.Code, rr.Header().Get("Allow"))
	}
}

// The config API is read-only: no method but GET reaches /api/config, and
// nothing ever touches the file.
func TestConfigIsReadOnly(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		rr := authREQ(t, s, m, "/api/config", validCfg+"# x\n")
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/config: %d, want 405", m, rr.Code)
		}
		if got := rr.Header().Get("Allow"); got != "GET" {
			t.Errorf("%s /api/config: Allow=%q, want GET", m, got)
		}
	}
	if got, _ := os.ReadFile(path); string(got) != validCfg {
		t.Fatal("config file changed")
	}
}

func validate(t *testing.T, s *Server, body string) (*httptest.ResponseRecorder, validateResult, string) {
	t.Helper()
	rr := authREQ(t, s, http.MethodPost, "/api/config/validate", body)
	raw := rr.Body.String()
	var res validateResult
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode %q: %v", raw, err)
		}
	}
	return rr, res, raw
}

func TestConfigValidateValid(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	rr, res, raw := validate(t, s, validCfg+"# comment\n")
	if rr.Code != 200 || !res.Valid {
		t.Fatalf("valid candidate: %d %s", rr.Code, raw)
	}
	if !strings.Contains(raw, `"errors":[]`) || !strings.Contains(raw, `"restart_required":[]`) {
		t.Errorf("empty lists must encode as [], got %s", raw)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if got, _ := os.ReadFile(path); string(got) != validCfg {
		t.Fatal("validate must not write the file")
	}
}

func TestConfigValidateInvalid(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	for _, body := range []string{
		"not: [valid yaml: for: this: schema",
		strings.Replace(validCfg, "ip: 127.0.0.1", "ip: not-an-ip", 1),
	} {
		rr, res, raw := validate(t, s, body)
		if rr.Code != 200 || res.Valid || len(res.Errors) == 0 {
			t.Errorf("invalid candidate %q: %d %s", body, rr.Code, raw)
		}
		if strings.Contains(raw, `"errors":null`) || !strings.Contains(raw, `"restart_required":[]`) {
			t.Errorf("lists must never be null: %s", raw)
		}
	}
}

func TestConfigValidateRestartRequired(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	cand := strings.Replace(validCfg, "udp: 5060", "udp: 5070", 1)
	_, res, raw := validate(t, s, cand)
	if !res.Valid || len(res.RestartRequired) != 1 || res.RestartRequired[0] != "edge.listen" {
		t.Fatalf("restart_required = %v (%s), want [edge.listen]", res.RestartRequired, raw)
	}
	// A hot-only change needs no restart.
	_, res, raw = validate(t, s, validCfg+"shield:\n  rate_limit: 50/s\n")
	if !res.Valid || len(res.RestartRequired) != 0 {
		t.Fatalf("shield-only candidate: %s", raw)
	}
}

// restart_required is measured against Deps.Running (the startup snapshot),
// not the store's current snapshot, which a hot reload may have advanced.
func TestConfigValidateUsesStartupSnapshot(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	boot := s.store.Current()
	moved := strings.Replace(validCfg, "udp: 5060", "udp: 5070", 1)
	cfg, err := config.Parse([]byte(moved))
	if err != nil {
		t.Fatal(err)
	}
	s.store.Replace(cfg) // a reload the process cannot apply
	s.deps.Running = func() *config.Config { return boot }
	_, res, raw := validate(t, s, moved)
	if len(res.RestartRequired) != 1 || res.RestartRequired[0] != "edge.listen" {
		t.Fatalf("restart_required = %v (%s), want [edge.listen] against the startup snapshot", res.RestartRequired, raw)
	}
}

func TestConfigValidateMethodAndSize(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rr := authREQ(t, s, m, "/api/config/validate", validCfg)
		if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != "POST" {
			t.Errorf("%s: %d Allow=%q, want 405 POST", m, rr.Code, rr.Header().Get("Allow"))
		}
	}
	rr, _, _ := validate(t, s, validCfg+"#"+strings.Repeat("x", maxConfigBytes))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d, want 413", rr.Code)
	}
}

func TestConfigValidateGuards(t *testing.T) {
	s, _ := newTestServerWithFile(t, validCfg)
	// No credentials: 401.
	req := newReq(http.MethodPost, "/api/config/validate", strings.NewReader(validCfg))
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: %d, want 401", rr.Code)
	}
	// Foreign Origin: 403 before auth.
	req = newReq(http.MethodPost, "/api/config/validate", strings.NewReader(validCfg))
	req.Header.Set("Origin", "http://evil.example.com")
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("foreign origin: %d, want 403", rr.Code)
	}
}

// design.md §14.2 names ${ENV} references as the protection for secrets in
// the config file. A candidate whose reference expands into an invalid value
// must not read the environment value back through the response.
func TestConfigValidateDoesNotEchoEnv(t *testing.T) {
	const sentinel = "audit-sentinel-env-value"
	t.Setenv("AUDIT_SECRET", sentinel)
	s, _ := newTestServerWithFile(t, validCfg)
	body := strings.Replace(validCfg, "ip: 127.0.0.1", `ip: "${AUDIT_SECRET}"`, 1)
	rr, res, raw := validate(t, s, body)
	if rr.Code != 200 || res.Valid || len(res.Errors) == 0 {
		t.Fatalf("want 200 with errors, got %d %s", rr.Code, raw)
	}
	if strings.Contains(raw, sentinel) {
		t.Errorf("response reveals the environment variable's value:\n%s", raw)
	}
}
