package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/freesbc/freesbc/callstate"
	"github.com/freesbc/freesbc/config"
	"golang.org/x/crypto/bcrypt"
)

// minimalConfigYAML is a minimal valid sbc.yaml: one SIP listener and one
// peer, everything else left to withDefaults.
const minimalConfigYAML = `
listen:
  sip: [udp://127.0.0.1:45999]
peers:
  carrier:
    address: 127.0.0.1:5060
`

// mustCfg parses a minimal valid config for tests that need a *config.Config
// to build a config.Store (the admin server reads config through the store,
// not through the AdminConfig it's constructed with).
func mustCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(minimalConfigYAML))
	if err != nil {
		t.Fatalf("parse minimal test config: %v", err)
	}
	return cfg
}

// emptyDeps returns Deps with harmless zero-value closures; individual tests
// override the fields they exercise.
func emptyDeps() Deps {
	return Deps{
		Calls:       func() []callstate.Call { return nil },
		Peers:       func() []PeerStatus { return nil },
		Ports:       func() (int, int) { return 0, 0 },
		Shield:      func() ShieldStats { return ShieldStats{DropsByReason: map[string]int64{}} },
		ActiveCalls: func() int { return 0 },
		Version:     "test",
	}
}

func newTestServer(t *testing.T, deps Deps) *Server {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0"}
	cfg.Auth.Username = "admin"
	cfg.Auth.PasswordHash = string(hash)
	store := config.NewStore(mustCfg(t))
	return New(cfg, store, deps, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func testServer(t *testing.T) *Server { return newTestServer(t, emptyDeps()) }

func TestAuthRequired(t *testing.T) {
	s := testServer(t)
	h := s.handler()
	// no creds → 401
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/status", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no creds: got %d want 401", rr.Code)
	}
	// wrong pass → 401
	rr = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "wrong")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong pass: got %d want 401", rr.Code)
	}
	// correct → not 401 (stub returns 501 until Task 4)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("correct creds must pass auth, got 401")
	}
}

func TestHealthzNoAuth(t *testing.T) {
	s := testServer(t)
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz no-auth: got %d want 200", rr.Code)
	}
}

func TestMetricsBehindAuth(t *testing.T) {
	s := testServer(t)
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics without creds: got %d want 401", rr.Code)
	}
}
