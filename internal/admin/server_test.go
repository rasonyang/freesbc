package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// minimalConfigYAML is a minimal valid v2 freesbc.yaml.
const minimalConfigYAML = `
public: { ip: 203.0.113.7 }
private: { ip: 10.77.0.2 }
edge:
  switch: [10.77.0.10:5060]
  listen: { udp: 5060 }
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
		Calls:       func() []Call { return nil },
		Ports:       func() (int, int) { return 0, 0 },
		Shield:      func() ShieldStats { return ShieldStats{DropsByReason: map[string]int64{}} },
		ActiveCalls: func() int { return 0 },
		Version:     "test",
	}
}

func newTestServer(t *testing.T, deps Deps) *Server {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: string(hash)}
	store := config.NewStore(mustCfg(t))
	return New(cfg, nil, store, deps, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
}

func testServer(t *testing.T) *Server { return newTestServer(t, emptyDeps()) }

// testServerWithCalls returns a test server whose Deps.Calls is overridden to
// return the given calls, for exercising /api/calls.
func testServerWithCalls(t *testing.T, calls []Call) *Server {
	t.Helper()
	deps := emptyDeps()
	deps.Calls = func() []Call { return calls }
	return newTestServer(t, deps)
}

// testServerWithSecretConfig returns a test server whose store carries an
// admin section with the given placeholder password hash, for exercising
// /api/config redaction.
func testServerWithSecretConfig(t *testing.T, adminHash string) *Server {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: string(hash)}
	stored := mustCfg(t)
	stored.Admin = &config.AdminConfig{Listen: "127.0.0.1:8080", PasswordHash: adminHash}
	return New(cfg, nil, config.NewStore(stored), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
}

// authGET performs an authenticated GET against s.handler(), fails the test
// on a non-200 response, and returns the response body.
func authGET(t *testing.T, s *Server, path string) []byte {
	t.Helper()
	rr := httptest.NewRecorder()
	req := newReq("GET", path, nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s: got %d want 200, body=%s", path, rr.Code, rr.Body.String())
	}
	return rr.Body.Bytes()
}

func TestAuthRequired(t *testing.T) {
	s := testServer(t)
	h := s.handler()
	// no creds → 401
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newReq("GET", "/api/status", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no creds: got %d want 401", rr.Code)
	}
	// wrong pass → 401
	rr = httptest.NewRecorder()
	req := newReq("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "wrong")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong pass: got %d want 401", rr.Code)
	}
	// wrong username → 401 (a security-boundary case: guards against an
	// inverted or missing username compare that would pass any username
	// through as long as the password matches)
	rr = httptest.NewRecorder()
	req = newReq("GET", "/api/status", nil)
	req.SetBasicAuth("wronguser", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong username: got %d want 401", rr.Code)
	}
	// correct → not 401
	rr = httptest.NewRecorder()
	req = newReq("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("correct creds must pass auth, got 401")
	}
}

func TestHealthzNoAuth(t *testing.T) {
	s := testServer(t)
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, newReq("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz no-auth: got %d want 200", rr.Code)
	}
}

func TestMetricsBehindAuth(t *testing.T) {
	s := testServer(t)
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, newReq("GET", "/metrics", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics without creds: got %d want 401", rr.Code)
	}
}

// TestHTTPServerTimeouts (T-24/D3-4): the admin http.Server must reclaim
// idle keep-alive connections and bound slow clients — pinned here on the
// constructed server rather than waited out at runtime (30s each).
func TestHTTPServerTimeouts(t *testing.T) {
	srv := testServer(t).newHTTPServer()
	if srv.IdleTimeout != 30*time.Second {
		t.Errorf("IdleTimeout = %v, want 30s", srv.IdleTimeout)
	}
	if srv.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s", srv.WriteTimeout)
	}
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s (pre-existing)", srv.ReadHeaderTimeout)
	}
}

// TestSensitiveResponsesNoStore (T-16/F-18 red test): the API serves live
// state and — on /api/config/raw — the full config with every credential
// in plaintext; responses must carry Cache-Control: no-store so browsers
// never persist them to disk. /healthz stays exempt (static poll target).
func TestSensitiveResponsesNoStore(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{"/api/config/raw", "/api/config", "/api/status", "/"} {
		rr := httptest.NewRecorder()
		req := newReq("GET", path, nil)
		req.SetBasicAuth("admin", "secret")
		s.handler().ServeHTTP(rr, req)
		if got := rr.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s: Cache-Control = %q, want no-store", path, got)
		}
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, newReq("GET", "/healthz", nil))
	if got := rr.Header().Get("Cache-Control"); got != "" {
		t.Errorf("/healthz: Cache-Control = %q, want none (exempt)", got)
	}
}

// TestAdminLoginFailureRateLimit (T-09/F-14 red test): the 11th wrong-password
// request from the same RemoteAddr within a minute must be refused 429 —
// bounding brute force — while the first 10 get the ordinary 401. While an
// IP is over its budget even CORRECT credentials are refused: the limiter
// gates before any credential work (that is what bounds the bcrypt CPU a
// single address can demand).
func TestAdminLoginFailureRateLimit(t *testing.T) {
	s := testServer(t)
	h := s.handler()
	for i := 1; i <= 11; i++ {
		rr := httptest.NewRecorder()
		req := newReq("GET", "/api/status", nil)
		req.SetBasicAuth("admin", "wrong")
		h.ServeHTTP(rr, req)
		want := http.StatusUnauthorized
		if i > authFailLimit {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("attempt %d: got %d want %d", i, rr.Code, want)
		}
	}
	rr := httptest.NewRecorder()
	req := newReq("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("correct creds while over limit: got %d want 429", rr.Code)
	}
}

// TestRequireAuthSkipsKDFOnMissingHeader (T-09/F-14 red test): with a
// REALISTIC-cost hash (DefaultCost, ~60ms per compare), the pre-fix
// requireAuth ran bcrypt even for requests carrying no Authorization header
// at all. Post-fix the headerless path must return 401 with no KDF work —
// the P99 latency over 50 requests must stay far under 5ms (the threshold
// is deliberately generous against CI jitter). Each request uses a DISTINCT
// RemoteAddr so the auth-failure rate limiter never kicks in (a 429 would
// be equally fast, but this test is about the KDF skip, not the limiter).
func TestRequireAuthSkipsKDFOnMissingHeader(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("generate hash: %v", err)
	}
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: string(hash)}
	s := New(cfg, nil, config.NewStore(mustCfg(t)), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	h := s.handler()

	var latencies []time.Duration
	for i := 0; i < 50; i++ {
		start := time.Now()
		rr := httptest.NewRecorder()
		req := newReq("GET", "/api/status", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i+1)
		h.ServeHTTP(rr, req)
		latencies = append(latencies, time.Since(start))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("headerless request %d: got %d want 401", i+1, rr.Code)
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if p99 := latencies[len(latencies)*99/100]; p99 >= 5*time.Millisecond {
		t.Fatalf("headerless request p99 latency %v — bcrypt appears to still run without an Authorization header", p99)
	}
}

// TestAuthLimiterWindowRollover: after authFailLimit failures an IP is over;
// once the window rolls, its budget is fresh again — and a single failure in
// the new window must not trip the limit.
func TestAuthLimiterWindowRollover(t *testing.T) {
	var l authLimiter
	now := time.Unix(1000, 0)
	for i := 0; i < authFailLimit; i++ {
		if l.over("ip", now) {
			t.Fatalf("failure %d: over too early", i+1)
		}
		l.recordFail("ip", now)
	}
	if !l.over("ip", now) {
		t.Fatal("must be over after authFailLimit failures")
	}
	now = now.Add(authFailWindow)
	if l.over("ip", now) {
		t.Fatal("window rollover must clear the limit")
	}
	l.recordFail("ip", now)
	if l.over("ip", now) {
		t.Fatal("one failure in a fresh window must not be over")
	}
}

// TestAuthLimiterPrunesExpired: the table sheds expired entries on access —
// after the window rolls, one new failure leaves exactly one entry behind.
func TestAuthLimiterPrunesExpired(t *testing.T) {
	var l authLimiter
	now := time.Unix(1000, 0)
	for i := 0; i < 100; i++ {
		l.recordFail(fmt.Sprintf("ip-%d", i), now)
	}
	if len(l.perIP) != 100 {
		t.Fatalf("setup: got %d entries want 100", len(l.perIP))
	}
	now = now.Add(authFailWindow + time.Second)
	l.recordFail("new-ip", now)
	if len(l.perIP) != 1 {
		t.Fatalf("expired entries not pruned: %d left", len(l.perIP))
	}
}

// Admin is restart-only: a reload that swaps the stored password_hash must
// not change which password the running server accepts.
func TestAdminIgnoresReloadedHash(t *testing.T) {
	s := testServer(t)
	h := s.handler()
	newHash, err := bcrypt.GenerateFromPassword([]byte("newsecret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	reloaded := mustCfg(t)
	reloaded.Admin = &config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: string(newHash)}
	s.store.Replace(reloaded)
	for pass, want := range map[string]int{"secret": http.StatusOK, "newsecret": http.StatusUnauthorized} {
		rr := httptest.NewRecorder()
		req := newReq("GET", "/api/status", nil)
		req.SetBasicAuth("admin", pass)
		h.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("password %q: got %d want %d", pass, rr.Code, want)
		}
	}
}

// The user name is the constant "admin", not configurable.
func TestAdminUserIsConstant(t *testing.T) {
	h := testServer(t).handler()
	rr := httptest.NewRecorder()
	req := newReq("GET", "/api/status", nil)
	req.SetBasicAuth("root", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want 401", rr.Code)
	}
}

// testCertPEMs generates a self-signed ECDSA certificate for 127.0.0.1 and
// writes cert.pem/key.pem into a temp dir, returning their paths plus a
// cert pool a TLS client can verify the server against.
func testCertPEMs(t *testing.T) (certPath, keyPath string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "admin-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return certPath, keyPath, roots
}

// TestAdminServesTLS (T-26b): with allow_remote and the top-level tls identity, the
// listener serves HTTPS with that certificate — a client that verifies
// against the cert (NO skip-verify) completes the handshake, sees the
// configured certificate, and gets the API. This is the LAN-deployment path
// the card exists for.
func TestAdminServesTLS(t *testing.T) {
	certPath, keyPath, roots := testCertPEMs(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate hash: %v", err)
	}
	cfg := &config.AdminConfig{Listen: "127.0.0.1:10100", AllowRemote: true, PasswordHash: string(hash)}
	s := New(cfg, &config.TLSConfig{Cert: certPath, Key: keyPath}, config.NewStore(mustCfg(t)), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()

	// Retry the handshake until Run has bound (it starts in a goroutine).
	deadline := time.Now().Add(5 * time.Second)
	var conn *tls.Conn
	for {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", cfg.Listen,
			&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots})
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	state := conn.ConnectionState()
	conn.Close()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != "admin-test" {
		t.Fatalf("server presented unexpected cert: %+v", state.PeerCertificates)
	}

	resp, err := (&http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
	}}).Get("https://" + cfg.Listen + "/healthz")
	if err != nil {
		t.Fatalf("https get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("https /healthz: got %d want 200", resp.StatusCode)
	}
}
