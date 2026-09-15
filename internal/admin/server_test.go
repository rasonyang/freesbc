package admin

import (
	"bytes"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// minimalConfigYAML is a minimal valid sbc.yaml: one SIP listener and one
// peer, everything else left to withDefaults. The peer carries an
// allowed_ips prefix: T-11 (F-16) rejects peers without one.
const minimalConfigYAML = `
listen:
  sip: [udp://127.0.0.1:45999]
peers:
  carrier:
    address: 127.0.0.1:5060
    allowed_ips: [203.0.113.0/24]
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
		Peers:       func() []PeerStatus { return nil },
		Ports:       func() (int, int) { return 0, 0 },
		Shield:      func() ShieldStats { return ShieldStats{DropsByReason: map[string]int64{}} },
		ActiveCalls: func() int { return 0 },
		KillCall:    func(string) bool { return false },
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
	return New(cfg, store, deps, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
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

// testServerWithSecretConfig returns a test server backed by a config.Store
// whose only peer ("carrier") carries the given password, for exercising
// /api/config redaction.
func testServerWithSecretConfig(t *testing.T, peerPassword string) *Server {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0"}
	cfg.Auth.Username = "admin"
	cfg.Auth.PasswordHash = string(hash)
	// The store's admin section must carry the SAME credentials the tests
	// authenticate with: requireAuth reads the store's current snapshot on
	// every request (T-15), so a placeholder hash here would lock the tests
	// out.
	store := config.NewStore(mustCfgWithSecret(t, peerPassword, string(hash)))
	return New(cfg, store, emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
}

// authGET performs an authenticated GET against s.handler(), fails the test
// on a non-200 response, and returns the response body.
func authGET(t *testing.T, s *Server, path string) []byte {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
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
	// wrong username → 401 (a security-boundary case: guards against an
	// inverted or missing username compare that would pass any username
	// through as long as the password matches)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("wronguser", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong username: got %d want 401", rr.Code)
	}
	// correct → not 401
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
		req := httptest.NewRequest("GET", path, nil)
		req.SetBasicAuth("admin", "secret")
		s.handler().ServeHTTP(rr, req)
		if got := rr.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s: Cache-Control = %q, want no-store", path, got)
		}
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if got := rr.Header().Get("Cache-Control"); got != "" {
		t.Errorf("/healthz: Cache-Control = %q, want none (exempt)", got)
	}
}

// TestAdminAuthFailureRateLimit (T-09/F-14 red test): the 11th wrong-password
// request from the same RemoteAddr within a minute must be refused 429 —
// bounding brute force — while the first 10 get the ordinary 401. While an
// IP is over its budget even CORRECT credentials are refused: the limiter
// gates before any credential work (that is what bounds the bcrypt CPU a
// single address can demand).
func TestAdminAuthFailureRateLimit(t *testing.T) {
	s := testServer(t)
	h := s.handler()
	for i := 1; i <= 11; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/status", nil)
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
	req := httptest.NewRequest("GET", "/api/status", nil)
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
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0"}
	cfg.Auth.Username = "admin"
	cfg.Auth.PasswordHash = string(hash)
	s := New(cfg, config.NewStore(mustCfg(t)), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	h := s.handler()

	var latencies []time.Duration
	for i := 0; i < 50; i++ {
		start := time.Now()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/status", nil)
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

// TestAdminAuthHotReloadRevokesOldPassword (T-15/F-15 red test): after
// store.Replace swaps in a config whose admin.auth carries a NEW hash, the
// old password must be refused 401 immediately — no restart, no grace
// window — and the new one must pass. Pre-fix, requireAuth read the
// construction-time cfg, so the old password kept working until restart
// (the revocation gap F-15 describes).
func TestAdminAuthHotReloadRevokesOldPassword(t *testing.T) {
	s := testServer(t)
	h := s.handler()

	// The construction-time password works before the reload.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("old password before reload: got %d want 200", rr.Code)
	}

	// Hot reload: a new hash lands in the store.
	newHash, err := bcrypt.GenerateFromPassword([]byte("newsecret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate new hash: %v", err)
	}
	reloaded := mustCfg(t)
	reloaded.Admin = &config.AdminConfig{Listen: "127.0.0.1:0", Auth: config.AdminAuth{
		Username: "admin", PasswordHash: string(newHash),
	}}
	s.store.Replace(reloaded)

	// The old password must be revoked on the very next request.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("old password after hot reload: got %d want 401 (revocation gap)", rr.Code)
	}

	// The new password must pass.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "newsecret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("new password after hot reload: got %d want 200", rr.Code)
	}
}

// lockedBuffer is a goroutine-safe bytes.Buffer for capturing logs written
// from server goroutines while the test polls them.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestAdminListenChangeWarns (T-15/F-15): a hot reload that changes
// admin.listen cannot rebind the running listener, but must log a prominent
// warning instead of silently keeping the old address.
func TestAdminListenChangeWarns(t *testing.T) {
	var buf lockedBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate hash: %v", err)
	}
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0", Auth: config.AdminAuth{
		Username: "admin", PasswordHash: string(hash),
	}}
	store := config.NewStore(mustCfg(t))
	s := New(cfg, store, emptyDeps(), logger, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()

	// Wait until Run is serving (the watcher is started before the
	// listening log line, so this also orders the subscription).
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "admin server listening") {
		if time.Now().After(deadline) {
			t.Fatal("admin server never started")
		}
		time.Sleep(10 * time.Millisecond)
	}

	reloaded := mustCfg(t)
	reloaded.Admin = &config.AdminConfig{Listen: "127.0.0.1:45888", Auth: config.AdminAuth{
		Username: "admin", PasswordHash: string(hash),
	}}
	store.Replace(reloaded)

	deadline = time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "admin.listen changed") {
		if time.Now().After(deadline) {
			t.Fatalf("listen-change warning never logged; log:\n%s", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
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

// TestAdminServesTLS (T-26b): with admin.tls_cert/tls_key configured, the
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
	cfg := &config.AdminConfig{Listen: "127.0.0.1:45886", TLSCert: certPath, TLSKey: keyPath}
	cfg.Auth.Username = "admin"
	cfg.Auth.PasswordHash = string(hash)
	s := New(cfg, config.NewStore(mustCfg(t)), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
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

// TestAdminRemoteWithoutTLSWarns (T-26b): a non-loopback listen with no TLS
// must log a prominent plaintext warning at startup (the operator opted in
// via allow_remote, but Basic credentials then travel in the clear). The
// TEST-NET address normally can't bind, so Run returns a bind error AFTER
// the warning has been logged — the warning is the assertion, not the bind.
func TestAdminRemoteWithoutTLSWarns(t *testing.T) {
	var buf lockedBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate hash: %v", err)
	}
	cfg := &config.AdminConfig{Listen: "192.0.2.1:8080"}
	cfg.Auth.Username = "admin"
	cfg.Auth.PasswordHash = string(hash)
	s := New(cfg, config.NewStore(mustCfg(t)), emptyDeps(), logger, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }() // bind error expected (TEST-NET)

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "PLAINTEXT on a non-loopback") {
		if time.Now().After(deadline) {
			t.Fatalf("plaintext-on-remote warning never logged; log:\n%s", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
