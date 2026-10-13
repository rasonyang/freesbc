package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// writeTLSPair writes a self-signed ECDSA leaf valid until notAfter (and
// since an hour earlier than the earlier of now and notAfter-2h) to
// dir/cert.pem and its key to dir/key.pem. With chain, a CA certificate is
// appended after the leaf, as a chain file has it.
func writeTLSPair(t *testing.T, dir, cn string, notAfter time.Time, chain bool) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"sbc.example.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if chain {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "chain-ca"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// tlsServer builds a server whose Deps.TLSCert reports the pair on disk as
// loaded now, as the edge does at bind. Building another one afterwards is
// the restart.
func tlsServer(t *testing.T, certPath, keyPath string) *Server {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	deps := emptyDeps()
	deps.TLSCert = func() (*x509.Certificate, time.Time, []string) {
		return leaf, time.Now(), []string{"wss"}
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: string(hash)}
	return New(cfg, &config.TLSConfig{Cert: certPath, Key: keyPath}, config.NewStore(mustCfg(t)), deps,
		slog.New(slog.NewTextHandler(io.Discard, nil)), "")
}

func getTLS(t *testing.T, s *Server) (tlsBody, string) {
	t.Helper()
	raw := string(authGET(t, s, "/api/tls"))
	var b tlsBody
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return b, raw
}

// Valid, expiring and expired leaves report the right days, verdicts and
// banner thresholds, and the response never carries the key or a PEM body.
func TestAPITLSExpiry(t *testing.T) {
	cases := []struct {
		name     string
		left     time.Duration
		days     int
		expired  bool
		expiring bool
	}{
		{"valid", 90*24*time.Hour + time.Hour, 90, false, false},
		{"exactly30d", 30*24*time.Hour + time.Hour, 30, false, false},
		{"expiring", 10*24*time.Hour + time.Hour, 10, false, true},
		{"almost10d", 10*24*time.Hour - time.Hour, 9, false, true},
		{"expired", -(2*24*time.Hour + time.Hour), -2, true, false},
		{"expired3d4m", -(3*24*time.Hour + 4*time.Minute), -3, true, false},
		{"expiredHours", -5 * time.Hour, 0, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert, key := writeTLSPair(t, t.TempDir(), "sbc.example.test", time.Now().Add(c.left), false)
			b, raw := getTLS(t, tlsServer(t, cert, key))
			if !b.Loaded || b.DaysToExpiry != c.days || b.Expired != c.expired || b.ExpiringSoon != c.expiring {
				t.Fatalf("got loaded=%v days=%d expired=%v soon=%v, want days=%d expired=%v soon=%v",
					b.Loaded, b.DaysToExpiry, b.Expired, b.ExpiringSoon, c.days, c.expired, c.expiring)
			}
			if b.Subject != "sbc.example.test" || b.KeyType != "ECDSA" || b.KeyCurve != "P-256" || b.KeySize != 256 ||
				len(b.Fingerprint) != 95 || b.CertFile != cert || b.KeyFile != key ||
				strings.Join(b.SANs, ",") != "sbc.example.test,127.0.0.1" || strings.Join(b.Listeners, ",") != "wss" ||
				b.DiskDiffers || b.DiskError != "" {
				t.Fatalf("unexpected body: %s", raw)
			}
			if strings.Contains(raw, "BEGIN") || strings.Contains(raw, "PRIVATE") {
				t.Fatalf("response leaks key or PEM material: %s", raw)
			}
		})
	}
}

// A chain file's leaf is its first certificate.
func TestAPITLSChainFileLeafIsFirst(t *testing.T) {
	cert, key := writeTLSPair(t, t.TempDir(), "leaf.example.test", time.Now().Add(60*24*time.Hour), true)
	b, _ := getTLS(t, tlsServer(t, cert, key))
	if b.Subject != "leaf.example.test" || strings.Contains(b.Issuer, "chain-ca") || b.DiskDiffers {
		t.Fatalf("chain file reported %+v", b)
	}
}

// disk_differs turns true once the files are replaced and false again for a
// server built from the new files (the restart). The file is read per
// request, so the same server flips without any timer.
func TestAPITLSDiskDiffersUntilRestart(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTLSPair(t, dir, "old.example.test", time.Now().Add(5*24*time.Hour), false)
	s := tlsServer(t, cert, key)
	if b, _ := getTLS(t, s); b.DiskDiffers {
		t.Fatal("disk_differs before any change")
	}
	writeTLSPair(t, dir, "new.example.test", time.Now().Add(80*24*time.Hour), false)
	b, _ := getTLS(t, s)
	if !b.DiskDiffers || b.Subject != "old.example.test" || !b.ExpiringSoon {
		t.Fatalf("after renewal on disk: %+v (the loaded leaf must stay the old one)", b)
	}
	b, _ = getTLS(t, tlsServer(t, cert, key))
	if b.DiskDiffers || b.Subject != "new.example.test" || b.ExpiringSoon {
		t.Fatalf("after restart: %+v", b)
	}
}

// An unreadable or unparsable file on disk is reported, not an error.
func TestAPITLSDiskError(t *testing.T) {
	cert, key := writeTLSPair(t, t.TempDir(), "x.example.test", time.Now().Add(60*24*time.Hour), false)
	s := tlsServer(t, cert, key)
	for name, mutate := range map[string]func(){
		"garbage": func() { _ = os.WriteFile(cert, []byte("junk"), 0o600) },
		"missing": func() { _ = os.Remove(cert) },
	} {
		mutate()
		b, raw := getTLS(t, s)
		if !b.Loaded || b.DiskError == "" || b.DiskDiffers {
			t.Fatalf("%s: want disk_error and a still-loaded record, got %s", name, raw)
		}
	}
}

// With nothing loaded the endpoint answers {"loaded": false}, and other
// methods are refused.
func TestAPITLSNotConfigured(t *testing.T) {
	s := testServer(t)
	if got := strings.TrimSpace(string(authGET(t, s, "/api/tls"))); got != `{"loaded":false}` {
		t.Fatalf("got %s", got)
	}
	if rr := authREQ(t, s, "POST", "/api/tls", ""); rr.Code != 405 {
		t.Fatalf("POST got %d want 405", rr.Code)
	}
	// tls configured but no listener loaded it: still nothing.
	deps := emptyDeps()
	deps.TLSCert = func() (*x509.Certificate, time.Time, []string) { return nil, time.Time{}, nil }
	s2 := New(&config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: s.cfg.PasswordHash},
		&config.TLSConfig{Cert: "c", Key: "k"}, config.NewStore(mustCfg(t)), deps, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	if got := strings.TrimSpace(string(authGET(t, s2, "/api/tls"))); got != `{"loaded":false}` {
		t.Fatalf("got %s", got)
	}
}

func TestAPITLSRequiresAuth(t *testing.T) {
	rr := httptest.NewRecorder()
	testServer(t).handler().ServeHTTP(rr, newReq("GET", "/api/tls", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want 401", rr.Code)
	}
}

// Remote admin HTTPS loads the pair itself: the record then lists "admin",
// and a malformed pair still fails Run.
func TestAdminRunRecordsTLSLeaf(t *testing.T) {
	cert, key := writeTLSPair(t, t.TempDir(), "admin.example.test", time.Now().Add(60*24*time.Hour), false)
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:10101", AllowRemote: true, PasswordHash: string(hash)}
	s := New(cfg, &config.TLSConfig{Cert: cert, Key: key}, config.NewStore(mustCfg(t)), emptyDeps(),
		slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for s.tlsRecord() == nil {
		if time.Now().After(deadline) {
			t.Fatal("admin never recorded its leaf")
		}
		time.Sleep(10 * time.Millisecond)
	}
	b := s.tlsRecord().body(time.Now())
	if b.Subject != "admin.example.test" || strings.Join(b.Listeners, ",") != "admin" || b.DiskDiffers {
		t.Fatalf("body %+v", b)
	}

	if err := os.WriteFile(cert, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2 := &config.AdminConfig{Listen: "127.0.0.1:10102", AllowRemote: true, PasswordHash: string(hash)}
	bad := New(cfg2, &config.TLSConfig{Cert: cert, Key: key}, config.NewStore(mustCfg(t)), emptyDeps(),
		slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	if err := bad.Run(context.Background()); err == nil || bad.tlsRecord() != nil {
		t.Fatalf("malformed pair: Run err=%v, record=%v", err, bad.tlsRecord())
	}
}

// Certificate expiry feeds the health conditions: none for a healthy leaf,
// degraded within 30 days, critical once expired.
func TestHealthTLSCertExpiry(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Duration
		want     HealthSeverity
	}{
		{"healthy", 90 * 24 * time.Hour, ""},
		{"expiring", 10 * 24 * time.Hour, HealthDegraded},
		{"expired", -time.Hour, HealthCritical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := writeTLSPair(t, t.TempDir(), "h.example.test", time.Now().Add(tc.notAfter), false)
			var found []ActiveCondition
			for _, c := range getHealth(t, tlsServer(t, cert, key)).Conditions {
				if c.ID == "tls_cert_expiry" {
					found = append(found, c)
				}
			}
			if tc.want == "" {
				if len(found) != 0 {
					t.Fatalf("unexpected condition %+v", found)
				}
				return
			}
			if len(found) != 1 || found[0].Severity != tc.want {
				t.Fatalf("conditions = %+v, want one %s", found, tc.want)
			}
		})
	}
	for _, c := range getHealth(t, testServer(t)).Conditions {
		if c.ID == "tls_cert_expiry" {
			t.Errorf("condition raised with no certificate loaded")
		}
	}
}

// healthByID returns the active conditions with the given id.
func healthByID(t *testing.T, s *Server, id string) []ActiveCondition {
	t.Helper()
	var out []ActiveCondition
	for _, c := range getHealth(t, s).Conditions {
		if c.ID == id {
			out = append(out, c)
		}
	}
	return out
}

// differsGauge reads freesbc_tls_cert_disk_differs from /metrics.
func differsGauge(t *testing.T, s *Server) string {
	t.Helper()
	for _, l := range strings.Split(string(authGET(t, s, "/metrics")), "\n") {
		if strings.HasPrefix(l, "freesbc_tls_cert_disk_differs ") {
			return strings.TrimPrefix(l, "freesbc_tls_cert_disk_differs ")
		}
	}
	return ""
}

// The same cert on disk raises nothing and exports 0; a different one raises
// tls_cert_renewed only after the cache refreshes, sets the gauge to 1 and
// makes the expiry message mention the renewal.
func TestHealthTLSCertRenewedOnDisk(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTLSPair(t, dir, "old.example.test", time.Now().Add(5*24*time.Hour), false)
	s := tlsServer(t, cert, key)
	s.refreshTLSDisk()
	if got := healthByID(t, s, "tls_cert_renewed"); len(got) != 0 {
		t.Fatalf("same cert on disk: %+v", got)
	}
	if g := differsGauge(t, s); g != "0" {
		t.Fatalf("gauge = %q, want 0", g)
	}
	exp := healthByID(t, s, "tls_cert_expiry")
	if len(exp) != 1 || strings.Contains(exp[0].Message, "renewed") {
		t.Fatalf("expiry before renewal: %+v", exp)
	}

	// The file changes but nothing refreshed the cache: health and metrics
	// must not notice (they never read the file).
	writeTLSPair(t, dir, "new.example.test", time.Now().Add(80*24*time.Hour), false)
	if got := healthByID(t, s, "tls_cert_renewed"); len(got) != 0 {
		t.Fatalf("health read the file: %+v", got)
	}
	if g := differsGauge(t, s); g != "0" {
		t.Fatalf("metrics read the file: gauge = %q", g)
	}

	s.refreshTLSDisk()
	got := healthByID(t, s, "tls_cert_renewed")
	if len(got) != 1 || got[0].Severity != HealthDegraded {
		t.Fatalf("after refresh: %+v", got)
	}
	if g := differsGauge(t, s); g != "1" {
		t.Fatalf("gauge = %q, want 1", g)
	}
	exp = healthByID(t, s, "tls_cert_expiry")
	if len(exp) != 1 || !strings.Contains(exp[0].Message, "renewed on disk") {
		t.Fatalf("expiry message lacks the renewal: %+v", exp)
	}

	// A restart loads the new file: back to quiet.
	s2 := tlsServer(t, cert, key)
	s2.refreshTLSDisk()
	if got := healthByID(t, s2, "tls_cert_renewed"); len(got) != 0 {
		t.Fatalf("after restart: %+v", got)
	}
}

// A missing or unparsable cert file is a degraded condition once the cache
// refreshes, and clears when a valid file is back.
func TestHealthTLSCertDiskError(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTLSPair(t, dir, "x.example.test", time.Now().Add(60*24*time.Hour), false)
	s := tlsServer(t, cert, key)
	for name, mutate := range map[string]func(){
		"garbage": func() { _ = os.WriteFile(cert, []byte("junk"), 0o600) },
		"missing": func() { _ = os.Remove(cert) },
	} {
		writeTLSPair(t, dir, "x.example.test", time.Now().Add(60*24*time.Hour), false)
		s.refreshTLSDisk()
		mutate()
		if got := healthByID(t, s, "tls_cert_disk_error"); len(got) != 0 {
			t.Fatalf("%s: raised before refresh: %+v", name, got)
		}
		s.refreshTLSDisk()
		got := healthByID(t, s, "tls_cert_disk_error")
		if len(got) != 1 || got[0].Severity != HealthDegraded {
			t.Fatalf("%s: %+v", name, got)
		}
		if g := differsGauge(t, s); g != "0" {
			t.Fatalf("%s: gauge = %q, want 0", name, g)
		}
	}
}

// With no certificate loaded there is no gauge and no disk condition.
func TestHealthTLSCertDiskNotLoaded(t *testing.T) {
	s := testServer(t)
	s.refreshTLSDisk()
	if g := differsGauge(t, s); g != "" {
		t.Fatalf("gauge exported with no certificate: %q", g)
	}
}

// Run checks once at start and then on the interval, and Run returns only
// after the checker has stopped.
func TestRunRefreshesTLSDisk(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTLSPair(t, dir, "old.example.test", time.Now().Add(60*24*time.Hour), false)
	s := tlsServer(t, cert, key)
	s.tlsDiskEvery = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	writeTLSPair(t, dir, "new.example.test", time.Now().Add(80*24*time.Hour), false)
	deadline := time.Now().Add(5 * time.Second)
	for !s.cachedTLSDisk().differs {
		if time.Now().After(deadline) {
			t.Fatal("timer never refreshed the cache")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
}
