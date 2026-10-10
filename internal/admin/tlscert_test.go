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
