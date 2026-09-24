package trunk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// genCertKey generates a self-signed ECDSA certificate (CA=itself) for the
// given SANs and returns the DER/PEM forms.
func genCertKey(t *testing.T, cn string, dns []string, ips []net.IP) (certDER []byte, certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dns,
		IPAddresses:           ips,
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
	return der,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// writeTLSCertKey writes certPEM/keyPEM into t.TempDir() and returns the
// two file paths.
func writeTLSCertKey(t *testing.T, certPEM, keyPEM []byte) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestTLSListenerUsesConfiguredCert is the T-17 (F-13) red test: with
// listen.tls_cert/tls_key configured, a tls:// SIP listener presents THAT
// certificate — a client that verifies against it (NO skip-verify)
// completes the handshake and sees the configured identity, not the
// "FreeSBC self-signed" fallback. Pre-fix the listener always self-signed,
// so any verifying client failed the handshake.
func TestTLSListenerUsesConfiguredCert(t *testing.T) {
	_, certPEM, keyPEM := genCertKey(t, "sig-tls-test", nil, []net.IP{net.IPv4(127, 0, 0, 1)})
	certPath, keyPath := writeTLSCertKey(t, certPEM, keyPEM)

	cfg := `
listen:
  sip: [tls://127.0.0.1:11780]
  tls_cert: ` + certPath + `
  tls_key: ` + keyPath + `
  media:
    port_range: 12780-12783
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
	srv := startServer(t, 11780, cfg)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)

	// Retry the handshake until the listener is bound (Run starts in a
	// goroutine; the readiness probe is a UDP dial, which can't see a TLS
	// listener, so it returns before the bind may have completed).
	deadline := time.Now().Add(5 * time.Second)
	var conn *tls.Conn
	var err error
	for {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:11780",
			&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots})
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("tls handshake against configured cert: %v", err)
	}
	state := conn.ConnectionState()
	conn.Close()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificate presented")
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	if cn != "sig-tls-test" {
		t.Fatalf("listener presented cert CN %q, want the configured cert (not the self-signed fallback)", cn)
	}
	_ = srv // server torn down by test cleanup
}

// TestBuildClientTLSConfig verifies the outbound TLS merge (T-17/F-13): a
// peer's tls_ca is added to the system roots (its CA-signed certificate now
// verifies), client cert/key pairs are loaded, MinVersion is pinned, and an
// empty config returns nil (sipgo's default behavior preserved).
func TestBuildClientTLSConfig(t *testing.T) {
	// The carrier's self-signed certificate (its own anchor), written as the
	// peer's tls_ca bundle.
	carrierDER, carrierPEM, _ := genCertKey(t, "carrier", []string{"carrier.example"}, nil)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, carrierPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// No TLS material configured → nil config (sipgo default).
	conf, err := buildClientTLSConfig(map[string]*config.Peer{"plain": {}})
	if err != nil || conf != nil {
		t.Fatalf("empty peers: got conf=%v err=%v, want nil,nil", conf, err)
	}

	conf, err = buildClientTLSConfig(map[string]*config.Peer{"carrier": {TLSCA: caPath}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if conf.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS1.2", conf.MinVersion)
	}
	// The configured anchor must now verify its own certificate (pre-fix a
	// self-signed carrier was simply undialable).
	opts := x509.VerifyOptions{Roots: conf.RootCAs, DNSName: "carrier.example"}
	carrierCert, err := x509.ParseCertificate(carrierDER)
	if err != nil {
		t.Fatalf("parse carrier cert: %v", err)
	}
	if _, err := carrierCert.Verify(opts); err != nil {
		t.Errorf("peer tls_ca not added as trust anchor: %v", err)
	}
	// A cert outside the pool must NOT verify — the merged pool is strict,
	// not verification-disabled.
	outsiderDER, _, _ := genCertKey(t, "outsider", []string{"outsider.example"}, nil)
	outsider, _ := x509.ParseCertificate(outsiderDER)
	if _, err := outsider.Verify(opts); err == nil {
		t.Error("certificate from an unconfigured CA must not verify")
	}

	// Client certificate pairs load into Certificates.
	_, certPEM, keyPEM := genCertKey(t, "client", nil, nil)
	certPath, keyPath := writeTLSCertKey(t, certPEM, keyPEM)
	conf, err = buildClientTLSConfig(map[string]*config.Peer{
		"mtls": {TLSClientCert: certPath, TLSClientKey: keyPath},
	})
	if err != nil {
		t.Fatalf("build mtls config: %v", err)
	}
	if len(conf.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1 loaded client pair", len(conf.Certificates))
	}

	// An unreadable CA file must fail startup-visible, not silently degrade.
	if _, err := buildClientTLSConfig(map[string]*config.Peer{
		"bad": {TLSCA: filepath.Join(dir, "does-not-exist.pem")},
	}); err == nil {
		t.Fatal("unreadable tls_ca must error")
	}
}
