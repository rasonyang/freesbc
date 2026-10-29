package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// deployPEM writes a self-signed certificate and its key into dir and
// returns the two paths.
func deployPEM(t *testing.T, dir, name string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{name + ".example.test"},
		IPAddresses:  []net.IP{net.IPv4(192, 0, 2, 9)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// deployConfig writes a config whose bind addresses are 127.0.0.1 (local)
// and extra, the yaml text appended to it.
func deployConfig(t *testing.T, extra string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "freesbc.yaml")
	y := `
public: { ip: 127.0.0.1 }
private: { ip: 192.0.2.250 }
rtp: 10010-10029
edge:
  switch: [127.0.0.1:5062]
  listen: { udp: 5060 }
` + extra
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCheckDeploySuccess: a good pair is reported (subject, SANs, issuer,
// not-after), a leaf under 30 days warns, and no private key is printed.
func TestCheckDeploySuccess(t *testing.T) {
	dir := t.TempDir()
	cert, key := deployPEM(t, dir, "soon", time.Now().Add(10*24*time.Hour))
	ccert, ckey := deployPEM(t, dir, "client", time.Now().Add(400*24*time.Hour))
	ca, _ := deployPEM(t, dir, "ca", time.Now().Add(400*24*time.Hour))
	cfg := deployConfig(t, fmt.Sprintf(`  carriers:
    acme: { host: "sip.acme.test:5061", transport: tls, ca_file: %q, client_cert: %q, client_key: %q }
    sys: { host: "sip.sys.test:5061", transport: tls }
tls: { cert: %q, key: %q }
`, ca, ccert, ckey, cert, key))
	report, _, err := CheckDeploy(cfg, false)
	if err != nil {
		t.Fatalf("CheckDeploy: %v\n%s", err, report)
	}
	for _, want := range []string{
		"config OK",
		"tls.cert/tls.key: loaded", "subject:   CN=soon", "DNS:soon.example.test", "IP:192.0.2.9", "issuer:    CN=soon", "not after:",
		"warning:   expires in 9 days",
		"edge.carriers.acme.client_cert/client_key: loaded", "subject:   CN=client",
		"edge.carriers.acme.ca_file " + ca + ": loaded",
		"edge.carriers.sys.ca_file: unset, system roots",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "PRIVATE KEY") || strings.Contains(report, "BEGIN") {
		t.Errorf("report leaks key material:\n%s", report)
	}
}

func TestCheckDeployFailures(t *testing.T) {
	dir := t.TempDir()
	good, goodKey := deployPEM(t, dir, "good", time.Now().Add(400*24*time.Hour))
	_, otherKey := deployPEM(t, dir, "other", time.Now().Add(400*24*time.Hour))
	expired, expiredKey := deployPEM(t, dir, "old", time.Now().Add(-time.Hour))
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "absent.pem")
	carrier := func(extra string) string {
		return fmt.Sprintf("  carriers:\n    acme: { host: \"sip.acme.test:5061\", transport: tls%s }\n", extra)
	}
	hepYAML := func(tlsBody string) string {
		return fmt.Sprintf("hep:\n  address: 192.0.2.40:9061\n  transport: tls\n  tls: { %s }\n", tlsBody)
	}
	cases := []struct {
		name, yaml string
		want       []string
	}{
		{"missing tls pair", fmt.Sprintf("tls: { cert: %q, key: %q }\n", missing, goodKey), []string{"tls.cert/tls.key", missing}},
		{"key mismatch", fmt.Sprintf("tls: { cert: %q, key: %q }\n", good, otherKey), []string{"tls.cert/tls.key", good, otherKey, "does not match"}},
		{"expired leaf", fmt.Sprintf("tls: { cert: %q, key: %q }\n", expired, expiredKey), []string{"tls.cert/tls.key", expired, "expired"}},
		{"bad ca_file", carrier(fmt.Sprintf(", ca_file: %q", junk)), []string{"edge.carriers.acme.ca_file", junk, "no PEM certificate"}},
		{"missing ca_file", carrier(fmt.Sprintf(", ca_file: %q", missing)), []string{"edge.carriers.acme.ca_file", missing}},
		{"client pair", carrier(fmt.Sprintf(", client_cert: %q, client_key: %q", good, missing)), []string{"edge.carriers.acme.client_cert/client_key", good, missing}},
		{"hep pair", hepYAML(fmt.Sprintf("cert: %q, key: %q", good, missing)), []string{"hep.tls", good, missing}},
		{"hep ca", hepYAML(fmt.Sprintf("ca: %q", junk)), []string{"hep.tls", junk}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := CheckDeploy(deployConfig(t, tc.yaml), false)
			if err == nil {
				t.Fatal("CheckDeploy passed; want an error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error lacks %q: %v", w, err)
				}
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Errorf("error leaks key material: %v", err)
			}
		})
	}
}

// TestCheckDeployCollectsAllFailures: one run names every broken file.
func TestCheckDeployCollectsAllFailures(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.pem")
	cfg := deployConfig(t, fmt.Sprintf("  carriers:\n    acme: { host: \"sip.acme.test:5061\", transport: tls, ca_file: %q }\ntls: { cert: %q, key: %q }\n", missing, missing, missing))
	_, _, err := CheckDeploy(cfg, false)
	if err == nil || !strings.Contains(err.Error(), "edge.carriers.acme.ca_file") || !strings.Contains(err.Error(), "tls.cert/tls.key") {
		t.Fatalf("want both failures, got %v", err)
	}
}

func TestCheckDeployLocalAddresses(t *testing.T) {
	p := deployConfig(t, "")
	// private.ip 192.0.2.250 is TEST-NET-1: never local.
	report, _, err := CheckDeploy(p, true)
	if err == nil || !strings.Contains(err.Error(), "private.ip 192.0.2.250") || strings.Contains(err.Error(), "public.bind") {
		t.Fatalf("want only private.ip to fail, got %v", err)
	}
	if !strings.Contains(report, "public.bind 127.0.0.1: on interface ") {
		t.Errorf("report does not name the interface:\n%s", report)
	}
	if _, _, err := CheckDeploy(p, false); err != nil {
		t.Errorf("without --local-addresses the addresses are not checked: %v", err)
	}
}
