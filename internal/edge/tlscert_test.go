package edge

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
)

func tlsTestServer(t *testing.T, cert, key string) *Server {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
public: {ip: 127.0.0.1}
private: {ip: 192.0.2.250}
tls: {cert: %q, key: %q}
edge:
  switch: [127.0.0.1:5060]
  listen: {udp: %d, wss: %d}
`, cert, key, nextPort(t), nextPort(t))))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithPrivateAddr(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", nextPort(t)))))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// The leaf of the pair a wss listener loads is kept for the admin surface,
// with the transport that loaded it; before any load there is none.
func TestTLSCertKeptOnLoad(t *testing.T) {
	cert, key := writeTestTLS(t, t.TempDir())
	srv := tlsTestServer(t, cert, key)
	if leaf, _, _ := srv.TLSCert(); leaf != nil {
		t.Fatal("leaf set before any listener loaded the pair")
	}
	l, err := srv.openListener("wss", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(nextPort(t))).String())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	leaf, at, users := srv.TLSCert()
	if leaf == nil || leaf.Subject.CommonName != "freesbc-test" || at.IsZero() {
		t.Fatalf("TLSCert = %v, %v", leaf, at)
	}
	if len(users) != 1 || users[0] != "wss" {
		t.Fatalf("users = %v, want [wss]", users)
	}
}

// A malformed certificate or key still fails the bind, and no leaf is kept.
func TestTLSMalformedPairFailsBind(t *testing.T) {
	cert, key := writeTestTLS(t, t.TempDir())
	if err := os.WriteFile(cert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := tlsTestServer(t, cert, key)
	if _, err := srv.openListener("wss", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(nextPort(t))).String()); err == nil {
		t.Fatal("malformed certificate did not fail the listener")
	}
	if leaf, _, _ := srv.TLSCert(); leaf != nil {
		t.Fatal("leaf kept for a pair that failed to load")
	}
}
