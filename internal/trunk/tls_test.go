package trunk

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

// handshakeVia dials a loopback TLS server presenting serverCert with the
// client config conf, setting ServerName to serverName exactly as sipgo
// does per dial (the dialled host; Go leaves an IP out of SNI), under a
// ctx that names peer (none when peer is ""). It returns the client's
// handshake error and the client certificate CNs the server received.
func handshakeVia(t *testing.T, conf *tls.Config, serverName, peer string, serverCert tls.Certificate) (error, []string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		var cns []string
		if tc.Handshake() == nil {
			for _, pc := range tc.ConnectionState().PeerCertificates {
				cns = append(cns, pc.Subject.CommonName)
			}
		}
		got <- cns
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := conf.Clone()
	c.ServerName = serverName
	ctx := context.Background()
	if peer != "" {
		ctx = withTLSPeer(ctx, peer)
	}
	hsErr := tls.Client(raw, c).HandshakeContext(ctx)
	if hsErr != nil {
		raw.Close()
		<-got
		return hsErr, nil
	}
	return nil, <-got
}

func mustTLSPair(t *testing.T, certPEM, keyPEM []byte) tls.Certificate {
	t.Helper()
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestClientTLSSelectsPeerByServerName covers the hostname path of the
// per-peer outbound TLS selector (P2-TRK-016): the peer is matched by
// cs.ServerName, its own tls_ca alone anchors it, and a certificate from
// another peer's CA is refused.
func TestClientTLSSelectsPeerByServerName(t *testing.T) {
	_, aPEM, aKey := genCertKey(t, "a", []string{"a.example"}, nil)
	_, bPEM, bKey := genCertKey(t, "b", []string{"b.example"}, nil)
	// Issued by A's key/"CA" but naming B: what a mis-issuing or compromised
	// peer-A CA could hand to someone sitting at B's address.
	_, aForBPEM, aForBKey := genCertKey(t, "a-for-b", []string{"b.example", "a.example"}, nil)
	aCA, _ := writeTLSCertKey(t, append(append([]byte{}, aPEM...), aForBPEM...), aKey)
	bCA, _ := writeTLSCertKey(t, bPEM, bKey)
	peers := map[string]*config.Peer{
		"a": {Address: "a.example:5061", Transport: "tls", TLSCA: aCA},
		"b": {Address: "b.example:5061", Transport: "tls", TLSCA: bCA},
	}
	sel, err := newClientTLS(peers, func() map[string]*config.Peer { return peers }, nil)
	if err != nil {
		t.Fatal(err)
	}
	conf := sel.config()
	if conf.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS1.2", conf.MinVersion)
	}

	if err, _ := handshakeVia(t, conf, "b.example", "b", mustTLSPair(t, bPEM, bKey)); err != nil {
		t.Fatalf("b's own certificate refused: %v", err)
	}
	if err, _ := handshakeVia(t, conf, "b.example", "b", mustTLSPair(t, aForBPEM, aForBKey)); err == nil {
		t.Fatal("a certificate from peer a's CA was accepted when dialling peer b")
	}
	// Name check: b's certificate does not name a.example.
	if err, _ := handshakeVia(t, conf, "a.example", "a", mustTLSPair(t, bPEM, bKey)); err == nil {
		t.Fatal("certificate for b.example accepted when dialling a.example")
	}
	// No peer has this name: fail closed.
	if err, _ := handshakeVia(t, conf, "c.example", "", mustTLSPair(t, bPEM, bKey)); err == nil {
		t.Fatal("dial to a name no TLS peer owns must fail")
	}
}

// TestClientTLSSRVTargetAndAmbiguity: a peer reached through SRV matches
// its targets' ServerName, and a name that more than one peer can own fails
// closed.
func TestClientTLSSRVTargetAndAmbiguity(t *testing.T) {
	_, tPEM, tKey := genCertKey(t, "sip1", []string{"sip1.carrier.example"}, nil)
	ca, _ := writeTLSCertKey(t, tPEM, tKey)
	peers := map[string]*config.Peer{
		"carrier": {Address: "carrier.example", Transport: "tls", TLSCA: ca},
	}
	targets := map[string][]string{"carrier.example/tls": {"sip1.carrier.example"}}
	srv := func(host, transport string) []string { return targets[host+"/"+transport] }
	cur := peers
	sel, err := newClientTLS(peers, func() map[string]*config.Peer { return cur }, srv)
	if err != nil {
		t.Fatal(err)
	}
	if err, _ := handshakeVia(t, sel.config(), "sip1.carrier.example", "carrier", mustTLSPair(t, tPEM, tKey)); err != nil {
		t.Fatalf("SRV target of the peer refused: %v", err)
	}
	// A second peer (added by reload) whose address is the SRV target
	// itself: the name now belongs to two peers.
	cur = map[string]*config.Peer{
		"carrier": peers["carrier"],
		"other":   {Address: "sip1.carrier.example:5061", Transport: "tls"},
	}
	if err, _ := handshakeVia(t, sel.config(), "sip1.carrier.example", "carrier", mustTLSPair(t, tPEM, tKey)); err == nil {
		t.Fatal("a ServerName that two peers match must fail closed")
	}
}

// TestClientTLSClientCertFromContext: GetClientCertificate returns only the
// certificate of the peer the handshake ctx names, and none without one.
func TestClientTLSClientCertFromContext(t *testing.T) {
	_, sPEM, sKey := genCertKey(t, "b", []string{"b.example"}, nil)
	ca, _ := writeTLSCertKey(t, sPEM, sKey)
	_, caPEM, caKey := genCertKey(t, "client-a", nil, nil)
	aCert, aKey := writeTLSCertKey(t, caPEM, caKey)
	_, cbPEM, cbKey := genCertKey(t, "client-b", nil, nil)
	bCert, bKey := writeTLSCertKey(t, cbPEM, cbKey)
	peers := map[string]*config.Peer{
		"a": {Address: "a.example:5061", Transport: "tls", TLSClientCert: aCert, TLSClientKey: aKey},
		"b": {Address: "b.example:5061", Transport: "tls", TLSCA: ca, TLSClientCert: bCert, TLSClientKey: bKey},
	}
	sel, err := newClientTLS(peers, func() map[string]*config.Peer { return peers }, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := mustTLSPair(t, sPEM, sKey)
	for _, tc := range []struct {
		peer string
		want string
	}{{"b", "[client-b]"}, {"", "[]"}} {
		err, cns := handshakeVia(t, sel.config(), "b.example", tc.peer, server)
		if err != nil {
			t.Fatalf("ctx peer %q: handshake: %v", tc.peer, err)
		}
		if fmt.Sprint(cns) != tc.want {
			t.Errorf("ctx peer %q: server received %v, want %s", tc.peer, cns, tc.want)
		}
	}
}

// TestClientTLSMaterialIsRestartOnly: material loads at startup (a bad file
// aborts it), and a TLS peer added by reload that names material which was
// never loaded fails closed instead of falling back to the system roots.
func TestClientTLSMaterialIsRestartOnly(t *testing.T) {
	dir := t.TempDir()
	if _, err := newClientTLS(map[string]*config.Peer{
		"bad": {Address: "x.example", Transport: "tls", TLSCA: filepath.Join(dir, "missing.pem")},
	}, nil, nil); err == nil {
		t.Fatal("unreadable tls_ca must error")
	}

	_, sPEM, sKey := genCertKey(t, "new", []string{"new.example"}, nil)
	ca, _ := writeTLSCertKey(t, sPEM, sKey)
	cur := map[string]*config.Peer{
		"new": {Address: "new.example:5061", Transport: "tls", TLSCA: ca},
	}
	sel, err := newClientTLS(map[string]*config.Peer{}, func() map[string]*config.Peer { return cur }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err, _ := handshakeVia(t, sel.config(), "new.example", "new", mustTLSPair(t, sPEM, sKey)); err == nil {
		t.Fatal("a reload-added peer's unloaded tls_ca must fail closed")
	}
}
