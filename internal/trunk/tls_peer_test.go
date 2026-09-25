package trunk

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// These tests drive the real trunk dial path: an INVITE from a UDP peer is
// routed to a TLS peer, and the trunk's sipgo UA dials a loopback TLS
// endpoint that plays that peer. The endpoint reports, per connection,
// whether the handshake completed (the trunk accepted its certificate) and
// which client certificate the trunk presented. Peers are dialled by IP
// literal, so the trunk sends no SNI and must identify the peer from the
// dialled address's IP SAN (see clientTLS.matchPeer).

// tlsHandshake is what the fake TLS peer saw on one inbound connection.
type tlsHandshake struct {
	err       error
	clientCNs []string
}

// tlsPeerEndpoint is a loopback TLS listener standing in for a TLS carrier.
// It serves the certificate in cert (swappable between calls), requests but
// does not require a client certificate, and closes every connection once
// the handshake is decided.
type tlsPeerEndpoint struct {
	cert    atomic.Pointer[tls.Certificate]
	results chan tlsHandshake
}

func startTLSPeerEndpoint(t *testing.T, addr string, cert tls.Certificate) *tlsPeerEndpoint {
	t.Helper()
	e := &tlsPeerEndpoint{results: make(chan tlsHandshake, 8)}
	e.cert.Store(&cert)
	ln, err := tls.Listen("tcp", addr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return e.cert.Load(), nil
		},
		ClientAuth: tls.RequestClientCert,
	})
	if err != nil {
		t.Fatalf("tls peer endpoint listen %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*tls.Conn)
			_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
			err = tc.Handshake()
			var cns []string
			if err == nil {
				// TLS 1.3: the client's certificate verdict on OUR
				// certificate arrives after the server-side handshake
				// returns, as an alert on the first read. A short read
				// surfaces it; a timeout means the client accepted.
				_ = tc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				if _, rerr := tc.Read(make([]byte, 1)); rerr != nil {
					var ne net.Error
					if !errors.As(rerr, &ne) || !ne.Timeout() {
						err = rerr
					}
				}
				for _, pc := range tc.ConnectionState().PeerCertificates {
					cns = append(cns, pc.Subject.CommonName)
				}
			}
			tc.Close()
			select {
			case e.results <- tlsHandshake{err: err, clientCNs: cns}:
			default:
			}
		}
	}()
	return e
}

// next waits for the endpoint's next handshake verdict.
func (e *tlsPeerEndpoint) next(t *testing.T) tlsHandshake {
	t.Helper()
	select {
	case r := <-e.results:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("trunk never dialled the TLS peer endpoint")
		return tlsHandshake{}
	}
}

// tlsIdentity is one self-signed certificate (its own CA, from genCertKey)
// written to disk: certPath doubles as a tls_ca bundle naming it.
type tlsIdentity struct {
	cert              tls.Certificate
	certPath, keyPath string
}

func newTLSIdentity(t *testing.T, cn string, ips ...net.IP) tlsIdentity {
	t.Helper()
	_, certPEM, keyPEM := genCertKey(t, cn, nil, ips)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeTLSCertKey(t, certPEM, keyPEM)
	return tlsIdentity{cert: cert, certPath: certPath, keyPath: keyPath}
}

// sendRawInvite sends one INVITE from a fresh UDP socket to the trunk on
// sipPort; the call itself is not followed, only the dial it triggers.
func sendRawInvite(t *testing.T, sipPort int, callID string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	local := conn.LocalAddr().(*net.UDPAddr)
	msg := sipInviteWithSDP(callID, local, testSDPBody(local.Port+1), sipPort)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sipPort}
	if _, err := conn.WriteToUDP([]byte(msg), dst); err != nil {
		t.Fatal(err)
	}
}

// twoTLSPeersCfg is a trunk with a UDP caller routed to TLS peer b, next to
// a second TLS peer a that is never dialled. extraA/extraB are appended to
// each TLS peer's block (tls_ca, client cert lines).
func twoTLSPeersCfg(sipPort, bPort, aPort, mediaMin int, extraA, extraB string) string {
	return fmt.Sprintf(`
listen:
  sip: [udp://127.0.0.1:%d]
  media:
    port_range: %d-%d
    public_ip: 127.0.0.1
ring_timeout: 2s
peers:
  caller:
    address: 127.0.0.1:%d
    allowed_ips: [127.0.0.1/32]
  a:
    address: 127.0.0.3:%d
    transport: tls
    allowed_ips: [203.0.113.1/32]
%s
  b:
    address: 127.0.0.1:%d
    transport: tls
    allowed_ips: [198.51.100.1/32]
    media_latch: loose
%s
routes:
  - name: out
    from: caller
    to: [b]
`, sipPort, mediaMin, mediaMin+7, sipPort+3, aPort, extraA, bPort, extraB)
}

// TestPeerTLSTrustIsPerPeer: two TLS peers with distinct private CAs. Peer
// B's endpoint presents a certificate issued by peer A's CA (valid for B's
// address); dialling B must fail, because only B's tls_ca may anchor B.
// Pre-fix every peer's tls_ca was merged into one RootCAs pool, so the dial
// succeeded. The control half then serves a certificate under B's own CA,
// which must be accepted.
//
// audit: P2-TRK-016
func TestPeerTLSTrustIsPerPeer(t *testing.T) {
	const sipPort, bPort, aPort, mediaMin = 14800, 14801, 14802, 14804
	lo := net.IPv4(127, 0, 0, 1)
	caA := newTLSIdentity(t, "carrier-a-ca", lo, net.IPv4(127, 0, 0, 3))
	caB := newTLSIdentity(t, "carrier-b-ca", lo)

	ep := startTLSPeerEndpoint(t, fmt.Sprintf("127.0.0.1:%d", bPort), caA.cert)
	startServer(t, sipPort, twoTLSPeersCfg(sipPort, bPort, aPort, mediaMin,
		"    tls_ca: "+caA.certPath, "    tls_ca: "+caB.certPath))

	sendRawInvite(t, sipPort, "tls-trust-cross-ca")
	if r := ep.next(t); r.err == nil {
		t.Fatal("trunk accepted peer A's CA-issued certificate when dialling peer B; trust anchors must be per peer")
	}

	ep.cert.Store(&caB.cert)
	sendRawInvite(t, sipPort, "tls-trust-own-ca")
	if r := ep.next(t); r.err != nil {
		t.Fatalf("trunk rejected peer B's own CA-issued certificate: %v", r.err)
	}
}

// TestPeerTLSClientCertIsPerPeer: with mutual TLS, peer B receives only B's
// client certificate, never peer A's. When B configures none it receives
// none; pre-fix every peer's client certificate sat in one Certificates
// slice and B was sent A's (a cross-peer identity leak).
//
// audit: P2-TRK-016
func TestPeerTLSClientCertIsPerPeer(t *testing.T) {
	lo := net.IPv4(127, 0, 0, 1)
	caB := newTLSIdentity(t, "carrier-b", lo)
	clientA := newTLSIdentity(t, "sbc-for-a")
	clientB := newTLSIdentity(t, "sbc-for-b")
	certLines := func(id tlsIdentity) string {
		return "    tls_client_cert: " + id.certPath + "\n    tls_client_key: " + id.keyPath
	}
	caLine := "    tls_ca: " + caB.certPath

	cases := []struct {
		name                         string
		sipPort, bPort, aPort, media int
		extraB                       string
		want                         []string
	}{
		{"b-without-cert-gets-none", 14820, 14821, 14822, 14824, caLine, nil},
		{"b-gets-only-its-own", 14840, 14841, 14842, 14844, caLine + "\n" + certLines(clientB), []string{"sbc-for-b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := startTLSPeerEndpoint(t, fmt.Sprintf("127.0.0.1:%d", tc.bPort), caB.cert)
			startServer(t, tc.sipPort, twoTLSPeersCfg(tc.sipPort, tc.bPort, tc.aPort, tc.media,
				certLines(clientA), tc.extraB))
			sendRawInvite(t, tc.sipPort, "tls-client-cert-"+tc.name)
			r := ep.next(t)
			if r.err != nil {
				t.Fatalf("handshake with peer B failed: %v", r.err)
			}
			if fmt.Sprint(r.clientCNs) != fmt.Sprint(tc.want) {
				t.Fatalf("peer B received client certificate(s) %v, want %v", r.clientCNs, tc.want)
			}
		})
	}
}

// TestPeerTLSIPLiteralNeedsIPSAN: a peer dialled by IP literal sends no SNI,
// so the trunk identifies it from the leaf's IP SANs. A certificate from
// the peer's own CA that does not name the dialled IP must be rejected
// (InsecureSkipVerify turns Go's own name check off; VerifyConnection has
// to do it). Go's default verification already did this, so this guard
// passes on the pre-rewrite code too; it pins that the rewrite keeps it.
func TestPeerTLSIPLiteralNeedsIPSAN(t *testing.T) {
	const sipPort, bPort, aPort, mediaMin = 14860, 14861, 14862, 14864
	// B's CA certificate names only another address, not 127.0.0.1.
	caB := newTLSIdentity(t, "carrier-b-elsewhere", net.IPv4(192, 0, 2, 10))
	caA := newTLSIdentity(t, "carrier-a", net.IPv4(127, 0, 0, 3))

	ep := startTLSPeerEndpoint(t, fmt.Sprintf("127.0.0.1:%d", bPort), caB.cert)
	startServer(t, sipPort, twoTLSPeersCfg(sipPort, bPort, aPort, mediaMin,
		"    tls_ca: "+caA.certPath, "    tls_ca: "+caB.certPath))

	sendRawInvite(t, sipPort, "tls-ip-literal-no-san")
	if r := ep.next(t); r.err == nil {
		t.Fatal("trunk accepted a certificate that does not name the dialled IP")
	}
}
