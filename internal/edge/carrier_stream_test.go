package edge

import (
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
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file tests SIP over TCP and TLS to and from carriers (carrierconn.go
// and the stream parts of carrier.go, carrierreg.go, carrierdns.go): real
// loopback sockets, with certificates generated here. The fake carrier is a
// client (register_test.go) that also serves a TCP or TLS listener.

// testPKI is a throwaway CA.
type testPKI struct {
	t    *testing.T
	dir  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	n    int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "carrier test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{t: t, dir: t.TempDir(), cert: cert, key: key, n: 1}
}

func (p *testPKI) write(name string, blockType string, der []byte) string {
	path := filepath.Join(p.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		p.t.Fatal(err)
	}
	return path
}

// caFile writes the CA certificate and returns its path.
func (p *testPKI) caFile() string { return p.write("ca.pem", "CERTIFICATE", p.cert.Raw) }

func (p *testPKI) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.cert)
	return pool
}

// leaf is an issued certificate and where it was written.
type leaf struct {
	cert              tls.Certificate
	certFile, keyFile string
}

// issue signs a server (or, with client, a client) certificate.
func (p *testPKI) issue(client bool, dns []string, ips ...string) leaf {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	p.n++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.n),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
	}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		p.t.Fatal(err)
	}
	name := fmt.Sprintf("leaf%d", p.n)
	l := leaf{
		certFile: p.write(name+".pem", "CERTIFICATE", der),
		keyFile:  p.write(name+".key", "EC PRIVATE KEY", keyDER),
	}
	l.cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return l
}

// countListener records the connections it accepted.
type countListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *countListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *countListener) accepted() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

// closeAccepted hard-closes every accepted connection: a carrier that drops
// its sessions.
func (l *countListener) closeAccepted() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
}

// streamCarrier is a fake carrier gateway listening on tcp or tls.
type streamCarrier struct {
	*client
	port    int
	rtpPort int
	ln      *countListener

	mu   sync.Mutex
	tags map[string]string // Call-ID → the To tag it answered with
}

// startStreamCarrier serves transport (tcp, or tls with serverConf) on a
// loopback port. clientConf is how it trusts FreeSBC when it dials the
// edge's tls listener.
func startStreamCarrier(t *testing.T, transport string, serverConf, clientConf *tls.Config) *streamCarrier {
	t.Helper()
	var opts []sipgo.UserAgentOption
	if clientConf != nil {
		opts = append(opts, sipgo.WithUserAgenTLSConfig(clientConf))
	}
	sc := &streamCarrier{client: newClientBase(t, transport, opts...), port: freeTCPPort(t), rtpPort: freePort(t),
		tags: map[string]string{}}
	raw, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", sc.port))
	if err != nil {
		t.Fatal(err)
	}
	sc.ln = &countListener{Listener: raw}
	var ln net.Listener = sc.ln
	if transport == "tls" {
		ln = tls.NewListener(sc.ln, serverConf)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tl := sc.srv.TransportLayer()
	if transport == "tls" {
		go func() { _ = tl.ServeTLS(ln) }()
	} else {
		go func() { _ = tl.ServeTCP(ln) }()
	}
	sc.setAnswer(sc.answer)
	return sc
}

func (sc *streamCarrier) contact() sip.Uri {
	u := sip.Uri{User: "gw", Host: "127.0.0.1", Port: sc.port, UriParams: sip.NewParams()}
	u.UriParams.Add("transport", sc.transport)
	return u
}

// answer is the carrier's UAS: INVITE answered 200 with an SDP, REGISTER
// accepted with the Contact echoed, everything else 200.
func (sc *streamCarrier) answer(req *sip.Request, tx sip.ServerTransaction) {
	switch req.Method {
	case sip.INVITE:
		tag := sip.GenerateTagN(12)
		if t, ok := req.To().Params.Get("tag"); ok && t != "" {
			tag = t
		}
		sc.mu.Lock()
		sc.tags[fsip.CallID(req)] = tag
		sc.mu.Unlock()
		body := fmt.Sprintf("v=0\r\no=gw 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n", sc.rtpPort)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.To().Params.Add("tag", tag)
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sc.contact()})
		_ = tx.Respond(res)
	case sip.REGISTER:
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		if c, ok := fsip.ContactURI(req); ok {
			echo := &sip.ContactHeader{Address: c, Params: sip.NewParams()}
			echo.Params.Add("expires", "120")
			res.AppendHeader(echo)
		}
		_ = tx.Respond(res)
	default:
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
}

// waitInbound returns the next request of method the carrier received.
func (sc *streamCarrier) waitInbound(t *testing.T, method sip.RequestMethod) *sip.Request {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case r := <-sc.inbound:
			if r.Method == method {
				return r
			}
		case <-deadline:
			t.Fatalf("the carrier never received a %s", method)
		}
	}
}

// noInbound fails if the carrier receives any request within a short wait.
func (sc *streamCarrier) noInbound(t *testing.T) {
	t.Helper()
	select {
	case r := <-sc.inbound:
		t.Fatalf("the carrier received a %s, want nothing", r.Method)
	case <-time.After(300 * time.Millisecond):
	}
}

// bye sends a BYE as the UAS of a call the switch placed (inv is the INVITE
// it received) to dest, over a connection the carrier already holds.
func (sc *streamCarrier) bye(t *testing.T, inv *sip.Request, dest string) *sip.Response {
	t.Helper()
	target, _ := fsip.ContactURI(inv)
	req := sip.NewRequest(sip.BYE, target)
	sc.mu.Lock()
	tag := sc.tags[fsip.CallID(inv)]
	sc.mu.Unlock()
	from := &sip.FromHeader{Address: inv.To().Address, Params: sip.NewParams()}
	from.Params.Add("tag", tag)
	req.AppendHeader(from)
	to := &sip.ToHeader{Address: inv.From().Address, Params: sip.NewParams()}
	if ft, ok := inv.From().Params.Get("tag"); ok {
		to.Params.Add("tag", ft)
	}
	req.AppendHeader(to)
	sip.CopyHeaders("Call-ID", inv, req)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.BYE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: strings.ToUpper(sc.transport),
		Host: "127.0.0.1", Port: sc.port, Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	return sc.do(t, req, dest)
}

// streamRigOpts picks how a carrier is configured and reached.
type streamRigOpts struct {
	transport  string      // tcp or tls
	host       string      // carrier host as written (default 127.0.0.1)
	extra      string      // more entry keys, e.g. `, ca_file: "/x.pem"`
	serverConf *tls.Config // the carrier's server side (tls)
	listenTLS  bool        // the edge also serves a tls listener
	dns        map[string]string
	tune       func(*streamLimits) // shortens the stream bounds before Run
}

type streamRig struct {
	*carrierRig
	carrier *streamCarrier
}

// ruri is a Request-URI addressed to the carrier.
func (r *streamRig) ruri(user, host string) sip.Uri {
	return sip.Uri{User: user, Host: host, Port: r.carrier.port}
}

// insecureClient is the TLS client config of a test endpoint that dials the
// edge's self-signed tls listener.
func insecureClient() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // test endpoint, self-signed edge listener
}

// startStreamRig starts the edge with one carrier "alpha" on o.transport
// and the fake carrier serving it. The switch's client port is h.fs and its
// carrier port rig.cs.
func startStreamRig(t *testing.T, o streamRigOpts) *streamRig {
	t.Helper()
	carrier := startStreamCarrier(t, o.transport, o.serverConf, insecureClient())
	host := o.host
	if host == "" {
		host = "127.0.0.1"
	}
	pubUDP, priv, up, cp := freePort(t), freePort(t), freePort(t), freePort(t)
	mediaBase := nextMediaBase(t)
	var extra []string
	if o.listenTLS {
		extra = append(extra, fmt.Sprintf("tls: %d", freeTCPPort(t)))
	}
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, 0, 0, mediaBase, "", extra...)
	yaml = strings.Replace(yaml, "edge:\n", fmt.Sprintf("edge:\n  switch_carrier_port: %d\n"+
		"  carriers:\n    alpha: {host: \"%s:%d\", transport: %s%s}\n", cp, host, carrier.port, o.transport, o.extra), 1)
	h := newHarness(t, yaml, priv)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	cs := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cp))
	h.upstreams["carrier-port"] = cs
	if len(o.dns) > 0 {
		stub := &dnsStub{ips: map[string][]string{}}
		for name, ip := range o.dns {
			stub.ips[name] = []string{ip}
		}
		h.srv.carriers.lookupSRV, h.srv.carriers.lookupIP = stub.lookupSRV, stub.lookupIP
	}
	if o.tune != nil {
		o.tune(&h.srv.streamLim)
	}
	h.run()
	rig := &streamRig{carrierRig: &carrierRig{harness: h, cs: cs}, carrier: carrier}
	waitFor(t, 5*time.Second, "the carrier to resolve", func() bool {
		_, ok := h.srv.carrierDest("alpha")
		return ok
	})
	return rig
}

// tlsServerConf is a carrier's TLS server side.
func tlsServerConf(l leaf) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{l.cert}, MinVersion: tls.VersionTLS12}
}

// placeCall has the switch call the carrier through FreeSBC and returns the
// INVITE the carrier received and the 200 the switch got.
func (r *streamRig) placeCall(t *testing.T, host string) (*sip.Request, *sip.Response) {
	t.Helper()
	res := r.fs.call(t, r.ruri("+442071234567", host), r.privateSIP, phoneOfferSDP(r.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("switch INVITE to the carrier: got %d, want 200", res.StatusCode)
	}
	return r.carrier.waitInbound(t, sip.INVITE), res
}

// A call placed to a tcp or tls carrier: the carrier sees FreeSBC's public
// identity on its transport, the call is acked and ended from the switch
// side, then a second call is ended from the carrier side over the
// connection FreeSBC opened. One connection carries everything.
func runStreamOutboundCall(t *testing.T, transport string) {
	var rig *streamRig
	if transport == "tls" {
		pki := newTestPKI(t)
		srv := pki.issue(false, nil, "127.0.0.1")
		rig = startStreamRig(t, streamRigOpts{transport: "tls", serverConf: tlsServerConf(srv),
			extra: fmt.Sprintf(", ca_file: %q", pki.caFile())})
	} else {
		rig = startStreamRig(t, streamRigOpts{transport: "tcp"})
	}
	want := strings.ToUpper(transport)
	defPort := 5060
	if transport == "tls" {
		defPort = 5061
	}

	inv, res := rig.placeCall(t, "127.0.0.1")
	if v := inv.Via(); !strings.EqualFold(v.Transport, want) || v.Port != defPort {
		t.Errorf("Via toward the carrier = %s %s:%d, want %s 127.0.0.1:%d", v.Transport, v.Host, v.Port, want, defPort)
	} else if _, ok := v.Params.Get("alias"); !ok {
		t.Errorf("Via %s has no alias parameter although no %s listener exists", v.String(), transport)
	}
	if n := len(inv.GetHeaders("Via")); n != 1 {
		t.Errorf("%d Vias reached the carrier, want 1", n)
	}
	rrs := inv.GetHeaders("Record-Route")
	if len(rrs) != 1 {
		t.Fatalf("%d Record-Routes reached the carrier, want FreeSBC's public one", len(rrs))
	}
	if tr, _ := rrs[0].(*sip.RecordRouteHeader).Address.UriParams.Get("transport"); tr != transport {
		t.Errorf("Record-Route transport = %q, want %q", tr, transport)
	}
	if tr, _ := inv.Contact().Address.UriParams.Get("transport"); tr != transport {
		t.Errorf("Contact %s names no transport=%s", inv.Contact().Address.String(), transport)
	}
	if a := portLeak(inv.String(), rig.privateSIP, rig.fs.addr, rig.cs.addr); a != "" {
		t.Errorf("%s leaked to the carrier:\n%s", a, inv.String())
	}
	// The switch's route set still starts at the private socket (double
	// Record-Route across the transport change).
	rr := res.GetHeaders("Record-Route")
	if len(rr) != 2 || rr[len(rr)-1].(*sip.RecordRouteHeader).Address.Port != portOf(rig.privateSIP) {
		t.Errorf("Record-Routes toward the switch = %v, want public then private", rr)
	}

	rig.fs.sendAckTo2xx(t, res)
	rig.carrier.waitInbound(t, sip.ACK)
	if bye := rig.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Fatalf("BYE from the switch: got %d, want the carrier's 200", bye.StatusCode)
	}
	rig.carrier.waitInbound(t, sip.BYE)
	waitForRelease(t, rig.harness)

	// Second call, ended by the carrier over the connection FreeSBC opened.
	inv2, res2 := rig.placeCall(t, "127.0.0.1")
	rig.fs.sendAckTo2xx(t, res2)
	rig.carrier.waitInbound(t, sip.ACK)
	if bye := rig.carrier.bye(t, inv2, inv2.Source()); bye.StatusCode != 200 {
		t.Fatalf("BYE from the carrier: got %d, want 200", bye.StatusCode)
	}
	if got := rig.fs.waitFor(sip.BYE, 1, 3*time.Second); len(got) != 1 {
		t.Errorf("the switch saw %d BYEs from the carrier, want 1", len(got))
	}
	waitForRelease(t, rig.harness)

	if n := rig.carrier.ln.accepted(); n != 1 {
		t.Errorf("the carrier accepted %d connections, want one reused for both calls", n)
	}
}

func TestCarrierTCPOutboundCall(t *testing.T) { runStreamOutboundCall(t, "tcp") }
func TestCarrierTLSOutboundCall(t *testing.T) { runStreamOutboundCall(t, "tls") }

// A lost connection is dialed again on the next request, and shutdown closes
// the connection FreeSBC opened.
func TestCarrierConnectionRedialAndShutdown(t *testing.T) {
	rig := startStreamRig(t, streamRigOpts{transport: "tcp"})
	inv, res := rig.placeCall(t, "127.0.0.1")
	rig.fs.sendAckTo2xx(t, res)
	rig.carrier.waitInbound(t, sip.ACK)
	rig.fs.uacBye(t, res)
	rig.carrier.waitInbound(t, sip.BYE)
	_ = inv

	rig.carrier.ln.closeAccepted()
	waitFor(t, 5*time.Second, "FreeSBC to notice the closed connection", func() bool {
		c, err := rig.srv.srv.TransportLayer().GetConnection("tcp", rig.carrier.ln.Addr().String())
		if err == nil && c != nil {
			_, _ = c.TryClose()
			return false
		}
		return true
	})
	_, res2 := rig.placeCall(t, "127.0.0.1")
	if n := rig.carrier.ln.accepted(); n != 2 {
		t.Errorf("the carrier accepted %d connections, want a second one after the loss", n)
	}
	rig.fs.sendAckTo2xx(t, res2)
	rig.carrier.waitInbound(t, sip.ACK)

	rig.cancel()
	<-rig.done
	rig.carrier.ln.mu.Lock()
	last := rig.carrier.ln.conns[len(rig.carrier.ln.conns)-1]
	rig.carrier.ln.mu.Unlock()
	_ = last.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := last.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("the carrier connection is still open after shutdown (read err = %v)", err)
	}
}

// The switch's REGISTER at a tls carrier: the Contact toward the carrier
// names FreeSBC's tls listener when there is one (else the tls default
// port), carries the token and transport=tls, and the carrier's 200 is
// restored for the switch.
func TestCarrierRegisterOverTLS(t *testing.T) {
	for _, listener := range []bool{false, true} {
		t.Run(fmt.Sprintf("listener=%v", listener), func(t *testing.T) {
			pki := newTestPKI(t)
			srv := pki.issue(false, nil, "127.0.0.1")
			rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: tlsServerConf(srv), listenTLS: listener,
				extra: fmt.Sprintf(", ca_file: %q", pki.caFile())})
			ruri := sip.Uri{Host: "127.0.0.1", Port: rig.carrier.port}
			orig := sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(rig.fs.addr), UriParams: sip.NewParams()}
			orig.UriParams.Add("transport", "udp")
			token := carrierToken(rig.upstream, orig.String())

			res := sendFromSwitch(t, rig.fs, carrierRegister(rig.fs, rig.privateSIP, ruri, orig, 3600, "reg-tls", 1, ""))
			if res.StatusCode != 200 {
				t.Fatalf("REGISTER over tls: got %d, want 200", res.StatusCode)
			}
			reg := rig.carrier.waitInbound(t, sip.REGISTER)
			c, _ := fsip.ContactURI(reg)
			wantPort := 5061
			if listener {
				wantPort = portOf(rig.publicTLS)
			}
			if tr, _ := c.UriParams.Get("transport"); c.User != "gw" || c.Port != wantPort || tr != "tls" || contactToken(reg) != token {
				t.Errorf("Contact toward the carrier = %s, want sip:gw@<public>:%d;fsbc=%s;transport=tls", c.String(), wantPort, token)
			}
			if got, _ := fsip.ContactURI(res); got.String() != orig.String() {
				t.Errorf("Contact restored for the switch = %s, want %s", got.String(), orig.String())
			}
			if _, found := rig.srv.carrierRegs.lookup(token); !found {
				t.Error("no binding stored for the registration")
			}
		})
	}
}

// A carrier call to FreeSBC's tls listener reaches the switch's carrier
// port with X-FreeSBC-Carrier, and the call completes.
func TestCarrierInboundOverTLSListener(t *testing.T) {
	pki := newTestPKI(t)
	srv := pki.issue(false, nil, "127.0.0.1")
	rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: tlsServerConf(srv), listenTLS: true,
		extra: fmt.Sprintf(", ca_file: %q", pki.caFile())})
	c := rig.carrier
	invite := c.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(c.rtpPort))
	res := c.do(t, invite, rig.publicTLS)
	if res.StatusCode != 200 {
		t.Fatalf("carrier INVITE over tls: got %d, want 200", res.StatusCode)
	}
	got := rig.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("the switch's carrier port saw %d INVITEs, want 1", len(got))
	}
	if hs := carrierHeaders(got[0]); len(hs) != 1 || hs[0] != "alpha" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [alpha]", hs)
	}
	sendAck(t, c.client, invite, res, rig.publicTLS)
	if bye := c.do(t, buildBye(c.client, invite, res), rig.publicTLS); bye.StatusCode != 200 {
		t.Fatalf("carrier BYE: got %d, want 200", bye.StatusCode)
	}
	if got := rig.cs.waitFor(sip.BYE, 1, 3*time.Second); len(got) != 1 {
		t.Errorf("the switch saw %d BYEs, want 1", len(got))
	}
	waitForRelease(t, rig.harness)
}

// With no tls listener at all, a tls carrier's own requests are accepted on
// the connection FreeSBC opened to it.
func TestCarrierInboundOverOpenedConnection(t *testing.T) {
	pki := newTestPKI(t)
	srv := pki.issue(false, nil, "127.0.0.1")
	rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: tlsServerConf(srv),
		extra: fmt.Sprintf(", ca_file: %q", pki.caFile())})
	if rig.publicTLS != "" {
		t.Fatal("the rig has a tls listener")
	}
	ruri := sip.Uri{Host: "127.0.0.1", Port: rig.carrier.port}
	orig := sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(rig.fs.addr)}
	if res := sendFromSwitch(t, rig.fs, carrierRegister(rig.fs, rig.privateSIP, ruri, orig, 3600, "reg-open", 1, "")); res.StatusCode != 200 {
		t.Fatalf("REGISTER: got %d, want 200", res.StatusCode)
	}
	c := rig.carrier
	dest := c.waitInbound(t, sip.REGISTER).Source() // FreeSBC's end of the connection it opened

	invite := c.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(c.rtpPort))
	res := c.do(t, invite, dest)
	if res.StatusCode != 200 {
		t.Fatalf("carrier INVITE over the opened connection: got %d, want 200", res.StatusCode)
	}
	got := rig.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("the switch's carrier port saw %d INVITEs, want 1", len(got))
	}
	if hs := carrierHeaders(got[0]); len(hs) != 1 || hs[0] != "alpha" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [alpha]", hs)
	}
	sendAck(t, c.client, invite, res, dest)
	if bye := c.do(t, buildBye(c.client, invite, res), dest); bye.StatusCode != 200 {
		t.Fatalf("carrier BYE: got %d, want 200", bye.StatusCode)
	}
	if n := c.ln.accepted(); n != 1 {
		t.Errorf("the carrier accepted %d connections, want 1", n)
	}
	waitForRelease(t, rig.harness)
}

// expectNoCall places a call to the carrier and expects a 503 from FreeSBC
// with nothing reaching the carrier.
func expectNoCall(t *testing.T, rig *streamRig, host string) {
	t.Helper()
	res := rig.fs.call(t, rig.ruri("+442071234567", host), rig.privateSIP, phoneOfferSDP(rig.fs.rtpPort))
	if res.StatusCode != 503 {
		t.Fatalf("INVITE to a carrier that failed verification: got %d, want 503", res.StatusCode)
	}
	rig.carrier.noInbound(t)
	waitForRelease(t, rig.harness)
}

// The server certificate must name the carrier host: a certificate for
// another name, or from a CA that is not trusted, fails closed. A DNS
// carrier is verified against its configured name, not the address.
func TestCarrierTLSVerificationFailsClosed(t *testing.T) {
	const host = "sip.carrier.test"
	dns := map[string]string{host: "127.0.0.1"}

	t.Run("valid name", func(t *testing.T) {
		pki := newTestPKI(t)
		rig := startStreamRig(t, streamRigOpts{transport: "tls", host: host, dns: dns,
			serverConf: tlsServerConf(pki.issue(false, []string{host})),
			extra:      fmt.Sprintf(", ca_file: %q", pki.caFile())})
		inv, res := rig.placeCall(t, host)
		_ = inv
		rig.fs.sendAckTo2xx(t, res)
		rig.fs.uacBye(t, res)
	})
	t.Run("wrong name", func(t *testing.T) {
		pki := newTestPKI(t)
		rig := startStreamRig(t, streamRigOpts{transport: "tls", host: host, dns: dns,
			serverConf: tlsServerConf(pki.issue(false, []string{"other.carrier.test"}, "127.0.0.1")),
			extra:      fmt.Sprintf(", ca_file: %q", pki.caFile())})
		expectNoCall(t, rig, host)
	})
	t.Run("untrusted CA", func(t *testing.T) {
		trusted, rogue := newTestPKI(t), newTestPKI(t)
		rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: tlsServerConf(rogue.issue(false, nil, "127.0.0.1")),
			extra: fmt.Sprintf(", ca_file: %q", trusted.caFile())})
		expectNoCall(t, rig, "127.0.0.1")
	})
	t.Run("system roots do not trust a private CA", func(t *testing.T) {
		pki := newTestPKI(t)
		rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: tlsServerConf(pki.issue(false, nil, "127.0.0.1"))})
		expectNoCall(t, rig, "127.0.0.1")
	})
}

// A carrier that demands a client certificate refuses FreeSBC without one
// and accepts it with client_cert and client_key.
func TestCarrierMutualTLS(t *testing.T) {
	newConf := func(pki *testPKI, maxTLS uint16) *tls.Config {
		c := tlsServerConf(pki.issue(false, nil, "127.0.0.1"))
		c.ClientAuth = tls.RequireAndVerifyClientCert
		c.ClientCAs = pki.pool()
		c.MaxVersion = maxTLS
		return c
	}
	t.Run("without a client certificate", func(t *testing.T) {
		pki := newTestPKI(t)
		// TLS 1.2 reports the refusal inside the handshake; under 1.3 the
		// client finishes first and learns on its next read.
		rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: newConf(pki, tls.VersionTLS12),
			extra: fmt.Sprintf(", ca_file: %q", pki.caFile())})
		expectNoCall(t, rig, "127.0.0.1")
	})
	t.Run("with a client certificate", func(t *testing.T) {
		pki := newTestPKI(t)
		client := pki.issue(true, nil)
		rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: newConf(pki, tls.VersionTLS13),
			extra: fmt.Sprintf(", ca_file: %q, client_cert: %q, client_key: %q", pki.caFile(), client.certFile, client.keyFile)})
		_, res := rig.placeCall(t, "127.0.0.1")
		rig.fs.sendAckTo2xx(t, res)
		rig.fs.uacBye(t, res)
	})
}

// A missing certificate file stops startup with a message naming the
// carrier.
func TestCarrierTLSFilesLoadedAtStartup(t *testing.T) {
	for name, extra := range map[string]string{
		"ca_file":     `, ca_file: "/nonexistent/ca.pem"`,
		"client pair": `, client_cert: "/nonexistent/c.pem", client_key: "/nonexistent/c.key"`,
	} {
		t.Run(name, func(t *testing.T) {
			yaml := harnessYAML(t, []string{"127.0.0.1:5090"}, freePort(t), 0, 0, nextMediaBase(t), "")
			yaml = strings.Replace(yaml, "edge:\n", "edge:\n  carriers:\n    alpha: {host: \"127.0.0.1:5061\", transport: tls"+extra+"}\n", 1)
			cfg, err := config.Parse([]byte(yaml))
			if err != nil {
				t.Fatal(err) // check-time validation opens no file
			}
			_, err = New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err == nil || !strings.Contains(err.Error(), "edge.carriers.alpha") {
				t.Errorf("New with an unreadable %s = %v, want an error naming edge.carriers.alpha", name, err)
			}
		})
	}
}

// A tls carrier's address over UDP is not a carrier source: its INVITE is
// dropped without a response and counted, never reaching the switch.
func TestCarrierAdmissionRequiresCarrierTransport(t *testing.T) {
	pki := newTestPKI(t)
	rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: tlsServerConf(pki.issue(false, nil, "127.0.0.1")),
		extra: fmt.Sprintf(", ca_file: %q", pki.caFile())})
	phone := newUDPClient(t) // 127.0.0.1, the tls carrier's address, over UDP
	before := admissionDrops(rig.harness, dropInviteNotAdmitted)
	invite := phone.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(4000))
	expectSilence(t, phone, invite, rig.publicUDP)
	if got := admissionDrops(rig.harness, dropInviteNotAdmitted); got == before {
		t.Error("the INVITE was not counted as an admission drop")
	}
	if got := rig.cs.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the switch saw %d INVITEs from a tls carrier over UDP, want 0", len(got))
	}
}

// Connections to and from carriers are counted apart from the public
// global cap, so public junk that fills it cannot block a switch-to-carrier
// call (a dial) or a carrier's own connection (an accept).
func TestStreamCarrierConnectionsOutsidePublicCap(t *testing.T) {
	t.Run("dial", func(t *testing.T) {
		rig := startStreamRig(t, streamRigOpts{transport: "tcp",
			tune: func(l *streamLimits) { l.maxTotal = 1 }})
		if why, ok := rig.srv.streams.acquire(netip.MustParseAddr("203.0.113.9"), false, rig.srv.streamLim); !ok {
			t.Fatalf("filling the public cap: %v", why)
		}
		if _, ok := rig.srv.streams.acquire(netip.MustParseAddr("203.0.113.10"), false, rig.srv.streamLim); ok {
			t.Fatal("the public cap of 1 admitted a second public connection")
		}
		inv, res := rig.placeCall(t, "127.0.0.1")
		rig.fs.sendAckTo2xx(t, res)
		rig.carrier.waitInbound(t, sip.ACK)
		_ = inv
		if n := rig.srv.metrics.Snapshot().StreamRefused["global_cap"]; n != 0 {
			t.Errorf("global_cap refusals = %d, want 0 for a carrier dial", n)
		}
		rig.fs.uacBye(t, res)
		rig.carrier.waitInbound(t, sip.BYE)
	})
	t.Run("accept", func(t *testing.T) {
		h := startStreamHarness(t, streamOpts{tcp: true, carrierSources: harnessCarrierSources,
			tune: func(l *streamLimits) { l.maxTotal = 1 }})
		if _, ok := h.srv.streams.acquire(netip.MustParseAddr("203.0.113.9"), false, h.srv.streamLim); !ok {
			t.Fatal("filling the public cap")
		}
		c := dialRaw(t, "tcp", h.publicTCP) // 127.0.0.1 is a carrier source
		c.expectServing(t, "tcp", 1)
		if n := h.srv.metrics.Snapshot().StreamRefused["global_cap"]; n != 0 {
			t.Errorf("global_cap refusals = %d, want 0 for a carrier source", n)
		}
	})
}

// The carrier pool has its own bound, and each source stays bounded per IP.
func TestStreamTableCarrierPool(t *testing.T) {
	tab := newStreamTable()
	lim := streamLimits{maxPerIP: 2, maxTotal: 1, maxCarrier: 2}
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	if _, ok := tab.acquire(a, false, lim); !ok {
		t.Fatal("first public slot refused")
	}
	if why, ok := tab.acquire(b, false, lim); ok || why != refuseGlobalCap {
		t.Fatalf("second public slot: ok=%v why=%v, want global cap", ok, why)
	}
	for i := 0; i < 2; i++ {
		if _, ok := tab.acquire(b, true, lim); !ok {
			t.Fatalf("carrier slot %d refused while the public pool is full", i)
		}
	}
	if why, ok := tab.acquire(b, true, lim); ok || why != refuseGlobalCap {
		t.Fatalf("third carrier slot: ok=%v why=%v, want the carrier cap", ok, why)
	}
	tab.release(b, true)
	if why, ok := tab.acquire(b, true, lim); !ok {
		t.Fatalf("carrier slot after a release: %v", why)
	}
	if n := tab.open(); n != 3 {
		t.Errorf("open = %d, want 3", n)
	}
}
