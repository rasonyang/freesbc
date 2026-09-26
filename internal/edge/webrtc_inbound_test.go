package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/pion/dtls/v3"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/srtp/v3"
	"github.com/pion/transport/v4/packetio"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// This file covers a call FreeSWITCH places to a browser registered over
// ws or wss (issue #79): FreeSBC offers the browser DTLS-SRTP, and the
// browser's answer starts ICE and DTLS. The "browser" is built from the
// same pion primitives a real one's stack is equivalent to — a full ICE
// agent (controlling), a DTLS endpoint and SRTP contexts keyed from the
// handshake — so the test exercises real connectivity checks, a real
// handshake and real SRTP over loopback.

// fakeBrowser is the media half of a browser answering an INVITE.
type fakeBrowser struct {
	t     *testing.T
	setup string // the a=setup its answer carries: "active" or "passive"
	cert  tls.Certificate
	agent *ice.Agent
	ufrag string
	pwd   string

	// ready receives the outcome of ICE + DTLS + SRTP keying, once.
	ready chan error

	mu      sync.Mutex
	conn    *ice.Conn
	dtls    *dtls.Conn
	dtlsBuf *packetio.Buffer
	srtpIn  chan []byte
	in, out *srtp.Context // in decrypts what FreeSBC sends; out encrypts ours
}

func newFakeBrowser(t *testing.T, setup string) *fakeBrowser {
	t.Helper()
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelError
	agent, err := ice.NewAgentWithOptions(
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost}),
		ice.WithIncludeLoopback(),
		ice.WithLoggerFactory(lf),
	)
	if err != nil {
		t.Fatal(err)
	}
	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := browserCertForTest()
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBrowser{t: t, setup: setup, cert: cert, agent: agent, ufrag: ufrag, pwd: pwd,
		ready: make(chan error, 1), srtpIn: make(chan []byte, 64)}
	t.Cleanup(b.close)
	return b
}

func (b *fakeBrowser) close() {
	b.mu.Lock()
	d, c, buf := b.dtls, b.conn, b.dtlsBuf
	b.mu.Unlock()
	if d != nil {
		_ = d.Close()
	}
	if buf != nil {
		_ = buf.Close()
	}
	if c != nil {
		_ = c.Close()
	}
	_ = b.agent.Close()
}

// fingerprint is the browser certificate's a=fingerprint value.
func (b *fakeBrowser) fingerprint() string { return sha256Fingerprint(b.cert.Certificate[0]) }

// answerSDP is the browser's answer to offer: its ICE credentials,
// fingerprint and DTLS role, rtcp-mux, and the offer's first codec plus
// telephone-event — reusing the offer's payload numbers, as RFC 3264
// requires. connAddr is its c= address ("0.0.0.0" is what a browser that
// has not gathered writes).
func (b *fakeBrowser) answerSDP(offer *sdp.Session, connAddr string) string {
	var pts []string
	var maps strings.Builder
	for _, c := range offer.Audio.Codecs {
		if len(pts) == 0 || strings.EqualFold(c.Name, "telephone-event") {
			pts = append(pts, fmt.Sprint(c.PayloadType))
			fmt.Fprintf(&maps, "a=rtpmap:%d %s/%d\r\n", c.PayloadType, c.Name, c.ClockRate)
		}
	}
	return fmt.Sprintf("v=0\r\no=- 7000 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"+
		"m=audio 9 UDP/TLS/RTP/SAVPF %s\r\nc=IN IP4 %s\r\n"+
		"a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n"+
		"a=fingerprint:sha-256 %s\r\na=setup:%s\r\na=mid:0\r\na=rtcp-mux\r\n%sa=sendrecv\r\n",
		strings.Join(pts, " "), connAddr, b.ufrag, b.pwd, b.fingerprint(), b.setup, maps.String())
}

// connect runs the browser's side once its answer is out: ICE against the
// offer's single host candidate, then DTLS in the role its answer took,
// checking FreeSBC's certificate against the offer's a=fingerprint, then
// SRTP keying. The outcome goes to b.ready.
func (b *fakeBrowser) connect(offerBody []byte) {
	b.ready <- b.establish(offerBody)
}

func (b *fakeBrowser) establish(offerBody []byte) error {
	offer, err := parseLabSDP(offerBody)
	if err != nil {
		return err
	}
	var cand ice.Candidate
	for _, line := range strings.Split(string(offerBody), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "a=candidate:"); ok {
			if cand, err = ice.UnmarshalCandidate(v); err != nil {
				return err
			}
		}
	}
	if cand == nil {
		return errors.New("offer has no candidate")
	}
	if err := b.agent.AddRemoteCandidate(cand); err != nil {
		return err
	}
	if err := b.agent.OnCandidate(func(ice.Candidate) {}); err != nil {
		return err
	}
	if err := b.agent.GatherCandidates(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := b.agent.Dial(ctx, offer.Audio.ICEUfrag, offer.Audio.ICEPwd)
	if err != nil {
		return fmt.Errorf("ice: %w", err)
	}
	buf := packetio.NewBuffer()
	b.mu.Lock()
	b.conn, b.dtlsBuf = conn, buf
	b.mu.Unlock()
	// RFC 7983 demultiplexing, as FreeSBC does on its side.
	go func() {
		p := make([]byte, 1600)
		for {
			n, err := conn.Read(p)
			if err != nil {
				_ = buf.Close()
				close(b.srtpIn)
				return
			}
			switch c := p[0]; {
			case n > 0 && c >= 20 && c <= 63:
				_, _ = buf.Write(p[:n])
			case n > 0 && c >= 128 && c <= 191:
				select {
				case b.srtpIn <- append([]byte(nil), p[:n]...):
				default:
				}
			}
		}
	}()

	want := offer.Audio.Fingerprint
	opts := []dtls.Option{
		dtls.WithCertificates(b.cert),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithVerifyPeerCertificate(func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || want == nil || sha256Fingerprint(raw[0]) != strings.ToUpper(want.Value) {
				return errors.New("FreeSBC's certificate does not match the offer's a=fingerprint")
			}
			return nil
		}),
	}
	pc := &browserDTLSConn{buf: buf, conn: conn}
	client := b.setup == "active"
	var dc *dtls.Conn
	if client {
		co := make([]dtls.ClientOption, 0, len(opts))
		for _, o := range opts {
			co = append(co, o)
		}
		dc, err = dtls.ClientWithOptions(pc, conn.RemoteAddr(), co...)
	} else {
		so := make([]dtls.ServerOption, 0, len(opts)+1)
		for _, o := range opts {
			so = append(so, o)
		}
		so = append(so, dtls.WithClientAuth(dtls.RequireAnyClientCert))
		dc, err = dtls.ServerWithOptions(pc, conn.RemoteAddr(), so...)
	}
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.dtls = dc
	b.mu.Unlock()
	if err := dc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("dtls: %w", err)
	}
	state, ok := dc.ConnectionState()
	if !ok {
		return errors.New("dtls: no connection state")
	}
	const keyLen, saltLen = 16, 14
	m, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, 2*keyLen+2*saltLen)
	if err != nil {
		return err
	}
	ck, sk := m[:keyLen], m[keyLen:2*keyLen]
	cs, ss := m[2*keyLen:2*keyLen+saltLen], m[2*keyLen+saltLen:]
	outK, outS, inK, inS := sk, ss, ck, cs
	if client {
		outK, outS, inK, inS = ck, cs, sk, ss
	}
	out, err := srtp.CreateContext(outK, outS, srtp.ProtectionProfileAes128CmHmacSha1_80)
	if err != nil {
		return err
	}
	in, err := srtp.CreateContext(inK, inS, srtp.ProtectionProfileAes128CmHmacSha1_80)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.in, b.out = in, out
	b.mu.Unlock()
	return nil
}

// waitReady waits for connect's outcome.
func (b *fakeBrowser) waitReady(t *testing.T) {
	t.Helper()
	select {
	case err := <-b.ready:
		if err != nil {
			t.Fatalf("browser ICE/DTLS: %v", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("browser ICE/DTLS never completed")
	}
}

// send encrypts one RTP packet and sends it to FreeSBC.
func (b *fakeBrowser) send(t *testing.T, pkt []byte) {
	t.Helper()
	b.mu.Lock()
	out, conn := b.out, b.conn
	b.mu.Unlock()
	enc, err := out.EncryptRTP(nil, pkt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(enc); err != nil {
		t.Fatal(err)
	}
}

// recv waits for one SRTP packet that decrypts, and returns the plaintext.
func (b *fakeBrowser) recv(d time.Duration) ([]byte, bool) {
	b.mu.Lock()
	in := b.in
	b.mu.Unlock()
	timeout := time.After(d)
	for {
		select {
		case p, ok := <-b.srtpIn:
			if !ok {
				return nil, false
			}
			if plain, err := in.DecryptRTP(nil, p, nil); err == nil {
				return plain, true
			}
		case <-timeout:
			return nil, false
		}
	}
}

// browserDTLSConn is the DTLS half of the browser's demultiplexed flow.
type browserDTLSConn struct {
	buf  *packetio.Buffer
	conn net.Conn
}

func (c *browserDTLSConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.buf.Read(p)
	return n, c.conn.RemoteAddr(), err
}
func (c *browserDTLSConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.conn.Write(p) }
func (c *browserDTLSConn) Close() error                              { return c.buf.Close() }
func (c *browserDTLSConn) LocalAddr() net.Addr                       { return c.conn.LocalAddr() }
func (c *browserDTLSConn) SetDeadline(t time.Time) error             { return c.buf.SetReadDeadline(t) }
func (c *browserDTLSConn) SetReadDeadline(t time.Time) error         { return c.buf.SetReadDeadline(t) }
func (c *browserDTLSConn) SetWriteDeadline(time.Time) error          { return nil }

func browserCertForTest() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "test-browser"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func sha256Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, v := range sum {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// inboundBrowserCall is one FreeSWITCH → browser call in progress.
type inboundBrowserCall struct {
	res    *sip.Response // FreeSWITCH's final response
	invite *sip.Request  // the INVITE the browser received
	toTag  string        // the browser's To tag
	offer  []byte        // the offer the browser received
}

// registerOver registers user from c through the proxy listener at dest
// (the fake switch does not challenge) and returns the Request-URI
// FreeSWITCH calls it on.
func registerOver(t *testing.T, h *harness, c *client, dest, user string) sip.Uri {
	t.Helper()
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	before := len(h.fs.contacts())
	if res := c.do(t, c.buildRegister(user, "example.com", 600, ""), dest); res.StatusCode != 200 {
		t.Fatalf("REGISTER over %s: %d", c.transport, res.StatusCode)
	}
	stored := h.fs.contacts()
	if len(stored) <= before {
		t.Fatal("nothing registered")
	}
	var ruri sip.Uri
	if err := sip.ParseUri(stored[len(stored)-1], &ruri); err != nil {
		t.Fatalf("stored contact %q: %v", stored[len(stored)-1], err)
	}
	return ruri
}

// browserAnswers makes c answer every INVITE: 180, then 200 with the fake
// browser's answer, then (for the initial INVITE) ICE/DTLS in the
// background. The INVITE and To tag go to calls.
func browserAnswers(c *client, b *fakeBrowser, connAddr string, calls chan<- inboundBrowserCall) {
	var mu sync.Mutex
	started := false
	tag := sip.GenerateTagN(12)
	c.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		offer, err := parseLabSDP(req.Body())
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		ringing := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
		ringing.To().Params.Add("tag", tag)
		_ = tx.Respond(ringing)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(b.answerSDP(offer, connAddr)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: c.contactURI(req.Recipient.User)})
		res.To().Params.Add("tag", tag)
		_ = tx.Respond(res)
		mu.Lock()
		first := !started
		started = true
		mu.Unlock()
		if first {
			go b.connect(req.Body())
			select {
			case calls <- inboundBrowserCall{invite: req.Clone(), toTag: tag, offer: req.Body()}:
			default:
			}
		}
	})
}

// assertBrowserOffer checks the offer FreeSBC sent the browser: the secure
// profile, ICE-Lite with exactly one host candidate at the public media
// address, FreeSBC's own fingerprint, rtcp-mux and a=setup:actpass, and
// nothing of FreeSWITCH's.
func assertBrowserOffer(t *testing.T, h *harness, body []byte) {
	t.Helper()
	s := string(body)
	for _, want := range []string{
		"UDP/TLS/RTP/SAVPF", "a=ice-lite", "a=ice-ufrag:", "a=ice-pwd:",
		"a=fingerprint:sha-256 " + h.srv.identity.FingerprintValue, "a=rtcp-mux", "a=setup:actpass",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("browser offer missing %q:\n%s", want, s)
		}
	}
	if n := strings.Count(s, "a=candidate:"); n != 1 {
		t.Errorf("browser offer has %d candidates, want exactly one:\n%s", n, s)
	}
	offer, err := parseLabSDP(body)
	if err != nil {
		t.Fatalf("browser offer unparseable: %v", err)
	}
	if !offer.Audio.WebRTC() {
		t.Error("browser offer is not a WebRTC body")
	}
	pub := h.srv.topo.publicMediaIP.String()
	if offer.Audio.Address.String() != pub {
		t.Errorf("offer c= %s, want the public media address %s", offer.Audio.Address, pub)
	}
	cand := fmt.Sprintf("%s %d typ host", pub, offer.Audio.Port)
	if !strings.Contains(s, cand) {
		t.Errorf("offer candidate is not a host candidate at %s:%d:\n%s", pub, offer.Audio.Port, s)
	}
	if offer.Audio.Port == h.fs.rtpPort {
		t.Error("the browser was offered FreeSWITCH's RTP port")
	}
	if strings.Contains(s, "FreeSWITCH") {
		t.Errorf("FreeSWITCH's o= line leaked to the browser:\n%s", s)
	}
}

// assertUpstreamPlain checks the answer FreeSWITCH got: plain RTP/AVP at
// the private media address, with nothing of the browser's in it.
func assertUpstreamPlain(t *testing.T, h *harness, body []byte, b *fakeBrowser) *sdp.Session {
	t.Helper()
	s := string(body)
	for _, forbidden := range []string{
		"ice-", "candidate", "fingerprint", "setup:", "rtcp-mux", "SAVPF", "UDP/TLS",
		b.ufrag, b.pwd, b.fingerprint(),
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("FreeSWITCH-facing answer leaks %q:\n%s", forbidden, s)
		}
	}
	ans, err := parseLabSDP(body)
	if err != nil {
		t.Fatalf("answer to FreeSWITCH unparseable: %v", err)
	}
	if ans.Audio.WebRTC() || !strings.Contains(s, "RTP/AVP") {
		t.Errorf("FreeSWITCH-facing answer is not plain RTP/AVP:\n%s", s)
	}
	if ans.Audio.Address != h.srv.topo.privateMediaIP {
		t.Errorf("answer c= %s, want the private media address", ans.Audio.Address)
	}
	return ans
}

// placeBrowserCall registers a browser over transport ("ws" or "wss"),
// has FreeSWITCH call it, and completes ICE/DTLS. It returns the call and
// FreeSWITCH's RTP socket, seeded as the address FreeSWITCH offered.
func placeBrowserCall(t *testing.T, h *harness, transport, setup, connAddr string) (*client, *fakeBrowser, inboundBrowserCall, *net.UDPConn) {
	t.Helper()
	var c *client
	dest := h.publicWS
	if transport == "wss" {
		c, dest = newWSSClient(t), h.publicWSS
	} else {
		c = newWSClient(t)
	}
	ruri := registerOver(t, h, c, dest, "1001")
	b := newFakeBrowser(t, setup)
	calls := make(chan inboundBrowserCall, 1)
	browserAnswers(c, b, connAddr, calls)

	fsRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: h.fs.rtpPort})
	if err != nil {
		t.Fatalf("bind FreeSWITCH's RTP port: %v", err)
	}
	t.Cleanup(func() { _ = fsRTP.Close() })

	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("FreeSWITCH → browser INVITE: got %d, want 200", res.StatusCode)
	}
	var call inboundBrowserCall
	select {
	case call = <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("the browser never received the INVITE")
	}
	call.res = res
	h.fs.sendAckTo2xx(t, res)
	b.waitReady(t)
	return c, b, call, fsRTP
}

// assertMediaBothWays sends audio each way through the anchored session.
func assertMediaBothWays(t *testing.T, b *fakeBrowser, fsRTP *net.UDPConn, upstreamAnswer *sdp.Session) {
	t.Helper()
	sbcPriv := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: upstreamAnswer.Audio.Port}
	// FreeSWITCH → browser. The first private packet also latches the
	// private side; repeat until one arrives (the leg may still be
	// verifying when the first goes out).
	fsPkt := rtpPacket(0, 100, 160)
	heard := false
	for i := 0; i < 40 && !heard; i++ {
		if _, err := fsRTP.WriteToUDP(fsPkt, sbcPriv); err != nil {
			t.Fatal(err)
		}
		if plain, ok := b.recv(250 * time.Millisecond); ok {
			if string(plain) != string(fsPkt) {
				t.Fatal("browser received an altered packet")
			}
			heard = true
		}
	}
	if !heard {
		t.Fatal("FreeSWITCH → browser audio never arrived")
	}
	// browser → FreeSWITCH.
	bPkt := rtpPacket(0, 200, 160)
	got := false
	buf := make([]byte, 2048)
	for i := 0; i < 20 && !got; i++ {
		b.send(t, bPkt)
		_ = fsRTP.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		for {
			n, _, err := fsRTP.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if string(buf[:n]) == string(bPkt) {
				got = true
				break
			}
		}
	}
	if !got {
		t.Fatal("browser → FreeSWITCH audio never arrived")
	}
}

// browserUASBye is the BYE the browser sends as the UAS of the call.
func browserUASBye(t *testing.T, c *client, call inboundBrowserCall) *sip.Request {
	t.Helper()
	bye := phoneUASBye(t, c, call.invite, call.toTag)
	bye.Via().Transport = strings.ToUpper(c.transport)
	return bye
}

func assertNoWebRTCFailures(t *testing.T, h *harness) {
	t.Helper()
	snap := h.srv.metrics.Snapshot()
	if snap.WebRTCICEFailures != 0 || snap.WebRTCDTLSFailures != 0 {
		t.Errorf("webrtc failure counters moved: ice=%d dtls=%d", snap.WebRTCICEFailures, snap.WebRTCDTLSFailures)
	}
}

func waitWebRTCSessions(t *testing.T, h *harness, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.metrics.Snapshot().ActiveWebRTCSessions == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("active webrtc sessions = %d, want %d", h.srv.metrics.Snapshot().ActiveWebRTCSessions, want)
}

// TestInboundCallToWSBrowser is issue #79 end to end over ws: FreeSWITCH
// calls a browser registered over a plaintext WebSocket (a TLS-terminating
// proxy in front), the browser is offered DTLS-SRTP, answers with the
// usual a=setup:active, completes ICE/DTLS, audio flows both ways, and a
// BYE from FreeSWITCH releases everything.
func TestInboundCallToWSBrowser(t *testing.T) {
	h := startHarness(t, true)
	_, b, call, fsRTP := placeBrowserCall(t, h, "ws", "active", "127.0.0.1")

	assertBrowserOffer(t, h, call.offer)
	ans := assertUpstreamPlain(t, h, call.res.Body(), b)

	d, ok := h.srv.dialogs.confirmed(fsip.CallID(call.res))
	if !ok {
		t.Fatal("no confirmed dialog")
	}
	sess := d.session()
	if !sess.IsWebRTC() {
		t.Fatal("the browser call's media session is not a WebRTC session")
	}
	if got := sess.webrtc.Leg().DTLSSetup(); got != "passive" {
		t.Errorf("after an a=setup:active answer FreeSBC's role is %q, want passive (DTLS server)", got)
	}
	waitWebRTCSessions(t, h, 1)
	// One reservation per plane (Stats counts reservations): the muxed
	// WebRTC socket on the public one, an RTP/RTCP pair on the private one.
	// Together they are the 2 the ports-in-use metric rises by.
	if pub, _ := h.srv.pubPool.Stats(); pub != 1 {
		t.Errorf("public port reservations = %d, want 1", pub)
	}
	if priv, _ := h.srv.privPool.Stats(); priv != 1 {
		t.Errorf("private port reservations = %d, want 1", priv)
	}

	assertMediaBothWays(t, b, fsRTP, ans)
	assertNoWebRTCFailures(t, h)

	if r := h.fs.uacBye(t, call.res); r.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
	waitWebRTCSessions(t, h, 0)
	assertNoWebRTCFailures(t, h)
}

// TestInboundCallToWSSBrowser is the same call with the browser connected
// over wss (FreeSBC terminating TLS), answering a=setup:passive (FreeSBC
// becomes the DTLS client) and with c=0.0.0.0, and hanging up itself.
func TestInboundCallToWSSBrowser(t *testing.T) {
	h := startHarnessWSS(t, true)
	c, b, call, fsRTP := placeBrowserCall(t, h, "wss", "passive", "0.0.0.0")

	assertBrowserOffer(t, h, call.offer)
	ans := assertUpstreamPlain(t, h, call.res.Body(), b)
	if call.invite.Recipient.UriParams.GetOr("transport", "") != "wss" {
		t.Errorf("INVITE to the browser: Request-URI %s, want transport=wss", call.invite.Recipient.String())
	}
	d, ok := h.srv.dialogs.confirmed(fsip.CallID(call.res))
	if !ok {
		t.Fatal("no confirmed dialog")
	}
	if got := d.session().webrtc.Leg().DTLSSetup(); got != "active" {
		t.Errorf("after an a=setup:passive answer FreeSBC's role is %q, want active (DTLS client)", got)
	}
	waitWebRTCSessions(t, h, 1)
	assertMediaBothWays(t, b, fsRTP, ans)

	if r := c.do(t, browserUASBye(t, c, call), h.publicWSS); r.StatusCode != 200 {
		t.Fatalf("BYE from the browser: got %d", r.StatusCode)
	}
	if got := h.fs.waitFor(sip.BYE, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("FreeSWITCH saw %d BYEs, want 1", len(got))
	}
	waitForRelease(t, h)
	waitWebRTCSessions(t, h, 0)
	assertNoWebRTCFailures(t, h)
}

// TestInboundBrowserCallReInvite: a re-INVITE FreeSWITCH sends on such a
// dialog (a session-timer refresh, a hold) reaches the browser as the same
// DTLS-SRTP stream — same credentials and fingerprint, and the NEGOTIATED
// role (passive), not actpass — and the browser's answer reaches
// FreeSWITCH as plain RTP. Media keeps flowing afterwards.
func TestInboundBrowserCallReInvite(t *testing.T) {
	h := startHarness(t, true)
	c, b, call, fsRTP := placeBrowserCall(t, h, "ws", "active", "127.0.0.1")
	ans := assertUpstreamPlain(t, h, call.res.Body(), b)
	initial, err := parseLabSDP(call.offer)
	if err != nil {
		t.Fatal(err)
	}
	drain(c.inbound)

	reRes := fsUacReInvite(t, h.fs, call.res, phoneOfferSDP(h.fs.rtpPort))
	if reRes.StatusCode != 200 {
		t.Fatalf("re-INVITE: got %d", reRes.StatusCode)
	}
	var reOffer *sip.Request
	timeout := time.After(3 * time.Second)
	for reOffer == nil {
		select {
		case r := <-c.inbound:
			if r.Method == sip.INVITE {
				reOffer = r
			}
		case <-timeout:
			t.Fatal("the browser never received the re-INVITE")
		}
	}
	s := string(reOffer.Body())
	for _, want := range []string{
		"UDP/TLS/RTP/SAVPF", "a=ice-lite", "a=rtcp-mux", "a=setup:passive",
		"a=ice-ufrag:" + initial.Audio.ICEUfrag, "a=ice-pwd:" + initial.Audio.ICEPwd,
		"a=fingerprint:sha-256 " + h.srv.identity.FingerprintValue,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("re-offer to the browser missing %q:\n%s", want, s)
		}
	}
	re, err := parseLabSDP(reOffer.Body())
	if err != nil {
		t.Fatal(err)
	}
	if re.Audio.Port != initial.Audio.Port {
		t.Errorf("re-offer moved the public port %d → %d", initial.Audio.Port, re.Audio.Port)
	}
	assertUpstreamPlain(t, h, reRes.Body(), b)
	assertMediaBothWays(t, b, fsRTP, ans)
	assertNoWebRTCFailures(t, h)

	if r := h.fs.uacBye(t, call.res); r.StatusCode != 200 {
		t.Fatalf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// fsUacReInvite sends a re-INVITE from the fake switch as the UAC of a
// call it placed (routed like uacBye), ACKs a 2xx, and returns the final
// response.
func fsUacReInvite(t *testing.T, f *fakeSwitch, res *sip.Response, body string) *sip.Response {
	t.Helper()
	build := func(method sip.RequestMethod, seq uint32) *sip.Request {
		req := sip.NewRequest(method, res.To().Address)
		if u, ok := fsip.ContactURI(res); ok {
			req.Recipient = u
		}
		sip.CopyHeaders("From", res, req)
		sip.CopyHeaders("To", res, req)
		sip.CopyHeaders("Call-ID", res, req)
		req.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: method})
		mf := sip.MaxForwardsHeader(70)
		req.AppendHeader(&mf)
		req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: hostOf(f.addr), Port: portOf(f.addr)}})
		copyRouteFromRecordRoute(res, req)
		via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
			Host: hostOf(f.addr), Port: portOf(f.addr), Params: sip.NewParams()}
		via.Params.Add("branch", sip.GenerateBranchN(16))
		req.PrependHeader(via)
		req.SetTransport("UDP")
		req.SetDestination(f.inDialogDest(t, req, res))
		req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}
		return req
	}
	seq := res.CSeq().SeqNo + 10
	req := build(sip.INVITE, seq)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody([]byte(body))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("fake switch re-INVITE: %v", err)
	}
	defer tx.Terminate()
	for {
		select {
		case r := <-tx.Responses():
			if r == nil || r.StatusCode < 200 {
				continue
			}
			if r.StatusCode/100 == 2 {
				if err := f.cli.WriteRequest(build(sip.ACK, seq)); err != nil {
					t.Fatalf("fake switch ACK: %v", err)
				}
			}
			return r
		case <-tx.Done():
			t.Fatalf("fake switch re-INVITE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("fake switch re-INVITE timed out")
		}
	}
}

// TestInboundBrowserCallWatchdog: once the browser leg is up, media
// silence ends the call through the silence watchdog, both ends get a
// BYE, and every port is released.
func TestInboundBrowserCallWatchdog(t *testing.T) {
	h := startHarness(t, true)
	auditReplaceConfig(h, func(c *config.Config) { c.Listen.Media.RTPTimeout = config.Duration(time.Second) })
	c, _, call, _ := placeBrowserCall(t, h, "ws", "active", "127.0.0.1")
	waitForDialog(t, h, fsip.CallID(call.res))

	deadline := time.Now().Add(8 * time.Second)
	for h.srv.ActiveCalls() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.srv.ActiveCalls() != 0 {
		t.Fatal("the media watchdog never ended the call")
	}
	if got := h.fs.waitFor(sip.BYE, 1, 3*time.Second); len(got) != 1 {
		t.Errorf("FreeSWITCH saw %d BYEs, want 1", len(got))
	}
	gotBye := false
	timeout := time.After(3 * time.Second)
	for !gotBye {
		select {
		case r := <-c.inbound:
			gotBye = r.Method == sip.BYE
		case <-timeout:
			t.Fatal("the browser never received a BYE")
		}
	}
	waitForRelease(t, h)
	waitWebRTCSessions(t, h, 0)
}

// TestInboundBrowserCallRejected: a browser that rings and then refuses
// (486) — the offer's leg was allocated but never started — leaves nothing
// behind, and FreeSWITCH gets the 486.
func TestInboundBrowserCallRejected(t *testing.T) {
	h := startHarness(t, true)
	c := newWSClient(t)
	ruri := registerOver(t, h, c, h.publicWS, "1001")
	c.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		_ = tx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
	})
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 486 {
		t.Fatalf("got %d, want the browser's 486", res.StatusCode)
	}
	waitForRelease(t, h)
	waitWebRTCSessions(t, h, 0)
	assertNoWebRTCFailures(t, h)
}

// TestInboundBrowserCallPlainAnswerRefused: a "browser" that answers the
// DTLS-SRTP offer with plain RTP cannot be anchored. FreeSWITCH gets a
// 488, the browser's dialog is ACKed and BYEd, and the leg is released.
func TestInboundBrowserCallPlainAnswerRefused(t *testing.T) {
	h := startHarness(t, true)
	c := newWSClient(t)
	ruri := registerOver(t, h, c, h.publicWS, "1001")
	c.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(40000)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: c.contactURI("1001")})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
	})
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 488 {
		t.Fatalf("got %d, want 488", res.StatusCode)
	}
	waitForRelease(t, h)
	waitWebRTCSessions(t, h, 0)
}

// TestInboundCallToBrowserWithoutWebRTC: with webrtc.enabled false there is
// no DTLS-SRTP offer to make, so a call to a ws/wss client is refused 488
// before anything is allocated or sent to the browser — instead of
// offering plain RTP the browser would fail with an opaque 480.
func TestInboundCallToBrowserWithoutWebRTC(t *testing.T) {
	h := startHarness(t, false)
	c := newWSClient(t)
	ruri := registerOver(t, h, c, h.publicWS, "1001")
	drain(c.inbound)
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 488 {
		t.Fatalf("got %d, want 488", res.StatusCode)
	}
	select {
	case r := <-c.inbound:
		t.Fatalf("the browser received a %s", r.Method)
	case <-time.After(300 * time.Millisecond):
	}
	waitForRelease(t, h)
}

// TestInboundCallToUDPPhoneStaysPlainWithWebRTCOn is the regression guard:
// with webrtc enabled, a phone registered over UDP is still offered plain
// RTP/AVP and anchored on the RTP↔RTP relay.
func TestInboundCallToUDPPhoneStaysPlainWithWebRTCOn(t *testing.T) {
	h := startHarness(t, true)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	phoneRTP := auditUDP(t)
	auditPhoneAnswers(phone, auditUDPPort(phoneRTP), nil)
	drain(phone.inbound)

	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("got %d, want 200", res.StatusCode)
	}
	var inv *sip.Request
	timeout := time.After(3 * time.Second)
	for inv == nil {
		select {
		case r := <-phone.inbound:
			if r.Method == sip.INVITE {
				inv = r
			}
		case <-timeout:
			t.Fatal("the phone never received the INVITE")
		}
	}
	s := string(inv.Body())
	if !strings.Contains(s, "RTP/AVP") {
		t.Errorf("UDP phone offer is not RTP/AVP:\n%s", s)
	}
	for _, forbidden := range []string{"SAVPF", "ice-", "candidate", "fingerprint", "setup:", "rtcp-mux"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("UDP phone offer carries %q:\n%s", forbidden, s)
		}
	}
	d, ok := h.srv.dialogs.confirmed(fsip.CallID(res))
	if !ok {
		t.Fatal("no confirmed dialog")
	}
	if d.session().IsWebRTC() {
		t.Error("a UDP phone's call got a WebRTC session")
	}
	h.fs.sendAckTo2xx(t, res)
	if r := h.fs.uacBye(t, res); r.StatusCode != 200 {
		t.Fatalf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}
