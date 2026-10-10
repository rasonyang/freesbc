package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/srtp/v3"
	"github.com/pion/transport/v4/packetio"
)

// leg is the media half of one WebRTC call: an ICE agent (controlling, full
// ICE against FreeSBC's ICE-Lite), a DTLS endpoint and SRTP contexts keyed
// from the handshake. It follows the pattern of the edge's fakeBrowser test
// helper (internal/edge/webrtc_inbound_test.go).
type leg struct {
	agent *ice.Agent
	ufrag string
	pwd   string
	cert  tls.Certificate
	cands []ice.Candidate

	mu      sync.Mutex
	conn    *ice.Conn
	dtlsBuf *packetio.Buffer
	dtlsC   *dtls.Conn
	srtpIn  chan []byte
	in, out *srtp.Context

	iceDur, dtlsDur time.Duration
}

func newLeg(includeLoopback bool) (*leg, error) {
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelError
	opts := []ice.AgentOption{
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost}),
		ice.WithLoggerFactory(lf),
	}
	if includeLoopback {
		opts = append(opts, ice.WithIncludeLoopback())
	}
	agent, err := ice.NewAgentWithOptions(opts...)
	if err != nil {
		return nil, err
	}
	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		_ = agent.Close()
		return nil, err
	}
	cert, err := selfSignedCert()
	if err != nil {
		_ = agent.Close()
		return nil, err
	}
	l := &leg{agent: agent, ufrag: ufrag, pwd: pwd, cert: cert, srtpIn: make(chan []byte, 256)}
	var cmu sync.Mutex
	done := make(chan struct{})
	if err := agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			close(done)
			return
		}
		cmu.Lock()
		l.cands = append(l.cands, c)
		cmu.Unlock()
	}); err != nil {
		_ = agent.Close()
		return nil, err
	}
	if err := agent.GatherCandidates(); err != nil {
		_ = agent.Close()
		return nil, err
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = agent.Close()
		return nil, errors.New("ICE gathering timed out")
	}
	cmu.Lock()
	n := len(l.cands)
	cmu.Unlock()
	if n == 0 {
		_ = agent.Close()
		return nil, errors.New("no ICE candidates gathered")
	}
	return l, nil
}

func (l *leg) close() {
	l.mu.Lock()
	d, c, buf := l.dtlsC, l.conn, l.dtlsBuf
	l.mu.Unlock()
	if d != nil {
		_ = d.Close()
	}
	if buf != nil {
		_ = buf.Close()
	}
	if c != nil {
		_ = c.Close()
	}
	_ = l.agent.Close()
}

func (l *leg) fingerprint() string { return fingerprintOf(l.cert.Certificate[0]) }

// offerSDP is a browser-style offer: PCMU + telephone-event, rtcp-mux,
// DTLS-SRTP with setup:actpass and the gathered host candidates.
func (l *leg) offerSDP(advertise string) string {
	var b strings.Builder
	first := l.cands[0]
	ip := first.Address()
	if advertise != "" {
		ip = advertise
	}
	fmt.Fprintf(&b, "v=0\r\no=- %d 2 IN IP4 %s\r\ns=-\r\nt=0 0\r\n", time.Now().UnixNano()/1000, ip)
	fmt.Fprintf(&b, "m=audio %d UDP/TLS/RTP/SAVPF 0 101\r\nc=IN IP4 %s\r\n", first.Port(), ip)
	fmt.Fprintf(&b, "a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n", l.ufrag, l.pwd)
	for _, c := range l.cands {
		fmt.Fprintf(&b, "a=candidate:%s\r\n", c.Marshal())
	}
	fmt.Fprintf(&b, "a=fingerprint:sha-256 %s\r\na=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\n", l.fingerprint())
	b.WriteString("a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=ptime:20\r\na=sendrecv\r\n")
	return b.String()
}

// answer is what the load client needs from FreeSBC's SDP answer.
type answer struct {
	ufrag, pwd  string
	fingerprint string
	setup       string
	cands       []ice.Candidate
}

func parseAnswer(body string) (*answer, error) {
	a := &answer{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "a=ice-ufrag:"):
			a.ufrag = strings.TrimPrefix(line, "a=ice-ufrag:")
		case strings.HasPrefix(line, "a=ice-pwd:"):
			a.pwd = strings.TrimPrefix(line, "a=ice-pwd:")
		case strings.HasPrefix(line, "a=fingerprint:sha-256 "):
			a.fingerprint = strings.TrimPrefix(line, "a=fingerprint:sha-256 ")
		case strings.HasPrefix(line, "a=setup:"):
			a.setup = strings.TrimPrefix(line, "a=setup:")
		case strings.HasPrefix(line, "a=candidate:"):
			c, err := ice.UnmarshalCandidate(strings.TrimPrefix(line, "a=candidate:"))
			if err != nil {
				return nil, err
			}
			a.cands = append(a.cands, c)
		}
	}
	if a.ufrag == "" || a.pwd == "" || a.fingerprint == "" || len(a.cands) == 0 {
		return nil, fmt.Errorf("answer lacks ICE or DTLS attributes: %q", body)
	}
	return a, nil
}

// connect runs ICE then DTLS then keys SRTP.
func (l *leg) connect(ctx context.Context, a *answer) error {
	for _, c := range a.cands {
		if err := l.agent.AddRemoteCandidate(c); err != nil {
			return err
		}
	}
	t0 := time.Now()
	conn, err := l.agent.Dial(ctx, a.ufrag, a.pwd)
	if err != nil {
		return fmt.Errorf("ice: %w", err)
	}
	l.iceDur = time.Since(t0)
	buf := packetio.NewBuffer()
	l.mu.Lock()
	l.conn, l.dtlsBuf = conn, buf
	l.mu.Unlock()
	go func() { // RFC 7983 demultiplexing
		p := make([]byte, 1600)
		for {
			n, err := conn.Read(p)
			if err != nil {
				_ = buf.Close()
				close(l.srtpIn)
				return
			}
			switch c := p[0]; {
			case n > 0 && c >= 20 && c <= 63:
				_, _ = buf.Write(p[:n])
			case n > 12 && c >= 128 && c <= 191:
				select {
				case l.srtpIn <- append([]byte(nil), p[:n]...):
				default:
				}
			}
		}
	}()

	want := strings.ToUpper(a.fingerprint)
	opts := []dtls.Option{
		dtls.WithCertificates(l.cert),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithVerifyPeerCertificate(func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || fingerprintOf(raw[0]) != want {
				return errors.New("DTLS certificate does not match the answer's a=fingerprint")
			}
			return nil
		}),
	}
	// We offered actpass: the answer's setup picks our role.
	client := !strings.EqualFold(a.setup, "active")
	pc := &demuxConn{buf: buf, conn: conn}
	var dc *dtls.Conn
	t1 := time.Now()
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
		return fmt.Errorf("dtls: %w", err)
	}
	l.mu.Lock()
	l.dtlsC = dc
	l.mu.Unlock()
	if err := dc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("dtls: %w", err)
	}
	l.dtlsDur = time.Since(t1)
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
	l.mu.Lock()
	l.in, l.out = in, out
	l.mu.Unlock()
	return nil
}

// mediaStats is what one call's RTP exchange measured.
type mediaStats struct {
	sent, recv uint64
	lostSeq    uint64  // gaps inside the received sequence range
	jitterMs   float64 // RFC 3550 interarrival jitter at the end
	rtts       []time.Duration
}

// exchange sends G.711 20 ms SRTP for hold and measures what comes back (the
// switch UAS echoes it): the receive ratio, sequence gaps, jitter and the
// round-trip time through FreeSBC and the switch.
func (l *leg) exchange(ctx context.Context, hold time.Duration) mediaStats {
	l.mu.Lock()
	in, out, conn := l.in, l.out, l.conn
	l.mu.Unlock()
	var st mediaStats
	var smu sync.Mutex
	done := make(chan struct{})

	go func() { // receiver
		defer close(done)
		var (
			have    bool
			last    uint16
			jitter  float64
			prevArr float64
			prevTS  uint32
		)
		for p := range l.srtpIn {
			if p[1]&0x7f >= 72 && p[1]&0x7f <= 76 { // RTCP muxed on the same port
				continue
			}
			plain, err := in.DecryptRTP(nil, p, nil)
			if err != nil || len(plain) < 12+8 {
				continue
			}
			now := time.Now()
			seq := binary.BigEndian.Uint16(plain[2:4])
			ts := binary.BigEndian.Uint32(plain[4:8])
			sendNs := int64(binary.BigEndian.Uint64(plain[12:20]))
			arr := float64(now.UnixNano()) * 8000 / 1e9
			smu.Lock()
			st.recv++
			if have {
				if d := int(seq) - int(last); d > 1 && d < 0x8000 {
					st.lostSeq += uint64(d - 1)
				}
				d := (arr - prevArr) - float64(int32(ts-prevTS))
				jitter += (math.Abs(d) - jitter) / 16
				st.jitterMs = jitter / 8
			}
			st.rtts = append(st.rtts, time.Duration(now.UnixNano()-sendNs))
			smu.Unlock()
			prevArr, prevTS, last, have = arr, ts, seq, true
		}
	}()

	ssrc := rand32()
	var seq uint16
	ts := rand32()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	end := time.NewTimer(hold)
	defer end.Stop()
	pkt := make([]byte, 12+160)
	pkt[0], pkt[1] = 0x80, 0
	binary.BigEndian.PutUint32(pkt[8:12], ssrc)
	for i := 12 + 8; i < len(pkt); i++ {
		pkt[i] = 0xFF // mu-law silence
	}
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-end.C:
			break loop
		case <-tick.C:
			binary.BigEndian.PutUint16(pkt[2:4], seq)
			binary.BigEndian.PutUint32(pkt[4:8], ts)
			binary.BigEndian.PutUint64(pkt[12:20], uint64(time.Now().UnixNano()))
			enc, err := out.EncryptRTP(nil, pkt, nil)
			if err != nil {
				break loop
			}
			if _, err := conn.Write(enc); err != nil {
				break loop
			}
			smu.Lock()
			st.sent++
			smu.Unlock()
			seq++
			ts += 160
		}
	}
	// Let the last echoes arrive, then stop the receiver by closing the conn.
	time.Sleep(200 * time.Millisecond)
	l.close()
	<-done
	smu.Lock()
	defer smu.Unlock()
	return st
}

func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(math.Ceil(p/100*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	return s[i]
}

func rand32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// demuxConn is the DTLS half of the demultiplexed ICE flow.
type demuxConn struct {
	buf  *packetio.Buffer
	conn net.Conn
}

func (c *demuxConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.buf.Read(p)
	return n, c.conn.RemoteAddr(), err
}
func (c *demuxConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.conn.Write(p) }
func (c *demuxConn) Close() error                              { return c.buf.Close() }
func (c *demuxConn) LocalAddr() net.Addr                       { return c.conn.LocalAddr() }
func (c *demuxConn) SetDeadline(t time.Time) error             { return c.buf.SetReadDeadline(t) }
func (c *demuxConn) SetReadDeadline(t time.Time) error         { return c.buf.SetReadDeadline(t) }
func (c *demuxConn) SetWriteDeadline(time.Time) error          { return nil }

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(rand32())),
		Subject:      pkix.Name{CommonName: "webrtcload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, v := range sum {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
