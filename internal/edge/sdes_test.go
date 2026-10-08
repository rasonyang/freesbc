package edge

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"

	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// SDES-SRTP on public legs, over real loopback sockets: the public far end
// is a pion/srtp peer (a client or a carrier), the switch a plain RTP
// socket. Timing-based over real UDP loopback: re-run once before treating
// a flake as failure.

func srtpProfileOf(s sdp.CryptoSuite) srtp.ProtectionProfile {
	switch s {
	case sdp.SuiteAESCM128HMACSHA132:
		return srtp.ProtectionProfileAes128CmHmacSha1_32
	case sdp.SuiteAEADAES128GCM:
		return srtp.ProtectionProfileAeadAes128Gcm
	}
	return srtp.ProtectionProfileAes128CmHmacSha1_80
}

func srtpContextOf(t *testing.T, c sdp.Crypto) *srtp.Context {
	t.Helper()
	ctx, err := srtp.CreateContext(c.Key, c.Salt, srtpProfileOf(c.Suite))
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

// sdesBody is an audio body for a public far end: RTP/SAVP with the given
// crypto lines, or plain RTP/AVP when there are none.
func sdesBody(t *testing.T, port int, lines ...sdp.Crypto) string {
	t.Helper()
	base, err := parseLabSDP([]byte(phoneOfferSDP(port)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := sdp.Build{Address: netip.MustParseAddr("127.0.0.1"), Port: port, Codecs: base.Audio.Codecs,
		Crypto: lines, SessionID: 1, SessionVersion: 1}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sdesUnusableBody is an RTP/SAVP offer whose only a=crypto line names a
// suite FreeSBC does not support.
func sdesUnusableBody(port int) string {
	b := strings.Replace(phoneOfferSDP(port), "RTP/AVP", "RTP/SAVP", 1)
	return strings.Replace(b, "a=sendrecv", "a=crypto:1 F8_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20\r\na=sendrecv", 1)
}

func mustCrypto(t *testing.T, tag int, suite sdp.CryptoSuite) sdp.Crypto {
	t.Helper()
	c, err := sdp.NewCrypto(tag, suite)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustParseBody(t *testing.T, body []byte) *sdp.Session {
	t.Helper()
	s, err := parseLabSDP(body)
	if err != nil {
		t.Fatalf("unparseable SDP: %v\n%s", err, body)
	}
	return s
}

// sdesPeer is the media end of a public SRTP peer.
type sdesPeer struct {
	conn     *net.UDPConn
	enc, dec *srtp.Context // protects what the peer sends / unprotects what FreeSBC sends
	seq      uint16
}

func newSDESPeer(t *testing.T) *sdesPeer { return newSDESPeerOn(t, 0) }

func newSDESPeerOn(t *testing.T, port int) *sdesPeer {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &sdesPeer{conn: c, seq: 100}
}

func (p *sdesPeer) port() int { return p.conn.LocalAddr().(*net.UDPAddr).Port }

// keys sets the peer's sending key (own) and the key FreeSBC sends with.
func (p *sdesPeer) keys(t *testing.T, own, fsbc sdp.Crypto) {
	t.Helper()
	p.enc, p.dec = srtpContextOf(t, own), srtpContextOf(t, fsbc)
}

func rtpOf(seq uint16, payload string) []byte {
	raw, err := (&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: seq,
		Timestamp: uint32(seq) * 160, SSRC: 0x0badcafe}, Payload: []byte(payload)}).Marshal()
	if err != nil {
		panic(err)
	}
	return raw
}

func payloadOfRTP(raw []byte) (string, bool) {
	var p rtp.Packet
	if p.Unmarshal(raw) != nil {
		return "", false
	}
	return string(p.Payload), true
}

func readUDP(c *net.UDPConn, d time.Duration) ([]byte, bool) {
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

// toSwitch sends SRTP from the peer to FreeSBC's public port until the
// switch's plain socket receives the payload.
func (p *sdesPeer) toSwitch(t *testing.T, pubPort int, fs *net.UDPConn, payload string) {
	t.Helper()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pubPort}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		p.seq++
		enc, err := p.enc.EncryptRTP(nil, rtpOf(p.seq, payload), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = p.conn.WriteToUDP(enc, dst)
		if raw, ok := readUDP(fs, 100*time.Millisecond); ok {
			if got, ok := payloadOfRTP(raw); ok && got == payload {
				return
			}
		}
	}
	t.Fatalf("peer -> switch: %q never arrived as plain RTP", payload)
}

// fromSwitch sends plain RTP from the switch socket to FreeSBC's private
// port until the peer decrypts the payload.
func (p *sdesPeer) fromSwitch(t *testing.T, privPort int, fs *net.UDPConn, payload string) {
	t.Helper()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: privPort}
	var seq uint16 = 5000
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		seq++
		_, _ = fs.WriteToUDP(rtpOf(seq, payload), dst)
		if raw, ok := readUDP(p.conn, 100*time.Millisecond); ok {
			if dec, err := p.dec.DecryptRTP(nil, raw, nil); err == nil {
				if got, ok := payloadOfRTP(dec); ok && got == payload {
					return
				}
			}
		}
	}
	t.Fatalf("switch -> peer: %q never arrived as SRTP the peer could decrypt", payload)
}

// expectNone asserts the switch socket receives nothing for d.
func expectNone(t *testing.T, fs *net.UDPConn, d time.Duration, what string) {
	t.Helper()
	if raw, ok := readUDP(fs, d); ok {
		t.Errorf("%s: the switch received %d bytes, want nothing", what, len(raw))
	}
}

func fsMediaSocket(t *testing.T, port int) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// sdesRig is a harness with one registered client and the switch's media
// socket.
type sdesRig struct {
	h     *harness
	phone *client
	dest  string
	fs    *net.UDPConn
}

func newSDESRig(t *testing.T, o streamOpts, transport string) *sdesRig {
	t.Helper()
	h := startStreamHarness(t, o)
	var phone *client
	dest := h.publicUDP
	if transport == "udp" {
		phone = newUDPClient(t)
	} else {
		phone, dest = newStreamClient(t, transport), h.streamAddr(transport)
	}
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), dest); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	return &sdesRig{h: h, phone: phone, dest: dest, fs: fsMediaSocket(t, h.fs.rtpPort)}
}

func (r *sdesRig) invite(t *testing.T, body string) (*sip.Request, *sip.Response) {
	t.Helper()
	inv := r.phone.buildInvite("1001", "2002", "example.com", body)
	return inv, r.phone.do(t, inv, r.dest)
}

// fsOffer is the body of the n-th INVITE the switch received.
func (r *sdesRig) fsOffer(t *testing.T, n int) *sip.Request {
	t.Helper()
	invs := r.h.fs.waitFor(sip.INVITE, n, 3*time.Second)
	if len(invs) < n {
		t.Fatalf("the switch saw %d INVITEs, want %d", len(invs), n)
	}
	return invs[n-1]
}

func (r *sdesRig) hangUp(t *testing.T, inv *sip.Request, res *sip.Response) {
	t.Helper()
	sendAck(t, r.phone, inv, res, r.dest)
	if bye := r.phone.do(t, buildBye(r.phone, inv, res), r.dest); bye.StatusCode != 200 {
		t.Errorf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, r.h)
}

// requireSAVPAnswer checks a public-facing answer: RTP/SAVP, exactly one
// crypto line with the offered tag and suite, no rtcp-mux.
func requireSAVPAnswer(t *testing.T, body []byte, want sdp.Crypto) sdp.Crypto {
	t.Helper()
	ans := mustParseBody(t, body)
	a := ans.Audio
	if !a.SDES() || len(a.Crypto) != 1 || a.Crypto[0].Tag != want.Tag || a.Crypto[0].Suite != want.Suite {
		t.Fatalf("answer is not an SDES answer selecting tag %d %s:\n%s", want.Tag, want.Suite, body)
	}
	if a.RTCPMux {
		t.Errorf("an SDES leg must not carry a=rtcp-mux:\n%s", body)
	}
	return a.Crypto[0]
}

// requirePlainSwitchBody checks a body toward the switch: plain RTP/AVP,
// no crypto.
func requirePlainSwitchBody(t *testing.T, body []byte) *sdp.Session {
	t.Helper()
	if strings.Contains(string(body), "a=crypto") || strings.Contains(string(body), "SAVP") {
		t.Errorf("the switch leg must be plain RTP/AVP without a=crypto:\n%s", body)
	}
	return mustParseBody(t, body)
}

func TestSDESClientOptionalEachSuite(t *testing.T) {
	for i, suite := range sdp.SupportedSuites {
		t.Run(string(suite), func(t *testing.T) {
			r := newSDESRig(t, streamOpts{tls: true, edgeExtra: "  srtp: optional\n"}, "tls")
			peer := newSDESPeer(t)
			own := mustCrypto(t, 3+i, suite)
			inv, res := r.invite(t, sdesBody(t, peer.port(), own))
			if res.StatusCode != 200 {
				t.Fatalf("INVITE: %d", res.StatusCode)
			}
			up := requirePlainSwitchBody(t, r.fsOffer(t, 1).Body())
			fsbc := requireSAVPAnswer(t, res.Body(), own)
			pub := mustParseBody(t, res.Body()).Audio.Port

			peer.keys(t, own, fsbc)
			peer.toSwitch(t, pub, r.fs, "from-client")
			peer.fromSwitch(t, up.Audio.Port, r.fs, "from-switch")
			r.hangUp(t, inv, res)
		})
	}
}

// A packet whose authentication tag is wrong is dropped, and the call's
// good traffic is unaffected.
func TestSDESBadAuthTagDropped(t *testing.T) {
	r := newSDESRig(t, streamOpts{tls: true, edgeExtra: "  srtp: optional\n"}, "tls")
	peer := newSDESPeer(t)
	own := mustCrypto(t, 1, sdp.SuiteAESCM128HMACSHA180)
	inv, res := r.invite(t, sdesBody(t, peer.port(), own))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	fsbc := requireSAVPAnswer(t, res.Body(), own)
	pub := mustParseBody(t, res.Body()).Audio.Port
	peer.keys(t, own, fsbc)
	peer.toSwitch(t, pub, r.fs, "warm-up")

	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pub}
	for i := 0; i < 5; i++ {
		peer.seq++
		enc, err := peer.enc.EncryptRTP(nil, rtpOf(peer.seq, "forged"), nil)
		if err != nil {
			t.Fatal(err)
		}
		enc[len(enc)-1] ^= 0xff // break the auth tag
		_, _ = peer.conn.WriteToUDP(enc, dst)
	}
	// Plaintext RTP on an SDES leg is dropped as well.
	_, _ = peer.conn.WriteToUDP(rtpOf(9000, "plaintext"), dst)
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		if raw, ok := readUDP(r.fs, 100*time.Millisecond); ok {
			if got, _ := payloadOfRTP(raw); got == "forged" || got == "plaintext" {
				t.Fatalf("a packet failing authentication reached the switch (%q)", got)
			}
		}
	}
	peer.toSwitch(t, pub, r.fs, "after-forgeries")
	r.hangUp(t, inv, res)
}

// Under "required" a plain offer is refused; under "optional" it is
// accepted and answered plain; an SAVP offer with no usable line is refused
// under both; with srtp off a crypto offer is answered as plain RTP.
func TestSDESOfferPolicy(t *testing.T) {
	cases := []struct {
		name, extra string
		body        func(t *testing.T, port int) string
		want        int
		wantSDES    bool
	}{
		{"required refuses plain", "  srtp: required\n", func(t *testing.T, p int) string { return phoneOfferSDP(p) }, 488, false},
		{"required accepts SAVP", "  srtp: required\n", func(t *testing.T, p int) string {
			return sdesBody(t, p, mustCrypto(t, 1, sdp.SuiteAESCM128HMACSHA180))
		}, 200, true},
		{"optional accepts plain", "  srtp: optional\n", func(t *testing.T, p int) string { return phoneOfferSDP(p) }, 200, false},
		{"optional refuses SAVP without a usable line", "  srtp: optional\n", func(t *testing.T, p int) string { return sdesUnusableBody(p) }, 488, false},
		{"required refuses SAVP without a usable line", "  srtp: required\n", func(t *testing.T, p int) string { return sdesUnusableBody(p) }, 488, false},
		{"off ignores crypto", "", func(t *testing.T, p int) string {
			return sdesBody(t, p, mustCrypto(t, 1, sdp.SuiteAESCM128HMACSHA180))
		}, 200, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newSDESRig(t, streamOpts{tls: true, edgeExtra: tc.extra}, "tls")
			peer := newSDESPeer(t)
			inv, res := r.invite(t, tc.body(t, peer.port()))
			if res.StatusCode != tc.want {
				t.Fatalf("INVITE: got %d, want %d", res.StatusCode, tc.want)
			}
			if tc.want != 200 {
				if n := len(r.h.fs.received(sip.INVITE)); n != 0 {
					t.Errorf("a refused offer still reached the switch (%d INVITEs)", n)
				}
				waitForRelease(t, r.h)
				return
			}
			requirePlainSwitchBody(t, r.fsOffer(t, 1).Body())
			ans := mustParseBody(t, res.Body()).Audio
			if ans.SDES() != tc.wantSDES || (len(ans.Crypto) > 0) != tc.wantSDES {
				t.Errorf("answer SDES = %v (%d lines), want %v:\n%s", ans.SDES(), len(ans.Crypto), tc.wantSDES, res.Body())
			}
			r.hangUp(t, inv, res)
		})
	}
}

// SDES keys travel in SDP, so a client whose signaling is not TLS gets SDES
// only with edge.allow_insecure_sdes.
func TestSDESInsecureTransport(t *testing.T) {
	good := func(t *testing.T, port int) (string, sdp.Crypto) {
		c := mustCrypto(t, 1, sdp.SuiteAESCM128HMACSHA180)
		return sdesBody(t, port, c), c
	}
	t.Run("optional over UDP is plain", func(t *testing.T) {
		r := newSDESRig(t, streamOpts{edgeExtra: "  srtp: optional\n"}, "udp")
		peer := newSDESPeer(t)
		body, _ := good(t, peer.port())
		inv, res := r.invite(t, body)
		if res.StatusCode != 200 {
			t.Fatalf("INVITE: %d", res.StatusCode)
		}
		requirePlainSwitchBody(t, r.fsOffer(t, 1).Body())
		if a := mustParseBody(t, res.Body()).Audio; a.SDES() || len(a.Crypto) != 0 {
			t.Errorf("SDES was used over UDP without allow_insecure_sdes:\n%s", res.Body())
		}
		r.hangUp(t, inv, res)
	})
	t.Run("required over UDP is refused, plain or SAVP", func(t *testing.T) {
		r := newSDESRig(t, streamOpts{edgeExtra: "  srtp: required\n"}, "udp")
		peer := newSDESPeer(t)
		body, _ := good(t, peer.port())
		for _, b := range []string{body, phoneOfferSDP(peer.port())} {
			_, res := r.invite(t, b)
			if res.StatusCode != 488 {
				t.Errorf("INVITE: got %d, want 488", res.StatusCode)
			}
		}
		if n := len(r.h.fs.received(sip.INVITE)); n != 0 {
			t.Errorf("a refused offer reached the switch (%d INVITEs)", n)
		}
		waitForRelease(t, r.h)
	})
	t.Run("allow_insecure_sdes over UDP works", func(t *testing.T) {
		r := newSDESRig(t, streamOpts{edgeExtra: "  srtp: optional\n  allow_insecure_sdes: true\n"}, "udp")
		peer := newSDESPeer(t)
		body, own := good(t, peer.port())
		inv, res := r.invite(t, body)
		if res.StatusCode != 200 {
			t.Fatalf("INVITE: %d", res.StatusCode)
		}
		up := requirePlainSwitchBody(t, r.fsOffer(t, 1).Body())
		fsbc := requireSAVPAnswer(t, res.Body(), own)
		peer.keys(t, own, fsbc)
		peer.toSwitch(t, mustParseBody(t, res.Body()).Audio.Port, r.fs, "udp-up")
		peer.fromSwitch(t, up.Audio.Port, r.fs, "udp-down")
		r.hangUp(t, inv, res)
	})
}

// registeredRuri is the Request-URI the switch uses to call the client
// registered as 1001.
func registeredRuri(t *testing.T, h *harness) sip.Uri {
	t.Helper()
	stored := h.fs.contacts()
	if len(stored) == 0 {
		t.Fatal("nothing registered upstream")
	}
	var ruri sip.Uri
	if err := sip.ParseUri(stored[0], &ruri); err != nil {
		t.Fatal(err)
	}
	return ruri
}

// answerWith makes the phone answer a switch call: mode "savp" selects the
// first offered line (and records the offer and the phone's key on got),
// "plain" answers RTP/AVP.
type phoneAnswer struct {
	offer *sdp.Session
	own   sdp.Crypto
}

func (r *sdesRig) answerCalls(t *testing.T, mode string, peerPort int) chan phoneAnswer {
	got := make(chan phoneAnswer, 4)
	r.phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		offer, err := parseLabSDP(req.Body())
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		pa := phoneAnswer{offer: offer}
		var lines []sdp.Crypto
		if mode == "savp" && len(offer.Audio.Crypto) > 0 {
			sel := offer.Audio.Crypto[0]
			c, err := sdp.NewCrypto(sel.Tag, sel.Suite)
			if err != nil {
				t.Error(err)
			}
			pa.own, lines = c, []sdp.Crypto{c}
		}
		base, _ := parseLabSDP([]byte(phoneOfferSDP(peerPort)))
		body, err := sdp.Build{Address: netip.MustParseAddr("127.0.0.1"), Port: peerPort, Codecs: base.Audio.Codecs,
			Crypto: lines, SessionID: 2, SessionVersion: 2}.Marshal()
		if err != nil {
			t.Error(err)
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", body)
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		got <- pa
		_ = tx.Respond(res)
	})
	return got
}

func waitInboundMethod(t *testing.T, c *client, m sip.RequestMethod) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case req := <-c.inbound:
			if req.Method == m {
				return
			}
		case <-deadline:
			t.Fatalf("the phone never received a %s", m)
		}
	}
}

// A call from the switch to a client under "required": FreeSBC offers
// RTP/SAVP with a line per suite, the client answers SRTP and media flows;
// a plain answer fails the call (the 2xx is ACKed and BYEd, the switch gets
// 488). Under "optional" a plain answer is accepted.
func TestSDESSwitchToClient(t *testing.T) {
	t.Run("required, SRTP answer", func(t *testing.T) {
		r := newSDESRig(t, streamOpts{tls: true, edgeExtra: "  srtp: required\n"}, "tls")
		peer := newSDESPeer(t)
		got := r.answerCalls(t, "savp", peer.port())
		res := r.h.fs.call(t, registeredRuri(t, r.h), r.h.privateSIP, phoneOfferSDP(r.h.fs.rtpPort))
		if res.StatusCode != 200 {
			t.Fatalf("switch INVITE: %d", res.StatusCode)
		}
		pa := <-got
		a := pa.offer.Audio
		if !a.SDES() || len(a.Crypto) != len(sdp.SupportedSuites) || a.RTCPMux {
			t.Fatalf("offer to the client: SDES=%v lines=%d mux=%v, want SAVP with %d lines and no rtcp-mux",
				a.SDES(), len(a.Crypto), a.RTCPMux, len(sdp.SupportedSuites))
		}
		down := requirePlainSwitchBody(t, res.Body())
		peer.keys(t, pa.own, a.Crypto[0])
		peer.toSwitch(t, a.Port, r.fs, "up")
		peer.fromSwitch(t, down.Audio.Port, r.fs, "down")
		if bye := r.h.fs.uacBye(t, res); bye.StatusCode != 200 {
			t.Errorf("BYE: %d", bye.StatusCode)
		}
		waitForRelease(t, r.h)
	})
	t.Run("required, plain answer fails the call", func(t *testing.T) {
		r := newSDESRig(t, streamOpts{tls: true, edgeExtra: "  srtp: required\n"}, "tls")
		peer := newSDESPeer(t)
		got := r.answerCalls(t, "plain", peer.port())
		res := r.h.fs.call(t, registeredRuri(t, r.h), r.h.privateSIP, phoneOfferSDP(r.h.fs.rtpPort))
		if res.StatusCode != 488 {
			t.Fatalf("switch INVITE: got %d, want 488", res.StatusCode)
		}
		<-got
		waitInboundMethod(t, r.phone, sip.BYE) // the unusable 2xx is ACKed, then BYEd
		waitForRelease(t, r.h)
	})
	t.Run("optional, plain answer accepted", func(t *testing.T) {
		r := newSDESRig(t, streamOpts{tls: true, edgeExtra: "  srtp: optional\n"}, "tls")
		peer := newSDESPeer(t)
		got := r.answerCalls(t, "plain", peer.port())
		res := r.h.fs.call(t, registeredRuri(t, r.h), r.h.privateSIP, phoneOfferSDP(r.h.fs.rtpPort))
		if res.StatusCode != 200 {
			t.Fatalf("switch INVITE: got %d, want 200", res.StatusCode)
		}
		if !(<-got).offer.Audio.SDES() {
			t.Error("optional must offer RTP/SAVP")
		}
		requirePlainSwitchBody(t, res.Body())
		if bye := r.h.fs.uacBye(t, res); bye.StatusCode != 200 {
			t.Errorf("BYE: %d", bye.StatusCode)
		}
		waitForRelease(t, r.h)
	})
}

// A call from the switch to a TLS carrier with srtp: required.
func TestSDESCarrierTLSRequired(t *testing.T) {
	run := func(t *testing.T, savp bool) (*streamRig, *sdesPeer, chan *sip.Request, chan sdp.Crypto) {
		pki := newTestPKI(t)
		srv := pki.issue(false, nil, "127.0.0.1")
		rig := startStreamRig(t, streamRigOpts{transport: "tls", serverConf: tlsServerConf(srv),
			extra: fmt.Sprintf(", ca_file: %q, srtp: required", pki.caFile())})
		peer := newSDESPeerOn(t, rig.carrier.rtpPort)
		invs, keys := make(chan *sip.Request, 2), make(chan sdp.Crypto, 2)
		rig.carrier.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
			if req.Method != sip.INVITE {
				rig.carrier.answer(req, tx)
				return
			}
			offer, err := parseLabSDP(req.Body())
			if err != nil {
				t.Error(err)
				return
			}
			var lines []sdp.Crypto
			var own sdp.Crypto
			if savp && len(offer.Audio.Crypto) > 0 {
				sel := offer.Audio.Crypto[0]
				own = mustCrypto(t, sel.Tag, sel.Suite)
				lines = []sdp.Crypto{own}
			}
			base, _ := parseLabSDP([]byte(phoneOfferSDP(rig.carrier.rtpPort)))
			body, err := sdp.Build{Address: netip.MustParseAddr("127.0.0.1"), Port: rig.carrier.rtpPort,
				Codecs: base.Audio.Codecs, Crypto: lines, SessionID: 3, SessionVersion: 3}.Marshal()
			if err != nil {
				t.Error(err)
				return
			}
			res := sip.NewResponseFromRequest(req, 200, "OK", body)
			res.To().Params.Add("tag", sip.GenerateTagN(12))
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			res.AppendHeader(&sip.ContactHeader{Address: rig.carrier.contact()})
			invs <- req.Clone()
			keys <- own
			_ = tx.Respond(res)
		})
		return rig, peer, invs, keys
	}

	t.Run("SRTP answer", func(t *testing.T) {
		rig, peer, invs, keys := run(t, true)
		fsConn := fsMediaSocket(t, rig.fs.rtpPort)
		res := rig.fs.call(t, rig.ruri("+442071234567", "127.0.0.1"), rig.privateSIP, phoneOfferSDP(rig.fs.rtpPort))
		if res.StatusCode != 200 {
			t.Fatalf("switch INVITE to the carrier: %d", res.StatusCode)
		}
		inv, own := <-invs, <-keys
		offer := mustParseBody(t, inv.Body()).Audio
		if !offer.SDES() || len(offer.Crypto) != len(sdp.SupportedSuites) || offer.RTCPMux {
			t.Fatalf("offer to the carrier is not SAVP with %d lines and no rtcp-mux:\n%s", len(sdp.SupportedSuites), inv.Body())
		}
		down := requirePlainSwitchBody(t, res.Body())
		peer.keys(t, own, offer.Crypto[0])
		peer.toSwitch(t, offer.Port, fsConn, "carrier-up")
		peer.fromSwitch(t, down.Audio.Port, fsConn, "carrier-down")
		rig.fs.sendAckTo2xx(t, res)
		if bye := rig.fs.uacBye(t, res); bye.StatusCode != 200 {
			t.Fatalf("BYE: %d", bye.StatusCode)
		}
		waitForRelease(t, rig.harness)
	})
	t.Run("plain answer fails the call", func(t *testing.T) {
		rig, _, invs, _ := run(t, false)
		res := rig.fs.call(t, rig.ruri("+442071234567", "127.0.0.1"), rig.privateSIP, phoneOfferSDP(rig.fs.rtpPort))
		if res.StatusCode != 488 {
			t.Fatalf("switch INVITE to the carrier: got %d, want 488", res.StatusCode)
		}
		<-invs
		rig.carrier.waitInbound(t, sip.BYE)
		waitForRelease(t, rig.harness)
	})
}

// phoneReInvite sends a re-INVITE inside an established call.
func phoneReInvite(t *testing.T, r *sdesRig, inv *sip.Request, res *sip.Response, cseq uint32, body string) *sip.Response {
	t.Helper()
	re := sip.NewRequest(sip.INVITE, inv.Recipient)
	sip.CopyHeaders("From", inv, re)
	sip.CopyHeaders("Call-ID", inv, re)
	re.AppendHeader(sip.HeaderClone(res.To()))
	re.AppendHeader(&sip.CSeqHeader{SeqNo: cseq, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	re.AppendHeader(&mf)
	re.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
	re.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: strings.ToUpper(r.phone.transport),
		Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	re.PrependHeader(via)
	copyRouteFromRecordRoute(res, re)
	re.SetBody([]byte(body))
	return r.phone.do(t, re, r.dest)
}

// Re-INVITE on an SRTP leg: the same crypto keeps the state and FreeSBC
// repeats its key; a new key re-keys without moving the ports; an offer
// that drops SRTP is refused and the keys in force keep working.
func TestSDESReInvite(t *testing.T) {
	r := newSDESRig(t, streamOpts{tls: true, edgeExtra: "  srtp: optional\n"}, "tls")
	peer := newSDESPeer(t)
	own1 := mustCrypto(t, 1, sdp.SuiteAESCM128HMACSHA180)
	inv, res := r.invite(t, sdesBody(t, peer.port(), own1))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	up := requirePlainSwitchBody(t, r.fsOffer(t, 1).Body())
	fsbc1 := requireSAVPAnswer(t, res.Body(), own1)
	pub := mustParseBody(t, res.Body()).Audio.Port
	peer.keys(t, own1, fsbc1)
	peer.toSwitch(t, pub, r.fs, "call-start")
	sendAck(t, r.phone, inv, res, r.dest)

	// 1. Same crypto line: nothing is re-keyed.
	r1 := phoneReInvite(t, r, inv, res, 2, sdesBody(t, peer.port(), own1))
	if r1.StatusCode != 200 {
		t.Fatalf("re-INVITE (same key): %d", r1.StatusCode)
	}
	fsbc2 := requireSAVPAnswer(t, r1.Body(), own1)
	if !fsbc2.SameKey(fsbc1) {
		t.Error("FreeSBC changed its own key in the answer to an unchanged re-offer")
	}
	if got := mustParseBody(t, r1.Body()).Audio.Port; got != pub {
		t.Errorf("re-INVITE moved the public port %d -> %d", pub, got)
	}
	if body := r.fsOffer(t, 2).Body(); strings.Contains(string(body), "crypto") {
		t.Errorf("re-offer toward the switch carries crypto:\n%s", body)
	}
	peer.toSwitch(t, pub, r.fs, "same-key")
	peer.fromSwitch(t, up.Audio.Port, r.fs, "same-key-down")
	sendAck(t, r.phone, bumpCSeq(inv, 2), r1, r.dest)

	// 2. A new key re-keys in place: ports and the other leg are untouched.
	oldEnc := peer.enc
	own2 := mustCrypto(t, 1, sdp.SuiteAESCM128HMACSHA180)
	r2 := phoneReInvite(t, r, inv, res, 3, sdesBody(t, peer.port(), own2))
	if r2.StatusCode != 200 {
		t.Fatalf("re-INVITE (new key): %d", r2.StatusCode)
	}
	fsbc3 := requireSAVPAnswer(t, r2.Body(), own2)
	if got := mustParseBody(t, r2.Body()).Audio.Port; got != pub {
		t.Errorf("re-keying moved the public port %d -> %d", pub, got)
	}
	sendAck(t, r.phone, bumpCSeq(inv, 3), r2, r.dest)
	peer.keys(t, own2, fsbc3)
	peer.toSwitch(t, pub, r.fs, "new-key")
	peer.fromSwitch(t, up.Audio.Port, r.fs, "new-key-down")
	oldEnc2, _ := oldEnc.EncryptRTP(nil, rtpOf(60000, "old-key"), nil)
	_, _ = peer.conn.WriteToUDP(oldEnc2, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pub})
	if raw, ok := readUDP(r.fs, 300*time.Millisecond); ok {
		if got, _ := payloadOfRTP(raw); got == "old-key" {
			t.Error("a packet under the replaced key still reached the switch")
		}
	}

	// 3. Dropping SRTP, or offering no usable line, is refused; the keys in
	// force are not touched.
	for i, body := range []string{phoneOfferSDP(peer.port()), sdesUnusableBody(peer.port())} {
		if bad := phoneReInvite(t, r, inv, res, uint32(4+i), body); bad.StatusCode != 488 {
			t.Fatalf("re-INVITE that drops SRTP (%d): got %d, want 488", i, bad.StatusCode)
		}
	}
	peer.toSwitch(t, pub, r.fs, "after-refusal")
	peer.fromSwitch(t, up.Audio.Port, r.fs, "after-refusal-down")

	if bye := r.phone.do(t, buildBye(r.phone, bumpCSeq(inv, 5), res), r.dest); bye.StatusCode != 200 {
		t.Errorf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, r.h)
}

// bumpCSeq returns a copy of inv whose CSeq is n, for building the ACK or
// BYE of a later transaction.
func bumpCSeq(inv *sip.Request, n uint32) *sip.Request {
	c := inv.Clone()
	c.RemoveHeader("CSeq")
	c.AppendHeader(&sip.CSeqHeader{SeqNo: n - 1, MethodName: sip.INVITE})
	return c
}

// Key material is never logged: the edge's log handler rewrites it, and a
// whole call at debug level leaves no key in the log.
func TestSDESKeysNeverLogged(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	h := slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug})
	r := newSDESRig(t, streamOpts{tls: true, edgeExtra: "  srtp: optional\n", log: h}, "tls")
	peer := newSDESPeer(t)
	own := mustCrypto(t, 1, sdp.SuiteAESCM128HMACSHA180)
	inv, res := r.invite(t, sdesBody(t, peer.port(), own))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	fsbc := requireSAVPAnswer(t, res.Body(), own)
	r.hangUp(t, inv, res)
	// A body with an unusable first line is logged on its way through.
	inv2, bad := r.invite(t, strings.Replace(sdesBody(t, peer.port(), own), "a=crypto:", "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:KEYKEYKEYKEYKEYKEY\r\na=crypto:", 1))
	if bad.StatusCode == 200 {
		r.hangUp(t, inv2, bad)
	}

	mu.Lock()
	logs := buf.String()
	mu.Unlock()
	for _, c := range []sdp.Crypto{own, fsbc} {
		key := strings.TrimPrefix(c.Value(), fmt.Sprintf("%d %s inline:", c.Tag, c.Suite))
		if key != "" && strings.Contains(logs, key) {
			t.Errorf("a key (%s) was logged", c)
		}
	}
	if m := regexp.MustCompile(`inline:[^\[\s]`).FindString(logs); m != "" {
		t.Errorf("unredacted inline: key material in the log: %q", m)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestRedactHandler(t *testing.T) {
	const key = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
	line := "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + key + "|2^20"
	var mu sync.Mutex
	var buf bytes.Buffer
	log := slog.New(newRedactHandler(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log = log.With("pre", line)
	log.Warn("message "+line, "str", line, "err", fmt.Errorf("parse: %s", line),
		"group", slog.GroupValue(slog.String("inner", line)), "n", 7)
	log.WithGroup("g").Info("x", "str", line)

	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if strings.Contains(out, key) {
		t.Errorf("key leaked through the handler:\n%s", out)
	}
	if strings.Count(out, "inline:[redacted]") < 6 {
		t.Errorf("want every occurrence redacted:\n%s", out)
	}
	if !strings.Contains(out, "n=7") {
		t.Errorf("non-secret attributes must pass through:\n%s", out)
	}
	if got := sdp.RedactCrypto("v=0\r\nm=audio 1 RTP/AVP 0\r\n"); got != "v=0\r\nm=audio 1 RTP/AVP 0\r\n" {
		t.Errorf("RedactCrypto changed text without a key: %q", got)
	}
}
