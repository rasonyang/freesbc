package media

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
)

// These tests cover the offerer leg: FreeSBC offers DTLS-SRTP to a browser
// (a call FreeSWITCH places to a WebSocket client), so the browser's ICE
// credentials, DTLS role and fingerprint arrive only in its answer.

func newOffererLeg(t *testing.T, pool *PlanePool) *WebRTCLeg {
	t.Helper()
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	leg, err := NewWebRTCLeg(pool, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"),
		Offerer:      true,
		Identity:     id,
	})
	if err != nil {
		t.Fatalf("offerer leg without remote credentials refused: %v", err)
	}
	return leg
}

func TestWebRTCOffererLegSetup(t *testing.T) {
	pool := testPlanePool(t, "public", 21100, 21119)
	for setup, want := range map[string]string{
		"active":  "passive", // the browser is the DTLS client: we serve
		"":        "passive", // RFC 4145 §4: absent means active
		"passive": "active",  // the browser serves: we are the client
	} {
		leg := newOffererLeg(t, pool)
		if got := leg.DTLSSetup(); got != "actpass" {
			t.Errorf("offerer leg before the answer: setup %q, want actpass", got)
		}
		if err := leg.SetRemote(WebRTCRemote{Ufrag: "abcd", Pwd: "0123456789abcdef012345", Setup: setup}); err != nil {
			t.Fatalf("SetRemote(%q): %v", setup, err)
		}
		if got := leg.DTLSSetup(); got != want {
			t.Errorf("answer setup %q → %q, want %q", setup, got, want)
		}
		// Restating the same remote is a no-op; a different one is refused.
		if err := leg.SetRemote(WebRTCRemote{Ufrag: "abcd", Pwd: "0123456789abcdef012345", Setup: setup}); err != nil {
			t.Errorf("restated remote refused: %v", err)
		}
		if err := leg.SetRemote(WebRTCRemote{Ufrag: "wxyz", Pwd: "0123456789abcdef012345", Setup: setup}); !errors.Is(err, ErrRemoteMismatch) {
			t.Errorf("different remote: got %v, want ErrRemoteMismatch", err)
		}
		_ = leg.Close()
	}

	// An answer may not leave the role open, nor omit its credentials.
	leg := newOffererLeg(t, pool)
	for _, r := range []WebRTCRemote{
		{Ufrag: "abcd", Pwd: "0123456789abcdef012345", Setup: "actpass"},
		{Ufrag: "abcd", Pwd: "0123456789abcdef012345", Setup: "holdconn"},
		{Pwd: "0123456789abcdef012345", Setup: "active"},
		{Ufrag: "abcd", Pwd: "0123456789abcdef012345", Setup: "active", FingerprintHash: "sha-1", FingerprintValue: "AB"},
	} {
		if err := leg.SetRemote(r); err == nil {
			t.Errorf("SetRemote(%+v) accepted", r)
		}
	}
	if got := leg.DTLSSetup(); got != "actpass" {
		t.Errorf("a refused answer changed the setup to %q", got)
	}
	_ = leg.Close()

	// SetRemote is for offerer legs only.
	id, _ := ProcessDTLSIdentity()
	answerer, err := NewWebRTCLeg(pool, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
		RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := answerer.SetRemote(WebRTCRemote{Ufrag: "abcd", Pwd: "0123456789abcdef012345"}); err == nil {
		t.Error("SetRemote accepted on an answerer leg")
	}
	_ = answerer.Close()

	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("ports leaked: %d in use", inUse)
	}
}

// An offerer leg started before its answer has nothing to run ICE
// against: it must fail at once and give its port back, not hold it until
// the establishment deadline.
func TestWebRTCOffererLegStartWithoutAnswer(t *testing.T) {
	pool := testPlanePool(t, "public", 21120, 21129)
	leg := newOffererLeg(t, pool)
	leg.Start(context.Background(), 30*time.Second)
	select {
	case <-leg.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("leg started without an answer did not fail promptly")
	}
	if err := leg.Err(); !errors.Is(err, ErrICEFailed) {
		t.Errorf("Err = %v, want ErrICEFailed", err)
	}
	if err := leg.SetRemote(WebRTCRemote{Ufrag: "abcd", Pwd: "0123456789abcdef012345"}); err == nil {
		t.Error("SetRemote accepted after the leg failed")
	}
	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("ports leaked: %d in use", inUse)
	}
}

// TestWebRTCOffererSessionEndToEnd is TestWebRTCSessionEndToEnd with the
// offer/answer roles reversed: the leg is allocated with no remote, the
// "browser" answers (with each DTLS role an answer may take), SetRemote
// applies the answer, and only then does ICE/DTLS run and audio flow both
// ways.
func TestWebRTCOffererSessionEndToEnd(t *testing.T) {
	for i, setup := range []string{"active", "passive"} {
		t.Run(setup, func(t *testing.T) {
			base := 21140 + i*20
			pubPool := testPlanePool(t, "public", base, base+9)
			privPool := testPlanePool(t, "private", base+10, base+19)
			runOffererSession(t, pubPool, privPool, setup)
			if inUse, _ := pubPool.Stats(); inUse != 0 {
				t.Errorf("public ports leaked: %d", inUse)
			}
			if inUse, _ := privPool.Stats(); inUse != 0 {
				t.Errorf("private ports leaked: %d", inUse)
			}
		})
	}
}

func runOffererSession(t *testing.T, pubPool, privPool *PlanePool, setup string) {
	t.Helper()
	leg := newOffererLeg(t, pubPool)
	sess, err := NewWebRTCSession(leg, privPool, WebRTCSessionConfig{
		PrivateLatch: LatchStrict, Timeout: 30 * time.Second,
	})
	if err != nil {
		_ = leg.Close()
		t.Fatal(err)
	}
	defer sess.Close()

	fsConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer fsConn.Close()
	sess.SetPrivateRemote(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"),
		uint16(fsConn.LocalAddr().(*net.UDPAddr).Port)))

	// --- the browser receives the offer: our ufrag/pwd and host candidate ---
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelError
	browser, err := ice.NewAgentWithOptions(
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost}),
		ice.WithIncludeLoopback(),
		ice.WithLoggerFactory(lf),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	bUfrag, bPwd, err := browser.GetLocalUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	browserCert, err := selfSignedForTest()
	if err != nil {
		t.Fatal(err)
	}

	// --- the answer arrives ---
	if err := leg.SetRemote(WebRTCRemote{
		Ufrag: bUfrag, Pwd: bPwd, Setup: setup,
		FingerprintHash: "sha-256", FingerprintValue: fingerprintOf(browserCert),
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	leg.Start(ctx, 15*time.Second)

	lUfrag, lPwd := leg.LocalCredentials()
	cand, err := ice.NewCandidateHost(&ice.CandidateHostConfig{
		Network: "udp", Address: "127.0.0.1", Port: leg.Port(), Component: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := browser.AddRemoteCandidate(cand); err != nil {
		t.Fatal(err)
	}
	if err := browser.OnCandidate(func(ice.Candidate) {}); err != nil {
		t.Fatal(err)
	}
	if err := browser.GatherCandidates(); err != nil {
		t.Fatal(err)
	}
	// The browser is the full ICE agent, so it controls whichever side
	// offered.
	browserConn, err := browser.Dial(ctx, lUfrag, lPwd)
	if err != nil {
		t.Fatalf("browser ICE dial: %v", err)
	}
	defer browserConn.Close()

	bDemux := newDemux(browserConn)
	defer bDemux.Close()
	opts := []dtls.Option{
		dtls.WithCertificates(browserCert),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithInsecureSkipVerify(true),
	}
	var bDTLS *dtls.Conn
	browserIsClient := setup == "active"
	if browserIsClient {
		co := make([]dtls.ClientOption, 0, len(opts))
		for _, o := range opts {
			co = append(co, o)
		}
		bDTLS, err = dtls.ClientWithOptions(bDemux.dtls, bDemux.dtls.RemoteAddr(), co...)
	} else {
		so := make([]dtls.ServerOption, 0, len(opts)+1)
		for _, o := range opts {
			so = append(so, o)
		}
		so = append(so, dtls.WithClientAuth(dtls.RequireAnyClientCert))
		bDTLS, err = dtls.ServerWithOptions(bDemux.dtls, bDemux.dtls.RemoteAddr(), so...)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer bDTLS.Close()
	handshakeErr := make(chan error, 1)
	go func() { handshakeErr <- bDTLS.HandshakeContext(ctx) }()
	if err := sess.Start(ctx); err != nil {
		t.Fatalf("session start: %v", err)
	}
	if err := <-handshakeErr; err != nil {
		t.Fatalf("browser DTLS handshake: %v", err)
	}

	bState, ok := bDTLS.ConnectionState()
	if !ok {
		t.Fatal("browser has no DTLS state")
	}
	profile, _ := srtpProfileFor(dtls.SRTP_AES128_CM_HMAC_SHA1_80)
	keyLen, _ := profile.KeyLen()
	saltLen, _ := profile.SaltLen()
	m, err := bState.ExportKeyingMaterial(srtpExporterLabel, nil, keyLen*2+saltLen*2)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, serverKey := m[:keyLen], m[keyLen:keyLen*2]
	clientSalt, serverSalt := m[keyLen*2:keyLen*2+saltLen], m[keyLen*2+saltLen:]
	outKey, outSalt, inKey, inSalt := serverKey, serverSalt, clientKey, clientSalt
	if browserIsClient {
		outKey, outSalt, inKey, inSalt = clientKey, clientSalt, serverKey, serverSalt
	}
	browserOut, err := newSRTPContextFromKeys(profile, outKey, outSalt)
	if err != nil {
		t.Fatal(err)
	}
	browserIn, err := newSRTPContextFromKeys(profile, inKey, inSalt)
	if err != nil {
		t.Fatal(err)
	}

	// private → public
	privAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sess.PrivateRTPPort()}
	fsPacket := rtpPacket(0, 1000, 160)
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2000)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			_ = bDemux.srtp.SetReadDeadline(time.Now().Add(time.Second))
			n, err := bDemux.srtp.Read(buf)
			if err != nil {
				continue
			}
			if plain, ok := browserIn.unprotectRTP(buf[:n]); ok {
				got <- plain
				return
			}
		}
	}()
	heard := false
	for i := 0; i < 50 && !heard; i++ {
		if _, err := fsConn.WriteToUDP(fsPacket, privAddr); err != nil {
			t.Fatal(err)
		}
		select {
		case plain := <-got:
			if string(plain) != string(fsPacket) {
				t.Fatal("browser received an altered packet")
			}
			heard = true
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !heard {
		t.Fatal("private → public audio never reached the browser")
	}

	// public → private
	browserPacket := rtpPacket(0, 2000, 160)
	protected, ok := browserOut.protectRTP(browserPacket)
	if !ok {
		t.Fatal("browser could not protect its RTP")
	}
	if _, err := bDemux.srtp.Write(protected); err != nil {
		t.Fatal(err)
	}
	_ = fsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2000)
	n, _, err := fsConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("public → private audio never reached FreeSWITCH: %v", err)
	}
	if string(buf[:n]) != string(browserPacket) {
		t.Fatal("packet reached FreeSWITCH altered")
	}
	_ = sess.Close()
}
