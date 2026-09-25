package media

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
)

// testPlanePool builds a pool over an explicit port range bound to
// loopback, independent of any config file.
func testPlanePool(t *testing.T, name string, lo, hi int) *PlanePool {
	t.Helper()
	return NewPlanePool(name, func() PlaneParams {
		return PlaneParams{
			MinPort: uint16(lo),
			MaxPort: uint16(hi),
			BindIP:  netip.MustParseAddr("127.0.0.1"),
			Timeout: 30 * time.Second,
		}
	})
}

func TestDTLSIdentityFingerprint(t *testing.T) {
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if id.FingerprintHash != "sha-256" {
		t.Errorf("hash = %q", id.FingerprintHash)
	}
	parts := strings.Split(id.FingerprintValue, ":")
	if len(parts) != 32 {
		t.Fatalf("fingerprint has %d bytes, want 32: %q", len(parts), id.FingerprintValue)
	}
	for _, p := range parts {
		if len(p) != 2 || strings.ToUpper(p) != p {
			t.Fatalf("fingerprint byte %q is not uppercase hex", p)
		}
	}
	// The identity is process-wide: a second call must not regenerate it,
	// or every session would pay for an ECDSA keygen.
	again, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if again != id {
		t.Error("ProcessDTLSIdentity generated a second identity")
	}
}

func TestMuxClassify(t *testing.T) {
	cases := []struct {
		first byte
		want  muxKind
	}{
		{0x00, muxUnknown}, // STUN — consumed by ICE, never reaches the mux
		{0x01, muxUnknown},
		{0x14, muxDTLS}, // 20
		{0x16, muxDTLS}, // handshake
		{0x3f, muxDTLS}, // 63
		{0x40, muxUnknown},
		{0x80, muxSRTP}, // 128, RTP version 2
		{0xbf, muxSRTP}, // 191
		{0xc0, muxUnknown},
	}
	for _, c := range cases {
		if got := classify([]byte{c.first, 0, 0, 0}); got != c.want {
			t.Errorf("classify(%#x) = %v, want %v", c.first, got, c.want)
		}
	}
	if got := classify(nil); got != muxUnknown {
		t.Errorf("classify(nil) = %v", got)
	}
}

func TestIsRTCP(t *testing.T) {
	// RFC 5761 §4: payload types 64-95 in the second byte mark RTCP.
	if !isRTCP([]byte{0x80, 200}) { // SR
		t.Error("SR not classified as RTCP")
	}
	if !isRTCP([]byte{0x81, 201}) { // RR
		t.Error("RR not classified as RTCP")
	}
	if isRTCP([]byte{0x80, 0}) { // PCMU
		t.Error("PCMU classified as RTCP")
	}
	if isRTCP([]byte{0x80, 111}) { // opus dynamic PT
		t.Error("opus classified as RTCP")
	}
	if isRTCP([]byte{0x80}) {
		t.Error("short packet classified as RTCP")
	}
}

func TestICECredentialsShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		u, p, err := newICECredentials()
		if err != nil {
			t.Fatal(err)
		}
		// RFC 5245 §15.4 minimums: 4 ufrag chars, 22 password chars.
		if len(u) < 4 {
			t.Fatalf("ufrag %q too short", u)
		}
		if len(p) < 22 {
			t.Fatalf("pwd %q too short (%d)", p, len(p))
		}
		if seen[p] {
			t.Fatal("duplicate ICE password generated")
		}
		seen[p] = true
	}
}

func TestWebRTCLegNeedsRemoteCredentials(t *testing.T) {
	pool := testPlanePool(t, "public", 23400, 23419)
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewWebRTCLeg(pool, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
	}); err == nil {
		t.Fatal("leg built without remote ICE credentials")
	}
	// A failed construction must not leak the port it tried to take.
	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("ports leaked: %d in use", inUse)
	}
}

func TestWebRTCLegDTLSRole(t *testing.T) {
	pool := testPlanePool(t, "public", 23420, 23439)
	id, _ := ProcessDTLSIdentity()
	for setup, want := range map[string]string{
		"actpass": "passive", // the browser lets us choose: we take the server role
		"active":  "passive", // the browser will be the client
		"passive": "active",  // the browser insists on being the server
		"":        "passive",
	} {
		leg, err := NewWebRTCLeg(pool, WebRTCLegConfig{
			AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
			RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
			RemoteSetup: setup,
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := leg.DTLSSetup(); got != want {
			t.Errorf("setup %q → %q, want %q", setup, got, want)
		}
		_ = leg.Close()
	}
	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("ports leaked after Close: %d in use", inUse)
	}
}

// TestWebRTCLegOnWildcardBind proves the browser leg works when the media
// pool binds every interface (bind_ip: 0.0.0.0), which is the normal
// production shape.
//
// It is worth its own test because pion's UDPMuxDefault logs a warning on
// an unspecified local address and takes a different code path for
// gathering. FreeSBC does not use the gathered candidates — it advertises
// one host candidate at the configured public address — but the agent
// still has to accept connectivity checks on that socket, and this is what
// verifies it does.
func TestWebRTCLegOnWildcardBind(t *testing.T) {
	pubPool := NewPlanePool("public", func() PlaneParams {
		return PlaneParams{
			MinPort: 23300,
			MaxPort: 23339,
			BindIP:  netip.Addr{}, // every interface
			Timeout: 30 * time.Second,
		}
	})
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}

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

	leg, err := NewWebRTCLeg(pubPool, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"),
		RemoteUfrag:  bUfrag, RemotePwd: bPwd,
		RemoteSetup: "actpass", Identity: id,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer leg.Close()

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

	dialCh := make(chan error, 1)
	var browserConn *ice.Conn
	go func() {
		c, err := browser.Dial(ctx, lUfrag, lPwd)
		browserConn = c
		dialCh <- err
	}()

	browserCert, err := selfSignedForTest()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-dialCh:
		if err != nil {
			t.Fatalf("ICE against a wildcard-bound leg failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("ICE against a wildcard-bound leg timed out")
	}
	defer browserConn.Close()

	bDemux := newDemux(browserConn)
	defer bDemux.Close()
	bDTLS, err := dtls.ClientWithOptions(bDemux.dtls, bDemux.dtls.RemoteAddr(),
		dtls.WithCertificates(browserCert),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithInsecureSkipVerify(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := bDTLS.HandshakeContext(ctx); err != nil {
		t.Fatalf("DTLS against a wildcard-bound leg failed: %v", err)
	}
	if err := leg.Err(); err != nil {
		t.Fatalf("leg did not establish: %v", err)
	}
	if _, _, err := leg.SRTPContexts(); err != nil {
		t.Fatalf("SRTP not keyed: %v", err)
	}
}

// TestWebRTCSessionEndToEnd is the real thing: a full-ICE peer (standing
// in for a browser) does ICE against FreeSBC's ICE-Lite leg, completes a
// DTLS handshake, and then audio flows both ways — SRTP inbound decrypted
// to plain RTP on the private socket, plain RTP from the private side
// encrypted back out as SRTP.
//
// It covers acceptance criteria 5 and 6 at the media layer: ICE succeeds,
// DTLS succeeds, SRTP decrypt/encrypt succeeds, bidirectional audio flows.
func TestWebRTCSessionEndToEnd(t *testing.T) {
	pubPool := testPlanePool(t, "public", 23500, 23539)
	privPool := testPlanePool(t, "private", 23540, 23579)

	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// --- the "browser": a full ICE agent, controlling, DTLS client ---
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

	// The browser's DTLS certificate, and the a=fingerprint its offer
	// would carry: the leg checks it inside the handshake.
	browserCert, err := selfSignedForTest()
	if err != nil {
		t.Fatal(err)
	}
	leg, err := NewWebRTCLeg(pubPool, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"),
		RemoteUfrag:  bUfrag, RemotePwd: bPwd,
		RemoteSetup:            "actpass", // → FreeSBC is the DTLS server
		Identity:               id,
		RemoteFingerprintHash:  "sha-256",
		RemoteFingerprintValue: fingerprintOf(browserCert),
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewWebRTCSession(leg, privPool, WebRTCSessionConfig{
		PrivateLatch: LatchStrict, Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// The private side is FreeSWITCH: seed the latch with its media
	// address, as the signaling plane would from the upstream SDP answer.
	// The port is fsConn's, bound below; seeding is what lets the relay
	// send toward FreeSWITCH before FreeSWITCH has sent anything.
	fsConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer fsConn.Close()
	fsPort := fsConn.LocalAddr().(*net.UDPAddr).Port
	sess.SetPrivateRemote(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(fsPort)))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	leg.Start(ctx, 15*time.Second)

	// The browser learns our single host candidate from the SDP answer.
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

	type dialResult struct {
		conn *ice.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		c, err := browser.Dial(ctx, lUfrag, lPwd)
		dialCh <- dialResult{c, err}
	}()

	var browserConn *ice.Conn
	select {
	case r := <-dialCh:
		if r.err != nil {
			t.Fatalf("browser ICE dial: %v", r.err)
		}
		browserConn = r.conn
	case <-ctx.Done():
		t.Fatal("browser ICE dial timed out")
	}
	defer browserConn.Close()

	// The browser's DTLS client half, over its own ICE connection.
	bDemux := newDemux(browserConn)
	defer bDemux.Close()
	bDTLS, err := dtls.ClientWithOptions(bDemux.dtls, bDemux.dtls.RemoteAddr(),
		dtls.WithCertificates(browserCert),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithInsecureSkipVerify(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	handshakeErr := make(chan error, 1)
	go func() { handshakeErr <- bDTLS.HandshakeContext(ctx) }()

	if err := sess.Start(ctx); err != nil {
		t.Fatalf("session start: %v", err)
	}
	if err := <-handshakeErr; err != nil {
		t.Fatalf("browser DTLS handshake: %v", err)
	}

	// Both sides derive SRTP keys from the same handshake.
	bState, ok := bDTLS.ConnectionState()
	if !ok {
		t.Fatal("browser has no DTLS state")
	}
	profile, err := srtpProfileFor(dtls.SRTP_AES128_CM_HMAC_SHA1_80)
	if err != nil {
		t.Fatal(err)
	}
	keyLen, _ := profile.KeyLen()
	saltLen, _ := profile.SaltLen()
	material, err := bState.ExportKeyingMaterial(srtpExporterLabel, nil, keyLen*2+saltLen*2)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := material[:keyLen]
	serverKey := material[keyLen : keyLen*2]
	clientSalt := material[keyLen*2 : keyLen*2+saltLen]
	serverSalt := material[keyLen*2+saltLen:]
	// The browser is the DTLS client, so it writes with the client key and
	// reads with the server key — the mirror of what the leg derived.
	browserOut, err := newSRTPContextFromKeys(profile, clientKey, clientSalt)
	if err != nil {
		t.Fatal(err)
	}
	browserIn, err := newSRTPContextFromKeys(profile, serverKey, serverSalt)
	if err != nil {
		t.Fatal(err)
	}

	// fsConn (bound above) is FreeSWITCH's socket, talking plain RTP to
	// the session's private pair.
	privAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sess.PrivateRTPPort()}

	// --- private → public: FreeSWITCH speaks, the browser must hear it ---
	// The first private packet also latches the private side, which is
	// what lets the reverse direction find a destination.
	fsPacket := rtpPacket(0, 1000, 160)
	deadline := time.Now().Add(10 * time.Second)
	gotAtBrowser := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2000)
		for time.Now().Before(deadline) {
			_ = bDemux.srtp.SetReadDeadline(time.Now().Add(time.Second))
			n, err := bDemux.srtp.Read(buf)
			if err != nil {
				continue
			}
			if plain, ok := browserIn.unprotectRTP(buf[:n]); ok {
				gotAtBrowser <- plain
				return
			}
		}
	}()
	sent := false
	for time.Now().Before(deadline) {
		if _, err := fsConn.WriteToUDP(fsPacket, privAddr); err != nil {
			t.Fatal(err)
		}
		select {
		case plain := <-gotAtBrowser:
			if string(plain) != string(fsPacket) {
				t.Fatalf("browser received %d bytes, want the original %d", len(plain), len(fsPacket))
			}
			sent = true
		case <-time.After(200 * time.Millisecond):
			continue
		}
		break
	}
	if !sent {
		t.Fatal("private → public audio never reached the browser")
	}

	// --- public → private: the browser speaks, FreeSWITCH must hear it ---
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

	// The fingerprint the browser would have signalled must match the
	// certificate the handshake actually produced.
	fp := fingerprintOf(browserCert)
	if err := leg.VerifyFingerprint("sha-256", fp); err != nil {
		t.Errorf("fingerprint verification: %v", err)
	}
	if err := leg.VerifyFingerprint("sha-256", strings.Repeat("AB:", 31)+"AB"); err == nil {
		t.Error("a wrong fingerprint was accepted")
	}

	st := sess.Stats()
	if st.PublicRTPPacketsRx == 0 || st.PrivateRTPPacketsTx == 0 {
		t.Errorf("public→private counters not moving: %+v", st)
	}
	if st.PrivateRTPPacketsRx == 0 || st.PublicRTPPacketsTx == 0 {
		t.Errorf("private→public counters not moving: %+v", st)
	}
}

// TestWebRTCSessionCleanup proves Close releases every resource: both
// pools return to zero in use, so nothing leaks after a call ends.
func TestWebRTCSessionCleanup(t *testing.T) {
	pubPool := testPlanePool(t, "public", 23600, 23639)
	privPool := testPlanePool(t, "private", 23640, 23679)
	id, _ := ProcessDTLSIdentity()

	for i := 0; i < 5; i++ {
		leg, err := NewWebRTCLeg(pubPool, WebRTCLegConfig{
			AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
			RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
		})
		if err != nil {
			t.Fatal(err)
		}
		sess, err := NewWebRTCSession(leg, privPool, WebRTCSessionConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if inUse, _ := pubPool.Stats(); inUse != 1 {
			t.Fatalf("public in use = %d, want 1", inUse)
		}
		if err := sess.Close(); err != nil {
			t.Fatal(err)
		}
		// Close is idempotent.
		_ = sess.Close()
		if inUse, _ := pubPool.Stats(); inUse != 0 {
			t.Fatalf("public ports leaked: %d", inUse)
		}
		if inUse, _ := privPool.Stats(); inUse != 0 {
			t.Fatalf("private ports leaked: %d", inUse)
		}
		select {
		case <-sess.Done():
		default:
			t.Fatal("Done not closed after Close")
		}
	}
}

// A leg whose handshake never completes must not pin its port forever.
func TestWebRTCLegHandshakeTimeout(t *testing.T) {
	pool := testPlanePool(t, "public", 23700, 23719)
	id, _ := ProcessDTLSIdentity()
	leg, err := NewWebRTCLeg(pool, WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
		RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
	})
	if err != nil {
		t.Fatal(err)
	}
	leg.Start(context.Background(), 300*time.Millisecond)
	select {
	case <-leg.Ready():
	case <-time.After(10 * time.Second):
		t.Fatal("leg never gave up")
	}
	if leg.Err() == nil {
		t.Fatal("a leg nobody connected to reported success")
	}
	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("timed-out leg leaked its port: %d in use", inUse)
	}
}

func TestAllocateAcrossUsesBothPools(t *testing.T) {
	a := testPlanePool(t, "public", 23800, 23819)
	b := testPlanePool(t, "private", 23820, 23839)
	sess, err := AllocateAcross(a, b, SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if p := sess.RTPPort(SideA); p < 23800 || p > 23819 {
		t.Errorf("side A port %d outside the public range", p)
	}
	if p := sess.RTPPort(SideB); p < 23820 || p > 23839 {
		t.Errorf("side B port %d outside the private range", p)
	}
	if inUse, _ := a.Stats(); inUse != 1 {
		t.Errorf("public in use = %d", inUse)
	}
	if inUse, _ := b.Stats(); inUse != 1 {
		t.Errorf("private in use = %d", inUse)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*PlanePool{a, b} {
		if inUse, _ := p.Stats(); inUse != 0 {
			t.Errorf("%s leaked: %d in use", p.name, inUse)
		}
	}
}

// A failure allocating the SECOND side must release the first, or a
// congested private plane would slowly drain the public one.
func TestAllocateAcrossReleasesOnPartialFailure(t *testing.T) {
	a := testPlanePool(t, "public", 23900, 23919)
	full := testPlanePool(t, "private", 23920, 23921) // exactly one pair
	first, err := AllocateAcross(a, full, SessionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := AllocateAcross(a, full, SessionConfig{}); err == nil {
		t.Fatal("second allocation should have failed on the exhausted pool")
	}
	if inUse, _ := a.Stats(); inUse != 1 {
		t.Errorf("public pool leaked on partial failure: %d in use, want 1", inUse)
	}
}
