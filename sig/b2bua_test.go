package sig

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
	"github.com/pion/sdp/v3"

	"github.com/freesbc/freesbc/media"
)

// A known peer (loopback) with a route to a target that is NOT this peer,
// so onInvite identifies + routes but (in Task 5) rejects because the B-leg
// isn't implemented yet. Task 6 replaces the expected code with a real bridge.
const bridgeNoRouteCfg = `
listen:
  sip: [udp://127.0.0.1:45070]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: nomatch
    from: local-uac
    match: { to: "^999$" }
    to: [local-uac]
`

func TestBridgeRejectsUnroutableInvite(t *testing.T) {
	// Dialed number 111 matches no route (only ^999$ exists) → 404.
	startServer(t, 45070, bridgeNoRouteCfg)
	got := roundTrip(t, 45070, "INVITE", "b2bua-noroute-1", 3*time.Second, "SIP/2.0 404")
	if !strings.Contains(got, "SIP/2.0 404") {
		t.Fatalf("unroutable INVITE must get 404, got:\n%s", got)
	}
}

// --- Task 6: happy-path bridge, stub carrier UAS ---

// stubCarrier is a minimal sipgo UAS standing in for a carrier trunk. It
// answers every INVITE with 200 + a fixed SDP body via its own dialog
// cache (mirroring sig.Server's dialogSrv/dialogCli setup — see
// dialog_integration_test.go in the sipgo module for the canonical
// pattern), absorbs the ACK, and ends the dialog on BYE. offers delivers
// each inbound INVITE so the test can inspect the bridge's rewritten
// B-leg offer (destination number, media port); byeDone closes once the
// carrier's side of the dialog has ended.
type stubCarrier struct {
	dialogSrv *sipgo.DialogServerCache
	log       *slog.Logger
	answerSDP []byte
	earlySDP  []byte
	proceed   <-chan struct{}

	// finalStatus/finalReason (Task 8): when finalStatus is set and is not
	// a 2xx, the handler declines every INVITE with this status instead of
	// answering — simulates an unavailable carrier for the failover tests.
	finalStatus int
	finalReason string

	// digestChallenge/digestUser/digestPass (Task 8): when set, the handler
	// challenges any INVITE that doesn't carry a matching Authorization
	// header with a 401 + WWW-Authenticate built from digestChallenge, and
	// only proceeds to the normal answer path once the retried INVITE's
	// digest response verifies — the outbound-auth test's stub carrier.
	// The challenge is fixed (not rotated per attempt) so verifying a
	// retry's Authorization header doesn't require correlating it back to
	// a per-request nonce.
	digestChallenge *digest.Challenge
	digestUser      string
	digestPass      string

	offers  chan *sip.Request
	byeDone chan struct{}
}

// stubCarrierConfig carries the Task 7 early-media and Task 8
// failover/auth options for startStubCarrier; the zero value reproduces
// Task 6's immediate-200 behavior (no options passed at all). When
// earlySDP is set, the handler sends a 183 Session Progress with that body
// before the final answer; if proceed is also set, it then blocks on that
// channel so the test can synchronize RTP/assertion checks before allowing
// the final 200 to go out — proving the early media flowed strictly before
// the answer. When finalStatus is a non-2xx code, every INVITE is declined
// with it instead of answered. When digestUser is set, every INVITE
// lacking a valid Authorization header is first challenged with a 401.
type stubCarrierConfig struct {
	earlySDP []byte
	proceed  <-chan struct{}

	finalStatus int
	finalReason string

	digestUser string
	digestPass string
}

// startStubCarrier boots the stub UAS on addr (e.g. "127.0.0.1:45182") and
// returns once it is accepting packets. It follows the same bind-our-own-
// socket-and-close-from-a-watcher-goroutine pattern as Server.bindListener
// (see sig/server.go) to avoid sipgo's known shutdown-race in
// ListenAndServe. opts is optional (Task 7 early-media, Task 8
// failover/digest-auth config); omit it for Task 6's plain immediate-200
// stub.
func startStubCarrier(t *testing.T, addr string, answerSDP []byte, opts ...stubCarrierConfig) *stubCarrier {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("carrier addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("carrier port: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("carrier ua: %v", err)
	}
	t.Cleanup(func() { ua.Close() })
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatalf("carrier server: %v", err)
	}
	client, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatalf("carrier client: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	contact := sip.ContactHeader{Address: sip.Uri{Host: host, Port: port}}
	c := &stubCarrier{
		dialogSrv: sipgo.NewDialogServerCache(client, contact),
		log:       log,
		answerSDP: answerSDP,
		offers:    make(chan *sip.Request, 4),
		byeDone:   make(chan struct{}),
	}
	if len(opts) > 0 {
		c.earlySDP = opts[0].earlySDP
		c.proceed = opts[0].proceed
		c.finalStatus = opts[0].finalStatus
		c.finalReason = opts[0].finalReason
		c.digestUser = opts[0].digestUser
		c.digestPass = opts[0].digestPass
		if c.digestUser != "" {
			c.digestChallenge = &digest.Challenge{
				Realm:     "freesbc-test",
				Nonce:     "test-nonce-fixed",
				Algorithm: "MD5",
			}
		}
	}

	srv.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		dlg, err := c.dialogSrv.ReadInvite(req, tx)
		if err != nil {
			log.Error("carrier read invite", "err", err)
			return
		}
		select {
		case c.offers <- req:
		default:
		}

		if c.digestChallenge != nil && !c.digestAuthorized(req) {
			if err := dlg.Respond(401, "Unauthorized", nil,
				sip.NewHeader("WWW-Authenticate", c.digestChallenge.String())); err != nil {
				log.Error("carrier respond 401", "err", err)
			}
			return
		}

		if c.finalStatus != 0 && c.finalStatus/100 != 2 {
			if err := dlg.Respond(c.finalStatus, c.finalReason, nil); err != nil {
				log.Error("carrier respond final", "err", err)
			}
			return
		}

		if len(c.earlySDP) > 0 {
			if err := dlg.Respond(183, "Session Progress", c.earlySDP,
				sip.NewHeader("Content-Type", "application/sdp")); err != nil {
				log.Error("carrier respond early media", "err", err)
				return
			}
			if c.proceed != nil {
				<-c.proceed
			}
		}
		if err := dlg.RespondSDP(c.answerSDP); err != nil {
			log.Error("carrier respond sdp", "err", err)
			return
		}
		<-dlg.Context().Done()
		close(c.byeDone)
	})
	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		if err := c.dialogSrv.ReadAck(req, tx); err != nil {
			log.Debug("carrier ack", "err", err)
		}
	})
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		if err := c.dialogSrv.ReadBye(req, tx); err != nil {
			log.Debug("carrier bye", "err", err)
		}
	})

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("carrier resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("carrier listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { <-ctx.Done(); conn.Close() }()
	tl := srv.TransportLayer()
	go func() { _ = tl.ServeUDP(conn) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		probe, err := net.Dial("udp", addr)
		if err == nil {
			probe.Close()
			time.Sleep(50 * time.Millisecond)
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("stub carrier did not start")
	return nil
}

// digestAuthorized reports whether req carries an Authorization header
// whose digest response matches c.digestChallenge for c.digestUser/Pass —
// mirrors sipgo's own (unexported) DialogServerSession.authDigest, which
// isn't reachable from this package.
func (c *stubCarrier) digestAuthorized(req *sip.Request) bool {
	h := req.GetHeader("Authorization")
	if h == nil {
		return false
	}
	creds, err := digest.ParseCredentials(h.Value())
	if err != nil {
		return false
	}
	want, err := digest.Digest(c.digestChallenge, digest.Options{
		Method:   sip.INVITE.String(),
		URI:      req.Recipient.Addr(),
		Username: c.digestUser,
		Password: c.digestPass,
	})
	if err != nil {
		return false
	}
	return creds.Response == want.Response
}

// testSDPBody builds a minimal offer/answer SDP whose audio media points
// at 127.0.0.1:port.
func testSDPBody(port int) []byte {
	return []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"c=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=audio " + strconv.Itoa(port) + " RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n")
}

// sdpAudioPort extracts the first audio m= line's port.
func sdpAudioPort(t *testing.T, body []byte) int {
	t.Helper()
	var sd sdp.SessionDescription
	if err := sd.Unmarshal(body); err != nil {
		t.Fatalf("parse sdp: %v\n%s", err, body)
	}
	for _, md := range sd.MediaDescriptions {
		if md.MediaName.Media == "audio" {
			return md.MediaName.Port.Value
		}
	}
	t.Fatalf("no audio media in sdp:\n%s", body)
	return 0
}

// sendUntilReceived writes payload from src to dst repeatedly (real UDP
// loopback is timing-based) until it is read back on recv, or fails the
// test after 5s. Mirrors media/relay_test.go's pump helper.
func sendUntilReceived(t *testing.T, src *net.UDPConn, dst *net.UDPAddr, recv *net.UDPConn, payload string) {
	t.Helper()
	buf := make([]byte, 1500)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := src.WriteToUDP([]byte(payload), dst); err != nil {
			t.Fatalf("write %q: %v", payload, err)
		}
		_ = recv.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, _, err := recv.ReadFromUDP(buf)
		if err == nil && string(buf[:n]) == payload {
			return
		}
	}
	t.Fatalf("payload %q never forwarded (dst %s)", payload, dst)
}

// waitForActiveCalls polls Server.ActiveCalls() until it matches want or
// timeout elapses; teardown after BYE is asynchronous (onInvite's own
// goroutine unwinds its defers).
func waitForActiveCalls(t *testing.T, srv *Server, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if srv.ActiveCalls() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("active calls = %d, want %d", srv.ActiveCalls(), want)
}

// bridgeCallCfg routes local-uac → carrier with a media pool sized to
// exactly one session (two port pairs), so the port-release assertion at
// the end of TestBridgePlacesCallAndBridges is meaningful: a second
// Allocate only succeeds if the bridge actually freed the first session's
// ports on teardown.
const bridgeCallCfg = `
listen:
  sip: [udp://127.0.0.1:45180]
  media:
    port_range: 46180-46183
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45182
    # A carrier peer is only ever the SBC's outbound target in this test
    # (the SBC never receives a fresh request *from* it), so its
    # allowed_ips is never consulted for identify() — deliberately not
    # 127.0.0.1 so it can't tie-break ahead of local-uac (IdentifyPeer
    # picks the lexicographically-first peer whose allowed_ips matches;
    # "carrier" < "local-uac" and both loopback-testing peers would
    # otherwise collide on 127.0.0.1).
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgePlacesCallAndBridges is the milestone's crux: a real end-to-end
// call through the B2BUA. A sipgo UAC INVITEs the bridge; the bridge routes
// to "carrier" (a stub UAS answering with its own SDP pointing at a test-
// controlled RTP socket), bridges media between the two, and tears
// everything down cleanly on BYE. Timing-based over real UDP loopback:
// re-run once before treating a flake as failure.
func TestBridgePlacesCallAndBridges(t *testing.T) {
	// Bind the RTP sockets first so their ports are baked into the SDP
	// bodies both endpoints exchange.
	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45185})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrier := startStubCarrier(t, "127.0.0.1:45182", testSDPBody(echoRTPPort))
	srv := startServer(t, 45180, bridgeCallCfg)

	// --- UAC: place the call (sipgo as a client-side dialog user agent) ---
	uacUA, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("uac ua: %v", err)
	}
	defer uacUA.Close()
	uacClient, err := sipgo.NewClient(uacUA, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("uac client: %v", err)
	}
	defer uacClient.Close()
	// Empty Contact: the UAC runs no SIP server of its own (it never
	// receives requests, only responses to its own transactions), so
	// there is no host:port to advertise — matches sipgo's own
	// dialog_integration_test.go client-harness pattern.
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45180}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPPort))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()

	if err := sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("got status %d, want 200", sess.InviteResponse.StatusCode)
	}

	// The bridge must hide topology: the answer's media address is the
	// bridge's own public_ip and a port from its own media pool range,
	// never the carrier's echo socket or SIP port.
	answerBody := sess.InviteResponse.Body()
	answerIP, err := remoteMediaIP(answerBody)
	if err != nil {
		t.Fatalf("parse answer sdp: %v", err)
	}
	if answerIP.String() != "127.0.0.1" {
		t.Errorf("answer c= = %v, want bridge public_ip 127.0.0.1", answerIP)
	}
	sideAPort := sdpAudioPort(t, answerBody)
	if sideAPort < 46180 || sideAPort > 46183 {
		t.Errorf("answer m=audio port %d not in media pool range 46180-46183", sideAPort)
	}
	if sideAPort == echoRTPPort || sideAPort == 45182 {
		t.Errorf("answer m=audio port %d leaks carrier topology", sideAPort)
	}
	// c= can't differ from the carrier's here (both loopback 127.0.0.1), so
	// the port assertions above carry the real topology-hiding proof; this
	// additionally proves the bridge actually rewrote the SDP at all,
	// rather than passing the carrier's answer through untouched.
	if string(answerBody) == string(testSDPBody(echoRTPPort)) {
		t.Errorf("answer sdp is byte-identical to carrier's original answer; bridge did not rewrite it:\n%s", answerBody)
	}

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	// The bridge must have offered the carrier the *dialed* number
	// (topology-hidden number transform is identity here) and its own
	// rewritten media, not the UAC's.
	var carrierOffer *sip.Request
	select {
	case carrierOffer = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}
	if carrierOffer.Recipient.User != "5551234" {
		t.Errorf("carrier invite user = %q, want 5551234", carrierOffer.Recipient.User)
	}
	sideBPort := sdpAudioPort(t, carrierOffer.Body())
	if sideBPort < 46180 || sideBPort > 46183 || sideBPort == sideAPort {
		t.Errorf("b-leg offer m=audio port %d invalid (side A port %d)", sideBPort, sideAPort)
	}

	// --- RTP round trip ---
	sideAAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideAPort}
	sideBAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideBPort}

	// Side B's latch is loose (media_latch: loose on the carrier peer), so
	// any first packet arms it as the A→B relay target — send one before
	// asserting forwarding either direction.
	if _, err := echoRTP.WriteToUDP([]byte("arm-b"), sideBAddr); err != nil {
		t.Fatalf("arm side b: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	sendUntilReceived(t, uacRTP, sideAAddr, echoRTP, "ping-a-to-b")
	sendUntilReceived(t, echoRTP, sideBAddr, uacRTP, "pong-b-to-a")

	// --- teardown ---
	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}

	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE")
	}

	waitForActiveCalls(t, srv, 0, 3*time.Second)

	// The pool holds exactly one session's worth of ports
	// (46180-46183): a fresh Allocate only succeeds if the bridge
	// actually released them on teardown.
	s2, err := srv.pool.Allocate(media.SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("media ports not released after teardown: %v", err)
	}
	s2.Close()
}

// --- Task 7: early media (18x with SDP) ---

// earlyMediaCfg mirrors bridgeCallCfg on a disjoint port set (Task 7 gets
// its own SIP/media ports rather than sharing bridgeCallCfg's, since Go
// tests in this package run sequentially but each starts/stops its own
// listeners and media pool).
const earlyMediaCfg = `
listen:
  sip: [udp://127.0.0.1:45190]
  media:
    port_range: 46190-46193
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45192
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeEarlyMedia proves 18x-with-SDP early media flows before the
// final answer: the stub carrier sends 183 Session Progress + SDP (pointing
// at its echo socket), the test verifies the 183's SDP was rewritten to the
// bridge's own A-side port and that RTP actually flows end to end on that
// port, and only then lets the carrier send 200 OK — so the RTP check
// necessarily happens strictly before the final answer, not just before the
// test's own assertions on it. Timing-based over real UDP loopback for the
// RTP hop itself: re-run once before treating a flake as failure.
func TestBridgeEarlyMedia(t *testing.T) {
	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45195})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	// The carrier keeps the same media address across 183 and 200 (typical
	// early-media behavior), and is held after the 183 until the test
	// signals proceed — so its 200 provably cannot reach the UAC before
	// the RTP checks below run.
	echoSDP := testSDPBody(echoRTPPort)
	proceed := make(chan struct{})
	carrier := startStubCarrier(t, "127.0.0.1:45192", echoSDP, stubCarrierConfig{
		earlySDP: echoSDP,
		proceed:  proceed,
	})
	srv := startServer(t, 45190, earlyMediaCfg)

	uacUA, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("uac ua: %v", err)
	}
	defer uacUA.Close()
	uacClient, err := sipgo.NewClient(uacUA, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("uac client: %v", err)
	}
	defer uacClient.Close()
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45190}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPPort))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()

	var (
		early        *sip.Response
		earlySideA   int
		gotEarlyRTP  bool
		carrierOffer *sip.Request
	)
	err = sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{
		OnResponse: func(res *sip.Response) error {
			if !res.IsProvisional() {
				return nil // final response: handled after WaitAnswer returns.
			}
			if res.StatusCode != 183 {
				return nil
			}
			early = res

			// The B-leg offer (captured by the carrier when the bridge
			// placed the outbound INVITE) is already available by the time
			// any response — even a 183 — comes back.
			select {
			case carrierOffer = <-carrier.offers:
			case <-time.After(3 * time.Second):
				t.Fatal("carrier never received the B-leg INVITE")
			}

			earlyBody := res.Body()
			if len(earlyBody) == 0 {
				t.Fatal("183 carried no SDP body")
			}
			if string(earlyBody) == string(echoSDP) {
				t.Fatal("183 sdp is byte-identical to carrier's original; bridge did not rewrite it")
			}
			earlySideA = sdpAudioPort(t, earlyBody)
			if earlySideA < 46190 || earlySideA > 46193 {
				t.Fatalf("183 m=audio port %d not in media pool range 46190-46193", earlySideA)
			}
			sideBPort := sdpAudioPort(t, carrierOffer.Body())
			if sideBPort < 46190 || sideBPort > 46193 || sideBPort == earlySideA {
				t.Fatalf("b-leg offer m=audio port %d invalid (early side A port %d)", sideBPort, earlySideA)
			}

			// --- RTP round trip, strictly before the carrier is allowed
			// to send 200 (gated below by proceed). ---
			sideAAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: earlySideA}
			sideBAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideBPort}
			if _, err := echoRTP.WriteToUDP([]byte("arm-b"), sideBAddr); err != nil {
				t.Fatalf("arm side b: %v", err)
			}
			time.Sleep(150 * time.Millisecond)
			sendUntilReceived(t, uacRTP, sideAAddr, echoRTP, "early-ping-a-to-b")
			sendUntilReceived(t, echoRTP, sideBAddr, uacRTP, "early-pong-b-to-a")
			gotEarlyRTP = true

			close(proceed) // let the carrier send its 200 now.
			return nil
		},
	})
	if err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if early == nil {
		t.Fatal("never received a 183 provisional")
	}
	if !gotEarlyRTP {
		t.Fatal("early media RTP round trip never completed")
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("got status %d, want 200", sess.InviteResponse.StatusCode)
	}

	// The final answer must reuse the same session (and so the same A-side
	// port) that early media already armed and started — Start runs at
	// most once whichever path (18x or 2xx) reaches it first.
	finalBody := sess.InviteResponse.Body()
	finalSideA := sdpAudioPort(t, finalBody)
	if finalSideA != earlySideA {
		t.Errorf("final answer m=audio port %d != early media port %d; session was re-armed on a different pair", finalSideA, earlySideA)
	}

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	// --- teardown ---
	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}

	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE")
	}

	waitForActiveCalls(t, srv, 0, 3*time.Second)

	s2, err := srv.pool.Allocate(media.SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("media ports not released after teardown: %v", err)
	}
	s2.Close()
}

// --- Task 8: B-leg failover across targets + outbound digest auth ---

// failoverCfg routes local-uac to two carriers, in failover order:
// carrier-a (always declines with 503) then carrier-b (answers normally).
// allowed_ips deliberately differ across all three peers and from
// 127.0.0.1 — see bridgeCallCfg's comment on why (IdentifyPeer's
// lexicographic tie-break on 127.0.0.1 would otherwise pick the wrong
// peer). Ports are a disjoint slice of the 45180-45199/46xxx blocks from
// Tasks 6/7's bridgeCallCfg (45180/45182/45185, 46180-46183) and
// earlyMediaCfg (45190/45192/45195, 46190-46193).
const failoverCfg = `
listen:
  sip: [udp://127.0.0.1:45181]
  media:
    port_range: 46200-46203
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier-a:
    address: 127.0.0.1:45183
    allowed_ips: [203.0.113.0/24]
  carrier-b:
    address: 127.0.0.1:45184
    allowed_ips: [198.51.100.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier-a, carrier-b]
`

// TestBridgeFailoverToSecondTarget proves the B2BUA walks decision.Targets
// in order: carrier-a always declines with 503, so the bridge must retry
// carrier-b, which answers — the UAC sees a 200 (not carrier-a's 503) and
// media bridges to carrier-b's echo socket, never carrier-a's. Timing-based
// over real UDP loopback: re-run once before treating a flake as failure.
func TestBridgeFailoverToSecondTarget(t *testing.T) {
	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45186})
	if err != nil {
		t.Fatalf("carrier-b echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrierA := startStubCarrier(t, "127.0.0.1:45183", nil, stubCarrierConfig{
		finalStatus: 503,
		finalReason: "Service Unavailable",
	})
	carrierB := startStubCarrier(t, "127.0.0.1:45184", testSDPBody(echoRTPPort))
	srv := startServer(t, 45181, failoverCfg)

	uacUA, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("uac ua: %v", err)
	}
	defer uacUA.Close()
	uacClient, err := sipgo.NewClient(uacUA, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("uac client: %v", err)
	}
	defer uacClient.Close()
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45181}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPPort))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()

	if err := sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("got status %d, want 200 (carrier-b should have answered after carrier-a's 503)", sess.InviteResponse.StatusCode)
	}

	// Both carriers must have been tried, in order.
	select {
	case <-carrierA.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-a never received the B-leg INVITE")
	}
	var carrierBOffer *sip.Request
	select {
	case carrierBOffer = <-carrierB.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-b never received the B-leg INVITE")
	}

	answerBody := sess.InviteResponse.Body()
	sideAPort := sdpAudioPort(t, answerBody)
	if sideAPort < 46200 || sideAPort > 46203 {
		t.Errorf("answer m=audio port %d not in media pool range 46200-46203", sideAPort)
	}
	sideBPort := sdpAudioPort(t, carrierBOffer.Body())
	if sideBPort < 46200 || sideBPort > 46203 || sideBPort == sideAPort {
		t.Errorf("b-leg offer m=audio port %d invalid (side A port %d)", sideBPort, sideAPort)
	}

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	// --- RTP round trip against carrier-b's echo socket ---
	sideAAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideAPort}
	sideBAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideBPort}
	if _, err := echoRTP.WriteToUDP([]byte("arm-b"), sideBAddr); err != nil {
		t.Fatalf("arm side b: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	sendUntilReceived(t, uacRTP, sideAAddr, echoRTP, "ping-a-to-b")
	sendUntilReceived(t, echoRTP, sideBAddr, uacRTP, "pong-b-to-a")

	// --- teardown ---
	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}
	select {
	case <-carrierB.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-b dialog never ended after BYE")
	}

	waitForActiveCalls(t, srv, 0, 3*time.Second)

	s2, err := srv.pool.Allocate(media.SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("media ports not released after teardown: %v", err)
	}
	s2.Close()
}

// allFailCfg routes local-uac to two carriers that both always decline —
// proves the failover loop exhausts every target and gives up, rather than
// looping forever or leaving the A-leg unanswered.
const allFailCfg = `
listen:
  sip: [udp://127.0.0.1:45187]
  media:
    port_range: 46210-46213
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier-a:
    address: 127.0.0.1:45188
    allowed_ips: [203.0.113.4/30]
  carrier-b:
    address: 127.0.0.1:45189
    allowed_ips: [203.0.113.8/30]
routes:
  - name: out
    from: local-uac
    to: [carrier-a, carrier-b]
`

// uacRTPStubPort binds a throwaway UDP socket, closes it immediately, and
// returns its port — TestBridgeAllTargetsFail and TestBridgeDigestAuth's
// A-leg offer just need a syntactically valid port for the m= line, not a
// live socket (no A-side media flows in the all-fail case; the digest-auth
// case doesn't assert on A-side RTP).
func uacRTPStubPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp stub socket: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestBridgeAllTargetsFail proves that when every target in decision.
// Targets fails, the B2BUA gives the caller the last upstream final code
// (both carriers answer 503 here) rather than hanging or answering
// success, and that it still releases the media session it allocated even
// though the call never bridged.
func TestBridgeAllTargetsFail(t *testing.T) {
	carrierA := startStubCarrier(t, "127.0.0.1:45188", nil, stubCarrierConfig{
		finalStatus: 503,
		finalReason: "Service Unavailable",
	})
	carrierB := startStubCarrier(t, "127.0.0.1:45189", nil, stubCarrierConfig{
		finalStatus: 503,
		finalReason: "Service Unavailable",
	})
	srv := startServer(t, 45187, allFailCfg)

	uacUA, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("uac ua: %v", err)
	}
	defer uacUA.Close()
	uacClient, err := sipgo.NewClient(uacUA, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("uac client: %v", err)
	}
	defer uacClient.Close()
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45187}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPStubPort(t)))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()

	err = sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{})
	if err == nil {
		t.Fatalf("uac wait answer: expected failure, got success (status %d)", sess.InviteResponse.StatusCode)
	}
	if sess.InviteResponse == nil {
		t.Fatalf("uac never received a final response: %v", err)
	}
	if sess.InviteResponse.StatusCode != 503 {
		t.Errorf("got status %d, want 503 (last upstream final code)", sess.InviteResponse.StatusCode)
	}

	select {
	case <-carrierA.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-a never received the B-leg INVITE")
	}
	select {
	case <-carrierB.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-b never received the B-leg INVITE")
	}

	// The call never bridged, so it was never added to the registry.
	if got := srv.ActiveCalls(); got != 0 {
		t.Errorf("active calls = %d, want 0 (call never bridged)", got)
	}

	// The media session allocated in onInvite before the loop must still be
	// released on total failure; onInvite's own goroutine unwinds its
	// defers asynchronously to this test, so retry briefly.
	var (
		s2       *media.Session
		allocErr error
	)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s2, allocErr = srv.pool.Allocate(media.SessionConfig{Timeout: time.Minute})
		if allocErr == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if allocErr != nil {
		t.Fatalf("media ports not released after teardown: %v", allocErr)
	}
	s2.Close()
}

// ringNoFinalCfg routes local-uac to a single carrier that floods
// provisionals and never sends a final response — see
// startFloodingRingCarrier and TestBridgeStaleProvisionalNotRelayedAsFinal
// (Finding 1: a stale 1xx must never be relayed to the caller as a
// fabricated final response).
const ringNoFinalCfg = `
listen:
  sip: [udp://127.0.0.1:45250]
  media:
    port_range: 46250-46253
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45251
    allowed_ips: [203.0.113.0/24]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// startFloodingRingCarrier boots a stub UAS that answers every INVITE with
// twelve back-to-back 180 Ringing provisionals and then goes silent forever
// — never a final response. This deterministically reproduces Finding 1's
// "transaction dies mid-ring" precondition without depending on any
// transport-level failure-detection behavior (sipgo's connection-close
// termination is opt-in and not enabled by sig.Server): sipgo's own
// DialogClientSession.WaitAnswer hard-caps itself at 10 responses
// ("more than 10 responses received", see WaitAnswer's `if i > 10` check in
// github.com/emiago/sipgo@v1.4.3/dialog_client.go) and returns a plain
// error once the 11th response arrives — while
// DialogClientSession.InviteResponse is left holding that response, a 180.
// That is exactly the stale-provisional-on-error state Finding 1 guards
// against, reached here via ordinary, in-spec SIP messaging rather than
// synthetic transport failures.
func startFloodingRingCarrier(t *testing.T, addr string) *stubCarrier {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("carrier addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("carrier port: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("carrier ua: %v", err)
	}
	t.Cleanup(func() { ua.Close() })
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatalf("carrier server: %v", err)
	}
	client, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatalf("carrier client: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	contact := sip.ContactHeader{Address: sip.Uri{Host: host, Port: port}}
	c := &stubCarrier{
		dialogSrv: sipgo.NewDialogServerCache(client, contact),
		log:       log,
		offers:    make(chan *sip.Request, 4),
		byeDone:   make(chan struct{}),
	}

	srv.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		dlg, err := c.dialogSrv.ReadInvite(req, tx)
		if err != nil {
			log.Error("carrier read invite", "err", err)
			return
		}
		select {
		case c.offers <- req:
		default:
		}
		// WaitAnswer's own loop receives responses for i=0..10 (11 total)
		// before its `i > 10` cap trips on the 12th iteration — so 11
		// provisionals is exactly enough to drive that path deterministically
		// without leaving any additional, never-read response sitting in the
		// client transaction's channel.
		for i := 0; i < 11; i++ {
			if err := dlg.Respond(180, "Ringing", nil); err != nil {
				log.Error("carrier respond 180", "err", err, "i", i)
				return
			}
		}
		// Never send a final response: the B-leg client transaction is left
		// ringing forever from the carrier's side.
	})

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("carrier resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("carrier listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { <-ctx.Done(); conn.Close() }()
	tl := srv.TransportLayer()
	go func() { _ = tl.ServeUDP(conn) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		probe, err := net.Dial("udp", addr)
		if err == nil {
			probe.Close()
			time.Sleep(50 * time.Millisecond)
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("stub carrier (flooding-ring) did not start")
	return nil
}

// TestBridgeStaleProvisionalNotRelayedAsFinal is Finding 1's regression
// test: the sole (and therefore last) target floods 180 Ringing responses
// and never sends a final one (see startFloodingRingCarrier), which drives
// sipgo's WaitAnswer to return a plain error once its own >10-response cap
// trips — with bLeg.InviteResponse left holding a 180, a provisional.
// Before the fix, dialTarget trusted bLeg.InviteResponse whenever it was
// non-nil regardless of whether it held a provisional; since this is the
// last target, placeCall would then relay that 180 to the caller as though
// it were a FINAL response — a SIP protocol violation (a 1xx cannot
// terminate a transaction). The fix guards on !IsProvisional(), falling
// back to 503. This proves the caller gets a proper 5xx instead of a
// fabricated "180" final.
//
// The A-leg observer here deliberately does NOT use sipgo's
// DialogClientSession.WaitAnswer: relayProvisional forwards every one of
// the carrier's 11 provisionals to the A-leg 1:1 and in near lockstep with
// the B-leg receiving them, so a sipgo-dialog UAC on the test side would be
// racing its OWN identical ">10 responses" cap against the bridge's — an
// artifact of the test client, not something the bridge does wrong. Reading
// raw UDP datagrams sidesteps that entirely and observes exactly what the
// bridge put on the wire.
func TestBridgeStaleProvisionalNotRelayedAsFinal(t *testing.T) {
	startFloodingRingCarrier(t, "127.0.0.1:45251")
	srv := startServer(t, 45250, ringNoFinalCfg)

	uac, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac socket: %v", err)
	}
	defer uac.Close()
	local := uac.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45250}

	req := sipInviteWithSDP("b2bua-staleprov-1", local, testSDPBody(uacRTPStubPort(t)))
	if _, err := uac.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatalf("write invite: %v", err)
	}

	// The carrier sends exactly 11 provisionals (see startFloodingRingCarrier)
	// and relayProvisional forwards each 1:1, so the A-leg should never see
	// more than 11 "180" lines from a correctly-behaving bridge. Any 180
	// beyond that can only be the bug: placeCall fabricating (or
	// retransmitting) a 180 as though it were the FINAL response.
	var ringingCount int
	var sawFinal bool
	var finalLine string
	buf := make([]byte, 4096)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !sawFinal {
		_ = uac.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := uac.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		statusLine := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
		switch {
		case strings.HasPrefix(statusLine, "SIP/2.0 180"):
			ringingCount++
			if ringingCount > 11 {
				t.Fatal("bridge relayed a 180 as a FINAL response — a SIP protocol violation (Finding 1 regression)")
			}
		case strings.HasPrefix(statusLine, "SIP/2.0 1"):
			// some other provisional (e.g. an auto-100); ignore.
		case strings.HasPrefix(statusLine, "SIP/2.0 "):
			sawFinal = true
			finalLine = statusLine
		}
	}

	if ringingCount == 0 {
		t.Fatal("uac never observed a relayed 180 — test didn't exercise the stale-provisional path")
	}
	if !sawFinal {
		t.Fatal("uac never received a final response (expected 503, or the bug: a 12th, fabricated 180)")
	}
	if !strings.Contains(finalLine, "503") {
		t.Errorf("final response line = %q, want 503 (fallback when the captured failure code is a stale provisional)", finalLine)
	}

	waitForActiveCalls(t, srv, 0, 3*time.Second)
}

// sipInviteWithSDP builds a raw INVITE carrying an SDP offer body, for tests
// that need to observe the bridge's raw wire responses without going
// through sipgo's DialogClientSession (see
// TestBridgeStaleProvisionalNotRelayedAsFinal). Mirrors sipRequest's
// no-body form (server_test.go) but adds Content-Type/Content-Length and
// the body.
func sipInviteWithSDP(callID string, localAddr *net.UDPAddr, sdpBody []byte) string {
	return strings.Join([]string{
		"INVITE sip:5551234@127.0.0.1:45250 SIP/2.0",
		fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-%s", localAddr.String(), callID),
		"From: <sip:tester@127.0.0.1>;tag=t1",
		"To: <sip:sbc@127.0.0.1>",
		"Call-ID: " + callID,
		"CSeq: 1 INVITE",
		"Contact: <sip:tester@" + localAddr.String() + ">",
		"Max-Forwards: 70",
		"Content-Type: application/sdp",
		fmt.Sprintf("Content-Length: %d", len(sdpBody)),
		"", string(sdpBody),
	}, "\r\n")
}

// digestAuthCfg routes local-uac to a single carrier that requires digest
// auth (peer Auth is set); the stub challenges the first attempt and only
// answers once WaitAnswer's built-in retry supplies a valid Authorization.
const digestAuthCfg = `
listen:
  sip: [udp://127.0.0.1:45191]
  media:
    port_range: 46220-46223
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45193
    allowed_ips: [203.0.113.12/30]
    media_latch: loose
    auth:
      username: carrieruser
      password: carrierpass
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeDigestAuth proves the B2BUA passes the target peer's Auth
// creds into WaitAnswer's AnswerOptions: the stub carrier challenges the
// first (unauthenticated) attempt with a 401 + WWW-Authenticate, and only
// answers once the authenticated retry's Authorization header verifies —
// entirely inside WaitAnswer's own internal retry (the bridge calls
// WaitAnswer exactly once per target). The UAC must see a single clean
// 200, never the intermediate 401.
func TestBridgeDigestAuth(t *testing.T) {
	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45194})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrier := startStubCarrier(t, "127.0.0.1:45193", testSDPBody(echoRTPPort), stubCarrierConfig{
		digestUser: "carrieruser",
		digestPass: "carrierpass",
	})
	srv := startServer(t, 45191, digestAuthCfg)

	uacUA, err := sipgo.NewUA()
	if err != nil {
		t.Fatalf("uac ua: %v", err)
	}
	defer uacUA.Close()
	uacClient, err := sipgo.NewClient(uacUA, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("uac client: %v", err)
	}
	defer uacClient.Close()
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45191}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPStubPort(t)))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()

	var sawProvisional bool
	if err := sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{
		OnResponse: func(res *sip.Response) error {
			if res.IsProvisional() {
				sawProvisional = true
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sawProvisional {
		t.Error("UAC observed a provisional/interim response; the 401 challenge-retry must stay entirely inside the B2BUA's WaitAnswer call")
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("got status %d, want 200 (digest retry should have completed the call)", sess.InviteResponse.StatusCode)
	}

	// The carrier must have seen exactly two INVITEs: the unauthenticated
	// first attempt, then the authenticated retry.
	var firstOffer, secondOffer *sip.Request
	select {
	case firstOffer = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the initial B-leg INVITE")
	}
	select {
	case secondOffer = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the authenticated retry INVITE")
	}
	if firstOffer.GetHeader("Authorization") != nil {
		t.Error("first B-leg INVITE already carried Authorization; nothing to challenge")
	}
	if secondOffer.GetHeader("Authorization") == nil {
		t.Error("retried B-leg INVITE carried no Authorization header")
	}

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}
	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE")
	}

	waitForActiveCalls(t, srv, 0, 3*time.Second)

	s2, err := srv.pool.Allocate(media.SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("media ports not released after teardown: %v", err)
	}
	s2.Close()
}
