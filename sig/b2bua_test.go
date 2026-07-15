package sig

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
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

	offers  chan *sip.Request
	byeDone chan struct{}
}

// startStubCarrier boots the stub UAS on addr (e.g. "127.0.0.1:45182") and
// returns once it is accepting packets. It follows the same bind-our-own-
// socket-and-close-from-a-watcher-goroutine pattern as Server.bindListener
// (see sig/server.go) to avoid sipgo's known shutdown-race in
// ListenAndServe.
func startStubCarrier(t *testing.T, addr string, answerSDP []byte) *stubCarrier {
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
