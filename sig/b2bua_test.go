package sig

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
	"github.com/pion/sdp/v3"
	"github.com/pion/srtp/v3"

	"github.com/freesbc/freesbc/config"
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

// TestBridgeRejectsReInvite proves an in-dialog INVITE (a re-INVITE — e.g.
// a phone pressing hold, or any target-refresh/renegotiation) is rejected
// with 501 Not Implemented rather than being handed to
// dialogSrv.ReadInvite: sipgo v1.4.3's DialogServerSession.ReadInvite is
// single-use and corrupts the established dialog's To-tag if called again
// for a re-INVITE, so mid-dialog renegotiation is deferred to M4 (see
// bridge.onInvite's in-dialog-INVITE guard). The detection signal is the
// presence of a To-tag: an initial INVITE never carries one (RFC 3261
// §8.1.1.2), while every in-dialog INVITE does.
//
// This also proves the server survives the rejection intact: a normal
// initial INVITE sent immediately afterward on the same server still
// routes/rejects normally, rather than the process having wedged or
// corrupted shared state.
func TestBridgeRejectsReInvite(t *testing.T) {
	cfg := strings.Replace(bridgeNoRouteCfg, "45070", "45071", 1)
	startServer(t, 45071, cfg)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac socket: %v", err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45071}

	// Same shape as sipRequest's INVITE, but the To header carries a tag —
	// exactly what distinguishes an in-dialog (re-)INVITE from an initial
	// one.
	req := strings.Replace(
		sipRequest("INVITE", "45071", local, "b2bua-reinvite-1"),
		"To: <sip:sbc@127.0.0.1>",
		"To: <sip:sbc@127.0.0.1>;tag=reinvite-tag",
		1,
	)
	if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatalf("write re-invite: %v", err)
	}

	var got strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		if strings.Contains(got.String(), "SIP/2.0 501") {
			break
		}
	}
	if !strings.Contains(got.String(), "SIP/2.0 501") {
		t.Fatalf("re-INVITE (To-tag present) must get 501 Not Implemented, got:\n%s", got.String())
	}

	// The server must have survived unscathed: a fresh initial INVITE
	// (no To-tag) still gets routed and rejected normally (bridgeNoRouteCfg
	// only routes ^999$, so 111 gets 404) — proving ReadInvite's dialog
	// state was never touched by the rejected re-INVITE.
	got2 := roundTrip(t, 45071, "INVITE", "b2bua-reinvite-followup", 3*time.Second, "SIP/2.0 404")
	if !strings.Contains(got2, "SIP/2.0 404") {
		t.Fatalf("server did not survive re-INVITE rejection; follow-up initial INVITE got:\n%s", got2)
	}
}

// TestBridgeRejects100relRequire proves an initial INVITE that mandates
// reliable provisional responses (Require: 100rel, RFC 3262) — a feature we
// do not implement — is rejected at the front door with 420 Bad Extension
// and an Unsupported: 100rel header (RFC 3261 §21.4.20's required pairing),
// before ever reaching Resolve/ReadInvite.
func TestBridgeRejects100relRequire(t *testing.T) {
	cfg := strings.Replace(knownPeerCfg, "45060", "45410", 1)
	startServer(t, 45410, cfg)
	got := roundTripWithHeaders(t, 45410, "INVITE", "req100rel-1", 3*time.Second, "SIP/2.0 420",
		"Require: 100rel")
	if !strings.Contains(got, "SIP/2.0 420") {
		t.Fatalf("Require:100rel must get 420, got:\n%s", got)
	}
	if !strings.Contains(strings.ToLower(got), "unsupported: 100rel") {
		t.Errorf("420 should carry Unsupported: 100rel, got:\n%s", got)
	}
}

// TestBridgeRejectsLowSessionExpires proves an initial INVITE offering a
// Session-Expires below the configured min_se (knownPeerCfg leaves min_se at
// its 90s default) is rejected with 422 Session Interval Too Small and a
// Min-SE header advertising the floor (RFC 4028 §5), before ever reaching
// Resolve/ReadInvite.
func TestBridgeRejectsLowSessionExpires(t *testing.T) {
	cfg := strings.Replace(knownPeerCfg, "45060", "45412", 1)
	startServer(t, 45412, cfg)
	got := roundTripWithHeaders(t, 45412, "INVITE", "lowse-1", 3*time.Second, "SIP/2.0 422",
		"Session-Expires: 30")
	if !strings.Contains(got, "SIP/2.0 422") {
		t.Fatalf("low Session-Expires must get 422, got:\n%s", got)
	}
	if !strings.Contains(strings.ToLower(got), "min-se:") {
		t.Errorf("422 should carry Min-SE, got:\n%s", got)
	}
}

// TestBridgeMalformedInviteGets400 proves a request-shape problem — here,
// an INVITE with no Contact header, which sipgo's DialogUA.ReadInvite
// refuses outright (sip.ErrDialogInviteNoContact) before any dialog is
// built — gets 400 Bad Request rather than the 500 Server Internal Error
// bridge.onInvite used to send for every ReadInvite failure. A malformed
// request from the far end is not an SBC-side failure, so a 5xx would
// misattribute it.
func TestBridgeMalformedInviteGets400(t *testing.T) {
	cfg := strings.Replace(knownPeerCfg, "45060", "45072", 1)
	startServer(t, 45072, cfg)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac socket: %v", err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45072}

	// sipRequest always builds a Contact header; strip it to produce the
	// malformed variant under test. No To-tag, so this is still an initial
	// INVITE (not the re-INVITE 501 path above).
	var lines []string
	for _, line := range strings.Split(sipRequest("INVITE", "45072", local, "b2bua-malformed-1"), "\r\n") {
		if strings.HasPrefix(line, "Contact:") {
			continue
		}
		lines = append(lines, line)
	}
	req := strings.Join(lines, "\r\n")
	if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatalf("write invite: %v", err)
	}

	var got strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		if strings.Contains(got.String(), "SIP/2.0 400") {
			break
		}
	}
	if !strings.Contains(got.String(), "SIP/2.0 400") {
		t.Fatalf("malformed INVITE (no Contact) must get 400, got:\n%s", got.String())
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

	// ringForever (Fix 1): see stubCarrierConfig.ringForever.
	ringForever bool

	// brokenAnswer (Fix 3 regression test): see stubCarrierConfig.brokenAnswer.
	brokenAnswer bool

	offers  chan *sip.Request
	byeDone chan struct{}

	// established (Task 6 fix wave: B-leg refresh test synchronization)
	// closes once THIS invite's answer (RespondSDP/Respond) call has
	// returned, i.e. once dlg.InviteResponse is set and the initial 2xx
	// has actually gone out. sendReinvite reads dlg's internal state
	// (dlg.InviteResponse, via buildReq/Do) from the TEST goroutine —
	// without waiting on this channel first, that read would race under
	// -race against WriteResponse's own unsynchronized write to
	// dlg.InviteResponse in the handler goroutine (see sipgo's
	// DialogServerSession.WriteResponse: a plain field assignment, no
	// mutex), even though in practice the answer has always long since
	// gone out by the time a test gets around to calling sendReinvite
	// (e.g. only after the UAC's own WaitAnswer already succeeded).
	established chan struct{}

	// cancelled (Task 4) closes exactly once, the first time this carrier's
	// dialog ends because it actually received a CANCEL request — as
	// opposed to ending for any other reason (the test tearing the
	// transport down, etc.). Only meaningful with ringForever: sipgo's
	// DialogUA.ReadInvite wires tx.OnCancel to end the dialog with cause
	// sip.ErrTransactionCanceled specifically on a real CANCEL (see
	// dialog_ua.go), which is what distinguishes it here from an ordinary
	// transaction/transport teardown.
	cancelled chan struct{}

	// mu guards lastInvite (Task 2/M4.1): OnInvite's handler runs in a
	// separate goroutine per request from the test's own goroutine, so
	// reading the captured From/Contact needs the same synchronization the
	// send does for offers — a plain field write/read here would otherwise
	// race under -race.
	mu         sync.Mutex
	lastInvite *sip.Request

	// dlg (Task 6 fix wave: B-leg session-timer refresh coverage) is the
	// sipgo dialog session OnInvite's handler establishes for the most
	// recent INVITE, guarded by the same mu. sendReinvite reuses it to send
	// an in-dialog INVITE FROM this stub carrier TO whichever peer it
	// dialogued with (the bridge, in every test that uses this) — sipgo's
	// own DialogServerSession.Do/buildReq fills in the swapped From/To,
	// the dialog's own Call-ID, and a fresh CSeq automatically (see
	// dialog_server.go in the sipgo module), so this simulates a genuine
	// carrier-initiated re-INVITE without hand-building SIP headers the
	// way the A-leg refresh test's raw-UDP sendReInvite has to.
	dlg *sipgo.DialogServerSession
}

// sendReinvite (Task 6 fix wave) sends an in-dialog INVITE FROM this stub
// carrier TO the peer of its most recently established dialog (dlg) —
// simulating a carrier-initiated session-timer refresh on the B-leg.
// Blocks for a final response or until ctx is done; fails the test if no
// dialog has been established yet or the request/response round trip
// itself errors (a non-2xx final response is NOT an error here — the
// caller inspects the status).
func (c *stubCarrier) sendReinvite(t *testing.T, ctx context.Context, body []byte, headers ...sip.Header) *sip.Response {
	t.Helper()
	c.mu.Lock()
	dlg := c.dlg
	c.mu.Unlock()
	if dlg == nil {
		t.Fatal("stub carrier: no established dialog to send a re-INVITE on")
	}
	recipient := dlg.InviteRequest.Contact().Address
	req := sip.NewRequest(sip.INVITE, recipient)
	req.SetBody(body)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	for _, h := range headers {
		req.AppendHeader(h)
	}
	res, err := dlg.Do(ctx, req)
	if err != nil {
		t.Fatalf("carrier re-INVITE: %v", err)
	}
	return res
}

// lastFrom returns the From header of the most recent INVITE this carrier
// received (nil if none yet) — captures what the bridge actually placed on
// the wire for the B-leg, in particular the caller identity (CLI)
// pass-through and topology-hiding host rewrite under test in
// TestBridgeOutboundFromAndContact.
func (c *stubCarrier) lastFrom() *sip.FromHeader {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastInvite == nil {
		return nil
	}
	return c.lastInvite.From()
}

// lastContact mirrors lastFrom for the Contact header.
func (c *stubCarrier) lastContact() *sip.ContactHeader {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastInvite == nil {
		return nil
	}
	return c.lastInvite.Contact()
}

// lastHeaders mirrors lastFrom for an arbitrary header name (M4.3 Task 4:
// Supported/Session-Expires/Min-SE on the B-leg INVITE) — returns every
// header with that name on the most recent INVITE this carrier received,
// nil if none yet or none match.
func (c *stubCarrier) lastHeaders(name string) []sip.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastInvite == nil {
		return nil
	}
	return c.lastInvite.GetHeaders(name)
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

	// ringForever (Fix 1's CANCEL-stops-failover regression test): send a
	// single 180 Ringing and then block until the dialog ends (e.g. the
	// bridge CANCELs this leg because the A-leg went away) or the test
	// tears the carrier down — simulates a carrier that is genuinely still
	// ringing and never answers.
	ringForever bool

	// brokenAnswer (whole-branch-review Fix 3 regression test): answer 200
	// OK, but with an unparseable body instead of the caller's answerSDP —
	// simulates a carrier that answered for real but whose SDP is
	// missing/broken. Proves dialTarget's post-answer failure path responds
	// the A-leg 502 Bad Gateway (not 488, which would wrongly blame the
	// caller's own offer for a problem in the carrier's answer).
	brokenAnswer bool
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
		dialogSrv:   sipgo.NewDialogServerCache(client, contact),
		log:         log,
		answerSDP:   answerSDP,
		offers:      make(chan *sip.Request, 4),
		byeDone:     make(chan struct{}),
		cancelled:   make(chan struct{}),
		established: make(chan struct{}),
	}
	if len(opts) > 0 {
		c.earlySDP = opts[0].earlySDP
		c.proceed = opts[0].proceed
		c.finalStatus = opts[0].finalStatus
		c.finalReason = opts[0].finalReason
		c.digestUser = opts[0].digestUser
		c.digestPass = opts[0].digestPass
		c.ringForever = opts[0].ringForever
		c.brokenAnswer = opts[0].brokenAnswer
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
		c.mu.Lock()
		c.lastInvite = req
		c.dlg = dlg
		c.mu.Unlock()

		if c.ringForever {
			if err := dlg.Respond(180, "Ringing", nil); err != nil {
				log.Error("carrier respond ringing", "err", err)
				return
			}
			// Never answer: block until the dialog ends (CANCEL from the
			// bridge — see DialogUA.ReadInvite's tx.OnCancel wiring — or the
			// test's own teardown closing the transport).
			<-dlg.Context().Done()
			if context.Cause(dlg.Context()) == sip.ErrTransactionCanceled {
				close(c.cancelled)
			}
			return
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
		if c.brokenAnswer {
			if err := dlg.Respond(200, "OK", []byte("not-valid-sdp"),
				sip.NewHeader("Content-Type", "application/sdp")); err != nil {
				log.Error("carrier respond broken sdp", "err", err)
				return
			}
		} else if err := dlg.RespondSDP(c.answerSDP); err != nil {
			log.Error("carrier respond sdp", "err", err)
			return
		}
		// Signal established only now that RespondSDP/Respond has actually
		// returned (dlg.InviteResponse is set) — see the established field's
		// doc comment: sendReinvite must not touch dlg from another
		// goroutine before this.
		close(c.established)
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

// sipBody extracts the message body from a raw SIP message (headers +
// blank line + body, as captured off the wire by TestBridgeAnswersSessionTimerRefresh's
// sendReInvite) — everything after the first CRLFCRLF. Used to assert a
// refresh re-INVITE's 200 OK carries the EXACT SDP under test, not just any
// 200 (see Fix 1's crux assertion).
func sipBody(t *testing.T, raw string) []byte {
	t.Helper()
	idx := strings.Index(raw, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("no header/body separator (CRLFCRLF) found in:\n%s", raw)
	}
	return []byte(raw[idx+4:])
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

// bridgeALegContactCfg mirrors bridgeCallCfg but lists a TCP listener
// BEFORE the UDP one, specifically so Run's dialog-cache default Contact
// (built once from listeners[0]'s port — see Server.Run's contactPort
// comment) lands on the TCP port, not the UDP one the test's UAC actually
// calls in on. That's what lets
// TestBridgeALegContactMatchesInboundTransport tell "per-transport
// override actually happened" (dialTarget's aLeg.Respond(..., aContact),
// Task 5) apart from "silently fell back to the cache default": if the
// override weren't wired up, the bridged 200 OK's Contact port would be
// the TCP listener's (45281) instead of the UDP one (45280) the call
// actually arrived on. The TCP listener is never dialed by the test — it
// only needs to exist and occupy listeners[0].
const bridgeALegContactCfg = `
listen:
  sip: [tcp://127.0.0.1:45281, udp://127.0.0.1:45280]
  media:
    port_range: 46280-46283
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45282
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeALegContactMatchesInboundTransport is Task 5's positive-path
// proof for the A-leg's per-transport Contact (spec §5): the establishing
// 2xx must carry a Contact for the transport/port the call actually
// arrived on, not whichever listener happens to be listeners[0] (the
// dialog cache's baked-in default from Server.Run). bridgeALegContactCfg
// puts a TCP listener first specifically so the two would diverge if the
// override weren't wired up — see its doc comment.
func TestBridgeALegContactMatchesInboundTransport(t *testing.T) {
	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 46285})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrier := startStubCarrier(t, "127.0.0.1:45282", testSDPBody(echoRTPPort))
	startServer(t, 45280, bridgeALegContactCfg)

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

	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45280}
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

	contact := sess.InviteResponse.Contact()
	if contact == nil {
		t.Fatal("bridged 200 OK carried no Contact header")
	}
	if contact.Address.Host != "127.0.0.1" {
		t.Errorf("a-leg contact host = %q, want 127.0.0.1", contact.Address.Host)
	}
	if contact.Address.Port != 45280 {
		t.Errorf("a-leg contact port = %d, want 45280 (the UDP listener the call actually arrived on, not the TCP listeners[0] port 45281 the dialog cache's default Contact would carry if the per-transport override weren't applied)", contact.Address.Port)
	}
	if tr, ok := contact.Address.UriParams.Get("transport"); ok && tr != "" {
		t.Errorf("a-leg contact transport param = %q, want none (udp is the RFC 3261 §19.1.2 default, omitted by buildContact)", tr)
	}

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	select {
	case <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}

	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}
	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE")
	}
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

// cancelFailoverCfg (Fix 1 regression) routes local-uac to two carriers in
// failover order: carrier-a rings forever and never answers, carrier-b
// would answer normally. Fresh port block (45200-45202/46220-46223),
// disjoint from every other test's — see bridgeCallCfg's comment for why
// allowed_ips differ per peer.
const cancelFailoverCfg = `
listen:
  sip: [udp://127.0.0.1:45200]
  media:
    port_range: 46220-46223
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier-a:
    address: 127.0.0.1:45201
    allowed_ips: [203.0.113.16/28]
  carrier-b:
    address: 127.0.0.1:45202
    allowed_ips: [198.51.100.16/28]
routes:
  - name: out
    from: local-uac
    to: [carrier-a, carrier-b]
`

// TestBridgeCancelStopsFailover is Fix 1's regression test: the caller
// CANCELs while the first failover target (carrier-a) is still ringing.
//
// Before the fix, placeCall's failover loop ignored the A-leg's state after
// a retryable dialTarget failure and dialed the next candidate (carrier-b)
// regardless of whether the caller was still there — sending a live INVITE
// to a real carrier, and potentially blocking up to Timer B (~32s) waiting
// on it, for a caller who already hung up. The fix checks
// aLeg.Context().Err() right after each retryable failure and stops the
// loop instead.
//
// carrier-a's CANCEL happens automatically: dialTarget dials via
// aLeg.Context(), so once the A-leg's real CANCEL cancels that context,
// sipgo's own WaitAnswer(ctx) sends the B-leg CANCEL to carrier-a itself.
// This test only has to prove the OUTCOME — carrier-b must never see an
// INVITE — asserted via carrier-b's offers channel staying empty across a
// bounded wait past the CANCEL, per the task's guidance that this is more
// reliable than trying to prove a negative directly.
//
// It also covers the Task 5 fix-wave finding that a caller CANCEL must
// NOT cool carrier-a down (it was reachable/ringing, not unreachable):
// dialTarget's WaitAnswer-error classification hits the
// aLeg.Context().Err() != nil case here, which leaves attemptResult.penalize
// at its zero-value default (false) — see attemptResult's doc and the
// classification switch in dialTarget.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.
func TestBridgeCancelStopsFailover(t *testing.T) {
	carrierA := startStubCarrier(t, "127.0.0.1:45201", nil, stubCarrierConfig{ringForever: true})
	carrierB := startStubCarrier(t, "127.0.0.1:45202", testSDPBody(uacRTPStubPort(t)))
	srv := startServer(t, 45200, cancelFailoverCfg)

	uac, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac socket: %v", err)
	}
	defer uac.Close()
	local := uac.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45200}

	const callID = "b2bua-cancel-failover-1"
	req := sipInviteWithSDP(callID, local, testSDPBody(uacRTPStubPort(t)), 45200)
	if _, err := uac.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatalf("write invite: %v", err)
	}

	// Wait for carrier-a's relayed 180 Ringing: proves the bridge is
	// mid-attempt-one (carrier-a dialed, ringing) before we cancel.
	var sawRinging bool
	buf := make([]byte, 4096)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !sawRinging {
		_ = uac.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := uac.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if strings.HasPrefix(string(buf[:n]), "SIP/2.0 180") {
			sawRinging = true
		}
	}
	if !sawRinging {
		t.Fatal("uac never saw carrier-a's relayed 180 Ringing")
	}

	select {
	case <-carrierA.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-a never received the B-leg INVITE")
	}

	// Cancel while carrier-a is still ringing and unanswered.
	cancelReq := sipCancel(callID, local, 45200)
	if _, err := uac.WriteToUDP([]byte(cancelReq), dst); err != nil {
		t.Fatalf("write cancel: %v", err)
	}

	// Bounded wait past the CANCEL, then assert carrier-b never got an
	// INVITE — the failover loop must have stopped rather than proceeding
	// to the next target for a caller who already left.
	select {
	case <-carrierB.offers:
		t.Fatal("carrier-b received a B-leg INVITE after the caller CANCELed — failover loop did not stop")
	case <-time.After(2 * time.Second):
	}

	// carrier-a was reachable (it was ringing when the caller CANCELed) —
	// the CANCEL must not have cooled it down.
	if !srv.health.Available(Endpoint{Host: "127.0.0.1", Port: 45201, Transport: "udp"}) {
		t.Error("carrier-a should not be cooled down after a caller CANCEL, only after a genuine connect failure")
	}
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

	req := sipInviteWithSDP("b2bua-staleprov-1", local, testSDPBody(uacRTPStubPort(t)), 45250)
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

// sipInviteWithSDP builds a raw INVITE carrying an SDP offer body targeting
// 127.0.0.1:port, for tests that need to observe the bridge's raw wire
// responses without going through sipgo's DialogClientSession (see
// TestBridgeStaleProvisionalNotRelayedAsFinal, TestBridgeCancelStopsFailover).
// Mirrors sipRequest's no-body form (server_test.go) but adds
// Content-Type/Content-Length and the body.
func sipInviteWithSDP(callID string, localAddr *net.UDPAddr, sdpBody []byte, port int) string {
	return strings.Join([]string{
		fmt.Sprintf("INVITE sip:5551234@127.0.0.1:%d SIP/2.0", port),
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

// sipCancel builds a CANCEL for the initial request built by sipInviteWithSDP
// with the same callID/localAddr/port. RFC 3261 §9.1 requires the CANCEL's
// Via (including branch), From, To, and Call-ID to match the request being
// cancelled exactly, and its CSeq to carry the same sequence number with
// method CANCEL — that's what lets the transaction layer match it to the
// pending INVITE server transaction and auto-terminate it (200 to the
// CANCEL, then 487 to the INVITE — see sipgo's TransactionLayer.handleRequest).
func sipCancel(callID string, localAddr *net.UDPAddr, port int) string {
	return strings.Join([]string{
		fmt.Sprintf("CANCEL sip:5551234@127.0.0.1:%d SIP/2.0", port),
		fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-%s", localAddr.String(), callID),
		"From: <sip:tester@127.0.0.1>;tag=t1",
		"To: <sip:sbc@127.0.0.1>",
		"Call-ID: " + callID,
		"CSeq: 1 CANCEL",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
}

// --- Task 9 test hardening: re-INVITE rejection during an established call ---

// reinviteDuringCallCfg mirrors bridgeCallCfg (Task 6) on a disjoint port
// set from every other test's — see bridgeCallCfg's comment for why the
// allowed_ips values differ per peer — so this test's real bridged call
// can't collide with any other test's listeners.
const reinviteDuringCallCfg = `
listen:
  sip: [udp://127.0.0.1:45196]
  media:
    port_range: 46196-46199
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45197
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeReInviteDuringCallDoesNotBreakCall closes a gap
// TestBridgeRejectsReInvite left open: that test proves 501 on a
// standalone To-tagged request sent to a server with no established call
// at all, which only proves the code *path* taken — it never demonstrates
// Task 9's actual claim, that a re-INVITE arriving DURING a live call is
// rejected without disturbing that call. This test establishes a real
// bridged call exactly like TestBridgePlacesCallAndBridges, then — while
// it is up — sends an in-dialog INVITE that reuses this dialog's genuine
// Call-ID, the UAC's own From-tag, and the real To-tag the bridge assigned
// (read off the UAC's 200 OK), asserts 501, and then proves the original
// dialog is unharmed: its BYE still completes cleanly, the carrier's side
// of the dialog still ends, and both the call registry and the media pool
// fully drain — the observable proof that onInvite's To-tag guard rejects
// the re-INVITE on the raw server transaction before ever touching
// dialogSrv or the established aLeg, rather than merely by construction of
// a narrower test. Timing-based over real UDP loopback: re-run once before
// treating a flake as failure.
func TestBridgeReInviteDuringCallDoesNotBreakCall(t *testing.T) {
	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45198})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrier := startStubCarrier(t, "127.0.0.1:45197", testSDPBody(echoRTPPort))
	srv := startServer(t, 45196, reinviteDuringCallCfg)

	// --- establish the call, same shape as TestBridgePlacesCallAndBridges ---
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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45196}
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
	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	select {
	case <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE; call never actually bridged")
	}

	// --- while the call is established, send a re-INVITE reusing this
	// dialog's real identifiers: the genuine Call-ID and From-tag the UAC
	// used to place the call, and the genuine To-tag the bridge assigned
	// in its 200 OK. ---
	callIDHdr := sess.InviteRequest.CallID()
	fromHdr := sess.InviteRequest.From()
	toHdr := sess.InviteResponse.To()
	if callIDHdr == nil || fromHdr == nil || toHdr == nil {
		t.Fatal("established dialog missing Call-ID/From/To; can't build a faithful re-INVITE")
	}
	realCallID := callIDHdr.Value()
	realFromTag, hasFromTag := fromHdr.Params.Get("tag")
	realToTag, hasToTag := toHdr.Params.Get("tag")
	if !hasFromTag || realFromTag == "" {
		t.Fatal("uac's own From header carries no tag")
	}
	if !hasToTag || realToTag == "" {
		t.Fatal("bridge's 200 OK carried no To-tag to reuse")
	}

	reConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("re-invite socket: %v", err)
	}
	defer reConn.Close()
	reLocal := reConn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45196}

	reInvite := strings.Join([]string{
		"INVITE sip:5551234@127.0.0.1:45196 SIP/2.0",
		fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-reinvite-established", reLocal.String()),
		fmt.Sprintf("From: <sip:tester@127.0.0.1>;tag=%s", realFromTag),
		fmt.Sprintf("To: <sip:sbc@127.0.0.1>;tag=%s", realToTag),
		"Call-ID: " + realCallID,
		"CSeq: 2 INVITE",
		"Contact: <sip:tester@" + reLocal.String() + ">",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
	if _, err := reConn.WriteToUDP([]byte(reInvite), dst); err != nil {
		t.Fatalf("write re-invite: %v", err)
	}

	var got strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = reConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := reConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		if strings.Contains(got.String(), "SIP/2.0 501") {
			break
		}
	}
	if !strings.Contains(got.String(), "SIP/2.0 501") {
		t.Fatalf("re-INVITE during an established call must get 501, got:\n%s", got.String())
	}

	// --- prove the original call is unharmed: its BYE still tears
	// everything down cleanly, same as the happy-path test's teardown. ---
	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}

	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE — the rejected re-INVITE perturbed the established call")
	}

	waitForActiveCalls(t, srv, 0, 3*time.Second)

	// The pool holds exactly one session's worth of ports (46196-46199): a
	// fresh Allocate only succeeds if the bridge actually released them on
	// teardown, proving the rejected re-INVITE didn't leak or corrupt the
	// session either.
	s2, err := srv.pool.Allocate(media.SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("media ports not released after teardown: %v", err)
	}
	s2.Close()
}

// sessionTimerRefreshCfg is TestBridgeAnswersSessionTimerRefresh's own
// listener/peer/route set, on ports not used by any other test in this
// file.
const sessionTimerRefreshCfg = `
listen:
  sip: [udp://127.0.0.1:45430]
  media:
    port_range: 46330-46333
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45431
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeAnswersSessionTimerRefresh is M4.3 Task 6's spike-and-implement
// test: it establishes a real bridged call (same technique as
// TestBridgeReInviteDuringCallDoesNotBreakCall — reusing the dialog's
// genuine Call-ID/From-tag and the bridge's own real To-tag), then sends an
// in-dialog re-INVITE carrying Session-Expires and the SAME SDP the call
// was established with (a session-timer refresh). Per the Task 6 spike
// finding (see timers.go's refresherOf doc and b2bua.go's onInvite
// in-dialog branch), sipgo v1.4.3 lets a bare tx.Respond(200) on the
// re-INVITE's own raw server transaction — never touching dialogSrv/aLeg —
// answer it cleanly: the peer's ACK to that 200 is routed by onAck to
// dialogSrv.ReadAck, which no-ops (a harmless, already-tolerated CSeq
// mismatch — see the comment on b.s.sdps.set below) rather than mutating or
// corrupting the established dialog's state, so the original call is
// provably unharmed by the refresh: its real BYE still completes, the
// carrier's dialog still ends, and the call registry/media pool still fully
// drain. It also proves a second re-INVITE whose SDP has genuinely changed
// still gets the M3.3 501 (media-change renegotiation stays out of scope
// for M4.3). Timing-based over real UDP loopback: re-run once before
// treating a flake as failure.
func TestBridgeAnswersSessionTimerRefresh(t *testing.T) {
	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45432})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrier := startStubCarrier(t, "127.0.0.1:45431", testSDPBody(echoRTPPort))
	srv := startServer(t, 45430, sessionTimerRefreshCfg)

	// --- establish the call, same shape as TestBridgePlacesCallAndBridges ---
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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45430}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	offerSDP := testSDPBody(uacRTPPort)
	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, offerSDP)
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
	// establishedAAnswer is the SBC's OWN A-leg answer SDP — what the
	// caller actually received in the original 200 OK (aAnswer, rewritten
	// to the SBC's own ports/IP; NOT byte-identical to offerSDP, which is
	// the caller's OWN offer). This is the Critical #1 crux: a refresh
	// re-INVITE's 200 OK must echo THIS, not offerSDP — sending offerSDP
	// back would aim the caller's RTP at itself and let the media watchdog
	// kill the call.
	establishedAAnswer := sess.InviteResponse.Body()
	if len(establishedAAnswer) == 0 {
		t.Fatal("original 200 OK carried no SDP body; can't assert against it")
	}
	if string(establishedAAnswer) == string(offerSDP) {
		t.Fatal("test setup is broken: established answer must not equal the caller's own offer, or the refresh-body assertion below can't distinguish the bug")
	}
	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	// bLegOffer is the SBC's OWN B-side offer SDP — what the carrier
	// actually received when the bridge placed the B-leg (bOffer). Needed
	// below to assert a B-leg (carrier-initiated) refresh's 200 OK echoes
	// THIS, not the carrier's own answer (Fix 1's B-leg counterpart, Fix 2).
	var bLegOfferReq *sip.Request
	select {
	case bLegOfferReq = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE; call never actually bridged")
	}
	bLegOffer := bLegOfferReq.Body()

	// --- reuse this dialog's real identifiers: the genuine Call-ID and
	// From-tag the UAC used to place the call, and the genuine To-tag the
	// bridge assigned in its 200 OK. ---
	callIDHdr := sess.InviteRequest.CallID()
	fromHdr := sess.InviteRequest.From()
	toHdr := sess.InviteResponse.To()
	if callIDHdr == nil || fromHdr == nil || toHdr == nil {
		t.Fatal("established dialog missing Call-ID/From/To; can't build a faithful re-INVITE")
	}
	realCallID := callIDHdr.Value()
	realFromTag, hasFromTag := fromHdr.Params.Get("tag")
	realToTag, hasToTag := toHdr.Params.Get("tag")
	if !hasFromTag || realFromTag == "" {
		t.Fatal("uac's own From header carries no tag")
	}
	if !hasToTag || realToTag == "" {
		t.Fatal("bridge's 200 OK carried no To-tag to reuse")
	}

	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45430}

	// sendReInvite fires one in-dialog INVITE with the given CSeq and SDP
	// body, over its own fresh socket (a distinct branch/local port per
	// send, same as the M3.3 technique), and returns everything read back
	// before wantSubstr appears or the 3s deadline elapses.
	sendReInvite := func(t *testing.T, cseq int, body []byte, branchSuffix, wantSubstr string) string {
		t.Helper()
		reConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("re-invite socket: %v", err)
		}
		defer reConn.Close()
		reLocal := reConn.LocalAddr().(*net.UDPAddr)

		reInvite := strings.Join([]string{
			"INVITE sip:5551234@127.0.0.1:45430 SIP/2.0",
			fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-%s", reLocal.String(), branchSuffix),
			fmt.Sprintf("From: <sip:tester@127.0.0.1>;tag=%s", realFromTag),
			fmt.Sprintf("To: <sip:sbc@127.0.0.1>;tag=%s", realToTag),
			"Call-ID: " + realCallID,
			fmt.Sprintf("CSeq: %d INVITE", cseq),
			"Contact: <sip:tester@" + reLocal.String() + ">",
			"Max-Forwards: 70",
			"Session-Expires: 1800;refresher=uac",
			"Supported: timer",
			"Content-Type: application/sdp",
			fmt.Sprintf("Content-Length: %d", len(body)),
			"", string(body),
		}, "\r\n")
		if _, err := reConn.WriteToUDP([]byte(reInvite), dst); err != nil {
			t.Fatalf("write re-invite: %v", err)
		}

		var got strings.Builder
		buf := make([]byte, 4096)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_ = reConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _, err := reConn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			got.Write(buf[:n])
			if strings.Contains(got.String(), wantSubstr) {
				break
			}
		}
		return got.String()
	}

	// --- refresh re-INVITE: same SDP, Session-Expires present → 200 OK,
	// echoing a Session-Expires header, not the M3.3 501. ---
	refreshResp := sendReInvite(t, 2, offerSDP, "reinvite-refresh", "SIP/2.0 200")
	if !strings.Contains(refreshResp, "SIP/2.0 200") {
		t.Fatalf("session-timer refresh re-INVITE must get 200, got:\n%s", refreshResp)
	}
	if !strings.Contains(refreshResp, "Session-Expires") {
		t.Fatalf("200 OK to a refresh re-INVITE must carry Session-Expires, got:\n%s", refreshResp)
	}
	// Fix 3: a 2xx to INVITE MUST carry a Contact (RFC 3261 §12.1.1) —
	// sip.NewResponseFromRequest alone does not add one.
	if !strings.Contains(refreshResp, "Contact:") && !strings.Contains(refreshResp, "\r\nm:") {
		t.Fatalf("200 OK to a refresh re-INVITE must carry Contact, got:\n%s", refreshResp)
	}
	// Fix 1's crux assertion: the refresh's 200 OK body must be the SBC's
	// own ESTABLISHED ANSWER (what the caller already has), never the
	// caller's own offer echoed back — the pre-fix bug, which aims the
	// caller's RTP at itself and lets the media watchdog kill the call.
	refreshBody := sipBody(t, refreshResp)
	if string(refreshBody) == string(offerSDP) {
		t.Fatalf("refresh 200 OK answered with the CALLER'S OWN OFFER instead of the SBC's established answer (Critical #1 regression):\n%s", refreshResp)
	}
	if string(refreshBody) != string(establishedAAnswer) {
		t.Fatalf("refresh 200 OK body must equal the SBC's established A-leg answer, got:\n%s\nwant body:\n%s", refreshResp, establishedAAnswer)
	}

	// --- o=-version-bump refresh (Fix 4): same c=/m= as the established
	// offer, but the o= line's version bumped, as a real UAC commonly does
	// on every re-offer (RFC 3264 §8) — must still be recognized as a
	// refresh (200, established answer), not misclassified as a media
	// change (501). ---
	bumpedOfferSDP := []byte(strings.Replace(string(offerSDP), "o=- 1 1", "o=- 1 2", 1))
	if string(bumpedOfferSDP) == string(offerSDP) {
		t.Fatal("test setup is broken: o= bump did not change the SDP")
	}
	bumpResp := sendReInvite(t, 3, bumpedOfferSDP, "reinvite-obump", "SIP/2.0 200")
	if !strings.Contains(bumpResp, "SIP/2.0 200") {
		t.Fatalf("o=-version-bump refresh re-INVITE must still get 200, got:\n%s", bumpResp)
	}
	if bumpBody := sipBody(t, bumpResp); string(bumpBody) != string(establishedAAnswer) {
		t.Fatalf("o=-version-bump refresh 200 body must equal the SBC's established A-leg answer, got:\n%s\nwant body:\n%s", bumpResp, establishedAAnswer)
	}

	// --- media-change re-INVITE: same Session-Expires header, but a
	// genuinely different SDP body → still 501, exactly like M3.3. ---
	changedSDP := testSDPBody(uacRTPPort + 1)
	changeResp := sendReInvite(t, 4, changedSDP, "reinvite-changed", "SIP/2.0 501")
	if !strings.Contains(changeResp, "SIP/2.0 501") {
		t.Fatalf("media-changing re-INVITE must still get 501, got:\n%s", changeResp)
	}

	// --- B-leg (carrier-initiated) session-timer refresh (Fix 2): the
	// carrier re-sends its own established answer SDP with Session-Expires
	// — must be recognized on the SAME in-dialog branch (looked up by ITS
	// OWN, B-leg Call-ID) and answered 200 with bLegOffer, the SBC's own
	// established B-side offer — never the carrier's own answer, and never
	// the A-leg's aAnswer. ---
	//
	// Wait for the carrier's OWN answer to have actually gone out
	// (carrier.established) before touching its dialog session from this
	// goroutine — required for -race correctness (see the established
	// field's doc comment), even though by this point in the test (well
	// after the UAC's own WaitAnswer succeeded) it always already has.
	select {
	case <-carrier.established:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never finished answering the B-leg INVITE")
	}
	bRefreshCtx, cancelBRefresh := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelBRefresh()
	bRefreshRes := carrier.sendReinvite(t, bRefreshCtx, testSDPBody(echoRTPPort),
		sessionExpiresHeader(1800*time.Second, "uac"),
		sip.NewHeader("Supported", "timer"))
	if bRefreshRes.StatusCode != 200 {
		t.Fatalf("B-leg session-timer refresh must get 200, got %d %s", bRefreshRes.StatusCode, bRefreshRes.Reason)
	}
	if bRefreshRes.Contact() == nil {
		t.Fatal("B-leg refresh 200 OK must carry Contact")
	}
	if string(bRefreshRes.Body()) != string(bLegOffer) {
		t.Fatalf("B-leg refresh 200 OK body must equal the SBC's established B-side offer, got:\n%s\nwant body:\n%s", bRefreshRes.Body(), bLegOffer)
	}

	// --- prove the original call is unharmed by either re-INVITE: its BYE
	// still tears everything down cleanly, same as the M3.3 test's
	// teardown proof. ---
	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}

	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE — a re-INVITE perturbed the established call")
	}

	waitForActiveCalls(t, srv, 0, 3*time.Second)

	// The pool holds exactly one session's worth of ports (46330-46333): a
	// fresh Allocate only succeeds if the bridge actually released them on
	// teardown, proving neither re-INVITE leaked or corrupted the session.
	s2, err := srv.pool.Allocate(media.SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("media ports not released after teardown: %v", err)
	}
	s2.Close()

	// The per-call SDP store must also drain on teardown — otherwise a
	// reused Call-ID (unlikely, but not impossible with a misbehaving UAC)
	// could compare a later call's re-INVITE against a stale entry.
	if _, ok := srv.callSDP(realCallID); ok {
		t.Fatal("established SDP still on record after teardown; callSDPStore not cleared")
	}
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

// --- M4.1 Task 2: From/CLI propagation + per-transport B-leg Contact ---

// outboundFromCfg mirrors bridgeCallCfg's shape on a disjoint port set
// (45180-45198 are already claimed by the Task 6/7/8/9 tests above — see
// bridgeCallCfg's comment for why allowed_ips differ per peer).
const outboundFromCfg = `
listen:
  sip: [udp://127.0.0.1:45203]
  media:
    port_range: 46230-46233
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45204
    allowed_ips: [203.0.113.0/24]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeOutboundFromAndContact is M4.1 Task 2's crux: it closes the
// M3.3 blocker where the B-leg INVITE went out with sipgo's synthesized
// "From: sipgo@localhost" instead of the caller's own identity. The UAC's
// INVITE carries From user "1001" (CLI pass-through under test); the
// assertions below read the carrier's *received* INVITE (not the UAC's own
// request) to prove the bridge rebuilt From/Contact rather than merely
// forwarding the A-leg's headers: From user must still be "1001" (CLI
// preserved) but From/Contact host must be ourIP (127.0.0.1, this config's
// public_ip) — never the UAC's own loopback source port — and the Contact
// must carry our SIP listen port with no transport= param (carrier's
// transport defaults to udp, SIP's own default per RFC 3261 §19.1.2).
// No RTP is exercised here (Task 6/7/8 already cover the media path); this
// test only needs the call to reach a bridged, ACKed state so the carrier's
// captured B-leg INVITE reflects a real end-to-end placement.
func TestBridgeOutboundFromAndContact(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:45204", testSDPBody(uacRTPStubPort(t)))
	startServer(t, 45203, outboundFromCfg)

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
	// Empty Contact, same as the other UAC harnesses above (see
	// TestBridgePlacesCallAndBridges): this UAC never receives requests.
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45203}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	// Build the A-leg INVITE by hand (via WriteInvite, not the plain Invite
	// convenience method) so it carries an explicit From identifying the
	// caller as "1001" with a display name — DialogClientCache.Invite would
	// otherwise let sipgo synthesize a default From from the UA's own
	// name/hostname, which wouldn't exercise CLI pass-through at all.
	// The caller's From host is set to a distinct address (203.0.113.50)
	// different from ourIP (127.0.0.1), so assertions can prove topology
	// hiding: the bridge must rewrite the host to ourIP, not forward the
	// caller's claimed host.
	inviteReq := sip.NewRequest(sip.INVITE, bridgeURI)
	inviteReq.SetBody(testSDPBody(uacRTPStubPort(t)))
	fromParams := sip.NewParams()
	fromParams.Add("tag", sip.GenerateTagN(16))
	inviteReq.AppendHeader(&sip.FromHeader{
		DisplayName: "Caller 1001",
		Address:     sip.Uri{Scheme: "sip", User: "1001", Host: "203.0.113.50", Port: 5070},
		Params:      fromParams,
	})

	sess, err := dialogCli.WriteInvite(inviteCtx, inviteReq)
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
	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	select {
	case <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}

	from := carrier.lastFrom()
	if from == nil {
		t.Fatal("carrier never captured a From header on the B-leg INVITE")
	}
	if from.Address.User != "1001" {
		t.Errorf("From user = %q, want caller number 1001 (CLI pass-through)", from.Address.User)
	}
	if from.Address.Host != "127.0.0.1" {
		t.Errorf("From host = %q, want ourIP 127.0.0.1 (topology hiding; must not be the caller's own address)", from.Address.Host)
	}
	if from.Address.Host == "203.0.113.50" {
		t.Error("From host = 203.0.113.50 (caller's claimed host); topology hiding failed: buildFrom forwarded the caller's host instead of rewriting to ourIP")
	}
	if from.Address.Port != 45203 {
		t.Errorf("From port = %d, want bridge's outbound SIP port 45203 (from config listener)", from.Address.Port)
	}
	if from.DisplayName != "Caller 1001" {
		t.Errorf("From display name = %q, want caller's display name preserved", from.DisplayName)
	}
	if tag, ok := from.Params.Get("tag"); !ok || tag == "" {
		t.Error("From must carry a tag")
	} else if uacTag, _ := inviteReq.From().Params.Get("tag"); tag == uacTag {
		t.Error("From tag must be freshly generated for the B-leg dialog, not the A-leg's own tag")
	}

	contact := carrier.lastContact()
	if contact == nil {
		t.Fatal("carrier never captured a Contact header on the B-leg INVITE")
	}
	if contact.Address.Host != "127.0.0.1" {
		t.Errorf("Contact host = %q, want ourIP 127.0.0.1", contact.Address.Host)
	}
	if contact.Address.Port != 45203 {
		t.Errorf("Contact port = %d, want our SIP listen port 45203", contact.Address.Port)
	}
	if tp, ok := contact.Address.UriParams.Get("transport"); ok && tp != "" && tp != "udp" {
		t.Errorf("Contact transport param = %q, want no param or udp (carrier's transport defaults to udp)", tp)
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
}

// --- M4.1 Task 3: response-code fidelity — real carrier final codes ---

// realCodeCfg routes local-uac to a single carrier that declines with a
// real final code (486 Busy Here) — proves that code reaches the caller
// verbatim rather than being flattened to a synthetic 502/503. Fresh ports
// (45210/45211, 46240-46243), disjoint from every earlier test's blocks
// (45180-45204/46180-46233, 45250-45251/46250-46253).
const realCodeCfg = `
listen:
  sip: [udp://127.0.0.1:45210]
  media:
    port_range: 46240-46243
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45211
    allowed_ips: [203.0.113.20/30]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgePassesRealFinalCode is M4.1 Task 3's crux: a single carrier
// declines with 486 Busy Here — a genuine SIP final failure, not a dial
// error — and the caller must see that real code verbatim, never a
// synthetic 502/503.
func TestBridgePassesRealFinalCode(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:45211", nil, stubCarrierConfig{
		finalStatus: 486,
		finalReason: "Busy Here",
	})
	startServer(t, 45210, realCodeCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45210}
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
	if finalCode := sess.InviteResponse.StatusCode; finalCode != 486 {
		t.Fatalf("caller got %d, want 486 (real carrier code, not a synthetic 502/503)", finalCode)
	}

	select {
	case <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}
}

// failoverRealCodeCfg routes local-uac to two carriers, both declining with
// real final codes: carrier-a 486, carrier-b 404 (Task 3's "last real code
// wins" precedence test). Fresh ports (45212-45214, 46244-46247), disjoint
// from realCodeCfg and every earlier test's blocks.
const failoverRealCodeCfg = `
listen:
  sip: [udp://127.0.0.1:45212]
  media:
    port_range: 46244-46247
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier-a:
    address: 127.0.0.1:45213
    allowed_ips: [203.0.113.24/30]
  carrier-b:
    address: 127.0.0.1:45214
    allowed_ips: [203.0.113.28/30]
routes:
  - name: out
    from: local-uac
    to: [carrier-a, carrier-b]
`

// TestBridgeFailoverThenRealCode proves failover precedence: when every
// target fails with a genuine final code (carrier-a 486, carrier-b 404),
// the caller sees the LAST real code (404) — not the first, and not a
// synthetic default.
func TestBridgeFailoverThenRealCode(t *testing.T) {
	carrierA := startStubCarrier(t, "127.0.0.1:45213", nil, stubCarrierConfig{
		finalStatus: 486,
		finalReason: "Busy Here",
	})
	carrierB := startStubCarrier(t, "127.0.0.1:45214", nil, stubCarrierConfig{
		finalStatus: 404,
		finalReason: "Not Found",
	})
	startServer(t, 45212, failoverRealCodeCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45212}
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
	if finalCode := sess.InviteResponse.StatusCode; finalCode != 404 {
		t.Fatalf("caller got %d, want 404 (last real code)", finalCode)
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
}

// trailingDialFailureCfg routes local-uac to two carriers: carrier-a
// declines with a real 486 Busy Here; carrier-b (the LAST target) never
// sends a final response at all, driving the same stale-provisional/
// dial-classified path as TestBridgeStaleProvisionalNotRelayedAsFinal (see
// startFloodingRingCarrier). Fresh ports (45215-45217, 46248-46251),
// disjoint from every earlier test's blocks.
const trailingDialFailureCfg = `
listen:
  sip: [udp://127.0.0.1:45215]
  media:
    port_range: 46248-46251
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier-a:
    address: 127.0.0.1:45216
    allowed_ips: [203.0.113.32/30]
  carrier-b:
    address: 127.0.0.1:45217
    allowed_ips: [203.0.113.36/30]
routes:
  - name: out
    from: local-uac
    to: [carrier-a, carrier-b]
`

// TestBridgeFailoverRealCodeSurvivesTrailingDialFailure is Task 3's actual
// precedence case, distinct from TestBridgeFailoverThenRealCode (where
// every target fails with a real code, so even M3.3's "last target's code"
// logic happens to land on the right answer): carrier-a (first) declines
// with a genuine 486 Busy Here; carrier-b (last) never sends a final
// response at all — a dial-classified (synthetic) failure, not a real
// carrier code. Before the Task 3 fix, placeCall unconditionally remembered
// whichever target failed LAST regardless of kind, so carrier-b's synthetic
// 503 would clobber carrier-a's real 486 even though carrier-b never
// actually said anything. The fix tracks only failReal outcomes, so the
// caller still sees carrier-a's real code.
//
// Like TestBridgeStaleProvisionalNotRelayedAsFinal, this reads raw UDP
// datagrams instead of using sipgo's DialogClientSession.WaitAnswer:
// carrier-b floods 11 provisionals and relayProvisional forwards each 1:1
// to the A-leg, so a sipgo-dialog UAC would be racing its OWN identical
// ">10 responses" cap against the bridge's — an artifact of the test
// client, not something the bridge does wrong.
func TestBridgeFailoverRealCodeSurvivesTrailingDialFailure(t *testing.T) {
	carrierA := startStubCarrier(t, "127.0.0.1:45216", nil, stubCarrierConfig{
		finalStatus: 486,
		finalReason: "Busy Here",
	})
	carrierB := startFloodingRingCarrier(t, "127.0.0.1:45217")
	startServer(t, 45215, trailingDialFailureCfg)

	uac, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac socket: %v", err)
	}
	defer uac.Close()
	local := uac.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45215}

	req := sipInviteWithSDP("b2bua-trailing-dial-failure-1", local, testSDPBody(uacRTPStubPort(t)), 45215)
	if _, err := uac.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatalf("write invite: %v", err)
	}

	// Read until the first FINAL (non-1xx) status line; carrier-a's 486
	// arrives as a relayed provisional-free final only once carrier-b's own
	// attempt (including its flood of 11 relayed 180s) has finished.
	var (
		sawFinal  bool
		finalLine string
	)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !sawFinal {
		_ = uac.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := uac.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		statusLine := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
		if strings.HasPrefix(statusLine, "SIP/2.0 1") {
			continue // provisional (100/180/...): keep reading for the final.
		}
		if strings.HasPrefix(statusLine, "SIP/2.0 ") {
			sawFinal = true
			finalLine = statusLine
		}
	}
	if !sawFinal {
		t.Fatal("uac never received a final response")
	}
	if !strings.Contains(finalLine, "486") {
		t.Fatalf("final response line = %q, want 486 (earlier real code must survive the trailing synthetic dial failure)", finalLine)
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
}

// --- Task 4: ring timeout with failover ---

// ringTimeoutFailoverCfg sets ring_timeout to 300ms so a single ringing
// target (carrier-a, which never answers) is capped and failed over well
// within the test's own timeouts. Fresh ports (45260-45262, 46260-46263),
// disjoint from every other test's — see bridgeCallCfg's comment for why
// allowed_ips differ per peer.
const ringTimeoutFailoverCfg = `
listen:
  sip: [udp://127.0.0.1:45260]
  media:
    port_range: 46260-46263
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier-a:
    address: 127.0.0.1:45261
    allowed_ips: [203.0.113.40/30]
  carrier-b:
    address: 127.0.0.1:45262
    allowed_ips: [203.0.113.44/30]
ring_timeout: 300ms
routes:
  - name: out
    from: local-uac
    to: [carrier-a, carrier-b]
`

// TestBridgeRingTimeoutFailsOver is Task 4's core case: carrier-a (the
// first target) sends 180 Ringing and then never answers. With
// ring_timeout set to 300ms, the bridge must give up on carrier-a well
// before the caller's own patience (Timer B, ~32s) runs out, send it a
// real CANCEL (not just abandon the transaction), and fail over to
// carrier-b, which answers immediately.
//
// This is the mirror image of TestBridgeCancelStopsFailover (Fix 1): there
// the CANCEL comes from the CALLER (aLeg.Context() itself is cancelled) and
// the failover loop must STOP; here the CANCEL is the BRIDGE's own, sent to
// a single hung target because only the per-attempt ring timer expired
// (aLeg.Context() is still live), and failover must PROCEED. Swapping that
// distinction in dialTarget's WaitAnswer-error classification would either
// wrongly halt failover here or wrongly continue it in the Fix-1 case.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.
func TestBridgeRingTimeoutFailsOver(t *testing.T) {
	carrierA := startStubCarrier(t, "127.0.0.1:45261", nil, stubCarrierConfig{ringForever: true})
	carrierB := startStubCarrier(t, "127.0.0.1:45262", testSDPBody(uacRTPStubPort(t)))
	startServer(t, 45260, ringTimeoutFailoverCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45260}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPStubPort(t)))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()

	if err := sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("got status %d, want 200 (carrier-b should have answered after carrier-a's ring timeout)", sess.InviteResponse.StatusCode)
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

	// carrier-a must have received an actual CANCEL — not just been
	// abandoned — once its ring timer expired.
	select {
	case <-carrierA.cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-a never received a CANCEL after its ring timeout expired")
	}

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}
	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}
	select {
	case <-carrierB.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-b dialog never ended after BYE")
	}
}

// ringTimeoutNoFailoverCfg routes to a single carrier that rings forever,
// with the same 300ms ring_timeout — proves the exhaustion fallback (408,
// not 503) when a ring timeout is the ONLY kind of failure seen across
// every target. Fresh ports (45265-45266, 46270-46273).
const ringTimeoutNoFailoverCfg = `
listen:
  sip: [udp://127.0.0.1:45265]
  media:
    port_range: 46270-46273
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45266
    allowed_ips: [203.0.113.48/30]
ring_timeout: 300ms
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeRingTimeoutNoTargetsReturns408 proves placeCall's exhaustion
// fallback: when every target's only failure is a ring timeout (no target
// ever produces a genuine failReal code), the caller gets 408 Request
// Timeout rather than the generic 503 — the same precedence slot failReal
// occupies, but one level below it (see placeCall's haveReal/haveRing
// switch).
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.
func TestBridgeRingTimeoutNoTargetsReturns408(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:45266", nil, stubCarrierConfig{ringForever: true})
	startServer(t, 45265, ringTimeoutNoFailoverCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45265}
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
	finalCode := sess.InviteResponse.StatusCode
	if finalCode != 408 {
		t.Fatalf("caller got %d, want 408 Request Timeout", finalCode)
	}

	select {
	case <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}
	select {
	case <-carrier.cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received a CANCEL after its ring timeout expired")
	}
}

// --- Whole-branch-review Fix wave: raced 2xx teardown, failReal restricted
// to real finals (401/407 -> 503), 502 for bad answer SDP ---

// authChallengeCfg routes local-uac to a single carrier peer with NO
// configured auth (an IP-auth trunk) that nonetheless challenges every
// INVITE with 401 Unauthorized — WaitAnswer only attempts its own digest
// retry when Password is non-empty (see authUser/authPass), so with no
// configured auth this 401 reaches dialTarget as a genuine final response
// it can't do anything about. Fresh ports (45270-45271, 46300-46303),
// disjoint from every other test's.
const authChallengeCfg = `
listen:
  sip: [udp://127.0.0.1:45270]
  media:
    port_range: 46300-46303
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45271
    allowed_ips: [203.0.113.60/30]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeAuthChallengeMapsTo503 is the whole-branch-review Fix 2's
// deterministic new coverage: a target's final response is 401
// Unauthorized (e.g. a carrier that unexpectedly challenges an IP-auth
// trunk, or whose challenge our credentials can't satisfy) and the peer
// has no configured auth, so WaitAnswer's own digest retry never engages
// (it only retries when opts.Password is non-empty — see
// AnswerOptions/authUser/authPass) — bLeg.InviteResponse ends up holding
// the bare 401 as its final response. Before the fix, dialTarget's
// classification trusted any non-provisional final (!IsProvisional()) as
// failReal and would have relayed this 401 to the caller verbatim — a
// hop-by-hop credential negotiation with the target that the caller can't
// act on. The fix excludes 401/407 from failReal, so this must reach the
// caller as 503 instead. (TestBridgePassesRealFinalCode/
// TestBridgeFailoverThenRealCode already cover the companion claim — a
// genuine >=300 final, e.g. 486, still reaches the caller verbatim.)
func TestBridgeAuthChallengeMapsTo503(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:45271", nil, stubCarrierConfig{
		finalStatus: 401,
		finalReason: "Unauthorized",
	})
	startServer(t, 45270, authChallengeCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45270}
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
	if finalCode := sess.InviteResponse.StatusCode; finalCode != 503 {
		t.Fatalf("caller got %d, want 503 (the target's 401 must not be relayed as-is)", finalCode)
	}

	select {
	case <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}
}

// brokenAnswerCfg routes local-uac to a single carrier that answers 200 OK
// but with an unparseable SDP body — see stubCarrierConfig.brokenAnswer.
// Fresh ports (45272-45273, 46310-46313), disjoint from every other
// test's.
const brokenAnswerCfg = `
listen:
  sip: [udp://127.0.0.1:45272]
  media:
    port_range: 46310-46313
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45273
    allowed_ips: [203.0.113.64/30]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeBrokenAnswerSDPGets502 is the whole-branch-review Fix 3's
// regression test: the carrier answers 200 OK for real — a live, billable
// carrier call — but its SDP body is unparseable, so processAnswerSDP
// fails. Before the fix, dialTarget responded the A-leg 488 Not Acceptable
// Here, which wrongly tells the caller ITS OWN offer was the problem; the
// fix responds 502 Bad Gateway, correctly attributing the failure to the
// upstream leg's answer. This also proves the B-leg is still torn down
// with a real ACK+BYE (ackThenBye) rather than abandoned: the carrier's
// dialog only ends, closing byeDone, once it has actually received that
// BYE.
func TestBridgeBrokenAnswerSDPGets502(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:45273", nil, stubCarrierConfig{
		brokenAnswer: true,
	})
	startServer(t, 45272, brokenAnswerCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45272}
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
	if finalCode := sess.InviteResponse.StatusCode; finalCode != 502 {
		t.Fatalf("caller got %d, want 502 (broken carrier answer SDP, not 488 which would blame the caller's own offer)", finalCode)
	}

	select {
	case <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}

	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended; B-leg was not ACKed+BYEed after the broken answer")
	}
}

// --- Task 6: routing gate skips unregistered register:true targets ---

// skipUnregisteredCfg routes local-uac to "carrier", a register:true peer.
// Its Address doubles as both the REGISTER target and the outbound call
// address (Registrar.paramsFor and peerURI both derive from the same
// config.Peer.Address — see sig/register.go), so pointing it at the stub
// carrier below both makes registration fail forever (the stub only
// installs OnInvite/OnAck/OnBye — no REGISTER handler — so sipgo's default
// no-route handler answers every REGISTER 405 Method Not Allowed, never
// 200) and lets the test observe whether an INVITE ever reaches it. Fresh
// port block (45290 sip / 45291 carrier / 46290-46293 media), disjoint from
// every other test's.
const skipUnregisteredCfg = `
listen:
  sip: [udp://127.0.0.1:45290]
  media:
    port_range: 46290-46293
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45291
    auth: { username: reguser, password: regpass }
    register: true
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeSkipsUnregisteredTarget proves Task 6's routing gate:
// placeCall must never dial a register:true target whose REGISTER has not
// succeeded. carrier is the ONLY target on the route, and its "registrar"
// (itself, per skipUnregisteredCfg's comment) never grants a 200, so
// Registrar.IsRegistered("carrier") stays false for the life of the test —
// the gate must skip it every time, leaving placeCall's failover loop with
// nothing dialed at all. With no target ever attempted, neither a real
// carrier failure (failReal) nor a ring timeout (failRing) is ever
// recorded, so placeCall's exhaustion default applies: 503 Service
// Unavailable to the caller. The stub carrier's offers channel staying
// empty proves the skip happened at the routing-gate level (before
// dialTarget ever ran), not that the carrier merely rejected an INVITE it
// received.
//
// Timing-based over real UDP loopback (waiting for the Registrar's Run
// goroutine to reconcile before placing the call): re-run once before
// treating a flake as failure.
func TestBridgeSkipsUnregisteredTarget(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:45291", nil)
	// startServer's own probe (dial the UDP port, then a short settle
	// sleep) already only returns once bindListener's accept/read loop is
	// live; b.s.registrar is assigned earlier in Run, in the same
	// goroutine, before any listener goroutine is even spawned, so the
	// INVITE this test sends below is guaranteed to be dispatched (via
	// sipgo's own request-handling goroutine, itself transitively spawned
	// from Run's goroutine — a real happens-before chain) after the
	// Registrar exists. No direct read of srv.registrar from this test
	// goroutine is needed (or safe: Run assigns it from its own goroutine
	// with no lock, so reading it straight from the test would race).
	startServer(t, 45290, skipUnregisteredCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45290}
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
	if got := sess.InviteResponse.StatusCode; got != 503 {
		t.Fatalf("caller got %d, want 503 (only target skipped: unregistered)", got)
	}

	select {
	case <-carrier.offers:
		t.Fatal("carrier received an INVITE — unregistered target was not skipped")
	case <-time.After(1 * time.Second):
	}
}

// --- M4.3 Task 4: session-timer headers on the A-leg 200 and B-leg INVITE ---

// sessionTimerCfg mirrors outboundFromCfg's shape on a disjoint port set
// (45180-45291/45410/45412 are already claimed by earlier tests in this
// file — see brokenAnswerCfg's comment for the highest prior block). No
// session_expires/min_se is set, so the config defaults apply (1800s /
// 90s — see config/schema.go's ApplyDefaults), which is exactly what the
// assertions below check for.
const sessionTimerCfg = `
listen:
  sip: [udp://127.0.0.1:45420]
  media:
    port_range: 46320-46323
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45421
    allowed_ips: [203.0.113.0/24]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// hasToken reports whether any of headers carries token (case-insensitive)
// among its comma-separated values — e.g. a Supported header listing
// "timer" or "100rel".
func hasToken(headers []sip.Header, token string) bool {
	for _, h := range headers {
		for _, tok := range strings.Split(h.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(tok), token) {
				return true
			}
		}
	}
	return false
}

// TestBridgeSessionTimerHeaders is M4.3 Task 4's crux: the caller's
// establishing 200 must carry Session-Expires;refresher=uac + Supported:
// timer, and the B-leg INVITE placed at the carrier must carry Supported:
// timer + Session-Expires;refresher=uas + Min-SE — but never Supported:
// 100rel (this bridge declines reliable provisional responses, Task 3).
// The A-leg INVITE here carries no Session-Expires of its own, so
// negotiateSE falls back to cfg.SessionExpires (1800s, the config
// default) on both legs — see sig/timers.go's negotiateSE.
func TestBridgeSessionTimerHeaders(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:45421", testSDPBody(uacRTPStubPort(t)))
	startServer(t, 45420, sessionTimerCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45420}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPStubPort(t)))
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
	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	select {
	case <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}

	// --- B-leg INVITE (carrier-side, captured by the stub) ---
	bSupported := carrier.lastHeaders("Supported")
	if !hasToken(bSupported, "timer") {
		t.Errorf("B-leg INVITE Supported = %v, want to include timer", bSupported)
	}
	if hasToken(bSupported, "100rel") {
		t.Errorf("B-leg INVITE Supported = %v, must NOT include 100rel (unsupported)", bSupported)
	}

	bSE := carrier.lastHeaders("Session-Expires")
	if len(bSE) != 1 {
		t.Fatalf("B-leg INVITE Session-Expires header count = %d, want 1", len(bSE))
	}
	if got, want := bSE[0].Value(), "1800;refresher=uas"; got != want {
		t.Errorf("B-leg INVITE Session-Expires = %q, want %q", got, want)
	}

	bMinSE := carrier.lastHeaders("Min-SE")
	if len(bMinSE) != 1 {
		t.Fatalf("B-leg INVITE Min-SE header count = %d, want 1", len(bMinSE))
	}
	if got, want := bMinSE[0].Value(), "90"; got != want {
		t.Errorf("B-leg INVITE Min-SE = %q, want %q", got, want)
	}

	// --- A-leg 200 (UAC-side, the caller's own establishing response) ---
	aSE := sess.InviteResponse.GetHeaders("Session-Expires")
	if len(aSE) != 1 {
		t.Fatalf("A-leg 200 Session-Expires header count = %d, want 1", len(aSE))
	}
	if got, want := aSE[0].Value(), "1800;refresher=uac"; got != want {
		t.Errorf("A-leg 200 Session-Expires = %q, want %q", got, want)
	}

	aSupported := sess.InviteResponse.GetHeaders("Supported")
	if !hasToken(aSupported, "timer") {
		t.Errorf("A-leg 200 Supported = %v, want to include timer", aSupported)
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
}

// minSERetryCfg sets a low session_expires (600s) so the B-leg's first
// INVITE undershoots startMinSERetryCarrier's 1800s floor, forcing exactly
// one 422 retry (M4.3 Task 5). Fresh ports (45422-45423, 46324-46327),
// disjoint from sessionTimerCfg's 45420-45421/46320-46323 block.
const minSERetryCfg = `
listen:
  sip: [udp://127.0.0.1:45422]
  media:
    port_range: 46324-46327
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45423
    allowed_ips: [203.0.113.0/24]
session_expires: 600s
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// startMinSERetryCarrier boots a stub UAS that declines any INVITE whose
// Session-Expires is below minSE with 422 Session Interval Too Small and a
// Min-SE header advertising minSE (RFC 4028 §5), and answers 200 with
// answerSDP once an INVITE meets it — the carrier side of M4.3 Task 5's
// retry: the bridge is expected to see this 422, read its Min-SE, and
// re-INVITE with a Session-Expires that satisfies it. Every INVITE (422'd or
// answered) is captured on offers/lastInvite exactly like startStubCarrier,
// so the test can inspect both the low first attempt and the raised retry.
func startMinSERetryCarrier(t *testing.T, addr string, answerSDP []byte, minSE time.Duration) *stubCarrier {
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
		c.mu.Lock()
		c.lastInvite = req
		c.mu.Unlock()

		if headerSeconds(req, "Session-Expires") < minSE {
			if err := dlg.Respond(422, "Session Interval Too Small", nil,
				sip.NewHeader("Min-SE", strconv.Itoa(int(minSE.Seconds())))); err != nil {
				log.Error("carrier respond 422", "err", err)
			}
			return
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
	t.Fatal("stub carrier (min-se-retry) did not start")
	return nil
}

// TestBridgeBLeg422RetriesWithMinSE is M4.3 Task 5's crux: minSERetryCfg's
// session_expires (600s) undershoots startMinSERetryCarrier's 1800s Min-SE
// floor, so the carrier 422s the bridge's first B-leg INVITE with
// Min-SE: 1800. dialTarget must read that Min-SE and retry the SAME target
// once with Session-Expires raised to meet it — the retry's 200 then flows
// into the ordinary bridge path exactly as if it had answered outright, so
// the caller still gets bridged rather than seeing the 422 or any failover
// churn. Timing-based over real UDP loopback: re-run once before treating a
// flake as failure.
func TestBridgeBLeg422RetriesWithMinSE(t *testing.T) {
	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrier := startMinSERetryCarrier(t, "127.0.0.1:45423", testSDPBody(echoRTPPort), 1800*time.Second)
	startServer(t, 45422, minSERetryCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45422}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPStubPort(t)))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()

	if err := sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v (call must bridge despite the carrier's 422, via the Min-SE retry)", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("got status %d, want 200", sess.InviteResponse.StatusCode)
	}
	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	// --- the carrier must have seen exactly two INVITEs: the low first
	// attempt (422'd) and the retry that met its Min-SE ---
	var first, second *sip.Request
	select {
	case first = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the first B-leg INVITE")
	}
	select {
	case second = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the retried B-leg INVITE")
	}

	if got := headerSeconds(first, "Session-Expires"); got != 600*time.Second {
		t.Errorf("first B-leg INVITE Session-Expires = %v, want 600s", got)
	}
	if got := headerSeconds(second, "Session-Expires"); got < 1800*time.Second {
		t.Errorf("retried B-leg INVITE Session-Expires = %v, want >= 1800s (the carrier's Min-SE)", got)
	}

	select {
	case <-carrier.offers:
		t.Fatal("carrier received a THIRD B-leg INVITE; retry must happen at most once")
	default:
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
}

// TestExpandTargetsResolvesEndpointsInOrder verifies expandTargets (M4.4
// Task 4) resolves a single Target's peer into its ordered endpoints and
// preserves the originating Target on each dialEndpoint, using a stubbed
// SRV lookup so the test doesn't depend on real DNS.
func TestExpandTargetsResolvesEndpointsInOrder(t *testing.T) {
	cfg, err := config.Parse([]byte(bridgeCallCfg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := NewServer(config.NewStore(cfg), nil, discardLogger())
	// expandTargets doesn't use the cfg's carrier peer here — we stub the
	// resolver and pass our own multi-endpoint peer.
	b := &bridge{s: s}

	peerA := &config.Peer{Address: "multi.example", Transport: "udp"}
	s.resolver.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{Target: "ep1.example.", Port: 5060, Priority: 10, Weight: 0},
			{Target: "ep2.example.", Port: 5061, Priority: 20, Weight: 0},
		}, nil
	}
	targets := []Target{{Name: "a", Peer: peerA}}
	des := b.expandTargets(targets)
	if len(des) != 2 {
		t.Fatalf("want 2 dialEndpoints, got %d: %+v", len(des), des)
	}
	if des[0].Endpoint.Host != "ep1.example" || des[1].Endpoint.Host != "ep2.example" {
		t.Errorf("endpoint order = [%s, %s], want [ep1.example, ep2.example]",
			des[0].Endpoint.Host, des[1].Endpoint.Host)
	}
	if des[0].Target.Name != "a" {
		t.Errorf("dialEndpoint lost its Target: %+v", des[0].Target)
	}
}

// TestExpandTargetsSkipsCooledEndpoints is Task 5's filter coverage: a
// cooled-down endpoint is skipped as long as some alternative is healthy,
// but cooldown is never a hard block — if every candidate is cooled,
// expandTargets dials them all anyway.
func TestExpandTargetsSkipsCooledEndpoints(t *testing.T) {
	cfg, err := config.Parse([]byte(bridgeCallCfg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := NewServer(config.NewStore(cfg), nil, discardLogger())
	b := &bridge{s: s}

	s.resolver.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{Target: "ep1.example.", Port: 5060, Priority: 10, Weight: 0},
			{Target: "ep2.example.", Port: 5061, Priority: 20, Weight: 0},
		}, nil
	}
	targets := []Target{{Name: "a", Peer: &config.Peer{Address: "multi.example", Transport: "udp"}}}

	// Cool down ep1: expandTargets returns only ep2.
	s.health.Penalize(Endpoint{Host: "ep1.example", Port: 5060, Transport: "udp"}, time.Hour)
	des := b.expandTargets(targets)
	if len(des) != 1 || des[0].Endpoint.Host != "ep2.example" {
		t.Fatalf("with ep1 cooled, want [ep2.example], got %+v", des)
	}

	// Cool down ep2 as well: everything is cooled → dial them ALL anyway.
	s.health.Penalize(Endpoint{Host: "ep2.example", Port: 5061, Transport: "udp"}, time.Hour)
	des = b.expandTargets(targets)
	if len(des) != 2 {
		t.Fatalf("all cooled → dial-anyway must return both, got %+v", des)
	}
}

// healthCfg routes local-uac → carrier, where carrier is addressed by a bare
// hostname (srvhost.test) so resolution goes through SRV (the resolver's
// lookupSRV is stubbed per-test — see
// TestBridgePenalizesDeadEndpointThenBridges). media_latch: loose matches
// the stub carrier's answer coming from a different address than the offer
// implied. ring_timeout is kept short as a general safety net for any
// attempt that DOES ring without answering (the dead-endpoint case in
// TestBridgePenalizesDeadEndpointThenBridges fails synchronously — see its
// comment — and so does not itself depend on this value).
const healthCfg = `
listen:
  sip: [udp://127.0.0.1:45191]
  media:
    port_range: 46210-46213
    public_ip: 127.0.0.1
ring_timeout: 3s
peer_cooldown: 60s
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: srvhost.test
    transport: udp
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// healthRecoverCfg is TestBridgeRecoversEndpointOnSuccess's config: it routes
// local-uac to a carrier addressed by a literal host:port (127.0.0.1:45301,
// an explicit port — see classifyAddress), which Resolve returns as exactly
// ONE endpoint, no SRV lookup involved. A single-endpoint peer is the point:
// with only one candidate, expandTargets' cooldown-is-skip-if-alternatives
// filter (Task 5) has no healthy alternative to prefer, so its dial-anyway
// fallback dials the sole endpoint regardless of its health state, and a
// successful bridge through it can only be explained by placeCall's
// post-answer Recover call actually firing (see the test).
const healthRecoverCfg = `
listen:
  sip: [udp://127.0.0.1:45300]
  media:
    port_range: 46300-46303
    public_ip: 127.0.0.1
ring_timeout: 3s
peer_cooldown: 60s
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:45301
    transport: udp
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgePenalizesDeadEndpointThenBridges proves the M4.4 health path's
// Penalize direction end to end: a peer resolving to [dead, live] fails over
// from the dead endpoint to the live one, and the dead endpoint is left in
// cooldown.
//
// Whole-branch-review Finding 2: earlier this test ALSO pre-penalized both
// endpoints before the call (to make the companion Recover assertion
// genuine — see TestBridgeRecoversEndpointOnSuccess, which now owns that
// assertion instead). That made the dead-endpoint-cooled assertion below
// vacuous: Available(dead) == false held from the pre-penalize alone,
// regardless of whether placeCall's own post-dial Penalize call ever ran —
// deleting that call from placeCall left the whole suite green. Neither
// endpoint is pre-penalized here anymore, so the dead endpoint starts (and
// is dialed) fully healthy; the ONLY thing that can cool it down by the time
// the call bridges is placeCall's genuine Penalize call on the dead
// attempt's failDial result. This test does not assert anything about the
// live endpoint's health — that direction is TestBridgeRecoversEndpointOnSuccess's.
func TestBridgePenalizesDeadEndpointThenBridges(t *testing.T) {
	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	// Live stub carrier on a real port. The "dead" endpoint's SRV target,
	// "deadhost..invalid." (note the DOUBLE dot — an empty DNS label), is
	// syntactically invalid per RFC 1035 (a label may not be empty): Go's
	// net package rejects it in-process ("no such host") before issuing any
	// query, under both the pure-Go and cgo resolvers alike (verified on
	// this machine: sub-millisecond, no network round trip). sipgo's client
	// therefore fails to resolve it and dialogCli.Invite() returns an error
	// immediately, so dialTarget's own `err != nil` branch fires — a fast,
	// deterministic, platform-portable failDial that depends on nothing but
	// DNS name syntax.
	//
	// Two alternatives were tried and rejected:
	//   - An unlistened 127.0.0.1 port (or 0.0.0.0, which on some platforms
	//     fails synchronously via the OS's "no route to host" but on Linux
	//     routes to loopback) is not portable: sipgo v1.4.3's UDP transport
	//     sends via an unconnected socket (net.ListenPacket + WriteTo), so a
	//     write to an unlistened loopback port never surfaces a synchronous
	//     error on every platform.
	//   - A name in the reserved .invalid TLD (RFC 6761, e.g.
	//     "deadhost.invalid") is NOT reliably unresolvable in every
	//     environment: this sandbox's resolver answers every hostname,
	//     including .invalid ones, with a synthetic address in the
	//     IANA-reserved benchmarking range (198.18.0.0/15) rather than
	//     NXDOMAIN. That address then never responds — but the ring-timeout
	//     fallback does NOT bound this the way it looks like it should:
	//     sipgo v1.4.3's WaitAnswer only cancels promptly on ctx expiry once
	//     at least one response (even a stray provisional) has been seen
	//     from the target; with none ever arriving, WaitAnswer instead blocks
	//     on the underlying INVITE transaction's own Timer B (RFC 3261,
	//     hardcoded 32s) or the caller's own context, whichever is shorter —
	//     confirmed experimentally: this test hung for its full 15s ctx
	//     budget and failed outright with .invalid. Only a failure at
	//     Invite() itself (before WaitAnswer is ever entered) sidesteps that
	//     quirk, which is why this must be a synchronous resolve failure,
	//     not a silent/unreachable one.
	const livePort = 45194
	const deadPort = 45195
	live := startStubCarrier(t, fmt.Sprintf("127.0.0.1:%d", livePort), testSDPBody(echoRTPPort))

	// A peer addressed by hostname so resolution goes through SRV; the SBC's
	// "carrier" peer in healthCfg uses address: srvhost.test (no port). The
	// resolver stub MUST be installed before Run starts handling calls —
	// startServerConfigured sets it inside NewServer→Run's happens-before
	// window (goroutine start), so -race sees no data race on lookupSRV.
	srv := startServerConfigured(t, 45191, healthCfg, func(s *Server) {
		s.resolver.lookupSRV = func(_, _, _ string) (string, []*net.SRV, error) {
			return "", []*net.SRV{
				{Target: "deadhost..invalid.", Port: deadPort, Priority: 10, Weight: 0}, // tried first — invalid DNS syntax, never resolves
				{Target: "127.0.0.1.", Port: livePort, Priority: 20, Weight: 0},         // fallback
			}, nil
		}
	})

	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	uacUA, _ := sipgo.NewUA()
	defer uacUA.Close()
	uacClient, _ := sipgo.NewClient(uacUA, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	defer uacClient.Close()
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	// Neither endpoint is pre-penalized (Finding 2's fix — see the doc
	// comment above): both start healthy, so expandTargets' one-time
	// snapshot at the top of placeCall's failover loop returns them in
	// priority order [dead, live] via its normal "available" branch, no
	// dial-anyway fallback involved. dead is tried first and fails to
	// connect (invalid DNS syntax — see the comment above on
	// "deadhost..invalid."); live is tried second and bridges.
	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45191}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sess, err := dialogCli.Invite(ctx, bridgeURI, testSDPBody(uacRTPPort))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()
	if err := sess.WaitAnswer(ctx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (should bridge on the live endpoint)", sess.InviteResponse.StatusCode)
	}
	select {
	case <-live.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("live carrier never received the B-leg INVITE")
	}
	_ = sess.Ack(context.Background())

	// The dead endpoint must now be in cooldown. Unlike the live/Recover
	// check this replaced (moved to TestBridgeRecoversEndpointOnSuccess),
	// this needs no poll: placeCall's Penalize call on the dead attempt runs
	// synchronously, inside the SAME goroutine, well before the live attempt
	// is even dialed — let alone before the A-leg's 200 OK reaches this
	// client — so by the time WaitAnswer above returned, Penalize has
	// already run (or, under the deleted-Penalize regression, provably has
	// not: nothing else in this test ever touches the dead endpoint's health,
	// so Available(dead) staying true is exactly the signal that guard is
	// gone).
	dead := Endpoint{Host: "deadhost..invalid", Port: deadPort, Transport: "udp"}
	if srv.health.Available(dead) {
		t.Error("dead endpoint should be cooled down after failDial")
	}

	_ = sess.Bye(context.Background())
	waitForActiveCalls(t, srv, 0, 5*time.Second)
}

// TestBridgeRecoversEndpointOnSuccess proves the M4.4 health path's Recover
// direction end to end, split out of TestBridgePenalizesDeadEndpointThenBridges
// (Finding 2): a peer resolving to exactly ONE endpoint (see healthRecoverCfg)
// — the live stub carrier — is pre-penalized before the call. Because it is
// the only candidate, expandTargets' dial-anyway fallback (Task 5: cooldown
// is skip-if-alternatives, never a hard block) dials it anyway despite the
// cooldown; the call bridges, and placeCall's post-answer Recover call is the
// ONLY thing that can explain Available(live) == true afterward — nothing
// else in this test ever touches its health. Deleting placeCall's Recover
// call makes this test fail.
func TestBridgeRecoversEndpointOnSuccess(t *testing.T) {
	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	const livePort = 45301
	live := startStubCarrier(t, fmt.Sprintf("127.0.0.1:%d", livePort), testSDPBody(echoRTPPort))

	srv := startServer(t, 45300, healthRecoverCfg)

	liveEndpoint := Endpoint{Host: "127.0.0.1", Port: livePort, Transport: "udp"}
	// Pre-penalize the only endpoint this peer resolves to, BEFORE the
	// INVITE: this is what makes the post-call Available(live) == true
	// assertion below genuine rather than trivially true (see the doc
	// comment above).
	srv.health.Penalize(liveEndpoint, time.Hour)

	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	uacUA, _ := sipgo.NewUA()
	defer uacUA.Close()
	uacClient, _ := sipgo.NewClient(uacUA, sipgo.WithClientConnectionAddr("127.0.0.1:0"))
	defer uacClient.Close()
	dialogCli := sipgo.NewDialogClientCache(uacClient, sip.ContactHeader{})

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45300}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sess, err := dialogCli.Invite(ctx, bridgeURI, testSDPBody(uacRTPPort))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()
	if err := sess.WaitAnswer(ctx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (should dial-anyway the sole, pre-penalized endpoint and bridge)", sess.InviteResponse.StatusCode)
	}
	select {
	case <-live.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("live carrier never received the B-leg INVITE")
	}
	_ = sess.Ack(context.Background())

	// dialTarget's aLeg.Respond (the 200 OK above) blocks server-side until
	// OUR ACK is processed, and only then does dialTarget return so placeCall
	// can call Recover — but sess.Ack just fires the ACK packet and returns,
	// without waiting for the server to finish processing it, so there is a
	// short unavoidable race between "ACK sent" and "Recover has run"; poll
	// briefly, but the final assertion is unconditional.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !srv.health.Available(liveEndpoint) {
		time.Sleep(10 * time.Millisecond)
	}
	if !srv.health.Available(liveEndpoint) {
		t.Fatal("live endpoint should be Recovered after a successful bridge, despite being pre-penalized")
	}

	_ = sess.Bye(context.Background())
	waitForActiveCalls(t, srv, 0, 5*time.Second)
}

// --- M5 Task 6: per-leg SDES/SRTP negotiation ---
//
// These tests use raw github.com/pion/srtp/v3 contexts directly (rather than
// media.SRTPContext, whose protect/unprotect methods are unexported outside
// package media) to encrypt/decrypt real RTP on the test side — proving the
// bridge performs GENUINE SRTP<->RTP interworking and per-leg key
// separation, not just passing bytes through unchanged.

// rawRTPPacket builds a minimal 12-byte-header RTP packet (V=2, no
// extensions/CSRCs) carrying payload as its body — just enough structure for
// pion/srtp to protect/unprotect.
func rawRTPPacket(seq uint16, ssrc uint32, payload string) []byte {
	pkt := make([]byte, 12+len(payload))
	pkt[0] = 0x80 // V=2, P=0, X=0, CC=0
	pkt[1] = 0    // M=0, PT=0 (PCMU)
	binary.BigEndian.PutUint16(pkt[2:4], seq)
	binary.BigEndian.PutUint32(pkt[4:8], uint32(seq)*160) // arbitrary timestamp
	binary.BigEndian.PutUint32(pkt[8:12], ssrc)
	copy(pkt[12:], payload)
	return pkt
}

// newTestSRTPContext builds a raw pion srtp.Context directly from a 30-byte
// SDES inline value, mirroring media.NewSRTPContext's own profile selection
// and key/salt split exactly (see media/srtp.go) — usable from this test
// package, which has no access to media.SRTPContext's unexported
// protect/unprotect methods.
func newTestSRTPContext(t *testing.T, suite media.CryptoSuite, keyValue []byte) *srtp.Context {
	t.Helper()
	profile := srtp.ProtectionProfileAes128CmHmacSha1_80
	if suite == media.SuiteAES128CM32 {
		profile = srtp.ProtectionProfileAes128CmHmacSha1_32
	}
	ctx, err := srtp.CreateContext(keyValue[:16], keyValue[16:30], profile)
	if err != nil {
		t.Fatalf("test srtp context: %v", err)
	}
	return ctx
}

// testSDPBodySAVP is testSDPBody plus RTP/SAVP and a single a=crypto line
// advertising keyValue — an SRTP offer/answer whose audio media points at
// 127.0.0.1:port.
func testSDPBodySAVP(port int, suite media.CryptoSuite, keyValue []byte) []byte {
	return []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"c=IN IP4 127.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=audio " + strconv.Itoa(port) + " RTP/SAVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=crypto:" + cryptoAttrValue(1, suite, keyValue) + "\r\n")
}

// sendUntilSRTPArrives repeatedly encrypts a FRESH copy (a new sequence
// number each attempt, to dodge pion/srtp's replay-window rejection of a
// resent packet) of a test RTP packet carrying payload with ctx, and sends
// it from src to dst, until any datagram arrives on recv — returned raw,
// undecrypted, since callers need to assert different things about it
// (exact plaintext for an interworking peer, still-protected-and-decryptable-
// only-with-the-right-key for a secure peer) — or fails the test after 5s.
func sendUntilSRTPArrives(t *testing.T, ctx *srtp.Context, src *net.UDPConn, dst *net.UDPAddr, recv *net.UDPConn, payload string) []byte {
	t.Helper()
	buf := make([]byte, 1500)
	deadline := time.Now().Add(5 * time.Second)
	seq := uint16(1000)
	for time.Now().Before(deadline) {
		plain := rawRTPPacket(seq, 0xCAFEBABE, payload)
		seq++
		protected, err := ctx.EncryptRTP(nil, plain, nil)
		if err != nil {
			t.Fatalf("srtp encrypt: %v", err)
		}
		if _, err := src.WriteToUDP(protected, dst); err != nil {
			t.Fatalf("write srtp packet: %v", err)
		}
		_ = recv.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, _, err := recv.ReadFromUDP(buf)
		if err == nil {
			return append([]byte(nil), buf[:n]...)
		}
	}
	t.Fatalf("srtp-encrypted payload %q never arrived at recv", payload)
	return nil
}

// srtpRequiredACfg (TestBridgeSRTPRequiredCallerNoCryptoGets488): local-uac
// has srtp: required; the route target is never actually reachable-relevant
// since the test's offer is plaintext and must be rejected before any
// B-leg is dialed.
const srtpRequiredACfg = `
listen:
  sip: [udp://127.0.0.1:45500]
  media:
    port_range: 46500-46503
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
    srtp: required
  carrier:
    address: 127.0.0.1:45502
    allowed_ips: [203.0.113.0/24]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeSRTPRequiredCallerNoCryptoGets488 proves "required" never
// silently downgrades to plaintext on the A-leg: a caller offering plain
// RTP/AVP against a peer configured srtp: required gets 488 Not Acceptable
// Here, and — critically — the carrier never even sees a B-leg INVITE,
// since the rejection happens in onInvite before any target is dialed.
func TestBridgeSRTPRequiredCallerNoCryptoGets488(t *testing.T) {
	carrier := startStubCarrier(t, "127.0.0.1:45502", testSDPBody(uacRTPStubPort(t)))
	startServer(t, 45500, srtpRequiredACfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45500}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, testSDPBody(uacRTPStubPort(t)))
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()

	err = sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{})
	if err == nil {
		t.Fatalf("uac wait answer: expected failure (488), got success (status %d)", sess.InviteResponse.StatusCode)
	}
	if sess.InviteResponse == nil {
		t.Fatalf("uac never received a final response: %v", err)
	}
	if sess.InviteResponse.StatusCode != 488 {
		t.Errorf("status = %d, want 488 (srtp required by local-uac's policy, caller offered plaintext)", sess.InviteResponse.StatusCode)
	}

	// The rejection happens entirely in onInvite, before any B-leg is even
	// dialed — the carrier must never see an INVITE.
	select {
	case <-carrier.offers:
		t.Fatal("carrier received a B-leg INVITE; the A-leg should have been rejected with 488 before any target was dialed")
	case <-time.After(300 * time.Millisecond):
	}
}

// srtpInterworkCfg (TestBridgeSRTPInterworksSecureAToPlaintextB): local-uac
// is srtp: required (A-leg must be secure); carrier is srtp's normalized
// default, "disabled" (B-leg must stay plaintext) — proving the bridge
// interworks between a secure caller and a plaintext carrier rather than
// propagating one leg's policy onto the other.
const srtpInterworkCfg = `
listen:
  sip: [udp://127.0.0.1:45510]
  media:
    port_range: 46510-46513
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
    srtp: required
  carrier:
    address: 127.0.0.1:45512
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeSRTPInterworksSecureAToPlaintextB is the milestone's SRTP
// interworking crux: the caller offers real SRTP (RTP/SAVP + a=crypto,
// required by local-uac's policy); the carrier peer is srtp: disabled, so
// the bridge must offer it plain RTP/AVP with no crypto attribute at all.
// End to end: a packet the caller encrypts with its own negotiated key
// arrives at the carrier's socket as genuine, already-decrypted plaintext
// RTP — proving real SRTP<->RTP interworking, not a byte pass-through.
func TestBridgeSRTPInterworksSecureAToPlaintextB(t *testing.T) {
	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45513})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrier := startStubCarrier(t, "127.0.0.1:45512", testSDPBody(echoRTPPort))
	startServer(t, 45510, srtpInterworkCfg)

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

	aKey, err := newCryptoKeyValue()
	if err != nil {
		t.Fatalf("gen a-leg key: %v", err)
	}
	offer := testSDPBodySAVP(uacRTPPort, media.SuiteAES128CM80, aKey)

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45510}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, offer)
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()
	if err := sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", sess.InviteResponse.StatusCode)
	}

	answerBody := sess.InviteResponse.Body()
	secure, lines := offeredCrypto(answerBody)
	if !secure || len(lines) == 0 {
		t.Fatalf("a-leg answer is not RTP/SAVP+a=crypto:\n%s", answerBody)
	}
	sel, ok := selectCrypto(lines)
	if !ok {
		t.Fatalf("a-leg answer crypto line unusable:\n%s", answerBody)
	}
	if string(sel.keyValue) == string(aKey) {
		t.Errorf("a-leg answer echoes the caller's own key; the SBC must advertise its own freshly generated key")
	}
	sideAPort := sdpAudioPort(t, answerBody)

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	var carrierOffer *sip.Request
	select {
	case carrierOffer = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}
	// carrier ("disabled" srtp) must have been offered plaintext RTP/AVP,
	// with no a=crypto at all — proving the bridge did not propagate the
	// A-leg's SRTP requirement onto a peer whose policy says plaintext.
	if bSecure, bLines := offeredCrypto(carrierOffer.Body()); bSecure || len(bLines) != 0 {
		t.Fatalf("b-leg offer is secure/has a=crypto, want plaintext (carrier peer is srtp: disabled):\n%s", carrierOffer.Body())
	}
	sideBPort := sdpAudioPort(t, carrierOffer.Body())

	sideAAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideAPort}
	sideBAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideBPort}

	// Arm side B's (loose) latch before relying on the A->B direction: the
	// relay only forwards to a side once that side's own latch has recorded
	// a remote target from an actually-received packet (see media/relay.go
	// forward's outLatch.target() check) — same pattern as
	// TestBridgePlacesCallAndBridges.
	if _, err := echoRTP.WriteToUDP([]byte("arm-b"), sideBAddr); err != nil {
		t.Fatalf("arm side b: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// The caller encrypts with aKey (the key it advertised) — the bridge's
	// A-inbound context was built from that same key in onInvite. The
	// carrier's socket must receive the DECRYPTED plaintext, unmodified: an
	// exact plaintext RTP packet, never the still-encrypted bytes.
	aCtx := newTestSRTPContext(t, media.SuiteAES128CM80, aKey)
	const payload = "ping-a-to-b"
	got := sendUntilSRTPArrives(t, aCtx, uacRTP, sideAAddr, echoRTP, payload)
	wantLen := 12 + len(payload)
	if len(got) != wantLen {
		t.Fatalf("carrier received %d bytes, want %d (a plain RTP packet — a longer packet means the bridge relayed still-SRTP-protected bytes instead of decrypting)", len(got), wantLen)
	}
	if got[0] != 0x80 {
		t.Fatalf("carrier received malformed RTP header byte %#x, want 0x80", got[0])
	}
	if string(got[12:]) != payload {
		t.Fatalf("carrier payload = %q, want %q", got[12:], payload)
	}

	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}
	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE")
	}
}

// srtpBothSecureCfg (TestBridgeSRTPBothLegsSecure): local-uac srtp:
// required, carrier srtp: required — both legs must end up SRTP, with
// independently generated keys.
const srtpBothSecureCfg = `
listen:
  sip: [udp://127.0.0.1:45515]
  media:
    port_range: 46516-46519
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
    srtp: required
  carrier:
    address: 127.0.0.1:45517
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
    srtp: required
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgeSRTPBothLegsSecure proves both-legs-secure negotiation end to
// end with genuinely DIFFERENT per-leg keys: the caller's A-leg key, the
// SBC's own A-outbound key, the SBC's own B-offer key, and the carrier's
// B-answer key are four independent values, and a packet the caller
// encrypts is only decryptable on the carrier's side with the SBC's B-offer
// key — decrypting the same bytes with the caller's OWN key must fail,
// which is the crux proof that keys are never copied between legs.
func TestBridgeSRTPBothLegsSecure(t *testing.T) {
	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45518})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	bAnswerKey, err := newCryptoKeyValue()
	if err != nil {
		t.Fatalf("gen b-leg answer key: %v", err)
	}
	carrier := startStubCarrier(t, "127.0.0.1:45517", testSDPBodySAVP(echoRTPPort, media.SuiteAES128CM80, bAnswerKey))
	startServer(t, 45515, srtpBothSecureCfg)

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

	aKey, err := newCryptoKeyValue()
	if err != nil {
		t.Fatalf("gen a-leg key: %v", err)
	}
	offer := testSDPBodySAVP(uacRTPPort, media.SuiteAES128CM80, aKey)

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45515}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, offer)
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()
	if err := sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", sess.InviteResponse.StatusCode)
	}

	answerBody := sess.InviteResponse.Body()
	aSecure, aAnswerLines := offeredCrypto(answerBody)
	if !aSecure || len(aAnswerLines) == 0 {
		t.Fatalf("a-leg answer is not RTP/SAVP+a=crypto:\n%s", answerBody)
	}
	aAnswerSel, ok := selectCrypto(aAnswerLines)
	if !ok {
		t.Fatalf("a-leg answer crypto line unusable:\n%s", answerBody)
	}
	sideAPort := sdpAudioPort(t, answerBody)

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	var carrierOffer *sip.Request
	select {
	case carrierOffer = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}
	bSecure, bOfferLines := offeredCrypto(carrierOffer.Body())
	if !bSecure || len(bOfferLines) == 0 {
		t.Fatalf("b-leg offer is not RTP/SAVP+a=crypto (carrier peer is srtp: required):\n%s", carrierOffer.Body())
	}
	bOfferSel, ok := selectCrypto(bOfferLines)
	if !ok {
		t.Fatalf("b-leg offer crypto line unusable:\n%s", carrierOffer.Body())
	}
	sideBPort := sdpAudioPort(t, carrierOffer.Body())

	// Four independent keys: the caller's own, the SBC's A-outbound
	// (advertised in the A-answer), the SBC's B-outbound (advertised in the
	// B-offer), and the carrier's own (advertised in the B-answer, fixed
	// above as bAnswerKey). None may collide.
	keys := map[string]string{
		"caller a-key":       string(aKey),
		"sbc a-outbound key": string(aAnswerSel.keyValue),
		"sbc b-outbound key": string(bOfferSel.keyValue),
		"carrier b-key":      string(bAnswerKey),
	}
	seen := map[string]string{}
	for name, k := range keys {
		if other, dup := seen[k]; dup {
			t.Fatalf("key collision: %q and %q share the same key value; every leg's key must be independently generated", name, other)
		}
		seen[k] = name
	}

	sideAAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideAPort}
	sideBAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideBPort}

	// Arm side B's (loose) latch before relying on the A->B direction (see
	// the interworking test's identical comment).
	if _, err := echoRTP.WriteToUDP([]byte("arm-b"), sideBAddr); err != nil {
		t.Fatalf("arm side b: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	aCtx := newTestSRTPContext(t, media.SuiteAES128CM80, aKey)
	const payload = "ping-a-to-b"
	got := sendUntilSRTPArrives(t, aCtx, uacRTP, sideAAddr, echoRTP, payload)

	// The relayed packet must still be SRTP-protected (larger than a plain
	// RTP packet by the suite-80 10-byte auth tag) — a plaintext leak here
	// would mean the bridge failed to re-encrypt toward a required-srtp B
	// peer.
	plainLen := 12 + len(payload)
	if len(got) <= plainLen {
		t.Fatalf("carrier received %d bytes, want > %d (still SRTP-protected)", len(got), plainLen)
	}

	bCtx := newTestSRTPContext(t, bOfferSel.suite, bOfferSel.keyValue)
	decrypted, err := bCtx.DecryptRTP(nil, got, nil)
	if err != nil {
		t.Fatalf("decrypt with the b-leg's own negotiated key: %v", err)
	}
	if string(decrypted[12:]) != payload {
		t.Fatalf("decrypted payload = %q, want %q", decrypted[12:], payload)
	}

	// The crux: decrypting the SAME bytes with the CALLER's own A-leg key
	// must fail — proving the bridge used an independently generated
	// B-outbound key, never the caller's key relayed straight through.
	wrongCtx := newTestSRTPContext(t, bOfferSel.suite, aKey)
	if _, err := wrongCtx.DecryptRTP(nil, got, nil); err == nil {
		t.Fatal("decrypted the b-leg packet with the a-leg's own key; the SBC must use independently generated keys per leg")
	}

	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}
	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE")
	}
}

// srtpRequiredBFailoverCfg (TestBridgeSRTPRequiredBNoCryptoFailsOver): both
// carrier targets are srtp: required, but the stub carriers in the test
// answer plain RTP/AVP — neither meets policy, so the bridge must fail over
// from carrier-a to carrier-b and, once both are exhausted, give the caller
// a non-2xx rather than ever bridging plaintext against a required policy.
const srtpRequiredBFailoverCfg = `
listen:
  sip: [udp://127.0.0.1:45520]
  media:
    port_range: 46520-46523
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier-a:
    address: 127.0.0.1:45521
    allowed_ips: [203.0.113.20/30]
    srtp: required
  carrier-b:
    address: 127.0.0.1:45522
    allowed_ips: [203.0.113.24/30]
    srtp: required
routes:
  - name: out
    from: local-uac
    to: [carrier-a, carrier-b]
`

// TestBridgeSRTPRequiredBNoCryptoFailsOver proves "required" never silently
// downgrades to plaintext on the B-leg either: both failover targets are
// srtp: required but answer plaintext, so EACH is a live, billable 2xx that
// the bridge must tear down (ACK+BYE) as unusable under policy and fail
// over from — not something it bridges anyway or gives up on after the
// first target.
func TestBridgeSRTPRequiredBNoCryptoFailsOver(t *testing.T) {
	carrierA := startStubCarrier(t, "127.0.0.1:45521", testSDPBody(uacRTPStubPort(t)))
	carrierB := startStubCarrier(t, "127.0.0.1:45522", testSDPBody(uacRTPStubPort(t)))
	startServer(t, 45520, srtpRequiredBFailoverCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45520}
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
	if sess.InviteResponse.StatusCode/100 == 2 {
		t.Fatalf("status = %d, want a non-2xx (both targets require srtp but answered plaintext — failover must exhaust, never bridge plaintext)", sess.InviteResponse.StatusCode)
	}

	select {
	case <-carrierA.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-a never received the B-leg INVITE")
	}
	select {
	case <-carrierB.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-b never received the B-leg INVITE (bridge must fail over from carrier-a's srtp mismatch, not give up after one target)")
	}

	// Both targets answered (2xx, billable) but were then torn down for
	// failing the srtp policy — their dialogs must end cleanly (ACK+BYE),
	// not leak.
	select {
	case <-carrierA.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-a dialog never torn down after its srtp mismatch")
	}
	select {
	case <-carrierB.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-b dialog never torn down after its srtp mismatch")
	}
}

// srtpPlaintextUnchangedCfg (TestBridgePlaintextUnchanged): both peers
// explicitly srtp: disabled — the same as the pre-M5 default, spelled out
// here so the test documents the regression it's guarding rather than
// relying on the zero value.
const srtpPlaintextUnchangedCfg = `
listen:
  sip: [udp://127.0.0.1:45530]
  media:
    port_range: 46530-46533
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
    srtp: disabled
  carrier:
    address: 127.0.0.1:45532
    allowed_ips: [203.0.113.0/24]
    srtp: disabled
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// TestBridgePlaintextUnchanged is the M5 regression guard: two srtp:
// disabled peers must bridge EXACTLY as pre-M5 — not merely "still
// plaintext," but byte-for-byte identical to the plain (non-crypto-aware)
// rewriteSDP output on both the A-answer and the B-offer, proving the SRTP
// wiring is purely additive and never perturbs the disabled path.
func TestBridgePlaintextUnchanged(t *testing.T) {
	uacRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("uac rtp socket: %v", err)
	}
	defer uacRTP.Close()
	uacRTPPort := uacRTP.LocalAddr().(*net.UDPAddr).Port

	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45533})
	if err != nil {
		t.Fatalf("carrier echo rtp socket: %v", err)
	}
	defer echoRTP.Close()
	echoRTPPort := echoRTP.LocalAddr().(*net.UDPAddr).Port

	carrierAnswer := testSDPBody(echoRTPPort)
	carrier := startStubCarrier(t, "127.0.0.1:45532", carrierAnswer)
	startServer(t, 45530, srtpPlaintextUnchangedCfg)

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

	bridgeURI := sip.Uri{User: "5551234", Host: "127.0.0.1", Port: 45530}
	inviteCtx, cancelInvite := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInvite()

	offer := testSDPBody(uacRTPPort)
	sess, err := dialogCli.Invite(inviteCtx, bridgeURI, offer)
	if err != nil {
		t.Fatalf("uac invite: %v", err)
	}
	defer sess.Close()
	if err := sess.WaitAnswer(inviteCtx, sipgo.AnswerOptions{}); err != nil {
		t.Fatalf("uac wait answer: %v", err)
	}
	if sess.InviteResponse.StatusCode != 200 {
		t.Fatalf("status %d, want 200", sess.InviteResponse.StatusCode)
	}
	answerBody := sess.InviteResponse.Body()

	if secure, lines := offeredCrypto(answerBody); secure || len(lines) != 0 {
		t.Fatalf("answer is secure (RTP/SAVP or has a=crypto), want plain RTP/AVP for two srtp:disabled peers:\n%s", answerBody)
	}

	// Byte-for-byte identical to the pre-M5 rewriteSDP path.
	sideAPort := sdpAudioPort(t, answerBody)
	wantAnswer, err := rewriteSDP(carrierAnswer, netip.MustParseAddr("127.0.0.1"), sideAPort)
	if err != nil {
		t.Fatalf("rewriteSDP reference (answer): %v", err)
	}
	if string(answerBody) != string(wantAnswer) {
		t.Errorf("answer body diverges from plain rewriteSDP output:\ngot:\n%s\nwant:\n%s", answerBody, wantAnswer)
	}

	if err := sess.Ack(context.Background()); err != nil {
		t.Fatalf("uac ack: %v", err)
	}

	var carrierOffer *sip.Request
	select {
	case carrierOffer = <-carrier.offers:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never received the B-leg INVITE")
	}
	sideBPort := sdpAudioPort(t, carrierOffer.Body())
	wantOffer, err := rewriteSDP(offer, netip.MustParseAddr("127.0.0.1"), sideBPort)
	if err != nil {
		t.Fatalf("rewriteSDP reference (offer): %v", err)
	}
	if string(carrierOffer.Body()) != string(wantOffer) {
		t.Errorf("b-leg offer diverges from plain rewriteSDP output:\ngot:\n%s\nwant:\n%s", carrierOffer.Body(), wantOffer)
	}

	sideAAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideAPort}
	sideBAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sideBPort}

	// Arm side B's latch before relying on the A->B direction (see
	// TestBridgePlacesCallAndBridges's identical comment/pattern).
	if _, err := echoRTP.WriteToUDP([]byte("arm-b"), sideBAddr); err != nil {
		t.Fatalf("arm side b: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	sendUntilReceived(t, uacRTP, sideAAddr, echoRTP, "ping-a-to-b")
	sendUntilReceived(t, echoRTP, sideBAddr, uacRTP, "pong-b-to-a")

	if err := sess.Bye(context.Background()); err != nil {
		t.Fatalf("uac bye: %v", err)
	}
	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier dialog never ended after BYE")
	}
}
