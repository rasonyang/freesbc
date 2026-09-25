package trunk

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// readUntil collects datagrams on conn until one starts with prefix or the
// timeout elapses, returning everything read.
func readUntil(t *testing.T, conn *net.UDPConn, prefix string, timeout time.Duration) (string, bool) {
	t.Helper()
	var got strings.Builder
	buf := make([]byte, 8192)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		got.WriteString("\n---\n")
		if strings.HasPrefix(string(buf[:n]), prefix) {
			return got.String(), true
		}
	}
	return got.String(), false
}

const mergedInviteCfg = `
listen:
  sip: [udp://127.0.0.1:13140]
  media:
    port_range: 13144-13151
    public_ip: 127.0.0.1
ring_timeout: 5s
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:13141
    allowed_ips: [203.0.113.0/24]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// audit: P2-TRK-002
// RFC 3261 §8.2.2.2: the same initial INVITE (Call-ID, From-tag, CSeq)
// arriving a second time on a different branch while the first is still
// being handled is a merged request and gets 482, not a second call.
func TestMergedInviteGets482(t *testing.T) {
	// carrier (13141) is left unbound, so the first INVITE stays in
	// progress (dialing a silent target) for the whole test.
	startServer(t, 13140, mergedInviteCfg)

	uac, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uac.Close()
	local := uac.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 13140}

	const callID = "merged-invite-1"
	first := sipInviteWithSDP(callID, local, testSDPBody(uacRTPStubPort(t)), 13140)
	if _, err := uac.WriteToUDP([]byte(first), dst); err != nil {
		t.Fatal(err)
	}
	if got, ok := readUntil(t, uac, "SIP/2.0 100", 2*time.Second); !ok {
		t.Fatalf("first INVITE got no 100 Trying:\n%s", got)
	}

	second := strings.Replace(first, "branch=z9hG4bK-"+callID, "branch=z9hG4bK-"+callID+"-fork2", 1)
	if _, err := uac.WriteToUDP([]byte(second), dst); err != nil {
		t.Fatal(err)
	}
	got, ok := readUntil(t, uac, "SIP/2.0 482", 2*time.Second)
	if !ok {
		t.Fatalf("merged INVITE (same Call-ID/From-tag/CSeq, new branch) must get 482, got:\n%s", got)
	}
	if !strings.Contains(got, "fork2") {
		t.Errorf("482 is not on the second branch:\n%s", got)
	}

	// Tidy up the first call.
	if _, err := uac.WriteToUDP([]byte(sipCancel(callID, local, 13140)), dst); err != nil {
		t.Fatal(err)
	}
	if got, ok := readUntil(t, uac, "SIP/2.0 487", 3*time.Second); !ok {
		t.Fatalf("first INVITE not terminated after CANCEL:\n%s", got)
	}
}

const dialogErrorsCfg = `
listen:
  sip: [udp://127.0.0.1:13160]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: in
    from: local-uac
    to: [local-uac]
`

// audit: P2-TRK-013
// RFC 3261 §12.2.2: an in-dialog INVITE (To-tag present) whose dialog does
// not exist gets 481, so a UA that lost its dialog tears it down.
func TestUnknownDialogReInviteGets481(t *testing.T) {
	startServer(t, 13160, dialogErrorsCfg)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := strings.Replace(sipRequest("INVITE", "13160", conn.LocalAddr().(*net.UDPAddr), "no-such-dialog-1"),
		"To: <sip:sbc@127.0.0.1>", "To: <sip:sbc@127.0.0.1>;tag=random-to-tag", 1)
	if _, err := conn.WriteToUDP([]byte(req), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 13160}); err != nil {
		t.Fatal(err)
	}
	if got, ok := readUntil(t, conn, "SIP/2.0 481", 3*time.Second); !ok {
		t.Fatalf("re-INVITE for an unknown dialog must get 481, got:\n%s", got)
	}
}

// audit: P2-TRK-014
// RFC 3261 §9.2: a CANCEL that matches no INVITE transaction gets 481, not
// 405 (CANCEL is supported).
func TestUnmatchedCancelGets481(t *testing.T) {
	cfg := strings.Replace(dialogErrorsCfg, "13160", "13161", 1)
	startServer(t, 13161, cfg)
	got := roundTrip(t, 13161, "CANCEL", "no-such-invite-1", 3*time.Second, "SIP/2.0 481")
	if !strings.Contains(got, "SIP/2.0 481") {
		t.Fatalf("unmatched CANCEL must get 481, got:\n%s", got)
	}
	if strings.Contains(got, "SIP/2.0 405") {
		t.Fatalf("unmatched CANCEL must not get 405, got:\n%s", got)
	}
}

// recordingTx is a sip.ServerTransaction that records the status codes
// responded on it. Only Respond is implemented.
type recordingTx struct {
	sip.ServerTransaction
	mu    sync.Mutex
	codes []int
}

func (r *recordingTx) Respond(res *sip.Response) error {
	r.mu.Lock()
	r.codes = append(r.codes, res.StatusCode)
	r.mu.Unlock()
	return nil
}

func (r *recordingTx) got() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.codes...)
}

// audit: P2-TRK-003
// A panic in onInvite before any final response was sent must still answer
// the INVITE (500, RFC 3261 §8.2 / §17.2.1) instead of leaving the caller's
// transaction to time out; after a final response it must send nothing
// more.
func TestRecoverCallAnswers500BeforeFinal(t *testing.T) {
	s := auditBareServer(t)
	msg, err := sip.ParseMessage([]byte(sipRequest("INVITE", "5060", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5070}, "panic-call-1")))
	if err != nil {
		t.Fatal(err)
	}
	req := msg.(*sip.Request)

	rec := &recordingTx{}
	func() {
		defer s.recoverCall(req, &callGuard{tx: &finalTx{ServerTransaction: rec}})
		panic("boom before any final")
	}()
	if got := rec.got(); len(got) != 1 || got[0] != 500 {
		t.Fatalf("panic before a final response: responses = %v, want [500]", got)
	}

	rec = &recordingTx{}
	ftx := &finalTx{ServerTransaction: rec}
	func() {
		defer s.recoverCall(req, &callGuard{tx: ftx})
		_ = ftx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
		panic("boom after a final")
	}()
	if got := rec.got(); len(got) != 1 || got[0] != 486 {
		t.Fatalf("panic after a final response: responses = %v, want only [486]", got)
	}
}

// testUAC is a sipgo UAC with its own server on a fixed loopback port, so
// the SBC's in-dialog requests toward the caller (BYE) have somewhere to
// land.
type testUAC struct {
	dialogs *sipgo.DialogClientCache
	addr    string
	byes    chan struct{}
}

func startTestUAC(t *testing.T, addr string) *testUAC {
	t.Helper()
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ua.Close() })
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	client, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	u := &testUAC{
		dialogs: sipgo.NewDialogClientCache(client, sip.ContactHeader{}),
		addr:    addr,
		byes:    make(chan struct{}, 4),
	}
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		if err := u.dialogs.ReadBye(req, tx); err == nil {
			u.byes <- struct{}{}
		}
	})
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() { _ = srv.TransportLayer().ServeUDP(conn) }()
	time.Sleep(50 * time.Millisecond)
	return u
}

// call places an INVITE to the SBC at sbcPort and waits for the answer,
// passing every response to onResponse.
func (u *testUAC) call(t *testing.T, ctx context.Context, sbcPort int, onResponse func(*sip.Response)) *sipgo.DialogClientSession {
	t.Helper()
	sess, err := u.dialogs.Invite(ctx, sip.Uri{User: "5551234", Host: "127.0.0.1", Port: sbcPort},
		testSDPBody(uacRTPStubPort(t)), sip.NewHeader("Contact", "<sip:"+u.addr+">"))
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	if err := sess.WaitAnswer(ctx, sipgo.AnswerOptions{OnResponse: func(res *sip.Response) error {
		if onResponse != nil {
			onResponse(res)
		}
		return nil
	}}); err != nil {
		t.Fatalf("wait answer: %v", err)
	}
	if err := sess.Ack(ctx); err != nil {
		t.Fatalf("ack: %v", err)
	}
	return sess
}

const panicBridgedCfg = `
listen:
  sip: [udp://127.0.0.1:13180]
  media:
    port_range: 13184-13187
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:13181
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// audit: P2-TRK-003
// A panic while a call is bridged must not leave both parties in a
// confirmed dialog with dead media: both legs get a BYE (RFC 3261 §15), and
// the call leaves the store.
func TestPanicWhileBridgedByesBothLegs(t *testing.T) {
	echoRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echoRTP.Close()
	carrier := startStubCarrier(t, "127.0.0.1:13181", testSDPBody(echoRTP.LocalAddr().(*net.UDPAddr).Port))
	srv := startServerConfigured(t, 13180, panicBridgedCfg, func(s *Server) {
		s.onBridged = func(*call) { panic("injected panic while bridged") }
	})
	uac := startTestUAC(t, "127.0.0.1:13182")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uac.call(t, ctx, 13180, nil)

	select {
	case <-uac.byes:
	case <-time.After(3 * time.Second):
		t.Fatal("caller never got a BYE after the bridged call's handler panicked")
	}
	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("carrier never got a BYE after the bridged call's handler panicked")
	}
	waitForActiveCalls(t, srv, 0, 3*time.Second)
}

// rawForkingCarrier answers the first INVITE as two forks: 183 (SDP) from
// fork A, 183 (SDP) from fork B, then 200 from A and 200 from B, a little
// apart so they reach the SBC in that order. Every later request is
// delivered to reqs; BYEs are answered 200.
type rawForkingCarrier struct {
	reqs chan string
}

func startRawForkingCarrier(t *testing.T, addr string, sdpA, sdpB []byte) *rawForkingCarrier {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &rawForkingCarrier{reqs: make(chan string, 32)}
	contact := conn.LocalAddr().String()
	go func() {
		buf := make([]byte, 65535)
		answered := false
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			text := string(buf[:n])
			method := rawMethod(text)
			if method == "INVITE" {
				if answered {
					continue
				}
				answered = true
				lines := rawHeaderLines(text)
				for _, r := range []struct {
					code int
					tag  string
					body []byte
				}{{183, "fork-a", sdpA}, {183, "fork-b", sdpB}, {200, "fork-a", sdpA}, {200, "fork-b", sdpB}} {
					reason := map[int]string{183: "Session Progress", 200: "OK"}[r.code]
					_, _ = conn.WriteToUDP([]byte(rawFinalResponse(r.code, reason, lines, r.tag, contact, r.body)), src)
					time.Sleep(100 * time.Millisecond)
				}
				continue
			}
			c.reqs <- text
			if method == "BYE" {
				_, _ = conn.WriteToUDP([]byte(rawFinalResponse(200, "OK", rawHeaderLines(text), "", contact, nil)), src)
			}
		}
	}()
	return c
}

// rawToTag returns the tag of a raw message's To header.
func rawToTag(text string) string {
	for _, l := range rawHeaderLines(text) {
		if strings.HasPrefix(strings.ToLower(l), "to:") {
			if i := strings.Index(l, ";tag="); i >= 0 {
				return strings.TrimSpace(l[i+len(";tag="):])
			}
		}
	}
	return ""
}

const forkCfg = `
listen:
  sip: [udp://127.0.0.1:13190]
  media:
    port_range: 13194-13197
    public_ip: 127.0.0.1
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:13191
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// audit: P2-TRK-008
// A forked B-leg: two early dialogs with SDP, then two 2xx with different
// To-tags. Early media stays with the first fork (the second fork's 183 is
// relayed without SDP), and the 2xx the bridge did not use is ACKed and
// BYEd (RFC 3261 §13.2.2.4) instead of left up until its own timeout.
func TestForkedBLegSecondAnswerTornDown(t *testing.T) {
	carrier := startRawForkingCarrier(t, "127.0.0.1:13191", testSDPBody(13198), testSDPBody(13199))
	srv := startServer(t, 13190, forkCfg)
	uac := startTestUAC(t, "127.0.0.1:13192")

	var mu sync.Mutex
	var early []*sip.Response
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess := uac.call(t, ctx, 13190, func(res *sip.Response) {
		if res.StatusCode == 183 {
			mu.Lock()
			early = append(early, res)
			mu.Unlock()
		}
	})

	mu.Lock()
	if len(early) != 2 {
		t.Errorf("caller got %d 183s, want 2 (one per fork)", len(early))
	} else {
		if len(early[0].Body()) == 0 {
			t.Errorf("first fork's 183 lost its early-media SDP")
		}
		if len(early[1].Body()) != 0 {
			t.Errorf("second fork's 183 carried SDP; early media must stay with the first fork:\n%s", early[1].Body())
		}
	}
	mu.Unlock()

	// Collect the carrier-side requests: the bridged fork gets an ACK; the
	// other gets an ACK and then a BYE.
	acked := map[string]bool{}
	byed := map[string]bool{}
	deadline := time.After(4 * time.Second)
	for len(byed) == 0 || len(acked) < 2 {
		select {
		case req := <-carrier.reqs:
			switch rawMethod(req) {
			case "ACK":
				acked[rawToTag(req)] = true
			case "BYE":
				byed[rawToTag(req)] = true
			}
		case <-deadline:
			t.Fatalf("forks not settled: ACKed %v, BYEd %v; want both ACKed and the unused one BYEd", acked, byed)
		}
	}
	if !acked["fork-a"] || !acked["fork-b"] {
		t.Fatalf("every 2xx must be ACKed: ACKed %v", acked)
	}
	var loser string
	for tag := range byed {
		loser = tag
	}
	if len(byed) != 1 || !acked[loser] {
		t.Fatalf("exactly the unused fork must be BYEd while the call is up: BYEd %v", byed)
	}
	if n := srv.ActiveCalls(); n != 1 {
		t.Fatalf("ActiveCalls = %d after the fork teardown, want the bridged call still up", n)
	}

	// Hanging up BYEs the fork that was bridged.
	if err := sess.Bye(ctx); err != nil {
		t.Fatalf("uac bye: %v", err)
	}
	winner := "fork-a"
	if loser == "fork-a" {
		winner = "fork-b"
	}
	for {
		select {
		case req := <-carrier.reqs:
			if rawMethod(req) == "BYE" && rawToTag(req) == winner {
				waitForActiveCalls(t, srv, 0, 3*time.Second)
				return
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("bridged fork %s never got a BYE after the caller hung up", winner)
		}
	}
}

// audit: P2-TRK-019
// relayGate is the one owner of an attempt's A-leg writes: closing it
// waits for a relay already inside it, and nothing runs through it after.
// Before the gate, the abandonment flag was checked before the relay's
// write, so a relay could still be writing when the main path moved on.
func TestRelayGateSerialisesAbandonment(t *testing.T) {
	var g relayGate
	inside := make(chan struct{})
	release := make(chan struct{})
	go g.do(func() {
		close(inside)
		<-release
	})
	<-inside

	closed := make(chan struct{})
	go func() {
		g.close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("close returned while a relay was still writing to the A-leg")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close never returned after the relay finished")
	}
	if g.do(func() { t.Error("relay ran after the gate closed") }) {
		t.Error("do reported running after the gate closed")
	}
}
