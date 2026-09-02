package proxy

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/sdpx"
)

// TestCaseE_NoLeaksAfterCalls is acceptance criterion 11: after a run of
// calls and registrations, nothing is left behind — no media ports, no
// dialogs, no registration bindings, and no goroutines beyond the ones the
// still-running proxy legitimately owns.
func TestCaseE_NoLeaksAfterCalls(t *testing.T) {
	h := startHarness(t, false)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()

	// Count media goroutines from a baseline rather than absolutely: the
	// count is process-wide, and other tests in this package may still be
	// winding their own harnesses down.
	settle()
	baseline, _ := goroutinesIn("freesbc/media.")

	const rounds = 6
	for i := 0; i < rounds; i++ {
		phone := newUDPClient(t)

		// Register, call, hang up, un-register.
		if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("round %d REGISTER: %d", i, res.StatusCode)
		}
		rtp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := rtp.LocalAddr().(*net.UDPAddr).Port

		invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(port))
		res := phone.do(t, invite, h.publicUDP)
		if res.StatusCode != 200 {
			t.Fatalf("round %d INVITE: %d", i, res.StatusCode)
		}
		sendAck(t, phone, invite, res, h.publicUDP)
		if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
			t.Fatalf("round %d BYE: %d", i, r.StatusCode)
		}
		if r := phone.do(t, phone.buildRegister("1001", "example.com", 0, ""), h.publicUDP); r.StatusCode != 200 {
			t.Fatalf("round %d un-REGISTER: %d", i, r.StatusCode)
		}
		_ = rtp.Close()
		phone.cancel()
	}

	waitForRelease(t, h)
	if n := h.srv.loc.Count(); n != 0 {
		t.Errorf("registration bindings left: %d", n)
	}
	if n := h.srv.ActiveCalls(); n != 0 {
		t.Errorf("dialogs left: %d", n)
	}
	if snap := h.srv.metrics.Snapshot(); snap.ActiveMediaSessions != 0 || snap.ActiveDialogs != 0 {
		t.Errorf("gauges did not return to zero: %+v", snap)
	}

	// Goroutines. Counting them all would measure the wrong thing: sipgo
	// parks a goroutine per server transaction in TerminateGracefully for
	// the RFC 3261 Timer J period (32s on UDP), so a run of calls leaves
	// dozens of perfectly correct goroutines behind that simply have not
	// aged out yet. Waiting them out would make this a 30-second test.
	//
	// What must be zero is the media plane's own goroutines: each session
	// starts four relay loops and a watchdog, and those are exactly the
	// ones a lifecycle bug would strand. So assert on those directly.
	settle()
	if n, dump := goroutinesIn("freesbc/media."); n > baseline {
		t.Errorf("media goroutines grew from %d to %d over %d calls:\n%s", baseline, n, rounds, dump)
	}
}

// goroutinesIn counts goroutines whose stack mentions pkg, and returns
// their stacks for the failure message.
func goroutinesIn(pkg string) (int, string) {
	buf := make([]byte, 1<<21)
	n := runtime.Stack(buf, true)
	count := 0
	var dump strings.Builder
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, pkg) {
			count++
			dump.WriteString(g)
			dump.WriteString("\n\n")
		}
	}
	return count, dump.String()
}

// settle gives background goroutines a chance to finish and the collector
// a chance to run, so a goroutine count means something.
func settle() {
	for i := 0; i < 8; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
}

// TestMediaPoolExhaustionRejectsCleanly is spec §7: a full port range must
// produce a clean 503, not a wedged call or a leaked socket.
func TestMediaPoolExhaustionRejectsCleanly(t *testing.T) {
	h := startHarness(t, false)
	// Drain the public pool by allocating every pair it holds.
	_, total := h.srv.pubPool.Stats()
	var held []interface{ Close() error }
	for i := 0; i < total; i++ {
		sess, err := h.srv.allocateRTP(&sdpx.Session{Audio: &sdpx.Audio{
			Address: mustAddr("127.0.0.1"), Port: 40000,
		}})
		if err != nil {
			break
		}
		held = append(held, sess)
	}
	defer func() {
		for _, s := range held {
			_ = s.Close()
		}
	}()

	phone := newUDPClient(t)
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30099)), h.publicUDP)
	if res.StatusCode != 503 {
		t.Fatalf("got %d, want 503 Service Unavailable", res.StatusCode)
	}
	if snap := h.srv.metrics.Snapshot(); snap.MediaPortAllocationFailures == 0 {
		t.Error("port allocation failure not counted")
	}
	// The call must not have been forwarded: rejecting locally is the
	// point of the capacity check.
	if got := h.fs.received(sip.INVITE); len(got) != 0 {
		t.Errorf("a call with no media was still forwarded upstream (%d times)", len(got))
	}
}

// A hostile or malformed offer must be refused, never panic the process.
func TestMalformedOffersRejected(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	bodies := map[string]string{
		"empty":           "",
		"garbage":         "not sdp at all\r\n",
		"no audio":        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=video 5000 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\n",
		"no connection":   "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n",
		"unknown codec":   "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 96\r\na=rtpmap:96 G729/8000\r\n",
		"dtmf only":       "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 101\r\na=rtpmap:101 telephone-event/8000\r\n",
		"absurd port":     "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 999999 RTP/AVP 0\r\n",
		"bad c= address":  "v=0\r\no=- 1 1 IN IP4 x\r\ns=-\r\nc=IN IP4 999.999.999.999\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n",
		"webrtc when off": browserOfferSDP(51234),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", body), h.publicUDP)
			if res.StatusCode < 400 {
				t.Fatalf("malformed offer accepted with %d:\n%s", res.StatusCode, body)
			}
		})
	}
	// An SDP over sdpx.MaxSize goes over the WebSocket listener: UDP would
	// refuse it at the sender's own transport (MTU), which would test
	// sipgo rather than FreeSBC. The body is sized to clear sdpx's 16 KiB
	// limit while staying under sipgo's 32 KiB read buffer, so what
	// rejects it is FreeSBC's own bound and not a transport artifact.
	browser := newWSClient(t)
	huge := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n" +
		strings.Repeat("a=x:yyyyyyyyyyyyyyyyyyyy\r\n", 800)
	if len(huge) <= sdpx.MaxSize {
		t.Fatalf("test body is %d bytes, not over the %d-byte limit it means to exercise", len(huge), sdpx.MaxSize)
	}
	if res := browser.do(t, browser.buildInvite("1001", "2002", "example.com", huge), h.publicWS); res.StatusCode < 400 {
		t.Errorf("oversize SDP accepted with %d", res.StatusCode)
	}

	// The proxy is still alive and healthy after all of that.
	if res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30098)), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("proxy unhealthy after malformed input: %d", res.StatusCode)
	}
	waitForReleaseEventually(t, h)
}

// waitForReleaseEventually is waitForRelease without the dialog check, for
// tests that deliberately leave a call up.
func waitForReleaseEventually(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.ActiveCalls() <= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A CANCEL from the caller must reach FreeSWITCH, so it stops ringing.
func TestCancelPropagatesUpstream(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	ringing := make(chan struct{})
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		close(ringing)
		return true // never answer: wait to be cancelled
	})

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30097))
	invite.SetTransport("UDP")
	invite.SetDestination(h.publicUDP)
	// Build the CANCEL from a snapshot taken BEFORE the INVITE is handed
	// to the transaction layer: sipgo mutates the request it is sending
	// (headers, params), so reading it from this goroutine afterwards is a
	// genuine data race. RFC 3261 §9.1 only requires the CANCEL to carry
	// the INVITE's top Via branch, which is already set here.
	cancelReq := buildCancelFor(phone, invite)

	done := make(chan int, 1)
	go func() {
		ctx, cancel := timeoutCtx(15 * time.Second)
		defer cancel()
		tx, err := phone.cli.TransactionRequest(ctx, invite)
		if err != nil {
			done <- 0
			return
		}
		defer tx.Terminate()
		for {
			select {
			case res, ok := <-tx.Responses():
				if !ok {
					done <- 0
					return
				}
				if res.StatusCode >= 200 {
					done <- res.StatusCode
					return
				}
			case <-tx.Done():
				done <- 0
				return
			case <-ctx.Done():
				done <- 0
				return
			}
		}
	}()

	select {
	case <-ringing:
	case <-time.After(5 * time.Second):
		t.Fatal("FreeSWITCH never rang")
	}

	if res := phone.do(t, cancelReq, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("CANCEL: got %d", res.StatusCode)
	}
	if got := h.fs.waitFor(sip.CANCEL, 1, 5*time.Second); len(got) != 1 {
		t.Errorf("FreeSWITCH saw %d CANCELs, want 1 — it would keep ringing", len(got))
	}
	select {
	case code := <-done:
		if code != 487 {
			t.Logf("caller saw final response %d (487 expected, but the exact code is the UAS's to choose)", code)
		}
	case <-time.After(5 * time.Second):
		t.Error("the INVITE transaction never finalised after CANCEL")
	}
	waitForRelease(t, h)
}

func buildCancelFor(c *client, invite *sip.Request) *sip.Request {
	cn := sip.NewRequest(sip.CANCEL, invite.Recipient)
	// RFC 3261 §9.1: the CANCEL carries the INVITE's own top Via branch.
	cn.AppendHeader(sip.HeaderClone(invite.Via()))
	sip.CopyHeaders("From", invite, cn)
	sip.CopyHeaders("To", invite, cn)
	sip.CopyHeaders("Call-ID", invite, cn)
	cn.AppendHeader(&sip.CSeqHeader{SeqNo: invite.CSeq().SeqNo, MethodName: sip.CANCEL})
	mf := sip.MaxForwardsHeader(70)
	cn.AppendHeader(&mf)
	return cn
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func timeoutCtx(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
