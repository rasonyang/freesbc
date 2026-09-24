package edge

// Regression tests for the edge INVITE/CANCEL lifecycle (issue #26).

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// auditPhoneInviteAsync sends a phone's INVITE on its own transaction and
// reports the final response (nil if none) on the returned channel, plus
// the CANCEL that would cancel it, built before the INVITE is handed to
// the transaction layer (see TestCancelPropagatesUpstream).
func auditPhoneInviteAsync(t *testing.T, h *harness, phone *client, rtpPort int) (*sip.Request, <-chan *sip.Response) {
	t.Helper()
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(rtpPort))
	invite.SetTransport("UDP")
	invite.SetDestination(h.publicUDP)
	cancelReq := buildCancelFor(invite)
	final := make(chan *sip.Response, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := phone.cli.TransactionRequest(ctx, invite)
		if err != nil {
			final <- nil
			return
		}
		defer tx.Terminate()
		for {
			select {
			case res := <-tx.Responses():
				if res != nil && res.StatusCode >= 200 {
					final <- res
					return
				}
			case <-tx.Done():
				final <- nil
				return
			case <-ctx.Done():
				final <- nil
				return
			}
		}
	}()
	return cancelReq, final
}

// audit: P2-EDG-009
// RFC 3261 §16.8 / §16.7 step 6: when a proxy gives up on a branch (its
// Timer C, here FreeSBC's INVITE backstop) it CANCELs that branch and sends
// the caller a final response (408). Both directions: a phone calling a
// FreeSWITCH that rings forever, and FreeSWITCH calling a phone that rings
// forever.
func TestAuditInviteBackstopCancelsAndAnswers408(t *testing.T) {
	t.Run("client-to-fs", func(t *testing.T) {
		h := startHarness(t, false)
		h.srv.inviteBackstop.Store(int64(700 * time.Millisecond))
		h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
			return h.fs.silentHook()(req, tx)
		})
		phone := newUDPClient(t)
		_, final := auditPhoneInviteAsync(t, h, phone, 30401)
		var res *sip.Response
		select {
		case res = <-final:
		case <-time.After(10 * time.Second):
		}
		cancels := len(h.fs.waitFor(sip.CANCEL, 1, 2*time.Second))
		if res == nil || res.StatusCode != 408 || cancels == 0 {
			code := 0
			if res != nil {
				code = res.StatusCode
			}
			t.Errorf("P2-EDG-009 confirmed: at the INVITE backstop the phone got final %d (want 408) and FreeSWITCH saw %d CANCEL(s) (want 1)", code, cancels)
		}
		waitForRelease(t, h)
	})
	t.Run("fs-to-client", func(t *testing.T) {
		h := startHarness(t, false)
		h.srv.inviteBackstop.Store(int64(700 * time.Millisecond))
		phone := newUDPClient(t)
		ruri := auditRegisterPhone(t, h, phone, "1001")
		var mu sync.Mutex
		cancelled := false
		phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
			if req.Method != sip.INVITE {
				_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
				return
			}
			_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
			got := make(chan struct{})
			if !tx.OnCancel(func(*sip.Request) {
				mu.Lock()
				cancelled = true
				mu.Unlock()
				close(got)
			}) {
				return
			}
			select {
			case <-got:
			case <-time.After(10 * time.Second):
			}
		})
		_, final := h.fs.callAsync(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
		var res *sip.Response
		select {
		case res = <-final:
		case <-time.After(10 * time.Second):
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			done := cancelled
			mu.Unlock()
			if done {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		if res == nil || res.StatusCode != 408 || !cancelled {
			code := 0
			if res != nil {
				code = res.StatusCode
			}
			t.Errorf("P2-EDG-009 confirmed: at the INVITE backstop FreeSWITCH got final %d (want 408) and the phone was CANCELled: %v", code, cancelled)
		}
	})
}

// auditMuteCancelSwitch replaces the harness's fake FreeSWITCH with a raw
// UDP one that rings every INVITE (180) and never answers a CANCEL — the
// case where FreeSBC's own CANCEL transaction runs its full 5 s budget.
func auditMuteCancelSwitch(t *testing.T, h *harness) {
	t.Helper()
	h.fs.stop()
	addr, err := net.ResolveUDPAddr("udp", h.upstream)
	if err != nil {
		t.Fatal(err)
	}
	var conn *net.UDPConn
	for i := 0; i < 50; i++ {
		if conn, err = net.ListenUDP("udp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("rebind fake switch %s: %v", h.upstream, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, err := sip.ParseMessage(buf[:n])
			if err != nil {
				continue
			}
			if req, ok := msg.(*sip.Request); ok && req.Method == sip.INVITE {
				res := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
				_, _ = conn.WriteToUDP([]byte(res.String()), src)
			}
		}
	}()
}

// audit: P2-EDG-020
// The OnCancel hook runs inside sipgo's server-transaction lock, and sipgo
// sends the caller its 487 only after the hook returns. A hook that waits
// for the upstream's answer to FreeSBC's own CANCEL holds that lock — and
// the caller's 487 — for up to 5 s when the upstream never answers it.
func TestAuditCancelHookDoesNotBlock487(t *testing.T) {
	h := startHarness(t, false)
	auditMuteCancelSwitch(t, h)
	phone := newUDPClient(t)
	cancelReq, final := auditPhoneInviteAsync(t, h, phone, 30403)
	time.Sleep(300 * time.Millisecond) // ringing
	start := time.Now()
	if res := phone.do(t, cancelReq, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("CANCEL: %d", res.StatusCode)
	}
	var res *sip.Response
	select {
	case res = <-final:
	case <-time.After(10 * time.Second):
	}
	took := time.Since(start)
	if res == nil || res.StatusCode != 487 {
		t.Fatalf("the INVITE was not finalised with 487 after CANCEL (%v)", res)
	}
	t.Logf("CANCEL → 487 took %v", took)
	if took > 2*time.Second {
		t.Errorf("P2-EDG-020 confirmed: the caller's 487 took %v — the OnCancel hook waited on the upstream's answer to FreeSBC's CANCEL", took)
	}
	waitForReleaseEventually(t, h)
}

// audit: P2-EDG-023
// A transaction finalises once. FreeSWITCH answers 200 with SDP FreeSBC
// cannot anchor: the phone is refused 488, and nothing else — no second
// final (the old path followed the 488 with a 503) is sent or counted.
func TestAuditUnanchorable2xxSendsOneFinal(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		body := fmt.Sprintf("v=0\r\no=FreeSWITCH 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 96\r\na=rtpmap:96 PCMU/8000\r\na=sendrecv\r\n", h.fs.rtpPort)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		_ = tx.Respond(res)
		return true
	})
	phone := newUDPClient(t)
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30405)), h.publicUDP)
	if res.StatusCode != 488 {
		t.Fatalf("INVITE with an unanchorable answer: got %d, want 488", res.StatusCode)
	}
	time.Sleep(500 * time.Millisecond)
	out := h.srv.metrics.Snapshot().ResponsesOut
	if out["5xx"] != 0 {
		t.Errorf("P2-EDG-023 confirmed: a second final was generated after the 488 (responses out: %v)", out)
	}
	waitForRelease(t, h)
}

// audit: P2-EDG-008
// A CANCEL that lands after an attempt is chosen but before its INVITE is
// on the wire must neither be lost (the INVITE would then ring on,
// uncancelled) nor be sent ahead of the INVITE (the next hop would answer
// 481 and then ring). The window is microseconds wide inside one handler
// goroutine and cannot be forced over a socket, so this drives the
// dialog's attempt protocol directly: tracked before sending, a CANCEL in
// the window is handed to the sender, and no later attempt may start.
func TestAuditCancelBeforeInviteSentIsNotLost(t *testing.T) {
	tab := newDialogTable(NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "2002", Host: "example.com"})
	from := &sip.FromHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", "caller")
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "2002", Host: "example.com"}, Params: sip.NewParams()})
	callID := sip.CallIDHeader("audit-cancel-window")
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	d, ok := tab.begin(req, planePublic)
	if !ok {
		t.Fatal("begin refused")
	}
	defer d.end()

	var seriesCancelled bool
	a := &inviteAttempt{req: req, cancel: func() { seriesCancelled = true }}
	if !d.track(a) {
		t.Fatal("track refused a fresh attempt")
	}
	// The caller's CANCEL arrives now, before the INVITE is sent.
	got, sendNow := d.cancelSeries(cancelByCaller)
	if got != a {
		t.Fatal("P2-EDG-008 confirmed: a CANCEL in the window found no attempt to cancel")
	}
	if sendNow {
		t.Error("P2-EDG-008 confirmed: the CANCEL would be sent before the INVITE it cancels")
	}
	if !d.markSent(a) {
		t.Error("P2-EDG-008 confirmed: the INVITE went out after a CANCEL took it, and nobody CANCELs it")
	}
	if d.track(&inviteAttempt{req: req, cancel: func() {}}) {
		t.Error("P2-EDG-008 confirmed: a new attempt may start after the caller cancelled")
	}
	if e, ok := tab.early(fsip.CallID(req), "caller"); !ok || e != d {
		t.Error("the cancelled record is no longer found by Call-ID and From tag")
	}
	_ = seriesCancelled
}
