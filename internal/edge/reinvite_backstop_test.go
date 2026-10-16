package edge

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Issue #71: a far end that answers a re-INVITE with only a 183 and never
// a final must not leave the requester hanging or the forwarded re-INVITE
// open. At the backstop the requester gets 408 and the far end a CANCEL
// (RFC 3261 §16.8), so a later re-INVITE is not refused with 491 (§14.1).
func TestReInviteBackstopAnswers408AndCancels(t *testing.T) {
	h := startHarness(t, false)
	tags := make(chan string, 1)
	silent := h.fs.silentHook()
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 183, "Session Progress", nil))
		silent(req, tx)
	}))
	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	<-tags
	waitForDialog(t, h, fsip.CallID(invite))
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("initial ACK: FreeSWITCH saw %d", len(acks))
	}
	h.srv.inviteBackstop.Store(int64(700 * time.Millisecond))

	_, reRes := auditPhoneReInvite(t, h, phone, invite, res, 2, phoneOfferSDP(auditUDPPort(phoneRTP)))
	if reRes.StatusCode != 408 {
		t.Errorf("requester got %d to a re-INVITE that outlived its budget, want 408", reRes.StatusCode)
	}
	cancels := h.fs.waitFor(sip.CANCEL, 1, 3*time.Second)
	if len(cancels) != 1 {
		t.Fatalf("far end saw %d CANCEL(s), want 1", len(cancels))
	}
	if cs := cancels[0].CSeq(); cs == nil || cs.SeqNo != 2 {
		t.Errorf("CANCEL cancels CSeq %v, want the re-INVITE's 2", cs)
	}
}

// Issue #223: a far end's 200 to an abandoned re-INVITE that crosses the
// CANCEL and arrives later than cancelDrain must still be ACKed, or the far
// end retransmits it until Timer H and may then BYE a confirmed call. The
// dialog is live, so the 200 is ACKed only: no BYE, and the call survives.
func TestReInviteBackstopAcksLate2xx(t *testing.T) {
	h := startHarness(t, false)
	tags := make(chan string, 1)
	pending := make(chan *sip.Response, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 183, "Session Progress", nil))
		ok := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		ok.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		ok.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		select {
		case pending <- ok:
		default:
		}
		// No final on the transaction: the test sends the 200 later.
	}))
	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	<-tags
	callID := fsip.CallID(invite)
	waitForDialog(t, h, callID)
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("initial ACK: FreeSWITCH saw %d", len(acks))
	}
	h.srv.inviteBackstop.Store(int64(700 * time.Millisecond))

	_, reRes := auditPhoneReInvite(t, h, phone, invite, res, 2, phoneOfferSDP(auditUDPPort(phoneRTP)))
	if reRes.StatusCode != 408 {
		t.Fatalf("requester got %d to a re-INVITE that outlived its budget, want 408", reRes.StatusCode)
	}
	if cancels := h.fs.waitFor(sip.CANCEL, 1, 3*time.Second); len(cancels) != 1 {
		t.Fatalf("far end saw %d CANCEL(s), want 1", len(cancels))
	}
	var ok *sip.Response
	select {
	case ok = <-pending:
	default:
		t.Fatal("FreeSWITCH never got the re-INVITE")
	}
	// Well past the inline drain, so only a transaction kept in the
	// background can still match the 200.
	time.Sleep(cancelDrain + 700*time.Millisecond)
	h.fs.sendResponse(t, ok) // the 200 that crossed the CANCEL

	acks := h.fs.waitFor(sip.ACK, 2, 3*time.Second)
	if len(acks) != 2 {
		t.Fatalf("the late 200 to the abandoned re-INVITE got %d ACK(s), want 1", len(acks)-1)
	}
	if cs := acks[1].CSeq(); cs == nil || cs.SeqNo != 2 || cs.MethodName != sip.ACK {
		t.Errorf("ACK CSeq %v, want 2 ACK", cs)
	}
	time.Sleep(300 * time.Millisecond)
	if byes := h.fs.received(sip.BYE); len(byes) != 0 {
		t.Errorf("far end got %d BYE(s); the dialog is live, so the 200 must be ACKed only", len(byes))
	}
	if _, live := h.srv.dialogs.confirmed(callID); !live || h.srv.ActiveCalls() != 1 {
		t.Errorf("dialog live=%v, ActiveCalls=%d after the late 200; want the call kept", live, h.srv.ActiveCalls())
	}
	deadline := time.Now().Add(3 * time.Second)
	for h.srv.cancelLingers.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.srv.cancelLingers.Load(); n != 0 {
		t.Errorf("%d background linger(s) still held after the final", n)
	}
}
