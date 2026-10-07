package edge

import (
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

// This file tests that no SDP the proxy did not build crosses in a
// response to PRACK or UPDATE, and that a retransmitted ACK restates the
// answer it carried.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// sdpResponse answers req with code and the fake switch's own SDP.
func sdpResponse(f *fakeSwitch, req *sip.Request, code int) *sip.Response {
	res := sip.NewResponseFromRequest(req, code, "Test", []byte(sdpWith(f.rtpPort, "sendrecv")))
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	return res
}

func assertNoSDP(t *testing.T, what string, res *sip.Response) {
	t.Helper()
	if len(res.Body()) != 0 || strings.Contains(res.String(), "m=audio") {
		t.Errorf("%s: SDP the far end wrote crossed the proxy: %q", what, res.Body())
	}
}

// A 2xx with SDP to a body-less UPDATE or PRACK, and a refusal with SDP to
// an UPDATE that carried SDP, reach the requester without a body.
func TestResponseSDPNotRelayedVerbatim(t *testing.T) {
	t.Run("200 to a body-less UPDATE", func(t *testing.T) {
		r := startUpdRig(t)
		r.h.fs.setUpdateHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
			_ = tx.Respond(sdpResponse(r.h.fs, req, 200))
			return true
		})
		res := r.phoneUpdate(t, 2, "")
		if res.StatusCode != 200 {
			t.Fatalf("UPDATE: got %d, want 200", res.StatusCode)
		}
		assertNoSDP(t, "200 to UPDATE", res)
		r.end(t)
	})
	t.Run("200 to a body-less PRACK", func(t *testing.T) {
		r := startUpdRig(t)
		r.h.fs.setPrackHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
			_ = tx.Respond(sdpResponse(r.h.fs, req, 200))
			return true
		})
		pr := prackFor(r.invite, r.res, 2, "127.0.0.1", 0)
		res := r.phone.do(t, pr, r.h.publicUDP)
		if res.StatusCode != 200 {
			t.Fatalf("PRACK: got %d, want 200", res.StatusCode)
		}
		assertNoSDP(t, "200 to PRACK", res)
		r.end(t)
	})
	t.Run("488 with SDP to an UPDATE with SDP", func(t *testing.T) {
		r := startUpdRig(t)
		r.h.fs.setUpdateHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
			_ = tx.Respond(sdpResponse(r.h.fs, req, 488))
			return true
		})
		res := r.phoneUpdate(t, 2, sdpWith(udpPort(r.phoneRTP), "sendrecv"))
		if res.StatusCode != 488 {
			t.Fatalf("UPDATE: got %d, want 488", res.StatusCode)
		}
		assertNoSDP(t, "488 to UPDATE", res)
		r.end(t)
	})
}

// The same on a carrier leg: nothing of the carrier's SDP reaches the
// switch in a response to a PRACK or UPDATE.
func TestOutboundResponseSDPNotRelayed(t *testing.T) {
	o := startOutboundRig(t)
	answerWithTag(o.carrier)
	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	o.fs.sendAckTo2xx(t, res)
	waitReceived(t, o.carrier, sip.ACK, 1)

	send := func(method sip.RequestMethod, cseq uint32, body string) *sip.Response {
		var r *sip.Request
		if method == sip.PRACK {
			r = uacRequestFrom(sip.PRACK, res, cseq, o.fs)
			r.AppendHeader(sip.NewHeader("RAck", "1 1 INVITE"))
		} else if body != "" {
			r = switchUpdateFrom(o.fs, res, cseq, body)
		} else {
			r = uacRequestFrom(sip.UPDATE, res, cseq, o.fs)
		}
		return switchSend(t, o.fs, r, res)
	}

	o.carrier.setUpdateHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sdpResponse(o.carrier, req, 200))
		return true
	})
	assertNoSDP(t, "carrier 200 to a body-less UPDATE", send(sip.UPDATE, 2, ""))

	o.carrier.setPrackHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sdpResponse(o.carrier, req, 200))
		return true
	})
	assertNoSDP(t, "carrier 200 to a PRACK", send(sip.PRACK, 3, ""))

	o.carrier.setUpdateHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sdpResponse(o.carrier, req, 488))
		return true
	})
	r488 := send(sip.UPDATE, 4, sdpWith(o.fs.rtpPort, "sendrecv"))
	if r488.StatusCode != 488 {
		t.Errorf("UPDATE with SDP: got %d, want 488", r488.StatusCode)
	}
	assertNoSDP(t, "carrier 488 to an UPDATE with SDP", r488)
	if bye := o.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Errorf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, o.harness)
}

// uacRequestFrom builds a body-less in-dialog request from the fake switch,
// as the UAC of the call whose 200 is res.
func uacRequestFrom(method sip.RequestMethod, res *sip.Response, cseq uint32, f *fakeSwitch) *sip.Request {
	r := switchUpdateFrom(f, res, cseq, "")
	r.Method = method
	r.CSeq().MethodName = method
	r.RemoveHeader("Content-Type")
	r.SetBody(nil)
	return r
}

// A retransmitted ACK (the first never reached the callee, which resends its
// 2xx) is restated with the same rebuilt answer, not stripped, and the media
// is left alone.
func TestRetransmittedACKRestatesAnswer(t *testing.T) {
	t.Run("initial INVITE", func(t *testing.T) {
		o := startOfferlessToSwitch(t, func(h *harness) func(*sip.Request, sip.ServerTransaction) bool {
			return offerIn200(h.fs, "uas-ol-dup", sdpWith(h.fs.rtpPort, "sendrecv"))
		})
		res := o.call.final200(t)
		sess := waitForDialog(t, o.h, o.invite.CallID().Value()).session()
		phoneAck(t, o.h, o.phone, o.invite, res, o.phoneAnswer())
		phoneAck(t, o.h, o.phone, o.invite, res, o.phoneAnswer())
		acks := waitReceived(t, o.h.fs, sip.ACK, 2)
		if len(acks[0].Body()) == 0 || string(acks[0].Body()) != string(acks[1].Body()) {
			t.Errorf("the retransmitted ACK carried a different answer:\n%s\n---\n%s", acks[0].Body(), acks[1].Body())
		}
		if !relayReaches(t, o.phoneRTP, loopback(sess.publicPort), o.fsRTP, rtpPacket(0, 400, 160)) {
			t.Error("media broke after the retransmitted ACK")
		}
		if r := o.phone.do(t, buildBye(o.phone, o.invite, res), o.h.publicUDP); r.StatusCode != 200 {
			t.Errorf("BYE: %d", r.StatusCode)
		}
		waitForRelease(t, o.h)
	})
	t.Run("re-INVITE", func(t *testing.T) {
		r := startUpdRig(t)
		req, res := offerlessReInvite(t, r, r.h.fs.rtpPort)
		answer := sdpWith(udpPort(r.phoneRTP), "sendrecv")
		phoneAck(t, r.h, r.phone, req, res, answer)
		phoneAck(t, r.h, r.phone, req, res, answer)
		acks := waitReceived(t, r.h.fs, sip.ACK, 3)
		if len(acks[1].Body()) == 0 || string(acks[1].Body()) != string(acks[2].Body()) {
			t.Errorf("the retransmitted ACK carried a different answer:\n%s\n---\n%s", acks[1].Body(), acks[2].Body())
		}
		r.end(t)
	})
}
