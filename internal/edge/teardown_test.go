package edge

import (
	"fmt"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// audit: P2-EDG-026
// The ACK and BYE FreeSBC sends itself to tear down a 2xx it cannot anchor
// leave by the private listener, exactly as a relayed request does: from
// the address FreeSWITCH already talks to, not from a fresh socket.
func TestTeardownLeavesByPrivateListener(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		// PT 96 as PCMU: the offer had PCMU on 0, so the answer is
		// renumbered and FreeSBC cannot anchor it.
		body := fmt.Sprintf("v=0\r\no=FreeSWITCH 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 96\r\na=rtpmap:96 PCMU/8000\r\na=sendrecv\r\n", h.fs.rtpPort)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		_ = tx.Respond(res)
		return true
	})
	phone := newUDPClient(t)
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30407)), h.publicUDP)
	if res.StatusCode != 488 {
		t.Fatalf("INVITE with an unanchorable answer: got %d, want 488", res.StatusCode)
	}
	for _, m := range []sip.RequestMethod{sip.ACK, sip.BYE} {
		got := h.fs.waitFor(m, 1, 3*time.Second)
		if len(got) != 1 {
			t.Fatalf("FreeSWITCH saw %d %s, want 1", len(got), m)
		}
		if src := got[0].Source(); src != h.privateSIP {
			t.Errorf("%s came from %s, want the private listener %s", m, src, h.privateSIP)
		}
	}
	waitForRelease(t, h)
}

// audit: P2-EDG-026
// The same toward a PSTN carrier with the public listener on the
// production wildcard bind (0.0.0.0): the ACK and BYE for the carrier's
// unanchorable 2xx must leave by the public listener the carrier's INVITE
// came from, not by whatever socket sipgo would pick for an unpinned
// request.
func TestTeardownLeavesByPublicListenerOnWildcardBind(t *testing.T) {
	carrierAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h := startHarnessCfg(t, false, "0.0.0.0", func(pubUDP int) string {
		return fmt.Sprintf("  pstn:\n    address: %s\n    match: 127.0.0.1:%d\n", carrierAddr, pubUDP)
	})
	carrier := startFakeSwitch(t, carrierAddr)
	h.carrier = carrier
	var inviteSrc string
	srcCh := make(chan string, 1)
	carrier.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		srcCh <- req.Source()
		body := "v=0\r\no=gw 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
			"m=audio 9998 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n"
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = tx.Respond(res)
		return true
	})

	ruri := sip.Uri{User: "12345", Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	if res := h.fs.call(t, ruri, h.publicUDP, phoneOfferSDP(h.fs.rtpPort)); res.StatusCode != 488 {
		t.Fatalf("got %d, want 488", res.StatusCode)
	}
	select {
	case inviteSrc = <-srcCh:
	case <-time.After(3 * time.Second):
		t.Fatal("the carrier never saw the INVITE")
	}
	for _, m := range []sip.RequestMethod{sip.ACK, sip.BYE} {
		got := carrier.waitFor(m, 1, 3*time.Second)
		if len(got) != 1 {
			t.Fatalf("the carrier saw %d %s, want 1", len(got), m)
		}
		if src := got[0].Source(); src != inviteSrc {
			t.Errorf("%s came from %s, the INVITE from %s: not the same listener", m, src, inviteSrc)
		}
	}
	waitForRelease(t, h)
}
