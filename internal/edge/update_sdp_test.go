package edge

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// This file tests UPDATE carrying SDP (RFC 3311): the offer and its answer
// are rebuilt like a re-INVITE's, media follows them, and a refusal, a
// glare or an unusable answer leaves the session as it was.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// sdpWith is a phone offer on port with the given direction.
func sdpWith(port int, dir string) string {
	return strings.Replace(phoneOfferSDP(port), "a=sendrecv", "a="+dir, 1)
}

func udpPort(c *net.UDPConn) int { return c.LocalAddr().(*net.UDPAddr).Port }

func loopback(port int) *net.UDPAddr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port} }

// updRig is a confirmed phone -> switch call with both media sockets open.
type updRig struct {
	h        *harness
	phone    *client
	invite   *sip.Request
	res      *sip.Response
	phoneRTP *net.UDPConn
	fsRTP    *net.UDPConn
	fsTag    string
	upInv    *sip.Request
	pubPort  int // the SBC's public anchor
	privPort int // the SBC's private anchor
}

func startUpdRig(t *testing.T) *updRig {
	t.Helper()
	h := startHarness(t, false)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	r := &updRig{h: h, phone: phone, invite: invite, res: res, phoneRTP: phoneRTP}
	r.fsTag = <-tags
	waitForDialog(t, h, fsip.CallID(invite))
	r.upInv = waitReceived(t, h.fs, sip.INVITE, 1)[0]
	waitReceived(t, h.fs, sip.ACK, 1)
	r.fsRTP = listenRTP(t, h.fs.rtpPort)
	first, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}
	up, err := parseLabSDP(r.upInv.Body())
	if err != nil {
		t.Fatal(err)
	}
	r.pubPort, r.privPort = first.Audio.Port, up.Audio.Port
	return r
}

// phoneUpdate sends an UPDATE from the phone inside the call's dialog.
func (r *updRig) phoneUpdate(t *testing.T, cseq uint32, body string) *sip.Response {
	t.Helper()
	req := uacRequest(sip.UPDATE, r.invite, r.res, cseq, "127.0.0.1", 0)
	req.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
	if body != "" {
		req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		req.SetBody([]byte(body))
	}
	return r.phone.do(t, req, r.h.publicUDP)
}

// switchUpdate sends an UPDATE from the switch (the call's UAS).
func (r *updRig) switchUpdate(t *testing.T, cseq uint32, body string) *sip.Response {
	t.Helper()
	return auditInDialogWithBody(t, r.h.fs, sip.UPDATE, r.upInv, r.fsTag, cseq, body)
}

// phoneAnswersUpdate makes the phone answer an UPDATE with 200 and, when it
// carries a body, an answer on port.
func phoneAnswersUpdate(phone *client, port int) {
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		var body []byte
		if len(req.Body()) > 0 {
			body = []byte(phoneOfferSDP(port))
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", body)
		if body != nil {
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		}
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		_ = tx.Respond(res)
	})
}

func mustInbound(t *testing.T, c *client, m sip.RequestMethod) *sip.Request {
	t.Helper()
	r := waitInbound(c, m, 3*time.Second)
	if r == nil {
		t.Fatalf("the phone never saw a %s", m)
	}
	return r
}

func mustSDP(t *testing.T, what string, body []byte) *sdp.Session {
	t.Helper()
	s, err := parseLabSDP(body)
	if err != nil {
		t.Fatalf("%s: %v\n%s", what, err, body)
	}
	return s
}

// An UPDATE offer from the phone: the switch receives a body on the SBC's
// private anchor, the phone's 200 carries the public anchor, and media
// follows the phone's new address in both directions.
func TestUpdateSDPConfirmedPhoneToSwitch(t *testing.T) {
	r := startUpdRig(t)
	moved := listenRTP(t, freePort(t))
	res := r.phoneUpdate(t, 2, sdpWith(udpPort(moved), "sendrecv"))
	if res.StatusCode != 200 {
		t.Fatalf("UPDATE: got %d, want 200", res.StatusCode)
	}
	fwd := mustSDP(t, "UPDATE at the switch", waitReceived(t, r.h.fs, sip.UPDATE, 1)[0].Body())
	if fwd.Audio.Port != r.privPort {
		t.Errorf("the switch was offered port %d, want the private anchor %d", fwd.Audio.Port, r.privPort)
	}
	if ans := mustSDP(t, "200 at the phone", res.Body()); ans.Audio.Port != r.pubPort {
		t.Errorf("the phone was answered with port %d, want the public anchor %d", ans.Audio.Port, r.pubPort)
	}
	if !relayReaches(t, moved, loopback(r.pubPort), r.fsRTP, rtpPacket(0, 300, 160)) {
		t.Error("phone -> switch audio from the new address never arrived")
	}
	if !relayReaches(t, r.fsRTP, loopback(r.privPort), moved, rtpPacket(0, 301, 160)) {
		t.Error("switch -> phone audio to the new address never arrived")
	}
	r.end(t)
}

// An UPDATE offer from the switch is rebuilt toward the phone and the
// phone's answer toward the switch; media follows both new addresses.
func TestUpdateSDPConfirmedSwitchToPhone(t *testing.T) {
	r := startUpdRig(t)
	phoneMoved := listenRTP(t, freePort(t))
	fsMoved := listenRTP(t, freePort(t))
	phoneAnswersUpdate(r.phone, udpPort(phoneMoved))
	res := r.switchUpdate(t, 2, sdpWith(udpPort(fsMoved), "sendrecv"))
	if res.StatusCode != 200 {
		t.Fatalf("UPDATE: got %d, want 200", res.StatusCode)
	}
	if ans := mustSDP(t, "200 at the switch", res.Body()); ans.Audio.Port != r.privPort {
		t.Errorf("the switch was answered with port %d, want the private anchor %d", ans.Audio.Port, r.privPort)
	}
	seen := mustSDP(t, "UPDATE at the phone", mustInbound(t, r.phone, sip.UPDATE).Body())
	if seen.Audio.Port != r.pubPort {
		t.Errorf("the phone was offered port %d, want the public anchor %d", seen.Audio.Port, r.pubPort)
	}
	if !relayReaches(t, fsMoved, loopback(r.privPort), phoneMoved, rtpPacket(0, 310, 160)) {
		t.Error("switch -> phone audio never arrived")
	}
	if !relayReaches(t, phoneMoved, loopback(r.pubPort), fsMoved, rtpPacket(0, 311, 160)) {
		t.Error("phone -> switch audio never arrived")
	}
	r.end(t)
}

// Hold and resume by UPDATE pass the direction through and keep the anchor.
func TestUpdateSDPHoldAndResume(t *testing.T) {
	r := startUpdRig(t)
	for i, dir := range []string{"sendonly", "sendrecv"} {
		res := r.phoneUpdate(t, uint32(2+i), sdpWith(udpPort(r.phoneRTP), dir))
		if res.StatusCode != 200 {
			t.Fatalf("UPDATE %s: got %d, want 200", dir, res.StatusCode)
		}
		ups := waitReceived(t, r.h.fs, sip.UPDATE, i+1)
		got := mustSDP(t, "UPDATE at the switch", ups[i].Body())
		if string(got.Audio.Direction) != dir && !(dir == "sendrecv" && got.Audio.Direction == "") {
			t.Errorf("UPDATE %s reached the switch as %q", dir, got.Audio.Direction)
		}
		if got.Audio.Port != r.privPort {
			t.Errorf("UPDATE %s offered port %d, want %d", dir, got.Audio.Port, r.privPort)
		}
	}
	if !relayReaches(t, r.phoneRTP, loopback(r.pubPort), r.fsRTP, rtpPacket(0, 320, 160)) {
		t.Error("audio did not resume after the hold")
	}
	r.end(t)
}

// A far end that refuses the offer (488, 491) leaves the session as it
// was: media keeps flowing at the old address, and the offer slot is free
// for the next UPDATE.
func TestUpdateSDPRefusedLeavesSessionIntact(t *testing.T) {
	for _, code := range []int{488, 491} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			r := startUpdRig(t)
			var once sync.Once
			r.h.fs.setUpdateHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
				refused := false
				once.Do(func() {
					refused = true
					_ = tx.Respond(sip.NewResponseFromRequest(req, code, "Refused", nil))
				})
				return refused
			})
			moved := listenRTP(t, freePort(t))
			if res := r.phoneUpdate(t, 2, sdpWith(udpPort(moved), "sendrecv")); res.StatusCode != code {
				t.Fatalf("UPDATE: got %d, want the far end's %d", res.StatusCode, code)
			}
			if !relayReaches(t, r.phoneRTP, loopback(r.pubPort), r.fsRTP, rtpPacket(0, 330, 160)) {
				t.Error("phone -> switch audio stopped after the refused UPDATE")
			}
			if !relayReaches(t, r.fsRTP, loopback(r.privPort), r.phoneRTP, rtpPacket(0, 331, 160)) {
				t.Error("switch -> phone audio stopped after the refused UPDATE")
			}
			if res := r.phoneUpdate(t, 3, sdpWith(udpPort(r.phoneRTP), "sendrecv")); res.StatusCode != 200 {
				t.Errorf("a later UPDATE: got %d, want 200", res.StatusCode)
			}
			r.end(t)
		})
	}
}

// An answer FreeSBC cannot anchor (a renumbered payload type) is refused
// like a re-INVITE's: the requester gets 488 and, the ends now disagreeing
// about the session, the call is ended on both.
func TestUpdateSDPRenumberedAnswerRejected(t *testing.T) {
	r := startUpdRig(t)
	r.h.fs.setUpdateHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		body := fmt.Sprintf("v=0\r\no=FreeSWITCH 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 96\r\na=rtpmap:96 PCMU/8000\r\na=sendrecv\r\n", r.h.fs.rtpPort)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = tx.Respond(res)
		return true
	})
	if res := r.phoneUpdate(t, 2, sdpWith(udpPort(r.phoneRTP), "sendrecv")); res.StatusCode != 488 {
		t.Fatalf("UPDATE: got %d, want 488", res.StatusCode)
	}
	waitReceived(t, r.h.fs, sip.BYE, 1)
	waitForRelease(t, r.h)
}

// A renumbered offer is refused up front, before anything reaches the far
// end.
func TestUpdateSDPNoUsableCodecRejected(t *testing.T) {
	r := startUpdRig(t)
	body := fmt.Sprintf("v=0\r\no=phone 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
		"m=audio %d RTP/AVP 97\r\na=rtpmap:97 speex/16000\r\na=sendrecv\r\n", udpPort(r.phoneRTP))
	if res := r.phoneUpdate(t, 2, body); res.StatusCode != 488 {
		t.Fatalf("UPDATE: got %d, want 488", res.StatusCode)
	}
	if n := len(r.h.fs.received(sip.UPDATE)); n != 0 {
		t.Errorf("%d unusable UPDATEs reached the switch", n)
	}
	r.end(t)
}

// An UPDATE offer while an UPDATE or a re-INVITE offer is pending in the
// dialog is answered 491 by FreeSBC and never forwarded, and a re-INVITE
// while an UPDATE offer is pending is too.
func TestUpdateSDPGlare(t *testing.T) {
	t.Run("update vs update", func(t *testing.T) {
		r := startUpdRig(t)
		release := make(chan struct{})
		r.h.fs.setUpdateHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
			select {
			case <-release:
			case <-time.After(8 * time.Second):
			}
			return false
		})
		first := make(chan *sip.Response, 1)
		go func() { first <- r.phoneUpdate(t, 2, sdpWith(udpPort(r.phoneRTP), "sendrecv")) }()
		waitReceived(t, r.h.fs, sip.UPDATE, 1)
		if res := r.switchUpdate(t, 2, sdpWith(r.h.fs.rtpPort, "sendrecv")); res.StatusCode != 491 {
			t.Errorf("crossing UPDATE: got %d, want 491", res.StatusCode)
		}
		if res := r.phoneUpdate(t, 3, sdpWith(udpPort(r.phoneRTP), "sendrecv")); res.StatusCode != 491 {
			t.Errorf("second UPDATE: got %d, want 491", res.StatusCode)
		}
		reInv, reRes := auditPhoneReInvite(t, r.h, r.phone, r.invite, r.res, 4, sdpWith(udpPort(r.phoneRTP), "sendrecv"))
		_ = reInv
		if reRes.StatusCode != 491 {
			t.Errorf("re-INVITE during an UPDATE offer: got %d, want 491", reRes.StatusCode)
		}
		close(release)
		if res := <-first; res.StatusCode != 200 {
			t.Errorf("the first UPDATE: got %d, want 200", res.StatusCode)
		}
		if n := len(r.h.fs.received(sip.UPDATE)); n != 1 {
			t.Errorf("the switch saw %d UPDATEs, want 1", n)
		}
		r.end(t)
	})
	t.Run("update vs re-invite", func(t *testing.T) {
		r := startUpdRig(t)
		release := make(chan struct{})
		r.h.fs.setInviteHook(auditTaggedAnswerHook(r.h.fs, nil, func(req *sip.Request, tx sip.ServerTransaction) {
			select {
			case <-release:
			case <-time.After(8 * time.Second):
			}
			res := sip.NewResponseFromRequest(req, 200, "OK", []byte(r.h.fs.answerSDP(req)))
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(r.h.fs.addr)}})
			_ = tx.Respond(res)
		}))
		done := make(chan *sip.Response, 1)
		go func() {
			_, res := auditPhoneReInvite(t, r.h, r.phone, r.invite, r.res, 2, sdpWith(udpPort(r.phoneRTP), "sendrecv"))
			done <- res
		}()
		r.h.fs.waitFor(sip.INVITE, 2, 3*time.Second)
		if res := r.phoneUpdate(t, 3, sdpWith(udpPort(r.phoneRTP), "sendrecv")); res.StatusCode != 491 {
			t.Errorf("UPDATE during a re-INVITE: got %d, want 491", res.StatusCode)
		}
		if n := len(r.h.fs.received(sip.UPDATE)); n != 0 {
			t.Errorf("%d UPDATEs reached the switch during a re-INVITE", n)
		}
		close(release)
		if res := <-done; res.StatusCode != 200 {
			t.Errorf("the re-INVITE: got %d, want 200", res.StatusCode)
		}
		r.end(t)
	})
}

func (r *updRig) end(t *testing.T) {
	t.Helper()
	if res := r.phone.do(t, buildBye(r.phone, r.invite, r.res), r.h.publicUDP); res.StatusCode != 200 {
		t.Errorf("BYE: %d", res.StatusCode)
	}
	waitForRelease(t, r.h)
}

// An UPDATE with SDP inside the early dialog, before any 2xx: it works on
// the call's early media, and the later 18x restatement and the 200 repeat
// the answer it produced rather than an older one.
func TestUpdateSDPEarlyDialog(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	phoneRTP := listenRTP(t, freePort(t))
	fsRTP := listenRTP(t, h.fs.rtpPort)
	const tag = "uas-tag-upd"
	releaseA, releaseB := make(chan struct{}), make(chan struct{})
	wait := func(c chan struct{}) {
		select {
		case <-c:
		case <-time.After(8 * time.Second):
		}
	}
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		ring := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
		ring.To().Params.Add("tag", tag)
		ring.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		_ = tx.Respond(ring)
		wait(releaseA)
		prog := sip.NewResponseFromRequest(req, 183, "Session Progress", []byte(h.fs.answerSDP(req)))
		prog.To().Params.Add("tag", tag)
		prog.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		prog.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		_ = tx.Respond(prog)
		wait(releaseB)
		_ = tx.Respond(finalAnswer(h.fs, req, tag))
		return true
	})
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(udpPort(phoneRTP)))
	call := phoneUAC(t, h, phone, invite)
	var ring *sip.Response
	for ring == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 180 {
			ring = r
		}
	}
	up := waitReceived(t, h.fs, sip.INVITE, 1)[0]
	privPort := mustSDP(t, "INVITE", up.Body()).Audio.Port

	moved := listenRTP(t, freePort(t))
	req := uacRequest(sip.UPDATE, invite, ring, invite.CSeq().SeqNo+1, "127.0.0.1", 0)
	req.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody([]byte(sdpWith(udpPort(moved), "sendrecv")))
	res := phone.do(t, req, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("early UPDATE: got %d, want 200", res.StatusCode)
	}
	fwd := mustSDP(t, "early UPDATE at the switch", waitReceived(t, h.fs, sip.UPDATE, 1)[0].Body())
	if fwd.Audio.Port != privPort {
		t.Errorf("the switch was offered port %d, want the private anchor %d", fwd.Audio.Port, privPort)
	}
	ans := mustSDP(t, "early UPDATE 200", res.Body())
	if ans.Audio.Port == h.fs.rtpPort {
		t.Error("the early UPDATE's 200 carried the switch's own media port")
	}
	if !relayReaches(t, moved, loopback(ans.Audio.Port), fsRTP, rtpPacket(0, 340, 160)) {
		t.Error("early media phone -> switch never arrived")
	}
	if !relayReaches(t, fsRTP, loopback(privPort), moved, rtpPacket(0, 341, 160)) {
		t.Error("early media switch -> phone never arrived")
	}

	// The far end now sends its 183 and 200: both restate the answer the
	// UPDATE produced, and the media stays where the UPDATE put it.
	close(releaseA)
	var prog *sip.Response
	for prog == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 183 {
			prog = r
		}
	}
	if string(prog.Body()) != string(res.Body()) {
		t.Errorf("the 183 after the UPDATE undid its answer:\n%s\n---\n%s", res.Body(), prog.Body())
	}
	close(releaseB)
	var final *sip.Response
	for final == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 200 {
			final = r
		}
	}
	if string(final.Body()) != string(res.Body()) {
		t.Errorf("the 200 after the UPDATE undid its answer:\n%s\n---\n%s", res.Body(), final.Body())
	}
	sendAck(t, phone, invite, final, h.publicUDP)
	waitReceived(t, h.fs, sip.ACK, 1)
	if !relayReaches(t, moved, loopback(ans.Audio.Port), fsRTP, rtpPacket(0, 342, 160)) {
		t.Error("media phone -> switch broke when the call was answered")
	}
	if !relayReaches(t, fsRTP, loopback(privPort), moved, rtpPacket(0, 343, 160)) {
		t.Error("media switch -> phone broke when the call was answered")
	}
	if r := phone.do(t, buildBye(phone, invite, final), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// On a carrier leg an UPDATE with SDP is rebuilt in both directions: the
// carrier is offered FreeSBC's public anchor, the switch is answered with
// the private one, and nothing of either side's media address crosses.
func TestOutboundUpdateSDPHidden(t *testing.T) {
	o := startOutboundRig(t)
	tags := answerWithTag(o.carrier)
	swRTP := listenRTP(t, o.fs.rtpPort)
	carRTP := listenRTP(t, o.carrier.rtpPort)
	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	o.fs.sendAckTo2xx(t, res)
	tag := <-tags
	inv := waitReceived(t, o.carrier, sip.INVITE, 1)[0]
	waitReceived(t, o.carrier, sip.ACK, 1)
	pubAnchor := mustSDP(t, "INVITE at the carrier", inv.Body()).Audio.Port
	privAnchor := mustSDP(t, "200 at the switch", res.Body()).Audio.Port

	// The switch's UPDATE: its address in the offer, the carrier's in the
	// answer; neither crosses.
	moved := listenRTP(t, freePort(t))
	up := switchUpdateFrom(o.fs, res, 2, sdpWith(udpPort(moved), "sendrecv"))
	ares := switchSend(t, o.fs, up, res)
	if ares.StatusCode != 200 {
		t.Fatalf("UPDATE from the switch: got %d, want 200", ares.StatusCode)
	}
	cu := waitReceived(t, o.carrier, sip.UPDATE, 1)[0]
	assertHidden(t, o, "UPDATE", cu, false)
	if got := mustSDP(t, "UPDATE at the carrier", cu.Body()); got.Audio.Port != pubAnchor {
		t.Errorf("the carrier was offered port %d, want the public anchor %d", got.Audio.Port, pubAnchor)
	}
	if got := mustSDP(t, "UPDATE 200 at the switch", ares.Body()); got.Audio.Port != privAnchor {
		t.Errorf("the switch was answered with port %d, want the private anchor %d", got.Audio.Port, privAnchor)
	}
	if !relayReaches(t, moved, loopback(privAnchor), carRTP, rtpPacket(0, 350, 160)) {
		t.Error("switch -> carrier audio from the new address never arrived")
	}
	if !relayReaches(t, carRTP, loopback(pubAnchor), moved, rtpPacket(0, 351, 160)) {
		t.Error("carrier -> switch audio to the new address never arrived")
	}

	// The carrier's UPDATE toward the switch.
	carMoved := listenRTP(t, freePort(t))
	before := len(o.fs.received(sip.UPDATE))
	cres := auditInDialogWithBody(t, o.carrier, sip.UPDATE, inv, tag, 2, sdpWith(udpPort(carMoved), "sendrecv"))
	if cres.StatusCode != 200 {
		t.Fatalf("UPDATE from the carrier: got %d, want 200", cres.StatusCode)
	}
	got := o.fs.waitFor(sip.UPDATE, before+1, 3*time.Second)
	if len(got) != before+1 {
		t.Fatal("the switch never saw the carrier's UPDATE")
	}
	if p := mustSDP(t, "UPDATE at the switch", got[before].Body()).Audio.Port; p != privAnchor {
		t.Errorf("the switch was offered port %d, want the private anchor %d", p, privAnchor)
	}
	if p := mustSDP(t, "UPDATE 200 at the carrier", cres.Body()).Audio.Port; p != pubAnchor {
		t.Errorf("the carrier was answered with port %d, want the public anchor %d", p, pubAnchor)
	}
	// The switch's default answer names its original socket again.
	if !relayReaches(t, carMoved, loopback(pubAnchor), swRTP, rtpPacket(0, 352, 160)) {
		t.Error("carrier -> switch audio from the carrier's new address never arrived")
	}
	if bye := o.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Errorf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, o.harness)
}

// switchUpdateFrom builds an UPDATE with SDP from the fake switch as the UAC
// of the call whose 200 is res.
func switchUpdateFrom(f *fakeSwitch, res *sip.Response, cseq uint32, body string) *sip.Request {
	req := sip.NewRequest(sip.UPDATE, res.To().Address)
	sip.CopyHeaders("From", res, req)
	sip.CopyHeaders("To", res, req)
	sip.CopyHeaders("Call-ID", res, req)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: cseq, MethodName: sip.UPDATE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: hostOf(f.addr), Port: portOf(f.addr)}})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	copyRouteFromRecordRoute(res, req)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: hostOf(f.addr), Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	req.SetBody([]byte(body))
	return req
}

// An UPDATE with SDP in the early dialog made by the CALLEE (the switch):
// its offer is rebuilt for the phone, the phone's answer for the switch,
// media follows both, and the call's 200 afterwards restates the offer the
// phone was shown.
func TestUpdateSDPEarlyDialogCalleeOffers(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	phoneRTP := listenRTP(t, freePort(t))
	fsMoved := listenRTP(t, freePort(t))
	phoneMoved := listenRTP(t, freePort(t))
	const tag = "uas-tag-callee"
	release := make(chan struct{})
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		ring := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
		ring.To().Params.Add("tag", tag)
		ring.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
		_ = tx.Respond(ring)
		select {
		case <-release:
		case <-time.After(8 * time.Second):
		}
		_ = tx.Respond(finalAnswer(h.fs, req, tag))
		return true
	})
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(udpPort(phoneRTP)))
	call := phoneUAC(t, h, phone, invite)
	call.provisional(t, 180)
	up := waitReceived(t, h.fs, sip.INVITE, 1)[0]
	privPort := mustSDP(t, "INVITE", up.Body()).Audio.Port

	phoneAnswersUpdate(phone, udpPort(phoneMoved))
	res := auditInDialogWithBody(t, h.fs, sip.UPDATE, up, tag, 2, sdpWith(udpPort(fsMoved), "sendrecv"))
	if res.StatusCode != 200 {
		t.Fatalf("early UPDATE from the switch: got %d, want 200", res.StatusCode)
	}
	if ans := mustSDP(t, "200 at the switch", res.Body()); ans.Audio.Port != privPort {
		t.Errorf("the switch was answered with port %d, want the private anchor %d", ans.Audio.Port, privPort)
	}
	seen := mustInbound(t, phone, sip.UPDATE)
	offer := mustSDP(t, "UPDATE at the phone", seen.Body())
	if offer.Audio.Port == h.fs.rtpPort || offer.Audio.Port == udpPort(fsMoved) {
		t.Errorf("the phone was offered a media port of the switch: %d", offer.Audio.Port)
	}
	if !relayReaches(t, fsMoved, loopback(privPort), phoneMoved, rtpPacket(0, 360, 160)) {
		t.Error("early media switch -> phone never arrived")
	}
	if !relayReaches(t, phoneMoved, loopback(offer.Audio.Port), fsMoved, rtpPacket(0, 361, 160)) {
		t.Error("early media phone -> switch never arrived")
	}

	close(release)
	final := call.final200(t)
	if string(final.Body()) != string(seen.Body()) {
		t.Errorf("the 200 did not restate the offer the phone was shown:\n%s\n---\n%s", seen.Body(), final.Body())
	}
	sendAck(t, phone, invite, final, h.publicUDP)
	waitReceived(t, h.fs, sip.ACK, 1)
	if !relayReaches(t, phoneMoved, loopback(offer.Audio.Port), fsMoved, rtpPacket(0, 362, 160)) {
		t.Error("media broke when the call was answered")
	}
	if r := phone.do(t, buildBye(phone, invite, final), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}
