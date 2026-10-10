package edge

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file tests delayed-offer exchanges (offerless.go): an INVITE or
// re-INVITE without SDP, the callee's offer in its 2xx or a reliable 18x,
// and the caller's answer in the ACK or the PRACK.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// relayBlocked reports whether a packet sent through the SBC does NOT come
// out the other side: no media may flow before an owed answer is applied.
func relayBlocked(from *net.UDPConn, via *net.UDPAddr, to *net.UDPConn, seq uint16) bool {
	buf := make([]byte, 2000)
	for i := 0; i < 3; i++ {
		_, _ = from.WriteToUDP(rtpPacket(0, seq+uint16(i), 160), via)
		_ = to.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		if _, _, err := to.ReadFromUDP(buf); err == nil {
			return false
		}
	}
	return true
}

// ackFor builds an ACK for the 2xx res of req, with an answer body when one
// is given, routed by the Record-Route set of rr.
func ackFor(req *sip.Request, res, rr *sip.Response, host string, port int, body string) *sip.Request {
	ack := sip.NewRequest(sip.ACK, req.Recipient)
	sip.CopyHeaders("From", req, ack)
	sip.CopyHeaders("Call-ID", req, ack)
	ack.AppendHeader(sip.HeaderClone(res.To()))
	ack.AppendHeader(&sip.CSeqHeader{SeqNo: req.CSeq().SeqNo, MethodName: sip.ACK})
	mf := sip.MaxForwardsHeader(70)
	ack.AppendHeader(&mf)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: host, Port: port, Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	ack.PrependHeader(via)
	copyRouteFromRecordRoute(rr, ack)
	if body != "" {
		ack.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		ack.SetBody([]byte(body))
	}
	return ack
}

// phoneAck sends the phone's ACK (answer body optional).
func phoneAck(t *testing.T, h *harness, phone *client, req *sip.Request, res *sip.Response, body string) {
	t.Helper()
	ack := ackFor(req, res, res, "127.0.0.1", 0, body)
	ack.SetTransport("UDP")
	ack.SetDestination(h.publicUDP)
	if err := phone.cli.WriteRequest(ack, noBuild); err != nil {
		t.Fatalf("phone ACK: %v", err)
	}
}

// switchAck sends the fake switch's ACK for a 2xx to an INVITE it placed.
func switchAck(t *testing.T, f *fakeSwitch, req *sip.Request, res *sip.Response, body string) {
	t.Helper()
	ack := ackFor(req, res, res, hostOf(f.addr), portOf(f.addr), body)
	ack.SetTransport("UDP")
	ack.SetDestination(f.inDialogDest(t, ack, res))
	ack.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}
	if err := f.cli.WriteRequest(ack); err != nil {
		t.Fatalf("switch ACK: %v", err)
	}
}

// offerIn200 makes the fake switch answer an INVITE with a 200 that carries
// ITS offer (sdp), under tag.
func offerIn200(f *fakeSwitch, tag, body string) func(*sip.Request, sip.ServerTransaction) bool {
	return func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(body))
		res.To().Params.Add("tag", tag)
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(f.addr)}})
		_ = tx.Respond(res)
		return true
	}
}

// finalResponse reads responses until the 200.
func (c *uacCall) final200(t *testing.T) *sip.Response {
	t.Helper()
	for {
		if r := c.next(t, 5*time.Second); r.StatusCode >= 200 {
			if r.StatusCode != 200 {
				t.Fatalf("final response %d, want 200", r.StatusCode)
			}
			return r
		}
	}
}

func (c *uacCall) provisional(t *testing.T, code int) *sip.Response {
	t.Helper()
	for {
		r := c.next(t, 5*time.Second)
		if r.StatusCode == code {
			return r
		}
		if r.StatusCode >= 200 {
			t.Fatalf("final %d before a %d", r.StatusCode, code)
		}
	}
}

// earlySession is the media session of a call still being set up.
func earlySession(t *testing.T, h *harness, req *sip.Request) *mediaSession {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if d, ok := h.srv.dialogs.early(fsip.CallID(req), fsip.FromTag(req)); ok {
			if s := d.session(); s != nil {
				return s
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no media session was allocated")
	return nil
}

// offerlessPhoneCall sends an offerless INVITE from a phone through a
// harness whose switch offers in its 200, and returns the call.
type olCall struct {
	h        *harness
	phone    *client
	phoneRTP *net.UDPConn
	fsRTP    *net.UDPConn
	invite   *sip.Request
	call     *uacCall
}

func startOfferlessToSwitch(t *testing.T, hook func(h *harness) func(*sip.Request, sip.ServerTransaction) bool) *olCall {
	t.Helper()
	h := startHarness(t, false)
	h.fs.setInviteHook(hook(h))
	phone := newUDPClient(t)
	o := &olCall{h: h, phone: phone, phoneRTP: listenRTP(t, freePort(t)), fsRTP: listenRTP(t, h.fs.rtpPort)}
	o.invite = phone.buildInvite("1001", "2002", "example.com", "")
	o.call = phoneUAC(t, h, phone, o.invite)
	return o
}

func (o *olCall) phoneAnswer() string { return phoneOfferSDP(udpPort(o.phoneRTP)) }

// An offerless INVITE from a phone to the switch: nothing but the INVITE
// reaches the switch, the switch's offer in the 200 comes out as FreeSBC's
// public offer, the phone's answer in the ACK goes to the switch as
// FreeSBC's private answer, and media flows only from then on.
func TestOfferlessInviteToSwitch(t *testing.T) {
	o := startOfferlessToSwitch(t, func(h *harness) func(*sip.Request, sip.ServerTransaction) bool {
		return offerIn200(h.fs, "uas-ol-1", sdpWith(h.fs.rtpPort, "sendrecv"))
	})
	h := o.h
	up := waitReceived(t, h.fs, sip.INVITE, 1)[0]
	if len(up.Body()) != 0 || headerValue(up, "Content-Type") != "" {
		t.Errorf("the offerless INVITE reached the switch with a body: %q", up.Body())
	}
	res := o.call.final200(t)
	d := waitForDialog(t, h, fsip.CallID(o.invite))
	sess := d.session()
	offer := mustSDP(t, "200 at the phone", res.Body())
	if offer.Audio.Port != sess.publicPort || offer.Audio.Port == h.fs.rtpPort {
		t.Errorf("the phone was offered port %d, want the public anchor %d", offer.Audio.Port, sess.publicPort)
	}

	// No media before the answer.
	if !relayBlocked(o.phoneRTP, loopback(sess.publicPort), o.fsRTP, 100) {
		t.Error("media flowed before the answer was applied")
	}

	phoneAck(t, h, o.phone, o.invite, res, o.phoneAnswer())
	ack := waitReceived(t, h.fs, sip.ACK, 1)[0]
	ans := mustSDP(t, "ACK at the switch", ack.Body())
	if ans.Audio.Port != sess.privatePort {
		t.Errorf("the switch was answered with port %d, want the private anchor %d", ans.Audio.Port, sess.privatePort)
	}
	if !relayReaches(t, o.phoneRTP, loopback(sess.publicPort), o.fsRTP, rtpPacket(0, 110, 160)) {
		t.Error("phone -> switch audio never arrived")
	}
	if !relayReaches(t, o.fsRTP, loopback(sess.privatePort), o.phoneRTP, rtpPacket(0, 111, 160)) {
		t.Error("switch -> phone audio never arrived")
	}
	if r := o.phone.do(t, buildBye(o.phone, o.invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// An answer in the ACK that is missing, has no codec in common, renumbers a
// payload type or is not SDP at all: the ACK is forwarded without a body
// and both ends are ended.
func TestOfferlessInviteBadAnswerEndsCall(t *testing.T) {
	bodies := map[string]string{
		"none": "",
		"no common codec": fmt.Sprintf("v=0\r\no=p 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 97\r\na=rtpmap:97 speex/16000\r\n", 40000),
		"renumbered": fmt.Sprintf("v=0\r\no=p 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
			"m=audio %d RTP/AVP 96\r\na=rtpmap:96 PCMU/8000\r\n", 40000),
		"garbage": "not sdp\r\n",
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			o := startOfferlessToSwitch(t, func(h *harness) func(*sip.Request, sip.ServerTransaction) bool {
				return offerIn200(h.fs, "uas-ol-bad", sdpWith(h.fs.rtpPort, "sendrecv"))
			})
			res := o.call.final200(t)
			phoneAck(t, o.h, o.phone, o.invite, res, body)
			ack := waitReceived(t, o.h.fs, sip.ACK, 1)[0]
			if len(ack.Body()) != 0 {
				t.Errorf("the ACK reached the switch with a body: %q", ack.Body())
			}
			waitReceived(t, o.h.fs, sip.BYE, 1)
			if waitInbound(o.phone, sip.BYE, 3*time.Second) == nil {
				t.Error("the phone was never sent a BYE")
			}
			waitForRelease(t, o.h)
		})
	}
}

// An ACK that never arrives: after the wait the call is ended on both
// sides and nothing leaks.
func TestOfferlessInviteLostACK(t *testing.T) {
	o := startOfferlessToSwitch(t, func(h *harness) func(*sip.Request, sip.ServerTransaction) bool {
		return offerIn200(h.fs, "uas-ol-lost", sdpWith(h.fs.rtpPort, "sendrecv"))
	})
	o.h.srv.ackWait.Store(int64(600 * time.Millisecond))
	o.call.final200(t)
	waitReceived(t, o.h.fs, sip.BYE, 1)
	if waitInbound(o.phone, sip.BYE, 3*time.Second) == nil {
		t.Error("the phone was never sent a BYE")
	}
	waitForRelease(t, o.h)
}

// A switch offering in a reliable 183: the offer reaches the phone as
// FreeSBC's, the answer in the PRACK reaches the switch as FreeSBC's, media
// flows from the PRACK on, and the 200 that follows carries no new offer.
// An unreliable 183 with SDP in the same call is not an offer: the phone
// sees it without a body.
func TestOfferlessReliable183OfferPrackAnswer(t *testing.T) {
	const tag = "uas-ol-183"
	release := make(chan struct{})
	o := startOfferlessToSwitch(t, func(h *harness) func(*sip.Request, sip.ServerTransaction) bool {
		return func(req *sip.Request, tx sip.ServerTransaction) bool {
			plain := sip.NewResponseFromRequest(req, 183, "Session Progress", []byte(sdpWith(h.fs.rtpPort+2, "sendrecv")))
			plain.To().Params.Add("tag", tag)
			plain.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			_ = tx.Respond(plain)
			rel := sip.NewResponseFromRequest(req, 183, "Session Progress", []byte(sdpWith(h.fs.rtpPort, "sendrecv")))
			rel.To().Params.Add("tag", tag)
			rel.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			rel.AppendHeader(sip.NewHeader("Require", "100rel"))
			rel.AppendHeader(sip.NewHeader("RSeq", "5"))
			rel.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
			_ = tx.Respond(rel.Clone())
			_ = tx.Respond(rel.Clone()) // retransmission
			select {
			case <-release:
			case <-time.After(8 * time.Second):
			}
			ok := sip.NewResponseFromRequest(req, 200, "OK", nil)
			ok.To().Params.Add("tag", tag)
			ok.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(h.fs.addr)}})
			_ = tx.Respond(ok)
			return true
		}
	})
	h := o.h
	var plain, rel *sip.Response
	for plain == nil || rel == nil {
		r := o.call.provisional(t, 183)
		if headerValue(r, "RSeq") != "" || headerTokens(r, "Require")["100REL"] {
			if rel == nil {
				rel = r
			}
		} else {
			if plain == nil {
				plain = r
			}
		}
	}
	if len(plain.Body()) != 0 {
		t.Errorf("an unreliable 183 of an offerless call reached the phone with a body: %q", plain.Body())
	}
	sess := earlySession(t, h, o.invite)
	offer := mustSDP(t, "reliable 183", rel.Body())
	if offer.Audio.Port != sess.publicPort {
		t.Errorf("the phone was offered port %d, want the public anchor %d", offer.Audio.Port, sess.publicPort)
	}
	if headerValue(rel, "RSeq") != "5" || !headerTokens(rel, "Require")["100REL"] {
		t.Errorf("reliable 183 lost Require/RSeq: %v", rel.Headers())
	}
	if !relayBlocked(o.phoneRTP, loopback(sess.publicPort), o.fsRTP, 120) {
		t.Error("media flowed before the answer was applied")
	}

	prack := prackFor(o.invite, rel, o.invite.CSeq().SeqNo+1, "127.0.0.1", 0)
	prack.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	prack.SetBody([]byte(o.phoneAnswer()))
	if res := o.phone.do(t, prack, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("PRACK with the answer: got %d, want 200", res.StatusCode)
	}
	pr := waitReceived(t, h.fs, sip.PRACK, 1)[0]
	if ans := mustSDP(t, "PRACK at the switch", pr.Body()); ans.Audio.Port != sess.privatePort {
		t.Errorf("the switch was answered with port %d, want the private anchor %d", ans.Audio.Port, sess.privatePort)
	}
	if !relayReaches(t, o.phoneRTP, loopback(sess.publicPort), o.fsRTP, rtpPacket(0, 130, 160)) {
		t.Error("early media phone -> switch never arrived")
	}
	if !relayReaches(t, o.fsRTP, loopback(sess.privatePort), o.phoneRTP, rtpPacket(0, 131, 160)) {
		t.Error("early media switch -> phone never arrived")
	}

	close(release)
	res := o.call.final200(t)
	if string(res.Body()) != string(rel.Body()) && len(res.Body()) != 0 {
		t.Errorf("the 200 carried a different offer than the reliable 183:\n%s", res.Body())
	}
	phoneAck(t, h, o.phone, o.invite, res, "")
	ack := waitReceived(t, h.fs, sip.ACK, 1)[0]
	if len(ack.Body()) != 0 {
		t.Errorf("the ACK reached the switch with a body: %q", ack.Body())
	}
	if !relayReaches(t, o.phoneRTP, loopback(sess.publicPort), o.fsRTP, rtpPacket(0, 132, 160)) {
		t.Error("media broke when the call was answered")
	}
	if r := o.phone.do(t, buildBye(o.phone, o.invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// A PRACK with SDP when no answer is owed is refused and never forwarded.
func TestPrackSDPWithoutOwedAnswerRefused(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	phoneRTP := listenRTP(t, freePort(t))
	const tag = "uas-ol-none"
	release := make(chan struct{})
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(reliableProvisional(h.fs, req, 183, tag, 3))
		select {
		case <-release:
		case <-time.After(8 * time.Second):
		}
		_ = tx.Respond(finalAnswer(h.fs, req, tag))
		return true
	})
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(udpPort(phoneRTP)))
	call := phoneUAC(t, h, phone, invite)
	prov := call.provisional(t, 183)
	pr := prackFor(invite, prov, invite.CSeq().SeqNo+1, "127.0.0.1", 0)
	pr.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	pr.SetBody([]byte(phoneOfferSDP(40000)))
	if res := phone.do(t, pr, h.publicUDP); res.StatusCode != 488 {
		t.Errorf("PRACK with SDP and nothing owed: got %d, want 488", res.StatusCode)
	}
	if n := len(h.fs.received(sip.PRACK)); n != 0 {
		t.Errorf("%d PRACKs reached the switch", n)
	}
	close(release)
	res := call.final200(t)
	sendAck(t, phone, invite, res, h.publicUDP)
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// An offerless INVITE from the switch to a registered phone: the phone's
// offer in its 200 is rebuilt for the switch, the switch's answer in the
// ACK for the phone, and media flows after the ACK.
func TestOfferlessInviteToClient(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	phoneRTP := listenRTP(t, freePort(t))
	fsRTP := listenRTP(t, h.fs.rtpPort)
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(udpPort(phoneRTP))))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
	})
	req := h.fs.callRequest(ruri, h.privateSIP, "")
	call := startUAC(t, h.fs.cli, req)
	res := call.final200(t)
	got := waitInbound(phone, sip.INVITE, 3*time.Second)
	if got == nil || len(got.Body()) != 0 {
		t.Fatalf("the phone's INVITE: %v", got)
	}
	d := waitForDialog(t, h, fsip.CallID(req))
	sess := d.session()
	if offer := mustSDP(t, "200 at the switch", res.Body()); offer.Audio.Port != sess.privatePort {
		t.Errorf("the switch was offered port %d, want the private anchor %d", offer.Audio.Port, sess.privatePort)
	}
	if !relayBlocked(fsRTP, loopback(sess.privatePort), phoneRTP, 140) {
		t.Error("media flowed before the answer was applied")
	}
	switchAck(t, h.fs, req, res, sdpWith(h.fs.rtpPort, "sendrecv"))
	ack := waitInbound(phone, sip.ACK, 3*time.Second)
	if ack == nil {
		t.Fatal("the phone never saw the ACK")
	}
	if ans := mustSDP(t, "ACK at the phone", ack.Body()); ans.Audio.Port != sess.publicPort {
		t.Errorf("the phone was answered with port %d, want the public anchor %d", ans.Audio.Port, sess.publicPort)
	}
	if !relayReaches(t, fsRTP, loopback(sess.privatePort), phoneRTP, rtpPacket(0, 150, 160)) {
		t.Error("switch -> phone audio never arrived")
	}
	if !relayReaches(t, phoneRTP, loopback(sess.publicPort), fsRTP, rtpPacket(0, 151, 160)) {
		t.Error("phone -> switch audio never arrived")
	}
	if bye := h.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Errorf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, h)
}

// An offerless INVITE to a carrier: the carrier's offer in the 200 reaches
// the switch as FreeSBC's, the switch's answer in the ACK reaches the
// carrier as FreeSBC's, and the ACK is hidden like every other message.
func TestOfferlessInviteToCarrier(t *testing.T) {
	o := startOutboundRig(t)
	o.carrier.setInviteHook(offerIn200(o.carrier, "car-ol-1", sdpWith(o.carrier.rtpPort, "sendrecv")))
	swRTP := listenRTP(t, o.fs.rtpPort)
	carRTP := listenRTP(t, o.carrier.rtpPort)
	req := o.fs.callRequest(o.ruri("+442071234567"), o.privateSIP, "")
	call := startUAC(t, o.fs.cli, req)
	res := call.final200(t)
	inv := waitReceived(t, o.carrier, sip.INVITE, 1)[0]
	assertHidden(t, o, "INVITE", inv, true)
	if len(inv.Body()) != 0 {
		t.Errorf("the offerless INVITE reached the carrier with a body: %q", inv.Body())
	}
	d := waitForDialog(t, o.harness, fsip.CallID(req))
	sess := d.session()
	if offer := mustSDP(t, "200 at the switch", res.Body()); offer.Audio.Port != sess.privatePort {
		t.Errorf("the switch was offered port %d, want the private anchor %d", offer.Audio.Port, sess.privatePort)
	}
	if !relayBlocked(swRTP, loopback(sess.privatePort), carRTP, 160) {
		t.Error("media flowed before the answer was applied")
	}
	switchAck(t, o.fs, req, res, sdpWith(o.fs.rtpPort, "sendrecv"))
	ack := waitReceived(t, o.carrier, sip.ACK, 1)[0]
	assertHidden(t, o, "ACK", ack, false)
	if ans := mustSDP(t, "ACK at the carrier", ack.Body()); ans.Audio.Port != sess.publicPort {
		t.Errorf("the carrier was answered with port %d, want the public anchor %d", ans.Audio.Port, sess.publicPort)
	}
	if !relayReaches(t, swRTP, loopback(sess.privatePort), carRTP, rtpPacket(0, 170, 160)) {
		t.Error("switch -> carrier audio never arrived")
	}
	if !relayReaches(t, carRTP, loopback(sess.publicPort), swRTP, rtpPacket(0, 171, 160)) {
		t.Error("carrier -> switch audio never arrived")
	}
	if bye := o.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Errorf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, o.harness)
}

// The carrier's offer in a reliable 183 and the switch's answer in the
// PRACK: both bodies are FreeSBC's and the PRACK is hidden.
func TestOfferlessCarrierReliable183PrackHidden(t *testing.T) {
	o := startOutboundRig(t)
	const tag = "car-ol-2"
	release := make(chan struct{})
	o.carrier.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		prov := reliableProvisional(o.carrier, req, 183, tag, 9)
		prov.SetBody([]byte(sdpWith(o.carrier.rtpPort, "sendrecv")))
		_ = tx.Respond(prov)
		select {
		case <-release:
		case <-time.After(8 * time.Second):
		}
		ok := sip.NewResponseFromRequest(req, 200, "OK", nil)
		ok.To().Params.Add("tag", tag)
		ok.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(o.carrier.addr)}})
		_ = tx.Respond(ok)
		return true
	})
	swRTP := listenRTP(t, o.fs.rtpPort)
	carRTP := listenRTP(t, o.carrier.rtpPort)
	req := o.fs.callRequest(o.ruri("+442071234567"), o.privateSIP, "")
	call := startUAC(t, o.fs.cli, req)
	prov := call.provisional(t, 183)
	sess := earlySession(t, o.harness, req)
	if offer := mustSDP(t, "183 at the switch", prov.Body()); offer.Audio.Port != sess.privatePort {
		t.Errorf("the switch was offered port %d, want the private anchor %d", offer.Audio.Port, sess.privatePort)
	}
	if vias := prov.GetHeaders("Via"); len(vias) != 1 || prov.Via().Port != portOf(o.fs.addr) {
		t.Errorf("183 Vias = %v, want exactly the switch's own", vias)
	}
	pr := prackFor(req, prov, 2, hostOf(o.fs.addr), portOf(o.fs.addr))
	pr.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: hostOf(o.fs.addr), Port: portOf(o.fs.addr)}})
	pr.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	pr.SetBody([]byte(sdpWith(o.fs.rtpPort, "sendrecv")))
	if res := switchSend(t, o.fs, pr, prov); res.StatusCode != 200 {
		t.Fatalf("PRACK: got %d, want 200", res.StatusCode)
	}
	cp := waitReceived(t, o.carrier, sip.PRACK, 1)[0]
	assertHidden(t, o, "PRACK", cp, false)
	if ans := mustSDP(t, "PRACK at the carrier", cp.Body()); ans.Audio.Port != sess.publicPort {
		t.Errorf("the carrier was answered with port %d, want the public anchor %d", ans.Audio.Port, sess.publicPort)
	}
	if !relayReaches(t, swRTP, loopback(sess.privatePort), carRTP, rtpPacket(0, 180, 160)) {
		t.Error("early media switch -> carrier never arrived")
	}
	if !relayReaches(t, carRTP, loopback(sess.publicPort), swRTP, rtpPacket(0, 181, 160)) {
		t.Error("early media carrier -> switch never arrived")
	}
	close(release)
	res := call.final200(t)
	switchAck(t, o.fs, req, res, "")
	ack := waitReceived(t, o.carrier, sip.ACK, 1)[0]
	assertHidden(t, o, "ACK", ack, false)
	if bye := o.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Errorf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, o.harness)
}

// offerlessReInvite sends an offerless re-INVITE from the phone of a
// confirmed rig, the switch offering in its 200, and returns the request
// and the 200.
func offerlessReInvite(t *testing.T, r *updRig, fsPort int) (*sip.Request, *sip.Response) {
	t.Helper()
	r.h.fs.setInviteHook(auditTaggedAnswerHook(r.h.fs, nil, func(req *sip.Request, tx sip.ServerTransaction) {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(sdpWith(fsPort, "sendrecv")))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(r.h.fs.addr)}})
		_ = tx.Respond(res)
	}))
	req := uacRequest(sip.INVITE, r.invite, r.res, 2, "127.0.0.1", 0)
	req.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
	return req, r.phone.do(t, req, r.h.publicUDP)
}

// An offerless re-INVITE: the switch's offer in the 200 is rebuilt for the
// phone on the anchor it already holds, the phone's answer in the ACK is
// rebuilt for the switch, and the media follows the new addresses only
// after the ACK.
func TestOfferlessReInvite(t *testing.T) {
	r := startUpdRig(t)
	fsMoved := listenRTP(t, freePort(t))
	phoneMoved := listenRTP(t, freePort(t))
	req, res := offerlessReInvite(t, r, udpPort(fsMoved))
	if res.StatusCode != 200 {
		t.Fatalf("re-INVITE: got %d, want 200", res.StatusCode)
	}
	if got := r.h.fs.received(sip.INVITE); len(got) != 2 || len(got[1].Body()) != 0 {
		t.Fatalf("the offerless re-INVITE reached the switch as %v", got)
	}
	if offer := mustSDP(t, "200 at the phone", res.Body()); offer.Audio.Port != r.pubPort {
		t.Errorf("the phone was offered port %d, want its public anchor %d", offer.Audio.Port, r.pubPort)
	}
	// Until the ACK the old addresses stay.
	if !relayReaches(t, r.phoneRTP, loopback(r.pubPort), r.fsRTP, rtpPacket(0, 190, 160)) {
		t.Error("media broke while the answer was owed")
	}
	// Glare: while the answer is owed no other offer is forwarded.
	if up := r.phoneUpdate(t, 3, sdpWith(udpPort(r.phoneRTP), "sendrecv")); up.StatusCode != 491 {
		t.Errorf("UPDATE while an answer is owed: got %d, want 491", up.StatusCode)
	}
	if up := r.switchUpdate(t, 2, sdpWith(r.h.fs.rtpPort, "sendrecv")); up.StatusCode != 491 {
		t.Errorf("switch UPDATE while an answer is owed: got %d, want 491", up.StatusCode)
	}
	if n := len(r.h.fs.received(sip.UPDATE)); n != 0 {
		t.Errorf("%d UPDATEs were forwarded while an answer was owed", n)
	}

	phoneAck(t, r.h, r.phone, req, res, sdpWith(udpPort(phoneMoved), "sendrecv"))
	acks := waitReceived(t, r.h.fs, sip.ACK, 2)
	if ans := mustSDP(t, "ACK at the switch", acks[1].Body()); ans.Audio.Port != r.privPort {
		t.Errorf("the switch was answered with port %d, want its private anchor %d", ans.Audio.Port, r.privPort)
	}
	if !relayReaches(t, phoneMoved, loopback(r.pubPort), fsMoved, rtpPacket(0, 191, 160)) {
		t.Error("phone -> switch audio at the new addresses never arrived")
	}
	if !relayReaches(t, fsMoved, loopback(r.privPort), phoneMoved, rtpPacket(0, 192, 160)) {
		t.Error("switch -> phone audio at the new addresses never arrived")
	}
	// The slot is free again.
	if up := r.phoneUpdate(t, 3, sdpWith(udpPort(phoneMoved), "sendrecv")); up.StatusCode != 200 {
		t.Errorf("UPDATE after the ACK: got %d, want 200", up.StatusCode)
	}
	r.end(t)
}

// A re-INVITE whose ACK is lost: the call does not hang; the owed answer
// times out and both ends are ended.
func TestOfferlessReInviteLostACK(t *testing.T) {
	r := startUpdRig(t)
	r.h.srv.ackWait.Store(int64(600 * time.Millisecond))
	_, res := offerlessReInvite(t, r, r.h.fs.rtpPort)
	if res.StatusCode != 200 {
		t.Fatalf("re-INVITE: got %d, want 200", res.StatusCode)
	}
	waitReceived(t, r.h.fs, sip.BYE, 1)
	if waitInbound(r.phone, sip.BYE, 3*time.Second) == nil {
		t.Error("the phone was never sent a BYE")
	}
	waitForRelease(t, r.h)
}

// An offerless re-INVITE answered with no usable answer in the ACK ends the
// call after forwarding the ACK without a body.
func TestOfferlessReInviteBadAnswerEndsCall(t *testing.T) {
	r := startUpdRig(t)
	req, res := offerlessReInvite(t, r, r.h.fs.rtpPort)
	phoneAck(t, r.h, r.phone, req, res, "")
	acks := waitReceived(t, r.h.fs, sip.ACK, 2)
	if len(acks[1].Body()) != 0 {
		t.Errorf("the ACK reached the switch with a body: %q", acks[1].Body())
	}
	waitReceived(t, r.h.fs, sip.BYE, 1)
	waitForRelease(t, r.h)
}

// A body in an ACK that answers nothing is dropped, not forwarded.
func TestAckBodyWithoutOwedAnswerDropped(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	phoneRTP := listenRTP(t, freePort(t))
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(udpPort(phoneRTP)))
	call := phoneUAC(t, h, phone, invite)
	res := call.final200(t)
	phoneAck(t, h, phone, invite, res, phoneOfferSDP(40000))
	ack := waitReceived(t, h.fs, sip.ACK, 1)[0]
	if len(ack.Body()) != 0 || strings.Contains(ack.String(), "m=audio") {
		t.Errorf("an unsolicited ACK body reached the switch: %q", ack.Body())
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// An offerless re-INVITE from the SWITCH (3pcc or a media renegotiation):
// the phone's offer in its 200 is rebuilt for the switch on its private
// anchor, the switch's answer in the ACK is rebuilt for the phone, and the
// media follows the new addresses only after the ACK.
func TestOfferlessReInviteFromSwitch(t *testing.T) {
	r := startUpdRig(t)
	phoneMoved := listenRTP(t, freePort(t))
	fsMoved := listenRTP(t, freePort(t))
	got := make(chan *sip.Request, 4)
	r.phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		got <- req.Clone()
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(udpPort(phoneMoved))))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
		_ = tx.Respond(res)
	})
	req, res := auditInDialogRaw(t, r.h.fs, sip.INVITE, r.upInv, r.fsTag, 2, "")
	if res.StatusCode != 200 {
		t.Fatalf("re-INVITE from the switch: got %d, want 200", res.StatusCode)
	}
	if in := <-got; len(in.Body()) != 0 {
		t.Fatalf("the offerless re-INVITE reached the phone with a body: %q", in.Body())
	}
	if offer := mustSDP(t, "200 at the switch", res.Body()); offer.Audio.Port != r.privPort {
		t.Errorf("the switch was offered port %d, want its private anchor %d", offer.Audio.Port, r.privPort)
	}
	// Until the ACK the old addresses stay.
	if !relayReaches(t, r.phoneRTP, loopback(r.pubPort), r.fsRTP, rtpPacket(0, 200, 160)) {
		t.Error("media broke while the answer was owed")
	}
	auditAckInDialogBody(t, r.h.fs, req, res, sdpWith(udpPort(fsMoved), "sendrecv"))
	ack := mustInbound(t, r.phone, sip.ACK)
	if ans := mustSDP(t, "ACK at the phone", ack.Body()); ans.Audio.Port != r.pubPort {
		t.Errorf("the phone was answered with port %d, want its public anchor %d", ans.Audio.Port, r.pubPort)
	}
	if !relayReaches(t, phoneMoved, loopback(r.pubPort), fsMoved, rtpPacket(0, 201, 160)) {
		t.Error("phone -> switch audio at the new addresses never arrived")
	}
	if !relayReaches(t, fsMoved, loopback(r.privPort), phoneMoved, rtpPacket(0, 202, 160)) {
		t.Error("switch -> phone audio at the new addresses never arrived")
	}
	r.end(t)
}
