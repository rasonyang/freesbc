package edge

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file tests PRACK / 100rel (RFC 3262) and UPDATE (RFC 3311) through
// the proxy: reliable 18x relayed with Require and RSeq intact, PRACK and
// body-less UPDATE forwarded in early and confirmed dialogs, and the
// SDP-bearing forms refused until they are handled.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// uacCall is an INVITE in flight whose every provisional the test can read.
type uacCall struct {
	req  *sip.Request
	resp chan *sip.Response
}

// startUAC sends req through cli and publishes every response on a channel.
func startUAC(t *testing.T, cli *sipgo.Client, req *sip.Request) *uacCall {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	tx, err := cli.TransactionRequest(ctx, req.Clone())
	if err != nil {
		t.Fatalf("send INVITE: %v", err)
	}
	c := &uacCall{req: req, resp: make(chan *sip.Response, 32)}
	go func() {
		defer tx.Terminate()
		for {
			select {
			case res, ok := <-tx.Responses():
				if !ok {
					return
				}
				c.resp <- res
			case <-tx.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return c
}

// next returns the next response, failing the test after d.
func (c *uacCall) next(t *testing.T, d time.Duration) *sip.Response {
	t.Helper()
	select {
	case res := <-c.resp:
		return res
	case <-time.After(d):
		t.Fatal("no response from the proxy")
		return nil
	}
}

// phoneUAC starts a phone INVITE toward the proxy.
func phoneUAC(t *testing.T, h *harness, phone *client, req *sip.Request) *uacCall {
	req.SetTransport("UDP")
	req.SetDestination(h.publicUDP)
	return startUAC(t, phone.cli, req)
}

// uacRequest builds an in-dialog request from the UAC of invite, routed by
// the Record-Route set of res (a response in the dialog), the way a UAC
// does.
func uacRequest(method sip.RequestMethod, invite *sip.Request, res *sip.Response, cseq uint32, host string, port int) *sip.Request {
	req := sip.NewRequest(method, invite.Recipient)
	sip.CopyHeaders("From", invite, req)
	sip.CopyHeaders("Call-ID", invite, req)
	req.AppendHeader(sip.HeaderClone(res.To()))
	req.AppendHeader(&sip.CSeqHeader{SeqNo: cseq, MethodName: method})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: host, Port: port, Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	copyRouteFromRecordRoute(res, req)
	return req
}

// prackFor builds the PRACK acknowledging the reliable response res.
func prackFor(invite *sip.Request, res *sip.Response, cseq uint32, host string, port int) *sip.Request {
	req := uacRequest(sip.PRACK, invite, res, cseq, host, port)
	rseq := "1" // a response in a confirmed dialog has none; the proxy does not check it
	if v := headerValue(res, "RSeq"); v != "" {
		rseq = v
	}
	req.AppendHeader(sip.NewHeader("RAck", rseq+" "+strconv.Itoa(int(invite.CSeq().SeqNo))+" INVITE"))
	return req
}

// switchSend sends an in-dialog request from the fake switch (the UAC of
// the call it placed) and returns the final response.
func switchSend(t *testing.T, f *fakeSwitch, req *sip.Request, res *sip.Response) *sip.Response {
	t.Helper()
	req.SetTransport("UDP")
	req.SetDestination(f.inDialogDest(t, req, res))
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}
	ctx, cancel := timeoutCtx(10 * time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("switch %s: %v", req.Method, err)
	}
	defer tx.Terminate()
	for {
		select {
		case r, ok := <-tx.Responses():
			if !ok {
				t.Fatalf("switch %s: no final response", req.Method)
			}
			if r.StatusCode >= 200 {
				return r
			}
		case <-tx.Done():
			t.Fatalf("switch %s: %v", req.Method, tx.Err())
		case <-ctx.Done():
			t.Fatalf("switch %s timed out", req.Method)
		}
	}
}

// reliableProvisional is a 18x with the far end's own SDP answer, a To
// tag, Require: 100rel and RSeq, from the UAS on f.
func reliableProvisional(f *fakeSwitch, req *sip.Request, code int, tag string, rseq int) *sip.Response {
	res := sip.NewResponseFromRequest(req, code, "Session Progress", []byte(f.answerSDP(req)))
	res.To().Params.Add("tag", tag)
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res.AppendHeader(sip.NewHeader("Require", "100rel"))
	res.AppendHeader(sip.NewHeader("RSeq", strconv.Itoa(rseq)))
	res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(f.addr)}})
	return res
}

// finalAnswer is the 200 with the far end's SDP for the same dialog.
func finalAnswer(f *fakeSwitch, req *sip.Request, tag string) *sip.Response {
	res := sip.NewResponseFromRequest(req, 200, "OK", []byte(f.answerSDP(req)))
	res.To().Params.Add("tag", tag)
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(f.addr)}})
	return res
}

func waitReceived(t *testing.T, f *fakeSwitch, m sip.RequestMethod, n int) []*sip.Request {
	t.Helper()
	got := f.waitFor(m, n, 3*time.Second)
	if len(got) != n {
		t.Fatalf("far end saw %d %s, want %d", len(got), m, n)
	}
	return got
}

func headerValue(m interface{ GetHeaders(string) []sip.Header }, name string) string {
	if hs := m.GetHeaders(name); len(hs) > 0 {
		return hs[0].Value()
	}
	return ""
}

// A reliable 183 with SDP and Require: 100rel is relayed with Require and
// RSeq intact and its SDP rebuilt; the PRACK reaches the far end with RAck,
// RSeq-derived and CSeq values untouched; its 200 comes back; early media
// is latched before any 2xx; a retransmitted 183 and a retransmitted PRACK
// add no state.
func TestReliable183PrackRelayed(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	phoneRTP := listenRTP(t, freePort(t))
	fsRTP := listenRTP(t, h.fs.rtpPort)

	const tag = "uas-tag-1"
	release := make(chan struct{})
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		prov := reliableProvisional(h.fs, req, 183, tag, 7)
		_ = tx.Respond(prov.Clone())
		_ = tx.Respond(prov.Clone()) // a retransmission of the same reliable 183
		select {
		case <-release:
		case <-time.After(8 * time.Second):
		}
		_ = tx.Respond(finalAnswer(h.fs, req, tag))
		return true
	})

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(portOf(phoneRTP.LocalAddr().String())))
	invite.AppendHeader(sip.NewHeader("Supported", "100rel"))
	call := phoneUAC(t, h, phone, invite)

	var first *sip.Response
	for first == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 183 {
			first = r
		}
	}
	if got := headerTokens(first, "Require"); !got["100REL"] {
		t.Errorf("183 lost Require: 100rel: %v", first.GetHeaders("Require"))
	}
	if got := headerValue(first, "RSeq"); got != "7" {
		t.Errorf("183 RSeq = %q, want 7", got)
	}
	ans, err := parseLabSDP(first.Body())
	if err != nil {
		t.Fatalf("183 SDP: %v", err)
	}
	if ans.Audio.Port == h.fs.rtpPort {
		t.Error("the 183 carried the switch's own media port")
	}
	ups := waitReceived(t, h.fs, sip.INVITE, 1)
	if got := headerTokens(ups[0], "Supported"); !got["100REL"] {
		t.Errorf("INVITE toward the switch lost Supported: 100rel: %v", ups[0].GetHeaders("Supported"))
	}
	upOffer, err := parseLabSDP(ups[0].Body())
	if err != nil {
		t.Fatal(err)
	}

	// The retransmitted 183 carries the same body: no re-negotiation.
	select {
	case again := <-call.resp:
		if again.StatusCode == 183 && string(again.Body()) != string(first.Body()) {
			t.Errorf("retransmitted 183 changed the SDP:\n%s\n---\n%s", first.Body(), again.Body())
		}
	case <-time.After(500 * time.Millisecond):
	}

	prack := prackFor(invite, first, invite.CSeq().SeqNo+1, "127.0.0.1", 0)
	dup := prack.Clone()
	prack.SetTransport("UDP")
	prack.SetDestination(h.publicUDP)
	res := phone.do(t, prack, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("PRACK: got %d, want 200", res.StatusCode)
	}
	pr := waitReceived(t, h.fs, sip.PRACK, 1)[0]
	if got := headerValue(pr, "RAck"); got != "7 1 INVITE" {
		t.Errorf("RAck = %q, want \"7 1 INVITE\"", got)
	}
	if c := pr.CSeq(); c.SeqNo != 2 || c.MethodName != sip.PRACK {
		t.Errorf("PRACK CSeq = %v, want 2 PRACK", c)
	}
	if tag2, _ := pr.To().Params.Get("tag"); tag2 != tag {
		t.Errorf("PRACK To tag = %q, want %q", tag2, tag)
	}
	if len(pr.Body()) != 0 {
		t.Errorf("PRACK grew a body: %q", pr.Body())
	}
	if pr.Recipient.Port != portOf(h.fs.addr) || pr.Recipient.User != "gw" {
		t.Errorf("PRACK Request-URI = %s, want the far end's Contact", pr.Recipient.String())
	}
	if vias := pr.GetHeaders("Via"); len(vias) < 2 {
		t.Errorf("PRACK carries %d Vias, want the proxy's on top of the phone's", len(vias))
	}

	// A retransmission of the PRACK (same branch) is absorbed.
	dup.SetTransport("UDP")
	dup.SetDestination(h.publicUDP)
	if err := phone.cli.WriteRequest(dup, noBuild); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(h.fs.received(sip.PRACK)); n != 1 {
		t.Errorf("far end saw %d PRACKs after a retransmission, want 1", n)
	}

	// Early media is latched before the 2xx exists.
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ans.Audio.Port}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: upOffer.Audio.Port}
	if !relayReaches(t, phoneRTP, sbcPublic, fsRTP, rtpPacket(0, 100, 160)) {
		t.Error("early media phone -> switch never arrived")
	}
	if !relayReaches(t, fsRTP, sbcPrivate, phoneRTP, rtpPacket(0, 200, 160)) {
		t.Error("early media switch -> phone never arrived")
	}
	d, ok := h.srv.dialogs.early(invite.CallID().Value(), fsip.FromTag(invite))
	if !ok {
		t.Fatal("the early dialog is gone before the 2xx")
	}
	d.tab.mu.Lock()
	forks := len(d.forks)
	d.tab.mu.Unlock()
	if forks != 1 {
		t.Errorf("early dialog holds %d forks, want 1", forks)
	}

	close(release)
	var final *sip.Response
	for final == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 200 {
			final = r
		}
	}
	if string(final.Body()) != string(first.Body()) {
		t.Errorf("the 200 restated a different SDP than the reliable 183:\n%s\n---\n%s", first.Body(), final.Body())
	}
	sendAck(t, phone, invite, final, h.publicUDP)
	waitReceived(t, h.fs, sip.ACK, 1)
	if r := phone.do(t, buildBye(phone, invite, final), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// UPDATE without SDP (a session-timer refresh) is forwarded and answered in
// both directions, first inside the early dialog and again once confirmed,
// and moves no media.
func TestUpdateWithoutSDPBothDirections(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	phoneRTP := listenRTP(t, freePort(t))

	const tag = "uas-tag-2"
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
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(portOf(phoneRTP.LocalAddr().String())))
	call := phoneUAC(t, h, phone, invite)
	var ring *sip.Response
	for ring == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 180 {
			ring = r
		}
	}
	up := waitReceived(t, h.fs, sip.INVITE, 1)[0]

	refresh := func(stage string, dlgRes *sip.Response, cseq uint32, wantFS int) {
		t.Helper()
		// Phone -> switch.
		req := uacRequest(sip.UPDATE, invite, dlgRes, cseq, "127.0.0.1", 0)
		req.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		req.AppendHeader(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
		req.AppendHeader(sip.NewHeader("Supported", "timer"))
		if res := phone.do(t, req, h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("%s: UPDATE from the phone: got %d, want 200", stage, res.StatusCode)
		}
		ups := waitReceived(t, h.fs, sip.UPDATE, wantFS)
		u := ups[len(ups)-1]
		if len(u.Body()) != 0 || headerValue(u, "Session-Expires") != "1800;refresher=uac" {
			t.Errorf("%s: forwarded UPDATE = %q, Session-Expires %q", stage, u.Body(), headerValue(u, "Session-Expires"))
		}
		if c := u.CSeq(); c.SeqNo != cseq {
			t.Errorf("%s: UPDATE CSeq = %d, want %d", stage, c.SeqNo, cseq)
		}
		// Switch -> phone, as the UAS of the call.
		if res := h.fs.inDialog(t, sip.UPDATE, up, tag); res.StatusCode != 200 {
			t.Fatalf("%s: UPDATE from the switch: got %d, want 200", stage, res.StatusCode)
		}
		deadline := time.Now().Add(3 * time.Second)
		seen := false
		for time.Now().Before(deadline) && !seen {
			select {
			case r := <-phone.inbound:
				seen = r.Method == sip.UPDATE
			case <-time.After(50 * time.Millisecond):
			}
		}
		if !seen {
			t.Errorf("%s: the phone never saw the switch's UPDATE", stage)
		}
	}
	refresh("early", ring, invite.CSeq().SeqNo+1, 1)

	close(release)
	var final *sip.Response
	for final == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 200 {
			final = r
		}
	}
	sendAck(t, phone, invite, final, h.publicUDP)
	waitReceived(t, h.fs, sip.ACK, 1)
	refresh("confirmed", final, invite.CSeq().SeqNo+2, 2)

	if r := phone.do(t, buildBye(phone, invite, final), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// A PRACK that carries SDP is not handled yet: it is never forwarded (its
// body would cross the anchor) and is answered 488, leaving the dialog
// alone. Without a matching dialog PRACK and UPDATE are 481.
func TestSDPBearingPrackRefused(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	phoneRTP := listenRTP(t, freePort(t))

	const tag = "uas-tag-3"
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
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(portOf(phoneRTP.LocalAddr().String())))
	call := phoneUAC(t, h, phone, invite)
	var prov *sip.Response
	for prov == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 183 {
			prov = r
		}
	}

	withBody := func(req *sip.Request) *sip.Request {
		req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		req.SetBody([]byte(phoneOfferSDP(40000)))
		return req
	}
	check := func(stage string, dlg *sip.Response) {
		t.Helper()
		pr := withBody(prackFor(invite, dlg, invite.CSeq().SeqNo+1, "127.0.0.1", 0))
		if res := phone.do(t, pr, h.publicUDP); res.StatusCode != 488 {
			t.Errorf("%s: PRACK with SDP: got %d, want 488", stage, res.StatusCode)
		}
	}
	check("early", prov)

	// No dialog: a PRACK or UPDATE that names no tags the proxy holds.
	stray := uacRequest(sip.UPDATE, invite, prov, 9, "127.0.0.1", 0)
	stray.RemoveHeader("Call-ID")
	strayID := sip.CallIDHeader("no-such-call")
	stray.AppendHeader(&strayID)
	if res := phone.do(t, stray, h.publicUDP); res.StatusCode != 481 {
		t.Errorf("UPDATE outside any dialog: got %d, want 481", res.StatusCode)
	}

	close(release)
	var final *sip.Response
	for final == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 200 {
			final = r
		}
	}
	sendAck(t, phone, invite, final, h.publicUDP)
	check("confirmed", final)
	if n := len(h.fs.received(sip.PRACK)) + len(h.fs.received(sip.UPDATE)); n != 0 {
		t.Errorf("%d SDP-bearing PRACK or dialog-less UPDATE reached the switch", n)
	}
	if r := phone.do(t, buildBye(phone, invite, final), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// On a carrier leg a reliable 183, its PRACK and its 200, and UPDATE in
// both directions are all hidden like every other message: nothing of the
// switch or the private socket reaches the carrier, and the switch gets
// its own Vias back.
func TestOutboundPrackAndUpdateHidden(t *testing.T) {
	o := startOutboundRig(t)
	const tag = "carrier-tag"
	release := make(chan struct{})
	o.carrier.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		prov := reliableProvisional(o.carrier, req, 183, tag, 11)
		_ = tx.Respond(prov.Clone())
		_ = tx.Respond(prov.Clone())
		select {
		case <-release:
		case <-time.After(8 * time.Second):
		}
		_ = tx.Respond(finalAnswer(o.carrier, req, tag))
		return true
	})
	swRTP := listenRTP(t, o.fs.rtpPort)
	carRTP := listenRTP(t, o.carrier.rtpPort)

	req := o.fs.callRequest(o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort),
		sip.NewHeader("Supported", "100rel"))
	call := startUAC(t, o.fs.cli, req)
	var prov *sip.Response
	for prov == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 183 {
			prov = r
		}
	}
	if got := headerValue(prov, "RSeq"); got != "11" || !headerTokens(prov, "Require")["100REL"] {
		t.Errorf("183 at the switch: RSeq %q, Require %v", got, prov.GetHeaders("Require"))
	}
	if vias := prov.GetHeaders("Via"); len(vias) != 1 || prov.Via().Port != portOf(o.fs.addr) {
		t.Errorf("183 Vias = %v, want exactly the switch's own", vias)
	}
	inv := waitReceived(t, o.carrier, sip.INVITE, 1)[0]
	assertHidden(t, o, "INVITE", inv, true)
	provAnswer, err := parseLabSDP(prov.Body())
	if err != nil {
		t.Fatal(err)
	}
	carOffer, err := parseLabSDP(inv.Body())
	if err != nil {
		t.Fatal(err)
	}

	prack := prackFor(req, prov, 2, hostOf(o.fs.addr), portOf(o.fs.addr))
	prack.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: hostOf(o.fs.addr), Port: portOf(o.fs.addr)}})
	pres := switchSend(t, o.fs, prack, prov)
	if pres.StatusCode != 200 {
		t.Fatalf("PRACK: got %d, want 200", pres.StatusCode)
	}
	if vias := pres.GetHeaders("Via"); len(vias) != 1 || pres.Via().Port != portOf(o.fs.addr) {
		t.Errorf("PRACK 200 Vias = %v, want exactly the switch's own", vias)
	}
	cp := waitReceived(t, o.carrier, sip.PRACK, 1)[0]
	assertHidden(t, o, "PRACK", cp, false)
	if got := headerValue(cp, "RAck"); got != "11 1 INVITE" {
		t.Errorf("RAck = %q, want \"11 1 INVITE\"", got)
	}

	// Early media both ways.
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: provAnswer.Audio.Port}
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: carOffer.Audio.Port}
	if !relayReaches(t, swRTP, sbcPrivate, carRTP, rtpPacket(0, 100, 160)) {
		t.Error("early media switch -> carrier never arrived")
	}
	if !relayReaches(t, carRTP, sbcPublic, swRTP, rtpPacket(0, 200, 160)) {
		t.Error("early media carrier -> switch never arrived")
	}

	// UPDATE from the switch, still early.
	up := uacRequest(sip.UPDATE, req, prov, 3, hostOf(o.fs.addr), portOf(o.fs.addr))
	up.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: hostOf(o.fs.addr), Port: portOf(o.fs.addr)}})
	if res := switchSend(t, o.fs, up, prov); res.StatusCode != 200 {
		t.Fatalf("UPDATE from the switch: got %d, want 200", res.StatusCode)
	}
	cu := waitReceived(t, o.carrier, sip.UPDATE, 1)[0]
	assertHidden(t, o, "UPDATE", cu, false)

	// UPDATE from the carrier toward the switch, as the carrier's UAS.
	before := len(o.fs.received(sip.UPDATE))
	if res := o.carrier.inDialog(t, sip.UPDATE, inv, tag); res.StatusCode != 200 {
		t.Fatalf("UPDATE from the carrier: got %d, want 200", res.StatusCode)
	}
	if got := o.fs.waitFor(sip.UPDATE, before+1, 3*time.Second); len(got) != before+1 {
		t.Fatalf("the switch saw %d UPDATEs from the carrier", len(got)-before)
	} else if names := carrierHeaders(got[len(got)-1]); len(names) != 1 || names[0] != "alpha" {
		t.Errorf("UPDATE from the carrier is stamped %v, want alpha", names)
	}

	close(release)
	var final *sip.Response
	for final == nil {
		if r := call.next(t, 5*time.Second); r.StatusCode == 200 {
			final = r
		}
	}
	o.fs.sendAckTo2xx(t, final)
	waitReceived(t, o.carrier, sip.ACK, 1)

	// Confirmed dialog: UPDATE from the switch is hidden too.
	up2 := uacRequest(sip.UPDATE, req, final, 4, hostOf(o.fs.addr), portOf(o.fs.addr))
	up2.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: hostOf(o.fs.addr), Port: portOf(o.fs.addr)}})
	if res := switchSend(t, o.fs, up2, final); res.StatusCode != 200 {
		t.Fatalf("confirmed UPDATE from the switch: got %d, want 200", res.StatusCode)
	}
	cu2 := waitReceived(t, o.carrier, sip.UPDATE, 2)[1]
	assertHidden(t, o, "confirmed UPDATE", cu2, false)

	m := o.srv.metrics.Snapshot().CarrierRequests
	if m["alpha/outbound/PRACK"] != 1 || m["alpha/outbound/UPDATE"] != 2 {
		t.Errorf("carrier metrics = %v, want 1 PRACK and 2 UPDATE outbound", m)
	}
	if bye := o.fs.uacBye(t, final); bye.StatusCode != 200 {
		t.Errorf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, o.harness)
}
