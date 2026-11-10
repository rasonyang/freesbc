package edge

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file tests FreeSBC behind a NAT SIP ALG, which on a flow to port 5060
// replaces the host's own public address inside the SIP message with an
// internal address of the NAT (algHost). The fake far ends write that
// rewrite themselves: the loopback harness cannot put an ALG on the path, so
// a peer sends what the ALG would have delivered (algResponse, the rig's
// requestHook).

const algHost = "10.0.0.55"

// algResponse rewrites FreeSBC's own address in a peer's response the way
// the ALG does: the top Via sent-by, the To host and every Record-Route host
// (the marker parameter is left alone, as the ALG leaves parameters), and
// sends it where the request came from, since the Via no longer says.
func algResponse(req *sip.Request, res *sip.Response) {
	if v := res.Via(); v != nil {
		nv := v.Clone()
		nv.Host = algHost
		res.RemoveHeader("Via")
		res.PrependHeader(nv)
	}
	if to := res.To(); to != nil {
		to.Address.Host = algHost
	}
	var rrs []*sip.RecordRouteHeader
	for _, h := range res.GetHeaders("Record-Route") {
		rr := h.(*sip.RecordRouteHeader).Clone()
		rr.Address.Host = algHost
		rrs = append(rrs, rr)
	}
	fsip.RemoveHeaders(res, "Record-Route")
	for _, rr := range rrs {
		res.AppendHeader(rr)
	}
	res.SetDestination(req.Source())
}

// ringAndAnswerALG makes the fake peer answer every INVITE 180 then 200,
// both with the ALG's rewrite, and report the To tag.
func ringAndAnswerALG(f *fakeSwitch, contact sip.Uri) chan string {
	tags := make(chan string, 8)
	f.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		tag := sip.GenerateTagN(12)
		ring := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
		ring.To().Params.Add("tag", tag)
		algResponse(req, ring)
		_ = tx.Respond(ring)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(f.answerSDP(req)))
		res.To().Params.Add("tag", tag)
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: contact})
		algResponse(req, res)
		_ = tx.Respond(res)
		tags <- tag
		return true
	})
	return tags
}

// callCodes is fakeSwitch.call that also reports every provisional status.
func callCodes(t *testing.T, f *fakeSwitch, ruri sip.Uri, dest, body string) (*sip.Response, []int) {
	t.Helper()
	req := f.callRequest(ruri, dest, body)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("fake switch INVITE: %v", err)
	}
	defer tx.Terminate()
	var codes []int
	for {
		select {
		case res, ok := <-tx.Responses():
			if !ok {
				t.Fatal("fake switch INVITE: no final response")
			}
			codes = append(codes, res.StatusCode)
			if res.StatusCode >= 200 {
				return res, codes
			}
		case <-tx.Done():
			t.Fatalf("fake switch INVITE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("fake switch INVITE timed out")
		}
	}
}

func hasCode(codes []int, c int) bool {
	for _, x := range codes {
		if x == c {
			return true
		}
	}
	return false
}

// A carrier behind the ALG answers 180 and 200 with the top Via, the To host
// and its echo of FreeSBC's Record-Route rewritten. The switch still gets
// both with its own Vias and its own To, a route set free of the NAT
// address, the dialog confirms, and the ACK and a later BYE reach the
// carrier without it.
func TestALGOutboundCarrierCall(t *testing.T) {
	o := startOutboundRig(t)
	ringAndAnswerALG(o.carrier, sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(o.carrier.addr)})

	ruri := o.ruri("+442071234567")
	res, codes := callCodes(t, o.fs, ruri, o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 200 || !hasCode(codes, 180) {
		t.Fatalf("switch saw %v, want 180 then 200", codes)
	}
	if vias := res.GetHeaders("Via"); len(vias) != 1 || res.Via().Port != portOf(o.fs.addr) || res.Via().Host == algHost {
		t.Errorf("response Vias = %v, want exactly the switch's own", vias)
	}
	if to := res.To().Address; to.Host != ruri.Host || to.Port != ruri.Port {
		t.Errorf("response To = %s, want the switch's own %s", to.String(), ruri.String())
	}
	if strings.Contains(res.String(), algHost) {
		t.Errorf("the NAT address reached the switch:\n%s", res.String())
	}
	rrs := res.GetHeaders("Record-Route")
	if len(rrs) != 2 {
		t.Fatalf("response Record-Routes = %d, want public and private", len(rrs))
	}
	pub := rrs[0].(*sip.RecordRouteHeader).Address
	if pub.Host != "127.0.0.1" || pub.Port != o.publicPort() || !hasRecordRouteMarker(pub) {
		t.Errorf("public Record-Route = %s, want FreeSBC's advertised entry, restored and marked", pub.String())
	}

	o.fs.sendAckTo2xx(t, res)
	acks := o.carrier.waitFor(sip.ACK, 1, 3*time.Second)
	if len(acks) != 1 {
		t.Fatalf("carrier saw %d ACKs, want 1", len(acks))
	}
	assertHidden(t, o, "ACK", acks[0], false)

	invs := o.carrier.received(sip.INVITE)
	if len(invs) != 1 {
		t.Fatalf("carrier saw %d INVITEs", len(invs))
	}
	if _, ok := waitForDialogOK(o.harness, invs[0].CallID().Value()); !ok {
		t.Fatal("dialog never confirmed")
	}
	// The BYE's route set was learned from the restored list: it names no
	// NAT address, and the carrier gets exactly what it always did.
	if bye := o.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Fatalf("BYE from the switch: %d", bye.StatusCode)
	}
	byes := o.carrier.waitFor(sip.BYE, 1, 3*time.Second)
	if len(byes) != 1 {
		t.Fatalf("carrier saw %d BYEs, want 1", len(byes))
	}
	assertHidden(t, o, "BYE", byes[0], false)
	if strings.Contains(byes[0].String(), algHost) {
		t.Errorf("the NAT address reached the carrier:\n%s", byes[0].String())
	}
	waitForRelease(t, o.harness)
}

func waitForDialogOK(h *harness, callID string) (*dialog, bool) {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if d, ok := h.srv.dialogs.confirmed(callID); ok {
			return d, true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil, false
}

// In-dialog requests from a carrier behind the ALG, whose Request-URI or top
// Route names the NAT address, are matched by Call-ID and tags and reach the
// switch at its stored contact with no Route naming the NAT; the 200 goes
// back to the carrier.
func TestALGInDialogFromCarrier(t *testing.T) {
	cases := []struct {
		name string
		hook func(o *outboundRig) func(*sip.Request)
	}{
		{"request-uri", func(o *outboundRig) func(*sip.Request) {
			return func(req *sip.Request) {
				req.Recipient = sip.Uri{User: "x", Host: algHost, Port: o.publicPort()}
				fsip.RemoveHeaders(req, "Route")
			}
		}},
		{"route", func(o *outboundRig) func(*sip.Request) {
			return func(req *sip.Request) {
				var rts []*sip.RouteHeader
				for _, h := range req.GetHeaders("Route") {
					r := *h.(*sip.RouteHeader)
					r.Address = *r.Address.Clone()
					r.Address.Host = algHost
					rts = append(rts, &r)
				}
				fsip.RemoveHeaders(req, "Route")
				for _, r := range rts {
					req.AppendHeader(r)
				}
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := startOutboundRig(t)
			tags := answerWithTag(o.carrier)
			res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
			if res.StatusCode != 200 {
				t.Fatalf("INVITE: %d", res.StatusCode)
			}
			o.fs.sendAckTo2xx(t, res)
			tag := <-tags
			invs := o.carrier.waitFor(sip.INVITE, 1, 3*time.Second)
			if len(invs) != 1 {
				t.Fatalf("carrier saw %d INVITEs", len(invs))
			}
			waitForDialog(t, o.harness, invs[0].CallID().Value())

			o.carrier.routeDest = o.publicUDP
			o.carrier.requestHook = c.hook(o)
			bye := o.carrier.inDialog(t, sip.BYE, invs[0], tag)
			if bye.StatusCode != 200 {
				t.Fatalf("BYE from the carrier: got %d, want 200", bye.StatusCode)
			}
			got := o.fs.waitFor(sip.BYE, 1, 3*time.Second)
			if len(got) != 1 {
				t.Fatalf("the switch saw %d BYEs, want 1", len(got))
			}
			if got[0].Recipient.Port != portOf(o.fs.addr) || got[0].Recipient.User != "3003" {
				t.Errorf("BYE Request-URI = %s, want the switch's stored contact", got[0].Recipient.String())
			}
			if strings.Contains(got[0].String(), algHost) {
				t.Errorf("the NAT address reached the switch:\n%s", got[0].String())
			}
			waitForRelease(t, o.harness)
		})
	}
}

// OPTIONS and INVITE from a carrier source whose Request-URI host the ALG
// replaced with the NAT address are admitted and routed as before.
func TestALGCarrierRequestURIHost(t *testing.T) {
	phone := newUDPClient(t) // stands in for the carrier's gateway
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(phone.local)), "", nil)
	answerWithEcho(rig.cs)
	natURI := func(user string) sip.Uri {
		return sip.Uri{User: user, Host: algHost, Port: portOf(rig.publicUDP)}
	}

	opt := phone.buildInvite("x", "y", "example.com", "")
	opt.Method = sip.OPTIONS
	opt.Recipient = natURI("")
	fsip.RemoveHeaders(opt, "Content-Type")
	opt.CSeq().MethodName = sip.OPTIONS
	if res := phone.do(t, opt, rig.publicUDP); res.StatusCode != 200 {
		t.Errorf("OPTIONS with the NAT host: got %d, want 200", res.StatusCode)
	}

	rtp := listenRTP(t, freePort(t))
	phonePort := portOf(rtp.LocalAddr().String())
	inv := phone.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(phonePort))
	inv.Recipient = natURI("+15551230000")
	res := phone.do(t, inv, rig.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE with the NAT host: got %d, want 200", res.StatusCode)
	}
	got := rig.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("the switch's carrier port saw %d INVITEs, want 1", len(got))
	}
	if hs := carrierHeaders(got[0]); len(hs) != 1 || hs[0] != "alpha" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [alpha]", hs)
	}
}

// The client leg takes the same ALG: the registered phone's responses to a
// switch-originated call come back with the Via, To and Record-Route rewritten, in
// both address layouts (the single-IP one skips without the 127.0.0.2 alias).
func TestALGClientLegResponses(t *testing.T) {
	layouts := []struct {
		name  string
		start func(t *testing.T) *harness
	}{
		{"two-address", func(t *testing.T) *harness { return startHarness(t, false) }},
		{"single-ip", func(t *testing.T) *harness { return startHarnessShared(t, harnessCarrierSources) }},
	}
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			h := l.start(t)
			phone := newUDPClient(t)
			ruri := auditRegisterPhone(t, h, phone, "1001")
			phoneRTP := listenRTPOn(t, "127.0.0.1", 0)
			phonePort := phoneRTP.LocalAddr().(*net.UDPAddr).Port
			phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
				if req.Method != sip.INVITE {
					res := sip.NewResponseFromRequest(req, 200, "OK", nil)
					algResponse(req, res)
					_ = tx.Respond(res)
					return
				}
				tag := sip.GenerateTagN(12)
				ring := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
				ring.To().Params.Add("tag", tag)
				algResponse(req, ring)
				_ = tx.Respond(ring)
				res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(phonePort)))
				res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
				res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
				res.To().Params.Add("tag", tag)
				algResponse(req, res)
				_ = tx.Respond(res)
			})

			res, codes := callCodes(t, h.fs, ruri, h.privateSIP, h.fs.answerSDP(&sip.Request{}))
			if res.StatusCode != 200 || !hasCode(codes, 180) {
				t.Fatalf("switch saw %v, want 180 then 200", codes)
			}
			if strings.Contains(res.String(), algHost) {
				t.Errorf("the NAT address reached the switch:\n%s", res.String())
			}
			if vias := res.GetHeaders("Via"); len(vias) != 1 || res.Via().Port != portOf(h.fs.addr) {
				t.Errorf("response Vias = %v, want exactly the switch's own", vias)
			}
			select {
			case <-phone.inbound:
			case <-time.After(5 * time.Second):
				t.Fatal("the phone never received the INVITE")
			}
			drain(phone.inbound)
			h.fs.sendAckTo2xx(t, res)
			if r := h.fs.uacBye(t, res); r.StatusCode != 200 {
				t.Fatalf("switch BYE: %d (the phone's rewritten 200 must still be relayed)", r.StatusCode)
			}
			waitForRelease(t, h)
		})
	}
}

func TestPopOwnViaByBranch(t *testing.T) {
	s := &Server{topo: testTopology(t)}
	mk := func(branch string, below ...*sip.ViaHeader) *sip.Response {
		res := sip.NewResponse(200, "OK")
		top := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
			Host: algHost, Port: 16060, Params: sip.NewParams()}
		top.Params.Add("branch", branch)
		res.AppendHeader(top)
		for _, v := range below {
			res.AppendHeader(v)
		}
		return res
	}
	below := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "10.77.0.10", Port: 5060, Params: sip.NewParams()}
	below.Params.Add("branch", "z9hG4bKswitch")

	// The branch we sent: accepted whatever the sent-by.
	res := mk("z9hG4bKours", below)
	if !s.popOwnVia(res, false, "z9hG4bKours") || len(res.GetHeaders("Via")) != 1 || res.Via().Host != "10.77.0.10" {
		t.Error("a top Via with our branch was not popped")
	}
	// Alone: popped only when the caller allows an empty stack.
	if !s.popOwnVia(mk("z9hG4bKours"), true, "z9hG4bKours") {
		t.Error("a lone Via with our branch was refused with allowEmpty")
	}
	if s.popOwnVia(mk("z9hG4bKours"), false, "z9hG4bKours") {
		t.Error("a lone Via was accepted without allowEmpty")
	}
	// Another branch, with and without Vias below it, or no branch known:
	// refused, and the exact sent-by check still applies.
	for _, branch := range []string{"z9hG4bKother", ""} {
		for _, bl := range [][]*sip.ViaHeader{nil, {below}} {
			if s.popOwnVia(mk(branch, bl...), true, "z9hG4bKours") {
				t.Errorf("a top Via with branch %q was accepted", branch)
			}
		}
	}
	if s.popOwnVia(mk("z9hG4bKours", below), true, "") {
		t.Error("an unknown branch accepted a foreign sent-by")
	}
	res = mk("z9hG4bKours", below)
	res.Via().Host, res.Via().Port = "203.0.113.7", 16060
	if !s.popOwnVia(res, false, "") {
		t.Error("the exact sent-by check no longer accepts our advertised address")
	}
}

func TestRecordRouteMarker(t *testing.T) {
	s := &Server{topo: testTopology(t)}
	udp, _ := s.topo.publicSide("udp")
	rr := udp.recordRoute().Address
	if !hasRecordRouteMarker(rr) || !strings.Contains(rr.String(), ";"+recordRouteMarker) {
		t.Errorf("public Record-Route %s carries no marker", rr.String())
	}
	if hasRecordRouteMarker(s.topo.private.recordRoute().Address) {
		t.Error("the private Record-Route is marked")
	}
	if _, ok := tokenOf(rr); ok {
		t.Error("the marker is read as a routing token")
	}
	tok := sip.Uri{Host: "203.0.113.7", Port: 16060}
	tok.UriParams = sip.NewParams()
	tok.UriParams.Add(contactTokenParam, "abc")
	if hasRecordRouteMarker(tok) {
		t.Error("a routing token is read as the marker")
	}
	nat := rr
	nat.Host = algHost
	if s.topo.isSelf(nat) || !s.topo.isSelfRoute(nat) || !s.isPublicURI(nat) {
		t.Error("a marked entry with the NAT host must be own as a route only")
	}
	plain := sip.Uri{Host: algHost, Port: 16060}
	if s.topo.isSelfRoute(plain) {
		t.Error("an unmarked foreign Route is claimed as our own")
	}

	// restoreOwnRecordRoutes: marked entries get the advertised address
	// back, foreign entries are untouched, and a transport with no side
	// loses its entry.
	res := sip.NewResponse(200, "OK")
	res.AppendHeader(&sip.RecordRouteHeader{Address: nat})
	foreign := sip.Uri{Host: "198.51.100.9", Port: 5060, UriParams: sip.NewParams()}
	foreign.UriParams.Add("lr", "")
	res.AppendHeader(&sip.RecordRouteHeader{Address: foreign})
	wss := nat
	wss.UriParams = sip.NewParams()
	wss.UriParams.Add("transport", "wss")
	wss.UriParams.Add(recordRouteMarker, "")
	res.AppendHeader(&sip.RecordRouteHeader{Address: wss})
	s.restoreOwnRecordRoutes(res)
	got := res.GetHeaders("Record-Route")
	if len(got) != 2 {
		t.Fatalf("%d Record-Routes left, want 2", len(got))
	}
	if a := got[0].(*sip.RecordRouteHeader).Address; a.Host != "203.0.113.7" || a.Port != 16060 {
		t.Errorf("restored entry = %s", a.String())
	}
	if a := got[1].(*sip.RecordRouteHeader).Address; a.Host != "198.51.100.9" {
		t.Errorf("foreign entry = %s", a.String())
	}
}

func TestUnroutableWarnRateLimited(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{topo: testTopology(t), log: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))}
	mk := func(host string, port int, branch string) *sip.Response {
		res := sip.NewResponse(200, "OK")
		v := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
			Host: host, Port: port, Params: sip.NewParams()}
		v.Params.Add("branch", branch)
		res.AppendHeader(v)
		return res
	}
	// A lone Via with our branch at a rewritten sent-by: popping would leave
	// none. The WARN names that Via, not the (absent) one below.
	s.logUnroutable(mk(algHost, 5060, "z9hG4bKx"), "z9hG4bKx")
	// Inside the minute: counted, not logged.
	s.logUnroutable(mk("198.51.100.9", 5060, "z9hG4bKy"), "z9hG4bKx")
	out := buf.String()
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Fatalf("%d WARN lines, want 1:\n%s", n, out)
	}
	for _, want := range []string{"via_sent_by=10.0.0.55:5060", "via_branch=z9hG4bKx", "branch_matches=true", "reason=no_via_below"} {
		if !strings.Contains(out, want) {
			t.Errorf("WARN lacks %q:\n%s", want, out)
		}
	}
	// A foreign Via with another branch, reported once the window is over.
	buf.Reset()
	s.unroutable.last = time.Now().Add(-2 * unroutableWarnEvery)
	s.logUnroutable(mk("198.51.100.9", 5060, "z9hG4bKy"), "z9hG4bKx")
	out = buf.String()
	for _, want := range []string{"reason=not_ours", "branch_matches=false", "via_sent_by=198.51.100.9:5060", "suppressed_since_last=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("WARN lacks %q:\n%s", want, out)
		}
	}
	if n, ok := (&unroutableLog{}).take(time.Now()); !ok || n != 0 {
		t.Error("the first drop must log at once")
	}
	var u unroutableLog
	now := time.Now()
	u.take(now)
	u.take(now.Add(time.Second))
	if n, ok := u.take(now.Add(2 * unroutableWarnEvery)); !ok || n != 1 {
		t.Errorf("take after the window = %d, %v; want 1 suppressed, logged", n, ok)
	}
}
