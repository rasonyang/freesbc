package edge

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file tests topology hiding on client legs (issue #167): nothing the
// switch puts on the wire may reach a registered client, and the switch
// still sees its own Via, From and To.
//
// The harness runs everything on 127.0.0.1, so a switch address cannot be
// told from the public one by IP. The tests tell them apart by what only the
// switch has: its SIP port (the fake switch's, and the private socket's) and
// strings the fake switch plants (a Server/User-Agent product, X-* and P-*
// headers, a Warning, Path and so on).

const (
	hideSwitchUA     = "FreeSWITCH-mod_sofia/1.10.99-secret-build"
	hideSwitchSecret = "s3cret-account-42"
)

type hideRig struct {
	t        *testing.T
	h        *harness
	phone    *client
	ruri     sip.Uri // the contact the switch stored for the phone
	swPort   int     // the fake switch's SIP port
	privPort int     // the private socket's port
	pubPort  int     // FreeSBC's public UDP port
	phoneTag chan string

	origFrom, origTo sip.Uri // what the switch calls itself and the phone in its own INVITE
	forbidden        *regexp.Regexp
}

// startHideRig registers a phone through the strict harness (the phone is a
// client, not a carrier source) and makes it answer INVITEs with a
// User-Agent of its own.
func startHideRig(t *testing.T) *hideRig {
	t.Helper()
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	r := &hideRig{t: t, h: h, phone: phone,
		swPort: portOf(h.fs.addr), privPort: portOf(h.privateSIP), pubPort: portOf(h.publicUDP),
		phoneTag: make(chan string, 4)}
	r.ruri = auditRegisterPhone(t, h, phone, "1001")
	r.origFrom = sip.Uri{User: "3003", Host: "127.0.0.1", Port: r.swPort}
	r.origTo = sip.Uri{User: "1001", Host: "127.0.0.1", Port: r.swPort}
	r.forbidden = regexp.MustCompile(fmt.Sprintf(`:(%d|%d)\b|%s|FreeSWITCH|%s`,
		r.swPort, r.privPort, regexp.QuoteMeta(harnessPrivatePlaceholder), hideSwitchSecret))
	phoneRTP := listenRTP(t, freePort(t))
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			res := sip.NewResponseFromRequest(req, 200, "OK", nil)
			res.AppendHeader(sip.NewHeader("User-Agent", "PhoneUA/1.0"))
			_ = tx.Respond(res)
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(udpPort(phoneRTP))))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(sip.NewHeader("User-Agent", "PhoneUA/1.0"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		tag := sip.GenerateTagN(12)
		res.To().Params.Add("tag", tag)
		r.phoneTag <- tag
		_ = tx.Respond(res)
	})
	return r
}

// switchHeaders are the headers a real switch adds that a client must never
// see, plus identity headers whose hosts must be masked.
func (r *hideRig) switchHeaders() []sip.Header {
	return []sip.Header{
		sip.NewHeader("User-Agent", hideSwitchUA),
		sip.NewHeader("Server", hideSwitchUA),
		sip.NewHeader("X-Switch-Account", hideSwitchSecret),
		sip.NewHeader("P-Switch-Hint", "internal"),
		sip.NewHeader("Warning", fmt.Sprintf(`399 127.0.0.1:%d "sofia"`, r.swPort)),
		sip.NewHeader("P-Asserted-Identity", fmt.Sprintf("<sip:1000@127.0.0.1:%d>", r.swPort)),
		sip.NewHeader("Diversion", fmt.Sprintf("<sip:1000@127.0.0.1:%d>;reason=unconditional", r.swPort)),
	}
}

// assertClean fails when a message a client receives carries a header the
// allowlist forbids or any value naming the switch.
func (r *hideRig) assertClean(what string, hdrs []sip.Header, recipient string) {
	t := r.t
	t.Helper()
	for _, h := range hdrs {
		name := strings.ToLower(h.Name())
		switch {
		case name == "user-agent", name == "server", name == "warning", name == "path",
			name == "service-route", name == "p-associated-uri", strings.HasPrefix(name, "x-"),
			strings.HasPrefix(name, "p-") && name != "p-asserted-identity" && name != "p-preferred-identity":
			t.Errorf("%s: header %s reached the client", what, h.Name())
		}
		if m := r.forbidden.FindString(h.Value()); m != "" {
			t.Errorf("%s: header %s: %s leaks %q", what, h.Name(), h.Value(), m)
		}
	}
	if m := r.forbidden.FindString(recipient); m != "" {
		t.Errorf("%s: Request-URI %s leaks %q", what, recipient, m)
	}
}

// assertClientRequest checks a request the phone received.
func (r *hideRig) assertClientRequest(what string, req *sip.Request) {
	r.t.Helper()
	if req == nil {
		r.t.Fatalf("%s: the phone never received it", what)
	}
	r.assertClean(what, req.Headers(), req.Recipient.String())
	if vias := req.GetHeaders("Via"); len(vias) != 1 {
		r.t.Errorf("%s: %d Vias reached the phone, want only FreeSBC's", what, len(vias))
	} else if v := req.Via(); v.Port != r.pubPort {
		r.t.Errorf("%s: Via %s:%d is not FreeSBC's public port %d", what, v.Host, v.Port, r.pubPort)
	}
	if f := req.From(); f != nil && (f.Address.Host != "127.0.0.1" || f.Address.Port != 0) {
		r.t.Errorf("%s: From %s, want the switch masked to the public host", what, f.Address.String())
	}
	if t := req.To(); t != nil && t.Address.Port == r.swPort {
		r.t.Errorf("%s: To %s names the switch", what, t.Address.String())
	}
}

// assertSwitchView checks a response the switch received to a request it
// sent: its own Via (branch included), From and To.
func (r *hideRig) assertSwitchView(what string, req *sip.Request, res *sip.Response) {
	t := r.t
	t.Helper()
	if vias := res.GetHeaders("Via"); len(vias) != 1 {
		t.Errorf("%s: %d Vias in the response, want the switch's own", what, len(vias))
	}
	want, _ := req.Via().Params.Get("branch")
	got, _ := res.Via().Params.Get("branch")
	if v := res.Via(); v.Port != r.swPort || got != want {
		t.Errorf("%s: response Via %s:%d branch %q, want the switch's %d branch %q", what, v.Host, v.Port, got, r.swPort, want)
	}
	if res.From().Address.String() != req.From().Address.String() {
		t.Errorf("%s: response From %s, want %s", what, res.From().Address.String(), req.From().Address.String())
	}
	if res.To().Address.String() != req.To().Address.String() {
		t.Errorf("%s: response To %s, want %s", what, res.To().Address.String(), req.To().Address.String())
	}
}

// call places the switch's INVITE to the phone, with the switch's own
// identity and headers, and returns the INVITE the switch sent and the 200.
func (r *hideRig) call() (*sip.Request, *sip.Response) {
	t := r.t
	t.Helper()
	req := r.h.fs.callRequest(r.ruri, r.h.privateSIP, phoneOfferSDP(r.h.fs.rtpPort), r.switchHeaders()...)
	req.From().Address = r.origFrom
	req.To().Address = r.origTo
	res := sendFromSwitch(t, r.h.fs, req)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE to the phone: %d", res.StatusCode)
	}
	return req, res
}

// A call the switch places to a client: the INVITE, a NOTIFY and a BYE
// arrive with no switch Via, address, product or header, and the switch gets
// its own Via, From and To back on every response.
func TestClientLegHidesSwitchRequests(t *testing.T) {
	r := startHideRig(t)
	h := r.h
	inv, res := r.call()

	got := waitInbound(r.phone, sip.INVITE, 5*time.Second)
	r.assertClientRequest("INVITE", got)
	r.assertSwitchView("200 to INVITE", inv, res)
	for _, c := range []struct{ name, want string }{
		{"P-Asserted-Identity", "<sip:1000@127.0.0.1>"},
		{"Diversion", "<sip:1000@127.0.0.1>;reason=unconditional"},
	} {
		if hd := got.GetHeader(c.name); hd == nil || hd.Value() != c.want {
			t.Errorf("INVITE %s = %v, want %s", c.name, hd, c.want)
		}
	}
	if got.GetHeader("Content-Type") == nil || len(got.Body()) == 0 {
		t.Error("the phone's INVITE lost its SDP")
	}

	h.fs.sendAckTo2xx(t, res)
	r.assertClientRequest("ACK", waitInbound(r.phone, sip.ACK, 5*time.Second))

	n := fsNotifyInConfirmed(t, h.fs, res, "talk")
	for _, hd := range r.switchHeaders() {
		n.AppendHeader(hd)
	}
	nres := sendFS(t, h.fs, n)
	if nres.StatusCode != 200 {
		t.Fatalf("NOTIFY: %d", nres.StatusCode)
	}
	r.assertClientRequest("NOTIFY", waitInbound(r.phone, sip.NOTIFY, 5*time.Second))
	r.assertSwitchView("200 to NOTIFY", n, nres)

	bye := h.fs.uacBye(t, res, r.switchHeaders()...)
	if bye.StatusCode != 200 {
		t.Fatalf("BYE: %d", bye.StatusCode)
	}
	r.assertClientRequest("BYE", waitInbound(r.phone, sip.BYE, 5*time.Second))
	if v := bye.Via(); v == nil || v.Port != r.swPort {
		t.Errorf("200 to BYE: Via %v, want the switch's own", v)
	}
	if bye.From().Address.String() != r.origFrom.String() || bye.To().Address.String() != r.origTo.String() {
		t.Errorf("200 to BYE: From %s To %s, want the switch's own", bye.From().Address.String(), bye.To().Address.String())
	}
	waitForRelease(t, h)
}

// A BYE FreeSBC sends itself in the middle of a call carries the masked
// identity toward the phone and the real one toward the switch.
func TestClientLegHidesMiddleBye(t *testing.T) {
	r := startHideRig(t)
	h := r.h
	inv, res := r.call()
	h.fs.sendAckTo2xx(t, res)
	waitInbound(r.phone, sip.INVITE, 5*time.Second)

	d := waitForDialog(t, h, fsip.CallID(inv))
	if d.end(endReinviteRefused) {
		h.srv.byeBothEnds(d, endReinviteRefused)
	}

	r.assertClientRequest("middle BYE", waitInbound(r.phone, sip.BYE, 5*time.Second))
	byes := h.fs.waitFor(sip.BYE, 1, 5*time.Second)
	if len(byes) != 1 {
		t.Fatalf("the switch saw %d BYEs, want 1", len(byes))
	}
	if from, to := byes[0].From().Address, byes[0].To().Address; from.String() != r.origTo.String() || to.String() != r.origFrom.String() {
		t.Errorf("middle BYE toward the switch: From %s To %s, want the switch's own %s and %s",
			from.String(), to.String(), r.origTo.String(), r.origFrom.String())
	}
	waitForRelease(t, h)
}

// The phone echoes the masked From and To in its own in-dialog requests; the
// switch gets its real ones, and the phone gets a clean answer.
func TestClientLegRestoresIdentityToSwitch(t *testing.T) {
	r := startHideRig(t)
	h := r.h
	h.fs.setByeHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		for _, hd := range r.switchHeaders() {
			res.AppendHeader(hd)
		}
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: r.swPort}})
		_ = tx.Respond(res)
		return true
	})
	_, res := r.call()
	h.fs.sendAckTo2xx(t, res)
	inv := waitInbound(r.phone, sip.INVITE, 5*time.Second)
	var tag string
	select {
	case tag = <-r.phoneTag:
	case <-time.After(3 * time.Second):
		t.Fatal("the phone never answered")
	}

	bye := sip.NewRequest(sip.BYE, inv.Contact().Address)
	from := &sip.FromHeader{Address: inv.To().Address, Params: sip.NewParams()}
	from.Params.Add("tag", tag)
	bye.AppendHeader(from)
	to := &sip.ToHeader{Address: inv.From().Address, Params: sip.NewParams()}
	callerTag, _ := inv.From().Params.Get("tag")
	to.Params.Add("tag", callerTag)
	bye.AppendHeader(to)
	sip.CopyHeaders("Call-ID", inv, bye)
	bye.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.BYE})
	mf := sip.MaxForwardsHeader(70)
	bye.AppendHeader(&mf)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	via.Params.Add("rport", "")
	bye.PrependHeader(via)
	for _, rr := range inv.GetHeaders("Record-Route") {
		bye.AppendHeader(&sip.RouteHeader{Address: rr.(*sip.RecordRouteHeader).Address})
	}
	// What the phone saw is the masked identity; it echoes exactly that.
	if got := bye.From().Address; got.Host != "127.0.0.1" || got.Port != 0 {
		t.Fatalf("the phone's From %s is not the masked identity", got.String())
	}

	bres := r.phone.do(t, bye, h.publicUDP)
	if bres.StatusCode != 200 {
		t.Fatalf("phone BYE: %d", bres.StatusCode)
	}
	r.assertClean("200 to the phone's BYE", bres.Headers(), "")
	if c := bres.Contact(); c == nil || c.Address.Port != r.pubPort {
		t.Errorf("200 to the phone's BYE: Contact %v, want FreeSBC's public address", c)
	}
	byes := h.fs.waitFor(sip.BYE, 1, 5*time.Second)
	if len(byes) != 1 {
		t.Fatalf("the switch saw %d BYEs, want 1", len(byes))
	}
	if f, to := byes[0].From().Address, byes[0].To().Address; f.String() != r.origTo.String() || to.String() != r.origFrom.String() {
		t.Errorf("BYE at the switch: From %s To %s, want its own %s and %s\n%s", f.String(), to.String(), r.origTo.String(), r.origFrom.String(), byes[0].String())
	}
	waitForRelease(t, h)
}

// A call from a client: the switch's answer, with its product, hosts and
// headers, reaches the phone clean, and so does the answer to the phone's
// in-dialog BYE. The To the switch answered with is echoed back to it.
func TestClientLegHidesSwitchResponses(t *testing.T) {
	r := startHideRig(t)
	h := r.h
	swTo := sip.Uri{User: "2002", Host: "127.0.0.1", Port: r.swPort}
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(h.fs.answerSDP(req)))
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		res.To().Address = swTo
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: r.swPort}})
		for _, hd := range r.switchHeaders() {
			res.AppendHeader(hd)
		}
		_ = tx.Respond(res)
		return true
	})
	h.fs.setByeHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		for _, hd := range r.switchHeaders() {
			res.AppendHeader(hd)
		}
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: r.swPort}})
		_ = tx.Respond(res)
		return true
	})
	phoneRTP := listenRTP(t, freePort(t))
	invite := r.phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(udpPort(phoneRTP)))
	res := r.phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	r.assertClean("200 to INVITE", res.Headers(), "")
	assertClientRecordRoute(t, "200 to INVITE", res.GetHeaders("Record-Route"), r.pubPort)
	if c := res.Contact(); c == nil || c.Address.Port != r.pubPort {
		t.Errorf("200 to INVITE: Contact %v, want FreeSBC's public address", c)
	}
	if to := res.To().Address; to.Host != "127.0.0.1" || to.Port != 0 || to.User != "2002" {
		t.Errorf("200 to INVITE: To %s, want the switch's address masked", to.String())
	}
	sendAck(t, r.phone, invite, res, h.publicUDP)
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("the switch saw %d ACKs", len(acks))
	}

	bres := r.phone.do(t, buildBye(r.phone, invite, res), h.publicUDP)
	if bres.StatusCode != 200 {
		t.Fatalf("BYE: %d", bres.StatusCode)
	}
	r.assertClean("200 to BYE", bres.Headers(), "")
	if c := bres.Contact(); c == nil || c.Address.Port != r.pubPort {
		t.Errorf("200 to BYE: Contact %v, want FreeSBC's public address", c)
	}
	byes := h.fs.waitFor(sip.BYE, 1, 3*time.Second)
	if len(byes) != 1 {
		t.Fatalf("the switch saw %d BYEs", len(byes))
	}
	if to := byes[0].To().Address; to.String() != swTo.String() {
		t.Errorf("BYE at the switch: To %s, want the one it answered with, %s", to.String(), swTo.String())
	}
	waitForRelease(t, h)
}

// A REGISTER answer reaches the phone with the digest challenge intact and
// without the headers that name the switch (Path, Service-Route,
// P-Associated-URI, Server...).
func TestClientLegHidesRegisterResponses(t *testing.T) {
	r := startHideRig(t)
	h := r.h
	h.fs.mu.Lock()
	h.fs.challenge = true
	h.fs.mu.Unlock()
	h.fs.setRegisterExtra(append(r.switchHeaders(),
		sip.NewHeader("Path", fmt.Sprintf("<sip:127.0.0.1:%d;lr>", r.swPort)),
		sip.NewHeader("Service-Route", fmt.Sprintf("<sip:127.0.0.1:%d;lr>", r.swPort)),
		sip.NewHeader("P-Associated-URI", fmt.Sprintf("<sip:1002@127.0.0.1:%d>", r.swPort)))...)

	phone := newUDPClient(t)
	first := phone.do(t, phone.buildRegister("1002", "example.com", 600, ""), h.publicUDP)
	if first.StatusCode != 401 {
		t.Fatalf("first REGISTER: %d, want the challenge", first.StatusCode)
	}
	r.assertClean("401", first.Headers(), "")
	if wa := first.GetHeader("WWW-Authenticate"); wa == nil || wa.Value() != `Digest realm="example.com", nonce="abc123nonce", algorithm=MD5, qop="auth"` {
		t.Errorf("WWW-Authenticate = %v, want the switch's challenge verbatim", wa)
	}

	ok := phone.do(t, phone.buildRegister("1002", "example.com", 600, `Digest username="1002", realm="example.com", nonce="abc123nonce", uri="sip:example.com", response="x"`), h.publicUDP)
	if ok.StatusCode != 200 {
		t.Fatalf("second REGISTER: %d", ok.StatusCode)
	}
	r.assertClean("200 to REGISTER", ok.Headers(), "")
	own := phone.contactURI("1002")
	if c := ok.Contact(); c == nil || c.Address.String() != own.String() {
		t.Errorf("200 to REGISTER: Contact %v, want the phone's own", c)
	}
	if ok.GetHeader("Expires") == nil {
		t.Error("200 to REGISTER lost its Expires")
	}
}

// Hosts in Refer-To, Referred-By and History-Info are masked; the Replaces
// escaped inside a Refer-To URI is left alone.
func TestMaskIdentityTransferHeaders(t *testing.T) {
	h := startHarness(t, false)
	pub := netip.MustParseAddr("203.0.113.9")
	req := sip.NewRequest(sip.REFER, sip.Uri{User: "1", Host: "example.org"})
	req.AppendHeader(sip.NewHeader("Refer-To", "<sip:2000@127.0.0.1:5080?Replaces=abc%40x%3Bto-tag%3D1>"))
	req.AppendHeader(sip.NewHeader("Referred-By", "<sip:3003@127.0.0.1:5080>"))
	req.AppendHeader(sip.NewHeader("History-Info", "<sip:1000@127.0.0.1>;index=1"))
	req.AppendHeader(sip.NewHeader("Referred-By", "<sip:1@example.org>"))
	h.srv.maskIdentity(req, pub)
	for name, want := range map[string]string{
		"Refer-To":     "<sip:2000@203.0.113.9?Replaces=abc%40x%3Bto-tag%3D1>",
		"History-Info": "<sip:1000@203.0.113.9>;index=1",
	} {
		if hd := req.GetHeader(name); hd == nil || hd.Value() != want {
			t.Errorf("%s = %v, want %s", name, hd, want)
		}
	}
	var rb []string
	for _, hd := range req.GetHeaders("Referred-By") {
		rb = append(rb, hd.Value())
	}
	if strings.Join(rb, ",") != "<sip:3003@203.0.113.9>,<sip:1@example.org>" {
		t.Errorf("Referred-By = %v", rb)
	}
}

// A SUBSCRIBE the switch sends to a client is hidden like an INVITE, and the
// client's NOTIFY, which echoes the masked identity, reaches the switch with
// its real From and To.
func TestClientLegHidesSubscription(t *testing.T) {
	r := startHideRig(t)
	h := r.h
	r.phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		if req.Method == sip.SUBSCRIBE {
			res.To().Params.Remove("tag")
			res.To().Params.Add("tag", "phone-tag")
			res.AppendHeader(sip.NewHeader("Expires", "600"))
			res.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
		}
		_ = tx.Respond(res)
	})
	sub := h.fs.callRequest(r.ruri, h.privateSIP, "", r.switchHeaders()...)
	sub.Method = sip.SUBSCRIBE
	sub.CSeq().MethodName = sip.SUBSCRIBE
	sub.RemoveHeader("Content-Type")
	sub.AppendHeader(sip.NewHeader("Event", "presence"))
	sub.AppendHeader(sip.NewHeader("Expires", "600"))
	sub.From().Address = r.origFrom
	sub.To().Address = r.origTo
	res := sendFromSwitch(t, h.fs, sub)
	if res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE from the switch: %d", res.StatusCode)
	}
	got := waitInbound(r.phone, sip.SUBSCRIBE, 3*time.Second)
	r.assertClientRequest("SUBSCRIBE", got)
	r.assertSwitchView("200 to SUBSCRIBE", sub, res)

	notify := sip.NewRequest(sip.NOTIFY, got.Contact().Address)
	from := &sip.FromHeader{Address: got.To().Address, Params: sip.NewParams()}
	from.Params.Add("tag", "phone-tag")
	notify.AppendHeader(from)
	to := &sip.ToHeader{Address: got.From().Address, Params: sip.NewParams()}
	to.Params.Add("tag", fsip.FromTag(got))
	notify.AppendHeader(to)
	cid := sip.CallIDHeader(fsip.CallID(got))
	notify.AppendHeader(&cid)
	notify.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.NOTIFY})
	mf := sip.MaxForwardsHeader(70)
	notify.AppendHeader(&mf)
	notify.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
	notify.AppendHeader(sip.NewHeader("Event", "presence"))
	notify.AppendHeader(sip.NewHeader("Subscription-State", "terminated;reason=timeout"))
	for _, rr := range got.GetHeaders("Record-Route") {
		notify.AppendHeader(&sip.RouteHeader{Address: rr.(*sip.RecordRouteHeader).Address})
	}
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	via.Params.Add("rport", "")
	notify.PrependHeader(via)
	if nres := r.phone.do(t, notify, h.publicUDP); nres.StatusCode != 200 {
		t.Fatalf("phone NOTIFY: %d", nres.StatusCode)
	}
	seen := h.fs.waitFor(sip.NOTIFY, 1, 3*time.Second)
	if len(seen) != 1 {
		t.Fatalf("the switch saw %d NOTIFYs, want 1", len(seen))
	}
	if f, to := seen[0].From().Address, seen[0].To().Address; f.String() != r.origTo.String() || to.String() != r.origFrom.String() {
		t.Errorf("NOTIFY at the switch: From %s To %s, want its own %s and %s", f.String(), to.String(), r.origTo.String(), r.origFrom.String())
	}
}

// maskURI, maskIdentity and restoreURI on a topology whose addresses differ:
// public 203.0.113.7, private 10.77.0.2, switch 10.77.0.10:5060.
func TestMaskAndRestoreDistinctTopology(t *testing.T) {
	s := &Server{topo: testTopology(t)}
	pub := netip.MustParseAddr("203.0.113.7")

	for _, host := range []string{"10.77.0.10", "10.77.0.2"} {
		u := sip.Uri{User: "1000", Host: host, Port: 5060}
		s.maskURI(&u, pub)
		if u.Host != "203.0.113.7" || u.Port != 0 || u.User != "1000" {
			t.Errorf("mask %s = %s", host, u.String())
		}
	}
	other := sip.Uri{User: "1000", Host: "198.51.100.1", Port: 5060}
	s.maskURI(&other, pub)
	if other.Host != "198.51.100.1" || other.Port != 5060 {
		t.Errorf("a foreign host was masked: %s", other.String())
	}

	// restoreURI: only a masked switch address with the same user comes back.
	real := sip.Uri{User: "3003", Host: "10.77.0.10", Port: 5060}
	masked := sip.Uri{User: "3003", Host: "203.0.113.7"}
	s.restoreURI(&masked, real, pub)
	if masked.Host != "10.77.0.10" || masked.Port != 5060 {
		t.Errorf("restore = %s, want the switch's address", masked.String())
	}
	diffUser := sip.Uri{User: "9999", Host: "203.0.113.7"}
	s.restoreURI(&diffUser, real, pub)
	if diffUser.Host != "203.0.113.7" {
		t.Errorf("a client with another user was rewritten: %s", diffUser.String())
	}
	clientReal := sip.Uri{User: "3003", Host: "198.51.100.1"}
	client := sip.Uri{User: "3003", Host: "203.0.113.7"}
	s.restoreURI(&client, clientReal, pub)
	if client.Host != "203.0.113.7" {
		t.Errorf("a record that is not a switch address was applied: %s", client.String())
	}

	// maskIdentity covers headers, including a bracketed IPv6 host.
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "1", Host: "example.org"})
	req.AppendHeader(&sip.FromHeader{Address: sip.Uri{User: "3003", Host: "10.77.0.10", Port: 5060}, Params: sip.NewParams()})
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "1001", Host: "203.0.113.7"}, Params: sip.NewParams()})
	req.AppendHeader(sip.NewHeader("Diversion", "<sip:1000@10.77.0.2:5060>;reason=unconditional"))
	req.AppendHeader(sip.NewHeader("Call-Info", "<sip:10.77.0.10>;answer-after=0"))
	req.AppendHeader(sip.NewHeader("Refer-To", "<sip:2000@10.77.0.10?Replaces=a%40b>"))
	s.maskIdentity(req, pub)
	if f := req.From().Address; f.Host != "203.0.113.7" || f.Port != 0 {
		t.Errorf("From = %s", f.String())
	}
	for name, want := range map[string]string{
		"Diversion": "<sip:1000@203.0.113.7>;reason=unconditional",
		"Call-Info": "<sip:203.0.113.7>;answer-after=0",
		"Refer-To":  "<sip:2000@203.0.113.7?Replaces=a%40b>",
	} {
		if h := req.GetHeader(name); h == nil || h.Value() != want {
			t.Errorf("%s = %v, want %s", name, h, want)
		}
	}

	// A bracketed IPv6 switch or private address is recognised and masked.
	s6 := &Server{topo: buildTestTopology(t, `
public: {ip: 203.0.113.7, bind: 172.31.5.10}
private: {ip: "fd00::2"}
edge:
  switch: ["[fd00::10]:5060"]
  listen: {udp: 16060}
`)}
	if !s6.isSwitchHost("[fd00::10]") || !s6.isSwitchHost("fd00::2") || s6.isSwitchHost("[2001:db8::1]") {
		t.Error("isSwitchHost does not handle IPv6 literals")
	}
	r6 := sip.NewRequest(sip.INVITE, sip.Uri{User: "1", Host: "example.org"})
	r6.AppendHeader(sip.NewHeader("Diversion", "<sip:1000@[fd00::10]:5060>;reason=unconditional"))
	r6.AppendHeader(sip.NewHeader("Call-Info", "<sip:[2001:db8::1]>"))
	s6.maskIdentity(r6, pub)
	if h := r6.GetHeader("Diversion"); h == nil || h.Value() != "<sip:1000@203.0.113.7>;reason=unconditional" {
		t.Errorf("IPv6 Diversion = %v", h)
	}
	if h := r6.GetHeader("Call-Info"); h == nil || h.Value() != "<sip:[2001:db8::1]>" {
		t.Errorf("a foreign IPv6 host was masked: %v", h)
	}
}

// In the early dialog of a client's call the switch's 18x names its own
// address in To; the client echoes the masked form in an UPDATE, and the
// switch gets its address back.
func TestClientLegRestoresIdentityInEarlyDialog(t *testing.T) {
	r := startHideRig(t)
	h := r.h
	swTo := sip.Uri{User: "2002", Host: "127.0.0.1", Port: r.swPort}
	tag := sip.GenerateTagN(12)
	release := make(chan struct{})
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		ring := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
		ring.To().Params.Add("tag", tag)
		ring.To().Address = swTo
		ring.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: r.swPort}})
		_ = tx.Respond(ring)
		<-release
		_ = tx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
		return true
	})
	defer close(release)
	invite := r.phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30301))
	invite.SetTransport("UDP")
	invite.SetDestination(h.publicUDP)
	go func() { _, _ = r.phone.cli.TransactionRequest(context.Background(), invite.Clone()) }()
	if got := h.fs.waitFor(sip.INVITE, 1, 3*time.Second); len(got) != 1 {
		t.Fatal("the switch never saw the INVITE")
	}
	time.Sleep(200 * time.Millisecond) // let the 180 reach the proxy

	upd := sip.NewRequest(sip.UPDATE, invite.Recipient)
	sip.CopyHeaders("From", invite, upd)
	to := &sip.ToHeader{Address: sip.Uri{User: "2002", Host: "127.0.0.1"}, Params: sip.NewParams()}
	to.Params.Add("tag", tag)
	upd.AppendHeader(to)
	sip.CopyHeaders("Call-ID", invite, upd)
	upd.AppendHeader(&sip.CSeqHeader{SeqNo: 2, MethodName: sip.UPDATE})
	mf := sip.MaxForwardsHeader(70)
	upd.AppendHeader(&mf)
	upd.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	via.Params.Add("rport", "")
	upd.PrependHeader(via)
	if res := r.phone.do(t, upd, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("UPDATE: %d", res.StatusCode)
	}
	ups := h.fs.waitFor(sip.UPDATE, 1, 3*time.Second)
	if len(ups) != 1 {
		t.Fatalf("the switch saw %d UPDATEs", len(ups))
	}
	if got := ups[0].To().Address; got.String() != swTo.String() {
		t.Errorf("UPDATE To at the switch = %s, want %s", got.String(), swTo.String())
	}
}
