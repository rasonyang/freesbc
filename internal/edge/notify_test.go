package edge

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Tests for NOTIFY through the edge proxy (issue #81): FreeSWITCH carries
// BroadSoft remote call control (Event: talk answers a ringing phone,
// Event: hold holds a call) in an in-dialog NOTIFY, and the proxy must
// forward it to the client and relay the client's answer back.

// notifyAnsweredHeader marks a NOTIFY response the CLIENT built, so a test
// can tell the client's answer from one FreeSBC generated itself.
const notifyAnsweredHeader = "X-Notify-Answered-By"

// answerNotify responds to a NOTIFY the way a client that implements the
// event does, marking the response as its own.
func answerNotify(req *sip.Request, tx sip.ServerTransaction) {
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader(notifyAnsweredHeader, "client"))
	_ = tx.Respond(res)
}

// buildFSNotify builds a NOTIFY the fake switch sends. from and to are
// copied onto it (the caller chooses the tags); ruri is the Request-URI and
// dest where it is sent. route, when non-empty, becomes the Route set.
func buildFSNotify(f *fakeSwitch, ruri sip.Uri, dest string, from *sip.FromHeader, to *sip.ToHeader,
	callID string, seq uint32, event string, route []sip.Uri) *sip.Request {
	req := sip.NewRequest(sip.NOTIFY, ruri)
	req.AppendHeader(sip.HeaderClone(from))
	req.AppendHeader(sip.HeaderClone(to))
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(&cid)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: sip.NOTIFY})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "mod_sofia", Host: hostOf(f.addr), Port: portOf(f.addr)}})
	for _, u := range route {
		req.AppendHeader(&sip.RouteHeader{Address: u})
	}
	req.AppendHeader(sip.NewHeader("Event", event))
	req.AppendHeader(sip.NewHeader("Allow-Events", "talk, hold, conference, refer"))
	req.AppendHeader(sip.NewHeader("Subscription-State", "active"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: hostOf(f.addr), Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	via.Params.Add("rport", "")
	req.PrependHeader(via)
	req.SetTransport("UDP")
	req.SetDestination(dest)
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}
	return req
}

// fsNotifyInConfirmed builds a NOTIFY the fake switch sends as the UAC of a
// confirmed call it placed: Request-URI = the 2xx's Contact, Route = its
// Record-Route set reversed (RFC 3261 §12.1.2), tags from the 2xx.
func fsNotifyInConfirmed(t *testing.T, f *fakeSwitch, res *sip.Response, event string) *sip.Request {
	t.Helper()
	ruri, ok := fsip.ContactURI(res)
	if !ok {
		t.Fatal("the 2xx carried no Contact")
	}
	hs := res.GetHeaders("Record-Route")
	var route []sip.Uri
	for i := len(hs) - 1; i >= 0; i-- {
		if rr, ok := hs[i].(*sip.RecordRouteHeader); ok {
			route = append(route, rr.Address)
		}
	}
	probe := buildFSNotify(f, ruri, "", res.From(), res.To(), fsip.CallID(res), res.CSeq().SeqNo+1, event, route)
	probe.SetDestination(f.inDialogDest(t, probe, res))
	return probe
}

// sendFS sends req from the fake switch and returns its final response.
func sendFS(t *testing.T, f *fakeSwitch, req *sip.Request) *sip.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("fake switch %s: %v", req.Method, err)
	}
	defer tx.Terminate()
	for {
		select {
		case res := <-tx.Responses():
			if res != nil && res.StatusCode >= 200 {
				return res
			}
		case <-tx.Done():
			t.Fatalf("fake switch %s: %v", req.Method, tx.Err())
		case <-ctx.Done():
			t.Fatalf("fake switch %s timed out", req.Method)
		}
	}
}

// waitInbound returns the next request of method the client receives,
// skipping others; nil on timeout.
func waitInbound(c *client, method sip.RequestMethod, d time.Duration) *sip.Request {
	timeout := time.After(d)
	for {
		select {
		case r := <-c.inbound:
			if r.Method == method {
				return r
			}
		case <-timeout:
			return nil
		}
	}
}

// assertClientNotify checks the NOTIFY a client received: the event is
// intact, and it is addressed to the client itself, never with the binding
// token or FreeSWITCH's own address.
func assertClientNotify(t *testing.T, got *sip.Request, event string, h *harness) {
	t.Helper()
	if got == nil {
		t.Fatal("the client never received the NOTIFY")
	}
	if ev := got.GetHeader("Event"); ev == nil || ev.Value() != event {
		t.Errorf("client NOTIFY Event = %v, want %q", ev, event)
	}
	if strings.Contains(got.Recipient.String(), contactTokenParam+"=") {
		t.Errorf("binding token leaked to the client: %s", got.Recipient.String())
	}
	if c := got.Contact(); c != nil && (c.Address.User == "mod_sofia" || c.Address.Port == portOf(h.fs.addr)) {
		t.Errorf("FreeSWITCH's Contact leaked to the client: %s", c.Address.String())
	}
}

// assertClientAnswered checks FreeSWITCH got the CLIENT's 200, relayed.
func assertClientAnswered(t *testing.T, res *sip.Response) {
	t.Helper()
	if res.StatusCode != 200 {
		t.Fatalf("NOTIFY: FreeSWITCH got %d, want the client's 200", res.StatusCode)
	}
	if hd := res.GetHeader(notifyAnsweredHeader); hd == nil || hd.Value() != "client" {
		t.Error("the 200 FreeSWITCH got is not the client's: FreeSBC answered it itself")
	}
}

// poolUsage is the port reservations on both media planes.
func poolUsage(h *harness) (pub, priv int) {
	pub, _ = h.srv.pubPool.Stats()
	priv, _ = h.srv.privPool.Stats()
	return pub, priv
}

// TestNotifyTalkOnEarlyDialogReachesBrowser is issue #81's regression: a
// browser registered over ws is ringing (its own 180 relayed, no 200 yet)
// when FreeSWITCH sends the in-dialog NOTIFY Event: talk that tells it to
// answer. The NOTIFY names an EARLY dialog, which the confirmed-dialog
// lookup cannot find; it must still reach the browser by the fsbc= token
// in its Request-URI, and the browser's 200 must reach FreeSWITCH. The
// early dialog and its media are left exactly as they were, and the call
// then completes when the browser answers.
func TestNotifyTalkOnEarlyDialogReachesBrowser(t *testing.T) {
	h := startHarness(t, true)
	c := newWSClient(t)
	ruri := registerOver(t, h, c, h.publicWS, "1001")
	b := newFakeBrowser(t, "active")

	fsRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: h.fs.rtpPort})
	if err != nil {
		t.Fatalf("bind FreeSWITCH's RTP port: %v", err)
	}
	t.Cleanup(func() { _ = fsRTP.Close() })

	// The browser rings and holds the INVITE until the test lets it answer
	// — the moment a real client answers is the talk event arriving.
	tag := sip.GenerateTagN(12)
	answerGate := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-answerGate:
		default:
			close(answerGate)
		}
	})
	c.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method == sip.NOTIFY {
			answerNotify(req, tx)
			return
		}
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		offer, err := parseLabSDP(req.Body())
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Not Acceptable Here", nil))
			return
		}
		ringing := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
		ringing.To().Params.Add("tag", tag)
		_ = tx.Respond(ringing)
		select {
		case <-answerGate:
		case <-time.After(15 * time.Second):
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(b.answerSDP(offer, "127.0.0.1")))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: c.contactURI(req.Recipient.User)})
		res.To().Params.Add("tag", tag)
		_ = tx.Respond(res)
		go b.connect(req.Body())
	})

	invite := h.fs.callRequest(ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := h.fs.cli.TransactionRequest(ctx, invite)
	if err != nil {
		t.Fatalf("fake switch INVITE: %v", err)
	}
	defer tx.Terminate()

	// Wait for the browser's 180 at FreeSWITCH: the early dialog's To tag
	// is the browser's own.
	var ringing *sip.Response
	for ringing == nil {
		select {
		case res := <-tx.Responses():
			if res == nil {
				continue
			}
			if res.StatusCode >= 200 {
				t.Fatalf("INVITE ended with %d before the NOTIFY", res.StatusCode)
			}
			if res.StatusCode == 180 {
				ringing = res
			}
		case <-tx.Done():
			t.Fatalf("fake switch INVITE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("the browser's 180 never reached FreeSWITCH")
		}
	}
	if got := fsip.ToTag(ringing); got != tag {
		t.Fatalf("180 To tag = %q, want the browser's %q", got, tag)
	}
	if waitInbound(c, sip.INVITE, 3*time.Second) == nil {
		t.Fatal("the browser never received the INVITE")
	}

	callID := fsip.CallID(invite)
	early, ok := h.srv.dialogs.early(callID, fsip.FromTag(invite))
	if !ok {
		t.Fatal("no early dialog while the browser rings")
	}
	sessBefore := early.session()
	pubBefore, privBefore := poolUsage(h)

	// FreeSWITCH's NOTIFY, shaped as in the issue: the INVITE's From and
	// Call-ID, the browser's To tag, the stored fsbc= contact as the
	// Request-URI, sent straight to the private socket.
	notify := buildFSNotify(h.fs, ruri, h.privateSIP, invite.From(), ringing.To(), callID, invite.CSeq().SeqNo+1, "talk", nil)
	nres := sendFS(t, h.fs, notify)
	assertClientAnswered(t, nres)
	assertClientNotify(t, waitInbound(c, sip.NOTIFY, 3*time.Second), "talk", h)

	// Nothing about the call moved: the early dialog is the same record,
	// still early, with the same media session, and no port was taken or
	// released.
	after, ok := h.srv.dialogs.early(callID, fsip.FromTag(invite))
	if !ok || after != early {
		t.Fatal("the NOTIFY disturbed the early dialog")
	}
	if after.session() != sessBefore {
		t.Error("the NOTIFY replaced the early dialog's media session")
	}
	if _, confirmed := h.srv.dialogs.confirmed(callID); confirmed {
		t.Error("the NOTIFY confirmed the dialog")
	}
	if pub, priv := poolUsage(h); pub != pubBefore || priv != privBefore {
		t.Errorf("port reservations moved: public %d→%d, private %d→%d", pubBefore, pub, privBefore, priv)
	}

	// The browser answers, as the talk event told it to.
	close(answerGate)
	var final *sip.Response
	for final == nil {
		select {
		case res := <-tx.Responses():
			if res != nil && res.StatusCode >= 200 {
				final = res
			}
		case <-tx.Done():
			t.Fatalf("fake switch INVITE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("the browser's 200 never reached FreeSWITCH")
		}
	}
	if final.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", final.StatusCode)
	}
	h.fs.sendAckTo2xx(t, final)
	b.waitReady(t)
	if d := waitForDialog(t, h, callID); d != early {
		t.Error("the confirmed dialog is not the early record the NOTIFY left alone")
	}
	assertMediaBothWays(t, b, fsRTP, assertUpstreamPlain(t, h, final.Body(), b))

	if r := h.fs.uacBye(t, final); r.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
	waitWebRTCSessions(t, h, 0)
}

// TestNotifyHoldOnConfirmedBrowserCall: Event: hold on a confirmed call to
// a ws browser is forwarded the same way, routed by the dialog record (the
// Request-URI is the SBC's own Contact, with no token), and leaves the
// dialog, its media session and its ports as they were — media keeps
// flowing.
func TestNotifyHoldOnConfirmedBrowserCall(t *testing.T) {
	h := startHarness(t, true)
	c, b, call, fsRTP := placeBrowserCall(t, h, "ws", "active", "127.0.0.1")
	ans := assertUpstreamPlain(t, h, call.res.Body(), b)
	c.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method == sip.NOTIFY {
			answerNotify(req, tx)
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	drain(c.inbound)

	callID := fsip.CallID(call.res)
	d := waitForDialog(t, h, callID)
	sessBefore := d.session()
	pubBefore, privBefore := poolUsage(h)

	nres := sendFS(t, h.fs, fsNotifyInConfirmed(t, h.fs, call.res, "hold"))
	assertClientAnswered(t, nres)
	assertClientNotify(t, waitInbound(c, sip.NOTIFY, 3*time.Second), "hold", h)

	after, ok := h.srv.dialogs.confirmed(callID)
	if !ok || after != d {
		t.Fatal("the NOTIFY disturbed the confirmed dialog")
	}
	if after.session() != sessBefore {
		t.Error("the NOTIFY replaced the dialog's media session")
	}
	if pub, priv := poolUsage(h); pub != pubBefore || priv != privBefore {
		t.Errorf("port reservations moved: public %d→%d, private %d→%d", pubBefore, pub, privBefore, priv)
	}
	if got := h.srv.ActiveCalls(); got != 1 {
		t.Errorf("active calls = %d, want 1", got)
	}
	assertMediaBothWays(t, b, fsRTP, ans)

	if r := h.fs.uacBye(t, call.res); r.StatusCode != 200 {
		t.Fatalf("BYE from FreeSWITCH: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
	waitWebRTCSessions(t, h, 0)
}

// TestNotifyTalkReachesUDPPhone: the same forwarding reaches a phone on
// plain SIP/UDP, addressed to the phone's own contact.
func TestNotifyTalkReachesUDPPhone(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	phoneRTP := auditUDP(t)
	auditPhoneAnswers(phone, auditUDPPort(phoneRTP), nil)
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	h.fs.sendAckTo2xx(t, res)
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method == sip.NOTIFY {
			answerNotify(req, tx)
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	drain(phone.inbound)

	callID := fsip.CallID(res)
	d := waitForDialog(t, h, callID)
	sessBefore := d.session()
	pubBefore, privBefore := poolUsage(h)

	nres := sendFS(t, h.fs, fsNotifyInConfirmed(t, h.fs, res, "talk"))
	assertClientAnswered(t, nres)
	got := waitInbound(phone, sip.NOTIFY, 3*time.Second)
	assertClientNotify(t, got, "talk", h)
	if want := phone.contactURI("1001"); got.Recipient.Host != want.Host || got.Recipient.Port != want.Port {
		t.Errorf("phone NOTIFY Request-URI = %s, want the phone's contact %s", got.Recipient.String(), want.String())
	}

	if after, ok := h.srv.dialogs.confirmed(callID); !ok || after != d || after.session() != sessBefore {
		t.Error("the NOTIFY disturbed the dialog or its media session")
	}
	if pub, priv := poolUsage(h); pub != pubBefore || priv != privBefore {
		t.Errorf("port reservations moved: public %d→%d, private %d→%d", pubBefore, pub, privBefore, priv)
	}

	if r := h.fs.uacBye(t, res); r.StatusCode != 200 {
		t.Fatalf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// TestOutOfDialogNotify pins the decision on NOTIFY with no To tag:
//   - from FreeSWITCH, addressed to a binding FreeSBC holds (MWI, Event:
//     message-summary): forwarded to the client, which answers it;
//   - from FreeSWITCH, addressed to a token nobody holds: 481;
//   - from a public client: 481, and FreeSWITCH never sees it.
//
// None of them creates a dialog or takes a port.
func TestOutOfDialogNotify(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method == sip.NOTIFY {
			answerNotify(req, tx)
			return
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	drain(phone.inbound)

	newFrom := func(user string) *sip.FromHeader {
		f := &sip.FromHeader{Address: sip.Uri{User: user, Host: "example.com"}, Params: sip.NewParams()}
		f.Params.Add("tag", sip.GenerateTagN(12))
		return f
	}

	t.Run("upstream to held binding is forwarded", func(t *testing.T) {
		to := &sip.ToHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
		req := buildFSNotify(h.fs, ruri, h.privateSIP, newFrom("1001"), to, "mwi-held", 1, "message-summary", nil)
		req.AppendHeader(sip.NewHeader("Content-Type", "application/simple-message-summary"))
		req.SetBody([]byte("Messages-Waiting: yes\r\nVoice-Message: 1/0 (0/0)\r\n"))
		res := sendFS(t, h.fs, req)
		assertClientAnswered(t, res)
		got := waitInbound(phone, sip.NOTIFY, 3*time.Second)
		assertClientNotify(t, got, "message-summary", h)
		if !strings.Contains(string(got.Body()), "Messages-Waiting: yes") {
			t.Errorf("MWI body not carried: %q", got.Body())
		}
	})

	t.Run("upstream to unknown binding is 481", func(t *testing.T) {
		unknown := sip.Uri{User: "9999", Host: "127.0.0.1", Port: portOf(h.privateSIP), UriParams: sip.NewParams()}
		unknown.UriParams.Add(contactTokenParam, "no-such-token")
		to := &sip.ToHeader{Address: unknown, Params: sip.NewParams()}
		req := buildFSNotify(h.fs, unknown, h.privateSIP, newFrom("9999"), to, "mwi-unknown", 1, "message-summary", nil)
		if res := sendFS(t, h.fs, req); res.StatusCode != 481 {
			t.Errorf("got %d, want 481", res.StatusCode)
		}
		if waitInbound(phone, sip.NOTIFY, 300*time.Millisecond) != nil {
			t.Error("a NOTIFY for an unknown binding reached a client")
		}
	})

	t.Run("public client is 481", func(t *testing.T) {
		req := sip.NewRequest(sip.NOTIFY, sip.Uri{User: "2002", Host: "example.com"})
		req.AppendHeader(newFrom("1001"))
		req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "2002", Host: "example.com"}, Params: sip.NewParams()})
		cid := sip.CallIDHeader("notify-from-client")
		req.AppendHeader(&cid)
		req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.NOTIFY})
		mf := sip.MaxForwardsHeader(70)
		req.AppendHeader(&mf)
		req.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		req.AppendHeader(sip.NewHeader("Event", "message-summary"))
		req.AppendHeader(sip.NewHeader("Subscription-State", "active"))
		via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
		via.Params.Add("branch", sip.GenerateBranchN(16))
		via.Params.Add("rport", "")
		req.PrependHeader(via)
		if res := phone.do(t, req, h.publicUDP); res.StatusCode != 481 {
			t.Errorf("got %d, want 481", res.StatusCode)
		}
		time.Sleep(200 * time.Millisecond)
		if got := h.fs.received(sip.NOTIFY); len(got) != 0 {
			t.Errorf("FreeSWITCH received %d NOTIFYs from a public client", len(got))
		}
	})

	if pub, priv := poolUsage(h); pub != 0 || priv != 0 {
		t.Errorf("out-of-dialog NOTIFY took ports: public=%d private=%d", pub, priv)
	}
	if got := h.srv.ActiveCalls(); got != 0 {
		t.Errorf("active calls = %d, want 0", got)
	}
	if n := auditDialogEntries(h); n != 0 {
		t.Errorf("dialog table has %d entries, want 0", n)
	}
}

// TestAllowListsNotify: the Allow FreeSBC emits — on its own OPTIONS answer
// and on a 405 — lists NOTIFY, and SUBSCRIBE is still refused.
func TestAllowListsNotify(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	build := func(method sip.RequestMethod, callID string) *sip.Request {
		req := sip.NewRequest(method, sip.Uri{User: "1001", Host: "example.com"})
		from := &sip.FromHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
		from.Params.Add("tag", sip.GenerateTagN(12))
		req.AppendHeader(from)
		req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()})
		cid := sip.CallIDHeader(callID)
		req.AppendHeader(&cid)
		req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: method})
		mf := sip.MaxForwardsHeader(70)
		req.AppendHeader(&mf)
		req.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
		via.Params.Add("branch", sip.GenerateBranchN(16))
		req.PrependHeader(via)
		return req
	}

	opt := phone.do(t, build(sip.OPTIONS, "allow-notify-options"), h.publicUDP)
	if opt.StatusCode != 200 {
		t.Fatalf("OPTIONS: got %d", opt.StatusCode)
	}
	if !headerTokens(opt, "Allow")["NOTIFY"] {
		t.Errorf("OPTIONS Allow does not list NOTIFY: %v", headerTokens(opt, "Allow"))
	}

	sub := build(sip.SUBSCRIBE, "allow-notify-subscribe")
	sub.AppendHeader(sip.NewHeader("Event", "message-summary"))
	res := phone.do(t, sub, h.publicUDP)
	if res.StatusCode != 405 {
		t.Fatalf("SUBSCRIBE: got %d, want 405", res.StatusCode)
	}
	allow := headerTokens(res, "Allow")
	if !allow["NOTIFY"] {
		t.Errorf("405 Allow does not list NOTIFY: %v", allow)
	}
	if allow["SUBSCRIBE"] {
		t.Errorf("405 Allow lists SUBSCRIBE: %v", allow)
	}
}
