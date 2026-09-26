package edge

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Tests for issue #84: FreeSWITCH's uuid_phone_event NOTIFY (Event: talk to
// resume a held call) carries a To header copied from the sip_full_to
// channel variable, so its tag can match no dialog. From the private plane,
// a NOTIFY whose Call-ID names a dialog FreeSBC holds is forwarded to that
// dialog's client whatever its tags; it is refused 481 only when no dialog
// with a public route carries the Call-ID. Everything else keeps exact tag
// matching.

// fsStrayRequest builds an in-dialog request the fake switch sends in the
// shape captured in issue #84 for a call it placed (res is the 2xx it got):
// Request-URI sip:<sbc-private>:<port> with no user and no token, Route =
// the 2xx's Record-Route set reversed (private first, then public), From =
// the switch's own From, and To = a copy of that same From, URI and tag.
// For a NOTIFY it carries Event: talk.
func fsStrayRequest(t *testing.T, h *harness, method sip.RequestMethod, res *sip.Response) *sip.Request {
	t.Helper()
	ruri := sip.Uri{Host: hostOf(h.privateSIP), Port: portOf(h.privateSIP)}
	hs := res.GetHeaders("Record-Route")
	var route []sip.Uri
	for i := len(hs) - 1; i >= 0; i-- {
		if rr, ok := hs[i].(*sip.RecordRouteHeader); ok {
			route = append(route, rr.Address)
		}
	}
	if len(route) != 2 {
		t.Fatalf("2xx carried %d Record-Route values, want the double Record-Route", len(route))
	}
	from := res.From()
	to := &sip.ToHeader{Address: from.Address, Params: from.Params.Clone()}
	req := buildFSNotify(h.fs, ruri, "", from, to, fsip.CallID(res), res.CSeq().SeqNo+1, "talk", route)
	if method != sip.NOTIFY {
		req.Method = method
		req.CSeq().MethodName = method
		req.RemoveHeader("Event")
		req.RemoveHeader("Allow-Events")
		req.RemoveHeader("Subscription-State")
	}
	req.SetDestination(h.fs.inDialogDest(t, req, res))
	return req
}

// TestNotifyStrayToTagReachesBrowser is acceptance test 1 of issue #84: a
// confirmed call from FreeSWITCH to a ws browser, then the resume NOTIFY
// exactly as captured — Event: talk, To identical to From — reaches the
// browser with its To untouched, the browser's 200 reaches FreeSWITCH, and
// the dialog, its media session and its ports are as they were. The switch
// sends it twice, as it retries, and both are delivered.
func TestNotifyStrayToTagReachesBrowser(t *testing.T) {
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
	callerTag, calleeTag := d.tags()
	sessBefore := d.session()
	pubBefore, privBefore := poolUsage(h)

	for i := 0; i < 2; i++ {
		notify := fsStrayRequest(t, h, sip.NOTIFY, call.res)
		strayTag := fsip.ToTag(notify)
		if strayTag != callerTag || strayTag == calleeTag {
			t.Fatalf("test NOTIFY To tag %q is not the stray shape (dialog tags %q, %q)", strayTag, callerTag, calleeTag)
		}
		nres := sendFS(t, h.fs, notify)
		assertClientAnswered(t, nres)
		got := waitInbound(c, sip.NOTIFY, 3*time.Second)
		assertClientNotify(t, got, "talk", h)
		if tag := fsip.ToTag(got); tag != strayTag {
			t.Errorf("attempt %d: client NOTIFY To tag = %q, want FreeSWITCH's %q forwarded verbatim", i, tag, strayTag)
		}
		if got.To().Address.User != notify.To().Address.User {
			t.Errorf("attempt %d: client NOTIFY To = %s, want %s", i, got.To().Address.String(), notify.To().Address.String())
		}
	}
	if !d.relaxedNotified() {
		t.Error("the relaxed routing was not recorded on the dialog")
	}

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

// fsCallPhone places a call from the fake switch to a registered UDP phone,
// optionally with a fixed Call-ID, ACKs it and returns the 2xx.
func fsCallPhone(t *testing.T, h *harness, ruri sip.Uri, callID string) *sip.Response {
	t.Helper()
	invite := h.fs.callRequest(ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if callID != "" {
		*invite.CallID() = sip.CallIDHeader(callID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := h.fs.cli.TransactionRequest(ctx, invite)
	if err != nil {
		t.Fatalf("fake switch INVITE: %v", err)
	}
	defer tx.Terminate()
	for {
		select {
		case res := <-tx.Responses():
			if res == nil || res.StatusCode < 200 {
				continue
			}
			if res.StatusCode != 200 {
				t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
			}
			h.fs.sendAckTo2xx(t, res)
			return res
		case <-tx.Done():
			t.Fatalf("fake switch INVITE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("fake switch INVITE timed out")
		}
	}
}

// strayPhoneCall registers a UDP phone that answers every request, places
// one call to it from the fake switch and returns the phone and the 2xx.
func strayPhoneCall(t *testing.T, h *harness) (*client, sip.Uri, *sip.Response) {
	t.Helper()
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	phoneRTP := auditUDP(t)
	auditPhoneAnswers(phone, auditUDPPort(phoneRTP), nil)
	res := fsCallPhone(t, h, ruri, "")
	waitForDialog(t, h, fsip.CallID(res))
	drain(phone.inbound)
	return phone, ruri, res
}

// relaxedNotified reads, under the table lock, whether a NOTIFY was ever
// routed to d by the relaxed lookup.
func (d *dialog) relaxedNotified() bool {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.relaxedNotify
}

// assertNotDelivered checks a refused request never reached the phone.
func assertNotDelivered(t *testing.T, phone *client, method sip.RequestMethod) {
	t.Helper()
	if got := waitInbound(phone, method, 300*time.Millisecond); got != nil {
		t.Errorf("a refused %s reached the client", method)
	}
}

// TestNotifyStrayToTagPaths covers the other cases of issue #84 on one
// confirmed call from FreeSWITCH to a UDP phone:
//   - test 3: a Call-ID that names no dialog → 481;
//   - test 5: a BYE and an INFO with the same stray To tag → 481, and the
//     BYE ends nothing;
//   - a NOTIFY whose From tag is neither of the dialog's tags is forwarded
//     all the same: tags are not checked on this path;
//   - test 4: the same stray-tag NOTIFY from the PUBLIC plane is not
//     relaxed: it is never routed back to the client side, and takes the
//     existing public no-dialog path to the hashed upstream.
//
// Afterwards the dialog is still up and ends normally.
func TestNotifyStrayToTagPaths(t *testing.T) {
	h := startHarness(t, false)
	phone, _, res := strayPhoneCall(t, h)
	callID := fsip.CallID(res)
	d := waitForDialog(t, h, callID)

	t.Run("unknown Call-ID is 481", func(t *testing.T) {
		req := fsStrayRequest(t, h, sip.NOTIFY, res)
		*req.CallID() = sip.CallIDHeader("no-such-call-" + sip.GenerateTagN(8))
		if r := sendFS(t, h.fs, req); r.StatusCode != 481 {
			t.Errorf("got %d, want 481", r.StatusCode)
		}
		assertNotDelivered(t, phone, sip.NOTIFY)
	})

	for _, m := range []sip.RequestMethod{sip.BYE, sip.INFO} {
		t.Run(string(m)+" with stray To tag is 481", func(t *testing.T) {
			if r := sendFS(t, h.fs, fsStrayRequest(t, h, m, res)); r.StatusCode != 481 {
				t.Errorf("got %d, want 481", r.StatusCode)
			}
			assertNotDelivered(t, phone, m)
		})
	}

	t.Run("public plane is not relaxed", func(t *testing.T) {
		_, calleeTag := d.tags()
		before := len(h.fs.received(sip.NOTIFY))
		req := sip.NewRequest(sip.NOTIFY, sip.Uri{Host: hostOf(h.publicUDP), Port: portOf(h.publicUDP)})
		from := &sip.FromHeader{Address: phone.contactURI("1001"), Params: sip.NewParams()}
		from.Params.Add("tag", calleeTag)
		req.AppendHeader(from)
		to := &sip.ToHeader{Address: phone.contactURI("1001"), Params: sip.NewParams()}
		to.Params.Add("tag", calleeTag) // the stray shape: To = From
		req.AppendHeader(to)
		cid := sip.CallIDHeader(callID)
		req.AppendHeader(&cid)
		req.AppendHeader(&sip.CSeqHeader{SeqNo: 50, MethodName: sip.NOTIFY})
		mf := sip.MaxForwardsHeader(70)
		req.AppendHeader(&mf)
		req.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		req.AppendHeader(sip.NewHeader("Event", "talk"))
		req.AppendHeader(sip.NewHeader("Subscription-State", "active"))
		via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
		via.Params.Add("branch", sip.GenerateBranchN(16))
		via.Params.Add("rport", "")
		req.PrependHeader(via)
		phone.do(t, req, h.publicUDP)
		assertNotDelivered(t, phone, sip.NOTIFY)
		// Unchanged path: directionFor forwards a public request that names
		// no dialog to the hashed upstream, which answers it itself (a real
		// FreeSWITCH with 481; the fake switch answers every method it has
		// no handler for with 200).
		if got := h.fs.waitFor(sip.NOTIFY, before+1, 3*time.Second); len(got) != before+1 {
			t.Errorf("the public-plane NOTIFY did not take the existing upstream path (FreeSWITCH got %d)", len(got))
		}
		if d.relaxedNotified() {
			t.Error("a public-plane NOTIFY was routed by the relaxed lookup")
		}
	})

	t.Run("From tag matching neither side is forwarded", func(t *testing.T) {
		req := fsStrayRequest(t, h, sip.NOTIFY, res)
		req.From().Params.Add("tag", "not-a-dialog-tag")
		if r := sendFS(t, h.fs, req); r.StatusCode != 200 {
			t.Errorf("got %d, want the phone's 200", r.StatusCode)
		}
		got := waitInbound(phone, sip.NOTIFY, 3*time.Second)
		assertClientNotify(t, got, "talk", h)
		if tag := fsip.FromTag(got); tag != "not-a-dialog-tag" {
			t.Errorf("phone NOTIFY From tag = %q, want it forwarded verbatim", tag)
		}
		if !d.relaxedNotified() {
			t.Error("the relaxed routing was not recorded on the dialog")
		}
	})

	if after, ok := h.srv.dialogs.confirmed(callID); !ok || after != d {
		t.Fatal("a stray-tag request disturbed the confirmed dialog")
	}
	if got := h.srv.ActiveCalls(); got != 1 {
		t.Errorf("active calls = %d, want 1", got)
	}
	if r := h.fs.uacBye(t, res); r.StatusCode != 200 {
		t.Fatalf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// TestNotifyStrayToTagSharedCallID is acceptance test 2 of issue #84, under
// the rule adopted for it: FreeSWITCH places two calls to the same phone
// with ONE Call-ID (different From tags), so two confirmed dialogs share
// it. The stray-tag NOTIFY — built from the FIRST call — is forwarded to
// the most recently created dialog with a public route, the second call,
// and the phone's 200 reaches FreeSWITCH.
func TestNotifyStrayToTagSharedCallID(t *testing.T) {
	h := startHarness(t, false)
	phone, ruri, first := strayPhoneCall(t, h)
	callID := fsip.CallID(first)
	second := fsCallPhone(t, h, ruri, callID)
	if fsip.CallID(second) != callID || fsip.FromTag(second) == fsip.FromTag(first) {
		t.Fatal("the second call does not share the Call-ID under a new From tag")
	}
	deadline := time.Now().Add(3 * time.Second)
	for h.srv.ActiveCalls() != 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := h.srv.ActiveCalls(); got != 2 {
		t.Fatalf("active calls = %d, want two confirmed dialogs on one Call-ID", got)
	}
	older, _, ok1 := h.srv.dialogs.lookup(callID, fsip.FromTag(first), fsip.ToTag(first))
	newer, _, ok2 := h.srv.dialogs.lookup(callID, fsip.FromTag(second), fsip.ToTag(second))
	if !ok1 || !ok2 || older == newer {
		t.Fatal("the two calls are not two confirmed dialogs")
	}
	drain(phone.inbound)

	if r := sendFS(t, h.fs, fsStrayRequest(t, h, sip.NOTIFY, first)); r.StatusCode != 200 {
		t.Errorf("got %d, want the phone's 200", r.StatusCode)
	}
	assertClientNotify(t, waitInbound(phone, sip.NOTIFY, 3*time.Second), "talk", h)
	if !newer.relaxedNotified() || older.relaxedNotified() {
		t.Errorf("routed to the wrong dialog: newer relaxed=%v, older relaxed=%v, want the newer only",
			newer.relaxedNotified(), older.relaxedNotified())
	}
	if got := h.srv.ActiveCalls(); got != 2 {
		t.Errorf("active calls = %d, want 2", got)
	}

	for _, res := range []*sip.Response{first, second} {
		if r := h.fs.uacBye(t, res); r.StatusCode != 200 {
			t.Fatalf("BYE: got %d", r.StatusCode)
		}
	}
	waitForRelease(t, h)
}

// TestNewestRoutedByCallID pins the helper the relaxed lookup rests on: it
// returns the most recently created record carrying the Call-ID that has a
// public route, and nothing when no record qualifies. An early record has
// no route and never qualifies.
func TestNewestRoutedByCallID(t *testing.T) {
	tab := newDialogTable(NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := func(callID string, st dialogState) *dialog {
		d := &dialog{tab: tab, callID: callID, callerTag: sip.GenerateTagN(8), state: st}
		if st == dialogConfirmed {
			d.route = dialogRoute{publicRemote: "127.0.0.1:5060", transport: "udp"}
		}
		tab.byCallID[callID] = append(tab.byCallID[callID], d)
		return d
	}
	one := rec("one", dialogConfirmed)
	withEarly := rec("with-early", dialogConfirmed)
	rec("with-early", dialogEarly)
	rec("two", dialogConfirmed)
	two := rec("two", dialogConfirmed)
	rec("early-only", dialogEarly)
	rec("no-public", dialogConfirmed).route.publicRemote = ""

	for _, tc := range []struct {
		callID string
		want   *dialog
	}{
		{"one", one},
		{"with-early", withEarly},
		{"two", two},
		{"early-only", nil},
		{"no-public", nil},
		{"absent", nil},
	} {
		got, r, ok := tab.newestRoutedByCallID(tc.callID)
		if got != tc.want || ok != (tc.want != nil) {
			t.Errorf("%s: got (%p, %v), want %p", tc.callID, got, ok, tc.want)
		}
		if ok && r.publicRemote == "" {
			t.Errorf("%s: returned a route with no public remote", tc.callID)
		}
	}
}
