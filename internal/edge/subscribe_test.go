package edge

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Tests for SUBSCRIBE dialogs through the edge proxy (issue #112): a
// registered client's SUBSCRIBE (BLF, MWI) reaches the hashed switch with
// FreeSBC's Contact and double Record-Route, the NOTIFYs come back along
// the subscription, and the proxy keeps a bounded record of each dialog.

// buildSubscribe builds an out-of-dialog SUBSCRIBE from c.
func (c *client) buildSubscribe(user, event string, expires int) *sip.Request {
	req := sip.NewRequest(sip.SUBSCRIBE, sip.Uri{User: "2002", Host: "example.com"})
	f := &sip.FromHeader{Address: sip.Uri{User: user, Host: "example.com"}, Params: sip.NewParams()}
	f.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(f)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "2002", Host: "example.com"}, Params: sip.NewParams()})
	callID := sip.CallIDHeader(fmt.Sprintf("sub-%s-%d", c.transport, time.Now().UnixNano()))
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.SUBSCRIBE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: c.contactURI(user)})
	req.AppendHeader(sip.NewHeader("Event", event))
	req.AppendHeader(sip.NewHeader("Expires", fmt.Sprint(expires)))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0",
		Transport: strings.ToUpper(c.transport), Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	if c.transport == "udp" {
		via.Params.Add("rport", "")
	}
	req.PrependHeader(via)
	return req
}

// subscribeResponse builds the notifier's 2xx to a SUBSCRIBE: the given
// To tag on an initial one, the request's Expires echoed, the switch's own
// Contact.
func subscribeResponse(f *fakeSwitch, req *sip.Request, tag string) *sip.Response {
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	if fsip.ToTag(req) == "" {
		res.To().Params.Remove("tag")
		res.To().Params.Add("tag", tag)
	}
	if e := req.GetHeader("Expires"); e != nil {
		res.AppendHeader(sip.NewHeader("Expires", e.Value()))
	}
	res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "mod_sofia", Host: hostOf(f.addr), Port: portOf(f.addr)}})
	return res
}

// subscribeAccepted makes the fake switch answer every SUBSCRIBE 200.
func subscribeAccepted(f *fakeSwitch, tag string) {
	f.setNoRouteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		if req.Method != sip.SUBSCRIBE {
			return false
		}
		_ = tx.Respond(subscribeResponse(f, req, tag))
		return true
	})
}

// fsSubNotify builds the NOTIFY the switch sends as the notifier of the
// SUBSCRIBE sub it received (Request-URI = the subscriber's Contact as the
// switch saw it, Route = the Record-Route set in order, RFC 3261 §12.1.1).
func fsSubNotify(t *testing.T, f *fakeSwitch, sub *sip.Request, tag string, seq uint32, event, state, ctype, body string) *sip.Request {
	t.Helper()
	target, ok := fsip.ContactURI(sub)
	if !ok {
		t.Fatal("the SUBSCRIBE the switch received carried no Contact")
	}
	from := &sip.FromHeader{Address: sub.To().Address, Params: sip.NewParams()}
	from.Params.Add("tag", tag)
	to := &sip.ToHeader{Address: sub.From().Address, Params: sip.NewParams()}
	to.Params.Add("tag", fsip.FromTag(sub))
	var route []sip.Uri
	for _, h := range sub.GetHeaders("Record-Route") {
		if rr, ok := h.(*sip.RecordRouteHeader); ok {
			route = append(route, rr.Address)
		}
	}
	req := buildFSNotify(f, target, "", from, to, fsip.CallID(sub), seq, event, route)
	req.ReplaceHeader(sip.NewHeader("Subscription-State", state))
	if body != "" {
		req.AppendHeader(sip.NewHeader("Content-Type", ctype))
		req.SetBody([]byte(body))
	}
	req.SetDestination(f.topRouteDest(t, req))
	return req
}

// waitSubs waits for the subscription record count (and its gauge) to
// reach n.
func waitSubs(t *testing.T, h *harness, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.subs.count() == n && h.srv.metrics.Snapshot().ActiveSubscriptions == int64(n) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("subscription records = %d (gauge %d), want %d",
		h.srv.subs.count(), h.srv.metrics.Snapshot().ActiveSubscriptions, n)
}

// subscribeDialog is an established subscription: the client's original
// SUBSCRIBE, the 2xx it got and the SUBSCRIBE as the switch received it.
type subscribeDialog struct {
	sub  *sip.Request
	res  *sip.Response
	seen *sip.Request
	tag  string // the notifier's tag
}

// establish places a SUBSCRIBE from c over dest and checks that the switch
// f received and answered it.
func establish(t *testing.T, c *client, f *fakeSwitch, dest, user, event string, expires int) subscribeDialog {
	t.Helper()
	sub := c.buildSubscribe(user, event, expires)
	before := len(f.received(sip.SUBSCRIBE))
	res := c.do(t, sub, dest)
	if res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE: got %d, want 200", res.StatusCode)
	}
	seen := f.waitFor(sip.SUBSCRIBE, before+1, 3*time.Second)
	if len(seen) != before+1 {
		t.Fatalf("the switch saw %d SUBSCRIBEs, want %d", len(seen), before+1)
	}
	return subscribeDialog{sub: sub, res: res, seen: seen[before], tag: toTagOf(res)}
}

func TestSubscribeDialogFlow(t *testing.T) {
	for _, tc := range []struct {
		event, ctype, body string
	}{
		{"dialog", "application/dialog-info+xml", `<dialog-info state="full"/>`},
		{"message-summary", "application/simple-message-summary", "Messages-Waiting: yes\r\n"},
	} {
		t.Run(tc.event, func(t *testing.T) {
			addrA := fmt.Sprintf("127.0.0.1:%d", freePort(t))
			addrB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
			h, switches := startHarnessSwitches(t, []string{addrA, addrB})
			fsA, fsB := switches[addrA], switches[addrB]
			subscribeAccepted(fsA, "notifier-tag")
			subscribeAccepted(fsB, "notifier-tag")
			user := userForNode(t, h.srv.topo, nodeIndex(t, h.srv.topo, addrA))
			phone := newUDPClient(t)
			registerUser(t, phone, user, h.publicUDP)
			drain(phone.inbound)

			d := establish(t, phone, fsA, h.publicUDP, user, tc.event, 600)
			if n := len(fsB.received(sip.SUBSCRIBE)); n != 0 {
				t.Errorf("the other node saw %d SUBSCRIBEs; the hash names fs-a", n)
			}
			// Toward the switch: FreeSBC's Contact, both Record-Routes.
			if c := d.seen.Contact(); c == nil || c.Address.Port != portOf(h.privateSIP) {
				t.Errorf("Contact toward the switch = %v, want FreeSBC's private socket", c)
			}
			if n := len(d.seen.GetHeaders("Record-Route")); n != 2 {
				t.Errorf("Record-Route values toward the switch = %d, want 2", n)
			}
			if ev := d.seen.GetHeader("Event"); ev == nil || ev.Value() != tc.event {
				t.Errorf("Event at the switch = %v", ev)
			}
			// Back to the client: FreeSBC's public Contact, the tag and
			// expiry intact.
			if c := d.res.Contact(); c == nil || c.Address.Port != portOf(h.publicUDP) {
				t.Errorf("Contact in the 2xx = %v, want FreeSBC's public socket", c)
			}
			if d.tag != "notifier-tag" {
				t.Errorf("To tag in the 2xx = %q", d.tag)
			}
			if e := d.res.GetHeader("Expires"); e == nil || e.Value() != "600" {
				t.Errorf("Expires in the 2xx = %v", e)
			}
			waitSubs(t, h, 1)

			// A NOTIFY on the same Call-ID, with its body, reaches the client.
			n1 := sendFS(t, fsA, fsSubNotify(t, fsA, d.seen, d.tag, 1, tc.event, "active;expires=600", tc.ctype, tc.body))
			if n1.StatusCode != 200 {
				t.Fatalf("NOTIFY: the switch got %d, want the client's 200", n1.StatusCode)
			}
			got := waitInbound(phone, sip.NOTIFY, 3*time.Second)
			if got == nil {
				t.Fatal("the client never received the NOTIFY")
			}
			if ev := got.GetHeader("Event"); ev == nil || ev.Value() != tc.event {
				t.Errorf("client NOTIFY Event = %v, want %q", ev, tc.event)
			}
			if strings.Contains(got.Recipient.String(), contactTokenParam+"=") {
				t.Errorf("binding token leaked to the client: %s", got.Recipient.String())
			}
			if c := got.Contact(); c != nil && c.Address.User == "mod_sofia" {
				t.Errorf("the switch's Contact leaked to the client: %s", c.Address.String())
			}
			if fsip.CallID(got) != fsip.CallID(d.sub) {
				t.Errorf("NOTIFY Call-ID = %q, want the SUBSCRIBE's %q", fsip.CallID(got), fsip.CallID(d.sub))
			}
			if string(got.Body()) != tc.body {
				t.Errorf("NOTIFY body = %q, want %q", got.Body(), tc.body)
			}
			if c := got.Contact(); c == nil || c.Address.Port != portOf(h.publicUDP) {
				t.Errorf("Contact in the NOTIFY = %v, want FreeSBC's public socket", c)
			}

			// A refresh runs in the dialog, to the same switch.
			refresh := inDialogRequest(phone, sip.SUBSCRIBE, 2, d.sub, d.res)
			refresh.AppendHeader(sip.NewHeader("Event", tc.event))
			refresh.AppendHeader(sip.NewHeader("Expires", "600"))
			if r := phone.do(t, refresh, h.publicUDP); r.StatusCode != 200 {
				t.Fatalf("refresh: got %d, want 200", r.StatusCode)
			}
			if n := len(fsA.waitFor(sip.SUBSCRIBE, 2, 3*time.Second)); n != 2 {
				t.Errorf("the switch saw %d SUBSCRIBEs, want the refresh as the second", n)
			}
			waitSubs(t, h, 1)

			// Expires: 0 keeps the record for subExpiryMargin so the final
			// NOTIFY still routes; the terminated NOTIFY then frees it.
			unsub := inDialogRequest(phone, sip.SUBSCRIBE, 3, d.sub, d.res)
			unsub.AppendHeader(sip.NewHeader("Event", tc.event))
			unsub.AppendHeader(sip.NewHeader("Expires", "0"))
			if r := phone.do(t, unsub, h.publicUDP); r.StatusCode != 200 {
				t.Fatalf("unsubscribe: got %d, want 200", r.StatusCode)
			}
			if n := h.srv.subs.count(); n != 1 {
				t.Errorf("records after Expires: 0 = %d, want 1 (kept for the final NOTIFY)", n)
			}
			drain(phone.inbound)
			n2 := sendFS(t, fsA, fsSubNotify(t, fsA, d.seen, d.tag, 2, tc.event, "terminated;reason=timeout", "", ""))
			if n2.StatusCode != 200 {
				t.Fatalf("terminated NOTIFY: the switch got %d", n2.StatusCode)
			}
			if waitInbound(phone, sip.NOTIFY, 3*time.Second) == nil {
				t.Error("the client never received the terminated NOTIFY")
			}
			waitSubs(t, h, 0)

			// With the record gone, a further NOTIFY has nowhere to go.
			if r := sendFS(t, fsA, fsSubNotify(t, fsA, d.seen, d.tag, 3, tc.event, "active", "", "")); r.StatusCode != 481 {
				t.Errorf("NOTIFY after the subscription ended: got %d, want 481", r.StatusCode)
			}
		})
	}
}

// A NOTIFY can beat the relayed 2xx; it matches the pending record by the
// subscriber's tag and is delivered.
func TestSubscribeNotifyBeforeResponse(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	drain(phone.inbound)

	notified := make(chan *sip.Response, 1)
	h.fs.setNoRouteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		if req.Method != sip.SUBSCRIBE {
			return false
		}
		// The NOTIFY goes out first; the 2xx follows a beat later.
		go func() {
			n := fsSubNotify(t, h.fs, req, "notifier-tag", 1, "dialog", "active;expires=600", "", "")
			notified <- trySendFS(h.fs, n)
		}()
		time.Sleep(300 * time.Millisecond)
		_ = tx.Respond(subscribeResponse(h.fs, req, "notifier-tag"))
		return true
	})
	d := establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)
	if d.tag != "notifier-tag" {
		t.Errorf("To tag = %q", d.tag)
	}
	if r := <-notified; r == nil || r.StatusCode != 200 {
		t.Errorf("the early NOTIFY was answered %v, want 200", r)
	}
	if waitInbound(phone, sip.NOTIFY, 3*time.Second) == nil {
		t.Error("the client never received the NOTIFY that beat the 2xx")
	}
	// The record is active now: a later NOTIFY still routes.
	if r := sendFS(t, h.fs, fsSubNotify(t, h.fs, d.seen, d.tag, 2, "dialog", "active", "", "")); r.StatusCode != 200 {
		t.Errorf("later NOTIFY: got %d", r.StatusCode)
	}
}

// trySendFS is sendFS for a goroutine: nil on any failure.
func trySendFS(f *fakeSwitch, req *sip.Request) *sip.Response {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		return nil
	}
	defer tx.Terminate()
	for {
		select {
		case res := <-tx.Responses():
			if res != nil && res.StatusCode >= 200 {
				return res
			}
		case <-tx.Done():
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// A failed SUBSCRIBE leaves no record.
func TestSubscribeRefusedLeavesNoRecord(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	h.fs.setNoRouteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		if req.Method != sip.SUBSCRIBE {
			return false
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 489, "Bad Event", nil))
		return true
	})
	if r := phone.do(t, phone.buildSubscribe("1001", "bogus", 600), h.publicUDP); r.StatusCode != 489 {
		t.Fatalf("got %d, want the switch's 489", r.StatusCode)
	}
	waitSubs(t, h, 0)
}

// A SUBSCRIBE from the switch to a client token is delivered to that
// client, and the client's NOTIFYs go back to the switch.
func TestSubscribeFromSwitchToClient(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	drain(phone.inbound)
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.SUBSCRIBE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		res.To().Params.Remove("tag")
		res.To().Params.Add("tag", "phone-tag")
		res.AppendHeader(sip.NewHeader("Expires", "600"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		_ = tx.Respond(res)
	})

	sub := h.fs.callRequest(ruri, h.privateSIP, "")
	sub.Method = sip.SUBSCRIBE
	sub.CSeq().MethodName = sip.SUBSCRIBE
	sub.RemoveHeader("Content-Type")
	sub.AppendHeader(sip.NewHeader("Event", "presence"))
	sub.AppendHeader(sip.NewHeader("Expires", "600"))
	res := sendFS(t, h.fs, sub)
	if res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE from the switch: got %d, want the client's 200", res.StatusCode)
	}
	if c := res.Contact(); c == nil || c.Address.Port != portOf(h.privateSIP) {
		t.Errorf("Contact toward the switch = %v, want FreeSBC's private socket", c)
	}
	got := waitInbound(phone, sip.SUBSCRIBE, 3*time.Second)
	if got == nil {
		t.Fatal("the client never received the SUBSCRIBE")
	}
	if strings.Contains(got.Recipient.String(), contactTokenParam+"=") {
		t.Errorf("binding token leaked to the client: %s", got.Recipient.String())
	}
	if c := got.Contact(); c == nil || c.Address.Port != portOf(h.publicUDP) {
		t.Errorf("Contact at the client = %v, want FreeSBC's public socket", c)
	}
	waitSubs(t, h, 1)

	// The client notifies back along the Record-Route set it received.
	notify := func(seq uint32, state string) *sip.Request {
		target, _ := fsip.ContactURI(got)
		req := sip.NewRequest(sip.NOTIFY, target)
		from := &sip.FromHeader{Address: got.To().Address, Params: sip.NewParams()}
		from.Params.Add("tag", "phone-tag")
		req.AppendHeader(from)
		to := &sip.ToHeader{Address: got.From().Address, Params: sip.NewParams()}
		to.Params.Add("tag", fsip.FromTag(got))
		req.AppendHeader(to)
		cid := sip.CallIDHeader(fsip.CallID(got))
		req.AppendHeader(&cid)
		req.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: sip.NOTIFY})
		mf := sip.MaxForwardsHeader(70)
		req.AppendHeader(&mf)
		req.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		req.AppendHeader(sip.NewHeader("Event", "presence"))
		req.AppendHeader(sip.NewHeader("Subscription-State", state))
		for _, rr := range got.GetHeaders("Record-Route") {
			if r, ok := rr.(*sip.RecordRouteHeader); ok {
				req.AppendHeader(&sip.RouteHeader{Address: r.Address})
			}
		}
		via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
		via.Params.Add("branch", sip.GenerateBranchN(16))
		via.Params.Add("rport", "")
		req.PrependHeader(via)
		return req
	}
	if r := phone.do(t, notify(1, "active;expires=600"), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("client NOTIFY: got %d, want the switch's 200", r.StatusCode)
	}
	seen := h.fs.waitFor(sip.NOTIFY, 1, 3*time.Second)
	if len(seen) != 1 {
		t.Fatalf("the switch saw %d NOTIFYs, want 1", len(seen))
	}
	if seen[0].Recipient.Port != portOf(h.fs.addr) {
		t.Errorf("NOTIFY Request-URI at the switch = %s, want the switch's own Contact", seen[0].Recipient.String())
	}
	if fsip.CallID(seen[0]) != fsip.CallID(sub) {
		t.Errorf("NOTIFY Call-ID = %q, want the SUBSCRIBE's", fsip.CallID(seen[0]))
	}
	if r := phone.do(t, notify(2, "terminated;reason=timeout"), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("terminated NOTIFY: got %d", r.StatusCode)
	}
	waitSubs(t, h, 0)

	// A token nobody holds, and a carrier Request-URI, are refused.
	unknown := sip.Uri{User: "9999", Host: "127.0.0.1", Port: portOf(h.privateSIP), UriParams: sip.NewParams()}
	unknown.UriParams.Add(contactTokenParam, "no-such-token")
	bad := h.fs.callRequest(unknown, h.privateSIP, "")
	bad.Method = sip.SUBSCRIBE
	bad.CSeq().MethodName = sip.SUBSCRIBE
	bad.AppendHeader(sip.NewHeader("Event", "presence"))
	if r := sendFS(t, h.fs, bad); r.StatusCode != 404 {
		t.Errorf("SUBSCRIBE to an unknown token: got %d, want 404", r.StatusCode)
	}
}

// Over a WebSocket: the same dialog, and closing the socket frees the
// records with the registration.
func TestSubscribeOverWebSocket(t *testing.T) {
	h := startHarnessStrict(t, true, false)
	subscribeAccepted(h.fs, "notifier-tag")
	browser := newWSClient(t)
	holdConnection(t, browser, h.publicWS)
	registerOver(t, h, browser, h.publicWS, "1001")
	drain(browser.inbound)

	d := establish(t, browser, h.fs, h.publicWS, "1001", "dialog", 600)
	if c := d.seen.Contact(); c == nil || c.Address.Port != portOf(h.privateSIP) {
		t.Errorf("Contact toward the switch = %v", c)
	}
	waitSubs(t, h, 1)
	if r := sendFS(t, h.fs, fsSubNotify(t, h.fs, d.seen, d.tag, 1, "dialog", "active;expires=600", "", "")); r.StatusCode != 200 {
		t.Fatalf("NOTIFY: got %d, want the browser's 200", r.StatusCode)
	}
	if waitInbound(browser, sip.NOTIFY, 3*time.Second) == nil {
		t.Fatal("the browser never received the NOTIFY")
	}

	browser.cancel() // closes the WebSocket
	waitSubs(t, h, 0)
	if n := h.srv.loc.Count(); n != 0 {
		t.Errorf("bindings left after the socket closed: %d", n)
	}
}

func TestSubscribeAdmission(t *testing.T) {
	t.Run("unregistered source is dropped silently and counted", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		stranger := newUDPClient(t)
		expectSilence(t, stranger, stranger.buildSubscribe("1001", "dialog", 600), h.publicUDP)
		if n := admissionDrops(h, dropSubscribeNotAdmitted); n < 1 {
			t.Errorf("subscribe_not_admitted drops = %d, want at least 1", n)
		}
		if n := len(h.fs.received(sip.SUBSCRIBE)); n != 0 {
			t.Errorf("the switch saw %d SUBSCRIBEs from an unregistered source", n)
		}
		waitSubs(t, h, 0)
	})
	t.Run("carrier source is 405", func(t *testing.T) {
		h := startHarness(t, false) // 127.0.0.1 is a carrier source
		carrier := newUDPClient(t)
		if r := carrier.do(t, carrier.buildSubscribe("+442071234567", "dialog", 600), h.publicUDP); r.StatusCode != 405 {
			t.Errorf("got %d, want 405", r.StatusCode)
		}
		if n := len(h.fs.received(sip.SUBSCRIBE)); n != 0 {
			t.Errorf("the switch saw %d SUBSCRIBEs from a carrier", n)
		}
	})
	t.Run("no Event header is 489", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		req := phone.buildSubscribe("1001", "dialog", 600)
		req.RemoveHeader("Event")
		if r := phone.do(t, req, h.publicUDP); r.StatusCode != 489 {
			t.Errorf("got %d, want 489", r.StatusCode)
		}
	})
}

// A public NOTIFY or SUBSCRIBE that matches no subscription is 481 and
// never reaches the switch; a subscription's tags are only good from the
// plane that owns them.
func TestSubscribeStrayRequestsAre481(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	subscribeAccepted(h.fs, "notifier-tag")
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	d := establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)

	before := len(h.fs.received(sip.NOTIFY))
	// The client forging the notifier's side of its own subscription.
	forged := fsSubNotify(t, h.fs, d.seen, d.tag, 1, "dialog", "active", "", "")
	forged.Laddr = sip.Addr{}
	forged.Recipient = sip.Uri{Host: hostOf(h.publicUDP), Port: portOf(h.publicUDP)}
	forged.RemoveHeader("Route")
	if r := phone.do(t, forged, h.publicUDP); r.StatusCode != 481 {
		t.Errorf("NOTIFY with the notifier's tags from the public plane: got %d, want 481", r.StatusCode)
	}
	// Made-up tags.
	fake := fsSubNotify(t, h.fs, d.seen, "made-up", 2, "dialog", "active", "", "")
	fake.Laddr = sip.Addr{}
	fake.Recipient = sip.Uri{Host: hostOf(h.publicUDP), Port: portOf(h.publicUDP)}
	fake.RemoveHeader("Route")
	if r := phone.do(t, fake, h.publicUDP); r.StatusCode != 481 {
		t.Errorf("NOTIFY with made-up tags: got %d, want 481", r.StatusCode)
	}
	// A refresh that names no subscription.
	refresh := inDialogRequest(phone, sip.SUBSCRIBE, 2, d.sub, d.res)
	refresh.To().Params.Remove("tag")
	refresh.To().Params.Add("tag", "made-up")
	refresh.AppendHeader(sip.NewHeader("Event", "dialog"))
	if r := phone.do(t, refresh, h.publicUDP); r.StatusCode != 481 {
		t.Errorf("SUBSCRIBE refresh with made-up tags: got %d, want 481", r.StatusCode)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(h.fs.received(sip.NOTIFY)); n != before {
		t.Errorf("a stray NOTIFY reached the switch (%d, was %d)", n, before)
	}
	if n := len(h.fs.received(sip.SUBSCRIBE)); n != 1 {
		t.Errorf("the switch saw %d SUBSCRIBEs, want only the original", n)
	}
	waitSubs(t, h, 1)
}

// A binding that leaves the table takes its subscriptions with it:
// un-REGISTER, expiry (Prune) and the per-binding sweep.
func TestSubscribeRecordsFollowTheBinding(t *testing.T) {
	t.Run("unregister", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		subscribeAccepted(h.fs, "notifier-tag")
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)
		establish(t, phone, h.fs, h.publicUDP, "1001", "message-summary", 600)
		waitSubs(t, h, 2)
		if r := phone.do(t, phone.buildRegister("1001", "example.com", 0, ""), h.publicUDP); r.StatusCode != 200 {
			t.Fatalf("un-REGISTER: %d", r.StatusCode)
		}
		waitSubs(t, h, 0)
	})
	t.Run("expiry is pruned", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		subscribeAccepted(h.fs, "notifier-tag")
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)
		waitSubs(t, h, 1)
		h.srv.loc.mu.Lock()
		for _, b := range h.srv.loc.byToken {
			b.ExpiresAt = time.Now().Add(-time.Second)
		}
		h.srv.loc.mu.Unlock()
		h.srv.loc.Prune()
		waitSubs(t, h, 0)
	})
}

// The record's own deadline: granted expiry plus subExpiryMargin, and
// Expires: 0 leaves the margin alone.
func TestSubTableDeadlines(t *testing.T) {
	tab := newSubTable(NewMetrics())
	now := time.Now()
	sub, res := tab.begin("c1", "st", "dialog", "tok", planePublic, dialogRoute{}, now)
	if res != subBeginOK {
		t.Fatalf("begin = %v", res)
	}
	if !tab.confirm(sub, "nt", sip.Uri{}, planePrivate, 600*time.Second, now) {
		t.Fatal("confirm failed")
	}
	if n := tab.prune(now.Add(600 * time.Second)); n != 0 {
		t.Errorf("pruned %d records at the granted expiry, want 0 (margin)", n)
	}
	tab.refresh(sub, 0, now)
	if n := tab.prune(now.Add(subExpiryMargin - time.Second)); n != 0 {
		t.Errorf("pruned %d records inside the margin", n)
	}
	if n := tab.prune(now.Add(subExpiryMargin)); n != 1 {
		t.Errorf("pruned %d records after the margin, want 1", n)
	}
	if tab.count() != 0 {
		t.Errorf("count = %d", tab.count())
	}
}

// setSubCaps lowers the subscription caps (0 leaves one alone).
func setSubCaps(h *harness, max, maxPer int) {
	h.srv.subs.mu.Lock()
	defer h.srv.subs.mu.Unlock()
	if max > 0 {
		h.srv.subs.max = max
	}
	if maxPer > 0 {
		h.srv.subs.maxPer = maxPer
	}
}

// The caps answer 503 with Retry-After, log instead of counting an
// admission drop, and leave the table as it was.
func TestSubscribeCaps(t *testing.T) {
	check := func(t *testing.T, h *harness, phone *client, label string) {
		t.Helper()
		r := phone.do(t, phone.buildSubscribe("1001", "dialog", 600), h.publicUDP)
		if r.StatusCode != 503 {
			t.Fatalf("%s: got %d, want 503", label, r.StatusCode)
		}
		if ra := r.GetHeader("Retry-After"); ra == nil || ra.Value() != fmt.Sprint(subCapRetryAfter) {
			t.Errorf("%s: Retry-After = %v, want %d", label, ra, subCapRetryAfter)
		}
	}
	t.Run("per binding", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		subscribeAccepted(h.fs, "notifier-tag")
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		setSubCaps(h, 0, 2)
		establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)
		establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)
		check(t, h, phone, "third subscription on one binding")
		waitSubs(t, h, 2)
		if n := len(h.fs.received(sip.SUBSCRIBE)); n != 2 {
			t.Errorf("the switch saw %d SUBSCRIBEs, want 2", n)
		}
		for r, n := range h.srv.metrics.Snapshot().AdmissionDrops {
			if n != 0 {
				t.Errorf("admission drop %s = %d; a cap reject is not a silent drop", r, n)
			}
		}
	})
	t.Run("global", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		subscribeAccepted(h.fs, "notifier-tag")
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		setSubCaps(h, 1, 0)
		establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)
		check(t, h, phone, "subscription over the table cap")
		waitSubs(t, h, 1)
	})
}

// Nothing outlives the proxy: records are closed at shutdown and no
// goroutine of ours is left behind.
func TestSubscribeShutdownLeaksNothing(t *testing.T) {
	baseline, _ := auditOwnedGoroutines()
	h := startHarnessStrict(t, false, false)
	subscribeAccepted(h.fs, "notifier-tag")
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	d := establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)
	sendFS(t, h.fs, fsSubNotify(t, h.fs, d.seen, d.tag, 1, "dialog", "active", "", ""))
	waitSubs(t, h, 1)
	h.stop()
	if n := h.srv.subs.count(); n != 0 {
		t.Errorf("records after stop = %d", n)
	}
	if s := h.srv.metrics.Snapshot().ActiveSubscriptions; s != 0 {
		t.Errorf("gauge after stop = %d", s)
	}
	if _, res := h.srv.subs.begin("late", "t", "dialog", "tok", planePublic, dialogRoute{}, time.Now()); res != subBeginClosed {
		t.Errorf("begin after stop = %v, want closed", res)
	}
	auditWaitOwnedGoroutines(t, "after stop", baseline, 5*time.Second)
}

// A public end that moves (NAT remap) is still reached. Public subscriber:
// its next in-subscription request from the new source moves the record.
// Switch-initiated (the client is the notifier and sends nothing): the
// binding, refreshed by a re-REGISTER from the new source, is followed.
func TestSubscribeFollowsPublicRemap(t *testing.T) {
	t.Run("public subscriber refreshes from a new source", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		subscribeAccepted(h.fs, "notifier-tag")
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		d := establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)

		moved := newUDPClient(t)
		refresh := inDialogRequest(phone, sip.SUBSCRIBE, 2, d.sub, d.res)
		refresh.AppendHeader(sip.NewHeader("Event", "dialog"))
		refresh.AppendHeader(sip.NewHeader("Expires", "600"))
		if r := moved.do(t, refresh, h.publicUDP); r.StatusCode != 200 {
			t.Fatalf("refresh from the new source: got %d, want 200", r.StatusCode)
		}
		drain(phone.inbound)
		if r := sendFS(t, h.fs, fsSubNotify(t, h.fs, d.seen, d.tag, 1, "dialog", "active;expires=600", "", "")); r.StatusCode != 200 {
			t.Fatalf("NOTIFY: got %d, want 200", r.StatusCode)
		}
		if waitInbound(moved, sip.NOTIFY, 3*time.Second) == nil {
			t.Error("the NOTIFY did not reach the subscriber's new source")
		}
		if waitInbound(phone, sip.NOTIFY, 300*time.Millisecond) != nil {
			t.Error("the NOTIFY still went to the old source")
		}
	})
	t.Run("switch-initiated follows the binding", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		phone := newUDPClient(t)
		ruri := auditRegisterPhone(t, h, phone, "1001")
		drain(phone.inbound)
		phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
			res := sip.NewResponseFromRequest(req, 200, "OK", nil)
			if fsip.ToTag(req) == "" {
				res.To().Params.Remove("tag")
				res.To().Params.Add("tag", "phone-tag")
			}
			res.AppendHeader(sip.NewHeader("Expires", "600"))
			res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
			_ = tx.Respond(res)
		})
		sub := h.fs.callRequest(ruri, h.privateSIP, "")
		sub.Method = sip.SUBSCRIBE
		sub.CSeq().MethodName = sip.SUBSCRIBE
		sub.RemoveHeader("Content-Type")
		sub.AppendHeader(sip.NewHeader("Event", "presence"))
		sub.AppendHeader(sip.NewHeader("Expires", "600"))
		res := sendFS(t, h.fs, sub)
		if res.StatusCode != 200 {
			t.Fatalf("SUBSCRIBE from the switch: got %d", res.StatusCode)
		}
		waitSubs(t, h, 1)

		// The client re-registers from a new socket (same AoR and
		// Call-ID, so the binding and its token are kept).
		moved := newUDPClient(t)
		if r := moved.do(t, moved.buildRegister("1001", "example.com", 600, ""), h.publicUDP); r.StatusCode != 200 {
			t.Fatalf("re-REGISTER from the new source: got %d", r.StatusCode)
		}
		drain(phone.inbound)

		// The switch refreshes the subscription; the client must be
		// reached at the new source.
		refresh := h.fs.callRequest(ruri, h.privateSIP, "")
		refresh.Method = sip.SUBSCRIBE
		refresh.CSeq().MethodName = sip.SUBSCRIBE
		refresh.CSeq().SeqNo = 2
		refresh.RemoveHeader("Content-Type")
		refresh.ReplaceHeader(sip.HeaderClone(sub.From()))
		to := sip.HeaderClone(sub.To()).(*sip.ToHeader)
		to.Params.Remove("tag")
		to.Params.Add("tag", "phone-tag")
		refresh.ReplaceHeader(to)
		cid := *sub.CallID()
		refresh.ReplaceHeader(&cid)
		refresh.AppendHeader(sip.NewHeader("Event", "presence"))
		refresh.AppendHeader(sip.NewHeader("Expires", "600"))
		if r := sendFS(t, h.fs, refresh); r.StatusCode != 200 {
			t.Fatalf("refresh from the switch: got %d, want 200", r.StatusCode)
		}
		if waitInbound(moved, sip.SUBSCRIBE, 3*time.Second) == nil {
			t.Error("the refresh did not reach the client's new source")
		}
		if waitInbound(phone, sip.SUBSCRIBE, 300*time.Millisecond) != nil {
			t.Error("the refresh still went to the old source")
		}
	})
}

// A binding that leaves the table between admission and the record's
// insertion must not leave a record behind: 480 to a public subscriber.
func TestSubscribeBindingGoneAfterBegin(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	subscribeAccepted(h.fs, "notifier-tag")
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	hook := func() { h.srv.loc.Remove("1001@example.com", "reg-1001-udp") }
	h.srv.afterSubBegin.Store(&hook)

	res := phone.do(t, phone.buildSubscribe("1001", "dialog", 600), h.publicUDP)
	if res.StatusCode != 480 {
		t.Fatalf("SUBSCRIBE whose binding vanished: got %d, want 480", res.StatusCode)
	}
	waitSubs(t, h, 0)
	if n := len(h.fs.received(sip.SUBSCRIBE)); n != 0 {
		t.Errorf("the switch saw %d SUBSCRIBEs, want none", n)
	}
}

// A NOTIFY only comes from the notifier and a SUBSCRIBE only from the
// subscriber; the wrong end gets 481 and nothing is forwarded.
func TestSubscribeWrongDirectionIs481(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	subscribeAccepted(h.fs, "notifier-tag")
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	d := establish(t, phone, h.fs, h.publicUDP, "1001", "dialog", 600)

	// The subscriber sending a NOTIFY into its own subscription.
	n := inDialogRequest(phone, sip.NOTIFY, 2, d.sub, d.res)
	n.AppendHeader(sip.NewHeader("Event", "dialog"))
	n.AppendHeader(sip.NewHeader("Subscription-State", "active"))
	if r := phone.do(t, n, h.publicUDP); r.StatusCode != 481 {
		t.Errorf("NOTIFY from the subscriber: got %d, want 481", r.StatusCode)
	}
	// The notifier refreshing the subscription.
	s := fsSubNotify(t, h.fs, d.seen, d.tag, 3, "dialog", "active", "", "")
	s.Method = sip.SUBSCRIBE
	s.CSeq().MethodName = sip.SUBSCRIBE
	s.RemoveHeader("Subscription-State")
	if r := sendFS(t, h.fs, s); r.StatusCode != 481 {
		t.Errorf("SUBSCRIBE from the notifier: got %d, want 481", r.StatusCode)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(h.fs.received(sip.NOTIFY)); n != 0 {
		t.Errorf("the switch saw %d NOTIFYs, want none", n)
	}
	if n := len(h.fs.received(sip.SUBSCRIBE)); n != 1 {
		t.Errorf("the switch saw %d SUBSCRIBEs, want only the original", n)
	}
	waitSubs(t, h, 1)
}
