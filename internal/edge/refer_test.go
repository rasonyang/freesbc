package edge

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Tests for REFER through the edge proxy (issue #112): call transfer is the
// endpoints' business, so a REFER in a call dialog is forwarded unchanged
// (Refer-To, Referred-By and the Replaces of an attended transfer reach the
// other end byte for byte), the 202 and the Event: refer NOTIFYs travel
// back, and a REFER that names no dialog, or a carrier's dialog, is not
// forwarded.

// inDialogRequest turns buildBye's in-dialog request for a call the client
// placed into one of method with CSeq seq.
func inDialogRequest(c *client, method sip.RequestMethod, seq uint32, invite *sip.Request, res *sip.Response) *sip.Request {
	req := buildBye(c, invite, res)
	// buildBye shares the INVITE's From and Call-ID headers; a test that
	// edits them must not edit the INVITE.
	req.ReplaceHeader(sip.HeaderClone(req.From()))
	cid := *req.CallID()
	req.ReplaceHeader(&cid)
	req.Method = method
	req.CSeq().MethodName = method
	req.CSeq().SeqNo = seq
	req.AppendHeader(&sip.ContactHeader{Address: c.contactURI("1001")})
	return req
}

// referAccepted makes the fake switch answer a REFER 202 Accepted.
func referAccepted(f *fakeSwitch) {
	f.setNoRouteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		if req.Method != sip.REFER {
			return false
		}
		res := sip.NewResponseFromRequest(req, 202, "Accepted", nil)
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "mod_sofia", Host: "127.0.0.1", Port: portOf(f.addr)}})
		_ = tx.Respond(res)
		return true
	})
}

// fsReferNotify builds the Event: refer NOTIFY (RFC 3515 §2.4.4) the switch
// sends into the call it received as the UAS, with a sipfrag body.
func fsReferNotify(t *testing.T, f *fakeSwitch, invite *sip.Request, toTag, frag string) *sip.Request {
	t.Helper()
	target, ok := fsip.ContactURI(invite)
	if !ok {
		t.Fatal("the INVITE the switch received carried no Contact")
	}
	from := &sip.FromHeader{Address: invite.To().Address, Params: sip.NewParams()}
	from.Params.Add("tag", toTag)
	to := &sip.ToHeader{Address: invite.From().Address, Params: sip.NewParams()}
	if tag, ok := invite.From().Params.Get("tag"); ok {
		to.Params.Add("tag", tag)
	}
	var route []sip.Uri
	for _, h := range invite.GetHeaders("Record-Route") {
		if rr, ok := h.(*sip.RecordRouteHeader); ok {
			route = append(route, rr.Address)
		}
	}
	req := buildFSNotify(f, target, "", from, to, fsip.CallID(invite), 2, "refer", route)
	req.ReplaceHeader(sip.NewHeader("Subscription-State", "terminated;reason=noresource"))
	req.AppendHeader(sip.NewHeader("Content-Type", "message/sipfrag;version=2.0"))
	req.SetBody([]byte(frag))
	req.SetDestination(f.topRouteDest(t, req))
	return req
}

func TestReferBlindAndAttended(t *testing.T) {
	const attended = "<sip:3003@example.com?Replaces=abc123%40host%3Bto-tag%3Dtt1%3Bfrom-tag%3Dff2>"
	for _, tc := range []struct {
		name, referTo string
	}{
		{"blind", "<sip:3003@example.com>"},
		{"attended", attended},
	} {
		for _, transport := range []string{"udp", "ws"} {
			t.Run(tc.name+"/"+transport, func(t *testing.T) {
				var h *harness
				var c *client
				var invite *sip.Request
				var res *sip.Response
				var send func(req *sip.Request) *sip.Response
				if transport == "udp" {
					h = startHarness(t, false)
					c = newUDPClient(t)
					auditRegisterPhone(t, h, c, "1001") // 127.0.0.1 is also a carrier source
					invite, res, _ = auditPhoneCall(t, h, c)
					send = func(req *sip.Request) *sip.Response { return c.do(t, req, h.publicUDP) }
				} else {
					h = startHarnessStrict(t, true, false)
					c = newWSClient(t)
					holdConnection(t, c, h.publicWS)
					registerOver(t, h, c, h.publicWS, "1001")
					invite = c.buildInvite("1001", "2002", "example.com", browserOfferSDP(51234))
					res = c.do(t, invite, h.publicWS)
					if res.StatusCode != 200 {
						t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
					}
					sendAck(t, c, invite, res, h.publicWS)
					send = func(req *sip.Request) *sip.Response { return c.do(t, req, h.publicWS) }
				}
				referAccepted(h.fs)
				drain(c.inbound)

				refer := inDialogRequest(c, sip.REFER, 2, invite, res)
				refer.AppendHeader(sip.NewHeader("Refer-To", tc.referTo))
				refer.AppendHeader(sip.NewHeader("Referred-By", "<sip:1001@example.com>"))
				got := send(refer)
				if got.StatusCode != 202 {
					t.Fatalf("REFER: got %d, want the switch's 202", got.StatusCode)
				}
				if ct := got.Contact(); ct != nil && ct.Address.Port == portOf(h.fs.addr) {
					t.Errorf("the switch's Contact leaked to the client: %s", ct.Address.String())
				}
				seen := h.fs.waitFor(sip.REFER, 1, 3*time.Second)
				if len(seen) != 1 {
					t.Fatalf("the switch saw %d REFERs, want 1", len(seen))
				}
				if v := seen[0].GetHeader("Refer-To"); v == nil || v.Value() != tc.referTo {
					t.Errorf("Refer-To at the switch = %v, want %q byte for byte", v, tc.referTo)
				}
				if v := seen[0].GetHeader("Referred-By"); v == nil || v.Value() != "<sip:1001@example.com>" {
					t.Errorf("Referred-By at the switch = %v", v)
				}
				if c := seen[0].Contact(); c == nil || c.Address.Port != portOf(h.privateSIP) {
					t.Errorf("Contact toward the switch = %v, want FreeSBC's private socket", c)
				}

				// The switch reports the transfer's progress with an
				// Event: refer NOTIFY, which the client answers.
				nres := sendFS(t, h.fs, fsReferNotify(t, h.fs, h.fs.received(sip.INVITE)[0], toTagOf(res), "SIP/2.0 200 OK\r\n"))
				if nres.StatusCode != 200 {
					t.Fatalf("refer NOTIFY: the switch got %d, want the client's 200", nres.StatusCode)
				}
				n := waitInbound(c, sip.NOTIFY, 3*time.Second)
				if n == nil {
					t.Fatal("the client never received the refer NOTIFY")
				}
				if ev := n.GetHeader("Event"); ev == nil || ev.Value() != "refer" {
					t.Errorf("client NOTIFY Event = %v, want refer", ev)
				}
				if string(n.Body()) != "SIP/2.0 200 OK\r\n" {
					t.Errorf("sipfrag body = %q", n.Body())
				}

				if r := send(buildBye(c, invite, res)); r.StatusCode != 200 {
					t.Errorf("BYE: got %d", r.StatusCode)
				}
				waitForRelease(t, h)
			})
		}
	}
}

// toTagOf is the To tag of a response.
func toTagOf(res *sip.Response) string {
	tag, _ := res.To().Params.Get("tag")
	return tag
}

// A REFER on a carrier dialog is declined 603 and never forwarded, from
// either end.
func TestReferOnCarrierDialogDeclined(t *testing.T) {
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

	// From the carrier.
	if r := o.carrier.inDialog(t, sip.REFER, invs[0], tag); r.StatusCode != 603 {
		t.Errorf("REFER from the carrier: got %d, want 603", r.StatusCode)
	}
	// From the switch.
	req := fsNotifyInConfirmed(t, o.fs, res, "refer")
	req.Method = sip.REFER
	req.CSeq().MethodName = sip.REFER
	req.AppendHeader(sip.NewHeader("Refer-To", "<sip:3003@example.com>"))
	if r := sendFS(t, o.fs, req); r.StatusCode != 603 {
		t.Errorf("REFER from the switch: got %d, want 603", r.StatusCode)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(o.fs.received(sip.REFER)) + len(o.carrier.received(sip.REFER)); n != 0 {
		t.Errorf("%d REFERs were forwarded on a carrier dialog", n)
	}

	if r := o.carrier.inDialog(t, sip.BYE, invs[0], tag); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, o.harness)
}

// A REFER with no To tag, or whose tags name no dialog, is answered 481 and
// never reaches the switch; so is one from the switch.
func TestReferWithoutDialogIs481(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001") // 127.0.0.1 is also a carrier source
	invite, res, _ := auditPhoneCall(t, h, phone)

	refer := func(mutate func(*sip.Request)) *sip.Request {
		req := inDialogRequest(phone, sip.REFER, 2, invite, res)
		req.AppendHeader(sip.NewHeader("Refer-To", "<sip:3003@example.com>"))
		mutate(req)
		return req
	}
	cases := map[string]func(*sip.Request){
		"no To tag":    func(r *sip.Request) { r.To().Params.Remove("tag") },
		"fake To tag":  func(r *sip.Request) { r.To().Params.Remove("tag"); r.To().Params.Add("tag", "fake-tag") },
		"fake Call-ID": func(r *sip.Request) { *r.CallID() = "no-such-call" },
		"fake both": func(r *sip.Request) {
			*r.CallID() = "no-such-call"
			r.To().Params.Remove("tag")
			r.To().Params.Add("tag", "fake-tag")
		},
		"wrong From tag": func(r *sip.Request) { r.From().Params.Add("tag", "other-from-tag") },
	}
	for name, mutate := range cases {
		req := refer(mutate)
		if got := phone.do(t, req, h.publicUDP); got.StatusCode != 481 {
			t.Errorf("%s: got %d, want 481", name, got.StatusCode)
		}
	}

	// From the switch: no To tag, to a client token.
	to := &sip.ToHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
	from := &sip.FromHeader{Address: sip.Uri{User: "3003", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(12))
	req := buildFSNotify(h.fs, ruri, h.privateSIP, from, to, "fs-refer-no-dialog", 1, "refer", nil)
	req.Method = sip.REFER
	req.CSeq().MethodName = sip.REFER
	if got := sendFS(t, h.fs, req); got.StatusCode != 481 {
		t.Errorf("REFER from the switch with no To tag: got %d, want 481", got.StatusCode)
	}

	time.Sleep(200 * time.Millisecond)
	if n := len(h.fs.received(sip.REFER)); n != 0 {
		t.Errorf("the switch saw %d REFERs, want none", n)
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}
