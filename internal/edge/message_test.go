package edge

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Tests for MESSAGE through the edge proxy (issue #112): pager-mode instant
// messages go between a registered client and the switch in both
// directions, out of dialog or inside a call, with a 1300-byte body cap.

// buildMessage builds an out-of-dialog MESSAGE from c.
func (c *client) buildMessage(from, to, body string) *sip.Request {
	req := sip.NewRequest(sip.MESSAGE, sip.Uri{User: to, Host: "example.com"})
	f := &sip.FromHeader{Address: sip.Uri{User: from, Host: "example.com"}, Params: sip.NewParams()}
	f.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(f)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: to, Host: "example.com"}, Params: sip.NewParams()})
	callID := sip.CallIDHeader(fmt.Sprintf("msg-%s-%d", c.transport, time.Now().UnixNano()))
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.MESSAGE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(sip.NewHeader("Content-Type", "text/plain"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0",
		Transport: strings.ToUpper(c.transport), Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	if c.transport == "udp" {
		via.Params.Add("rport", "")
	}
	req.PrependHeader(via)
	req.SetBody([]byte(body))
	return req
}

func TestMessageBothDirections(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	drain(phone.inbound)

	// Client to switch.
	res := phone.do(t, phone.buildMessage("1001", "2002", "hello switch"), h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("MESSAGE from the client: got %d, want 200", res.StatusCode)
	}
	seen := h.fs.waitFor(sip.MESSAGE, 1, 3*time.Second)
	if len(seen) != 1 || string(seen[0].Body()) != "hello switch" {
		t.Fatalf("the switch saw %d MESSAGEs, body %q", len(seen), func() []byte {
			if len(seen) > 0 {
				return seen[0].Body()
			}
			return nil
		}())
	}
	if ct := seen[0].GetHeader("Content-Type"); ct == nil || ct.Value() != "text/plain" {
		t.Errorf("Content-Type at the switch = %v", ct)
	}

	// Switch to client, addressed by the client's registered token.
	req := h.fs.callRequest(ruri, h.privateSIP, "hello phone")
	req.Method = sip.MESSAGE
	req.CSeq().MethodName = sip.MESSAGE
	req.RemoveHeader("Content-Type")
	req.AppendHeader(sip.NewHeader("Content-Type", "text/plain"))
	if r := sendFS(t, h.fs, req); r.StatusCode != 200 {
		t.Fatalf("MESSAGE from the switch: got %d, want the client's 200", r.StatusCode)
	}
	got := waitInbound(phone, sip.MESSAGE, 3*time.Second)
	if got == nil {
		t.Fatal("the client never received the MESSAGE")
	}
	if string(got.Body()) != "hello phone" {
		t.Errorf("body at the client = %q", got.Body())
	}
	if strings.Contains(got.Recipient.String(), contactTokenParam+"=") {
		t.Errorf("binding token leaked to the client: %s", got.Recipient.String())
	}

	// A token nobody holds is nobody's.
	unknown := sip.Uri{User: "9999", Host: "127.0.0.1", Port: portOf(h.privateSIP), UriParams: sip.NewParams()}
	unknown.UriParams.Add(contactTokenParam, "no-such-token")
	req = h.fs.callRequest(unknown, h.privateSIP, "x")
	req.Method = sip.MESSAGE
	req.CSeq().MethodName = sip.MESSAGE
	if r := sendFS(t, h.fs, req); r.StatusCode != 404 {
		t.Errorf("MESSAGE to an unknown token: got %d, want 404", r.StatusCode)
	}
}

func TestMessageBodyCap(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")

	if r := phone.do(t, phone.buildMessage("1001", "2002", strings.Repeat("a", maxMessageBody)), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("1300-byte body: got %d, want 200", r.StatusCode)
	}
	if r := phone.do(t, phone.buildMessage("1001", "2002", strings.Repeat("a", maxMessageBody+1)), h.publicUDP); r.StatusCode != 413 {
		t.Errorf("1301-byte body: got %d, want 413", r.StatusCode)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(h.fs.received(sip.MESSAGE)); n != 1 {
		t.Errorf("the switch saw %d MESSAGEs, want only the 1300-byte one", n)
	}
}

func TestMessageAdmission(t *testing.T) {
	t.Run("unregistered source is dropped silently and counted", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		stranger := newUDPClient(t)
		expectSilence(t, stranger, stranger.buildMessage("1001", "2002", "hi"), h.publicUDP)
		if n := admissionDrops(h, dropMessageNotAdmitted); n < 1 {
			t.Errorf("message_not_admitted drops = %d, want at least 1", n)
		}
		if n := len(h.fs.received(sip.MESSAGE)); n != 0 {
			t.Errorf("the switch saw %d MESSAGEs from an unregistered source", n)
		}
	})
	t.Run("carrier source is 405", func(t *testing.T) {
		h := startHarness(t, false) // 127.0.0.1 is a carrier source
		carrier := newUDPClient(t)
		res := carrier.do(t, carrier.buildMessage("+442071234567", "1001", "hi"), h.publicUDP)
		if res.StatusCode != 405 {
			t.Errorf("got %d, want 405", res.StatusCode)
		}
		if n := len(h.fs.received(sip.MESSAGE)); n != 0 {
			t.Errorf("the switch saw %d MESSAGEs from a carrier", n)
		}
	})
}

func TestMessageInDialog(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001") // 127.0.0.1 is also a carrier source
	invite, res, _ := auditPhoneCall(t, h, phone)
	drain(phone.inbound)

	// Client to switch, in the call.
	msg := inDialogRequest(phone, sip.MESSAGE, 2, invite, res)
	msg.AppendHeader(sip.NewHeader("Content-Type", "text/plain"))
	msg.SetBody([]byte("in call"))
	if r := phone.do(t, msg, h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("in-dialog MESSAGE: got %d, want 200", r.StatusCode)
	}
	seen := h.fs.waitFor(sip.MESSAGE, 1, 3*time.Second)
	if len(seen) != 1 || string(seen[0].Body()) != "in call" {
		t.Fatalf("the switch saw %d MESSAGEs", len(seen))
	}

	// Switch to client, in the call.
	fsInvite := h.fs.received(sip.INVITE)[0]
	if r := h.fs.inDialog(t, sip.MESSAGE, fsInvite, toTagOf(res)); r.StatusCode != 200 {
		t.Fatalf("MESSAGE from the switch in the call: got %d, want 200", r.StatusCode)
	}
	if waitInbound(phone, sip.MESSAGE, 3*time.Second) == nil {
		t.Error("the client never received the in-call MESSAGE")
	}

	// Made-up tags name no dialog: 481, never forwarded.
	before := len(h.fs.received(sip.MESSAGE))
	for name, mutate := range map[string]func(*sip.Request){
		"fake To tag":  func(r *sip.Request) { r.To().Params.Remove("tag"); r.To().Params.Add("tag", "fake-tag") },
		"fake Call-ID": func(r *sip.Request) { *r.CallID() = "no-such-call" },
	} {
		req := inDialogRequest(phone, sip.MESSAGE, 3, invite, res)
		mutate(req)
		if r := phone.do(t, req, h.publicUDP); r.StatusCode != 481 {
			t.Errorf("%s: got %d, want 481", name, r.StatusCode)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(h.fs.received(sip.MESSAGE)); n != before {
		t.Errorf("a MESSAGE with made-up tags reached the switch (%d, was %d)", n, before)
	}

	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// A 3xx to a MESSAGE carries the switch's Contact; the client must see
// FreeSBC's public side, out of dialog and in a call.
func TestMessageResponseContactIsRewritten(t *testing.T) {
	redirect := func(f *fakeSwitch) {
		f.setNoRouteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
			if req.Method != sip.MESSAGE {
				return false
			}
			res := sip.NewResponseFromRequest(req, 302, "Moved Temporarily", nil)
			res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "other", Host: "127.0.0.1", Port: portOf(f.addr)}})
			_ = tx.Respond(res)
			return true
		})
	}
	check := func(t *testing.T, h *harness, r *sip.Response) {
		t.Helper()
		if r.StatusCode != 302 {
			t.Fatalf("got %d, want 302", r.StatusCode)
		}
		if c := r.Contact(); c == nil || c.Address.Port != portOf(h.publicUDP) {
			t.Errorf("Contact in the 302 = %v, want FreeSBC's public socket", c)
		}
	}
	t.Run("out of dialog", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		redirect(h.fs)
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		check(t, h, phone.do(t, phone.buildMessage("1001", "2002", "hi"), h.publicUDP))
	})
	t.Run("in dialog", func(t *testing.T) {
		h := startHarness(t, false)
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		invite, res, _ := auditPhoneCall(t, h, phone)
		redirect(h.fs)
		msg := inDialogRequest(phone, sip.MESSAGE, 2, invite, res)
		msg.AppendHeader(sip.NewHeader("Content-Type", "text/plain"))
		msg.SetBody([]byte("in call"))
		check(t, h, phone.do(t, msg, h.publicUDP))
	})
}

// A Content-Length that disagrees with the body never gets the edge to
// relay more than the cap. sipgo's parser decides what the handler sees:
// a Content-Length longer than the datagram or frame is an incomplete
// body and the message is dropped before any handler runs (no response);
// a shorter one truncates the body to that length, which the cap then
// measures. Over UDP and WS alike.
func TestMessageLyingContentLength(t *testing.T) {
	lie := func(req *sip.Request, n int) *sip.Request {
		cl := sip.ContentLengthHeader(n)
		req.ReplaceHeader(&cl)
		return req
	}
	run := func(t *testing.T, ws bool) {
		h := startHarnessStrict(t, ws, false)
		var phone *client
		var dest string
		if ws {
			phone, dest = newWSClient(t), h.publicWS
			holdConnection(t, phone, dest)
			registerOver(t, h, phone, dest, "1001")
		} else {
			phone, dest = newUDPClient(t), h.publicUDP
			auditRegisterPhone(t, h, phone, "1001")
		}
		drain(phone.inbound)

		// Content-Length 5000 over a short body: unparsable, dropped.
		expectSilence(t, phone, lie(phone.buildMessage("1001", "2002", "short"), 5000), dest)
		if n := len(h.fs.received(sip.MESSAGE)); n != 0 {
			t.Errorf("the switch saw %d MESSAGEs after a lying Content-Length", n)
		}
		// Content-Length 100 over a 1400-byte body: the body is cut to 100
		// bytes, within the cap, and that is all the switch gets.
		r := phone.do(t, lie(phone.buildMessage("1001", "2002", strings.Repeat("b", 1400)), 100), dest)
		if r.StatusCode != 200 {
			t.Fatalf("Content-Length 100 over a 1400-byte body: got %d, want 200", r.StatusCode)
		}
		seen := h.fs.waitFor(sip.MESSAGE, 1, 3*time.Second)
		if len(seen) != 1 || len(seen[0].Body()) != 100 {
			t.Errorf("the switch saw %d MESSAGEs, first body length %d, want one of 100 bytes", len(seen), func() int {
				if len(seen) > 0 {
					return len(seen[0].Body())
				}
				return -1
			}())
		}
	}
	t.Run("udp", func(t *testing.T) { run(t, false) })
	t.Run("ws", func(t *testing.T) { run(t, true) })
}
