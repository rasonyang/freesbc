package edge

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// withCallID replaces a REGISTER's Call-ID, so one AoR can hold several
// bindings the way two devices of one user do.
func withCallID(req *sip.Request, id string) *sip.Request {
	req.RemoveHeader("Call-ID")
	cid := sip.CallIDHeader(id)
	req.AppendHeader(&cid)
	return req
}

// audit: P2-EDG-028
// "Contact: *" with Expires: 0 removes every binding of the AoR (RFC 3261
// §10.2.2), not just the one sharing the un-REGISTER's Call-ID: FreeSBC
// forwards the wildcard unchanged, drops every local binding of the AoR,
// and relays the 200 with no Contact (the upstream ones are FreeSBC's
// private addresses).
func TestWildcardUnregisterRemovesAllBindings(t *testing.T) {
	h := startHarness(t, false)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	desk, mobile := newUDPClient(t), newUDPClient(t)

	for _, reg := range []struct {
		c  *client
		id string
	}{{desk, "reg-desk"}, {mobile, "reg-mobile"}} {
		if res := reg.c.do(t, withCallID(reg.c.buildRegister("1001", "example.com", 600, ""), reg.id), h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("REGISTER %s: %d", reg.id, res.StatusCode)
		}
	}
	if n := len(h.srv.loc.ByAOR("1001@example.com")); n != 2 {
		t.Fatalf("bindings for the AoR = %d after two registrations, want 2", n)
	}

	unreg := withCallID(desk.buildRegister("1001", "example.com", 0, ""), "reg-desk")
	unreg.RemoveHeader("Contact")
	unreg.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Wildcard: true}})
	seen := len(h.fs.received(sip.REGISTER))
	res := desk.do(t, unreg, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("wildcard un-REGISTER: %d", res.StatusCode)
	}
	if n := len(h.srv.loc.ByAOR("1001@example.com")); n != 0 {
		t.Errorf("bindings for the AoR = %d after Contact: *, want 0", n)
	}
	regs := h.fs.waitFor(sip.REGISTER, seen+1, 3*time.Second)
	if len(regs) <= seen {
		t.Fatal("the un-REGISTER never reached FreeSWITCH")
	}
	if c := regs[seen].Contact(); c == nil || !c.Address.Wildcard {
		t.Errorf("FreeSWITCH got Contact %v, want *", regs[seen].GetHeader("Contact"))
	}
	if hs := res.GetHeaders("Contact"); len(hs) != 0 {
		t.Errorf("the client's 200 carries Contact %v, want none", hs)
	}
}

// audit: P2-EDG-028
// "*" with a non-zero expires, or alongside another Contact, is refused
// with 400 (RFC 3261 §10.3 step 6) and never reaches the registrar.
func TestWildcardRegisterMisuseRejected(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	seen := len(h.fs.received(sip.REGISTER))

	nonZero := phone.buildRegister("1001", "example.com", 600, "")
	nonZero.RemoveHeader("Contact")
	nonZero.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Wildcard: true}})
	if res := phone.do(t, nonZero, h.publicUDP); res.StatusCode != 400 {
		t.Errorf("Contact: * with Expires: 600 answered %d, want 400", res.StatusCode)
	}

	mixed := phone.buildRegister("1001", "example.com", 0, "")
	mixed.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Wildcard: true}})
	if res := phone.do(t, mixed, h.publicUDP); res.StatusCode != 400 {
		t.Errorf("Contact: * alongside another Contact answered %d, want 400", res.StatusCode)
	}
	if got := h.fs.waitFor(sip.REGISTER, seen+1, 300*time.Millisecond); len(got) > seen {
		t.Errorf("a refused REGISTER reached FreeSWITCH")
	}
}
