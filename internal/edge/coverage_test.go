package edge

import (
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Tests for production paths the rest of the suite never reached
// (audit P1-010).

// TestUnhandledMethodGets405WithAllow covers onNoRoute: a method the proxy
// does not handle gets a 405 naming the methods it does, rather than
// silence that would leave the client retransmitting. It also reads the
// counters through Server.Metrics, the accessor app wires into admin.
func TestUnhandledMethodGets405WithAllow(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	req := sip.NewRequest(sip.SUBSCRIBE, sip.Uri{User: "1001", Host: "example.com"})
	from := &sip.FromHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()})
	callID := sip.CallIDHeader("subscribe-405")
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.SUBSCRIBE})
	req.AppendHeader(sip.NewHeader("Event", "presence"))
	req.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})

	res := phone.do(t, req, h.publicUDP)
	if res.StatusCode != 405 {
		t.Fatalf("SUBSCRIBE got %d, want 405", res.StatusCode)
	}
	allow := res.GetHeader("Allow")
	if allow == nil {
		t.Fatal("405 carries no Allow header")
	}
	if got, want := allow.Value(), strings.Join(allowedMethods, ", "); got != want {
		t.Errorf("Allow = %q, want %q", got, want)
	}
	if strings.Contains(allow.Value(), "SUBSCRIBE") {
		t.Error("Allow must not advertise the method that was just refused")
	}
	if got := h.srv.Metrics().Snapshot().ResponsesOut["4xx"]; got < 1 {
		t.Errorf("Metrics().Snapshot().ResponsesOut[4xx] = %d, want the 405 counted", got)
	}
	if len(h.fs.received(sip.SUBSCRIBE)) != 0 {
		t.Error("an unhandled method must not be forwarded to FreeSWITCH")
	}
}

// TestRejectedRegistrationCountsFailure covers Metrics.RegistrationFailed
// on the path where the registrar refuses the AoR: the refusal is relayed
// to the phone untouched and counted once.
func TestRejectedRegistrationCountsFailure(t *testing.T) {
	h := startHarness(t, false)
	h.fs.mu.Lock()
	h.fs.registerStatus = 403
	h.fs.mu.Unlock()
	phone := newUDPClient(t)

	res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicUDP)
	if res.StatusCode != 403 {
		t.Fatalf("REGISTER got %d, want FreeSWITCH's 403 relayed", res.StatusCode)
	}
	snap := h.srv.Metrics().Snapshot()
	if snap.RegistrationFailure != 1 {
		t.Errorf("RegistrationFailure = %d, want 1", snap.RegistrationFailure)
	}
	if snap.RegistrationTotal != 0 || snap.ActiveRegistrations != 0 {
		t.Errorf("a refused REGISTER must not count as registered: total=%d active=%d",
			snap.RegistrationTotal, snap.ActiveRegistrations)
	}
}

// TestPrivateSourcesPrunesExpiredWhenFull covers pruneLocked: a full table
// makes room by dropping expired entries, and refuses a new source only
// when every entry is still live.
func TestPrivateSourcesPrunesExpiredWhenFull(t *testing.T) {
	p := newPrivateSources()
	p.max = 2
	p.ttl = time.Minute

	p.note("10.0.0.1:5060")
	p.note("10.0.0.1:5061")
	p.mu.Lock()
	p.m["10.0.0.1:5060"] = time.Now().Add(-2 * time.Minute) // expired
	p.mu.Unlock()

	p.note("10.0.0.1:5062")
	if p.has("10.0.0.1:5060") {
		t.Error("the expired entry must be pruned to make room")
	}
	if !p.has("10.0.0.1:5061") || !p.has("10.0.0.1:5062") {
		t.Error("live entries and the new source must be present after pruning")
	}

	p.note("10.0.0.1:5063") // full of live entries: refused
	if p.has("10.0.0.1:5063") {
		t.Error("a full table of live entries must refuse a new source, not grow")
	}
	p.mu.RLock()
	n := len(p.m)
	p.mu.RUnlock()
	if n != 2 {
		t.Errorf("table holds %d entries, want its cap of 2", n)
	}
}

// TestListenerDescribe covers the label used in serve errors.
func TestListenerDescribe(t *testing.T) {
	for _, tc := range []struct {
		l    listener
		want string
	}{
		{listener{transport: "udp", addr: "127.0.0.1:5060"}, "udp://127.0.0.1:5060"},
		{listener{transport: "wss", addr: "0.0.0.0:7443"}, "wss://0.0.0.0:7443"},
	} {
		if got := tc.l.Describe(); got != tc.want {
			t.Errorf("Describe() = %q, want %q", got, tc.want)
		}
	}
}
