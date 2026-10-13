package edge

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Drain (maintenance) mode (issues #123, #149): while draining, a new
// carrier call (carrier to switch, switch to carrier) is refused 503 +
// Retry-After 30 before a slot, a rate token or a media port is taken, and
// so is an out-of-dialog OPTIONS from a carrier source or from the switch to
// FreeSBC or a carrier host. Client calls in both directions are admitted.
// Everything that belongs to a call or registration already in place is
// unchanged. Runtime state only.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// assertNothingAllocated checks that a refused INVITE left no dialog, no
// session slot and no media port.
func assertNothingAllocated(t *testing.T, h *harness) {
	t.Helper()
	if n := auditDialogEntries(h); n != 0 {
		t.Errorf("dialog table holds %d records, want 0", n)
	}
	if n := h.srv.dialogs.sessionCount(); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
	if n := portsInUse(h); n != 0 {
		t.Errorf("media ports in use = %d, want 0", n)
	}
}

// The state machine: idempotent, keeps the original since, drives the gauge,
// and a fresh server starts not draining.
func TestDrainState(t *testing.T) {
	h := startHarness(t, false)
	if on, since := h.srv.DrainState(); on || !since.IsZero() {
		t.Fatalf("fresh server: draining=%v since=%v", on, since)
	}
	if h.srv.metrics.Snapshot().Draining {
		t.Fatal("gauge is set on a fresh server")
	}
	if h.srv.SetDraining(false) {
		t.Error("leaving drain while not draining reported a change")
	}
	if !h.srv.SetDraining(true) {
		t.Fatal("entering drain reported no change")
	}
	on, since := h.srv.DrainState()
	if !on || since.IsZero() || time.Since(since) > time.Minute {
		t.Fatalf("after enter: draining=%v since=%v", on, since)
	}
	if !h.srv.metrics.Snapshot().Draining {
		t.Error("gauge not set while draining")
	}
	time.Sleep(5 * time.Millisecond)
	if h.srv.SetDraining(true) {
		t.Error("entering drain twice reported a change")
	}
	if _, again := h.srv.DrainState(); !again.Equal(since) {
		t.Errorf("since moved from %v to %v on a repeated enter", since, again)
	}
	if !h.srv.SetDraining(false) {
		t.Error("leaving drain reported no change")
	}
	if on, since := h.srv.DrainState(); on || !since.IsZero() {
		t.Errorf("after leave: draining=%v since=%v", on, since)
	}
	if h.srv.metrics.Snapshot().Draining {
		t.Error("gauge still set after leaving drain")
	}
}

// SetDraining is safe under concurrent use (run with -race).
func TestDrainConcurrent(t *testing.T) {
	h := startHarness(t, false)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.srv.SetDraining((i+j)%2 == 0)
				h.srv.DrainState()
			}
		}(i)
	}
	wg.Wait()
}

// A registered client's new INVITE is admitted while draining.
func TestDrainClientToSwitch(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	h.srv.SetDraining(true)

	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Errorf("client call while draining: %d, want 200", code)
	}
	if got := h.fs.received(sip.INVITE); len(got) != 1 {
		t.Errorf("the switch saw %d INVITEs while draining, want 1", len(got))
	}
	assertRejects(t, h, nil)
}

// An unknown public source keeps the silent drop: admission runs before
// the drain check.
func TestDrainUnknownSourceStaysSilent(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	h.srv.SetDraining(true)
	other := newUDPClient(t)
	expectSilence(t, other, other.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30502)), h.publicUDP)
	assertRejects(t, h, nil)
	if n := admissionDrops(h, dropInviteNotAdmitted); n == 0 {
		t.Error("the unknown source's INVITE was not counted as an admission drop")
	}
}

// The switch's call to a registered client is admitted while draining.
func TestDrainSwitchToClient(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	rtp := auditUDP(t)
	var offered atomic.Int32
	auditPhoneAnswers(phone, auditUDPPort(rtp), func(*sip.Request) string {
		offered.Add(1)
		return phoneOfferSDP(auditUDPPort(rtp))
	})
	h.srv.SetDraining(true)

	if r := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)); r.StatusCode != 200 {
		t.Errorf("call to a client while draining: %d, want 200", r.StatusCode)
	}
	if n := offered.Load(); n != 1 {
		t.Errorf("the client saw %d INVITEs while draining, want 1", n)
	}
	assertRejects(t, h, nil)
}

// The switch's call out through a carrier is refused.
func TestDrainSwitchToCarrier(t *testing.T) {
	o := startOutboundRig(t)
	answerWithTag(o.carrier)
	o.srv.SetDraining(true)

	assertBusy(t, o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort)), "30")
	if got := o.carrier.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the carrier saw %d INVITEs while draining", len(got))
	}
	assertNothingAllocated(t, o.harness)
	assertRejects(t, o.harness, map[inviteReject]uint64{rejectDraining: 1})

	o.srv.SetDraining(false)
	if r := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort)); r.StatusCode != 200 {
		t.Errorf("call after leaving drain: %d, want 200", r.StatusCode)
	}
}

// A carrier delivering a call is refused 503 so it can fail over.
func TestDrainCarrierToSwitch(t *testing.T) {
	carrier := newUDPClient(t)
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(carrier.local)), "", nil)
	rig.cs.setInviteHook(auditTaggedAnswerHook(rig.cs, nil, nil))
	rig.srv.SetDraining(true)

	assertBusy(t, carrier.do(t, carrier.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(30500)), rig.publicUDP), "30")
	if got := rig.cs.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the switch saw %d INVITEs while draining", len(got))
	}
	assertNothingAllocated(t, rig.harness)
	assertRejects(t, rig.harness, map[inviteReject]uint64{rejectDraining: 1})

	rig.srv.SetDraining(false)
	if r := carrier.do(t, carrier.buildInvite("+442071234568", "+15551230001", "example.com", phoneOfferSDP(30502)), rig.publicUDP); r.StatusCode != 200 {
		t.Errorf("call after leaving drain: %d, want 200", r.StatusCode)
	}
}

// An established call survives entering drain: RTP flows, a re-INVITE is
// answered, REGISTER still reaches the switch, and BYE tears it down.
func TestDrainEstablishedCallSurvives(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	fsRTP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: h.fs.rtpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer fsRTP.Close()
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("switch saw %d ACKs", len(acks))
	}
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answer.Audio.Port}

	h.srv.SetDraining(true)

	if !relayReaches(t, phoneRTP, sbcPublic, fsRTP, rtpPacket(0, 100, 160)) {
		t.Error("RTP stopped flowing after entering drain")
	}
	_, re := auditPhoneReInvite(t, h, phone, invite, res, 2, phoneOfferSDP(auditUDPPort(phoneRTP)))
	if re.StatusCode != 200 {
		t.Errorf("re-INVITE while draining: %d, want 200", re.StatusCode)
	}
	before := len(h.fs.received(sip.REGISTER))
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicUDP); res.StatusCode != 200 {
		t.Errorf("REGISTER while draining: %d, want 200", res.StatusCode)
	}
	if got := len(h.fs.received(sip.REGISTER)); got <= before {
		t.Errorf("REGISTER did not reach the switch while draining (%d -> %d)", before, got)
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE while draining: %d, want 200", r.StatusCode)
	}
	waitForRelease(t, h)
	assertRejects(t, h, nil)
	if on, _ := h.srv.DrainState(); !on {
		t.Error("the last call ending left drain mode (there is no auto-exit)")
	}
}

// buildOptions is an out-of-dialog OPTIONS from c to example.com.
func buildOptions(c *client, callID string) *sip.Request {
	req := sip.NewRequest(sip.OPTIONS, sip.Uri{Host: "example.com"})
	from := &sip.FromHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{Host: "example.com"}, Params: sip.NewParams()})
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(&cid)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.OPTIONS})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	return req
}

// While draining, an OPTIONS from a carrier source is 503 + Retry-After 30;
// leaving drain restores the 200. It is not an INVITE reject.
func TestDrainCarrierOptions(t *testing.T) {
	carrier := newUDPClient(t)
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(carrier.local)), "", nil)
	rig.srv.SetDraining(true)

	assertBusy(t, carrier.do(t, buildOptions(carrier, "drain-opt-c1"), rig.publicUDP), "30")
	assertRejects(t, rig.harness, nil)
	rig.srv.SetDraining(false)
	if r := carrier.do(t, buildOptions(carrier, "drain-opt-c2"), rig.publicUDP); r.StatusCode != 200 {
		t.Errorf("carrier OPTIONS after leaving drain: %d, want 200", r.StatusCode)
	}
}

// A client's OPTIONS is answered 200 while draining.
func TestDrainClientOptions(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	h.srv.SetDraining(true)
	if r := phone.do(t, buildOptions(phone, "drain-opt-p1"), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("client OPTIONS while draining: %d, want 200", r.StatusCode)
	}
}

// While draining, the switch's OPTIONS to FreeSBC itself is 503 and its
// OPTIONS to a carrier host is 503 and not forwarded; leaving drain restores
// the 200 and the proxying. A live client token stays 200.
func TestDrainSwitchOptions(t *testing.T) {
	o := startOutboundRig(t)
	self := sip.Uri{Host: "127.0.0.1", Port: portOf(o.privateSIP)}
	carrierURI := sip.Uri{Host: "127.0.0.1", Port: o.cport}
	o.srv.SetDraining(true)

	assertBusy(t, switchRequest(t, o.fs, sip.OPTIONS, self, o.privateSIP), "30")
	assertBusy(t, switchRequest(t, o.fs, sip.OPTIONS, carrierURI, o.privateSIP), "30")
	if got := o.carrier.received(sip.OPTIONS); len(got) != 0 {
		t.Errorf("the carrier saw %d OPTIONS while draining", len(got))
	}
	assertRejects(t, o.harness, nil)

	o.srv.SetDraining(false)
	if r := switchRequest(t, o.fs, sip.OPTIONS, self, o.privateSIP); r.StatusCode != 200 {
		t.Errorf("OPTIONS to FreeSBC after leaving drain: %d, want 200", r.StatusCode)
	}
	if r := switchRequest(t, o.fs, sip.OPTIONS, carrierURI, o.privateSIP); r.StatusCode != 200 {
		t.Errorf("OPTIONS to the carrier after leaving drain: %d, want 200", r.StatusCode)
	}
	if got := o.carrier.waitFor(sip.OPTIONS, 1, 3*time.Second); len(got) != 1 {
		t.Errorf("the carrier saw %d OPTIONS after leaving drain, want 1", len(got))
	}
}

// A switch OPTIONS to a client token with a live binding is answered 200
// locally (also while draining); an unknown token is 404, as an INVITE is.
func TestSwitchOptionsToken(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	bogus := sip.NewParams()
	bogus.Add("fsbc", "bogus-token")
	unknown := sip.Uri{User: "1001", Host: "127.0.0.1", Port: 1234, UriParams: bogus}

	for _, draining := range []bool{false, true} {
		h.srv.SetDraining(draining)
		if r := switchRequest(t, h.fs, sip.OPTIONS, ruri, h.privateSIP); r.StatusCode != 200 {
			t.Errorf("draining=%v: OPTIONS to a live token: %d, want 200", draining, r.StatusCode)
		}
		if r := switchRequest(t, h.fs, sip.OPTIONS, unknown, h.privateSIP); r.StatusCode != 404 {
			t.Errorf("draining=%v: OPTIONS to an unknown token: %d, want 404", draining, r.StatusCode)
		}
	}
	if got := h.fs.received(sip.OPTIONS); len(got) != 0 {
		t.Errorf("OPTIONS was forwarded to the switch %d times", len(got))
	}
}
