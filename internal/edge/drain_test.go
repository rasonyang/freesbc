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

// Drain (maintenance) mode (issue #123): while draining, every new
// out-of-dialog INVITE (public client, carrier, or the switch) is refused
// 503 + Retry-After 30 before a slot, a rate token or a media port is taken.
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

// A registered client's new INVITE is refused; nothing reaches the switch;
// leaving drain restores normal handling without a restart.
func TestDrainClientToSwitch(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	h.srv.SetDraining(true)

	assertBusy(t, phoneInvite(t, h, phone), "30")
	if got := h.fs.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the switch saw %d INVITEs while draining", len(got))
	}
	assertNothingAllocated(t, h)
	assertRejects(t, h, map[inviteReject]uint64{rejectDraining: 1})

	h.srv.SetDraining(false)
	if code := phoneCallStatus(t, h, phone); code != 200 {
		t.Errorf("call after leaving drain: %d, want 200", code)
	}
	assertRejects(t, h, map[inviteReject]uint64{rejectDraining: 1})
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

// The switch is not exempt: its call to a registered client is refused.
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

	assertBusy(t, h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)), "30")
	if n := offered.Load(); n != 0 {
		t.Errorf("the client saw %d INVITEs while draining", n)
	}
	assertNothingAllocated(t, h)
	assertRejects(t, h, map[inviteReject]uint64{rejectDraining: 1})

	h.srv.SetDraining(false)
	if r := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)); r.StatusCode != 200 {
		t.Errorf("call after leaving drain: %d, want 200", r.StatusCode)
	}
}

// The switch's call out through a carrier is refused too.
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
