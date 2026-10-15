package edge

import (
	"fmt"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// A public OPTIONS is answered only for an admitted source (issue #188): a
// live registration, a carrier source, or a To tag naming a live dialog.
// Anyone else gets silence, nothing reaches the switch, and the drop is
// counted.

func TestOptionsUnregisteredSourceDropped(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	stranger := newUDPClient(t)
	expectSilence(t, stranger, buildOptions(stranger, "optadm-1"), h.publicUDP)
	// UDP retransmissions of the unanswered request are drops too.
	if n := admissionDrops(h, dropOptions); n < 1 {
		t.Errorf("options_not_admitted drops = %d, want at least 1", n)
	}
	if got := h.fs.received(sip.OPTIONS); len(got) != 0 {
		t.Errorf("the switch saw %d OPTIONS from an unadmitted source", len(got))
	}
}

func TestOptionsRegisteredSourceAnswered(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	res := phone.do(t, buildOptions(phone, "optadm-2"), h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("OPTIONS from a registered phone: got %d, want 200", res.StatusCode)
	}
	if got := headerValue(res, "Allow"); got == "" {
		t.Error("200 carries no Allow header")
	}
	if got := h.fs.received(sip.OPTIONS); len(got) != 0 {
		t.Errorf("OPTIONS was forwarded upstream %d times", len(got))
	}
	if n := admissionDrops(h, dropOptions); n != 0 {
		t.Errorf("options_not_admitted drops = %d, want 0", n)
	}
}

func TestOptionsCarrierSourceAnswered(t *testing.T) {
	carrier := newUDPClient(t)
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(carrier.local)), "", nil)
	res := carrier.do(t, buildOptions(carrier, "optadm-3"), rig.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("OPTIONS from a carrier source: got %d, want 200", res.StatusCode)
	}
	if got := headerValue(res, "Allow"); got == "" {
		t.Error("200 carries no Allow header")
	}
	if n := admissionDrops(rig.harness, dropOptions); n != 0 {
		t.Errorf("options_not_admitted drops = %d, want 0", n)
	}
}

// An OPTIONS whose To tag names a live dialog is answered even from a
// source that is neither registered nor a carrier; a made-up To tag is not.
func TestOptionsInDialogAnswered(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}

	other := newUDPClient(t)
	opt := inDialogRequest(other, sip.OPTIONS, 2, invite, res)
	if got := other.do(t, opt, h.publicUDP); got.StatusCode != 200 {
		t.Fatalf("in-dialog OPTIONS from an unregistered source: got %d, want 200", got.StatusCode)
	}
	if n := admissionDrops(h, dropOptions); n != 0 {
		t.Errorf("options_not_admitted drops = %d, want 0", n)
	}

	ghost, gres := ghostDialog(other)
	expectSilence(t, other, inDialogRequest(other, sip.OPTIONS, 2, ghost, gres), h.publicUDP)
	if n := admissionDrops(h, dropOptions); n < 1 {
		t.Errorf("options_not_admitted drops = %d, want at least 1", n)
	}
}

// Admission is decided before drain: a stranger gets silence while
// draining, a registered client its 200.
func TestOptionsUnregisteredSourceDroppedWhileDraining(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	h.srv.SetDraining(true)

	stranger := newUDPClient(t)
	expectSilence(t, stranger, buildOptions(stranger, "optadm-5"), h.publicUDP)
	if n := admissionDrops(h, dropOptions); n < 1 {
		t.Errorf("options_not_admitted drops = %d, want at least 1", n)
	}
	if r := phone.do(t, buildOptions(phone, "optadm-6"), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("registered OPTIONS while draining: got %d, want 200", r.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	assertRejects(t, h, nil)
}
