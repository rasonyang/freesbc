package edge

import (
	"runtime"
	"testing"
	"time"
	"weak"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Issue #228: an ended dialog must not stay reachable through what outlives
// it for about 32 s. sipgo keeps a finished transaction, and the callbacks
// registered on it (OnCancel, OnRetransmission), until its terminate timers
// (J, M) run; and a stopped time.Timer stays in the runtime's timer heap, with
// its closure, until the heap is cleaned up (the ACK backstop reaches 32 s).
// Any of them capturing the dialog keeps the record, its media session and
// its forks alive, so the memory held scales with the call rate. The
// transactions are still alive when this test checks, so a regression keeps
// the record reachable until the 5 s deadline.
func TestEndedDialogNotRetainedByTransactionHooks(t *testing.T) {
	h := startHarness(t, false)
	tags := make(chan string, 4)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	phone := newUDPClient(t)

	// The call runs in its own frame so no stack slot of the test keeps the
	// record: only the weak pointer leaves it.
	call := func() weak.Pointer[dialog] {
		invite, res, _ := auditPhoneCall(t, h, phone)
		wp := weak.Make(waitForDialog(t, h, fsip.CallID(invite)))
		if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
			t.Fatalf("BYE: %d", r.StatusCode)
		}
		return wp
	}
	var wps []weak.Pointer[dialog]
	for i := 0; i < 12; i++ {
		wps = append(wps, call())
	}

	deadline := time.Now().Add(5 * time.Second)
	for _, wp := range wps {
		for wp.Value() != nil && time.Now().Before(deadline) {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
		}
		if d := wp.Value(); d != nil {
			t.Fatalf("ended dialog %s still reachable while its transactions and timers linger", d.callID)
		}
	}
}
