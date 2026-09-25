package edge

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// audit: P2-EDG-027
// An INVITE handler still in flight when shutdown begins must not allocate
// media afterwards, and must not leak a session it allocated just before:
// once the dialog table is closed, begin refuses, allocation is skipped,
// and attach closes a session it can no longer hand to a dialog.
func TestInFlightInviteCannotAllocateAfterShutdown(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	body := phoneOfferSDP(40000)
	src := netip.MustParseAddr("127.0.0.1")
	inUse := func() int {
		a, _ := h.srv.pubPool.Stats()
		b, _ := h.srv.privPool.Stats()
		return a + b
	}

	// A handler that opened its dialog before shutdown, and allocates
	// after it began.
	early, ok := h.srv.dialogs.begin(phone.buildInvite("1001", "2002", "example.com", body), planePublic)
	if !ok {
		t.Fatal("begin before shutdown refused")
	}
	// A handler that allocated before shutdown, and attaches after it.
	late, ok := h.srv.dialogs.begin(phone.buildInvite("1003", "2002", "example.com", body), planePublic)
	if !ok {
		t.Fatal("begin before shutdown refused")
	}
	offer, err := h.srv.parseSDP([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := h.srv.allocateRTP(offer, src)
	if err != nil {
		t.Fatal(err)
	}

	h.srv.dialogs.close() // what Run does first on shutdown

	if _, err := h.srv.buildUpstreamOffer(context.Background(), early, []byte(body), src); !errors.Is(err, errShuttingDown) {
		t.Errorf("buildUpstreamOffer after shutdown began: err = %v, want errShuttingDown", err)
	}
	if err := late.attach(sess); !errors.Is(err, errShuttingDown) {
		t.Errorf("attach after shutdown began: err = %v, want errShuttingDown", err)
	}
	if n := inUse(); n != 0 {
		t.Errorf("media pairs in use after shutdown began = %d, want 0 (nothing allocated, nothing leaked)", n)
	}
	if _, ok := h.srv.dialogs.begin(phone.buildInvite("1005", "2002", "example.com", body), planePublic); ok {
		t.Error("begin after shutdown began opened a dialog")
	}
	h.srv.dialogs.closeAll()
}
