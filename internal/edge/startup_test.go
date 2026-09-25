package edge

import (
	"testing"
)

// regression: edge startup race
//
// Run used to close Ready as soon as it had started the goroutines serving
// its listeners, but sipgo adds a UDP listener to its connection pool only
// from inside that goroutine. A phone INVITE arriving in between was
// forwarded upstream pinned to the private bind's address, missed the pool,
// and made sipgo bind a second socket there ("address already in use"):
// the phone got a 503. The harness starts the proxy and waits for Ready
// and nothing else; the very first INVITE must be forwarded.
func TestFirstInviteAfterReadyIsForwarded(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(40000))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("first INVITE after Ready: got %d %s, want 200", res.StatusCode, res.Reason)
	}
	sendAck(t, phone, invite, res, h.publicUDP)
}
