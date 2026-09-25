package edge

import (
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// audit: P2-SDP-011
// The WebRTC leg carries RTCP muxed on the RTP component and every body
// toward the browser says a=rtcp-mux. RFC 5761 §5.1.1 allows that in an
// answer only when the offer had it, so a browser offer without
// a=rtcp-mux is refused with 488 before anything reaches FreeSWITCH.
func TestWebRTCOfferWithoutRTCPMuxRejected(t *testing.T) {
	h := startHarness(t, true)
	browser := newWSClient(t)
	offer := browserOfferSDP(51234)
	if !strings.Contains(offer, "a=rtcp-mux\r\n") {
		t.Fatal("fixture no longer carries a=rtcp-mux")
	}
	offer = strings.Replace(offer, "a=rtcp-mux\r\n", "", 1)
	seen := len(h.fs.received(sip.INVITE))
	res := browser.do(t, browser.buildInvite("1001", "2002", "example.com", offer), h.publicWS)
	if res.StatusCode != 488 {
		t.Fatalf("non-mux WebRTC offer answered %d, want 488", res.StatusCode)
	}
	if got := h.fs.waitFor(sip.INVITE, seen+1, 300*time.Millisecond); len(got) > seen {
		t.Errorf("a refused offer still reached FreeSWITCH")
	}
}
