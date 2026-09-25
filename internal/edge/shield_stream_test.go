package edge

import (
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// audit: P2-SHD-006
// A ban closes the banned client's stream: a WebSocket client whose
// request earns a scanner ban has its connection closed by the proxy,
// instead of keeping a socket every later message is read and parsed on.
// The control request with a benign User-Agent leaves the connection up.
func TestBannedStreamIsClosed(t *testing.T) {
	h := startHarness(t, false)
	browser := newWSClient(t)
	send := func(ua string) {
		t.Helper()
		req := browser.buildRegister("1001", "example.com", 300, "")
		req.AppendHeader(sip.NewHeader("User-Agent", ua))
		req.SetTransport(strings.ToUpper(browser.transport))
		req.SetDestination(h.publicWS)
		if err := browser.cli.WriteRequest(req); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	open := func() bool {
		_, err := browser.ua.TransportLayer().GetConnection("ws", h.publicWS)
		return err == nil
	}

	send("sip.js")
	time.Sleep(300 * time.Millisecond)
	if !open() {
		t.Fatal("control: the connection closed without a ban")
	}

	send("friendly-scanner")
	deadline := time.Now().Add(2 * time.Second)
	for open() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if open() {
		t.Error("the proxy kept a banned client's WebSocket open")
	}
}
