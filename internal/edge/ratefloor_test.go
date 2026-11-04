package edge

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// These tests cover the per-socket rate floor (shield.AllowRate). Every
// test source is 127.0.0.1, so a "forged" source is another socket on
// 127.0.0.1 with a different port. Timing-based over real UDP loopback:
// re-run once before treating a flake as failure.

// noRetransmit is below SIP's first UDP retransmission (T1 = 500 ms): an
// answer faster than this was not preceded by a rate drop.
const noRetransmit = 400 * time.Millisecond

// startDatagramFlood sends well-formed OPTIONS datagrams to dest from a
// fresh UDP socket at several thousand per second until the test ends. The
// socket's port differs from every client's, as a forged source's would.
func startDatagramFlood(t *testing.T, dest string) {
	t.Helper()
	c := dialUDP(t, dest)
	stop := make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() { close(stop); <-done })
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			for j := 0; j < 5; j++ {
				_, _ = c.Write(rawOptions(c.LocalAddr(), i*5+j))
			}
			time.Sleep(time.Millisecond)
		}
	}()
	time.Sleep(300 * time.Millisecond) // let the flood empty the IP bucket
}

// While a forged datagram flood names 127.0.0.1, a registered UDP phone, TLS
// client and WS client each still refresh their registration, and the stream
// connections stay open.
func TestRateFloorKeepsRegisteredClientsDuringForgedFlood(t *testing.T) {
	for _, tr := range []string{"udp", "tls", "ws"} {
		t.Run(tr, func(t *testing.T) {
			h := startStreamHarness(t, streamOpts{tls: true, ws: true})
			var c *client
			dest := h.publicUDP
			switch tr {
			case "udp":
				c = newUDPClient(t)
			case "tls":
				c, dest = newTLSClient(t), h.publicTLS
			case "ws":
				c, dest = newWSClient(t), h.publicWS
			}
			if res := c.do(t, c.buildRegister("1001", "example.com", 600, ""), dest); res.StatusCode != 200 {
				t.Fatalf("REGISTER: %d", res.StatusCode)
			}
			// admission_ban stays on: the flood's admitted OPTIONS must not
			// get the victim's IP banned (it holds a binding, so it is never struck).
			auditReplaceConfig(h, func(c *config.Config) { c.Shield.RateLimit = "20/s per_ip" })
			startDatagramFlood(t, h.publicUDP)

			for round := 0; round < 3; round++ {
				start := time.Now()
				res := c.do(t, c.buildRegister("1001", "example.com", 600, ""), dest)
				if took := time.Since(start); took > noRetransmit {
					t.Fatalf("round %d: refresh took %s: it was dropped and retransmitted", round, took)
				}
				if res.StatusCode != 200 {
					t.Fatalf("round %d: refresh during the flood: %d", round, res.StatusCode)
				}
				time.Sleep(100 * time.Millisecond)
			}
			if n := h.rateDrops(); n < 500 {
				t.Errorf("only %d rate drops: the flood never drained the bucket", n)
			}
			if n := h.srv.metrics.Snapshot().StreamClosed["rate"]; n != 0 {
				t.Errorf("%d stream connections closed for rate during a datagram flood", n)
			}
		})
	}
}

// A UDP carrier configured as a literal edge.carriers address keeps its
// rate while a forged flood names its IP and drains the IP bucket. The
// carrier sends from its configured port, as a real gateway does.
func TestRateFloorKeepsLiteralCarrierDuringForgedFlood(t *testing.T) {
	port := freePort(t)
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", port), "", nil)
	auditReplaceConfig(rig.harness, func(c *config.Config) {
		c.Shield.CarrierRateLimit = "20/s per_ip"
	})
	startDatagramFlood(t, rig.publicUDP)
	dst, err := net.ResolveUDPAddr("udp", rig.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for i := 0; i < 3; i++ {
		start := time.Now()
		if _, err := sock.WriteToUDP(rawOptions(sock.LocalAddr(), i), dst); err != nil {
			t.Fatal(err)
		}
		_ = sock.SetReadDeadline(time.Now().Add(noRetransmit))
		n, _, err := sock.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("OPTIONS %d from the carrier's address: no answer within %s: %v", i, time.Since(start), err)
		}
		if !strings.HasPrefix(string(buf[:n]), "SIP/2.0 ") {
			t.Fatalf("OPTIONS %d: %q is not a SIP response", i, buf[:n])
		}
	}
	if n := rig.rateDrops(); n < 500 {
		t.Errorf("only %d rate drops: the flood never drained the bucket", n)
	}
}
