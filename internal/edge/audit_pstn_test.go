package edge

// Phase 3 audit tests for the edge PSTN failover path. P2-EDG-014 (a 6xx
// stops failover) is covered by TestPSTNRelayedFinalStopsTheSeries in
// pstn_test.go.

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// auditLateRingGateway is a raw UDP gateway that ignores the INVITE (so the
// attempt budget expires), and on the CANCEL answers 200, then a 180, then
// the 487 — a provisional arriving inside the SBC's post-expiry drain.
type auditLateRingGateway struct {
	conn *net.UDPConn
	mu   sync.Mutex
	inv  *sip.Request
	src  *net.UDPAddr
}

func (g *auditLateRingGateway) serve() {
	buf := make([]byte, 64<<10)
	for {
		n, src, err := g.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg, err := sip.ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		req, ok := msg.(*sip.Request)
		if !ok {
			continue
		}
		switch req.Method {
		case sip.INVITE:
			g.mu.Lock()
			if g.inv == nil {
				g.inv, g.src = req.Clone(), src
			}
			g.mu.Unlock()
		case sip.CANCEL:
			g.write(sip.NewResponseFromRequest(req, 200, "OK", nil), src)
			g.mu.Lock()
			inv, isrc := g.inv, g.src
			g.mu.Unlock()
			if inv == nil {
				continue
			}
			g.write(sip.NewResponseFromRequest(inv, 180, "Ringing", nil), isrc)
			time.Sleep(50 * time.Millisecond)
			g.write(sip.NewResponseFromRequest(inv, 487, "Request Terminated", nil), isrc)
		}
	}
}

func (g *auditLateRingGateway) write(res *sip.Response, dst *net.UDPAddr) {
	_, _ = g.conn.WriteToUDP([]byte(res.String()), dst)
}

// audit: P2-EDG-015
// RFC 3261 §16.7 step 6: when every branch fails the proxy sends a FINAL
// response. A 180 that arrives in the drain after the attempt budget
// expired must not be recorded as the attempt's "real" final and then
// synthesised as FreeSWITCH's final response. The gateway's 487 follows
// the 180 inside pstnDrain, so the expired attempt is a ring timeout
// (expirePSTNAttempt) and the series synthesises 408 Request Timeout.
func TestAuditPSTNProvisionalInDrainNotFinal(t *testing.T) {
	gwAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	ua, err := net.ResolveUDPAddr("udp", gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatal(err)
	}
	g := &auditLateRingGateway{conn: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go g.serve()

	h := startHarnessCfg(t, false, "127.0.0.1", func(pubUDP int) string {
		return fmt.Sprintf("  pstn:\n    match: 127.0.0.1:%d\n    attempt_timeout: 300ms\n    gateways:\n"+
			"      gw-a:\n        address: %s\n    routes:\n      - to: [gw-a]\n", pubUDP, gwAddr)
	})
	ruri := sip.Uri{User: "12345", Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	_, final := h.fs.callAsync(t, ruri, h.publicUDP, phoneOfferSDP(h.fs.rtpPort))
	select {
	case res := <-final:
		if res == nil {
			t.Errorf("P2-EDG-015 confirmed: FreeSWITCH never received a final response after the only gateway expired and rang in the drain")
		} else if res.StatusCode != 408 {
			t.Errorf("FreeSWITCH final = %d %s, want 408 Request Timeout", res.StatusCode, res.Reason)
		}
	case <-time.After(12 * time.Second):
		t.Errorf("P2-EDG-015 confirmed: no final response to FreeSWITCH within 12 s")
	}
}
