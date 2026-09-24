package edge

// Phase 3 audit tests for the edge PSTN failover path. These use the PSTN
// harness, whose fake FreeSWITCH lives on 127.0.0.2: on macOS they need
// `sudo ifconfig lo0 alias 127.0.0.2 up`, or a Linux container.

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// audit: P2-EDG-014
// RFC 3261 §16.7 step 5 / §21.6: a 6xx means no other location is to be
// tried; docs/edge.md says failover happens on a 5xx/408. gw-a answers
// 603 Decline; gw-b must never be dialed and FreeSWITCH must get the 603.
func TestAuditPSTN6xxStopsFailover(t *testing.T) {
	h, gws := startHarnessPSTNGateways(t, "", "      - to: [gw-a, gw-b]\n", map[string]string{
		"gw-a": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"gw-b": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	gwA, gwB := gws["gw-a"], gws["gw-b"]
	gwA.setInviteHook(gwA.answerHook(603, false))
	gwB.setInviteHook(gwB.answerHook(200, true))

	res := bridgePSTNCall(t, h, "12345")
	gotB := len(gwB.waitFor(sip.INVITE, 1, time.Second))
	if res.StatusCode != 603 || gotB != 0 {
		t.Errorf("P2-EDG-014 confirmed: after gw-a's 603 Decline FreeSWITCH got %d and gw-b saw %d INVITE(s); want 603 and 0",
			res.StatusCode, gotB)
	}
	if res.StatusCode == 200 {
		hangupPSTN(t, h, res)
	}
}

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
// synthesised as FreeSWITCH's final response.
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

	h := startHarnessCfg(t, false, "127.0.0.1", "127.0.0.2", func(pubUDP int) string {
		return fmt.Sprintf("  pstn:\n    match: 127.0.0.1:%d\n    attempt_timeout: 300ms\n    gateways:\n"+
			"      gw-a:\n        address: %s\n    routes:\n      - to: [gw-a]\n", pubUDP, gwAddr)
	})
	ruri := sip.Uri{User: "12345", Host: "127.0.0.1", Port: portOf(h.publicUDP)}
	_, final := h.fs.callAsync(t, ruri, h.publicUDP, phoneOfferSDP(h.fs.rtpPort))
	select {
	case res := <-final:
		if res == nil {
			t.Errorf("P2-EDG-015 confirmed: FreeSWITCH never received a final response after the only gateway expired and rang in the drain")
		} else {
			t.Logf("FreeSWITCH final: %d %s", res.StatusCode, res.Reason)
		}
	case <-time.After(12 * time.Second):
		t.Errorf("P2-EDG-015 confirmed: no final response to FreeSWITCH within 12 s")
	}
}
