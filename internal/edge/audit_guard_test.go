package edge

// Regression tests for the edge security plane and handler umbrella
// (issue #42).

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// auditRecordTx is a sip.ServerTransaction that records the responses sent
// on it. Only the methods guard and the handlers under test call are
// implemented; any other call panics on the nil embedded interface.
type auditRecordTx struct {
	sip.ServerTransaction
	mu    sync.Mutex
	codes []int
}

func (f *auditRecordTx) Respond(res *sip.Response) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes = append(f.codes, res.StatusCode)
	return nil
}

// auditRawRequest writes a raw SIP request from c to the proxy's public
// UDP listener.
func auditRawRequest(t *testing.T, c *net.UDPConn, dst string, msg string) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteToUDP([]byte(msg), addr); err != nil {
		t.Fatal(err)
	}
}

// audit: P2-EDG-022
// A shield ban is a silent drop (invariant 61). A scanner gets itself
// banned; a malformed request from it afterwards — one sipgo would answer
// with a stateless 400 before any handler runs — must get no response.
func TestAuditBannedSourceGetsNoResponse(t *testing.T) {
	h := startHarness(t, false)
	c := auditUDP(t)
	port := auditUDPPort(c)
	auditRawRequest(t, c, h.publicUDP, fmt.Sprintf("OPTIONS sip:x@127.0.0.1 SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-audit-scan;rport\r\n"+
		"Max-Forwards: 70\r\nFrom: <sip:s@127.0.0.1>;tag=scan\r\nTo: <sip:x@127.0.0.1>\r\n"+
		"Call-ID: audit-scan-1\r\nCSeq: 1 OPTIONS\r\nUser-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n", port))
	deadline := time.Now().Add(2 * time.Second)
	for h.srv.shield.Stats().BannedCurrent == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.srv.shield.Stats().BannedCurrent == 0 {
		t.Fatal("the scanner was never banned")
	}
	// No CSeq: sipgo rejects this with a stateless 400 on its own.
	auditRawRequest(t, c, h.publicUDP, fmt.Sprintf("OPTIONS sip:x@127.0.0.1 SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-audit-malformed;rport\r\n"+
		"Max-Forwards: 70\r\nFrom: <sip:s@127.0.0.1>;tag=scan\r\nTo: <sip:x@127.0.0.1>\r\n"+
		"Call-ID: audit-scan-2\r\nContent-Length: 0\r\n\r\n", port))
	buf := make([]byte, 8192)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	for {
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return // silence: the ban held
		}
		if bytes.HasPrefix(buf[:n], []byte("SIP/2.0")) {
			t.Errorf("P2-EDG-022 confirmed: a banned source was answered: %q", bytes.SplitN(buf[:n], []byte("\r\n"), 2)[0])
			return
		}
	}
}

// audit: P2-EDG-031
// Media is anchored before FreeSWITCH has authenticated the caller, so one
// source must not be able to hold media for an unbounded number of
// unanswered INVITEs. A source sends one INVITE more than the cap to a
// FreeSWITCH that rings forever: the extra one is refused and allocates
// nothing.
func TestAuditUnansweredInvitesPerSourceAreCapped(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(h.fs.silentHook())
	c := auditUDP(t)
	port := auditUDPPort(c)
	const n = maxEarlyPerSource + 1
	for i := 0; i < n; i++ {
		body := phoneOfferSDP(31000 + 2*i)
		auditRawRequest(t, c, h.publicUDP, fmt.Sprintf("INVITE sip:2002@example.com SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-audit-flood-%d;rport\r\n"+
			"Max-Forwards: 70\r\nFrom: <sip:1001@example.com>;tag=flood%d\r\nTo: <sip:2002@example.com>\r\n"+
			"Call-ID: audit-flood-%d-%d\r\nCSeq: 1 INVITE\r\nContact: <sip:1001@127.0.0.1:%d>\r\n"+
			"Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s",
			port, i, i, i, time.Now().UnixNano(), port, len(body), body))
		time.Sleep(5 * time.Millisecond)
	}
	// The 503 is retransmitted until ACKed (this raw client never ACKs), so
	// refusals are counted per call.
	refused := map[string]bool{}
	buf := make([]byte, 8192)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		k, _, err := c.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if !bytes.HasPrefix(buf[:k], []byte("SIP/2.0 503")) {
			continue
		}
		if msg, err := sip.ParseMessage(buf[:k]); err == nil {
			if cid := msg.CallID(); cid != nil {
				refused[cid.Value()] = true
			}
		}
	}
	inUse, _ := h.srv.pubPool.Stats()
	t.Logf("%d INVITEs from one source: %d refused, %d public port pairs in use", n, len(refused), inUse)
	if len(refused) != 1 || inUse > maxEarlyPerSource {
		t.Errorf("P2-EDG-031 confirmed: %d unanswered INVITEs from one source hold %d public port pairs (%d refused); want at most %d",
			n, inUse, len(refused), maxEarlyPerSource)
	}
}

// audit: P2-EDG-034
// guard's recover must not hide a handler panic, and must not answer 500
// on a transaction that already had its final response.
func TestAuditGuardPanicAfterFinal(t *testing.T) {
	h := startHarness(t, false)
	req := sip.NewRequest(sip.INFO, sip.Uri{User: "x", Host: "127.0.0.1"})
	callID := sip.CallIDHeader("audit-panic")
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INFO})
	req.SetTransport("UDP")
	req.SetSource("127.0.0.1:5999")
	tx := &auditRecordTx{}
	before := h.srv.metrics.Snapshot().HandlerPanics
	h.srv.guard(func(req *sip.Request, tx sip.ServerTransaction, _ netip.AddrPort) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
		panic("audit: handler bug after the final response")
	})(req, tx)
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if len(tx.codes) != 1 || tx.codes[0] != 200 {
		t.Errorf("P2-EDG-034 confirmed: responses after a panic that followed the final: %v, want only [200]", tx.codes)
	}
	if got := h.srv.metrics.Snapshot().HandlerPanics - before; got != 1 {
		t.Errorf("P2-EDG-034 confirmed: the recovered panic was counted %d times, want 1", got)
	}
}
