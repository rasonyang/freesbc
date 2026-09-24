package trunk

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const auditTCPCapCfg = `
listen:
  sip: [tcp://127.0.0.1:47760]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: in
    from: local-uac
    to: [local-uac]
`

// auditTCPOptions sends one OPTIONS over a fresh TCP connection from the
// peer address and reports the response text ("" if none / closed).
func auditTCPOptions(t *testing.T, addr, callID string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return "dial error: " + err.Error()
	}
	defer conn.Close()
	local := conn.LocalAddr().String()
	req := strings.Join([]string{
		"OPTIONS sip:sbc@" + addr + " SIP/2.0",
		"Via: SIP/2.0/TCP " + local + ";branch=z9hG4bK-" + callID,
		"From: <sip:peer@127.0.0.1>;tag=f",
		"To: <sip:sbc@127.0.0.1>",
		"Call-ID: " + callID,
		"CSeq: 1 OPTIONS",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(req)); err != nil {
		return "write error: " + err.Error()
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "read error: " + err.Error()
	}
	return string(buf[:n])
}

// audit: P2-TRK-001
// Non-peer sources must not be able to consume the TCP connection cap that
// peers need: docs/design.md §6.1 says bytes from a non-peer source never
// reach the connection pool. The cap is lowered to 4 through the
// test-only hook; the attacker connects from 127.0.0.2 (not in any
// allowed_ips) and sends nothing.
func TestAuditTCPCapExhaustedByNonPeers(t *testing.T) {
	const addr = "127.0.0.1:47760"
	startServerConfigured(t, 47760, auditTCPCapCfg, func(s *Server) { s.tcpMaxConns = 4 })

	if got := auditTCPOptions(t, addr, "cap-control"); !strings.HasPrefix(got, "SIP/2.0 ") {
		t.Fatalf("control: peer OPTIONS over TCP got %q, want a SIP response", got)
	}

	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}, Timeout: time.Second}
	var held []net.Conn
	for i := 0; i < 4; i++ {
		c, err := d.Dial("tcp", addr)
		if err != nil {
			if i == 0 && strings.Contains(err.Error(), "assign requested address") {
				t.Skipf("127.0.0.2 not configured on this host: %v", err)
			}
			t.Fatalf("attacker dial %d: %v", i, err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond)

	got := auditTCPOptions(t, addr, "cap-after")
	if !strings.HasPrefix(got, "SIP/2.0 ") {
		t.Errorf("after 4 idle TCP connections from non-peer 127.0.0.2, peer OPTIONS got %q: "+
			"non-peers exhausted the connection cap (%s)", got, fmt.Sprintf("cap=%d", 4))
	}
}

const auditMinSECfg = `
min_se: 90s
listen:
  sip: [udp://127.0.0.1:47770]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: in
    from: local-uac
    to: [local-uac]
`

// audit: P2-TRK-010
// RFC 4028 §4: "x" is the compact form of Session-Expires. An INVITE with
// "x: 30" under min_se 90s must get 422 exactly like the long form does.
func TestAuditCompactSessionExpiresBypassesMinSE(t *testing.T) {
	startServer(t, 47770, auditMinSECfg)
	long := roundTripWithHeaders(t, 47770, "INVITE", "minse-long", 3*time.Second, "SIP/2.0 422", "Session-Expires: 30")
	if !strings.Contains(long, "SIP/2.0 422") {
		t.Fatalf("control: long-form Session-Expires: 30 got:\n%s\nwant 422", long)
	}
	compact := roundTripWithHeaders(t, 47770, "INVITE", "minse-compact", 3*time.Second, "SIP/2.0 422", "x: 30")
	if !strings.Contains(compact, "SIP/2.0 422") {
		first := compact
		if i := strings.Index(first, "\r\n"); i >= 0 {
			first = first[:i]
		}
		t.Errorf("compact 'x: 30' under min_se 90s: first response line %q, want 422", first)
	}
}
