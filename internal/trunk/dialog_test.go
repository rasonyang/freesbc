package trunk

import (
	"net"
	"strings"
	"testing"
	"time"
)

// readUntil collects datagrams on conn until one starts with prefix or the
// timeout elapses, returning everything read.
func readUntil(t *testing.T, conn *net.UDPConn, prefix string, timeout time.Duration) (string, bool) {
	t.Helper()
	var got strings.Builder
	buf := make([]byte, 8192)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		got.WriteString("\n---\n")
		if strings.HasPrefix(string(buf[:n]), prefix) {
			return got.String(), true
		}
	}
	return got.String(), false
}

const mergedInviteCfg = `
listen:
  sip: [udp://127.0.0.1:13140]
  media:
    port_range: 13144-13151
    public_ip: 127.0.0.1
ring_timeout: 5s
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:13141
    allowed_ips: [203.0.113.0/24]
routes:
  - name: out
    from: local-uac
    to: [carrier]
`

// audit: P2-TRK-002
// RFC 3261 §8.2.2.2: the same initial INVITE (Call-ID, From-tag, CSeq)
// arriving a second time on a different branch while the first is still
// being handled is a merged request and gets 482, not a second call.
func TestMergedInviteGets482(t *testing.T) {
	// carrier (13141) is left unbound, so the first INVITE stays in
	// progress (dialing a silent target) for the whole test.
	startServer(t, 13140, mergedInviteCfg)

	uac, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uac.Close()
	local := uac.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 13140}

	const callID = "merged-invite-1"
	first := sipInviteWithSDP(callID, local, testSDPBody(uacRTPStubPort(t)), 13140)
	if _, err := uac.WriteToUDP([]byte(first), dst); err != nil {
		t.Fatal(err)
	}
	if got, ok := readUntil(t, uac, "SIP/2.0 100", 2*time.Second); !ok {
		t.Fatalf("first INVITE got no 100 Trying:\n%s", got)
	}

	second := strings.Replace(first, "branch=z9hG4bK-"+callID, "branch=z9hG4bK-"+callID+"-fork2", 1)
	if _, err := uac.WriteToUDP([]byte(second), dst); err != nil {
		t.Fatal(err)
	}
	got, ok := readUntil(t, uac, "SIP/2.0 482", 2*time.Second)
	if !ok {
		t.Fatalf("merged INVITE (same Call-ID/From-tag/CSeq, new branch) must get 482, got:\n%s", got)
	}
	if !strings.Contains(got, "fork2") {
		t.Errorf("482 is not on the second branch:\n%s", got)
	}

	// Tidy up the first call.
	if _, err := uac.WriteToUDP([]byte(sipCancel(callID, local, 13140)), dst); err != nil {
		t.Fatal(err)
	}
	if got, ok := readUntil(t, uac, "SIP/2.0 487", 3*time.Second); !ok {
		t.Fatalf("first INVITE not terminated after CANCEL:\n%s", got)
	}
}
