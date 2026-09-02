package trunk

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// preparseCfg renders a config whose only peer allows 127.0.0.9 while the
// SIP listener binds 127.0.0.2 — so a socket bound to 127.0.0.1 is a
// non-peer source at the transport layer, and 127.0.0.9 is a peer source.
// (Both bind fine: loopback covers the whole 127/8 on Linux.)
func preparseCfg(port int) string {
	return fmt.Sprintf(`
listen:
  sip: [udp://127.0.0.2:%d]
peers:
  remote:
    address: 127.0.0.9:5060
    allowed_ips: [127.0.0.9/32]
routes:
  - name: in
    from: remote
    to: [remote]
`, port)
}

// TestPreParseFilterDropsNonPeerBytes is T-01's red test (F-01/F-10): a
// Via-less OPTIONS — parseable, but malformed enough that sipgo's
// transaction layer would answer a stateless 400 (rejectMalformedRequest)
// before any handler or the shield ever saw it — sent from a source matching
// no peer's allowed_ips must produce NO response bytes at all: the
// transport-layer read filter drops it before parsing. Before T-01, the 400
// comes back and this test fails.
func TestPreParseFilterDropsNonPeerBytes(t *testing.T) {
	const port = 45600
	startServerAt(t, port, "127.0.0.2", preparseCfg(port), nil)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port}

	// Deliberately no Via line: makeServerTxKey fails on it and the
	// transaction layer answers 400 statelessly — the pre-handler,
	// pre-shield path the read filter must close.
	req := strings.Join([]string{
		fmt.Sprintf("OPTIONS sip:sbc@127.0.0.2:%d SIP/2.0", port),
		"From: <sip:tester@127.0.0.1>;tag=t1",
		"To: <sip:sbc@127.0.0.2>",
		"Call-ID: prefilter-nonpeer-1",
		"CSeq: 1 OPTIONS",
		"Content-Length: 0",
		"", "",
	}, "\r\n")

	var got strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	sent := 0
	for time.Now().Before(deadline) {
		if sent < 4 {
			// Resend a few times so the test can't pass vacuously: once the
			// server is up, at least one copy must reach it — and, without
			// the filter, draw the 400 back.
			if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
				t.Fatalf("write OPTIONS: %v", err)
			}
			sent++
		}
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		if strings.Contains(got.String(), "SIP/2.0") {
			t.Fatalf("non-peer source must be dropped pre-parse, but got a response:\n%s", got.String())
		}
	}
}

// TestPreParseFilterAllowsPeerBytes is the positive control: a well-formed
// OPTIONS from an allowed source (127.0.0.9) still gets its 200 — guarding
// against a filter that drops everything instead of only non-peer bytes.
func TestPreParseFilterAllowsPeerBytes(t *testing.T) {
	const port = 45601
	startServerAt(t, port, "127.0.0.2", preparseCfg(port), nil)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 9)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port}

	req := sipRequest("OPTIONS", fmt.Sprintf("%d", port), local, "prefilter-peer-1")
	if _, err := conn.WriteToUDP([]byte(req), dst); err != nil {
		t.Fatalf("write OPTIONS: %v", err)
	}

	var got strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		got.Write(buf[:n])
		if strings.Contains(got.String(), "SIP/2.0 200") {
			return
		}
	}
	t.Fatalf("allowed peer source must get 200 OK, got:\n%s", got.String())
}
