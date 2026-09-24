package trunk

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestStubCarrierByeBeforeAckEndsDialog pins the stub carrier's own
// contract that every answered dialog closes byeDone when it ends,
// including when the peer BYEs before sipgo has seen an ACK for the 2xx.
//
// sipgo's DialogServerSession.Respond blocks on the ACK and returns "No ACK
// received" when a BYE ends the dialog first. The bridge ACKs and BYEs a
// broken answer back to back, so that ordering is exactly what
// TestBridgeBrokenAnswerSDPGets502 hits now and then; the carrier used to
// return on that error without closing byeDone, and the test then timed
// out waiting for a dialog end that had already happened. Driven here with
// raw datagrams so the ordering is deterministic.
//
// audit: P1-006
func TestStubCarrierByeBeforeAckEndsDialog(t *testing.T) {
	const carrierPort = 11980
	carrier := startStubCarrier(t, fmt.Sprintf("127.0.0.1:%d", carrierPort), nil, stubCarrierConfig{
		brokenAnswer: true,
	})

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: carrierPort}

	msg := func(method string, cseq int, branch, toTag string) string {
		to := "To: <sip:5551234@127.0.0.1>"
		if toTag != "" {
			to += ";tag=" + toTag
		}
		return strings.Join([]string{
			fmt.Sprintf("%s sip:5551234@127.0.0.1:%d SIP/2.0", method, carrierPort),
			fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-%s", local, branch),
			"From: <sip:caller@127.0.0.1>;tag=caller-1",
			to,
			"Call-ID: stub-bye-before-ack",
			fmt.Sprintf("CSeq: %d %s", cseq, method),
			"Contact: <sip:caller@" + local.String() + ">",
			"Max-Forwards: 70",
			"Content-Length: 0",
			"", "",
		}, "\r\n")
	}

	if _, err := conn.WriteToUDP([]byte(msg("INVITE", 1, "inv", "")), dst); err != nil {
		t.Fatal(err)
	}

	// Wait for the 200 and take its To-tag; deliberately never ACK it.
	var toTag string
	buf := make([]byte, 8192)
	deadline := time.Now().Add(3 * time.Second)
	for toTag == "" {
		_ = conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no 200 from the stub carrier: %v", err)
		}
		resp := string(buf[:n])
		if !strings.HasPrefix(resp, "SIP/2.0 200") {
			continue
		}
		for _, line := range strings.Split(resp, "\r\n") {
			if i := strings.Index(line, ";tag="); i >= 0 && strings.HasPrefix(strings.ToLower(line), "to:") {
				toTag = strings.TrimSpace(line[i+len(";tag="):])
			}
		}
		if toTag == "" {
			t.Fatalf("200 carries no To-tag:\n%s", resp)
		}
	}

	if _, err := conn.WriteToUDP([]byte(msg("BYE", 2, "bye", toTag)), dst); err != nil {
		t.Fatal(err)
	}

	select {
	case <-carrier.byeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("stub carrier never closed byeDone for a dialog BYEd before its 2xx was ACKed")
	}
}
