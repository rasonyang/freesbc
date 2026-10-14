package edge

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// The helper must never fail and must report a cap exactly when the kernel
// read-back is below the request. The granted size depends on the host's
// rmem_max / maxsockbuf, so the test asserts consistency, not a fixed size.
func TestApplyUDPBuffers(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	var sb strings.Builder
	log := slog.New(slog.NewTextHandler(&sb, nil))
	rcv, snd, capped := applyUDPBuffers(pc, udpSIPReadBuffer, udpSIPWriteBuffer, log)
	if rcv == 0 || snd == 0 {
		t.Skip("socket buffer read-back unsupported on this platform")
	}
	wantCap := rcv < udpSIPReadBuffer || snd < udpSIPWriteBuffer
	if capped != wantCap {
		t.Fatalf("capped=%v, want %v (rcv=%d snd=%d)", capped, wantCap, rcv, snd)
	}
	if warned := strings.Contains(sb.String(), "level=WARN"); warned != capped {
		t.Fatalf("warned=%v capped=%v log=%q", warned, capped, sb.String())
	}
	if !capped && rcv < udpSIPReadBuffer {
		t.Fatalf("rcv=%d below request without a cap", rcv)
	}
}

// A 1 GiB request (above any default rmem_max or maxsockbuf, and within
// the int32 setsockopt takes) must warn, not fail.
func TestApplyUDPBuffersCapped(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rcv, _, capped := applyUDPBuffers(pc, 1<<30, 1<<30, log)
	if rcv == 0 {
		t.Skip("socket buffer read-back unsupported on this platform")
	}
	if !capped {
		t.Fatalf("a 1 GiB request reported no cap (rcv=%d)", rcv)
	}
}
