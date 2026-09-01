package media

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// pumpTransform sends `send` from src exactly ONCE and reads dst until it
// reads exactly `expect` or the deadline expires. It deliberately does not
// resend on timeout (T-08/F-09): with replay protection enabled, a resent
// identical SRTP ciphertext is a replay and would be dropped by the relay,
// so retrying could only guarantee failure — the old resend loop relied on
// pion's default no-replay behavior. A single UDP datagram over loopback is
// not lost in practice.
func pumpTransform(t *testing.T, src, dst *net.UDPConn, send, expect []byte) {
	t.Helper()
	if _, err := src.Write(send); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	deadline := time.Now().Add(3 * time.Second)
	for {
		_ = dst.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := dst.Read(buf)
		if err == nil && bytes.Equal(buf[:n], expect) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("send %x never forwarded as %x", send, expect)
		}
	}
}

// latchBoth sends one raw packet from each endpoint so both sides latch. On a
// secure side the packet won't decrypt (dropped after latching) — latching
// happens on the source address before decryption, so any first packet arms it.
func latchBoth(t *testing.T, ea, eb *net.UDPConn) {
	t.Helper()
	_, _ = ea.Write([]byte("latch-a"))
	_, _ = eb.Write([]byte("latch-b"))
	time.Sleep(100 * time.Millisecond)
}

func TestRelaySRTPToRTPInterworks(t *testing.T) {
	s := newLooseSession(t, 41200, 41215, time.Minute)
	key := mustKey(t)
	peerEnc, _ := NewSRTPContext(SuiteAES128CM80, key) // the A-peer's SRTP sender
	sbcInA, _ := NewSRTPContext(SuiteAES128CM80, key)  // SBC decrypts from A
	s.SetSRTP(SideA, sbcInA, nil)                      // A: inbound secure, outbound plaintext
	s.SetSRTP(SideB, nil, nil)                         // B: plaintext both ways
	s.Start()
	ea, eb := dialSide(t, s, SideA), dialSide(t, s, SideB)
	latchBoth(t, ea, eb)

	plain := testRTPPacket()
	cipher, ok := peerEnc.protectRTP(append([]byte(nil), plain...))
	if !ok {
		t.Fatal("encrypt failed")
	}
	pumpTransform(t, ea, eb, cipher, plain) // B receives DECRYPTED plaintext
}

// TestRelayRTPToSRTPInterworks: A sends plaintext RTP; B's leg is secure
// (outbound encrypted). B must read ciphertext that only a matching SRTP
// context can decrypt back to the original plaintext.
func TestRelayRTPToSRTPInterworks(t *testing.T) {
	s := newLooseSession(t, 41220, 41235, time.Minute)
	keyB := mustKey(t)
	sbcOutB, _ := NewSRTPContext(SuiteAES128CM80, keyB) // SBC encrypts toward B
	peerDecB, _ := NewSRTPContext(SuiteAES128CM80, keyB)
	s.SetSRTP(SideA, nil, nil)     // A: plaintext both ways
	s.SetSRTP(SideB, nil, sbcOutB) // B: inbound plaintext, outbound secure
	s.Start()
	ea, eb := dialSide(t, s, SideA), dialSide(t, s, SideB)
	latchBoth(t, ea, eb)

	plain := testRTPPacket()
	buf := make([]byte, 1500)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := ea.Write(plain); err != nil {
			t.Fatal(err)
		}
		_ = eb.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := eb.Read(buf)
		if err == nil {
			got, ok := peerDecB.unprotectRTP(append([]byte(nil), buf[:n]...))
			if ok && bytes.Equal(got, plain) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("plaintext from A never arrived at B re-encrypted")
		}
	}
}

// TestRelaySRTPToSRTPRekeyed: both legs are secure with DIFFERENT keys. The
// SBC must decrypt with keyA and re-encrypt with keyB — proving it actually
// re-keys rather than passing ciphertext through untouched.
func TestRelaySRTPToSRTPRekeyed(t *testing.T) {
	s := newLooseSession(t, 41240, 41255, time.Minute)
	keyA := mustKey(t)
	keyB := mustKey(t)
	peerEncA, _ := NewSRTPContext(SuiteAES128CM80, keyA) // A-peer's sender
	sbcInA, _ := NewSRTPContext(SuiteAES128CM80, keyA)   // SBC decrypts from A
	sbcOutB, _ := NewSRTPContext(SuiteAES128CM80, keyB)  // SBC encrypts toward B
	peerDecBKeyB, _ := NewSRTPContext(SuiteAES128CM80, keyB)
	peerDecBKeyA, _ := NewSRTPContext(SuiteAES128CM80, keyA)
	s.SetSRTP(SideA, sbcInA, nil)
	s.SetSRTP(SideB, nil, sbcOutB)
	s.Start()
	ea, eb := dialSide(t, s, SideA), dialSide(t, s, SideB)
	latchBoth(t, ea, eb)

	plain := testRTPPacket()
	cipherA, ok := peerEncA.protectRTP(append([]byte(nil), plain...))
	if !ok {
		t.Fatal("encrypt failed")
	}

	// Send ONCE (T-08/F-09): resending the identical ciphertext would be a
	// replay to the relay's now replay-protected inbound context, i.e. a
	// guaranteed drop instead of loss tolerance.
	if _, err := ea.Write(cipherA); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	deadline := time.Now().Add(3 * time.Second)
	var received []byte
	for {
		_ = eb.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := eb.Read(buf)
		if err == nil {
			got, ok := peerDecBKeyB.unprotectRTP(append([]byte(nil), buf[:n]...))
			if ok && bytes.Equal(got, plain) {
				received = append([]byte(nil), buf[:n]...)
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("A-encrypted packet never arrived at B re-keyed")
		}
	}

	// The keyB context already proved it decrypts correctly (loop above).
	// Now prove keyA does NOT decrypt what arrived at B — the SBC re-keyed,
	// it did not pass the original A-ciphertext through untouched.
	if _, ok := peerDecBKeyA.unprotectRTP(append([]byte(nil), received...)); ok {
		t.Fatal("keyA must NOT decrypt the packet delivered to B; SBC failed to re-key")
	}
}

// TestRelayPlaintextUnchanged is the regression check: with both sides
// plaintext (nil SRTP contexts), behavior must be byte-identical to the
// pre-SRTP relay (same as TestRelayForwardsBothDirections).
func TestRelayPlaintextUnchanged(t *testing.T) {
	s := newLooseSession(t, 41260, 41275, time.Minute)
	s.SetSRTP(SideA, nil, nil)
	s.SetSRTP(SideB, nil, nil)
	s.Start()
	ea := dialSide(t, s, SideA)
	eb := dialSide(t, s, SideB)
	latchBoth(t, ea, eb)
	pump(t, ea, eb, "ping-from-a")
	pump(t, eb, ea, "pong-from-b")
}

// TestRelayTamperedSRTPDropped: a corrupted SRTP packet from a secure A leg
// must never reach B — bad auth tag means fail-closed drop, not passthrough.
func TestRelayTamperedSRTPDropped(t *testing.T) {
	s := newLooseSession(t, 41280, 41295, time.Minute)
	key := mustKey(t)
	peerEnc, _ := NewSRTPContext(SuiteAES128CM80, key)
	sbcInA, _ := NewSRTPContext(SuiteAES128CM80, key)
	s.SetSRTP(SideA, sbcInA, nil)
	s.SetSRTP(SideB, nil, nil)
	s.Start()
	ea, eb := dialSide(t, s, SideA), dialSide(t, s, SideB)
	latchBoth(t, ea, eb)

	plain := testRTPPacket()
	cipher, ok := peerEnc.protectRTP(append([]byte(nil), plain...))
	if !ok {
		t.Fatal("encrypt failed")
	}
	cipher[len(cipher)-1] ^= 0xff // corrupt the auth tag

	buf := make([]byte, 1500)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := ea.Write(cipher); err != nil {
			t.Fatal(err)
		}
		_ = eb.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, err := eb.Read(buf)
		if err == nil {
			t.Fatalf("tampered packet must be dropped, but B received %x", buf[:n])
		}
	}
}
