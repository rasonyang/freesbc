package media

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
)

// a minimal well-formed RTP packet (V=2, PT=0, seq=1, ts=0, ssrc=0x1234).
func testRTPPacket() []byte {
	return []byte{
		0x80, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x12, 0x34,
		0xde, 0xad, 0xbe, 0xef, // 4 bytes payload
	}
}

// a minimal RTCP receiver report (V=2, PT=201, len=1, ssrc).
func testRTCPPacket() []byte {
	return []byte{
		0x80, 0xc9, 0x00, 0x01,
		0x00, 0x00, 0x12, 0x34,
	}
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, SDESKeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestSRTPContextRoundTripRTP(t *testing.T) {
	key := mustKey(t)
	enc, err := NewSRTPContext(SuiteAES128CM80, key)
	if err != nil {
		t.Fatalf("enc ctx: %v", err)
	}
	dec, err := NewSRTPContext(SuiteAES128CM80, key)
	if err != nil {
		t.Fatalf("dec ctx: %v", err)
	}
	plain := testRTPPacket()
	cipher, ok := enc.protectRTP(append([]byte(nil), plain...))
	if !ok {
		t.Fatal("protectRTP failed")
	}
	if bytes.Equal(cipher, plain) {
		t.Fatal("ciphertext equals plaintext (not encrypted)")
	}
	got, ok := dec.unprotectRTP(cipher)
	if !ok {
		t.Fatal("unprotectRTP failed")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: got %x want %x", got, plain)
	}
}

func TestSRTPContextRoundTripRTCP(t *testing.T) {
	key := mustKey(t)
	enc, _ := NewSRTPContext(SuiteAES128CM32, key)
	dec, _ := NewSRTPContext(SuiteAES128CM32, key)
	plain := testRTCPPacket()
	cipher, ok := enc.protectRTCP(append([]byte(nil), plain...))
	if !ok {
		t.Fatal("protectRTCP failed")
	}
	got, ok := dec.unprotectRTCP(cipher)
	if !ok {
		t.Fatal("unprotectRTCP failed")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("rtcp round trip mismatch: got %x want %x", got, plain)
	}
}

func TestSRTPContextTamperedPacketDropped(t *testing.T) {
	key := mustKey(t)
	enc, _ := NewSRTPContext(SuiteAES128CM80, key)
	dec, _ := NewSRTPContext(SuiteAES128CM80, key)
	cipher, _ := enc.protectRTP(testRTPPacket())
	cipher[len(cipher)-1] ^= 0xff // corrupt the auth tag
	if _, ok := dec.unprotectRTP(cipher); ok {
		t.Fatal("tampered packet must fail auth (ok=false)")
	}
}

func TestSRTPContextWrongKeyDropped(t *testing.T) {
	enc, _ := NewSRTPContext(SuiteAES128CM80, mustKey(t))
	dec, _ := NewSRTPContext(SuiteAES128CM80, mustKey(t)) // different key
	cipher, _ := enc.protectRTP(testRTPPacket())
	if _, ok := dec.unprotectRTP(cipher); ok {
		t.Fatal("wrong-key decrypt must fail (ok=false)")
	}
}

func TestSRTPContextBadKeyLength(t *testing.T) {
	if _, err := NewSRTPContext(SuiteAES128CM80, make([]byte, 10)); err == nil {
		t.Fatal("want error for short key value")
	}
}

// TestSRTPReplayDropped (T-08/F-09) is the RFC 3711 §3.3.2/§3.4.2 replay
// guard: decrypting the SAME ciphertext twice must fail the second time —
// a captured valid packet must never be re-injected into the stream.
func TestSRTPReplayDropped(t *testing.T) {
	key := mustKey(t)
	enc, _ := NewSRTPContext(SuiteAES128CM80, key)
	dec, _ := NewSRTPContext(SuiteAES128CM80, key)
	cipher, ok := enc.protectRTP(testRTPPacket())
	if !ok {
		t.Fatal("protectRTP failed")
	}
	if _, ok := dec.unprotectRTP(cipher); !ok {
		t.Fatal("first decrypt of a fresh packet must succeed")
	}
	if _, ok := dec.unprotectRTP(cipher); ok {
		t.Fatal("second decrypt of the SAME ciphertext must fail as a replay")
	}
}

// TestSRTCPReplayDropped is TestSRTPReplayDropped's RTCP counterpart (the
// RTCP replay detector is a separate window, so it needs its own guard).
func TestSRTCPReplayDropped(t *testing.T) {
	key := mustKey(t)
	enc, _ := NewSRTPContext(SuiteAES128CM32, key)
	dec, _ := NewSRTPContext(SuiteAES128CM32, key)
	cipher, ok := enc.protectRTCP(testRTCPPacket())
	if !ok {
		t.Fatal("protectRTCP failed")
	}
	if _, ok := dec.unprotectRTCP(cipher); !ok {
		t.Fatal("first rtcp decrypt of a fresh packet must succeed")
	}
	if _, ok := dec.unprotectRTCP(cipher); ok {
		t.Fatal("second rtcp decrypt of the SAME ciphertext must fail as a replay")
	}
}

// TestSRTPReplayWindowAcceptsOutOfOrder: distinct packets arriving out of
// order but within the window must still decrypt — replay protection rejects
// replayed/too-old packets, never legitimate jitter. The packets must carry
// DISTINCT sequence numbers: pion derives the SRTP index from the packet's
// own seq field (not an internal counter), so encrypting the same bytes
// three times would just produce one ciphertext three times.
func TestSRTPReplayWindowAcceptsOutOfOrder(t *testing.T) {
	key := mustKey(t)
	enc, _ := NewSRTPContext(SuiteAES128CM80, key)
	dec, _ := NewSRTPContext(SuiteAES128CM80, key)
	plain := testRTPPacket()
	p1 := append([]byte(nil), plain...)
	p2 := append([]byte(nil), plain...)
	p2[2], p2[3] = 0, 2
	p3 := append([]byte(nil), plain...)
	p3[2], p3[3] = 0, 3
	c0, ok := enc.protectRTP(p1)
	if !ok {
		t.Fatal("protect 0 failed")
	}
	c1, _ := enc.protectRTP(p2)
	c2, _ := enc.protectRTP(p3)
	// Deliver out of order — all three are distinct packets inside the
	// window and must be accepted.
	for _, c := range [][]byte{c2, c0, c1} {
		if _, ok := dec.unprotectRTP(c); !ok {
			t.Fatal("out-of-order packet within the replay window was rejected")
		}
	}
	// A true replay of an already-accepted packet must still fail.
	if _, ok := dec.unprotectRTP(c0); ok {
		t.Fatal("replay of an already-accepted packet must fail")
	}
}

// One context shared by an RTP goroutine and an RTCP goroutine (as the relay
// does) must be race-free — the wrapper's mutex guards pion's lockless Context.
func TestSRTPContextConcurrentRTPandRTCP(t *testing.T) {
	key := mustKey(t)
	enc, _ := NewSRTPContext(SuiteAES128CM80, key)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); enc.protectRTP(testRTPPacket()) }()
		go func() { defer wg.Done(); enc.protectRTCP(testRTCPPacket()) }()
	}
	wg.Wait() // -race is the assertion
}

func TestNewSDESKeyLengthAndRandomness(t *testing.T) {
	a := NewSDESKey()
	if len(a) != SDESKeyLen {
		t.Fatalf("key value len=%d, want %d", len(a), SDESKeyLen)
	}
	if string(a) == string(NewSDESKey()) {
		t.Fatal("two generated keys are identical (not random)")
	}
}

func TestParseCryptoSuiteRoundTrip(t *testing.T) {
	for _, want := range []CryptoSuite{SuiteAES128CM80, SuiteAES128CM32} {
		got, ok := ParseCryptoSuite(want.String())
		if !ok || got != want {
			t.Errorf("ParseCryptoSuite(%q) = %v/%v, want %v/true", want.String(), got, ok, want)
		}
	}
	for _, name := range []string{"AES_256_CM_HMAC_SHA1_80", "", "aes_cm_128_hmac_sha1_80"} {
		if _, ok := ParseCryptoSuite(name); ok {
			t.Errorf("ParseCryptoSuite(%q) accepted an unsupported suite", name)
		}
	}
}
