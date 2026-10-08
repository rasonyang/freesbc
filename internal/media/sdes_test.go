package media

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

// SDES-SRTP leg tests: side A is the SDES side, side B plain RTP. The far
// end of A is pion/srtp driven directly over real loopback UDP. Ports are
// in 21300-21399 (media test band).
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

var sdesSuites = []struct {
	name    string
	suite   SDESSuite
	profile srtp.ProtectionProfile
	saltLen int
}{
	{"cm80", SDESAESCM128HMACSHA180, srtp.ProtectionProfileAes128CmHmacSha1_80, 14},
	{"cm32", SDESAESCM128HMACSHA132, srtp.ProtectionProfileAes128CmHmacSha1_32, 14},
	{"gcm", SDESAEADAES128GCM, srtp.ProtectionProfileAeadAes128Gcm, 12},
}

func sdesKey(suite SDESSuite, saltLen int, fill byte) SDESKey {
	return SDESKey{
		Suite: suite,
		Key:   bytes.Repeat([]byte{fill}, 16),
		Salt:  bytes.Repeat([]byte{fill ^ 0x55}, saltLen),
	}
}

func farCtx(t *testing.T, profile srtp.ProtectionProfile, k SDESKey) *srtp.Context {
	t.Helper()
	c, err := srtp.CreateContext(k.Key, k.Salt, profile)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// sdesRig is one session with SDES on side A.
type sdesRig struct {
	s       *Session
	profile srtp.ProtectionProfile
	salt    int
	suite   SDESSuite
	remote  SDESKey // far end -> FreeSBC
	local   SDESKey // FreeSBC -> far end
	farEnc  *srtp.Context
	farDec  *srtp.Context
	seq     uint16
}

func newSDESRig(t *testing.T, base int, i int) *sdesRig {
	t.Helper()
	su := sdesSuites[i]
	s := newLooseSession(t, base, base+7, time.Minute)
	r := &sdesRig{s: s, profile: su.profile, salt: su.saltLen, suite: su.suite, seq: 1000}
	r.remote = sdesKey(su.suite, su.saltLen, 0x11)
	r.local = sdesKey(su.suite, su.saltLen, 0x22)
	if err := s.SetSDESRemote(SideA, r.remote); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSDESLocal(SideA, r.local); err != nil {
		t.Fatal(err)
	}
	r.farEnc = farCtx(t, su.profile, r.remote)
	r.farDec = farCtx(t, su.profile, r.local)
	s.Start()
	return r
}

func (r *sdesRig) rtpPacket(payload string) []byte {
	r.seq++
	h := rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: r.seq, Timestamp: uint32(r.seq) * 160, SSRC: 0xabcdef01}
	raw, err := (&rtp.Packet{Header: h, Payload: []byte(payload)}).Marshal()
	if err != nil {
		panic(err)
	}
	return raw
}

func (r *sdesRig) srtpPacket(t *testing.T, payload string) []byte {
	t.Helper()
	out, err := r.farEnc.EncryptRTP(nil, r.rtpPacket(payload), nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func readOne(c *net.UDPConn, d time.Duration) ([]byte, bool) {
	buf := make([]byte, 2000)
	_ = c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

func payloadOf(t *testing.T, raw []byte) string {
	t.Helper()
	var p rtp.Packet
	if err := p.Unmarshal(raw); err != nil {
		t.Fatalf("not RTP: %v", err)
	}
	return string(p.Payload)
}

// sendUntil keeps calling send until recv yields a packet satisfying ok.
func sendUntil(t *testing.T, send func(), conn *net.UDPConn, ok func([]byte) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		send()
		if pkt, got := readOne(conn, 100*time.Millisecond); got && ok(pkt) {
			return
		}
	}
	t.Fatal("packet never arrived")
}

func TestSDESRoundTripRTP(t *testing.T) {
	for i, su := range sdesSuites {
		t.Run(su.name, func(t *testing.T) {
			r := newSDESRig(t, 21300+i*8, i)
			a := dialSide(t, r.s, SideA)
			b := dialSide(t, r.s, SideB)
			_, _ = b.Write([]byte{0x80}) // latch B (dropped: junk RTP is plain, not inspected)

			// SRTP in on A -> plain RTP out on B.
			n := 0
			sendUntil(t, func() { n++; _, _ = a.Write(r.srtpPacket(t, fmt.Sprintf("up-%d", n))) }, b,
				func(p []byte) bool { return strings.HasPrefix(payloadOf(t, p), "up-") })

			// Plain RTP in on B -> SRTP out on A, which the far end decrypts.
			sendUntil(t, func() { _, _ = b.Write(r.rtpPacket("down")) }, a, func(p []byte) bool {
				if bytes.Contains(p, []byte("down")) {
					t.Error("plaintext leaked to the SDES side")
				}
				plain, err := r.farDec.DecryptRTP(nil, p, nil)
				return err == nil && payloadOf(t, plain) == "down"
			})
			if st := r.s.Stats().A; st.SRTPRxDrops != 0 || st.SRTPTxDrops != 0 {
				t.Errorf("unexpected drops: %+v", st)
			}
		})
	}
}

func TestSDESRoundTripRTCP(t *testing.T) {
	for i, su := range sdesSuites {
		t.Run(su.name, func(t *testing.T) {
			r := newSDESRig(t, 21324+i*8, i)
			aRTCP, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.s.RTPPort(SideA) + 1})
			if err != nil {
				t.Fatal(err)
			}
			defer aRTCP.Close()
			bRTCP, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.s.RTPPort(SideB) + 1})
			if err != nil {
				t.Fatal(err)
			}
			defer bRTCP.Close()
			_, _ = bRTCP.Write([]byte{0x80}) // latch B's RTCP

			rr, err := (&rtcp.ReceiverReport{SSRC: 0x01020304}).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			sendUntil(t, func() {
				enc, err := r.farEnc.EncryptRTCP(nil, rr, nil)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = aRTCP.Write(enc)
			}, bRTCP, func(p []byte) bool { return bytes.Equal(p, rr) })

			sendUntil(t, func() { _, _ = bRTCP.Write(rr) }, aRTCP, func(p []byte) bool {
				plain, err := r.farDec.DecryptRTCP(nil, p, nil)
				return err == nil && bytes.Equal(plain, rr)
			})
		})
	}
}

func TestSDESBadAuthDroppedAndDoesNotLatch(t *testing.T) {
	r := newSDESRig(t, 21348, 0)
	forger := dialSide(t, r.s, SideA)
	real := dialSide(t, r.s, SideA)
	b := dialSide(t, r.s, SideB)
	_, _ = b.Write([]byte{0x80})

	// A good packet with one flipped bit in the auth tag.
	bad := r.srtpPacket(t, "forged")
	bad[len(bad)-1] ^= 1
	_, _ = forger.Write(bad)
	// Plaintext is not SRTP either.
	_, _ = forger.Write(r.rtpPacket("plain"))
	if _, got := readOne(b, 200*time.Millisecond); got {
		t.Fatal("unauthenticated packet was relayed")
	}
	if d := r.s.Stats().A.SRTPRxDrops; d != 2 {
		t.Errorf("SRTPRxDrops = %d, want 2", d)
	}

	// The forger did not latch A: B's packets reach nobody until a real
	// packet latches, and then reach only the real sender.
	_, _ = b.Write(r.rtpPacket("before"))
	if _, got := readOne(forger, 200*time.Millisecond); got {
		t.Fatal("a forged packet latched the stream")
	}
	sendUntil(t, func() { _, _ = real.Write(r.srtpPacket(t, "real")) }, b,
		func(p []byte) bool { return payloadOf(t, p) == "real" })
	sendUntil(t, func() { _, _ = b.Write(r.rtpPacket("after")) }, real, func(p []byte) bool {
		plain, err := r.farDec.DecryptRTP(nil, p, nil)
		return err == nil && payloadOf(t, plain) == "after"
	})
	if _, got := readOne(forger, 100*time.Millisecond); got {
		t.Error("audio reached the forger")
	}
}

func TestSDESNoKeyFailsClosed(t *testing.T) {
	s := newLooseSession(t, 21356, 21363, time.Minute)
	if err := s.SetSDESLocal(SideA, sdesKey(SDESAESCM128HMACSHA180, 14, 0x22)); err != nil {
		t.Fatal(err)
	}
	// Remote key never set: nothing from A is accepted.
	s.Start()
	a := dialSide(t, s, SideA)
	b := dialSide(t, s, SideB)
	r := &sdesRig{seq: 5}
	_, _ = a.Write(r.rtpPacket("x"))
	if _, got := readOne(b, 150*time.Millisecond); got {
		t.Fatal("packet relayed without a remote key")
	}
	if s.Stats().A.SRTPRxDrops == 0 {
		t.Error("drop not counted")
	}

	// And the reverse direction never emits plaintext without a local key.
	s2 := newLooseSession(t, 21364, 21371, time.Minute)
	if err := s2.SetSDESRemote(SideA, sdesKey(SDESAESCM128HMACSHA180, 14, 0x11)); err != nil {
		t.Fatal(err)
	}
	s2.Start()
	a2 := dialSide(t, s2, SideA)
	b2 := dialSide(t, s2, SideB)
	_, _ = b2.Write([]byte{0x80}) // latch B so A's packets have somewhere to go
	rig := &sdesRig{seq: 9, farEnc: farCtx(t, srtp.ProtectionProfileAes128CmHmacSha1_80, sdesKey(SDESAESCM128HMACSHA180, 14, 0x11))}
	sendUntil(t, func() { _, _ = a2.Write(rig.srtpPacket(t, "hi")) }, b2, func([]byte) bool { return true })
	for i := 0; i < 5; i++ {
		_, _ = b2.Write(rig.rtpPacket("down"))
	}
	if _, got := readOne(a2, 200*time.Millisecond); got {
		t.Fatal("plaintext sent to an SDES side with no local key")
	}
	if s2.Stats().A.SRTPTxDrops == 0 {
		t.Error("tx drop not counted")
	}
}

func TestSDESRekeyMidStream(t *testing.T) {
	r := newSDESRig(t, 21372, 0)
	a := dialSide(t, r.s, SideA)
	b := dialSide(t, r.s, SideB)
	_, _ = b.Write([]byte{0x80})
	sendUntil(t, func() { _, _ = a.Write(r.srtpPacket(t, "k1")) }, b, func(p []byte) bool { return payloadOf(t, p) == "k1" })
	sendUntil(t, func() { _, _ = b.Write(r.rtpPacket("d1")) }, a, func(p []byte) bool {
		plain, err := r.farDec.DecryptRTP(nil, p, nil)
		return err == nil && payloadOf(t, plain) == "d1"
	})
	pa := r.s.RTPPort(SideA)

	// Re-key both directions on the live session.
	newRemote := sdesKey(r.suite, r.salt, 0x33)
	newLocal := sdesKey(r.suite, r.salt, 0x44)
	if err := r.s.SetSDESRemote(SideA, newRemote); err != nil {
		t.Fatal(err)
	}
	if err := r.s.SetSDESLocal(SideA, newLocal); err != nil {
		t.Fatal(err)
	}
	if r.s.RTPPort(SideA) != pa {
		t.Fatal("port changed on re-key")
	}

	// The old key no longer authenticates.
	before := r.s.Stats().A.SRTPRxDrops
	_, _ = a.Write(r.srtpPacket(t, "oldkey"))
	if _, got := readOne(b, 150*time.Millisecond); got {
		t.Fatal("old key still accepted")
	}
	if r.s.Stats().A.SRTPRxDrops != before+1 {
		t.Error("old-key drop not counted")
	}

	r.farEnc = farCtx(t, r.profile, newRemote)
	r.farDec = farCtx(t, r.profile, newLocal)
	sendUntil(t, func() { _, _ = a.Write(r.srtpPacket(t, "k2")) }, b, func(p []byte) bool { return payloadOf(t, p) == "k2" })
	sendUntil(t, func() { _, _ = b.Write(r.rtpPacket("d2")) }, a, func(p []byte) bool {
		plain, err := r.farDec.DecryptRTP(nil, p, nil)
		return err == nil && payloadOf(t, plain) == "d2"
	})
}

func TestSDESSameKeyKeepsState(t *testing.T) {
	r := newSDESRig(t, 21380, 0)
	a := dialSide(t, r.s, SideA)
	b := dialSide(t, r.s, SideB)
	_, _ = b.Write([]byte{0x80})
	pkt := r.srtpPacket(t, "once")
	sendUntil(t, func() { _, _ = a.Write(pkt) }, b, func(p []byte) bool { return payloadOf(t, p) == "once" })

	leg := r.s.sdes[SideA].Load()
	inCtx, outCtx := leg.in.ctx.Load(), leg.out.ctx.Load()
	// A copy with the same bytes, as a re-INVITE repeating the line.
	if err := r.s.SetSDESRemote(SideA, r.remote.clone()); err != nil {
		t.Fatal(err)
	}
	if err := r.s.SetSDESLocal(SideA, r.local.clone()); err != nil {
		t.Fatal(err)
	}
	if leg.in.ctx.Load() != inCtx || leg.out.ctx.Load() != outCtx {
		t.Fatal("same key rebuilt the context")
	}
	// Replay window survived: the already-seen packet is still refused.
	before := r.s.Stats().A.SRTPRxDrops
	_, _ = a.Write(pkt)
	if _, got := readOne(b, 150*time.Millisecond); got {
		t.Fatal("replay accepted after a same-key update")
	}
	if r.s.Stats().A.SRTPRxDrops != before+1 {
		t.Error("replay not counted")
	}
	// And a fresh packet still flows.
	sendUntil(t, func() { _, _ = a.Write(r.srtpPacket(t, "next")) }, b, func(p []byte) bool { return payloadOf(t, p) == "next" })
}

func TestSDESRekeyUnderTraffic(t *testing.T) {
	r := newSDESRig(t, 21388, 0)
	a := dialSide(t, r.s, SideA)
	b := dialSide(t, r.s, SideB)
	_, _ = b.Write([]byte{0x80})
	down := r.rtpPacket("y")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = a.Write(r.srtpPacket(t, "x"))
			time.Sleep(time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = b.Write(down)
			time.Sleep(time.Millisecond)
		}
	}()
	for i := 0; i < 50; i++ {
		fill := byte(0x40 + i%3)
		_ = r.s.SetSDESRemote(SideA, sdesKey(r.suite, r.salt, fill))
		_ = r.s.SetSDESLocal(SideA, sdesKey(r.suite, r.salt, fill))
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

func TestSDESKeyValidationAndRedaction(t *testing.T) {
	s := newLooseSession(t, 21396, 21399, time.Minute)
	good := sdesKey(SDESAESCM128HMACSHA180, 14, 0x77)
	for name, k := range map[string]SDESKey{
		"unknown suite": {Suite: "NOPE", Key: good.Key, Salt: good.Salt},
		"short key":     {Suite: good.Suite, Key: good.Key[:8], Salt: good.Salt},
		"short salt":    {Suite: good.Suite, Key: good.Key, Salt: good.Salt[:4]},
		"gcm cm salt":   {Suite: SDESAEADAES128GCM, Key: good.Key, Salt: good.Salt},
	} {
		err := s.SetSDESRemote(SideB, k)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if bytes.Contains([]byte(err.Error()), good.Key) {
			t.Errorf("%s: error leaks key", name)
		}
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		out := fmt.Sprintf(f, good)
		if strings.Contains(out, fmt.Sprintf("%x", good.Key)) || strings.Contains(out, string(good.Key)) {
			t.Errorf("%s leaks key: %q", f, out)
		}
	}
	// A rejected key leaves the previous one in force.
	if err := s.SetSDESRemote(SideB, good); err != nil {
		t.Fatal(err)
	}
	ctx := s.sdes[SideB].Load().in.ctx.Load()
	if err := s.SetSDESRemote(SideB, SDESKey{Suite: good.Suite, Key: good.Key[:3], Salt: good.Salt}); err == nil {
		t.Fatal("accepted a short key")
	}
	if s.sdes[SideB].Load().in.ctx.Load() != ctx {
		t.Error("failed update replaced the context")
	}
}
