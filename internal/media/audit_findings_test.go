package media

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// audit: P2-MED-001
//
// Close called while establish is still building the ICE mux/agent must
// still tear the agent down. establish stores l.mux/l.agent without
// checking for legClosed (webrtcleg.go:270-293), and Close snapshots the
// handles only once (webrtcleg.go:525), so an agent created after Close is
// never closed and its goroutines outlive the leg.
func TestAuditMED001CloseRacingEstablishLeaksICEAgent(t *testing.T) {
	pool := newAuditPool("public", 24000, 24099, "127.0.0.1")
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
		RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
	}
	// Warm up pion's package-level state so it is not counted as a leak.
	warm, err := NewWebRTCLeg(pool.PlanePool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	warm.Start(context.Background(), 100*time.Millisecond)
	<-warm.Ready()
	baseline, _ := auditWaitGoroutines(0, 0, 500*time.Millisecond)

	const n = 40
	const establishTimeout = 300 * time.Millisecond
	legs := make([]*WebRTCLeg, 0, n)
	for i := 0; i < n; i++ {
		leg, err := NewWebRTCLeg(pool.PlanePool, cfg)
		if err != nil {
			t.Fatal(err)
		}
		leg.Start(context.Background(), establishTimeout)
		// Spin 0-2 ms so Close lands at different points of establish.
		spin := time.Duration(rand.IntN(2000)) * time.Microsecond
		for start := time.Now(); time.Since(start) < spin; {
		}
		_ = leg.Close()
		legs = append(legs, leg)
	}
	for _, leg := range legs {
		select {
		case <-leg.Ready():
		case <-time.After(5 * time.Second):
			t.Fatal("a closed leg never fired Ready")
		}
	}
	time.Sleep(establishTimeout + 200*time.Millisecond) // let establish give up
	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("pool in use after closing every leg: %d, want 0", inUse)
	}
	got, ok := auditWaitGoroutines(baseline, 2, 5*time.Second)
	if !ok {
		s := auditGoroutineSummary("pion/ice", "pion/transport", "media.(*WebRTCLeg)")
		t.Errorf("FACT P2-MED-001: goroutines did not return to baseline after %d Close-during-establish legs: baseline=%d now=%d (+%d); stacks mentioning %v",
			n, baseline, got, got-baseline, s)
	}
}

// audit: P2-MED-002
//
// The relay starts as soon as DTLS completes (webrtcsession.go:169-172);
// the signalled a=fingerprint is checked only by a later, separate
// VerifyFingerprint call (edge/media.go:249). Here the browser's DTLS
// certificate does NOT match what it "signalled", and its SRTP still
// reaches FreeSWITCH before anyone verifies.
func TestAuditMED002MediaFlowsBeforeFingerprintVerified(t *testing.T) {
	c := auditEstablishBrowserCall(t, 24100, 24139, 24140, 24179)

	other, err := selfSignedForTest()
	if err != nil {
		t.Fatal(err)
	}
	signalled := fingerprintOf(other) // what the SDP offer claimed

	pkt := rtpPacket(0, 4242, 160)
	prot, ok := c.browserOut.protectRTP(pkt)
	if !ok {
		t.Fatal("browser could not protect its RTP")
	}
	if _, err := c.bDemux.srtp.Write(prot); err != nil {
		t.Fatal(err)
	}
	_ = c.fsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2000)
	n, _, err := c.fsConn.ReadFromUDP(buf)
	delivered := err == nil && string(buf[:n]) == string(pkt)

	// Sanity: the peer really is not who the signalling said.
	if verr := c.leg.VerifyFingerprint("sha-256", signalled); !errors.Is(verr, ErrFingerprintMismatch) {
		t.Fatalf("precondition: VerifyFingerprint(signalled) = %v, want ErrFingerprintMismatch", verr)
	}
	if delivered {
		t.Errorf("FACT P2-MED-002: SRTP from a DTLS peer whose certificate does not match the signalled fingerprint was decrypted and delivered to the private side before VerifyFingerprint ran")
	}
}

// audit: P2-MED-003
//
// latch.seed (session.go:91-102) accepts any valid address with a
// non-zero port. The unspecified address means hold (RFC 3264 §8.4), and
// multicast, link-local and unspecified addresses are never a valid RTP
// unicast destination learned from a public client's SDP.
func TestAuditMED003SeedAcceptsNonUnicastDestinations(t *testing.T) {
	for _, s := range []string{
		"0.0.0.0:4000",
		"[::]:4000",
		"224.0.0.1:4000",
		"239.1.2.3:4000",
		"255.255.255.255:4000",
		"169.254.1.1:4000",
		"[ff02::1]:4000",
		"[fe80::1]:4000",
	} {
		t.Run(s, func(t *testing.T) {
			l := &latch{mode: LatchLoose}
			l.seed(netip.MustParseAddrPort(s))
			if dst := l.target(); dst != nil {
				t.Errorf("FACT P2-MED-003: seed(%s) installed %v as the relay destination", s, dst)
			}
		})
	}
}

// audit: P2-MED-003
//
// End to end: a public client's SDP names a loopback (resp. unspecified)
// media address, and the SBC's public media socket relays FreeSWITCH
// audio to a local service there. The fix must be policy-scoped: several
// lab setups (and this package's tests) legitimately use loopback, so
// this test records the reflection; it does not by itself say loopback
// must always be refused.
func TestAuditMED003SeedReflectsToLocalService(t *testing.T) {
	for _, tc := range []struct{ name, bind, seedIP string }{
		{"loopback", "127.0.0.1", "127.0.0.1"},
		{"unspecified", "0.0.0.0", "0.0.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := newAuditPool("audit", 24180, 24199, "127.0.0.1")
			s, err := pool.Allocate(SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchStrict}, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			victim := auditUDP(t, tc.bind)
			vport := victim.LocalAddr().(*net.UDPAddr).Port
			fs := auditUDP(t, "127.0.0.1")
			s.SetRemote(SideA, netip.AddrPortFrom(netip.MustParseAddr(tc.seedIP), uint16(vport)))
			s.SetRemote(SideB, auditAddrPort(fs))
			s.Start()

			dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideB)}
			buf := make([]byte, 1500)
			got := false
			for i := 0; i < 10 && !got; i++ {
				if _, err := fs.WriteToUDP([]byte("fs-audio"), dst); err != nil {
					t.Fatal(err)
				}
				_ = victim.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if n, _, err := victim.ReadFromUDP(buf); err == nil && string(buf[:n]) == "fs-audio" {
					got = true
				}
			}
			if got {
				t.Errorf("FACT P2-MED-003: relay sent RTP to %s:%d, a destination taken verbatim from the public side's SDP", tc.seedIP, vport)
			}
		})
	}
}

// audit: P2-MED-004
//
// One lastRx is shared by both directions (relay.go:77, :99-122). Side A
// has gone away (BYE lost) while side B keeps streaming: the watchdog
// must still reclaim the call, but B's packets keep refreshing lastRx.
func TestAuditMED004OneWaySilenceNeverReclaimed(t *testing.T) {
	pool := newAuditPool("audit", 24200, 24219, "127.0.0.1")
	const timeout = 200 * time.Millisecond
	s, err := pool.Allocate(SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchLoose}, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetRemote(SideA, netip.MustParseAddrPort("127.0.0.1:9")) // the dead phone
	s.Start()
	b, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideB)})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				_, _ = b.Write([]byte("moh"))
			}
		}
	}()
	window := 8 * timeout
	select {
	case <-s.Done():
	case <-time.After(window):
		t.Errorf("FACT P2-MED-004: side A silent for %v (rtp_timeout %v) while side B streams; session was never reclaimed", window, timeout)
	}
}

// audit: P2-MED-006
//
// LatchLoose (session.go:112-127) latches the first packet from any
// source. An attacker on another host sends one packet to the public
// port before the real phone; afterwards the phone is ignored and
// FreeSWITCH audio goes to the attacker. Needs 127.0.0.2 (Linux).
func TestAuditMED006LooseLatchFirstPacketHijack(t *testing.T) {
	pool := newAuditPool("audit", 24220, 24239, "")
	s, err := pool.Allocate(SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchStrict}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	attacker := auditUDP(t, "127.0.0.2")
	phone := auditUDP(t, "127.0.0.1")
	fs := auditUDP(t, "127.0.0.1")
	s.SetRemote(SideA, auditAddrPort(phone)) // the phone's signalled c=/m=
	s.SetRemote(SideB, auditAddrPort(fs))
	s.Start()

	pubPort := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideA)}
	privPort := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideB)}
	if _, err := attacker.WriteToUDP([]byte("evil"), pubPort); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	buf := make([]byte, 1500)
	phoneHeard := false
	for i := 0; i < 10 && !phoneHeard; i++ {
		msg := fmt.Sprintf("phone-%d", i)
		_, _ = phone.WriteToUDP([]byte(msg), pubPort)
		_ = fs.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		for {
			n, _, err := fs.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if strings.HasPrefix(string(buf[:n]), "phone-") {
				phoneHeard = true
			}
		}
	}
	_, _ = fs.WriteToUDP([]byte("fs-audio"), privPort)
	_ = attacker.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _, err := attacker.ReadFromUDP(buf)
	attackerHeard := err == nil && string(buf[:n]) == "fs-audio"

	if !phoneHeard {
		t.Errorf("FACT P2-MED-006: after one packet from 127.0.0.2, the signalled phone (%s) is never relayed to FreeSWITCH", phone.LocalAddr())
	}
	if attackerHeard {
		t.Errorf("FACT P2-MED-006: FreeSWITCH audio is delivered to the attacker 127.0.0.2, not the phone")
	}
}

// audit: P2-MED-011
//
// After a hot reload shrinks the port range, Stats reports inUse from the
// old reservations against the new total (portpool.go:154-170).
func TestAuditMED011StatsInUseExceedsTotalAfterShrink(t *testing.T) {
	pool := newAuditPool("audit", 24240, 24251, "127.0.0.1") // 6 pairs
	var pairs []*portPair
	for i := 0; i < 3; i++ {
		pp, err := pool.allocatePair()
		if err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, pp)
	}
	defer func() {
		for _, pp := range pairs {
			pp.Close()
			pool.release(pp.RTPPort())
		}
	}()
	pool.setRange(24240, 24243) // 2 pairs
	inUse, total := pool.Stats()
	if inUse > total {
		t.Errorf("FACT P2-MED-011: Stats after range shrink reports inUse=%d > total=%d", inUse, total)
	}
}

// audit: P2-MED-007
//
// SRTP protect/unprotect pass nil dst/header to pion (srtp.go:118-139),
// so each packet allocates. The relay is otherwise allocation-free per
// packet; this reports the per-packet cost.
func TestAuditMED007SRTPAllocsPerPacket(t *testing.T) {
	key := NewSDESKey()
	send, err := NewSRTPContext(SuiteAES128CM80, key)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := NewSRTPContext(SuiteAES128CM80, key)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := NewSRTPContext(SuiteAES128CM80, key)
	if err != nil {
		t.Fatal(err)
	}
	const runs = 1000
	plain := make([][]byte, runs+2)
	prot := make([][]byte, runs+2)
	for i := range plain {
		plain[i] = rtpPacket(0, uint16(i+1), 160)
		p, ok := gen.protectRTP(rtpPacket(0, uint16(i+1), 160))
		if !ok {
			t.Fatal("protect")
		}
		prot[i] = p
	}
	i := 0
	protectAllocs := testing.AllocsPerRun(runs, func() {
		_, _ = send.protectRTP(plain[i])
		i++
	})
	j := 0
	unprotectAllocs := testing.AllocsPerRun(runs, func() {
		if _, ok := recv.unprotectRTP(prot[j]); !ok {
			panic("unprotect failed")
		}
		j++
	})
	t.Logf("P2-MED-007: allocs/packet protectRTP=%.1f unprotectRTP=%.1f", protectAllocs, unprotectAllocs)
	if protectAllocs > 0 || unprotectAllocs > 0 {
		t.Errorf("FACT P2-MED-007: per-packet heap allocations on the SRTP relay path: protectRTP=%.1f unprotectRTP=%.1f", protectAllocs, unprotectAllocs)
	}
}

// audit: P3-MED-001
//
// Found by FuzzAuditSRTPUnprotect (corpus entry
// testdata/fuzz/FuzzAuditSRTPUnprotect/666d63480a603d0b). A plaintext RTP
// packet carrying a non-RFC-8285 header extension of length 0 (RFC 3550
// §5.3.1 allows any profile and length 0) is accepted by protectRTP, but the SRTP it produces fails
// unprotectRTP under the same key. On an RTP→SRTP interworking call the
// relay (relay.go:80-89) forwards such packets as undecryptable SRTP.
func TestAuditMED_P3_001SRTPRoundTripEmptyHeaderExtension(t *testing.T) {
	key := NewSDESKey()
	// V=2, X=1, then the minimised fuzz input: extension profile 0xC2DE
	// (neither RFC 8285 one-byte nor two-byte), length 0, 1-byte payload.
	pkt := []byte("\x9000000000000\xc2\xde\x00\x000")[:17]
	pkt[0] = 0x90
	send, _ := NewSRTPContext(SuiteAES128CM80, key)
	recv, _ := NewSRTPContext(SuiteAES128CM80, key)
	prot, ok := send.protectRTP(append([]byte(nil), pkt...))
	if !ok {
		t.Skip("protectRTP rejected the packet; nothing is forwarded")
	}
	got, ok := recv.unprotectRTP(prot)
	if !ok || string(got) != string(pkt) {
		t.Errorf("FACT P3-MED-001: RTP with a zero-length 0xC2DE header extension: protectRTP ok, unprotectRTP ok=%v equal=%v", ok, string(got) == string(pkt))
	}
}
