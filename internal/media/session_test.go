package media

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestLatchStrictRejectsWrongSource(t *testing.T) {
	l := &latch{mode: LatchStrict}
	l.setExpected(netip.MustParseAddr("203.0.113.9"))
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4444}
	if l.accept(src) {
		t.Fatal("wrong source must not latch in strict mode")
	}
	if l.target() != nil {
		t.Fatal("latch must remain empty after rejection")
	}
	l.setExpected(netip.MustParseAddr("127.0.0.1"))
	if !l.accept(src) {
		t.Fatal("matching source must latch")
	}
}

func TestLatchStrictRejectsUntilArmed(t *testing.T) {
	l := &latch{mode: LatchStrict}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9}
	if l.accept(src) {
		t.Fatal("strict mode must reject packets before SetExpectedRemote arms the latch")
	}
	l.setExpected(netip.MustParseAddr("10.0.0.1"))
	if !l.accept(src) {
		t.Fatal("after arming with the matching IP, the first packet must latch")
	}
}

func TestLatchNeverMoves(t *testing.T) {
	l := &latch{mode: LatchLoose}
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111}
	hijack := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
	if !l.accept(first) {
		t.Fatal("first packet must latch")
	}
	if l.accept(hijack) {
		t.Fatal("a different source must be dropped after latching")
	}
	if got := l.target(); got == nil || got.Port != 1111 {
		t.Fatalf("latch moved: %v", got)
	}
	if !l.accept(first) {
		t.Fatal("the latched source must stay accepted")
	}
}

// TestLatchSymmetricOverridesSDPSeedNAT is the regression test for a
// one-way-audio bug: a phone behind a hard NAT puts an unroutable fake IP
// (198.18.0.1:55135) in its SDP c= line but its RTP actually arrives from
// the NATed source 183.241.147.126:50699. The loose ("symmetric") latch —
// the proxy's public-leg policy — must accept that first packet and move
// the send-destination to the real source; strict latching must keep
// rejecting it, which is what starved the relay.
func TestLatchSymmetricOverridesSDPSeedNAT(t *testing.T) {
	sdpAddr := netip.MustParseAddrPort("198.18.0.1:55135")
	natSrc := &net.UDPAddr{IP: net.IPv4(183, 241, 147, 126), Port: 50699}

	// Symmetric: seed still provides a provisional destination before any
	// packet arrives, then the first packet from ANY source latches and
	// redirects outbound media to the real NATed address.
	sym := &latch{mode: LatchLoose}
	sym.seed(sdpAddr)
	if got := sym.target(); got == nil || got.String() != sdpAddr.String() {
		t.Fatalf("seed must provide a provisional destination before the first packet, got %v", got)
	}
	if !sym.accept(natSrc) {
		t.Fatal("symmetric latch must accept the first packet even though its source IP differs from the SDP IP")
	}
	if got := sym.target(); got == nil || !got.IP.Equal(natSrc.IP) || got.Port != natSrc.Port {
		t.Fatalf("send-destination must relatch to the real packet source, got %v", got)
	}

	// Strict: the same first packet is rejected — the source IP must equal
	// the SDP IP (only the port may differ), so the seeded destination
	// stands and the stream stays one-way.
	strict := &latch{mode: LatchStrict}
	strict.seed(sdpAddr)
	if strict.accept(natSrc) {
		t.Fatal("strict latch must reject a first packet whose source IP differs from the SDP IP")
	}
	if got := strict.target(); got == nil || got.String() != sdpAddr.String() {
		t.Fatalf("strict latch must keep the seeded destination after rejecting, got %v", got)
	}
}

func TestRelatchMovesToNewRemote(t *testing.T) {
	l := &latch{mode: LatchStrict}
	l.setExpected(netip.MustParseAddr("10.0.0.1"))
	first := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1000}
	if !l.accept(first) {
		t.Fatal("initial arm+latch failed")
	}
	// A re-INVITE moves media to a new address; Relatch re-arms.
	l.relatch(netip.MustParseAddr("10.0.0.2"))
	if l.accept(first) {
		t.Fatal("after relatch, the old remote must no longer be accepted")
	}
	newRemote := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2000}
	if !l.accept(newRemote) {
		t.Fatal("after relatch, the new expected IP must latch")
	}
}

func TestSessionRelatchBothKinds(t *testing.T) {
	p := NewPool(testStore(40500, 40507))
	s, err := p.Allocate(SessionConfig{Latch: [2]LatchMode{LatchStrict, LatchStrict}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetExpectedRemote(SideB, netip.MustParseAddr("10.0.0.1"))
	s.Relatch(SideB, netip.MustParseAddr("10.0.0.9"))
	if !s.rtp[SideB].accept(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 1}) {
		t.Error("rtp latch not relatched")
	}
	if !s.rtcp[SideB].accept(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 2}) {
		t.Error("rtcp latch not relatched")
	}
}

// TestSetLatchModeChangesAcceptBehavior proves setMode actually changes a
// latch's runtime accept policy: a loose latch accepts a first packet from
// anywhere, and switching it to strict (before anything has latched) makes
// it reject again until armed — mirroring what a failover winner with a
// different media_latch than the pre-dial default needs.
func TestSetLatchModeChangesAcceptBehavior(t *testing.T) {
	l := &latch{mode: LatchLoose}
	first := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 5000}
	if !l.accept(first) {
		t.Fatal("loose mode must accept the first packet from any source")
	}

	l2 := &latch{mode: LatchLoose}
	l2.setMode(LatchStrict)
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 5001}
	if l2.accept(src) {
		t.Fatal("after setMode(strict) with no expectation armed, packets must be rejected")
	}
	l2.setExpected(netip.MustParseAddr("198.51.100.2"))
	if !l2.accept(src) {
		t.Fatal("after arming with the matching IP, the first packet must latch")
	}
}

// TestSessionSetLatchModeChangesBothKinds mirrors
// TestSessionRelatchBothKinds: SetLatchMode on a Session must flip both the
// RTP and RTCP latches of the given side, not just one of them.
func TestSessionSetLatchModeChangesBothKinds(t *testing.T) {
	p := NewPool(testStore(40510, 40517))
	s, err := p.Allocate(SessionConfig{Latch: [2]LatchMode{LatchStrict, LatchStrict}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Strict with no expectation set: both latches reject.
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 4000}
	if s.rtp[SideB].accept(src) || s.rtcp[SideB].accept(src) {
		t.Fatal("strict latches must reject before SetLatchMode/SetExpectedRemote")
	}

	s.SetLatchMode(SideB, LatchLoose)
	if !s.rtp[SideB].accept(src) {
		t.Error("rtp latch not switched to loose")
	}
	if !s.rtcp[SideB].accept(src) {
		t.Error("rtcp latch not switched to loose")
	}
}

func TestParseLatchMode(t *testing.T) {
	if ParseLatchMode("loose") != LatchLoose {
		t.Error("loose")
	}
	if ParseLatchMode("strict") != LatchStrict || ParseLatchMode("") != LatchStrict {
		t.Error("strict default")
	}
}

func TestAllocateAndPorts(t *testing.T) {
	p := NewPool(testStore(40300, 40315))
	s, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer s.Close()
	a, b := s.RTPPort(SideA), s.RTPPort(SideB)
	if a%2 != 0 || b%2 != 0 || a == b {
		t.Errorf("bad ports: A=%d B=%d", a, b)
	}
}

func TestAllocateDefaultsTimeoutFromConfig(t *testing.T) {
	p := NewPool(testStore(40320, 40327))
	s, err := p.Allocate(SessionConfig{}) // zero timeout
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.timeout != 5*time.Minute {
		t.Errorf("timeout = %v, want config default 5m", s.timeout)
	}
}

func TestSessionCloseIdempotentAndReleases(t *testing.T) {
	p := NewPool(testStore(40400, 40403)) // exactly 2 pairs = 1 session
	s, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Allocate(SessionConfig{Timeout: time.Minute}); err == nil {
		t.Fatal("second session must exhaust the 2-pair range")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("Close must be idempotent")
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("Done must be closed after Close")
	}
	s2, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("ports not released by Close: %v", err)
	}
	s2.Close()
}
