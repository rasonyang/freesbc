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

func TestLatchStrictWithoutExpectationAcceptsFirst(t *testing.T) {
	l := &latch{mode: LatchStrict}
	if !l.accept(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9}) {
		t.Fatal("strict mode without an expectation must accept the first packet")
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
