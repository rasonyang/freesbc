package media

import (
	"net"
	"testing"
	"time"
)

func newLooseSession(t *testing.T, minPort, maxPort int, timeout time.Duration) *Session {
	t.Helper()
	p := NewPool(testStore(minPort, maxPort))
	s, err := p.Allocate(SessionConfig{
		Latch:   [2]LatchMode{LatchLoose, LatchLoose},
		Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func dialSide(t *testing.T, s *Session, side Side) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(side),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// pump sends payload from src until dst receives exactly it, tolerating
// earlier packets still in flight. Both endpoints must already have sent
// one packet so their side is latched.
func pump(t *testing.T, src, dst *net.UDPConn, payload string) {
	t.Helper()
	buf := make([]byte, 1500)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := src.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		_ = dst.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := dst.Read(buf)
		if err == nil && string(buf[:n]) == payload {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("packet %q never forwarded", payload)
		}
	}
}

func TestRelayForwardsBothDirections(t *testing.T) {
	s := newLooseSession(t, 41000, 41015, time.Minute)
	s.Start()
	ea := dialSide(t, s, SideA)
	eb := dialSide(t, s, SideB)
	// First packet from each endpoint latches its side.
	if _, err := ea.Write([]byte("latch-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := eb.Write([]byte("latch-b")); err != nil {
		t.Fatal(err)
	}
	pump(t, ea, eb, "ping-from-a")
	pump(t, eb, ea, "pong-from-b")
}

func TestRelayDropsHijackPackets(t *testing.T) {
	s := newLooseSession(t, 41100, 41115, time.Minute)
	s.Start()
	ea := dialSide(t, s, SideA)
	eb := dialSide(t, s, SideB)
	if _, err := ea.Write([]byte("latch-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := eb.Write([]byte("latch-b")); err != nil {
		t.Fatal(err)
	}
	pump(t, ea, eb, "establish")

	// Same IP, different source port: must be dropped, latch must not move.
	hijacker := dialSide(t, s, SideA)
	if _, err := hijacker.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = eb.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		n, err := eb.Read(buf)
		if err != nil {
			break // drained: nothing (more) arrived
		}
		if string(buf[:n]) == "evil" {
			t.Fatal("hijack packet was forwarded")
		}
	}
	// The legitimate stream still works.
	pump(t, ea, eb, "still-alive")
}

func TestRelaySilenceTimeoutReleasesPorts(t *testing.T) {
	p := NewPool(testStore(41200, 41203)) // exactly one session's worth
	s, err := p.Allocate(SessionConfig{
		Latch:   [2]LatchMode{LatchLoose, LatchLoose},
		Timeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not tear down on RTP silence")
	}
	s2, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("ports not released after silence teardown: %v", err)
	}
	s2.Close()
}

func TestRelayActivityDefersTimeout(t *testing.T) {
	s := newLooseSession(t, 41250, 41257, 500*time.Millisecond)
	s.Start()
	ea := dialSide(t, s, SideA)
	// Keep the session alive for ~3 timeout periods with steady traffic.
	stop := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(stop) {
		if _, err := ea.Write([]byte("keepalive")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.Done():
			t.Fatal("session timed out despite steady traffic")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func TestRelayPanicRecoveryKillsSession(t *testing.T) {
	p := NewPool(testStore(41260, 41267))
	s, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer s.recoverRelayPanic()
		panic("injected relay bug")
	}()
	<-finished
	select {
	case <-s.Done():
	default:
		t.Fatal("session must be closed after a relay panic")
	}
}
