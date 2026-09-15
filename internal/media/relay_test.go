package media

import (
	"net"
	"testing"
	"time"
)

func newLooseSession(t *testing.T, minPort, maxPort int, timeout time.Duration) *Session {
	t.Helper()
	p := testPool(minPort, maxPort)
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

// TestWatchdogNotRefreshedByGarbage is the T-22 (D5-4) red test: traffic
// that passes the latch but fails SRTP authentication must not keep the
// call alive — the silence watchdog may only see AUTHENTICATED media.
// Pre-fix, lastRx refreshed on latch-accept alone, so a party who knows
// the latched source address could renew rtp_timeout indefinitely with
// junk and a dead call never tore down.
func TestWatchdogNotRefreshedByGarbage(t *testing.T) {
	s := newLooseSession(t, 41300, 41315, 500*time.Millisecond)
	key := mustKey(t)
	peerEnc, _ := NewSRTPContext(SuiteAES128CM80, key)
	sbcInA, _ := NewSRTPContext(SuiteAES128CM80, key)
	s.SetSRTP(SideA, sbcInA, nil)
	s.SetSRTP(SideB, nil, nil)
	s.Start()
	ea := dialSide(t, s, SideA)

	// One VALID packet: latches the session and arms the watchdog with a
	// genuine refresh.
	cipher, ok := peerEnc.protectRTP(append([]byte(nil), testRTPPacket()...))
	if !ok {
		t.Fatal("encrypt failed")
	}
	if _, err := ea.Write(cipher); err != nil {
		t.Fatal(err)
	}

	// Hammer garbage that passes the loose latch but fails SRTP auth, well
	// past the 500ms timeout — post-fix the watchdog must still fire.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = ea.Write([]byte("garbage-not-srtp"))
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-s.Done():
		// Watchdog fired despite the garbage stream.
	case <-time.After(2 * time.Second):
		t.Fatal("garbage traffic kept the session alive past rtp_timeout")
	}
}

// TestWatchdogRefreshedByValidSRTP is T-22's counterpart: AUTHENTICATED
// media must keep renewing the watchdog — the fix gates the refresh, it
// doesn't break legitimate keepalive.
func TestWatchdogRefreshedByValidSRTP(t *testing.T) {
	s := newLooseSession(t, 41320, 41335, 500*time.Millisecond)
	key := mustKey(t)
	peerEnc, _ := NewSRTPContext(SuiteAES128CM80, key)
	sbcInA, _ := NewSRTPContext(SuiteAES128CM80, key)
	s.SetSRTP(SideA, sbcInA, nil)
	s.SetSRTP(SideB, nil, nil)
	s.Start()
	ea := dialSide(t, s, SideA)

	// Valid packets every 200ms (well under the 500ms timeout) keep the
	// session alive for 1.2s — more than double the timeout.
	deadline := time.Now().Add(1200 * time.Millisecond)
	seq := byte(0)
	for time.Now().Before(deadline) {
		plain := testRTPPacket()
		plain[2], plain[3] = 0, seq // distinct seq per packet (SRTP index)
		seq++
		cipher, ok := peerEnc.protectRTP(plain)
		if !ok {
			t.Fatal("encrypt failed")
		}
		if _, err := ea.Write(cipher); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	select {
	case <-s.Done():
		t.Fatal("authenticated media must keep the session alive")
	default:
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
	p := testPool(41200, 41203) // exactly one session's worth
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
	p := testPool(41260, 41267)
	s, err := p.Allocate(SessionConfig{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer recoverRelayPanic(nil, s.Close)
		panic("injected relay bug")
	}()
	<-finished
	select {
	case <-s.Done():
	default:
		t.Fatal("session must be closed after a relay panic")
	}
}
