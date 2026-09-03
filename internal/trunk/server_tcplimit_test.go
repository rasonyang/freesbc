package trunk

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// tcpLimitCfg is TestTCPIdleTimeoutClosesConn's own listener/peer set: a TCP
// listener only (no UDP — the test exercises the wrapped TCP accept path),
// on a port no other test uses.
const tcpLimitCfg = `
listen:
  sip: [tcp://127.0.0.1:45710]
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
routes:
  - name: in
    from: local-uac
    to: [local-uac]
`

// dialTCPWithRetry dials addr until the connection is accepted. startServer
// already waits for the listener socket to be bound (srv.onListening), but
// the accept loop starts a moment later, so a short retry keeps this
// robust.
func dialTCPWithRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tcp listener %s not reachable", addr)
	return nil
}

// TestTCPIdleTimeoutClosesConn is the T-05 (F-02) red test: connect to the
// TCP listener, send half a request line (no terminating CRLF), then go
// silent — the wrapped listener's per-connection idle read deadline must
// close the connection. Without the wrapper, sipgo v1.4.3 has no read
// timeout at all (transport_tcp.go readConnection), so the connection would
// stay open forever and this test would hang until its own deadline fails.
func TestTCPIdleTimeoutClosesConn(t *testing.T) {
	// The production idle default is 120s — far too slow for a test. Lower
	// it via startServerConfigured's hook, which runs before the Run
	// goroutine spawns (so the write happens-before bindListener's read, and
	// -race stays clean).
	const idle = 300 * time.Millisecond
	startServerConfigured(t, 45710, tcpLimitCfg, func(s *Server) {
		s.tcpIdleTimeout = idle
	})

	conn := dialTCPWithRetry(t, "127.0.0.1:45710")
	defer conn.Close()

	// Half a request line, deliberately unterminated: the parser accepts the
	// bytes and waits for more, leaving the connection silent — exactly the
	// case the idle timeout must reclaim.
	if _, err := conn.Write([]byte("INVITE sip:5551234@127.0.0.1:45710 SIP/2.0\r\n")); err != nil {
		t.Fatalf("write partial request: %v", err)
	}

	// The server must close the connection once the idle deadline fires.
	// A client-side timeout (rather than EOF) means the server never closed
	// it — the red condition this test exists for.
	_ = conn.SetReadDeadline(time.Now().Add(idle + 3*time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection still open after idle timeout — server did not close it")
	} else {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("client deadline expired before the server closed the connection (err=%v) — idle timeout not enforced", err)
		}
	}
}

// TestTCPLimitListenerCapsConnections is the T-05 connection-cap test at the
// wrapper level: the third concurrent connection is closed immediately at
// accept (and never surfaced to sipgo), admitted connections stay open, and
// closing one frees its slot so the accept loop keeps serving.
func TestTCPLimitListenerCapsConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var count atomic.Int64
	limited := &tcpLimitListener{
		Listener: ln,
		max:      2,
		idle:     time.Minute,
		count:    &count,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer c1.Close()
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer c2.Close()
	c3, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 3: %v", err)
	}
	defer c3.Close()

	// Accepts pop in dial order: the first two are admitted, and the third
	// — over the cap — is closed inside Accept, which then retries (so it
	// must run on its own goroutine; it blocks awaiting a fourth dial).
	a1, err := limited.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}
	defer a1.Close()
	a2, err := limited.Accept()
	if err != nil {
		t.Fatalf("accept 2: %v", err)
	}
	defer a2.Close()
	if got := count.Load(); got != 2 {
		t.Fatalf("counter = %d, want 2 (cap)", got)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := limited.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	// readErr waits up to d for the server to close conn: EOF/ECONNRESET
	// means closed, a deadline timeout means still open.
	readErr := func(conn net.Conn, d time.Duration) error {
		_ = conn.SetReadDeadline(time.Now().Add(d))
		_, err := conn.Read(make([]byte, 1))
		return err
	}

	// The over-cap connection was closed immediately (by the third Accept).
	err = readErr(c3, time.Second)
	var ne3 net.Error
	if err == nil || (errors.As(err, &ne3) && ne3.Timeout()) {
		t.Fatalf("over-cap connection was not closed (err=%v)", err)
	}

	// The admitted connections are still open.
	err = readErr(c1, 300*time.Millisecond)
	var ne1 net.Error
	if !errors.As(err, &ne1) || !ne1.Timeout() {
		t.Fatalf("admitted connection unexpectedly closed (err=%v)", err)
	}

	// Closing an admitted connection frees a slot: a new dial is admitted
	// by the pending Accept, proving the accept loop continues past the
	// overflow.
	if err := a1.Close(); err != nil {
		t.Fatalf("close admitted conn: %v", err)
	}
	c4, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 4: %v", err)
	}
	defer c4.Close()
	select {
	case a3 := <-accepted:
		defer a3.Close()
	case <-time.After(time.Second):
		t.Fatal("accept loop did not resume after an over-cap connection was closed")
	}
	err = readErr(c4, 300*time.Millisecond)
	var ne4 net.Error
	if !errors.As(err, &ne4) || !ne4.Timeout() {
		t.Fatalf("connection admitted after slot release was unexpectedly closed (err=%v)", err)
	}
}
