package trunk

import (
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// TCP/TLS listener resource bounds (T-05, F-02). sipgo v1.4.3's TCP accept
// loop is unbounded and its per-connection read loop sets no read deadline
// (transport_tcp.go Serve/readConnection), so a connection flood or a
// silent/slow-feeding connection each consume resources without bound.
// The bounds live on Server (tcpMaxConns/tcpIdleTimeout — see server.go) so
// tests can lower them via startServerConfigured's hook before Run spawns
// its goroutines (no cross-goroutine write to a package var); the defaults
// are set in NewServer. The values may move into config later
// (REMEDIATION-PLAN T-05 defers that).

// tcpLimitListener wraps a TCP/TLS net.Listener with the global connection
// cap and the per-connection idle read deadline. The cap is enforced with a
// compare-and-swap on the shared counter, so concurrent Accept loops (one
// per listener) can never both admit the last slot.
type tcpLimitListener struct {
	net.Listener
	max   int64
	idle  time.Duration
	count *atomic.Int64
	log   *slog.Logger
}

// Accept returns the next admitted connection. A connection accepted over
// the cap is closed immediately and the accept loop retries — it must never
// be surfaced to sipgo, whose Serve treats a nil conn or an Accept error as
// fatal to the listener.
func (l *tcpLimitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		for {
			cur := l.count.Load()
			if cur >= l.max {
				l.log.Debug("tcp connection limit reached; closing overflow connection",
					"remote", c.RemoteAddr().String(), "max", l.max)
				c.Close()
				break // outer loop re-accepts
			}
			if l.count.CompareAndSwap(cur, cur+1) {
				return &idleTimeoutConn{Conn: c, idle: l.idle, count: l.count}, nil
			}
		}
	}
}

// idleTimeoutConn refreshes the read deadline before every Read, so a
// connection that stops sending (including one slow-feeding a partial
// message into the stream parser) is closed after idle. Writes are
// deliberately left deadline-free: response traffic is bounded by dialog
// and transaction timers, and the finding (F-02) is about read-side
// resource retention.
type idleTimeoutConn struct {
	net.Conn
	idle   time.Duration
	count  *atomic.Int64
	closed atomic.Bool
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// Close releases the connection's cap slot exactly once: sipgo's teardown
// may Close the same connection twice (its read loop defers a pool
// CloseAndDelete and the pool itself may Close on Clear), and a double
// decrement would let the shared counter drift negative and silently raise
// the cap.
func (c *idleTimeoutConn) Close() error {
	err := c.Conn.Close()
	if c.closed.CompareAndSwap(false, true) {
		c.count.Add(-1)
	}
	return err
}

// newTCPLimitListener wraps ln for s's TCP/TLS accept path: global
// connection cap (shared counter across all of s's tcp/tls listeners) and
// per-connection idle read timeout, both taken from s.
func newTCPLimitListener(ln net.Listener, s *Server) net.Listener {
	return &tcpLimitListener{
		Listener: ln,
		max:      s.tcpMaxConns,
		idle:     s.tcpIdleTimeout,
		count:    &s.tcpConns,
		log:      s.log,
	}
}
