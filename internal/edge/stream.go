package edge

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/freesbc/freesbc/internal/shield"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file is the connection plane of every stream transport the edge
// serves on the public side: tcp, tls, ws and wss. sipgo hands a listener's
// connections to its read loop with no limits at all (no cap, no deadline,
// and for ws/wss an upgrade done inline in the accept loop), so FreeSBC owns
// the listener sipgo is given and applies, in one place:
//
//   - a cap on open connections per source IP and in all, and a per-source
//     rate on new connections (the token every datagram costs, so a
//     connection flood and a handshake flood meet the shield's budget);
//   - the TLS handshake and the WebSocket upgrade request, done here, before
//     sipgo sees the connection, each within streamHandshakeTimeout, so a
//     stalled client can neither hold sipgo's accept loop nor reach its read
//     loop;
//   - an idle timeout, and a bound on how long one started message may take
//     to arrive (the slow-loris guard), enforced with read deadlines driven
//     by a small framer that follows message boundaries in the byte stream;
//   - a write deadline, so a client that stops reading cannot hold a
//     transaction goroutine;
//   - the registration-binding cleanup when a connection closes.
//
// None of this parses SIP: a framer only finds where a message ends
// (Content-Length) and how big it is. The parser stays sipgo's.

// Stream connection bounds. They are constants, not configuration: they are
// there so the edge stays up under a connection flood, not to be tuned per
// deployment (docs/design.md §15.2).
const (
	// streamMaxConnsPerIP caps open stream connections from one source
	// address (an IPv6 source by its /64), across tcp, tls, ws and wss. A
	// carrier or an office NAT with a few hundred phones fits well under it.
	streamMaxConnsPerIP = 256
	// streamMaxConns caps open stream connections in all. Each costs a
	// goroutine, a 32 KiB read buffer and a file descriptor, so the process
	// needs a matching file-descriptor limit.
	streamMaxConns = 10000
	// streamHandshakeTimeout bounds the TLS handshake and the WebSocket
	// upgrade request of a new connection.
	streamHandshakeTimeout = 10 * time.Second
	// streamIdleTimeout closes a connection that has been silent this long
	// and is carrying nothing: no live registration binding, no dialog and
	// no carrier source (streamBusy). A connection that is in use is never
	// closed for being idle; it lives as long as the binding or the dialog.
	// It is longer than the 32 s transaction timers so a request waiting on
	// the switch does not lose its connection.
	streamIdleTimeout = 60 * time.Second
	// streamMessageTimeout bounds how long one message may take to arrive
	// once its first byte has, measured from that byte (not reset by later
	// bytes), so a client trickling a message cannot hold a connection.
	streamMessageTimeout = 15 * time.Second
	// streamWriteTimeout bounds one write to a client.
	streamWriteTimeout = 10 * time.Second
	// streamUpgradeMax bounds a WebSocket upgrade request.
	streamUpgradeMax = 8 << 10
)

// streamLimits is the set of bounds one Server applies. The zero value is
// not usable; defaultStreamLimits is what New installs. Tests shorten the
// durations on the Server before Run.
type streamLimits struct {
	maxPerIP   int
	maxTotal   int
	handshake  time.Duration
	idle       time.Duration
	message    time.Duration
	write      time.Duration
	maxMessage int // one SIP message (stream) or one WebSocket frame payload
}

func defaultStreamLimits() streamLimits {
	return streamLimits{
		maxPerIP: streamMaxConnsPerIP, maxTotal: streamMaxConns,
		handshake: streamHandshakeTimeout, idle: streamIdleTimeout,
		message: streamMessageTimeout, write: streamWriteTimeout,
		maxMessage: fsip.MaxReadSize,
	}
}

// streamTransports are the transports this file serves, in metric order.
var streamTransports = [...]string{"tcp", "tls", "ws", "wss"}

func streamIndex(transport string) int {
	for i, t := range streamTransports {
		if t == transport {
			return i
		}
	}
	return -1
}

// streamRefusal is why a new connection was refused at accept; streamClose
// is why an established one was closed by policy. Both are fixed enums, so
// the metric label sets are bounded and exported from zero.
type streamRefusal uint8

const (
	refuseGlobalCap streamRefusal = iota
	refuseIPCap
	refuseBanned
	refuseRate
	numStreamRefusals
)

var streamRefusalLabels = [numStreamRefusals]string{"global_cap", "ip_cap", "banned", "rate"}

type streamClose uint8

const (
	closeNone streamClose = iota
	closeIdle
	closeSlow
	closeOversize
	closeMalformed
	closeHandshake
	closeRate
	numStreamCloses
)

var streamCloseLabels = [numStreamCloses]string{"", "idle", "slow", "oversize", "malformed", "handshake", "rate"}

// streamTable counts open stream connections per source and in all.
type streamTable struct {
	mu    sync.Mutex
	total int
	perIP map[netip.Addr]int
}

func newStreamTable() *streamTable { return &streamTable{perIP: map[netip.Addr]int{}} }

// streamKey is the per-source key: an IPv6 source by its /64, as the shield
// keys its buckets, so one host cannot multiply its allowance by address.
func streamKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		return netip.PrefixFrom(ip.WithZone(""), 64).Masked().Addr()
	}
	return ip
}

// acquire takes a connection slot for ip, or says which cap refuses it.
func (t *streamTable) acquire(ip netip.Addr, lim streamLimits) (streamRefusal, bool) {
	k := streamKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.total >= lim.maxTotal {
		return refuseGlobalCap, false
	}
	if t.perIP[k] >= lim.maxPerIP {
		return refuseIPCap, false
	}
	t.total++
	t.perIP[k]++
	return 0, true
}

func (t *streamTable) release(ip netip.Addr) {
	k := streamKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total--
	if t.perIP[k] <= 1 {
		delete(t.perIP, k)
	} else {
		t.perIP[k]--
	}
}

// open is the number of open stream connections (tests).
func (t *streamTable) open() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

// streamBusy reports whether a connection is carrying something that must
// outlive a quiet minute: a live registration binding made over it, a dialog
// routed to it, or a carrier source (carriers keep their own sessions and
// are bounded by the per-source cap instead).
func (s *Server) streamBusy(transport string, ap netip.AddrPort) bool {
	if s.loc.HasSource(transport, ap) {
		return true
	}
	if s.carriers.snapshot().isSource(ap.Addr()) {
		return true
	}
	return s.dialogs.usesRemote(transport, ap.String())
}

// currentShield returns the running shield, nil before Run installs it.
func (s *Server) currentShield() *shield.Shield {
	s.shieldMu.RLock()
	defer s.shieldMu.RUnlock()
	return s.shield
}

// streamListener is the listener sipgo's stream transports are given. A
// goroutine accepts raw connections and prepares each one on its own
// (admission, TLS handshake, WebSocket upgrade request); only a connection
// that is ready reaches Accept, so sipgo's serial accept loop never waits on
// a client.
type streamListener struct {
	net.Listener
	s         *Server
	transport string
	tlsConf   *tls.Config // tls and wss

	ready     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func (s *Server) newStreamListener(ln net.Listener, transport string, conf *tls.Config) *streamListener {
	l := &streamListener{
		Listener: ln, s: s, transport: transport, tlsConf: conf,
		ready: make(chan net.Conn, 128), done: make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *streamListener) acceptLoop() {
	defer l.shut()
	var backoff time.Duration
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			// Out of file descriptors (or a transient failure) must not end
			// the listener: sipgo treats an Accept error as fatal to Serve.
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || isTimeout(err) {
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				select {
				case <-time.After(backoff):
					continue
				case <-l.done:
					return
				}
			}
			return
		}
		backoff = 0
		go l.prepare(c)
	}
}

// Accept returns the next prepared connection. It reports net.ErrClosed once
// the listener is shut, like a closed listener.
func (l *streamListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *streamListener) Close() error {
	err := l.Listener.Close()
	l.shut()
	return err
}

// shut ends the listener once and closes what was prepared but never taken.
func (l *streamListener) shut() {
	l.closeOnce.Do(func() {
		close(l.done)
		for {
			select {
			case c := <-l.ready:
				_ = c.Close()
			default:
				return
			}
		}
	})
}

// prepare admits one raw connection and brings it to the state sipgo can
// read from: TLS handshaken, and for ws/wss the upgrade request received.
func (l *streamListener) prepare(raw net.Conn) {
	s := l.s
	lim := s.streamLim
	ap, err := netip.ParseAddrPort(raw.RemoteAddr().String())
	if err != nil {
		_ = raw.Close()
		return
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	ip := ap.Addr()

	if sh := s.currentShield(); sh != nil && sh.BannedFrom(ap, l.transport) {
		s.metrics.StreamRefused(refuseBanned)
		_ = raw.Close()
		return
	}
	if why, ok := s.streams.acquire(ip, lim); !ok {
		s.metrics.StreamRefused(why)
		_ = raw.Close()
		return
	}
	c := &streamConn{Conn: raw, l: l, ap: ap, remote: raw.RemoteAddr().String(), lim: lim}
	s.metrics.StreamConnOpened(l.transport)
	if sh := s.currentShield(); sh != nil && !sh.AllowRate(ip) {
		// A connection costs the token a datagram does, so a flood of
		// connections or handshakes from one source meets the same budget as
		// a flood of requests. Silent, like every shield denial.
		s.metrics.StreamRefused(refuseRate)
		_ = c.Close()
		return
	}
	switch l.transport {
	case "tls", "wss":
		tc := tls.Server(raw, l.tlsConf)
		c.Conn = tc
		_ = raw.SetDeadline(time.Now().Add(lim.handshake))
		if err := tc.Handshake(); err != nil {
			s.metrics.StreamClosed(closeHandshake)
			_ = c.Close()
			return
		}
		_ = raw.SetDeadline(time.Time{})
	}
	switch l.transport {
	case "tcp", "tls":
		c.fr = &sipFramer{max: lim.maxMessage}
	default:
		c.fr = &wsFramer{max: int64(lim.maxMessage)}
		if !c.readUpgrade() {
			return
		}
	}
	select {
	case l.ready <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// streamConn is one accepted stream connection. sipgo reads it from one
// goroutine; Close may come from any.
type streamConn struct {
	net.Conn
	l      *streamListener
	ap     netip.AddrPort
	remote string
	lim    streamLimits
	fr     framer

	// pending is data already read from the connection that sipgo has yet
	// to see: the WebSocket upgrade request, received during prepare.
	pending []byte

	// partial and since are the framer's view after the last read: a
	// message has started, and when its first byte arrived. Only the
	// reading goroutine touches them.
	partial bool
	since   time.Time

	closeOnce sync.Once
}

// readUpgrade receives the WebSocket upgrade request into pending, within the
// handshake timeout, so sipgo's inline Upgrade finds all of it buffered.
func (c *streamConn) readUpgrade() bool {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.lim.handshake))
	var buf []byte
	tmp := make([]byte, 2048)
	for !bytes.Contains(buf, []byte("\r\n\r\n")) {
		if len(buf) >= streamUpgradeMax {
			c.l.s.metrics.StreamClosed(closeMalformed)
			_ = c.Close()
			return false
		}
		n, err := c.Conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			c.l.s.metrics.StreamClosed(closeHandshake)
			_ = c.Close()
			return false
		}
	}
	c.pending = buf
	return true
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// arm sets the read deadline for the next read: the rest of the message
// timeout while a message is arriving, the idle timeout otherwise.
func (c *streamConn) arm() {
	if c.partial {
		_ = c.Conn.SetReadDeadline(c.since.Add(c.lim.message))
		return
	}
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.lim.idle))
}

// Read is the read sipgo's loop makes. It enforces the deadlines and feeds
// the framer. A policy close returns io.EOF, which sipgo logs at Debug as an
// ordinary close (a timeout error would be logged at Error).
func (c *streamConn) Read(p []byte) (int, error) {
	for {
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			if !c.observe(p[:n]) {
				return 0, io.EOF
			}
			return n, nil
		}
		c.arm()
		n, err := c.Conn.Read(p)
		if n > 0 && !c.observe(p[:n]) {
			return 0, io.EOF
		}
		if err == nil || !isTimeout(err) || n > 0 {
			return n, err
		}
		if c.partial {
			c.closeFor(closeSlow)
			return 0, io.EOF
		}
		if c.l.s.streamBusy(c.l.transport, c.ap) {
			continue // quiet but in use: wait another interval
		}
		c.closeFor(closeIdle)
		return 0, io.EOF
	}
}

// observe feeds data to the framer, charges the shield for each message
// started, and closes the connection on a violation. It reports whether the
// connection survives.
func (c *streamConn) observe(data []byte) bool {
	charges, bad := c.fr.feed(data)
	if bad != closeNone {
		c.closeFor(bad)
		return false
	}
	if sh := c.l.s.currentShield(); sh != nil {
		for range charges {
			if !sh.AllowRate(c.ap.Addr()) {
				c.closeFor(closeRate)
				return false
			}
		}
	}
	if p := c.fr.partial(); p && !c.partial {
		c.since = time.Now()
		c.partial = true
	} else if !p {
		c.partial = false
	}
	return true
}

func (c *streamConn) closeFor(why streamClose) {
	c.l.s.metrics.StreamClosed(why)
	_ = c.Close()
}

func (c *streamConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.lim.write))
	return c.Conn.Write(p)
}

// Close releases the connection's slot and drops the registration bindings
// made over it. sipgo's pool may close a connection more than once, and the
// hook must not run again after the address has been reused.
//
// A stream registration is only reachable through its own connection: there
// is no address to dial (RFC 5626 flow semantics). Keeping the binding after
// the connection is gone would make FreeSBC accept inbound calls it cannot
// deliver and leak a table entry until the registrar-granted expiry.
func (c *streamConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.Conn.Close()
		s := c.l.s
		s.streams.release(c.ap.Addr())
		s.metrics.StreamConnClosed(c.l.transport)
		if n := s.loc.RemoveBySource(c.ap); n > 0 {
			s.metrics.SetRegistrations(s.loc.Count())
			s.log.Debug("stream connection closed; dropped its registration bindings",
				"transport", c.l.transport, "public_remote", c.remote, "count", n)
		}
	})
	return err
}

// framer follows message boundaries in the bytes read from one connection.
type framer interface {
	// feed consumes data. charges is how many shield tokens the data costs
	// (a SIP message started, or a keep-alive read); bad is a violation the
	// connection is closed for.
	feed(data []byte) (charges int, bad streamClose)
	// partial reports whether a message has started and not completed.
	partial() bool
}

var crlfcrlf = []byte("\r\n\r\n")

// sipFramer frames SIP over a byte stream (RFC 3261 §18.3): a header block
// ending in an empty line, then Content-Length bytes of body. CRLFs between
// messages are RFC 5626 keep-alives and belong to no message.
type sipFramer struct {
	max   int
	state int // sipIdle, sipHead, sipBody
	head  []byte
	left  int
}

const (
	sipIdle = iota
	sipHead
	sipBody
)

func (f *sipFramer) partial() bool { return f.state != sipIdle }

func (f *sipFramer) feed(p []byte) (int, streamClose) {
	charges := 0
	content := f.state != sipIdle
	for len(p) > 0 {
		switch f.state {
		case sipIdle:
			i := 0
			for i < len(p) && (p[i] == '\r' || p[i] == '\n') {
				i++
			}
			p = p[i:]
			if len(p) == 0 {
				break
			}
			content = true
			charges++
			f.state = sipHead
			f.head = f.head[:0]
		case sipHead:
			old := len(f.head)
			take := min(len(p), f.max-old)
			f.head = append(f.head, p[:take]...)
			from := max(old-3, 0)
			idx := bytes.Index(f.head[from:], crlfcrlf)
			if idx < 0 {
				if take < len(p) || len(f.head) >= f.max {
					return charges, closeOversize
				}
				p = nil
				continue
			}
			end := from + idx + 4
			n, ok := contentLength(f.head[:end])
			if !ok {
				return charges, closeMalformed
			}
			if end+n > f.max {
				return charges, closeOversize
			}
			p = p[end-old:]
			f.left = n
			f.state = sipBody
			if n == 0 {
				f.state = sipIdle
			}
			f.head = f.head[:0]
		case sipBody:
			take := min(f.left, len(p))
			f.left -= take
			p = p[take:]
			if f.left == 0 {
				f.state = sipIdle
			}
		}
	}
	if !content {
		charges++ // a CRLF keep-alive costs a token like any read
	}
	return charges, closeNone
}

// contentLength reads the Content-Length (or "l") of a header block. A
// missing header is length 0; two that disagree, or a value that is not a
// plain non-negative number, are malformed.
func contentLength(head []byte) (int, bool) {
	n, seen := 0, false
	for line := range bytes.SplitSeq(head, []byte("\r\n")) {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := string(bytes.ToLower(bytes.TrimSpace(line[:colon])))
		if name != "content-length" && name != "l" {
			continue
		}
		v, err := strconv.Atoi(string(bytes.TrimSpace(line[colon+1:])))
		if err != nil || v < 0 {
			return 0, false
		}
		if seen && v != n {
			return 0, false
		}
		n, seen = v, true
	}
	return n, true
}

// wsFramer frames a client's WebSocket stream (RFC 6455): the HTTP upgrade
// request, then frames. It only follows lengths; the messages are sipgo's.
type wsFramer struct {
	max   int64
	state int // wsHTTP, wsHead, wsPayload
	match int // progress through the upgrade request's final CRLFCRLF
	read  int // upgrade request bytes so far
	hdr   [14]byte
	hn    int
	need  int
	left  int64
}

const (
	wsHTTP = iota
	wsHead
	wsPayload
)

func (f *wsFramer) partial() bool {
	switch f.state {
	case wsHTTP:
		return f.read > 0
	case wsHead:
		return f.hn > 0
	}
	return true
}

func (f *wsFramer) feed(p []byte) (int, streamClose) {
	for len(p) > 0 {
		switch f.state {
		case wsHTTP:
			b := p[0]
			p = p[1:]
			f.read++
			switch {
			case b == '\r' && (f.match == 0 || f.match == 2):
				f.match++
			case b == '\n' && (f.match == 1 || f.match == 3):
				f.match++
			case b == '\r':
				f.match = 1
			default:
				f.match = 0
			}
			if f.match == 4 {
				f.state, f.read, f.hn, f.need = wsHead, 0, 0, 2
			} else if f.read > streamUpgradeMax {
				return 0, closeMalformed
			}
		case wsHead:
			take := min(f.need-f.hn, len(p))
			copy(f.hdr[f.hn:], p[:take])
			f.hn += take
			p = p[take:]
			if f.hn < f.need {
				continue
			}
			if f.need == 2 {
				// Header size is known from the second byte: extended
				// length, then the client's mask key.
				l7 := f.hdr[1] & 0x7f
				switch l7 {
				case 126:
					f.need += 2
				case 127:
					f.need += 8
				}
				if f.hdr[1]&0x80 != 0 {
					f.need += 4
				}
				if f.hn < f.need {
					continue
				}
			}
			n := int64(f.hdr[1] & 0x7f)
			switch n {
			case 126:
				n = int64(f.hdr[2])<<8 | int64(f.hdr[3])
			case 127:
				n = 0
				for _, b := range f.hdr[2:10] {
					n = n<<8 | int64(b)
				}
			}
			if n < 0 || n > f.max {
				return 0, closeOversize
			}
			f.hn, f.need, f.left = 0, 2, n
			f.state = wsPayload
			if n == 0 {
				f.state = wsHead
			}
		case wsPayload:
			take := min(f.left, int64(len(p)))
			f.left -= take
			p = p[take:]
			if f.left == 0 {
				f.state = wsHead
			}
		}
	}
	return 0, closeNone
}
