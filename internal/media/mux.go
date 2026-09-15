package media

import (
	"net"
	"sync"
	"time"

	"github.com/pion/transport/v4/packetio"
)

// This file demultiplexes the single UDP flow a WebRTC leg carries. After
// ICE has selected a candidate pair, DTLS handshake records and SRTP/SRTCP
// packets share one socket, and RFC 7983 §7 defines how to tell them
// apart by the first byte:
//
//	 20..63   DTLS
//	128..191  RTP or RTCP   (SRTP/SRTCP once DTLS has keyed)
//
// Everything else — STUN (already consumed by the ICE agent), ZRTP, TURN
// channel data, and anything malformed — is dropped. Dropping rather than erroring is
// deliberate: a single hostile datagram must not be able to tear down a
// live call's media path.

// muxKind classifies a packet on the shared WebRTC socket.
type muxKind int

const (
	muxUnknown muxKind = iota
	muxDTLS
	muxSRTP
)

func classify(b []byte) muxKind {
	if len(b) == 0 {
		return muxUnknown
	}
	switch c := b[0]; {
	case c >= 20 && c <= 63:
		return muxDTLS
	case c >= 128 && c <= 191:
		return muxSRTP
	default:
		return muxUnknown
	}
}

// Buffer limits for the demultiplexer's two queues. A queue that fills is
// a queue whose reader has stalled; dropping the newest packet there is
// correct for real-time media and bounds the memory one session can pin
// (spec §16: no memory amplification from untrusted input).
const (
	dtlsBufferSize = 1 << 16  // handshake flights are small and bursty
	srtpBufferSize = 1 << 20  // ~1 MB of audio backlog is already far too much
	maxPacketSize  = 1500 + 8 // MTU plus room for an SRTP tag on an already-full packet
)

// demux reads a WebRTC leg's single connection and fans packets out to a
// DTLS endpoint and an SRTP endpoint. Both endpoints write back through
// the same connection.
type demux struct {
	conn net.Conn // the ICE connection for the selected candidate pair

	dtls *muxEndpoint
	srtp *muxEndpoint

	closeOnce sync.Once
	done      chan struct{}
}

func newDemux(conn net.Conn) *demux {
	d := &demux{conn: conn, done: make(chan struct{})}
	d.dtls = newMuxEndpoint(d, dtlsBufferSize)
	d.srtp = newMuxEndpoint(d, srtpBufferSize)
	go d.readLoop()
	return d
}

func (d *demux) readLoop() {
	defer d.Close()
	buf := make([]byte, maxPacketSize)
	for {
		n, err := d.conn.Read(buf)
		if err != nil {
			return // ICE connection closed or failed
		}
		if n <= 0 {
			continue
		}
		var dst *muxEndpoint
		switch classify(buf[:n]) {
		case muxDTLS:
			dst = d.dtls
		case muxSRTP:
			dst = d.srtp
		default:
			continue // RFC 7983: not ours, drop silently
		}
		// A full buffer means the consumer is not keeping up; drop this
		// packet rather than block the read loop (which would stall the
		// OTHER endpoint too, e.g. wedging a DTLS handshake behind an
		// audio backlog).
		_, _ = dst.buf.Write(buf[:n])
	}
}

// Close tears the demultiplexer down. Idempotent.
func (d *demux) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		_ = d.dtls.buf.Close()
		_ = d.srtp.buf.Close()
		_ = d.conn.Close()
	})
	return nil
}

// muxEndpoint is one demultiplexed stream, exposed as a net.PacketConn so
// it can be handed straight to pion's dtls.Server, and as a net.Conn for
// the SRTP relay. Reads come from the demultiplexer's buffer; writes go
// directly to the shared connection.
type muxEndpoint struct {
	parent *demux
	buf    *packetio.Buffer
}

func newMuxEndpoint(parent *demux, limit int) *muxEndpoint {
	b := packetio.NewBuffer()
	b.SetLimitSize(limit)
	return &muxEndpoint{parent: parent, buf: b}
}

func (e *muxEndpoint) Read(p []byte) (int, error) { return e.buf.Read(p) }

func (e *muxEndpoint) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := e.Read(p)
	return n, e.parent.conn.RemoteAddr(), err
}

func (e *muxEndpoint) Write(p []byte) (int, error) { return e.parent.conn.Write(p) }

// WriteTo ignores addr: an ICE connection has exactly one peer — the
// selected candidate pair — and writing anywhere else would make this a
// UDP reflector (spec §16).
func (e *muxEndpoint) WriteTo(p []byte, _ net.Addr) (int, error) { return e.Write(p) }

func (e *muxEndpoint) Close() error                       { return e.buf.Close() }
func (e *muxEndpoint) LocalAddr() net.Addr                { return e.parent.conn.LocalAddr() }
func (e *muxEndpoint) RemoteAddr() net.Addr               { return e.parent.conn.RemoteAddr() }
func (e *muxEndpoint) SetDeadline(t time.Time) error      { return e.buf.SetReadDeadline(t) }
func (e *muxEndpoint) SetReadDeadline(t time.Time) error  { return e.buf.SetReadDeadline(t) }
func (e *muxEndpoint) SetWriteDeadline(_ time.Time) error { return nil }

var (
	_ net.Conn       = (*muxEndpoint)(nil)
	_ net.PacketConn = (*muxEndpoint)(nil)
)
