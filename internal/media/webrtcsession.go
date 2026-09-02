package media

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// WebRTCSession is the media half of a browser call: a WebRTC leg on the
// public side and a plain RTP/RTCP port pair on the private side, relaying
// audio between them without decoding a single sample (spec §9).
//
//	Browser ──SRTP/SRTCP (muxed, one socket)──▶ WebRTCLeg
//	                                              │ decrypt
//	                                              ▼
//	                                          plain RTP ──▶ FreeSWITCH
//
// and the reverse. The two directions are independent goroutines with an
// explicit shutdown path; the session owns both and releases every socket
// and port reservation in Close.
//
// It is a separate type from Session rather than a third latch/socket
// combination inside it: the public side here is one muxed socket driven
// by ICE and DTLS, which shares nothing with Session's symmetric
// four-socket shape. Forcing them behind one interface would make both
// harder to reason about for no reuse.
type WebRTCSession struct {
	leg      *WebRTCLeg
	priv     *PortPair
	privPool *PlanePool

	// Private-side latches: the same hardened first-packet latching the
	// trunk relay uses (see session.go). The public side needs none — ICE
	// already fixed the peer, and SRTP authenticates every packet.
	privRTP  *latch
	privRTCP *latch

	// privMux is set when FreeSWITCH agreed to rtcp-mux, in which case
	// RTCP goes back over the RTP socket and the RTCP socket stays idle.
	privMux bool

	timeout  time.Duration
	lastRx   atomic.Int64
	counters counters

	log *slog.Logger

	started   sync.Once
	done      chan struct{}
	closeOnce sync.Once
}

// errWebRTCSessionClosed reports that a session ended before its media
// leg was established.
var errWebRTCSessionClosed = errors.New("media: webrtc session closed before establishment")

// WebRTCSessionConfig configures one browser call's media.
type WebRTCSessionConfig struct {
	// PrivateLatch is the latching mode for the FreeSWITCH side.
	PrivateLatch LatchMode
	// PrivateRTCPMux relays RTCP over the private RTP socket instead of
	// the RTCP one.
	PrivateRTCPMux bool
	// Timeout tears the session down after this much media silence.
	Timeout time.Duration
	// Log receives relay-level errors; nil uses the default logger.
	Log *slog.Logger
}

// NewWebRTCSession pairs an already-allocated WebRTC leg with a freshly
// allocated private RTP port pair. The leg's handshake may still be in
// flight — Start waits for it.
//
// On error the private pair is released; the caller still owns the leg
// (it holds the port and credentials that already went out in SDP).
func NewWebRTCSession(leg *WebRTCLeg, privPool *PlanePool, cfg WebRTCSessionConfig) (*WebRTCSession, error) {
	priv, err := privPool.allocatePair()
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = privPool.timeout()
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &WebRTCSession{
		leg:      leg,
		priv:     priv,
		privPool: privPool,
		privRTP:  &latch{mode: cfg.PrivateLatch},
		privRTCP: &latch{mode: cfg.PrivateLatch},
		privMux:  cfg.PrivateRTCPMux,
		timeout:  timeout,
		log:      log,
		done:     make(chan struct{}),
	}, nil
}

// PrivateRTPPort is the FreeSWITCH-facing RTP port (RTCP is +1). The
// signaling plane writes it into the SDP it sends upstream.
func (s *WebRTCSession) PrivateRTPPort() int { return s.priv.RTPPort() }

// PublicPort is the browser-facing port (the WebRTC leg's socket).
func (s *WebRTCSession) PublicPort() int { return s.leg.Port() }

// Leg exposes the WebRTC leg so the signaling plane can read its ICE
// credentials, DTLS role and readiness.
func (s *WebRTCSession) Leg() *WebRTCLeg { return s.leg }

// SetPrivateRemote seeds the private side with the media address
// FreeSWITCH signalled: both the expected source IP and the address to
// send to, so audio flows toward FreeSWITCH before its first packet
// arrives. The first accepted packet still corrects the destination
// (symmetric RTP) — see latch.seed.
func (s *WebRTCSession) SetPrivateRemote(addr netip.AddrPort) {
	s.privRTP.seed(addr)
	if addr.Port() < 65535 {
		s.privRTCP.seed(netip.AddrPortFrom(addr.Addr(), addr.Port()+1))
	}
}

// Done is closed when the session ends (Close or silence timeout).
func (s *WebRTCSession) Done() <-chan struct{} { return s.done }

// Stats returns the session's packet counters.
func (s *WebRTCSession) Stats() Stats { return s.counters.snapshot(s.lastRx.Load()) }

// Start waits for the WebRTC leg to finish ICE and DTLS, then launches the
// relay. It returns the leg's establishment error if the handshake failed,
// in which case the session is already closed.
//
// Calling it more than once is a no-op after the first.
func (s *WebRTCSession) Start(ctx context.Context) error {
	var err error
	s.started.Do(func() { err = s.start(ctx) })
	return err
}

func (s *WebRTCSession) start(ctx context.Context) error {
	select {
	case <-s.leg.Ready():
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	case <-s.done:
		// The session was torn down before the handshake finished (the
		// call was cancelled, or the process is shutting down). Report it
		// rather than returning nil, which a caller would read as "the
		// media leg is up" and go on to use contexts that do not exist.
		return errWebRTCSessionClosed
	}
	if err := s.leg.Err(); err != nil {
		_ = s.Close()
		return err
	}
	in, out, err := s.leg.SRTPContexts()
	if err != nil {
		_ = s.Close()
		return err
	}
	conn, err := s.leg.Conn()
	if err != nil {
		_ = s.Close()
		return err
	}
	s.lastRx.Store(time.Now().UnixNano())
	go s.publicToPrivate(conn, in)
	go s.privateToPublic(conn, out, true)
	if !s.privMux {
		go s.privateToPublic(conn, out, false)
	}
	go s.watchdog()
	return nil
}

// publicToPrivate reads the browser's muxed SRTP/SRTCP flow, authenticates
// and decrypts each packet, and forwards the plaintext to FreeSWITCH.
//
// A packet that fails authentication is dropped and — importantly — does
// NOT refresh the silence watchdog: only a packet proven genuine counts as
// media activity, so an attacker who can reach the socket cannot keep a
// dead call alive with garbage.
func (s *WebRTCSession) publicToPrivate(conn net.Conn, in *SRTPContext) {
	defer s.recoverRelayPanic()
	buf := make([]byte, maxPacketSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return // leg closed
		}
		pkt := buf[:n]
		rtcp := isRTCP(pkt)
		var ok bool
		if rtcp {
			pkt, ok = in.UnprotectRTCP(pkt)
		} else {
			pkt, ok = in.UnprotectRTP(pkt)
		}
		if !ok {
			continue // bad auth tag or replay: fail closed, call stays up
		}
		s.lastRx.Store(time.Now().UnixNano())
		s.counters.recordRx(SideA, !rtcp, len(pkt))

		sock, lat := s.priv.RTP, s.privRTP
		if rtcp && !s.privMux {
			sock, lat = s.priv.RTCP, s.privRTCP
		}
		dst := lat.target()
		if dst == nil {
			// FreeSWITCH has not sent us anything yet, so we don't know
			// which source/port to answer. Nothing to do but drop; media
			// starts flowing as soon as its first packet latches.
			continue
		}
		if w, err := sock.WriteToUDP(pkt, dst); err == nil {
			s.counters.recordTx(SideB, !rtcp, w)
		}
	}
}

// privateToPublic reads one of the private sockets, gates it through the
// latch, encrypts, and writes to the browser.
func (s *WebRTCSession) privateToPublic(conn net.Conn, out *SRTPContext, rtpKind bool) {
	defer s.recoverRelayPanic()
	sock, lat := s.priv.RTP, s.privRTP
	if !rtpKind {
		sock, lat = s.priv.RTCP, s.privRTCP
	}
	buf := make([]byte, maxPacketSize)
	for {
		n, src, err := sock.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (session teardown)
		}
		if !lat.accept(src) {
			continue // pre-latch source mismatch, or post-latch hijack
		}
		pkt := buf[:n]
		// On a muxed private socket the RTP socket also carries RTCP, so
		// classify per packet rather than trusting which socket it came
		// from.
		rtcp := !rtpKind
		if rtpKind && s.privMux {
			rtcp = isRTCP(pkt)
		}
		s.lastRx.Store(time.Now().UnixNano())
		s.counters.recordRx(SideB, !rtcp, n)

		var ok bool
		if rtcp {
			pkt, ok = out.ProtectRTCP(pkt)
		} else {
			pkt, ok = out.ProtectRTP(pkt)
		}
		if !ok {
			continue
		}
		if w, err := conn.Write(pkt); err == nil {
			s.counters.recordTx(SideA, !rtcp, w)
		}
	}
}

// watchdog tears the session down after `timeout` of media silence, so a
// half-dead call never keeps a public port and a private pair reserved.
func (s *WebRTCSession) watchdog() {
	interval := s.timeout / 4
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if time.Since(time.Unix(0, s.lastRx.Load())) > s.timeout {
				_ = s.Close()
				return
			}
		}
	}
}

// Close tears the session down: both relay directions stop (their sockets
// close), the WebRTC leg releases its public port and ICE agent, and the
// private pair returns to its pool. Idempotent and safe from any
// goroutine.
func (s *WebRTCSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.priv.Close()
		s.privPool.release(s.priv.RTPPort())
		_ = s.leg.Close()
	})
	return nil
}

// recoverRelayPanic is deferred by every relay goroutine: a panic from a
// malformed packet kills only this session, never the process, and leaves
// a forensic trace instead of a silent call drop.
func (s *WebRTCSession) recoverRelayPanic() {
	if r := recover(); r != nil {
		s.log.Error("webrtc relay panic; killing session",
			"panic", r, "stack", string(debug.Stack()))
		_ = s.Close()
	}
}
