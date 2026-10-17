package media

import (
	"log/slog"
	"net"
	"runtime/debug"
	"sync/atomic"
	"time"
)

// Start launches the four forwarding loops (RTP and RTCP in both
// directions) and the silence watchdog, after any SetExpectedRemote calls
// for strict latching.
//
// It reports whether THIS call started the session. Calling it again — or
// after Close — does nothing and returns false, so the "start exactly
// once" rule is the session's own (one CompareAndSwap), not something
// every caller has to re-establish with a sync.Once of its own. Callers
// that only need the relay running can ignore the result.
func (s *Session) Start() bool {
	if !s.state.CompareAndSwap(sessAllocated, sessRunning) {
		return false // already running, or already closed
	}
	now := time.Now().UnixNano()
	s.lastRx[SideA].Store(now)
	s.lastRx[SideB].Store(now)
	s.forward(SideA, SideB, true)
	s.forward(SideB, SideA, true)
	s.forward(SideA, SideB, false)
	s.forward(SideB, SideA, false)
	go watchdog(s.timeout, &s.lastRx, s.done, func() error { return s.closeWith(CloseSilence) })
	return true
}

// forward starts one read loop copying packets that arrive on the `from`
// side (gated by its latch) to the `to` side's latched remote, sending
// from the `to` side's own socket so the remote sees the port it already
// talks to. rtpKind selects the RTP or RTCP socket/latch of both sides.
// The loop exits when its socket is closed. A panic kills only this
// session, never the process (spec §7).
//
// RTP loops use the batched relay (relayBatched, recvmmsg/sendmmsg) when
// batchRelay is set and the platform has one; RTCP, a packet every few
// seconds, always uses the plain loop.
func (s *Session) forward(from, to Side, rtpKind bool) {
	in, inLatch := s.pairs[from].RTCP, s.rtcp[from]
	outSock, outLatch := s.pairs[to].RTCP, s.rtcp[to]
	if rtpKind {
		in, inLatch = s.pairs[from].RTP, s.rtp[from]
		outSock, outLatch = s.pairs[to].RTP, s.rtp[to]
	}
	l := relayLoop{s: s, from: from, to: to, rtpKind: rtpKind, in: in, out: outSock, inLatch: inLatch, outLatch: outLatch}
	batched := rtpKind && batchRelayAvailable && batchRelay.Load()
	go func() {
		defer recoverRelayPanic(nil, func() error { return s.closeWith(CloseFault) })
		if batched {
			l.relayBatched()
			return
		}
		l.relayPlain()
	}()
}

// batchRelay turns on the batched RTP relay (issue #172) for sessions
// started after it is set, where batchRelayAvailable. Off by default: on
// loopback it is no clear win (docs/notes/172-rtp-batch-io.md), and it has
// not been measured on a real NIC. Not configuration: tests and benchmarks
// flip it, and a measurement build sets batchRelayBuild.
var batchRelay atomic.Bool

// batchRelayBuild is set at link time to build a binary with the batched
// relay on, for the measurement the notes describe:
//
//	go build -ldflags "-X github.com/freesbc/freesbc/internal/media.batchRelayBuild=on" ./cmd/freesbc
var batchRelayBuild string

func init() {
	if batchRelayBuild == "on" {
		batchRelay.Store(true)
	}
}

// relayLoop is one direction of one stream of a Session: what forward
// hands to the read loop that relays it.
type relayLoop struct {
	s                 *Session
	from, to          Side
	rtpKind           bool
	in, out           *net.UDPConn
	inLatch, outLatch *latch
}

// relayPlain is the portable read loop: one recvfrom and one sendto per
// packet.
func (l *relayLoop) relayPlain() {
	buf := make([]byte, relayBufSize)
	for {
		n, src, err := l.in.ReadFromUDP(buf[:maxPacketSize+1])
		if err != nil {
			return // socket closed (session teardown)
		}
		if n > maxPacketSize {
			continue // oversize: forwarding it would forward a truncation
		}
		pkt, dst, ok := l.packet(buf[:n], src)
		if !ok {
			continue
		}
		if n, err := l.out.WriteToUDP(pkt, dst); err == nil {
			l.s.counters.recordTx(l.to, l.rtpKind, n)
		}
	}
}

// packet applies everything but the I/O to one packet read from the `from`
// side: the latch, SDES decryption and encryption, the silence watchdog
// and the counters. It returns the bytes to send and where, or ok=false
// when the packet is dropped. pkt must sit at the start of a
// relayBufSize buffer, which is encrypted in place. src is not retained.
func (l *relayLoop) packet(pkt []byte, src *net.UDPAddr) (out []byte, dst *net.UDPAddr, ok bool) {
	s, from, to, rtpKind, inLatch := l.s, l.from, l.to, l.rtpKind, l.inLatch
	if leg := s.sdes[from].Load(); leg != nil {
		// SDES side: authenticate and decrypt BEFORE the latch may
		// move, so a forged packet from a vouched address cannot
		// latch the stream. permits only spares a decrypt for a
		// source the latch would refuse anyway.
		if !inLatch.permits(src) {
			return nil, nil, false
		}
		ctx := leg.in.ctx.Load()
		ok := ctx != nil
		if ok && rtpKind {
			pkt, ok = ctx.unprotectRTPInto(pkt, pkt)
		} else if ok {
			pkt, ok = ctx.unprotectRTCPInto(pkt, pkt)
		}
		if !ok {
			s.counters.srtpRxDrops[from].Add(1)
			return nil, nil, false
		}
		if !inLatch.accept(src) {
			return nil, nil, false
		}
	} else if !inLatch.accept(src) {
		return nil, nil, false // pre-latch source mismatch, or post-latch hijack
	}
	// Only NOW is the packet proven genuine: the latch accepted it
	// (and, on an SDES side, it authenticated).
	// Refresh the silence watchdog here, never on latch-accept alone:
	// A party who knows the latched source address could
	// feed garbage that failed auth yet renewed rtp_timeout
	// indefinitely, keeping a dead call alive forever.
	s.lastRx[from].Store(time.Now().UnixNano())
	s.counters.recordRx(from, rtpKind, len(pkt))
	dst = l.outLatch.target()
	if dst == nil {
		return nil, nil, false
	}
	if leg := s.sdes[to].Load(); leg != nil {
		// Encrypt in place: the read buffer has srtpMaxOverhead
		// spare. Only done once there is a destination, since
		// protecting advances the SRTP index.
		ctx := leg.out.ctx.Load()
		ok := ctx != nil
		if ok && rtpKind {
			pkt, ok = ctx.protectRTPInto(pkt, pkt)
		} else if ok {
			pkt, ok = ctx.protectRTCPInto(pkt, pkt)
		}
		if !ok {
			s.counters.srtpTxDrops[to].Add(1)
			return nil, nil, false
		}
	}
	return pkt, dst, true
}

// relayBufSize is every relay read buffer: the largest datagram relayed
// (maxPacketSize), one byte more to detect an oversize one, and room to
// SRTP-protect a full-size packet in place.
const relayBufSize = maxPacketSize + 1 + srtpMaxOverhead

// watchdog closes a session once EITHER side has sent no genuine packet
// for `timeout`, so a half-dead call never keeps its ports reserved (spec
// §7: half-dead calls are reclaimed automatically). lastRx holds one
// timestamp per sending side: a call whose one end has gone away (its BYE
// lost) is reclaimed even while the other end — FreeSWITCH playing music
// on hold, say — keeps streaming (P2-MED-004). Both RTP and RTCP count,
// so a receive-only side that sends RTCP receiver reports stays alive.
// Shared by Session and WebRTCSession.
func watchdog(timeout time.Duration, lastRx *[2]atomic.Int64, done <-chan struct{}, closeFn func() error) {
	interval := timeout / 4
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			oldest := min(lastRx[SideA].Load(), lastRx[SideB].Load())
			if time.Since(time.Unix(0, oldest)) > timeout {
				_ = closeFn()
				return
			}
		}
	}
}

// recoverRelayPanic is deferred by every relay goroutine: a panic kills
// only this session, never the process (spec §7), and leaves a forensic
// trace instead of a silent call drop. A nil log uses the default logger.
func recoverRelayPanic(log *slog.Logger, closeFn func() error) {
	if r := recover(); r != nil {
		if log == nil {
			log = slog.Default()
		}
		log.Error("media relay panic; killing session",
			"panic", r,
			"stack", string(debug.Stack()))
		_ = closeFn()
	}
}
