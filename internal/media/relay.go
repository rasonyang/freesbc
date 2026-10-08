package media

import (
	"log/slog"
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
func (s *Session) forward(from, to Side, rtpKind bool) {
	in, inLatch := s.pairs[from].RTCP, s.rtcp[from]
	outSock, outLatch := s.pairs[to].RTCP, s.rtcp[to]
	if rtpKind {
		in, inLatch = s.pairs[from].RTP, s.rtp[from]
		outSock, outLatch = s.pairs[to].RTP, s.rtp[to]
	}
	go func() {
		defer recoverRelayPanic(nil, func() error { return s.closeWith(CloseFault) })
		buf := make([]byte, relayBufSize)
		for {
			n, src, err := in.ReadFromUDP(buf[:maxPacketSize+1])
			if err != nil {
				return // socket closed (session teardown)
			}
			if n > maxPacketSize {
				continue // oversize: forwarding it would forward a truncation
			}
			pkt := buf[:n]
			if leg := s.sdes[from].Load(); leg != nil {
				// SDES side: authenticate and decrypt BEFORE the latch may
				// move, so a forged packet from a vouched address cannot
				// latch the stream. permits only spares a decrypt for a
				// source the latch would refuse anyway.
				if !inLatch.permits(src) {
					continue
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
					continue
				}
				if !inLatch.accept(src) {
					continue
				}
			} else if !inLatch.accept(src) {
				continue // pre-latch source mismatch, or post-latch hijack
			}
			// Only NOW is the packet proven genuine: the latch accepted it
			// (and, on an SDES side, it authenticated).
			// Refresh the silence watchdog here, never on latch-accept alone:
			// A party who knows the latched source address could
			// feed garbage that failed auth yet renewed rtp_timeout
			// indefinitely, keeping a dead call alive forever.
			s.lastRx[from].Store(time.Now().UnixNano())
			s.counters.recordRx(from, rtpKind, len(pkt))
			if dst := outLatch.target(); dst != nil {
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
						continue
					}
				}
				if n, err := outSock.WriteToUDP(pkt, dst); err == nil {
					s.counters.recordTx(to, rtpKind, n)
				}
			}
		}
	}()
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
