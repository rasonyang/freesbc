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
	go watchdog(s.timeout, &s.lastRx, s.done, s.Close)
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
		defer recoverRelayPanic(nil, s.Close)
		buf := make([]byte, relayBufSize)
		for {
			n, src, err := in.ReadFromUDP(buf[:maxPacketSize+1])
			if err != nil {
				return // socket closed (session teardown)
			}
			if n > maxPacketSize {
				continue // oversize: forwarding it would forward a truncation
			}
			if !inLatch.accept(src) {
				continue // pre-latch source mismatch, or post-latch hijack
			}
			pkt := buf[:n]
			// Decrypt what a secure sending leg gave us, then (re-)encrypt for
			// a secure receiving leg. A failure at either step drops the packet
			// (bad auth tag / replay) — fail-closed, call stays up.
			// Both transforms run in place in buf, which has room for the
			// SRTP overhead, so the relay allocates nothing per packet.
			if ic := s.srtpIn[from].Load(); ic != nil {
				var ok bool
				if rtpKind {
					pkt, ok = ic.unprotectRTPInto(pkt, pkt)
				} else {
					pkt, ok = ic.unprotectRTCPInto(pkt, pkt)
				}
				if !ok {
					continue
				}
			}
			// Only NOW is the packet proven genuine — plaintext
			// path: the latch accepted it; secure path: SRTP auth passed.
			// Refresh the silence watchdog here, never on latch-accept alone:
			// A party who knows the latched source address could
			// feed garbage that failed auth yet renewed rtp_timeout
			// indefinitely, keeping a dead call alive forever.
			s.lastRx[from].Store(time.Now().UnixNano())
			s.counters.recordRx(from, rtpKind, len(pkt))
			if oc := s.srtpOut[to].Load(); oc != nil {
				var ok bool
				if rtpKind {
					pkt, ok = oc.protectRTPInto(pkt, pkt)
				} else {
					pkt, ok = oc.protectRTCPInto(pkt, pkt)
				}
				if !ok {
					continue
				}
			}
			if dst := outLatch.target(); dst != nil {
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
