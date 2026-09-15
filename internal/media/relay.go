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
	s.lastRx.Store(time.Now().UnixNano())
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
		buf := make([]byte, 1500)
		for {
			n, src, err := in.ReadFromUDP(buf)
			if err != nil {
				return // socket closed (session teardown)
			}
			if !inLatch.accept(src) {
				continue // pre-latch source mismatch, or post-latch hijack
			}
			pkt := buf[:n]
			// Decrypt what a secure sending leg gave us, then (re-)encrypt for
			// a secure receiving leg. A failure at either step drops the packet
			// (bad auth tag / replay) — fail-closed, call stays up.
			if ic := s.srtpIn[from].Load(); ic != nil {
				var ok bool
				if rtpKind {
					pkt, ok = ic.unprotectRTP(pkt)
				} else {
					pkt, ok = ic.unprotectRTCP(pkt)
				}
				if !ok {
					continue
				}
			}
			// T-22 (D5-4): only NOW is the packet proven genuine — plaintext
			// path: the latch accepted it; secure path: SRTP auth passed.
			// Refresh the silence watchdog here, never on latch-accept alone:
			// pre-fix, a party who knows the latched source address could
			// feed garbage that failed auth yet renewed rtp_timeout
			// indefinitely, keeping a dead call alive forever.
			s.lastRx.Store(time.Now().UnixNano())
			s.counters.recordRx(from, rtpKind, len(pkt))
			if oc := s.srtpOut[to].Load(); oc != nil {
				var ok bool
				if rtpKind {
					pkt, ok = oc.protectRTP(pkt)
				} else {
					pkt, ok = oc.protectRTCP(pkt)
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

// watchdog closes a session after `timeout` of media silence, so a
// half-dead call never keeps its ports reserved (spec §7: half-dead calls
// are reclaimed automatically). Shared by Session and WebRTCSession: both
// track the last genuine packet in an atomic nanosecond timestamp and are
// torn down the same way.
func watchdog(timeout time.Duration, lastRx *atomic.Int64, done <-chan struct{}, closeFn func() error) {
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
			if time.Since(time.Unix(0, lastRx.Load())) > timeout {
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
