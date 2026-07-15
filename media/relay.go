package media

import (
	"log/slog"
	"runtime/debug"
	"time"
)

// Start launches the four forwarding loops (RTP and RTCP in both
// directions) and the silence watchdog. Call at most once, after any
// SetExpectedRemote calls for strict latching.
func (s *Session) Start() {
	s.lastRx.Store(time.Now().UnixNano())
	s.forward(SideA, SideB, true)
	s.forward(SideB, SideA, true)
	s.forward(SideA, SideB, false)
	s.forward(SideB, SideA, false)
	go s.watchdog()
}

// forward starts one read loop copying packets that arrive on the `from`
// side (gated by its latch) to the `to` side's latched remote, sending
// from the `to` side's own socket so the remote sees the port it already
// talks to. rtpKind selects the RTP or RTCP socket/latch of both sides.
// The loop exits when its socket is closed. A panic kills only this
// session, never the process (spec §7).
func (s *Session) forward(from, to Side, rtpKind bool) {
	in, inLatch := s.pairs[from].RTCP, s.rtcp[from]
	out, outLatch := s.pairs[to].RTCP, s.rtcp[to]
	if rtpKind {
		in, inLatch = s.pairs[from].RTP, s.rtp[from]
		out, outLatch = s.pairs[to].RTP, s.rtp[to]
	}
	go func() {
		defer s.recoverRelayPanic()
		buf := make([]byte, 1500)
		for {
			n, src, err := in.ReadFromUDP(buf)
			if err != nil {
				return // socket closed (session teardown)
			}
			if !inLatch.accept(src) {
				continue // pre-latch source mismatch, or post-latch hijack
			}
			s.lastRx.Store(time.Now().UnixNano())
			if dst := outLatch.target(); dst != nil {
				_, _ = out.WriteToUDP(buf[:n], dst)
			}
		}
	}()
}

// watchdog tears the session down after `timeout` of RTP silence
// (spec §7: half-dead calls are reclaimed automatically).
func (s *Session) watchdog() {
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
			last := time.Unix(0, s.lastRx.Load())
			if time.Since(last) > s.timeout {
				_ = s.Close()
				return
			}
		}
	}
}

// recoverRelayPanic is deferred by every relay goroutine: a panic kills
// only this session, never the process (spec §7), and leaves a forensic
// trace instead of a silent call drop.
func (s *Session) recoverRelayPanic() {
	if r := recover(); r != nil {
		slog.Error("media relay panic; killing session",
			"panic", r,
			"stack", string(debug.Stack()))
		_ = s.Close()
	}
}
