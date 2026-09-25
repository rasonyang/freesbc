package trunk

import (
	"sync"
	"time"
)

// defaultShutdownGrace bounds how long Run waits, at shutdown, for the
// calls it has told to end. It covers byeBoth's worst case (two BYEs of
// 5 s each, see byeContext) with a margin; a call still being dialled when
// shutdown begins gets the same budget to be answered or fail.
const defaultShutdownGrace = 12 * time.Second

// callGate closes the door on new calls when shutdown begins, and counts
// the bridged calls shutdown must wait for: a call counts from its
// publication (registerCall) until its onInvite has returned and released
// everything it held. INVITEs that were never bridged — still dialling, or
// already answered with an error and waiting for its ACK — are not waited
// for: they hold no call record and end on their own.
type callGate struct {
	mu       sync.Mutex
	draining bool
	bridged  int
	idle     chan struct{} // closed when draining and bridged reaches 0
}

// admit reports whether a new initial INVITE may be handled; false once
// shutdown has begun.
func (g *callGate) admit() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.draining
}

// bridge counts a call just published by registerCall. It reports whether
// shutdown has already begun, in which case the caller ends the call at
// once.
func (g *callGate) bridge() (draining bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bridged++
	return g.draining
}

// unbridge is bridge's inverse, run when the call's onInvite has returned.
func (g *callGate) unbridge() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bridged--
	if g.draining && g.bridged == 0 && g.idle != nil {
		close(g.idle)
		g.idle = nil
	}
}

// drain refuses every later admit and returns a channel closed once no
// bridged call is left.
func (g *callGate) drain() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.draining = true
	ch := make(chan struct{})
	if g.bridged == 0 {
		close(ch)
	} else {
		g.idle = ch
	}
	return ch
}

// drainCalls is the first step of Run's shutdown, while every listener is
// still open: it refuses new calls (503), tells every bridged call to end
// — the same teardown as an admin kick, a BYE to both legs — and waits,
// bounded by grace, for every bridged call's goroutine to return, which
// releases its media session and ports. A call that is answered while
// draining is ended by registerCall the moment it is published, and waited
// for like the others unless the wait has already finished. Calls still up
// when the grace expires are logged and left to the listeners' close.
func (s *Server) drainCalls(grace time.Duration) {
	idle := s.gate.drain()
	s.callMu.Lock()
	victims := make([]*call, 0, len(s.calls))
	for _, c := range s.calls {
		victims = append(victims, c)
	}
	s.callMu.Unlock()
	if len(victims) > 0 {
		s.log.Info("shutdown: ending live calls", "calls", len(victims))
	}
	for _, c := range victims {
		if c.cancel != nil {
			c.cancel()
		}
	}
	t := time.NewTimer(grace)
	defer t.Stop()
	select {
	case <-idle:
	case <-t.C:
		s.log.Warn("shutdown: calls still up after the grace period; closing listeners anyway",
			"grace", grace, "calls", s.ActiveCalls())
	}
}
