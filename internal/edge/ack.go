package edge

import (
	"sync"
	"time"
)

// This file holds the 2xx ACK watch. Once FreeSBC has relayed the 2xx of an
// initial INVITE, the side that sent the INVITE owes an ACK (RFC 3261
// §13.2.2.4). When it never comes, the callee gives up after 64*T1 (RFC
// 3261 §13.3.1.4) and BYEs a call that never really started; unrecorded,
// that reads as a normal hangup. The miss is recorded instead: reason ack_timeout, the
// freesbc_edge_ack_missed_total counter, a rate-limited WARN naming the
// address the ACK should have reached, and the recent count the health
// condition reads (AckMisses).
//
// Re-INVITE 2xx ACKs are not watched: the dialog is already established,
// and a callee that gives up on one ends it with a BYE that is relayed and
// classified like any other.

// ackMissWarnEvery is the least time between two WARNs of one plane.
const ackMissWarnEvery = time.Minute

// ackMissKeep is how many recent miss times a plane remembers. It only has
// to exceed the health threshold.
const ackMissKeep = 32

// ackOwed is the ACK a relayed 2xx still waits for.
type ackOwed struct {
	plane plane  // the plane that must send it
	cseq  uint32 // CSeq number of the INVITE
	// timer is FreeSBC's own backstop; nil when an owed answer (offerless)
	// owns the teardown.
	timer *time.Timer
	// counted is set once the miss was counted, so one transaction never
	// counts twice.
	counted bool
	// cleared is closed when the ACK arrives (clearAck).
	cleared chan struct{}
}

// byeAckGrace is how long a BYE from the 2xx sender waits for the ACK it is
// owed before the missing ACK is held against the far end. The caller's ACK
// (public side) and the callee's BYE (private side) are independent flows
// that can cross, so a BYE seen first is not proof that the ACK is lost.
const byeAckGrace = 500 * time.Millisecond

// armAckTimer records that the dialog's caller owes the ACK for the 2xx
// just relayed and starts the backstop. An offerless exchange carries its
// answer in that ACK and has its own backstop (armOwedTimer, run first), so
// no second teardown timer is armed there.
func (s *Server) armAckTimer(d *dialog, cseq uint32) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	if d.state != dialogConfirmed {
		return
	}
	a := &ackOwed{plane: d.callerPlane, cseq: cseq, cleared: make(chan struct{})}
	d.ack = a
	if d.owed == nil {
		// The timer captures the hook, not d: a stopped timer stays in the
		// runtime's heap until it is cleaned up, and its closure with it.
		h := d.hook
		a.timer = time.AfterFunc(s.ackBudget(), func() {
			if d := h.dialog(); d != nil {
				s.ackExpired(d, a)
			}
		})
	}
}

// ackExpired ends a call whose ACK is still missing after the backstop.
func (s *Server) ackExpired(d *dialog, a *ackOwed) {
	d.tab.mu.Lock()
	owed := d.ack == a
	d.tab.mu.Unlock()
	if !owed {
		return
	}
	s.noteAckMiss(d)
	if d.end(endAckTimeout) {
		s.byeBothEnds(d, endAckTimeout)
	}
}

// clearAck records the ACK from plane p for the INVITE with cseq.
func (d *dialog) clearAck(p plane, cseq uint32) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	if a := d.ack; a != nil && a.plane == p && a.cseq == cseq {
		if a.timer != nil {
			a.timer.Stop()
		}
		close(a.cleared)
		d.ack = nil
	}
}

// ackOwedAfterGrace reports whether the ACK owed by the plane other than
// from is still missing after byeAckGrace. A crossing ACK that lands within
// the grace clears the debt and the BYE is classified as an ordinary hangup.
func (d *dialog) ackOwedAfterGrace(from plane, grace time.Duration) bool {
	d.tab.mu.Lock()
	a := d.ack
	if a == nil || a.plane == from {
		d.tab.mu.Unlock()
		return false
	}
	cleared := a.cleared
	d.tab.mu.Unlock()
	t := time.NewTimer(grace)
	defer t.Stop()
	select {
	case <-cleared:
		return false
	case <-t.C:
		return d.ackOwedByOther(from)
	}
}

// ackOwedByOther reports whether an ACK is owed by the plane other than
// from, i.e. from is the side that sent the 2xx.
func (d *dialog) ackOwedByOther(from plane) bool {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.ack != nil && d.ack.plane != from
}

// takeAckMiss marks the owed ACK as counted and returns the plane that
// missed it; false when none is owed or it was counted already.
func (d *dialog) takeAckMiss() (plane, bool) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	if d.ack == nil || d.ack.counted {
		return 0, false
	}
	d.ack.counted = true
	return d.ack.plane, true
}

// noteAckMiss counts the dialog's missing ACK, once per transaction.
func (s *Server) noteAckMiss(d *dialog) {
	p, ok := d.takeAckMiss()
	if !ok {
		return
	}
	s.metrics.AckMissed(p)
	endpoint := s.advertisedFor(p, d.routeSnapshot().transport)
	n, warn := s.ackMiss.record(p, endpoint)
	s.log.Debug("2xx ACK never arrived", "sip_call_id", d.callID, "plane", p.String(), "advertised", endpoint)
	if warn {
		s.log.Warn("2xx ACK never arrived; the far end is not reaching the advertised Contact/Record-Route address (NAT or firewall?)",
			"plane", p.String(), "advertised", endpoint, "sip_call_id", d.callID,
			"suppressed", n, "interval", ackMissWarnEvery)
	}
}

// advertisedFor is the URI plane p's far end is told to send its in-dialog
// requests and ACKs to.
func (s *Server) advertisedFor(p plane, transport string) string {
	if p == planePrivate {
		u := s.topo.private.uri()
		return u.String()
	}
	if sd, ok := s.topo.publicSide(transport); ok {
		u := sd.uri()
		return u.String()
	}
	for _, t := range []string{"udp", "tcp", "tls", "wss", "ws"} {
		if sd, ok := s.topo.publicSide(t); ok {
			u := sd.uri()
			return u.String()
		}
	}
	return ""
}

// AckMiss is the recent 2xx ACK misses of one plane.
type AckMiss struct {
	Plane string // "public" or "private"
	// Recent is the misses within the window asked for (at most
	// ackMissKeep), Endpoint the advertised URI of the latest one.
	Recent   int
	Endpoint string
}

// AckMisses reports, per plane, the 2xx ACK misses within window.
func (s *Server) AckMisses(window time.Duration) []AckMiss {
	return s.ackMiss.recent(window)
}

// ackMissTracker keeps the recent miss times, the latest advertised
// endpoint and the WARN rate limit of each plane.
type ackMissTracker struct {
	now func() time.Time // nil is time.Now

	mu     sync.Mutex
	planes [2]ackMissPlane
}

type ackMissPlane struct {
	times      []time.Time
	endpoint   string
	lastWarn   time.Time
	suppressed int
}

func (t *ackMissTracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// record notes one miss and reports whether it earns a WARN (the first of a
// plane, then one per ackMissWarnEvery) with the misses folded since the
// last one.
func (t *ackMissTracker) record(p plane, endpoint string) (suppressed int, warn bool) {
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	pl := &t.planes[p]
	pl.times = append(pl.times, now)
	if len(pl.times) > ackMissKeep {
		pl.times = pl.times[len(pl.times)-ackMissKeep:]
	}
	pl.endpoint = endpoint
	if !pl.lastWarn.IsZero() && now.Sub(pl.lastWarn) < ackMissWarnEvery {
		pl.suppressed++
		return 0, false
	}
	n := pl.suppressed
	pl.lastWarn, pl.suppressed = now, 0
	return n, true
}

// recent counts each plane's misses newer than window.
func (t *ackMissTracker) recent(window time.Duration) []AckMiss {
	cutoff := t.clock().Add(-window)
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]AckMiss, 0, len(t.planes))
	for p := range t.planes {
		pl := &t.planes[p]
		m := AckMiss{Plane: plane(p).String(), Endpoint: pl.endpoint}
		for _, ts := range pl.times {
			if ts.After(cutoff) {
				m.Recent++
			}
		}
		out = append(out, m)
	}
	return out
}
