package edge

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Why an out-of-dialog INVITE never connected (issue #335). Every such
// INVITE that ends without a confirmed dialog produces exactly one
// "invite failed" log line and, unless the caller's own CANCEL ended it, one
// count in freesbc_edge_invite_failures_total{leg,direction,class}.
//
// The line is written from the point where the outcome is known: the pump
// that relays the far end's final (pumpInvite), rejectInvite for a final the
// edge generates, giveUp when there is no final at all, and the CANCEL
// bridge. inviteFlow.done makes the first caller the only one.

// failLeg names the far end the INVITE was heading for, a fixed metric
// label.
type failLeg int

const (
	legCarrier failLeg = iota // switch to carrier
	legClient                 // switch to client
	legSwitch                 // carrier or client to the switch
	numFailLegs
)

var failLegLabels = [numFailLegs]string{legCarrier: "carrier", legClient: "client", legSwitch: "switch"}

// failClass is how an INVITE failed, a fixed metric label.
type failClass int

const (
	class4xx failClass = iota
	class5xx
	class6xx
	classTimeout // no final response at all: a timeout or a transport failure
	numFailClasses
)

var failClassLabels = [numFailClasses]string{class4xx: "4xx", class5xx: "5xx", class6xx: "6xx", classTimeout: "timeout"}

// Directions of the counter, as freesbc_edge_carrier_requests_total uses
// them: inbound is toward the switch (dirInbound), outbound away from it.
const (
	dirIdxInbound = iota
	dirIdxOutbound
	numFailDirs
)

var failDirLabels = [numFailDirs]string{dirIdxInbound: dirInbound, dirIdxOutbound: dirOutbound}

// failSource says who produced the outcome, the "source" log field.
type failSource string

const (
	failFarEnd  failSource = "far_end" // a final the far end sent, relayed
	failEdge    failSource = "edge"    // a final FreeSBC generated
	failTimeout failSource = "timeout" // no final at all
	failCancel  failSource = "cancel"  // the caller's own CANCEL
)

// maxFailText bounds the far end's reason phrase and Reason header in the
// log: both are chosen by a public party.
const maxFailText = 256

// inviteFlow is what one out-of-dialog INVITE's failure line needs, made by
// the handler when the INVITE arrives.
type inviteFlow struct {
	callID   string
	leg      failLeg
	inbound  bool   // toward the switch (public to private)
	carrier  string // the edge.carriers name; empty for a client call
	received time.Time
	sentNano atomic.Int64 // unix nanoseconds of the latest INVITE send; 0 before the first
	done     atomic.Bool
}

func newInviteFlow(req *sip.Request, leg failLeg, inbound bool, carrier string) *inviteFlow {
	return &inviteFlow{callID: fsip.CallID(req), leg: leg, inbound: inbound, carrier: carrier, received: time.Now()}
}

// markSent records that the INVITE went out, the start of the duration.
func (f *inviteFlow) markSent() { f.sentNano.Store(time.Now().UnixNano()) }

// elapsed is the time since the INVITE was sent, or, for one that never
// went out, since it was received.
func (f *inviteFlow) elapsed() time.Duration {
	if n := f.sentNano.Load(); n != 0 {
		return time.Since(time.Unix(0, n))
	}
	return time.Since(f.received)
}

func (f *inviteFlow) direction() string {
	if f.inbound {
		return "public->private"
	}
	return "private->public"
}

func (f *inviteFlow) dirIndex() int {
	if f.inbound {
		return dirIdxInbound
	}
	return dirIdxOutbound
}

// classOf is the counter class of a final response code; ok is false for a
// code the counter has no class for (1xx to 3xx).
func classOf(code int) (failClass, bool) {
	switch code / 100 {
	case 4:
		return class4xx, true
	case 5:
		return class5xx, true
	case 6:
		return class6xx, true
	}
	return 0, false
}

// clipText bounds s for the log.
func clipText(s string) string {
	if len(s) > maxFailText {
		s = s[:maxFailText]
	}
	return strings.ToValidUTF8(s, "")
}

// inviteFailed writes the one "invite failed" line of f and counts it. Only
// the first call per INVITE does anything. A 3xx or lower code is not a
// failure and is ignored without using the INVITE's one report.
func (s *Server) inviteFailed(f *inviteFlow, code int, phrase, sipReason string, src failSource) {
	level := slog.LevelInfo
	switch src {
	case failTimeout:
		level = slog.LevelWarn
	case failCancel:
		level = slog.LevelDebug
	}
	s.inviteFailedAt(f, code, phrase, sipReason, src, level)
}

func (s *Server) inviteFailedAt(f *inviteFlow, code int, phrase, sipReason string, src failSource, level slog.Level) {
	if f == nil {
		return
	}
	class := classTimeout
	if src != failTimeout {
		c, ok := classOf(code)
		if !ok && src != failCancel {
			return
		}
		if ok {
			class = c
		}
	}
	if !f.done.CompareAndSwap(false, true) {
		return
	}
	if src != failCancel {
		s.metrics.InviteFailed(f.leg, f.dirIndex(), class)
	}
	s.log.Log(context.Background(), level, "invite failed",
		"sip_call_id", f.callID, "direction", f.direction(), "leg", failLegLabels[f.leg],
		"carrier", f.carrier, "code", code, "reason_phrase", clipText(phrase),
		"sip_reason", clipText(sipReason), "duration", f.elapsed().Round(time.Millisecond),
		"source", string(src), "class", failClassLabels[class])
}

// inviteFailedRelayed records a final the far end sent, with every Reason
// header it carried joined by ", ". res is the
// response as received: relayResponseHide works on a clone, so what
// hiding strips (the Reason header) is still here.
func (s *Server) inviteFailedRelayed(f *inviteFlow, res *sip.Response) {
	// RFC 3326: one Reason header per protocol (SIP, Q.850), all of them.
	var reasons []string
	for _, h := range res.GetHeaders("Reason") {
		reasons = append(reasons, h.Value())
	}
	s.inviteFailed(f, res.StatusCode, res.Reason, strings.Join(reasons, ", "), failFarEnd)
}
