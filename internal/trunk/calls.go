package trunk

import (
	"context"
	"time"

	"github.com/emiago/sipgo"

	"github.com/freesbc/freesbc/internal/media"
)

// callState is where a bridged call is in its lifecycle. There are exactly
// three, matching what onInvite actually does:
//
//   - callDialing: the A-leg has been read and a media session allocated,
//     and placeCall is trying targets. The call exists only as onInvite's
//     own *call; nothing else can see it (it is in no store, so /api/calls
//     does not list it and KillCall cannot find it), and no B-leg is
//     committed yet.
//   - callBridged: both legs are established, media is anchored and the
//     A-leg's 200 OK has been ACKed. registerCall publishes the call under
//     this state, which is the only state a call is ever visible in.
//   - callEnded: teardown. endCall sets it while removing the call from the
//     store, so a KillCall or in-dialog lookup racing a natural end sees
//     either a live callBridged entry or nothing at all — never a stale one.
//
// The two transitions live in registerCall and endCall, and nowhere else.
type callState int

const (
	callDialing callState = iota
	callBridged
	callEnded
)

// legSDP is what one established leg needs on record to answer a
// session-timer refresh re-INVITE on THAT leg:
//
//   - compare is the peer's own offer/answer for this leg — the SDP a
//     refresh re-INVITE on this leg is expected to re-send (modulo an o=
//     version bump; see isRefreshReInvite). It is what the refresh's body
//     is checked against, never what gets sent back.
//   - answer is the SBC's OWN established answer SDP for this leg — what
//     must be sent back in the refresh's 200 OK. A session-timer refresh
//     re-INVITE is not a new offer/answer exchange (RFC 4028 §7 / RFC 3264
//     §8 in spirit): the far end already has this answer and expects to
//     see it restated, not the offer it itself sent, and not the other
//     leg's SDP.
//   - fromTag/toTag are the From/To tags the leg's REMOTE endpoint will
//     carry in an in-dialog request on this leg: From always identifies the
//     sender, so fromTag is the remote endpoint's own tag and toTag is OURS
//     for that leg. An in-dialog request legitimately re-sends exactly that
//     pair on either leg, so matching both recorded tags against an
//     incoming re-INVITE is the RFC 3261 §12.2.2 dialog match for both
//     roles — and what keeps answer (which on a secure leg contains the
//     SDES master key) from ever being handed to a request that merely
//     replays the Call-ID and the established SDP.
//
// The two legs are asymmetric; see where call.aSDP/call.bSDP are filled in
// onInvite for which tag comes off which message.
type legSDP struct {
	compare, answer []byte
	fromTag, toTag  string
}

// call is one B2BUA call: every piece of per-call state the bridge owns,
// in one record with one owner (the onInvite goroutine that built it).
//
// Only onInvite's goroutine writes these fields, and every field is written
// before registerCall publishes the record; readers (Calls, ActiveCalls,
// KillCall, lookupLeg) only ever see a published record, under Server.callMu.
// The one exception is bSRTP, which dialTarget rewrites per failover attempt
// while the call is still callDialing — i.e. before publication.
type call struct {
	// id is the A-leg's Call-ID: the identity admin uses (/api/calls,
	// KillCall). bID is the B-leg's own, distinct Call-ID, which a carrier
	// refresh re-INVITE arrives under.
	id  string
	bID string

	fromPeer string    // identified inbound peer name
	toPeer   string    // winning target's peer name
	start    time.Time // bridged-at, for the admin record

	aLeg   *sipgo.DialogServerSession
	bLeg   *sipgo.DialogClientSession
	sess   *media.Session
	target Target

	// aSRTP/bSRTP are the negotiated per-leg SRTP state; nil means that
	// leg is plaintext (see legSRTP).
	aSRTP *legSRTP
	bSRTP *legSRTP

	// aSDP/bSDP are the established SDP bodies plus dialog tags for each
	// leg, keyed into Server.legs by that leg's own Call-ID.
	aSDP legSDP
	bSDP legSDP

	// cancel is the admin kick-call hook: cancelling it wakes onInvite's
	// teardown select, which BYEs both legs via byeBoth.
	cancel context.CancelFunc

	// state is guarded by Server.callMu and only ever changed by
	// registerCall/endCall.
	state callState
}

// registerCall publishes c as a live call, in one transition to
// callBridged: it becomes visible to Calls/ActiveCalls and KillCall under
// its A-leg Call-ID, and to the in-dialog refresh lookup under EITHER leg's
// own Call-ID (a refresh from the caller carries the A-leg's Call-ID and is
// answered with aSDP; one from the carrier carries the B-leg's and is
// answered with bSDP). One lock, one moment: there is no window in which a
// call is listed but unkillable, or killable but unlisted.
func (s *Server) registerCall(c *call) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	c.state = callBridged
	s.calls[c.id] = c
	s.legs[c.id] = c
	if c.bID != "" && c.bID != c.id {
		s.legs[c.bID] = c
	}
}

// endCall is registerCall's exact inverse, deferred by onInvite so it runs
// however the call ends (either leg's BYE, media silence, an admin kick, or
// a panic unwind). It drops both leg indexes and the admin entry under one
// lock, marks the call callEnded, and fires the kick hook's cancel (safe on
// an already-cancelled context) so no call context outlives the call.
func (s *Server) endCall(c *call) {
	s.callMu.Lock()
	c.state = callEnded
	delete(s.calls, c.id)
	delete(s.legs, c.id)
	if c.bID != "" {
		delete(s.legs, c.bID)
	}
	cancel := c.cancel
	s.callMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// lookupLeg returns the established SDP record for the leg whose OWN
// Call-ID is callID, or ok=false when no live call has such a leg. Both
// legs of every bridged call are indexed, so an in-dialog request is
// answered with its own leg's state whichever side sent it.
func (s *Server) lookupLeg(callID string) (legSDP, bool) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	c, ok := s.legs[callID]
	if !ok {
		return legSDP{}, false
	}
	if callID == c.id {
		return c.aSDP, true
	}
	return c.bSDP, true
}

// KillCall tears down the live call with the given A-leg Call-ID by
// cancelling its kick context (the onInvite goroutine then BYEs both legs
// via the normal teardown — see byeBoth). Returns false if no such active
// call is tracked. Idempotent: endCall removes the entry once the call
// actually ends, so a second kick for the same id (or one racing a natural
// end) returns false rather than firing twice.
func (s *Server) KillCall(id string) bool {
	s.callMu.Lock()
	c, ok := s.calls[id]
	s.callMu.Unlock()
	if !ok {
		return false
	}
	c.cancel()
	return true
}

// ActiveCalls returns the number of bridged calls, for metrics.
func (s *Server) ActiveCalls() int {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	return len(s.calls)
}

// CallRecord is one bridged call's metadata — deliberately just metadata:
// the SIP dialog and media objects stay inside the trunk plane. It is what
// Calls hands out, so callers (the admin API) never touch call state.
type CallRecord struct {
	ID            string // A-leg Call-ID
	FromPeer      string
	ToPeer        string
	StartUnixNano int64
}

// Calls returns a snapshot of the bridged calls as plain metadata records,
// for the admin API — deliberately not the *call itself: admin has no
// business with SIP dialogs or media sessions.
func (s *Server) Calls() []CallRecord {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	out := make([]CallRecord, 0, len(s.calls))
	for _, c := range s.calls {
		out = append(out, CallRecord{
			ID:            c.id,
			FromPeer:      c.fromPeer,
			ToPeer:        c.toPeer,
			StartUnixNano: c.start.UnixNano(),
		})
	}
	return out
}
