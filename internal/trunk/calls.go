package trunk

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync/atomic"
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
// KillCall, lookupDialog) only ever see a published record, under
// Server.callMu. The one exception is bSRTP, which dialTarget rewrites per
// failover attempt while the call is still callDialing — i.e. before
// publication.
type call struct {
	// adminID is the call's identity in the admin API (/api/calls,
	// KillCall). It is minted by registerCall, unique among live calls, and
	// deliberately NOT a Call-ID: a Call-ID names a dialog only together
	// with both tags (RFC 3261 §12), so two live calls can share one.
	adminID string

	// id is the A-leg's Call-ID and bID the B-leg's own, distinct one. Each
	// is only a third of its leg's dialog ID; the tags are in aSDP/bSDP.
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

	// aOrigin is the SBC's own o= identity on the A-leg, shared by every
	// body sent to the caller (early media and the answer, across
	// failover). Each B-leg attempt gets its own, in dialTarget.
	aOrigin *sdpOrigin

	// aSDP/bSDP are the established SDP bodies plus dialog tags for each
	// leg; together with id/bID they are each leg's dialog ID.
	aSDP legSDP
	bSDP legSDP

	// cancel is the admin kick-call hook: cancelling it wakes onInvite's
	// teardown select, which BYEs both legs via byeBoth.
	cancel context.CancelFunc

	// state is guarded by Server.callMu and only ever changed by
	// registerCall/endCall.
	state callState
}

// legRef is one entry of the Server.legs index: a live call and which of
// its legs the indexing Call-ID belongs to.
type legRef struct {
	c     *call
	bLeg  bool
	entry legSDP
}

// mergeKey identifies an initial INVITE for merged-request detection
// (RFC 3261 §8.2.2.2): the same From-tag, Call-ID and CSeq arriving again on
// a different branch is the same request reaching us twice.
type mergeKey struct {
	callID, fromTag string
	cseq            uint32
}

// adminIDSeq disambiguates admin IDs if crypto/rand ever fails.
var adminIDSeq atomic.Uint64

// newAdminID returns a random 16-hex-char admin call ID.
func newAdminID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "call-" + strconv.FormatUint(adminIDSeq.Add(1), 10)
	}
	return hex.EncodeToString(b)
}

// registerCall publishes c as a live call, in one transition to
// callBridged: it gets a fresh admin ID (unique among live calls) and
// becomes visible to Calls/ActiveCalls and KillCall under it, and to the
// in-dialog lookup under EITHER leg's dialog ID (a refresh from the caller
// matches the A-leg's Call-ID and tags and is answered with aSDP; one from
// the carrier matches the B-leg's and is answered with bSDP). One lock, one
// moment: there is no window in which a call is listed but unkillable, or
// killable but unlisted.
//
// Nothing here is keyed by Call-ID alone, so two live calls that share one
// (a peer reusing a Call-ID with a new From-tag, or an A-leg Call-ID equal
// to another call's B-leg Call-ID) never overwrite each other.
func (s *Server) registerCall(c *call) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	if s.calls == nil {
		s.calls = make(map[string]*call)
	}
	if s.legs == nil {
		s.legs = make(map[string][]legRef)
	}
	c.state = callBridged
	if c.adminID == "" {
		c.adminID = newAdminID()
	}
	for s.calls[c.adminID] != nil {
		c.adminID = newAdminID()
	}
	s.calls[c.adminID] = c
	s.legs[c.id] = append(s.legs[c.id], legRef{c: c, entry: c.aSDP})
	if c.bID != "" {
		s.legs[c.bID] = append(s.legs[c.bID], legRef{c: c, bLeg: true, entry: c.bSDP})
	}
}

// endCall is registerCall's exact inverse, deferred by onInvite so it runs
// however the call ends (either leg's BYE, media silence, an admin kick, or
// a panic unwind). It drops c's own leg entries and admin entry under one
// lock — never another call's that shares a Call-ID — marks the call
// callEnded, and fires the kick hook's cancel (safe on an already-cancelled
// context) so no call context outlives the call.
func (s *Server) endCall(c *call) {
	s.callMu.Lock()
	c.state = callEnded
	if s.calls[c.adminID] == c {
		delete(s.calls, c.adminID)
	}
	s.dropLegs(c.id, c)
	if c.bID != "" {
		s.dropLegs(c.bID, c)
	}
	cancel := c.cancel
	s.callMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// dropLegs removes c's entries from the legs index under callID. Caller
// holds callMu.
func (s *Server) dropLegs(callID string, c *call) {
	refs := s.legs[callID]
	kept := refs[:0]
	for _, r := range refs {
		if r.c != c {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		delete(s.legs, callID)
		return
	}
	// Zero the tail so the dropped *call is not kept reachable.
	for i := len(kept); i < len(refs); i++ {
		refs[i] = legRef{}
	}
	s.legs[callID] = kept
}

// lookupDialog returns the established SDP record for the live leg whose
// dialog ID is (callID, fromTag, toTag) as the REMOTE endpoint of that leg
// sends them in an in-dialog request (see legSDP), RFC 3261 §12.2.2.
func (s *Server) lookupDialog(callID, fromTag, toTag string) (legSDP, bool) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	for _, r := range s.legs[callID] {
		if r.entry.fromTag == fromTag && r.entry.toTag == toTag {
			return r.entry, true
		}
	}
	return legSDP{}, false
}

// lookupLeg reports whether any live leg has callID as its own Call-ID,
// returning the first such leg's record. It is a Call-ID-only probe for
// tests and diagnostics; request handling matches the full dialog ID with
// lookupDialog.
func (s *Server) lookupLeg(callID string) (legSDP, bool) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	refs := s.legs[callID]
	if len(refs) == 0 {
		return legSDP{}, false
	}
	return refs[0].entry, true
}

// beginInvite records an initial INVITE as in progress and reports false
// when the same request (same Call-ID, From-tag and CSeq) is already being
// handled: a merged request, which the caller answers 482 Loop Detected
// (RFC 3261 §8.2.2.2). A retransmission on the SAME branch never gets here —
// sipgo's server transaction absorbs it. The returned func releases the
// entry; onInvite defers it, so it lives exactly as long as the call's
// handler does.
func (s *Server) beginInvite(k mergeKey) (done func(), ok bool) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	if s.inviting == nil {
		s.inviting = make(map[mergeKey]struct{})
	}
	if _, dup := s.inviting[k]; dup {
		return nil, false
	}
	s.inviting[k] = struct{}{}
	return func() {
		s.callMu.Lock()
		delete(s.inviting, k)
		s.callMu.Unlock()
	}, true
}

// KillCall tears down a live call by cancelling its kick context (the
// onInvite goroutine then BYEs both legs via the normal teardown — see
// byeBoth). id is the admin ID Calls lists. As a convenience for operators
// who only have a Call-ID from a SIP trace, an id that is no admin ID is
// also tried as an A-leg Call-ID, and then kills EVERY live call whose
// A-leg carries it (a Call-ID alone does not name one dialog). Returns
// false if nothing matched. Idempotent: endCall removes the entry once the
// call actually ends, so a kick racing a natural end returns false rather
// than firing twice.
func (s *Server) KillCall(id string) bool {
	s.callMu.Lock()
	var victims []*call
	if c, ok := s.calls[id]; ok {
		victims = append(victims, c)
	} else {
		for _, r := range s.legs[id] {
			if !r.bLeg {
				victims = append(victims, r.c)
			}
		}
	}
	s.callMu.Unlock()
	for _, c := range victims {
		c.cancel()
	}
	return len(victims) > 0
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
	ID            string // admin ID: what KillCall takes
	CallID        string // A-leg Call-ID, for correlating with SIP traces
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
			ID:            c.adminID,
			CallID:        c.id,
			FromPeer:      c.fromPeer,
			ToPeer:        c.toPeer,
			StartUnixNano: c.start.UnixNano(),
		})
	}
	return out
}
