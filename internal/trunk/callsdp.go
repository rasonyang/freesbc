package trunk

import "sync"

// callSDP holds what a bridged call leg needs on record to answer a
// session-timer refresh re-INVITE on THAT leg (Task 6 fix wave, extended by
// T-07/F-08 with the dialog identity):
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
//     carry in an in-dialog request on this leg (T-07/F-08): From always
//     identifies the sender, so fromTag is the remote endpoint's own tag
//     and toTag is OURS for that leg. An in-dialog request legitimately
//     re-sends exactly that pair on either leg, so matching both recorded
//     tags against an incoming re-INVITE is the RFC 3261 §12.2.2 dialog
//     match for both roles — and what keeps answer (which on a secure leg
//     contains the SDES master key) from ever being handed to a request
//     that merely replays the Call-ID and the established SDP.
//
// The two legs are asymmetric:
//   - A-leg (SBC is UAS toward the caller): compare = the caller's initial
//     offer, answer = aAnswer (our A-side media SDP, rewritten to our
//     ports); fromTag = the caller's tag, toTag = OUR tag (the one our 200
//     OK went out with).
//   - B-leg (SBC is UAC toward the carrier): compare = the carrier's
//     answer to our offer, answer = bOffer (our B-side media SDP we sent
//     the carrier); fromTag = the carrier's own tag (off its 200 OK's To —
//     the UAS was the carrier, so ITS local identity lives in the To), and
//     toTag = OUR tag (buildFrom's From). Swapped relative to the
//     establishment headers because the carrier's in-dialog request
//     carries ITS identity in From and ours in To.
type callSDP struct {
	compare, answer []byte
	fromTag, toTag  string
}

// callSDPStore remembers each established call LEG's callSDP, keyed by that
// leg's own Call-ID: one entry for the A-leg (the inbound INVITE's Call-ID)
// and one for the B-leg (the outbound INVITE's own, distinct Call-ID) — see
// bridge.onInvite/placeCall, where both are populated at bridge
// establishment. A refresh re-INVITE on either leg arrives at the same
// onInvite in-dialog branch and is looked up by ITS OWN Call-ID, which is
// why both legs need their own entry rather than one shared one keyed by
// the A-leg's Call-ID alone.
//
// Deliberately a separate map in package trunk rather than a field on
// call.Record: package call must stay free of SDP and trunk-specific concerns, so
// it can be reused (or read) without pulling in signaling internals.
type callSDPStore struct {
	mu   sync.Mutex
	sdps map[string]callSDP
}

func newCallSDPStore() *callSDPStore {
	return &callSDPStore{sdps: make(map[string]callSDP)}
}

// set stores entry as callID's established SDP pair, overwriting any prior value.
func (c *callSDPStore) set(callID string, entry callSDP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sdps[callID] = entry
}

// delete removes callID's entry, e.g. at call teardown.
func (c *callSDPStore) delete(callID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sdps, callID)
}

// get returns callID's stored SDP pair, or ok=false if none is on record (no
// established call leg with that Call-ID, or it already tore down).
func (c *callSDPStore) get(callID string) (callSDP, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.sdps[callID]
	return entry, ok
}
