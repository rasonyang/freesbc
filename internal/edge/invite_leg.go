package edge

import (
	"context"
	"errors"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file holds the INVITE client-transaction side of the proxy: relaying
// each response of a forwarded INVITE back to the caller, per early dialog
// (fork), confirming the dialog on the 2xx BEFORE the caller can see it,
// and keeping the client transaction alive through Timer M so every 2xx
// retransmission is relayed (RFC 3261 §13.3.1.4, §16.7 step 10; RFC 6026
// §7.2).

// calleeKind says who answers the forwarded INVITE, which decides which
// media side a fork's answer points and whether the caller-facing answer
// carries the WebRTC block.
type calleeKind int

const (
	// calleeUpstream: FreeSWITCH answers a public client's call.
	calleeUpstream calleeKind = iota
	// calleeClient: a registered client answers FreeSWITCH's call.
	calleeClient
	// calleeCarrier: a carrier answers the switch's call. Its legs are the
	// plain RTP relay, like a client's that was not offered WebRTC.
	calleeCarrier
)

// calleePlane is the plane the callee's answers come from, and so the
// media side each fork's answer points.
func (k calleeKind) calleePlane() plane {
	if k == calleeUpstream {
		return planePrivate
	}
	return planePublic
}

// inviteLeg is one forwarded INVITE: the caller's server transaction, the
// client transaction toward the callee, and what relaying its responses
// needs.
type inviteLeg struct {
	req  *sip.Request // the caller's INVITE
	tx   sip.ServerTransaction
	out  *sip.Request // the INVITE as forwarded
	clTx sip.ClientTransaction
	d    *dialog
	// offer is what the caller's SDP was turned into; nil for an offerless
	// INVITE, where offerless builds the near-side offer from the callee's
	// first SDP instead (offerless.go).
	offer     *offerResult
	offerless func(calleeBody []byte) (*offerResult, error)

	// near is the caller-facing side (the Contact the caller is given);
	// far the callee-facing one (the side a 2xx FreeSBC will not relay is
	// ACKed and BYEd on).
	near, far side
	callee    calleeKind

	// What commit records: where in-dialog traffic toward the callee goes,
	// the public transport, and which plane the caller is on.
	calleeRemote string
	transport    string
	fromPrivate  bool

	// resp is the topology-hiding rewrite the caller's responses get
	// (hide.go): respToSwitch for a call to a carrier, respToCarrier for a
	// carrier's call to the switch, respToSwitch for a call to a client and
	// respToClient for a client's call to the switch.
	resp respHide
}

func (l *inviteLeg) dialog() *dialog { return l.d }

// watch2xx registers the Timer M hook: once the first 2xx has moved the
// client transaction to Accepted, sipgo passes every later 2xx —
// retransmissions of the one relayed, and 2xx from other forks — to this
// hook rather than to Responses(). The transaction is deliberately NOT
// terminated after the 2xx; Timer M (64·T1) ends it.
//
// The hook captures the dialog's hook, not the leg or the record: the
// transaction outlives the call by Timer M (see dialogHook).
func (s *Server) watch2xx(l *inviteLeg) {
	h, tx, src, far := l.d.hook, l.tx, l.req.Source(), l.far
	l.clTx.OnRetransmission(func(res *sip.Response) { s.onLate2xx(h, tx, src, far, res) })
}

// onLate2xx handles a 2xx that arrived after the first one.
//
// A retransmission of the confirmed dialog's own 2xx means the caller's ACK
// has not reached the callee yet: relay the same response again, so a lost
// 200 on the caller's leg does not fail the call. A 2xx from any other
// fork is a second dialog FreeSBC has no media anchor for: it is ACKed and
// BYEd rather than relayed, once, and its own retransmissions are only
// re-ACKed. While the record is still early the first 2xx is being
// processed by the pump; the far end retransmits, so this one is dropped.
func (s *Server) onLate2xx(h *dialogHook, tx sip.ServerTransaction, src string, far side, res *sip.Response) {
	tag := fsip.ToTag(res)
	if d := h.dialog(); d != nil {
		if ok := d.relayed2xx(tag); ok != nil {
			// The stored 2xx is shared, so it is cloned, and sent to the
			// caller's transport source, where every response to it goes
			// (RFC 3581).
			out := ok.Clone()
			out.SetDestination(src)
			s.metrics.ResponseOut(out.StatusCode)
			if err := tx.Respond(out); err != nil {
				s.log.Debug("relay 2xx retransmission", "err", err, "sip_call_id", fsip.CallID(res))
			}
			return
		}
		d.tab.mu.Lock()
		early := d.state == dialogEarly && !h.isRejected(tag)
		d.tab.mu.Unlock()
		if early {
			return
		}
	}
	// The record has ended (or is not early): the 2xx is ACKed and BYEd.
	s.refuse2xx(h, far, res)
}

// refuse2xx completes and tears down a dialog the far end believes it has
// established but FreeSBC will not relay: ACK then BYE the first time, ACK
// alone for a retransmission.
func (s *Server) refuse2xx(h *dialogHook, far side, res *sip.Response) {
	if h.reject(fsip.ToTag(res)) {
		go s.ackThenBye(res, far)
		return
	}
	go s.ack2xx(res, far)
}

// errNoAnswer reports a 2xx that carries no SDP on a fork that never
// answered: there is nothing to anchor the call's media to.
var errNoAnswer = errors.New("proxy: 2xx without an answer")

// errDialogGone reports a 2xx for a call whose record has already ended
// (shutdown racing the answer).
var errDialogGone = errors.New("proxy: dialog already ended")

// relayInviteResponse relays one response of a forwarded INVITE to the
// caller.
//
// Each response is attributed to its fork by its To tag. The first body a
// fork sends is negotiated into that fork's own answer; a later body on the
// same fork is answered with the same body again; a body-less 2xx is given
// the fork's answer (or, for a far end that answered in one early dialog
// and confirmed in another without restating, the answer the media is
// following). The caller always sees FreeSBC as the remote target.
//
// A 2xx confirms the dialog BEFORE it is relayed, so the ACK the caller
// sends the moment it sees the 2xx always finds the record. A 2xx that
// cannot be anchored is ACKed and BYEd instead, and the error is returned
// for the caller's final to be decided by the pump.
func (s *Server) relayInviteResponse(l *inviteLeg, res *sip.Response) error {
	is2xx := res.StatusCode/100 == 2
	err := s.relayResponseHide(l.req, l.tx, res, l.resp, func(out *sip.Response) error {
		if tag := fsip.ToTag(res); tag != "" && res.StatusCode < 300 {
			// Recorded before the response goes out, so a PRACK or UPDATE
			// the caller sends the moment it sees this 18x finds its route.
			l.dialog().setForkRoute(tag, s.legRoute(l, res))
		}
		if l.callee == calleeUpstream {
			if t := res.To(); t != nil {
				if tag := fsip.ToTag(res); tag != "" && res.StatusCode < 300 {
					// The early dialog's identity, for a PRACK or UPDATE.
					l.dialog().setForkTo(tag, t.Address)
				}
				if is2xx {
					l.dialog().setCalleeURI(t.Address)
				}
			}
		}
		fsip.SetContact(out, l.near.uri())
		if l.fromPrivate && res.StatusCode < 300 {
			// The switch's route set must start at the private socket, and
			// neither a carrier nor a client echoes that entry.
			s.addPrivateRecordRoute(out)
		}
		if len(res.Body()) > 0 || is2xx {
			body, err := s.forkAnswer(l, res)
			if err != nil {
				return err
			}
			if body != nil {
				fsip.SetSDPBody(out, body)
			} else if len(out.Body()) > 0 {
				// An SDP the caller cannot use (an unreliable 18x of an
				// offerless call) must not reach it in the far end's words.
				stripBody(out)
			}
		}
		if !is2xx {
			return nil
		}
		if !s.commit(l, res) {
			return errDialogGone
		}
		s.armOwedTimer(l.dialog())
		s.armAckTimer(l.dialog(), fsip.CSeqNumber(l.req))
		// What retransmissions of this 2xx are answered with. Stored last:
		// nothing changes out after adapt (relayResponseHide only reads and
		// sends it), so onLate2xx can clone it from another goroutine
		// without a copy here.
		l.dialog().setRelayed2xx(out)
		return nil
	})
	if err != nil && !errors.Is(err, errResponseDropped) && is2xx {
		s.refuse2xx(l.d.hook, l.far, res)
	}
	return err
}

// pumpResult is how a forwarded INVITE ended, for its caller.
//
// final is the final response relayed (a 2xx confirmed first), or nil.
// responded says whether the far side responded AT ALL — any
// fsip.Forwardable response, even a provisional one, counts: it is what
// makes retrying another node safe, since a retry is only allowed when
// nothing was answered, so a node that spoke is always heard out and a
// call whose answer was already applied can never be re-negotiated against
// a second node (see inviteToUpstream). finalised says the caller's
// transaction has had its final response — relayed, or generated by the
// pump — so nothing more may be sent on it: a transaction finalises once,
// and a second final would only be counted, never delivered.
type pumpResult struct {
	final     *sip.Response
	responded bool
	finalised bool
}

// pumpInvite relays every response of a forwarded INVITE until the final
// one.
//
// Before a final response goes out, any provisional the wire delivered
// ahead of it that sipgo's transaction layer dropped (prov.go) is relayed
// first, in wire order, through the same path as a channel response. Once
// the final has been relayed the pump returns, so a 1xx read after it is
// never relayed (RFC 6026 §7.2).
func (s *Server) pumpInvite(ctx context.Context, l *inviteLeg) pumpResult {
	s.watch2xx(l)
	d := l.dialog()
	responded := false
	seen := make(map[*sip.Response]struct{}) // responses already read from the channel
	responses := l.clTx.Responses()

	// step relays one response; done says the pump ends with the result.
	step := func(res *sip.Response) (r pumpResult, done bool) {
		responded = true
		if ctx.Err() != nil || d.wasCancelled() {
			// The caller cancelled (or the backstop fired) while this
			// response was in flight: nothing may be relayed or
			// confirmed. A 2xx believes the call is up — complete and
			// tear it down; anything else is drained below.
			if res.StatusCode/100 == 2 {
				s.refuse2xx(l.d.hook, l.far, res)
				return pumpResult{responded: true, finalised: d.callerCancelled()}, true
			}
			s.abandonAttempt(l)
			return pumpResult{responded: true, finalised: d.callerCancelled()}, true
		}
		err := s.relayInviteResponse(l, res)
		switch {
		case errors.Is(err, errResponseDropped):
			return pumpResult{}, false
		case err != nil && d.wasCancelled():
			// The caller's CANCEL won the race with this 2xx (confirm
			// refused it); relayInviteResponse has ACKed and BYEd it.
			return pumpResult{responded: true, finalised: d.callerCancelled()}, true
		case err != nil:
			s.log.Warn("media negotiation failed", "err", err, "sip_call_id", fsip.CallID(l.req))
			// Relaying an answer we cannot anchor would set up a call
			// with no audio, so refuse the requesting side — once: this
			// 488 is its final. A 2xx has already been ACKed and BYEd by
			// relayInviteResponse; a provisional leaves the far side
			// ringing, so its INVITE is CANCELled (RFC 3261 §16.7 step
			// 10: a proxy that finalises the caller cancels the pending
			// branches).
			s.rejectInvite(l.req, l.tx, 488, "Not Acceptable Here", rejectMediaFailed)
			if res.StatusCode/100 != 2 {
				s.abandonAttempt(l)
			}
			return pumpResult{responded: true, finalised: true}, true
		}
		if res.StatusCode >= 200 {
			return pumpResult{final: res, responded: true, finalised: true}, true
		}
		return pumpResult{}, false
	}

	for {
		select {
		case res, ok := <-responses:
			if !ok {
				// sipgo never closes this channel — it ends a transaction
				// through Done() — so this arm is unreachable. A closed
				// channel is permanently ready, so stop selecting on it and
				// let the loop end the way it ends for any transaction
				// that produced no further response.
				responses = nil
				continue
			}
			seen[res] = struct{}{}
			if !fsip.Forwardable(res) {
				continue // a 100 Trying is hop-by-hop; ours already went out
			}
			if res.StatusCode >= 200 {
				for _, p := range s.prov.before(l.out, res, seen) {
					if r, done := step(p); done {
						return r
					}
				}
			}
			if r, done := step(res); done {
				return r
			}
		case <-l.clTx.Done():
			if err := l.clTx.Err(); err != nil {
				s.log.Debug("invite client transaction ended", "err", err, "sip_call_id", fsip.CallID(l.req))
			}
			return pumpResult{responded: responded, finalised: d.callerCancelled()}
		case <-ctx.Done():
			// The caller is gone (its CANCEL) or the backstop fired. A
			// caller's CANCEL is already on the wire; the backstop's is
			// sent here (RFC 3261 §16.8: a proxy that gives up on a branch
			// CANCELs it). Either way the far end's 487 may still be in
			// flight — drain for it so the transaction layer can match it
			// and send the ACK the far end expects.
			s.abandonAttempt(l)
			return pumpResult{responded: responded, finalised: d.callerCancelled()}
		}
	}
}

// cancelDrain is how long lingerForFinal waits inline for the final
// response a CANCEL provokes. Long enough for a local far end's 487 (a few
// RTTs); a slower one is waited for in the background (cancelLinger), so the
// pump or re-INVITE relay never stalls on it.
const cancelDrain = 300 * time.Millisecond

// cancelLinger bounds how long a cancelled INVITE's (or abandoned
// re-INVITE's) client transaction is kept to match a final that has not
// come yet (64*T1, RFC 3261 Timer B). A final leaves the transaction to its
// own timers (D, or M after a 2xx). A 2xx that crossed the CANCEL can come
// well after cancelDrain; once the transaction is gone it matches nothing
// and is never ACKed: the far end's dialog lingers, or, for a re-INVITE, a
// confirmed call may be BYEd over the missing ACK. Any final ends the wait
// early, so the usual 487 releases it at once; only a far end that goes
// silent holds it for the full bound.
const cancelLinger = 32 * time.Second

// maxCancelLingers caps the transactions held in the background by
// lingerForFinal, cancelled INVITEs and abandoned re-INVITEs together. Over
// it the transaction is terminated after the inline drain, as before.
const maxCancelLingers = 4096

// drainCancelledInvite reads whatever the far end still has to say after the
// call has been cancelled, without relaying any of it.
//
// The CANCEL for the forwarded INVITE is already on the wire (sendCancel
// sent it before cancelling the series context), but the final it provokes
// — the 487, or a 2xx that raced the CANCEL — may still be in flight. A
// final response that matches no transaction is never ACKed (RFC 3261
// §17.1.1.3): the far end retransmits it until Timer H and the log fills
// with "ACK missed". Keeping the transaction alive to match the final is
// what makes sipgo's transaction layer send that ACK.
//
// Nothing read here may be relayed — the caller's server transaction is
// already terminated. A 2xx is the one response with work left in it: the
// far end believes it has a live dialog, so it is completed and torn down.
func (s *Server) drainCancelledInvite(l *inviteLeg) {
	h, far := l.d.hook, l.far // not l: the linger can outlive the call by cancelLinger
	s.lingerForFinal(l.clTx, func(res *sip.Response) { s.refuse2xx(h, far, res) })
}

// lingerForFinal waits on a CANCELled INVITE client transaction for the
// final the CANCEL provokes, handing a 2xx to on2xx. It waits cancelDrain
// inline; when nothing final has come by then the wait continues in the
// background for up to cancelLinger and lingerForFinal returns. The
// transaction is terminated only when the wait runs out: after a final it
// is left to its own timers (D, or M after a 2xx), and it owns the
// transaction from the call on, so the caller must not terminate it.
func (s *Server) lingerForFinal(clTx sip.ClientTransaction, on2xx func(*sip.Response)) {
	if awaitCancelledFinal(clTx, cancelDrain, on2xx) {
		return
	}
	if s.cancelLingers.Add(1) > maxCancelLingers {
		s.cancelLingers.Add(-1)
		clTx.Terminate()
		return
	}
	go func() {
		defer s.cancelLingers.Add(-1)
		if !awaitCancelledFinal(clTx, cancelLinger-cancelDrain, on2xx) {
			clTx.Terminate()
		}
	}()
}

// awaitCancelledFinal reads a cancelled INVITE's transaction for up to
// wait and reports whether it ended: a final arrived (a 2xx is handed to
// on2xx) or the transaction died. false means the time ran out.
func awaitCancelledFinal(clTx sip.ClientTransaction, wait time.Duration, on2xx func(*sip.Response)) bool {
	drain := time.NewTimer(wait)
	defer drain.Stop()
	responses := clTx.Responses()
	for {
		select {
		case res, ok := <-responses:
			if !ok {
				// sipgo never closes this channel — it ends a transaction
				// through Done() — so this arm is unreachable. A closed
				// channel is permanently ready, so stop selecting on it and
				// let the loop end the way it ends for any transaction
				// that produced no further response.
				responses = nil
				continue
			}
			if !fsip.Forwardable(res) {
				continue // a 100 Trying carries nothing to match
			}
			if res.StatusCode/100 == 2 {
				on2xx(res)
			}
			if res.StatusCode >= 200 {
				// The final: a non-2xx was ACKed by the transaction layer on
				// its way in, a 2xx has been handed on. Nothing left to wait
				// for.
				return true
			}
		case <-clTx.Done():
			// The transaction died under us (a transport error, or a
			// Terminate from another path): no response can be matched any
			// more, so there is nothing left to drain for.
			return true
		case <-drain.C:
			return false
		}
	}
}

// ackThenBye completes and immediately tears down a dialog FreeSBC
// accepted at the SIP layer but cannot anchor media for. RFC 3261 requires
// a 2xx to be ACKed; without that the far end retransmits its 200 until
// Timer H, and the dialog lingers either way. ACK, then BYE.
func (s *Server) ackThenBye(res *sip.Response, from side) {
	if !s.ack2xx(res, from) {
		return
	}
	bye := fsip.TeardownRequest(sip.BYE, res, from.via(fsip.NewBranch()), fsip.CSeqNumber(res)+1, s.teardownOpts(from)...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clTx, err := s.clientTx(ctx, bye)
	if err != nil {
		s.log.Debug("bye unanchorable dialog", "err", err)
		return
	}
	defer clTx.Terminate()
	select {
	case <-clTx.Responses():
	case <-clTx.Done():
	case <-ctx.Done():
	}
}

// ack2xx sends the end-to-end ACK for a 2xx FreeSBC answers itself.
func (s *Server) ack2xx(res *sip.Response, from side) bool {
	ack := fsip.TeardownRequest(sip.ACK, res, from.via(fsip.NewBranch()), fsip.CSeqNumber(res), s.teardownOpts(from)...)
	if err := s.writeRequest(ack); err != nil {
		s.log.Debug("ack unanchorable answer", "err", err)
		return false
	}
	return true
}

// teardownOpts routes FreeSBC's own ACK/BYE for a dialog it tears down:
// out of the listener on side from, exactly as forward pins a relayed
// request, and along the route set beyond FreeSBC's own Record-Route
// entries (the INVITE carried them, so the 2xx lists them too).
func (s *Server) teardownOpts(from side) []fsip.TeardownOption {
	return []fsip.TeardownOption{fsip.FromListener(from.laddr), fsip.OwnRecordRoute(s.topo.isSelf)}
}

// commit confirms the dialog an answered INVITE established and hands its
// media session over to it: from here the session's lifetime is the
// dialog's, and dialog.end() is what releases it. It runs before the 2xx
// is relayed.
func (s *Server) commit(l *inviteLeg, final *sip.Response) bool {
	return l.dialog().confirm(fsip.ToTag(final), s.legRoute(l, final))
}

// legRoute is the routing record for the dialog a response of the leg
// establishes (early or confirmed): where each endpoint is reached and the
// Contact it gave.
func (s *Server) legRoute(l *inviteLeg, res *sip.Response) dialogRoute {
	r := dialogRoute{transport: l.transport}
	// The caller's signaling address is always where its INVITE came from;
	// the callee's is the destination this call was finally connected to —
	// the WINNING switch or gateway, so in-dialog traffic rides it.
	callerRemote, callerContact := &r.publicRemote, &r.publicContact
	calleeAddr, calleeContact := &r.privateRemote, &r.privateContact
	if l.fromPrivate {
		callerRemote, callerContact = &r.privateRemote, &r.privateContact
		calleeAddr, calleeContact = &r.publicRemote, &r.publicContact
	}
	*callerRemote, *calleeAddr = l.req.Source(), l.calleeRemote
	// Which endpoint's Contact arrived on which message follows from the
	// direction and nothing else: the caller's rode in on the INVITE, the
	// callee's came back on the response.
	if u, ok := fsip.ContactURI(l.req); ok {
		*callerContact = u
	}
	if u, ok := fsip.ContactURI(res); ok {
		*calleeContact = u
	}
	return r
}

// cancelCall gives up on a call being placed and CANCELs its in-flight
// INVITE, reporting whether there was one.
//
// It is what the caller's CANCEL runs, from inside sipgo's OnCancel hook:
// sipgo holds the server transaction's lock while the hook runs and sends
// the caller its 487 only after it returns, so the hook must not wait on
// the network. Marking the call cancelled is synchronous — from here no
// 2xx can confirm it — and the CANCEL itself goes out on a goroutine. An
// INVITE that is not on the wire yet is not CANCELled here: its sender
// does that the moment it is (see inviteAttempt).
func (s *Server) cancelCall(d *dialog, why cancelReason) bool {
	a, sendNow := d.cancelSeries(why)
	if a == nil {
		return false
	}
	if !sendNow {
		a.cancel()
		return true
	}
	go s.sendCancel(a)
	return true
}

// sendCancel sends a CANCEL for an INVITE FreeSBC forwarded.
//
// The CANCEL must carry the SAME top Via branch as the INVITE it cancels
// (RFC 3261 §9.1) — that is how the next hop matches the two — so it is
// built from the forwarded request rather than from the CANCEL we
// received, whose branch belongs to a different transaction.
//
// Once the CANCEL is on the wire the series context is cancelled: that is
// what ends the INVITE's pump (which then drains for the far end's 487)
// and releases its media promptly, rather than waiting on the forwarded
// INVITE's own transaction timer — up to 32 seconds of capacity held by a
// call nobody is on.
func (s *Server) sendCancel(a *inviteAttempt) {
	cancelReq := fsip.BuildCancel(a.req)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clTx, err := s.clientTx(ctx, cancelReq)
	a.cancel()
	if err != nil {
		s.log.Debug("forward CANCEL", "err", err, "sip_call_id", fsip.CallID(a.req))
		return
	}
	defer clTx.Terminate()
	select {
	case <-clTx.Responses():
	case <-clTx.Done():
	case <-ctx.Done():
	}
}

// abandonAttempt ends the forwarded INVITE of a call being given up on:
// CANCELs it unless that has already been done (the caller's own CANCEL
// takes the attempt first), then drains for the final the CANCEL provokes.
func (s *Server) abandonAttempt(l *inviteLeg) {
	if a, sendNow := l.dialog().cancelSeries(cancelBackstop); sendNow {
		go s.sendCancel(a)
	}
	s.drainCancelledInvite(l)
}
