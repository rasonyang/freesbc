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
	// calleePSTN: a carrier gateway answers FreeSWITCH's bridged call.
	calleePSTN
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
	req   *sip.Request // the caller's INVITE
	tx    sip.ServerTransaction
	out   *sip.Request // the INVITE as forwarded
	clTx  sip.ClientTransaction
	offer *offerResult

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
}

func (l *inviteLeg) dialog() *dialog { return l.offer.dialog }

// watch2xx registers the Timer M hook: once the first 2xx has moved the
// client transaction to Accepted, sipgo passes every later 2xx —
// retransmissions of the one relayed, and 2xx from other forks — to this
// hook rather than to Responses(). The transaction is deliberately NOT
// terminated after the 2xx; Timer M (64·T1) ends it.
func (s *Server) watch2xx(l *inviteLeg) {
	l.clTx.OnRetransmission(func(res *sip.Response) { s.onLate2xx(l, res) })
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
func (s *Server) onLate2xx(l *inviteLeg, res *sip.Response) {
	d := l.dialog()
	tag := fsip.ToTag(res)
	if ok := d.relayed2xx(tag); ok != nil {
		// A clone carries no destination; the caller's transport source is
		// where every response to it goes (RFC 3581).
		out := ok.Clone()
		out.SetDestination(l.req.Source())
		s.metrics.ResponseOut(out.StatusCode)
		if err := l.tx.Respond(out); err != nil {
			s.log.Debug("relay 2xx retransmission", "err", err, "sip_call_id", fsip.CallID(res))
		}
		return
	}
	d.tab.mu.Lock()
	early := d.state == dialogEarly && !d.rejected[tag]
	d.tab.mu.Unlock()
	if early {
		return
	}
	s.refuse2xx(l, res)
}

// refuse2xx completes and tears down a dialog the far end believes it has
// established but FreeSBC will not relay: ACK then BYE the first time, ACK
// alone for a retransmission.
func (s *Server) refuse2xx(l *inviteLeg, res *sip.Response) {
	if l.dialog().reject2xx(fsip.ToTag(res)) {
		go s.ackThenBye(res, l.far)
		return
	}
	go s.ack2xx(res, l.far)
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
	err := s.relayResponse(l.req, l.tx, res, func(out *sip.Response) error {
		fsip.SetContact(out, l.near.uri())
		if len(res.Body()) > 0 || is2xx {
			body, err := s.forkAnswer(l, res)
			if err != nil {
				return err
			}
			if body != nil {
				fsip.SetSDPBody(out, body)
			}
		}
		if !is2xx {
			return nil
		}
		if !s.commit(l, res) {
			return errDialogGone
		}
		// What retransmissions of this 2xx are answered with.
		l.dialog().setRelayed2xx(out.Clone())
		return nil
	})
	if err != nil && !errors.Is(err, errResponseDropped) && is2xx {
		s.refuse2xx(l, res)
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
func (s *Server) pumpInvite(ctx context.Context, l *inviteLeg) pumpResult {
	s.watch2xx(l)
	d := l.dialog()
	responded := false
	responses := l.clTx.Responses()
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
				continue // a 100 Trying is hop-by-hop; ours already went out
			}
			responded = true
			if ctx.Err() != nil || d.wasCancelled() {
				// The caller cancelled (or the backstop fired) while this
				// response was in flight: nothing may be relayed or
				// confirmed. A 2xx believes the call is up — complete and
				// tear it down; anything else is drained below.
				if res.StatusCode/100 == 2 {
					s.refuse2xx(l, res)
					return pumpResult{responded: true, finalised: d.callerCancelled()}
				}
				s.abandonAttempt(l)
				return pumpResult{responded: true, finalised: d.callerCancelled()}
			}
			err := s.relayInviteResponse(l, res)
			switch {
			case errors.Is(err, errResponseDropped):
				continue
			case err != nil && d.wasCancelled():
				// The caller's CANCEL won the race with this 2xx (confirm
				// refused it); relayInviteResponse has ACKed and BYEd it.
				return pumpResult{responded: true, finalised: d.callerCancelled()}
			case err != nil:
				s.log.Warn("media negotiation failed", "err", err, "sip_call_id", fsip.CallID(l.req))
				// Relaying an answer we cannot anchor would set up a call
				// with no audio, so refuse the requesting side — once: this
				// 488 is its final. A 2xx has already been ACKed and BYEd by
				// relayInviteResponse; a provisional leaves the far side
				// ringing, so its INVITE is CANCELled (RFC 3261 §16.7 step
				// 10: a proxy that finalises the caller cancels the pending
				// branches).
				s.reject(l.req, l.tx, 488, "Not Acceptable Here")
				if res.StatusCode/100 != 2 {
					s.abandonAttempt(l)
				}
				return pumpResult{responded: true, finalised: true}
			}
			if res.StatusCode >= 200 {
				return pumpResult{final: res, responded: true, finalised: true}
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

// pumpPSTNAttempt drives one gateway attempt to its end and classifies the
// outcome for the failover loop. It is deliberately NOT pumpInvite with
// options: the two differ in exactly the ways failover forces — an
// attempt can end in a retry (its 408/>=500 finals are HELD, never
// relayed), its budget is a timer rather than the transaction's context,
// and an answer it can no longer serve must be torn down rather than left
// to retransmit.
//
// wholeCtx is the whole-call context the client transaction was started on
// (it survives the attempt budget — the CANCEL the budget expiry sends is
// what ends the attempt). budget bounds the attempt.
func (s *Server) pumpPSTNAttempt(wholeCtx context.Context, budget time.Duration,
	l *inviteLeg, gateway string) attemptResult {

	s.watch2xx(l)
	// The budget is enforced by a timer, NOT a derived context: the client
	// transaction must outlive the budget so the expiry path can complete a
	// CANCEL against a live transaction.
	timer := time.NewTimer(budget)
	defer timer.Stop()

	responded := false // any response was received (liveness evidence)
	responses := l.clTx.Responses()
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
				continue // a 100 Trying is hop-by-hop; ours already went out
			}
			if wholeCtx.Err() != nil || l.dialog().wasCancelled() {
				// FreeSWITCH cancelled while this response was in flight:
				// nothing may be relayed (its transaction is already
				// terminated). A 2xx that raced the CANCEL still believes
				// it has a live dialog — complete and tear it down. A
				// provisional leaves the gateway's 487 still to come, so
				// drain for it.
				if res.StatusCode/100 == 2 {
					s.refuse2xx(l, res)
				}
				if res.StatusCode < 200 {
					s.abandonAttempt(l)
				}
				return attemptResult{retryable: true, kind: failDial, code: 503,
					reason: "Service Unavailable"}
			}
			// A final of 408 or >= 500 is HELD, never relayed: the server
			// transaction toward FreeSWITCH can finalise only once, and a
			// later gateway may still connect the call. The failover loop
			// synthesises this code only when every attempt has failed.
			if res.StatusCode >= 500 || res.StatusCode == 408 {
				return attemptResult{retryable: true, kind: failReal,
					code: res.StatusCode, reason: res.Reason}
			}
			responded = true
			err := s.relayInviteResponse(l, res)
			switch {
			case errors.Is(err, errResponseDropped):
				s.log.Debug("dropping unroutable pstn response", "code", res.StatusCode,
					"sip_call_id", fsip.CallID(l.req), "gateway", gateway)
				continue
			case err != nil && l.dialog().wasCancelled():
				// FreeSWITCH's CANCEL won the race with this 2xx; it has been
				// ACKed and BYEd.
				return attemptResult{retryable: true, kind: failDial, code: 503,
					reason: "Service Unavailable"}
			case err != nil:
				s.log.Warn("pstn media negotiation failed", "err", err,
					"sip_call_id", fsip.CallID(l.req), "gateway", gateway)
				// Nothing of this response reaches FreeSWITCH — not even a
				// media-bearing provisional that could not be anchored (a
				// 2xx has been ACKed and BYEd, out the PUBLIC side: the
				// gateway can only route to the public identity). 488
				// outranks every other failure at exhaustion.
				return attemptResult{retryable: true, kind: failAnchor,
					code: 488, reason: "Not Acceptable Here"}
			}
			switch {
			case res.StatusCode < 200:
				// A provisional; keep pumping.
			case res.StatusCode < 300:
				// The call is up: the dialog was confirmed from this 2xx.
				return attemptResult{ok: true}
			default:
				// Relayed and final: a 3xx, 401/407, or a 4xx other than
				// the held 408. These are the far end's verdict on THIS
				// call — a wrong number will be wrong on every gateway
				// (404/486) and a redirect is a response to this dialog —
				// so the series stops here.
				return attemptResult{retryable: false}
			}
		case <-l.clTx.Done():
			// The transaction died without a final: the INVITE never got
			// out, or the remote vanished mid-ring. Zero responses while
			// FreeSWITCH is still waiting is the cooldown case.
			return attemptResult{retryable: true, kind: failDial, code: 503,
				reason: "Service Unavailable", penalize: !responded && wholeCtx.Err() == nil}
		case <-wholeCtx.Done():
			// FreeSWITCH cancelled (or the 5-minute backstop fired): the
			// attempt ends, and the series with it. No penalize: the caller
			// gave up; the gateway was not given its chance to fail. A
			// caller's CANCEL is already on the wire; the backstop's is sent
			// here. Its 487 is not necessarily here yet — drain for it.
			s.abandonAttempt(l)
			return attemptResult{retryable: true, kind: failDial, code: 503,
				reason: "Service Unavailable"}
		case <-timer.C:
			return s.expirePSTNAttempt(wholeCtx, l, responded, gateway)
		}
	}
}

// expirePSTNAttempt ends an attempt whose budget ran out. It sends the
// CANCEL (built from the attempt's own forwarded request, so it carries the
// Via branch and destination the gateway will match), then drains the
// transaction briefly for the final that CANCEL provokes — the drain is
// what tells a gateway that answered (a 2xx that raced the CANCEL, which
// must be ACKed and BYEd or it retransmits its 200) from one that was
// simply silent (nothing within pstnDrain: the cooldown case).
func (s *Server) expirePSTNAttempt(wholeCtx context.Context, l *inviteLeg, responded bool,
	gateway string) attemptResult {
	s.log.Warn("pstn attempt budget expired; cancelling",
		"gateway", gateway, "sip_call_id", fsip.CallID(l.req))

	// A short-lived transaction of its own: per RFC 3261 §9.1 the CANCEL
	// echoes the INVITE's branch, which fsip.BuildCancel(out) provides.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.client.TransactionRequest(ctx, fsip.BuildCancel(l.out), noBuild); err != nil {
		s.log.Debug("cancel pstn attempt", "err", err, "sip_call_id", fsip.CallID(l.req))
		l.clTx.Terminate()
		return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout",
			penalize: !responded && wholeCtx.Err() == nil}
	}

	// Drain briefly. Nothing read here is relayed — the attempt is over —
	// but what arrives classifies how it ended.
	drain := time.NewTimer(pstnDrain)
	defer drain.Stop()
	responses := l.clTx.Responses()
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
				continue
			}
			switch {
			case res.StatusCode == 200:
				// A 2xx raced the CANCEL: the gateway accepted a call the
				// budget had already given up on. It responded, so no
				// cooldown; complete and tear down the dialog it believes
				// exists.
				s.log.Warn("pstn gateway answered as its attempt expired",
					"gateway", gateway, "sip_call_id", fsip.CallID(l.req))
				s.refuse2xx(l, res)
				return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout"}
			case res.StatusCode == 487:
				// The CANCEL's own product: the attempt failed by expiry.
				return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout",
					penalize: !responded && wholeCtx.Err() == nil}
			default:
				// Any other final racing the CANCEL is the gateway's real
				// word on the call; surface its code like any held final.
				return attemptResult{retryable: true, kind: failReal,
					code: res.StatusCode, reason: res.Reason}
			}
		case <-drain.C:
			// Nothing within the drain: a silent gateway. Ring timeout;
			// cooldown when FreeSWITCH was still waiting for it.
			l.clTx.Terminate()
			return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout",
				penalize: !responded && wholeCtx.Err() == nil}
		case <-wholeCtx.Done():
			// The call ended while we were draining the attempt; nothing
			// more may be relayed either way.
			l.clTx.Terminate()
			return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout",
				penalize: !responded && wholeCtx.Err() == nil}
		}
	}
}

// drainCancelledInvite reads whatever the far end still has to say after the
// call has been cancelled, briefly and without relaying any of it.
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
// When nothing final arrives in time the transaction is terminated here.
func (s *Server) drainCancelledInvite(l *inviteLeg) {
	drain := time.NewTimer(pstnDrain)
	defer drain.Stop()
	responses := l.clTx.Responses()
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
				s.refuse2xx(l, res)
			}
			if res.StatusCode >= 200 {
				// The final: a non-2xx was ACKed by the transaction layer on
				// its way in, a 2xx is being torn down. Nothing left to wait
				// for.
				return
			}
		case <-l.clTx.Done():
			// The transaction died under us (a transport error, or a
			// Terminate from another path): no response can be matched any
			// more, so there is nothing left to drain for.
			return
		case <-drain.C:
			l.clTx.Terminate()
			return
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
	bye := fsip.TeardownRequest(sip.BYE, res, from.via(fsip.NewBranch()), fsip.CSeqNumber(res)+1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clTx, err := s.client.TransactionRequest(ctx, bye, noBuild)
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
	ack := fsip.TeardownRequest(sip.ACK, res, from.via(fsip.NewBranch()), fsip.CSeqNumber(res))
	if err := s.client.WriteRequest(ack, noBuild); err != nil {
		s.log.Debug("ack unanchorable answer", "err", err)
		return false
	}
	return true
}

// commit confirms the dialog an answered INVITE established and hands its
// media session over to it: from here the session's lifetime is the
// dialog's, and dialog.end() is what releases it. It runs before the 2xx
// is relayed.
func (s *Server) commit(l *inviteLeg, final *sip.Response) bool {
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
	// callee's came back on the 200.
	if u, ok := fsip.ContactURI(l.req); ok {
		*callerContact = u
	}
	if u, ok := fsip.ContactURI(final); ok {
		*calleeContact = u
	}
	return l.dialog().confirm(fsip.ToTag(final), r)
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
	clTx, err := s.client.TransactionRequest(ctx, cancelReq, noBuild)
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
