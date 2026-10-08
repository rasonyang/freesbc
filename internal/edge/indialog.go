package edge

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// onReInvite proxies an in-dialog INVITE — a hold or unhold from a client,
// a session-timer refresh from FreeSWITCH, a codec change from either.
//
// The body MUST be rewritten. Forwarding it unchanged would hand each side
// the other's media address mid-call, so the anchor would simply fall away
// on the first refresh and (for a browser) FreeSWITCH would receive ICE
// candidates and a DTLS fingerprint. What is NOT re-done is allocation:
// the session keeps the ports and, for a WebRTC leg, the ICE and DTLS
// state it already holds, so a renegotiation never interrupts media.
func (s *Server) onReInvite(req *sip.Request, tx sip.ServerTransaction, onPrivate bool) {
	from, to, dest, d, ok := s.directionFor(req, onPrivate)
	if !ok || d == nil || d.session() == nil {
		// No confirmed dialog with these tags, or no anchored session to
		// renegotiate against. Forwarding the body as-is here would be the
		// exact leak this function exists to prevent, so refuse instead.
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	d.noteCSeq(req)
	body := req.Body()
	// An offerless re-INVITE is forwarded as it is. The offer is the far
	// end's, in its 2xx, and the answer comes in the requester's ACK
	// (offerless.go).
	offerless := len(body) == 0
	if !d.beginReInviteOffer() {
		// An UPDATE offer, or an answer owed in an ACK, is pending in this
		// dialog (RFC 3311 §5.2).
		s.reject(req, tx, 491, "Request Pending")
		return
	}
	// The offer slot is held until the ACK when this re-INVITE's 2xx
	// carries an offer, then released with it (owedAnswer.release).
	keepSlot := false
	defer func() {
		if !keepSlot {
			d.endReInviteOffer()
		}
	}()
	var reOffer []byte
	var parsed *sdp.Session
	if !offerless {
		var err error
		if reOffer, parsed, err = s.rebuildInDialogOffer(d, nil, body, to.plane); err != nil {
			s.rejectMedia(req, tx, err)
			return
		}
	}
	hide, resp := s.carrierLeg(req, d, from, to)
	out, err := s.prepareForwardFor(req, from, to, dest, false, hide)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	s.noteOutbound(req, d, hide)
	s.retargetInDialog(req, out, to, d)
	fsip.SetContact(out, to.uri())
	if offerless {
		stripBody(out)
	} else {
		fsip.SetSDPBody(out, reOffer)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.inviteBudget())
	defer cancel()

	clTx, err := s.clientTx(ctx, out)
	if err != nil {
		s.log.Debug("forward re-INVITE", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}

	// The answer built for THIS transaction — never another re-INVITE's,
	// which may be crossing this one from the other side (glare) — and the
	// answer as the far end sent it. A 200 restating the answer an earlier
	// provisional carried gets the same body again.
	var answer []byte
	var farAnswer *sdp.Session
	// The relayed 2xx, for its retransmissions: as with the initial INVITE
	// the client transaction is kept until Timer M, and each retransmitted
	// 2xx is relayed again (RFC 3261 §13.3.1.4).
	var mu sync.Mutex
	var okOut *sip.Response
	refused := false
	clTx.OnRetransmission(func(res *sip.Response) {
		mu.Lock()
		ok, again := okOut, refused
		mu.Unlock()
		if again {
			// A 2xx FreeSBC could not anchor, retransmitted: its ACK was
			// lost, so send it again.
			go s.ack2xx(res, to)
			return
		}
		if ok == nil || fsip.ToTag(res) != fsip.ToTag(ok) {
			return
		}
		out := ok.Clone()
		out.SetDestination(req.Source())
		s.metrics.ResponseOut(out.StatusCode)
		_ = tx.Respond(out)
	})
	finalised := false
	defer func() {
		if !finalised {
			clTx.Terminate()
		}
	}()

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
				continue
			}
			is2xx := res.StatusCode/100 == 2
			err := s.relayResponseHide(req, tx, res, resp, func(relayed *sip.Response) error {
				fsip.SetContact(relayed, from.uri())
				if offerless {
					// The far end's offer in the 2xx is rebuilt for the
					// requester; any other body (an unreliable 18x) is not
					// an offer it can answer and is dropped. The answer is
					// owed from here, and nothing moves until the ACK.
					if !is2xx || len(res.Body()) == 0 {
						stripBody(relayed)
						if is2xx {
							mu.Lock()
							okOut = relayed.Clone()
							mu.Unlock()
						}
						return nil
					}
					if answer == nil {
						offerBody, offerParsed, err := s.rebuildInDialogOffer(d, nil, res.Body(), from.plane)
						if err != nil {
							return err
						}
						answer = offerBody
						d.setOwed(&owedAnswer{offer: offerParsed, offerer: to.plane, answerer: from.plane,
							cseq: fsip.CSeqNumber(req), release: d.endReInviteOffer})
						keepSlot = true
					}
					fsip.SetSDPBody(relayed, answer)
					mu.Lock()
					okOut = relayed.Clone()
					mu.Unlock()
					return nil
				}
				if len(res.Body()) > 0 && answer == nil {
					reAnswer, parsedAnswer, err := s.rebuildInDialogAnswer(d, nil, parsed, res.Body(), from.plane)
					if err != nil {
						return err
					}
					answer, farAnswer = reAnswer, parsedAnswer
				}
				if len(res.Body()) > 0 {
					fsip.SetSDPBody(relayed, answer)
				}
				if is2xx {
					// The offer/answer exchange is complete: whichever side
					// moved its media, the anchor follows now (RFC 3264
					// §8.3.1-8.3.2).
					s.applyReInvite(d, from.plane, parsed, to.plane, farAnswer)
					mu.Lock()
					okOut = relayed.Clone()
					mu.Unlock()
				}
				return nil
			})
			switch {
			case errors.Is(err, errResponseDropped):
				s.log.Debug("dropping unroutable re-INVITE response", "code", res.StatusCode, "sip_call_id", fsip.CallID(req))
				continue
			case err != nil:
				s.log.Warn("re-INVITE media negotiation failed", "err", err, "sip_call_id", fsip.CallID(req))
				s.reject(req, tx, 488, "Not Acceptable Here")
				if is2xx {
					// The far end accepted a session FreeSBC cannot anchor.
					// Its 2xx must still be ACKed (RFC 3261 §13.3.1.4) or it
					// retransmits and then drops the call; and the two ends
					// now disagree about the session — media would flow in a
					// form one of them never agreed to — so the call is ended
					// on both sides rather than left half-renegotiated.
					finalised = true
					mu.Lock()
					refused = true
					mu.Unlock()
					s.ack2xx(res, to)
					if d.end(endReinviteRefused) {
						s.byeBothEnds(d, endReinviteRefused)
					}
				}
				return
			}
			if res.StatusCode >= 200 {
				finalised = is2xx
				if is2xx {
					s.armOwedTimer(d)
				}
				return
			}
		case <-clTx.Done():
			s.reject(req, tx, 408, "Request Timeout")
			return
		case <-ctx.Done():
			// The backstop expired with only provisionals seen. sipgo uses
			// ctx only to send, so the client transaction is still live:
			// CANCEL it (RFC 3261 §16.8, as giveUp does for an initial
			// INVITE) and answer the requester 408, or it waits out its own
			// timer and the far end keeps an open INVITE transaction that
			// 491s every later re-INVITE (§14.1).
			s.abandonReInvite(req, tx, out, clTx, to)
			return
		}
	}
}

// abandonReInvite ends a re-INVITE whose backstop expired: the requester is
// answered 408 and the forwarded re-INVITE is CANCELled. CANCEL is built
// from out, the request as it went on the wire, so a carrier leg's CANCEL
// carries the same hidden identity as the re-INVITE (hide.go). The
// transaction is then drained for the final the CANCEL provokes, so a 487
// is ACKed by the transaction layer and a 2xx that crossed the CANCEL is
// ACKed here rather than retransmitted.
func (s *Server) abandonReInvite(req *sip.Request, tx sip.ServerTransaction, out *sip.Request,
	clTx sip.ClientTransaction, to side) {
	s.reject(req, tx, 408, "Request Timeout")
	s.sendCancel(&inviteAttempt{req: out, cancel: func() {}})
	drain := time.NewTimer(cancelDrain)
	defer drain.Stop()
	responses := clTx.Responses()
	for {
		select {
		case res, ok := <-responses:
			if !ok {
				responses = nil
				continue
			}
			if res.StatusCode/100 == 2 {
				s.ack2xx(res, to)
			}
			if res.StatusCode >= 200 {
				return
			}
		case <-clTx.Done():
			return
		case <-drain.C:
			return
		}
	}
}

// applyReInvite points the anchored media at whatever a completed
// re-INVITE moved: the offerer's side at the address its offer signalled,
// the answerer's side at its answer's. A side whose address is unchanged
// (a hold, a session-timer refresh) is left alone, and a side that
// signalled no usable address (port 0, or the RFC 2543 hold address
// 0.0.0.0) keeps the one it had.
func (s *Server) applyReInvite(d *dialog, offerer plane, offer *sdp.Session, answerer plane, answer *sdp.Session) {
	sess := d.session()
	for _, x := range []struct {
		p    plane
		body *sdp.Session
	}{{offerer, offer}, {answerer, answer}} {
		if x.body == nil {
			continue
		}
		a := x.body.Audio
		if !a.Address.IsValid() || a.Address.IsUnspecified() || a.Port <= 0 {
			continue
		}
		remote := netip.AddrPortFrom(a.Address, uint16(a.Port))
		var rtcp netip.AddrPort
		if a.RTCPPort > 0 {
			rtcp = netip.AddrPortFrom(a.Address, uint16(a.RTCPPort))
		}
		s.pointMedia(sess, x.p, remote, rtcp)
	}
}

// onAck forwards an ACK. A 2xx ACK is a separate end-to-end transaction
// (RFC 3261 §17.1.1.3) and must be sent statelessly, not through a client
// transaction — sipgo enforces this by refusing an ACK in
// TransactionRequest.
func (s *Server) onAck(req *sip.Request, tx sip.ServerTransaction, in inbound) {
	from, to, dest, d, ok := s.directionFor(req, in.private())
	if !ok {
		return // nothing to forward it to; an ACK gets no response
	}
	hide, _ := s.carrierLeg(req, d, from, to)
	out, err := s.prepareForwardFor(req, from, to, dest, false, hide)
	if err != nil {
		return
	}
	s.noteOutbound(req, d, hide)
	s.retargetInDialog(req, out, to, d)
	if d == nil && !in.private() {
		s.restoreCarrierRURI(req, out)
	}
	if !in.private() {
		s.stampCarrier(out, req, d)
	}
	// The ACK carries a body only as the answer to an offer FreeSBC owes
	// the far end (offerless.go); that body is rebuilt, never passed on.
	// Any other body is dropped. An ACK cannot be refused, so when the owed
	// answer is missing or unusable it is forwarded without one and the
	// call is ended on both sides.
	answerFailed := false
	var owed *owedAnswer
	if d != nil {
		d.ackMu.Lock()
		defer d.ackMu.Unlock()
		owed = d.takeOwed(from.plane, fsip.CSeqNumber(req))
	}
	if owed != nil {
		body, err := s.answerFromACK(d, owed, req.Body())
		if err != nil {
			s.log.Warn("answer to a delayed offer unusable; ending the call", "err", err, "sip_call_id", fsip.CallID(req))
			stripBody(out)
			answerFailed = true
		} else {
			fsip.SetSDPBody(out, body)
			d.setAckAnswer(from.plane, owed.cseq, body)
		}
		owed.finish()
	} else {
		var again []byte
		if d != nil {
			again = d.ackAnswerFor(from.plane, fsip.CSeqNumber(req))
		}
		switch {
		case again != nil:
			// A retransmitted ACK: the first may not have reached the
			// callee, which then retransmits its 2xx. The answer is
			// restated as it was built, and the media is not touched again.
			fsip.SetSDPBody(out, again)
		case len(out.Body()) > 0:
			stripBody(out)
		}
	}
	if err := s.writeRequest(out); err != nil {
		s.log.Debug("forward ACK", "err", err, "sip_call_id", fsip.CallID(req))
	}
	if answerFailed && d.end(endAnswerUnusable) {
		s.byeBothEnds(d, endAnswerUnusable)
	}
}

// onCancel handles a CANCEL that sipgo did not already match to a live
// INVITE server transaction. When it DID match, sipgo answers 200 and
// terminates the INVITE itself, which fires the OnCancel hook that
// cancels our upstream leg — so this path only sees an orphan.
func (s *Server) onCancel(req *sip.Request, tx sip.ServerTransaction, _ inbound) {
	if d, ok := s.dialogs.early(fsip.CallID(req), fsip.FromTag(req)); ok && s.cancelCall(d, cancelOrphan) {
		s.respond(req, tx, sip.NewResponseFromRequest(req, 200, "OK", nil))
		return
	}
	// RFC 3261 §9.2: a CANCEL matching no transaction is answered 481, not
	// 200. Answering 200 would tell the sender its request was cancelled
	// when nothing was.
	s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
}

// onInDialog forwards BYE, INFO, NOTIFY, REFER, MESSAGE, PRACK and UPDATE
// (MESSAGE also out of dialog from the switch, see below). Direction is
// decided by the dialog the request's tags name, and a BYE additionally
// tears the media session down — but only the dialog it names, and only
// once its far end has agreed the dialog is over.
//
// NOTIFY is forwarded whatever its Event: the proxy carries no policy, and
// the endpoint interprets talk, hold, conference or refer itself. A NOTIFY
// from FreeSWITCH on an EARLY dialog (Event: talk answering a ringing
// phone) matches no confirmed dialog; directionFor routes it by the fsbc=
// binding token its Request-URI carries, exactly as it routes the INVITE.
//
// A NOTIFY is first matched against the SUBSCRIBE dialogs FreeSBC carried
// (subTable, subscribe.go) by Call-ID and both tags, from either plane, and
// forwarded along the subscription; a terminated Subscription-State or a
// 481 ends the record. Only a NOTIFY that matches no subscription goes on
// to the rules below.
//
// Out-of-dialog NOTIFY (no To tag) is decided per plane, on purpose:
//   - From the private plane (FreeSWITCH, trusted) it is forwarded when its
//     Request-URI carries the token of a binding FreeSBC holds — the MWI
//     case, Event: message-summary. Without such a binding directionFor
//     finds no target and it is answered 481, which is what RFC 6665
//     §4.1.3 prescribes for a NOTIFY that matches no subscription.
//   - From the public plane it is answered 481: a NOTIFY needs a
//     subscription, and an unsolicited one from the internet would only add
//     load on a switch.
//
// A private-plane NOTIFY that HAS a To tag but that directionFor cannot
// route (issue #84) is forwarded by Call-ID alone, through
// relaxedNotifyDirection: FreeSWITCH's uuid_phone_event NOTIFY copies its
// To from a channel variable, so the tag can be another leg's. It is
// answered 481 only when no dialog with a public route carries the
// Call-ID. BYE, INFO and ACK, and every NOTIFY from the public plane, keep
// exact tag matching.
//
// A public NOTIFY that matches neither a subscription nor an INVITE dialog
// (the refer sipfrag NOTIFY of a transfer rides the call's dialog) is
// answered 481, not hashed upstream. The no-To-tag rule above is separate
// and unchanged.
//
// REFER (RFC 3515) is in-dialog only and forwarded unchanged, so Refer-To,
// Referred-By and Replaces reach the other end as written; the transfer
// target's call is that endpoint's own INVITE, admitted like any other. It
// is answered 481 with no To tag or no matching dialog, and 603 on a
// carrier dialog (never forwarded).
//
// A MESSAGE from the public plane that names no dialog is likewise 481: the
// generic fallback that hashes an unmatched public in-dialog request
// upstream would let a made-up To tag carry it past admission. A MESSAGE
// from the switch with no To tag is classified by Request-URI above and
// delivered to the client its token names, or answered 404 when the token
// names no live binding (onMessage sends everything else here).
func (s *Server) onInDialog(req *sip.Request, tx sip.ServerTransaction, in inbound) {
	if req.Method == sip.NOTIFY && fsip.ToTag(req) == "" && !in.private() {
		s.reject(req, tx, 481, "Subscription Does Not Exist")
		return
	}
	if in.private() && fsip.ToTag(req) == "" {
		// An out-of-dialog request from the switch is classified by its
		// Request-URI alone (classifySwitchRequest). Only a client token
		// goes on to directionFor; a carrier accepts REGISTER, INVITE and
		// OPTIONS only; anything else is nobody's.
		switch kind, _ := s.classifySwitchRequest(req); kind {
		case targetClient:
		case targetCarrier:
			s.respond(req, tx, methodNotAllowed(req))
			return
		default:
			s.reject(req, tx, 404, "Not Found")
			return
		}
	}
	if req.Method == sip.REFER && fsip.ToTag(req) == "" {
		// A REFER is only ever in-dialog (RFC 3515): there is no
		// out-of-dialog form to route, from either plane.
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	if req.Method == sip.NOTIFY && fsip.ToTag(req) != "" {
		// A NOTIFY on a subscription FreeSBC carried (subscribe.go) goes
		// back along it, whatever INVITE dialogs share the Call-ID.
		arrived := planePublic
		if in.private() {
			arrived = planePrivate
		}
		if sub, v, fromSub, ok := s.subs.lookup(fsip.CallID(req), fsip.FromTag(req), fsip.ToTag(req), arrived, req.Method); ok {
			s.forwardInSubscription(req, tx, sub, v, fromSub)
			return
		}
	}
	from, to, dest, d, ok := s.directionFor(req, in.private())
	if !ok && req.Method == sip.NOTIFY && fsip.ToTag(req) != "" && in.private() {
		from, to, dest, d, ok = s.relaxedNotifyDirection(req)
	}
	if !ok {
		if req.Method == sip.MESSAGE && in.private() && fsip.ToTag(req) == "" {
			// An out-of-dialog switch MESSAGE whose token names no live
			// binding is nobody's: 404, as for any unknown token.
			s.reject(req, tx, 404, "Not Found")
			return
		}
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	// directionFor forwards a public in-dialog request that names no
	// dialog to the hashed switch (FreeSWITCH answers 481 itself). That is
	// right for a BYE or INFO, but a REFER, MESSAGE or NOTIFY would then
	// reach the switch past admission with nothing but a made-up To tag,
	// so these are answered 481 here. A switch REFER is refused the same way: it
	// has no dialog to refer. A private MESSAGE with no dialog is the
	// out-of-dialog case, routed by its client token.
	if d == nil && (req.Method == sip.REFER || ((req.Method == sip.MESSAGE || req.Method == sip.NOTIFY) && !in.private())) {
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	// Call transfer is the switch's business, and a carrier leg's Refer-To
	// would name an address on the far side of the topology hiding. A
	// REFER on a carrier dialog is declined, never forwarded.
	if req.Method == sip.REFER && d.carrierName() != "" {
		s.log.Info("REFER on a carrier dialog declined", "sip_call_id", fsip.CallID(req),
			"carrier", d.carrierName())
		s.reject(req, tx, 603, "Decline")
		return
	}
	if d != nil {
		d.noteCSeq(req)
	}
	// An UPDATE with SDP is an offer: its body is rebuilt like a
	// re-INVITE's and the answer in its 2xx the same way (update.go).
	// onPrackUpdate has established that d is a dialog it belongs to.
	var ux *updateExchange
	if req.Method == sip.UPDATE && len(req.Body()) > 0 {
		var err error
		if ux, err = s.beginUpdate(req, d, from, to); err != nil {
			if errors.Is(err, errOfferPending) {
				s.reject(req, tx, 491, "Request Pending")
			} else {
				s.rejectMedia(req, tx, err)
			}
			return
		}
		defer ux.end()
	}
	// A PRACK with SDP is the answer to an offer in a reliable 18x of an
	// offerless INVITE: it is rebuilt for the callee and applied when the
	// callee accepts it. onPrackUpdate has checked that one is owed.
	var pk *owedAnswer
	var pkBody []byte
	var pkAnswer *sdp.Session
	if req.Method == sip.PRACK && len(req.Body()) > 0 {
		if pk = d.owedForPrack(req, from.plane); pk == nil {
			s.reject(req, tx, 488, "Not Acceptable Here")
			return
		}
		var err error
		if pkBody, pkAnswer, err = s.prepareOwed(d, pk, req.Body()); err != nil {
			s.rejectMedia(req, tx, err)
			return
		}
	}
	hide, resp := s.carrierLeg(req, d, from, to)
	out, err := s.prepareForwardFor(req, from, to, dest, false, hide)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	s.noteOutbound(req, d, hide)
	s.retargetInDialog(req, out, to, d)
	if d == nil && !in.private() {
		s.restoreCarrierRURI(req, out)
	}
	if pk != nil {
		fsip.SetSDPBody(out, pkBody)
	}
	// A PRACK carries no Contact, and a MESSAGE only when the sender
	// supplied one.
	if req.Method != sip.PRACK && (req.Method != sip.MESSAGE || len(req.GetHeaders("Contact")) > 0) {
		fsip.SetContact(out, to.uri())
	}
	if !in.private() {
		s.stampCarrier(out, req, d)
	}
	var adapt func(*sip.Response) error
	var answerErr error
	rebuilt := false // the response body in hand is one FreeSBC built
	if pk != nil {
		adapt = func(res *sip.Response) error {
			if res.StatusCode/100 == 2 && d.dropOwed(pk) {
				pk.finish()
				answerErr = s.applyOwed(d, pk, pkAnswer)
			}
			return answerErr
		}
	}
	if req.Method == sip.REFER || req.Method == sip.MESSAGE {
		adapt = func(res *sip.Response) error {
			// A 2xx to a REFER may carry a Contact (a target refresh,
			// RFC 3515), and a 3xx to a MESSAGE one (RFC 3428): it must
			// name FreeSBC, not the far endpoint.
			if len(res.GetHeaders("Contact")) > 0 {
				fsip.SetContact(res, from.uri())
			}
			return nil
		}
	}
	if req.Method == sip.UPDATE {
		if ux != nil {
			fsip.SetSDPBody(out, ux.offerBody)
		}
		adapt = func(res *sip.Response) error {
			// The 2xx's Contact refreshes the requester's remote target
			// (RFC 3311 §5.2): it must name FreeSBC, not the far endpoint.
			if len(res.GetHeaders("Contact")) > 0 {
				fsip.SetContact(res, from.uri())
			}
			if ux != nil && res.StatusCode/100 == 2 {
				had := len(res.Body()) > 0
				if answerErr = ux.answered(res); answerErr != nil {
					return answerErr
				}
				rebuilt = had
			}
			return nil
		}
	}

	// A response body FreeSBC did not rebuild never crosses: a PRACK or
	// UPDATE response carries SDP only as the answer rebuilt above, and any
	// SDP in another in-dialog response (INFO, NOTIFY, BYE) is the far
	// end's own addresses. Non-SDP bodies of INFO and the like pass.
	inner := adapt
	adapt = func(res *sip.Response) error {
		rebuilt = false
		if inner != nil {
			if err := inner(res); err != nil {
				return err
			}
		}
		if len(res.Body()) > 0 && !rebuilt &&
			(req.Method == sip.PRACK || req.Method == sip.UPDATE || isSDPBody(res)) {
			stripBody(res)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	final, err := s.forwardAndRelay(ctx, req, tx, out, resp, adapt)
	if err != nil {
		s.log.Warn("forward in-dialog request failed", "err", err,
			"method", req.Method.String(), "sip_call_id", fsip.CallID(req))
		// The far side never answered, or the request never got out. For a
		// BYE the dialog is over either way, and answering 408 tells the
		// switch its hangup FAILED when the proxy is the one that could
		// not deliver — sofia treats that as a failed BYE and keeps the
		// leg. Answer 200 instead: the dialog IS being ended, which the
		// teardown below reflects. And make one stateless attempt to put
		// the BYE on the wire toward the far side ourselves, so a phone
		// that never saw it is told the call is over and stops sending
		// media. A duplicate BYE is harmless (a dialog is only ended once);
		// the far end's answer to it has no transaction left to match and
		// is absorbed by the transport layer.
		if req.Method == sip.BYE {
			// A clone: the failed client transaction may still hold the
			// original request (a retransmission timer winding down), so
			// handing the same object to WriteRequest would race it.
			if werr := s.writeRequest(out.Clone()); werr != nil {
				s.log.Warn("resend in-dialog BYE toward far side", "err", werr,
					"sip_call_id", fsip.CallID(req))
			}
			s.respond(req, tx, sip.NewResponseFromRequest(req, 200, "OK", nil))
		}
	}
	if answerErr != nil {
		// The far end accepted an offer whose answer FreeSBC cannot anchor
		// (nothing was relayed or applied): the requester is refused, and
		// since the two ends now disagree about the session the call is
		// ended on both, as for a re-INVITE.
		s.log.Warn("UPDATE media negotiation failed", "err", answerErr, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
		if ux != nil && ux.fork == nil {
			if d.end(endAnswerUnusable) {
				s.byeBothEnds(d, endAnswerUnusable)
			}
		} else {
			s.cancelCall(d, cancelBackstop)
		}
		return
	}
	if req.Method == sip.BYE && d != nil && byeEndsDialog(final) {
		// The media ends as soon as the dialog does, rather than waiting
		// for the silence watchdog — the difference between a port
		// returning to the pool immediately and minutes later.
		why := endByeCallee
		switch {
		case err != nil:
			why = endByeUnanswered
		case from.plane == d.callerPlane:
			why = endByeCaller
		}
		d.end(why)
	}
}

// relaxedNotifyDirection routes a NOTIFY from the private plane whose tags
// name no dialog (issue #84). FreeSWITCH sends the uuid_phone_event NOTIFY
// (Event: talk/hold, BroadSoft remote call control) with a To header
// copied verbatim from the sip_full_to channel variable (mod_sofia.c,
// SWITCH_MESSAGE_INDICATE_PHONE_EVENT), so its tag can belong to another
// leg; the client accepts it when registered directly to FreeSWITCH, and a
// proxy stricter than the endpoint would leave a held call un-resumable.
//
// The caller has already established that the request is a NOTIFY with a
// To tag, that it arrived on the private plane (FreeSWITCH, trusted), and
// that directionFor found no route. The rule is then: a NOTIFY from the
// private plane whose Call-ID names a dialog FreeSBC holds is forwarded to
// that dialog's public side, and is never refused because of its tags —
// neither the To tag nor the From tag is checked. When several records
// share the Call-ID, the most recently created one with a usable public
// route is chosen (newestRoutedByCallID; in practice the newest confirmed
// dialog, because only a confirmed record has a route). It is still
// refused (ok false, answered 481) when no record carries the Call-ID or
// none has a public side to send to — there is nowhere to deliver it.
//
// The To header is forwarded verbatim: rewriting it to the dialog's tag
// would make FreeSBC fabricate dialog state. The first relaxed routing on a
// dialog is logged at WARN and later ones (FreeSWITCH retries about once a
// second) at Debug, so an operator can see when the upstream defect stops
// occurring. There is no counter: the edge metrics count requests by
// method and transport, and none of them fits a routing decision.
func (s *Server) relaxedNotifyDirection(req *sip.Request) (from, to side, dest string, d *dialog, ok bool) {
	callID := fsip.CallID(req)
	dd, r, found := s.dialogs.newestRoutedByCallID(callID)
	if !found {
		return side{}, side{}, "", nil, false
	}
	to, ok = s.topo.publicSide(r.transport)
	if !ok {
		return side{}, side{}, "", nil, false
	}
	callerTag, calleeTag := dd.tags()
	attrs := []any{"sip_call_id", callID, "from_tag", fsip.FromTag(req), "stray_to_tag", fsip.ToTag(req),
		"dialog_caller_tag", callerTag, "dialog_callee_tag", calleeTag}
	if dd.noteRelaxedNotify() {
		s.log.Warn("NOTIFY tags match no dialog; routed by Call-ID", attrs...)
	} else {
		s.log.Debug("NOTIFY tags match no dialog; routed by Call-ID", attrs...)
	}
	return s.topo.private, to, r.publicRemote, dd, true
}

// byeEndsDialog reports whether the far end's answer to a tag-matched BYE
// ends the dialog: a 2xx; a 481 or 408, which RFC 3261 §12.2.1.2 says end
// it for the sender too; or no answer at all (the proxy could not deliver
// it, and has answered the sender 200). Anything else — a 401/407
// challenge, a 491 — leaves the call up.
func byeEndsDialog(final *sip.Response) bool {
	if final == nil {
		return true
	}
	return final.StatusCode/100 == 2 || final.StatusCode == 481 || final.StatusCode == 408
}

// directionFor decides where an in-dialog request goes, from which side
// (onPrivate: it arrived on the private bind, see arrival.go),
// and — when the request names one — which confirmed dialog it belongs
// to.
//
// A dialog is identified by the Call-ID and BOTH tags (RFC 3261 §12). The
// request's From and To tags say which endpoint sent it, and it must also
// have arrived on that endpoint's plane: a request that names the caller's
// tags but came in from the callee's side is not this dialog's. A request
// that names no confirmed dialog is still routed — FreeSBC is a proxy, and
// the endpoint itself answers 481 honestly — but d is nil, so nothing is
// torn down on its account.
func (s *Server) directionFor(req *sip.Request, onPrivate bool) (from, to side, dest string, d *dialog, ok bool) {
	dd, fromCaller, found := s.dialogs.lookup(fsip.CallID(req), fsip.FromTag(req), fsip.ToTag(req))
	var r dialogRoute
	switch {
	case found:
		r = dd.routeSnapshot()
	case req.Method == sip.PRACK || req.Method == sip.UPDATE:
		// These two are valid in an early dialog. Everything else keeps
		// requiring a confirmed one (a re-INVITE needs a committed
		// session; a NOTIFY on an early dialog is routed by its token).
		dd, r, fromCaller, found = s.dialogs.lookupEarly(fsip.CallID(req), fsip.FromTag(req), fsip.ToTag(req))
	}
	if found {
		sender := dd.callerPlane
		if !fromCaller {
			sender = otherPlane(sender)
		}
		arrived := planePublic
		if onPrivate {
			arrived = planePrivate
		}
		if arrived == sender {
			if onPrivate {
				if to, ok = s.topo.publicSide(r.transport); ok && r.publicRemote != "" {
					return s.topo.private, to, r.publicRemote, dd, true
				}
				return side{}, side{}, "", nil, false
			}
			if from, ok = s.publicSideFor(req); ok && r.privateRemote != "" {
				return from, s.topo.private, r.privateRemote, dd, true
			}
			return side{}, side{}, "", nil, false
		}
	}
	if onPrivate {
		// An IN-DIALOG request from FreeSWITCH carries no binding token.
		// The token only ever rides on the contact FreeSBC REGISTERED; a
		// dialog's remote target is the Contact FreeSBC put in the INVITE
		// or the 200, which names the SBC and nothing else. So the dialog
		// record — not the location table — is what identifies the client
		// here, and without one this falls back to the binding token, which
		// is how a PRE-dialog request (an inbound INVITE) is routed.
		b, found := s.bindingForRequest(req)
		if !found {
			return side{}, side{}, "", nil, false
		}
		to, ok = s.topo.publicSide(b.Transport)
		if !ok {
			return side{}, side{}, "", nil, false
		}
		return s.topo.private, to, b.Source.String(), nil, true
	}
	from, ok = s.publicSideFor(req)
	if !ok {
		return side{}, side{}, "", nil, false
	}
	// No dialog on record — one already ended, or a request with tags that
	// name none. Recompute the node from the same identity and the same
	// pool the INVITE was hashed with: for every request the caller itself
	// causes that is the node the INVITE went to. It deliberately NEVER
	// 481s: a request the SBC cannot place is still better forwarded to the
	// most plausible switch than refused, and the switch itself answers
	// honestly if the dialog is unknown to it. (A dialog that IS on record
	// is found above; the record of which switch carries it is the whole
	// stickiness guarantee — a dialog must never migrate between switches
	// mid-call.)
	//
	// A carrier's request is hashed by the DID (as its INVITE was) and goes
	// to the node's carrier port; stampCarrier names the carrier.
	if _, isCarrier := s.carrierFallback(req); isCarrier {
		if name, entry, found := s.selectUpstream(carrierHashUser(req)); found {
			s.log.Debug("carrier in-dialog request without a dialog record; hashing upstream",
				"sip_call_id", fsip.CallID(req), "upstream", name)
			return from, s.topo.private, entry.carrierAddr().String(), nil, true
		}
		return side{}, side{}, "", nil, false
	}
	if name, entry, found := s.selectUpstream(hashUserFor(req)); found {
		s.log.Debug("in-dialog request without a dialog record; hashing upstream",
			"sip_call_id", fsip.CallID(req), "upstream", name)
		return from, s.topo.private, entry.host, nil, true
	}
	// An empty pool cannot happen on a validated config: edge.switch
	// is exactly what enables the proxy at all.
	return side{}, side{}, "", nil, false
}

// otherPlane is the plane across the proxy from p.
func otherPlane(p plane) plane {
	if p == planePublic {
		return planePrivate
	}
	return planePublic
}

// retargetInDialog replaces the Request-URI of a forwarded in-dialog
// request with the far endpoint's own Contact, undoing the topology hiding
// the proxy applied when the dialog was established. Falls back to the
// registration binding (for a request that reaches a client outside any
// dialog we track), and leaves the URI alone when neither is known.
func (s *Server) retargetInDialog(req, out *sip.Request, to side, d *dialog) {
	if d != nil {
		r := d.routeFor(req)
		u := r.privateContact
		if to.plane == planePublic {
			u = r.publicContact
		}
		if u.Host != "" {
			out.Recipient = u
			return
		}
	}
	if to.plane == planePublic {
		if b, ok := s.bindingForRequest(req); ok {
			out.Recipient = clientRequestURI(b)
		}
	}
}

// byeBothEnds tells both endpoints of a confirmed dialog that the call is
// over, when FreeSBC ended it on its own (the silence watchdog, a WebRTC
// peer whose certificate did not match its fingerprint, an answer it could
// not anchor). Neither endpoint sent a BYE, so both still believe the call
// is up: FreeSWITCH would keep the channel and answer 481 to its own later
// BYE, and a phone would sit in a silent call (RFC 3261 §15). FreeSBC sends
// each one a BYE on behalf of the other, built from the identities and CSeqs
// the dialog record kept. why is the reason end() recorded.
func (s *Server) byeBothEnds(d *dialog, why endReason) {
	s.log.Info("ending the call; sending BYE to both ends",
		"sip_call_id", d.callID, "reason", why.String())
	for _, b := range d.byes() {
		go s.sendMiddleBye(b)
	}
}

// sendMiddleBye sends one BYE FreeSBC originates in the middle of a
// dialog.
func (s *Server) sendMiddleBye(b byeInfo) {
	var toward side
	if b.toward == planePrivate {
		toward = s.topo.private
	} else {
		var ok bool
		if toward, ok = s.topo.publicSide(b.transport); !ok {
			return
		}
	}
	if b.remote == "" {
		return
	}
	ruri := b.contact
	if ruri.Host == "" {
		host, port, err := net.SplitHostPort(b.remote)
		if err != nil {
			return
		}
		ruri = sip.Uri{Host: host}
		ruri.Port, _ = strconv.Atoi(port)
	}
	req := sip.NewRequest(sip.BYE, ruri)
	req.AppendHeader(toward.via(fsip.NewBranch()))
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	if b.carrier && toward.plane == planePublic {
		// Identity toward a carrier never names the switch (hide.go).
		s.maskURI(&b.fromURI, toward.advIP)
		s.maskURI(&b.toURI, toward.advIP)
	}
	from := &sip.FromHeader{Address: b.fromURI, Params: sip.NewParams()}
	from.Params.Add("tag", b.fromTag)
	req.AppendHeader(from)
	to := &sip.ToHeader{Address: b.toURI, Params: sip.NewParams()}
	to.Params.Add("tag", b.toTag)
	req.AppendHeader(to)
	callID := sip.CallIDHeader(b.callID)
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: b.cseq, MethodName: sip.BYE})
	cl := sip.ContentLengthHeader(0) // stream transports need it (see TeardownRequest)
	req.AppendHeader(&cl)
	req.SetTransport(strings.ToUpper(toward.transport))
	req.SetDestination(b.remote)
	if toward.laddr.IP != nil && toward.laddr.Port > 0 {
		// Pinned to the listener, as prepareForward does, so the BYE leaves
		// by the socket the endpoint's NAT pinhole or WebSocket is on.
		req.Laddr = toward.laddr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clTx, err := s.clientTx(ctx, req)
	if err != nil {
		s.log.Debug("bye after media end", "err", err, "sip_call_id", b.callID)
		return
	}
	defer clTx.Terminate()
	select {
	case <-clTx.Responses():
	case <-clTx.Done():
	case <-ctx.Done():
	}
}
