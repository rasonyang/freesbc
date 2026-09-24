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
func (s *Server) onReInvite(req *sip.Request, tx sip.ServerTransaction) {
	from, to, dest, d, ok := s.directionFor(req)
	if !ok || d == nil || d.session() == nil {
		// No confirmed dialog with these tags, or no anchored session to
		// renegotiate against. Forwarding the body as-is here would be the
		// exact leak this function exists to prevent, so refuse instead.
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	d.noteCSeq(req)
	body := req.Body()
	if len(body) == 0 {
		// An offerless re-INVITE would make FreeSBC the offerer and
		// require answering against the ACK. Not supported; refusing is
		// honest and leaves the existing session untouched.
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}

	reOffer, parsed, err := s.rebuildInDialogOffer(d, body, to.plane)
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	out, err := s.prepareForward(req, from, to, dest, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	s.retargetInDialog(req, out, to, d)
	fsip.SetContact(out, to.uri())
	fsip.SetSDPBody(out, reOffer)

	ctx, cancel := context.WithTimeout(context.Background(), s.inviteBudget())
	defer cancel()

	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
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
			err := s.relayResponse(req, tx, res, func(relayed *sip.Response) error {
				fsip.SetContact(relayed, from.uri())
				if len(res.Body()) > 0 && answer == nil {
					reAnswer, parsedAnswer, err := s.rebuildInDialogAnswer(d, parsed, res.Body(), from.plane)
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
					if d.end() {
						s.byeBothEnds(d)
					}
				}
				return
			}
			if res.StatusCode >= 200 {
				finalised = is2xx
				return
			}
		case <-clTx.Done():
			s.reject(req, tx, 408, "Request Timeout")
			return
		case <-ctx.Done():
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
func (s *Server) onAck(req *sip.Request, tx sip.ServerTransaction, _ netip.AddrPort) {
	from, to, dest, d, ok := s.directionFor(req)
	if !ok {
		return // nothing to forward it to; an ACK gets no response
	}
	out, err := s.prepareForward(req, from, to, dest, false)
	if err != nil {
		return
	}
	s.retargetInDialog(req, out, to, d)
	if err := s.client.WriteRequest(out, noBuild); err != nil {
		s.log.Debug("forward ACK", "err", err, "sip_call_id", fsip.CallID(req))
	}
}

// onCancel handles a CANCEL that sipgo did not already match to a live
// INVITE server transaction. When it DID match, sipgo answers 200 and
// terminates the INVITE itself, which fires the OnCancel hook that
// cancels our upstream leg — so this path only sees an orphan.
func (s *Server) onCancel(req *sip.Request, tx sip.ServerTransaction, _ netip.AddrPort) {
	if d, ok := s.dialogs.early(fsip.CallID(req), fsip.FromTag(req)); ok && s.cancelCall(d, cancelOrphan) {
		s.respond(req, tx, sip.NewResponseFromRequest(req, 200, "OK", nil))
		return
	}
	// RFC 3261 §9.2: a CANCEL matching no transaction is answered 481, not
	// 200. Answering 200 would tell the sender its request was cancelled
	// when nothing was.
	s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
}

// onInDialog forwards BYE and INFO. Direction is decided by the dialog the
// request's tags name, and a BYE additionally tears the media session down
// — but only the dialog it names, and only once its far end has agreed
// the dialog is over.
func (s *Server) onInDialog(req *sip.Request, tx sip.ServerTransaction, _ netip.AddrPort) {
	from, to, dest, d, ok := s.directionFor(req)
	if !ok {
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	if d != nil {
		d.noteCSeq(req)
	}
	out, err := s.prepareForward(req, from, to, dest, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	s.retargetInDialog(req, out, to, d)
	fsip.SetContact(out, to.uri())

	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	final, err := s.forwardAndRelay(ctx, req, tx, out)
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
			if werr := s.client.WriteRequest(out.Clone(), noBuild); werr != nil {
				s.log.Warn("resend in-dialog BYE toward far side", "err", werr,
					"sip_call_id", fsip.CallID(req))
			}
			s.respond(req, tx, sip.NewResponseFromRequest(req, 200, "OK", nil))
		}
	}
	if req.Method == sip.BYE && d != nil && byeEndsDialog(final) {
		// The media ends as soon as the dialog does, rather than waiting
		// for the silence watchdog — the difference between a port
		// returning to the pool immediately and minutes later.
		d.end()
	}
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

// directionFor decides where an in-dialog request goes, from which side,
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
func (s *Server) directionFor(req *sip.Request) (from, to side, dest string, d *dialog, ok bool) {
	onPrivate := s.arrivedOnPrivate(req)
	if dd, fromCaller, found := s.dialogs.lookup(fsip.CallID(req), fsip.FromTag(req), fsip.ToTag(req)); found {
		sender := dd.callerPlane
		if !fromCaller {
			sender = otherPlane(sender)
		}
		arrived := planePublic
		if onPrivate {
			arrived = planePrivate
		}
		if arrived == sender {
			r := dd.routeSnapshot()
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
	if name, entry, found := s.selectUpstream(hashUserFor(req)); found {
		s.log.Debug("in-dialog request without a dialog record; hashing upstream",
			"sip_call_id", fsip.CallID(req), "upstream", name)
		return from, s.topo.private, entry.host, nil, true
	}
	// An empty pool cannot happen on a validated config: sip.upstream.address
	// or sip.upstreams.nodes is exactly what enables the proxy at all.
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
		r := d.routeSnapshot()
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
// over, when it was the media that ended it (the silence watchdog, or a
// WebRTC peer whose certificate did not match its fingerprint). Neither
// endpoint sent a BYE, so both still believe the call is up: FreeSWITCH
// would keep the channel and answer 481 to its own later BYE, and a phone
// would sit in a silent call (RFC 3261 §15). FreeSBC sends each one a BYE
// on behalf of the other, built from the identities and CSeqs the dialog
// record kept.
func (s *Server) byeBothEnds(d *dialog) {
	s.log.Info("media ended the call; sending BYE to both ends", "sip_call_id", d.callID)
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
	from := &sip.FromHeader{Address: b.fromURI, Params: sip.NewParams()}
	from.Params.Add("tag", b.fromTag)
	req.AppendHeader(from)
	to := &sip.ToHeader{Address: b.toURI, Params: sip.NewParams()}
	to.Params.Add("tag", b.toTag)
	req.AppendHeader(to)
	callID := sip.CallIDHeader(b.callID)
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: b.cseq, MethodName: sip.BYE})
	req.SetTransport(strings.ToUpper(toward.transport))
	req.SetDestination(b.remote)
	if toward.laddr.IP != nil && toward.laddr.Port > 0 {
		// Pinned to the listener, as prepareForward does, so the BYE leaves
		// by the socket the endpoint's NAT pinhole or WebSocket is on.
		req.Laddr = toward.laddr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clTx, err := s.client.TransactionRequest(ctx, req, noBuild)
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
