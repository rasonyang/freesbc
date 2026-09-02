package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/media"
	"github.com/freesbc/freesbc/sdpx"
)

// inviteTimeout bounds an INVITE transaction end to end. It is longer than
// a typical ring cap because the far end, not FreeSBC, decides when to
// give up; this is a backstop against a transaction that never finalises
// pinning a media session forever.
const inviteTimeout = 5 * time.Minute

// onInvite proxies a call in whichever direction it is going and anchors
// its media.
//
// The two directions are genuinely different — one starts from a public
// client and ends at FreeSWITCH, the other starts at FreeSWITCH and ends
// at a registered binding — but they share this shape:
//
//	parse the offer → allocate media → build the far-side offer →
//	forward → on the answer, negotiate codecs and build the near-side
//	answer → relay → tie the media session's lifetime to the dialog.
func (s *Server) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	src, ok := sourceAddrPort(req)
	if !ok {
		return
	}
	if isInDialog(req) {
		s.onReInvite(req, tx)
		return
	}
	if s.arrivedOnPrivate(req) {
		s.inviteToClient(req, tx)
		return
	}
	s.inviteToUpstream(req, tx, src)
}

// inviteToUpstream handles a call placed BY a public client.
func (s *Server) inviteToUpstream(req *sip.Request, tx sip.ServerTransaction, src netip.AddrPort) {
	from, ok := s.publicSideFor(req)
	if !ok {
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}
	body := req.Body()
	if len(body) == 0 {
		// An offerless INVITE would make FreeSBC the offerer toward
		// FreeSWITCH and then require a second negotiation against the
		// client's ACK. Not supported in this phase; refusing is honest.
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), inviteTimeout)
	defer cancel()

	offer, err := s.buildUpstreamOffer(ctx, body)
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = offer.sess.Close()
		}
	}()

	out, err := s.prepareForward(req, from, s.topo.private, s.topo.upstreamHost, true)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	// The client's Contact must not reach FreeSWITCH: it names the
	// client's own address (or, for a browser, an unreachable .invalid
	// host), and FreeSWITCH would send in-dialog requests straight to it,
	// bypassing the SBC entirely.
	setContact(out, s.topo.private.uri())
	setSDP(out, offer.sdp)

	s.log.Info("proxying INVITE upstream",
		"sip_call_id", callIDOf(req), "direction", "public->private",
		"transport", from.transport, "public_remote", src.String(),
		"rtp_public_port", offer.sess.publicPort,
		"rtp_private_port", offer.sess.privatePort,
		"codec", codecNames(offer.sess.codecs))

	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
	if err != nil {
		s.log.Warn("forward INVITE upstream", "err", err, "sip_call_id", callIDOf(req))
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	defer clTx.Terminate()
	s.trackPending(req, &pendingInvite{req: out, dest: s.topo.upstreamHost, side: s.topo.private, cancel: cancel})
	defer s.untrackPending(req)

	// A CANCEL from the client terminates this server transaction; when it
	// does, the INVITE we sent upstream must be cancelled too or
	// FreeSWITCH would keep ringing. A false return means the transaction
	// is ALREADY terminated — the CANCEL beat this registration — in which
	// case the hook will never fire and the upstream leg must be cancelled
	// right here instead.
	if !tx.OnCancel(func(*sip.Request) { s.cancelPending(req) }) {
		s.cancelPending(req)
	}

	final := s.pumpInvite(ctx, req, tx, clTx, offer, from, true)
	if final != nil && final.StatusCode/100 == 2 {
		committed = true
		c := &call{
			CallID: callIDOf(req), FromTag: fromTagOf(req),
			ToTag:        toTagOf(final),
			PublicRemote: req.Source(), PrivateRemote: s.topo.upstreamHost,
			Transport: from.transport,
		}
		// The caller is public here, so its Contact came on the INVITE and
		// FreeSWITCH's came back on the 200.
		if u, ok := contactURI(req); ok {
			c.PublicContact = u
		}
		if u, ok := contactURI(final); ok {
			c.PrivateContact = u
		}
		s.commitCall(req, final, offer, c)
	}
}

// inviteToClient handles a call FreeSWITCH is placing to a registered
// client — acceptance criterion 3.
func (s *Server) inviteToClient(req *sip.Request, tx sip.ServerTransaction) {
	binding, ok := s.resolveTarget(req)
	if !ok {
		// Nothing registered under that contact any more. 404 is the
		// correct answer and lets FreeSWITCH fail over or play a
		// treatment, rather than ringing into nothing.
		s.reject(req, tx, 404, "Not Found")
		return
	}
	to, ok := s.topo.publicSide(binding.Transport)
	if !ok {
		s.reject(req, tx, 480, "Temporarily Unavailable")
		return
	}
	body := req.Body()
	if len(body) == 0 {
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), inviteTimeout)
	defer cancel()

	offer, err := s.buildPublicOffer(body)
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = offer.sess.Close()
		}
	}()

	dest := binding.Source.String()
	out, err := s.prepareForward(req, s.topo.private, to, dest, true)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	// The Request-URI FreeSWITCH used names FreeSBC's own contact; the
	// client must see one addressed to itself.
	out.Recipient = clientRequestURI(binding)
	setContact(out, to.uri())
	setSDP(out, offer.sdp)

	s.log.Info("proxying INVITE to client",
		"sip_call_id", callIDOf(req), "direction", "private->public",
		"transport", binding.Transport, "aor", binding.AOR,
		"public_remote", dest,
		"rtp_public_port", offer.sess.publicPort,
		"rtp_private_port", offer.sess.privatePort,
		"codec", codecNames(offer.sess.codecs))

	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
	if err != nil {
		s.log.Warn("forward INVITE to client", "err", err, "aor", binding.AOR)
		s.reject(req, tx, 480, "Temporarily Unavailable")
		return
	}
	defer clTx.Terminate()
	s.trackPending(req, &pendingInvite{req: out, dest: dest, side: to, cancel: cancel})
	defer s.untrackPending(req)
	if !tx.OnCancel(func(*sip.Request) { s.cancelPending(req) }) {
		s.cancelPending(req)
	}

	final := s.pumpInvite(ctx, req, tx, clTx, offer, s.topo.private, false)
	if final != nil && final.StatusCode/100 == 2 {
		committed = true
		c := &call{
			CallID: callIDOf(req), FromTag: fromTagOf(req),
			ToTag: toTagOf(final), Inbound: true,
			PublicRemote: dest, PrivateRemote: req.Source(),
			Transport: binding.Transport,
		}
		// FreeSWITCH is the caller here, so the roles are reversed: its
		// Contact came on the INVITE and the client's on the 200.
		if u, ok := contactURI(req); ok {
			c.PrivateContact = u
		}
		if u, ok := contactURI(final); ok {
			c.PublicContact = u
		}
		s.commitCall(req, final, offer, c)
	}
}

// pumpInvite relays every response of a forwarded INVITE, rewriting the
// Contact and negotiating the SDP answer on whichever response carries
// one. It returns the final response, or nil if the transaction died.
//
// toUpstream selects which direction's answer processing applies.
func (s *Server) pumpInvite(ctx context.Context, req *sip.Request, tx sip.ServerTransaction,
	clTx sip.ClientTransaction, offer *offerResult, near side, toUpstream bool) *sip.Response {

	answered := false
	for {
		select {
		case res, ok := <-clTx.Responses():
			if !ok {
				s.reject(req, tx, 500, "Server Internal Error")
				return nil
			}
			if !forwardable(res) {
				continue // a 100 Trying is hop-by-hop; ours already went out
			}
			out := res.Clone()
			if !s.popOwnVia(out) {
				s.log.Debug("dropping unroutable response", "code", res.StatusCode, "sip_call_id", callIDOf(req))
				continue
			}
			// Whichever side answers, the near side must see FreeSBC as
			// the dialog's remote target — otherwise in-dialog requests
			// would bypass the SBC and its media anchor.
			setContact(out, near.uri())

			if len(res.Body()) > 0 && !answered {
				var body []byte
				var err error
				if toUpstream {
					body, err = s.applyUpstreamAnswer(offer, res.Body(), offer.offer.Audio.WebRTC())
				} else {
					body, err = s.applyPublicAnswer(offer, res.Body())
				}
				if err != nil {
					s.log.Warn("media negotiation failed", "err", err, "sip_call_id", callIDOf(req))
					// Relaying an answer we cannot anchor would set up a
					// call with no audio, so refuse the requesting side.
					// If the answer came in a 2xx, the far end now believes
					// it has a live dialog — it must be ACKed and then BYEd,
					// or it sits there retransmitting its 200 until its own
					// timers give up.
					if res.StatusCode/100 == 2 {
						go s.ackThenBye(res, near)
					}
					s.reject(req, tx, 488, "Not Acceptable Here")
					return nil
				}
				setSDP(out, body)
				// Only the FIRST answer is negotiated. A later
				// provisional or the 200 restating the same answer must
				// not reallocate or re-latch anything.
				answered = true
			} else if len(res.Body()) > 0 {
				// A restated answer: send the body we already built, so
				// the near side sees a consistent session.
				setSDP(out, offer.sess.lastAnswer)
			}
			if len(res.Body()) > 0 {
				offer.sess.lastAnswer = out.Body()
			}

			out.SetDestination(req.Source())
			s.metrics.ResponseOut(out.StatusCode)
			if err := tx.Respond(out); err != nil {
				s.log.Debug("relay INVITE response", "err", err, "sip_call_id", callIDOf(req))
			}
			if res.StatusCode >= 200 {
				return res
			}
		case <-clTx.Done():
			if err := clTx.Err(); err != nil {
				s.log.Debug("invite client transaction ended", "err", err, "sip_call_id", callIDOf(req))
			}
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// ackThenBye completes and immediately tears down a dialog FreeSBC
// accepted at the SIP layer but cannot anchor media for. RFC 3261 requires
// a 2xx to be ACKed; without that the far end retransmits its 200 until
// Timer H, and the dialog lingers either way. ACK, then BYE.
func (s *Server) ackThenBye(res *sip.Response, from side) {
	ack := sip.NewRequest(sip.ACK, contactOrRecipient(res))
	via := from.via(newBranch())
	ack.PrependHeader(via)
	sip.CopyHeaders("From", res, ack)
	sip.CopyHeaders("To", res, ack)
	sip.CopyHeaders("Call-ID", res, ack)
	seq := uint32(1)
	if c := res.CSeq(); c != nil {
		seq = c.SeqNo
	}
	ack.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: sip.ACK})
	mf := sip.MaxForwardsHeader(70)
	ack.AppendHeader(&mf)
	ack.SetTransport(res.Transport())
	ack.SetDestination(res.Source())
	if err := s.client.WriteRequest(ack, noBuild); err != nil {
		s.log.Debug("ack unanchorable answer", "err", err)
		return
	}

	bye := sip.NewRequest(sip.BYE, contactOrRecipient(res))
	bye.PrependHeader(from.via(newBranch()))
	sip.CopyHeaders("From", res, bye)
	sip.CopyHeaders("To", res, bye)
	sip.CopyHeaders("Call-ID", res, bye)
	bye.AppendHeader(&sip.CSeqHeader{SeqNo: seq + 1, MethodName: sip.BYE})
	mf2 := sip.MaxForwardsHeader(70)
	bye.AppendHeader(&mf2)
	bye.SetTransport(res.Transport())
	bye.SetDestination(res.Source())

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

// contactOrRecipient is the request target for a teardown: the far end's
// Contact when it sent one, else its transport source rendered as a URI.
func contactOrRecipient(res *sip.Response) sip.Uri {
	if u, ok := contactURI(res); ok {
		return u
	}
	host, portStr, err := net.SplitHostPort(res.Source())
	if err != nil {
		return sip.Uri{Host: res.Source()}
	}
	port, _ := strconv.Atoi(portStr)
	return sip.Uri{Host: host, Port: port}
}

// commitCall records an established call and ties its media session's
// lifetime to it: whichever ends first — a BYE, or the media watchdog
// noticing silence — tears the other down.
func (s *Server) commitCall(req *sip.Request, final *sip.Response, offer *offerResult, c *call) {
	c.Media = offer.sess
	c.StartedAt = time.Now()
	s.calls.put(c)
	s.metrics.DialogStarted()
	s.metrics.MediaStarted(offer.sess.IsWebRTC())

	// One goroutine per call watching for the media session to end. It has
	// an explicit exit (the session's Done channel, closed by Close or by
	// the silence watchdog), so it cannot outlive the call.
	go func() {
		<-offer.sess.Done()
		if _, ok := s.calls.remove(c.CallID); ok {
			s.metrics.DialogEnded()
			s.metrics.MediaEnded(offer.sess.IsWebRTC(), offer.sess.Stats())
			s.log.Info("call media ended", "sip_call_id", c.CallID, "stats", offer.sess.Stats())
		}
	}()
}

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
	from, to, dest, ok := s.directionFor(req)
	if !ok {
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	body := req.Body()
	if len(body) == 0 {
		// An offerless re-INVITE would make FreeSBC the offerer and
		// require answering against the ACK. Not supported; refusing is
		// honest and leaves the existing session untouched.
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}
	c, found := s.calls.get(callIDOf(req))
	if !found || c.Media == nil {
		// No anchored session to renegotiate against. Forwarding the body
		// as-is here would be the exact leak this function exists to
		// prevent, so refuse instead.
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}

	reOffer, parsed, err := s.rebuildInDialogOffer(c.Media, body, to.plane)
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	out, err := s.prepareForward(req, from, to, dest, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	s.retargetInDialog(req, out, to)
	setContact(out, to.uri())
	setSDP(out, reOffer)

	ctx, cancel := context.WithTimeout(context.Background(), inviteTimeout)
	defer cancel()

	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
	if err != nil {
		s.log.Debug("forward re-INVITE", "err", err, "sip_call_id", callIDOf(req))
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	defer clTx.Terminate()

	answered := false
	for {
		select {
		case res, ok := <-clTx.Responses():
			if !ok {
				s.reject(req, tx, 408, "Request Timeout")
				return
			}
			if !forwardable(res) {
				continue
			}
			relayed := res.Clone()
			if !s.popOwnVia(relayed) {
				s.log.Debug("dropping unroutable re-INVITE response", "code", res.StatusCode, "sip_call_id", callIDOf(req))
				continue
			}
			setContact(relayed, from.uri())
			if len(res.Body()) > 0 && !answered {
				reAnswer, err := s.rebuildInDialogAnswer(c.Media, parsed, res.Body(), from.plane)
				if err != nil {
					s.log.Warn("re-INVITE media negotiation failed", "err", err, "sip_call_id", callIDOf(req))
					s.reject(req, tx, 488, "Not Acceptable Here")
					return
				}
				setSDP(relayed, reAnswer)
				c.Media.lastAnswer = relayed.Body()
				answered = true
			} else if len(res.Body()) > 0 {
				setSDP(relayed, c.Media.lastAnswer)
			}
			relayed.SetDestination(req.Source())
			s.metrics.ResponseOut(relayed.StatusCode)
			if err := tx.Respond(relayed); err != nil {
				s.log.Debug("relay re-INVITE response", "err", err, "sip_call_id", callIDOf(req))
			}
			if res.StatusCode >= 200 {
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

// onAck forwards an ACK. A 2xx ACK is a separate end-to-end transaction
// (RFC 3261 §17.1.1.3) and must be sent statelessly, not through a client
// transaction — sipgo enforces this by refusing an ACK in
// TransactionRequest.
func (s *Server) onAck(req *sip.Request, tx sip.ServerTransaction) {
	from, to, dest, ok := s.directionFor(req)
	if !ok {
		return // nothing to forward it to; an ACK gets no response
	}
	out, err := s.prepareForward(req, from, to, dest, false)
	if err != nil {
		return
	}
	s.retargetInDialog(req, out, to)
	if err := s.client.WriteRequest(out, noBuild); err != nil {
		s.log.Debug("forward ACK", "err", err, "sip_call_id", callIDOf(req))
	}
}

// onCancel forwards a CANCEL that sipgo did not already match to a live
// INVITE server transaction. When it DID match, sipgo answers 200 and
// terminates the INVITE itself, which fires the OnCancel hook that
// cancels our upstream leg — so this path only sees an orphan.
func (s *Server) onCancel(req *sip.Request, tx sip.ServerTransaction) {
	if s.cancelPending(req) {
		s.respond(req, tx, sip.NewResponseFromRequest(req, 200, "OK", nil))
		return
	}
	// RFC 3261 §9.2: a CANCEL matching no transaction is answered 481, not
	// 200. Answering 200 would tell the sender its request was cancelled
	// when nothing was.
	s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
}

// onInDialog forwards BYE, INFO and in-dialog INVITE. Direction is decided
// by where the request came from, and a BYE additionally tears the media
// session down.
func (s *Server) onInDialog(req *sip.Request, tx sip.ServerTransaction) {
	from, to, dest, ok := s.directionFor(req)
	if !ok {
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	out, err := s.prepareForward(req, from, to, dest, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	s.retargetInDialog(req, out, to)
	setContact(out, to.uri())

	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	if _, err := s.forwardAndRelay(ctx, req, tx, out); err != nil {
		s.log.Debug("forward in-dialog request", "err", err,
			"method", req.Method.String(), "sip_call_id", callIDOf(req))
		// The far side never answered. Answering 408 locally is better
		// than leaving the sender retransmitting into silence — and for a
		// BYE the call is over either way, which the teardown below
		// reflects.
		if req.Method == sip.BYE {
			s.reject(req, tx, 408, "Request Timeout")
		}
	}
	if req.Method == sip.BYE {
		s.teardown(callIDOf(req))
	}
}

// teardown ends a call's media as soon as its dialog ends, rather than
// waiting for the silence watchdog — the difference between a port
// returning to the pool immediately and minutes later.
func (s *Server) teardown(callID string) {
	c, ok := s.calls.remove(callID)
	if !ok || c.Media == nil {
		return
	}
	st := c.Media.Stats()
	webrtc := c.Media.IsWebRTC()
	_ = c.Media.Close()
	s.metrics.DialogEnded()
	s.metrics.MediaEnded(webrtc, st)
	s.log.Info("call ended", "sip_call_id", callID, "stats", st)
}

// directionFor decides where an in-dialog request goes, and from which
// side. Requests from FreeSWITCH go to the client; everything else goes
// upstream.
func (s *Server) directionFor(req *sip.Request) (from, to side, dest string, ok bool) {
	if s.arrivedOnPrivate(req) {
		// An IN-DIALOG request from FreeSWITCH carries no binding token.
		// The token only ever rides on the contact FreeSBC REGISTERED; a
		// dialog's remote target is the Contact FreeSBC put in the INVITE
		// or the 200, which names the SBC and nothing else. So the dialog
		// record — not the location table — is what identifies the client
		// here. Getting this wrong 481s every callee-side hangup.
		if c, found := s.calls.get(callIDOf(req)); found && c.PublicRemote != "" {
			if to, ok = s.topo.publicSide(c.Transport); ok {
				return s.topo.private, to, c.PublicRemote, true
			}
		}
		// No dialog on record: fall back to the binding token, which is
		// how a PRE-dialog request (an inbound INVITE) is routed.
		b, found := s.bindingForRequest(req)
		if !found {
			return side{}, side{}, "", false
		}
		to, ok = s.topo.publicSide(b.Transport)
		if !ok {
			return side{}, side{}, "", false
		}
		return s.topo.private, to, b.Source.String(), true
	}
	from, ok = s.publicSideFor(req)
	if !ok {
		return side{}, side{}, "", false
	}
	return from, s.topo.private, s.topo.upstreamHost, true
}

// farContact returns the Request-URI an in-dialog request should carry on
// its way out: the far endpoint's own Contact, recorded when the dialog was
// established. Returns ok=false when there is no dialog on record, in
// which case the caller leaves the Request-URI alone.
func (s *Server) farContact(req *sip.Request, toward plane) (sip.Uri, bool) {
	c, found := s.calls.get(callIDOf(req))
	if !found {
		return sip.Uri{}, false
	}
	u := c.PrivateContact
	if toward == planePublic {
		u = c.PublicContact
	}
	if u.Host == "" {
		return sip.Uri{}, false
	}
	return u, true
}

// publicSideFor returns the public side matching a request's transport.
func (s *Server) publicSideFor(req *sip.Request) (side, bool) {
	return s.topo.publicSide(sip.NetworkToLower(req.Transport()))
}

// resolveTarget finds the binding an inbound request is addressed to,
// preferring the opaque token FreeSBC put in the registered Contact and
// falling back to the address-of-record.
func (s *Server) resolveTarget(req *sip.Request) (Binding, bool) {
	if b, ok := s.bindingForRequest(req); ok {
		return b, true
	}
	// No token: fall back to the AoR in the Request-URI. With several
	// devices registered this picks the first, which is a real limitation
	// — FreeSWITCH normally forks per contact, so each INVITE carries its
	// own token and this path is not taken.
	u := req.Recipient
	if u.User == "" || u.Host == "" {
		return Binding{}, false
	}
	for _, host := range []string{u.Host, s.topo.private.advIP.String()} {
		if bs := s.loc.ByAOR(strings.ToLower(u.User + "@" + host)); len(bs) > 0 {
			return bs[0], true
		}
	}
	return Binding{}, false
}

// bindingForRequest extracts the binding token from a Request-URI (or from
// the topmost Route, where a strict-routing element may have moved it) and
// resolves it.
func (s *Server) bindingForRequest(req *sip.Request) (Binding, bool) {
	if tok, ok := tokenOf(req.Recipient); ok {
		if b, found := s.loc.ByToken(tok); found {
			return b, true
		}
	}
	if r := req.Route(); r != nil {
		if tok, ok := tokenOf(r.Address); ok {
			if b, found := s.loc.ByToken(tok); found {
				return b, true
			}
		}
	}
	return Binding{}, false
}

func tokenOf(u sip.Uri) (string, bool) {
	if u.UriParams == nil {
		return "", false
	}
	v, ok := u.UriParams.Get(contactTokenParam)
	if !ok || v == "" || len(v) > 64 {
		return "", false
	}
	return v, true
}

// clientRequestURI builds the Request-URI a client should see: its own
// address-of-record user at the address it registered from, with the
// transport it registered over.
func clientRequestURI(b Binding) sip.Uri {
	host := b.Source.Addr().String()
	port := int(b.Source.Port())
	params := sip.NewParams()
	if b.Transport != "udp" {
		params.Add("transport", b.Transport)
	}
	return sip.Uri{User: b.User, Host: host, Port: port, UriParams: params}
}

// retargetInDialog replaces the Request-URI of a forwarded in-dialog
// request with the far endpoint's own Contact, undoing the topology hiding
// the proxy applied when the dialog was established. Falls back to the
// registration binding (for a request that reaches a client outside any
// dialog we track), and leaves the URI alone when neither is known.
func (s *Server) retargetInDialog(req, out *sip.Request, to side) {
	if u, ok := s.farContact(req, to.plane); ok {
		out.Recipient = u
		return
	}
	if to.plane == planePublic {
		if b, ok := s.bindingForRequest(req); ok {
			out.Recipient = clientRequestURI(b)
		}
	}
}

// trackPending / untrackPending / cancelPending manage the CANCEL bridge.
func (s *Server) trackPending(req *sip.Request, p *pendingInvite) {
	s.pendingMu.Lock()
	s.pending[pendingKey(req)] = p
	s.pendingMu.Unlock()
}

func (s *Server) untrackPending(req *sip.Request) {
	s.pendingMu.Lock()
	delete(s.pending, pendingKey(req))
	s.pendingMu.Unlock()
}

// cancelPending sends a CANCEL for the INVITE FreeSBC forwarded on behalf
// of this one.
//
// The CANCEL must carry the SAME top Via branch as the INVITE it cancels
// (RFC 3261 §9.1) — that is how the next hop matches the two — so it is
// built from the forwarded request rather than from the CANCEL we
// received, whose branch belongs to a different transaction.
func (s *Server) cancelPending(req *sip.Request) bool {
	s.pendingMu.Lock()
	p, ok := s.pending[pendingKey(req)]
	if ok {
		delete(s.pending, pendingKey(req))
	}
	s.pendingMu.Unlock()
	if !ok {
		return false
	}
	// Once the CANCEL has been sent and answered, the INVITE exchange is
	// over as far as the proxy is concerned: the caller has already been
	// finalised (sipgo answers the CANCEL and 487s the INVITE server
	// transaction itself), so there is nothing left to relay. Cancelling
	// the INVITE's context here is what releases its media promptly —
	// without it the media session would sit on its ports until the
	// forwarded INVITE's own transaction timer expired, which is up to
	// 32 seconds of capacity held by a call nobody is on.
	defer p.cancel()

	cancelReq := buildCancel(p.req)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clTx, err := s.client.TransactionRequest(ctx, cancelReq, noBuild)
	if err != nil {
		s.log.Debug("forward CANCEL", "err", err, "sip_call_id", callIDOf(req))
		return true
	}
	defer clTx.Terminate()
	select {
	case <-clTx.Responses():
	case <-clTx.Done():
	case <-ctx.Done():
	}
	return true
}

// buildCancel constructs a CANCEL for a request FreeSBC sent, per
// RFC 3261 §9.1: same Request-URI, same top Via (branch included), same
// Call-ID, From, To and CSeq number with the method changed.
func buildCancel(invite *sip.Request) *sip.Request {
	c := sip.NewRequest(sip.CANCEL, invite.Recipient)
	c.SipVersion = invite.SipVersion
	if v := invite.Via(); v != nil {
		c.AppendHeader(sip.HeaderClone(v))
	}
	sip.CopyHeaders("Route", invite, c)
	mf := sip.MaxForwardsHeader(70)
	c.AppendHeader(&mf)
	sip.CopyHeaders("From", invite, c)
	sip.CopyHeaders("To", invite, c)
	sip.CopyHeaders("Call-ID", invite, c)
	if cseq := invite.CSeq(); cseq != nil {
		nc := sip.CSeqHeader{SeqNo: cseq.SeqNo, MethodName: sip.CANCEL}
		c.AppendHeader(&nc)
	}
	c.SetBody(nil)
	c.SetTransport(invite.Transport())
	c.SetDestination(invite.Destination())
	c.Laddr = invite.Laddr
	return c
}

func pendingKey(req *sip.Request) string {
	return callIDOf(req) + "|" + fromTagOf(req)
}

// rejectMedia maps a media-setup failure to the right SIP status: no
// common codec is 488 (the offer is unacceptable), an exhausted port pool
// is 503 (temporary capacity), anything else 500.
func (s *Server) rejectMedia(req *sip.Request, tx sip.ServerTransaction, err error) {
	switch {
	case errors.Is(err, errNoUsableCodec), errors.Is(err, errRenumbered):
		s.log.Info("rejecting call: media not negotiable", "err", err, "sip_call_id", callIDOf(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
	case errors.Is(err, media.ErrPortsExhausted):
		s.metrics.PortAllocationFailed()
		s.log.Error("rejecting call: media ports exhausted", "err", err, "sip_call_id", callIDOf(req))
		s.reject(req, tx, 503, "Service Unavailable")
	default:
		s.log.Warn("rejecting call: media setup failed", "err", err, "sip_call_id", callIDOf(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
	}
}

// isInDialog reports whether a request belongs to an established dialog,
// which RFC 3261 §12.2 identifies by the presence of a To tag.
func isInDialog(req *sip.Request) bool { return toTagOf(req) != "" }

// tagOf reads the dialog tag from a From or To header, or "" when absent.
func tagOf(h sip.Header) string {
	switch v := h.(type) {
	case *sip.FromHeader:
		if v == nil {
			return ""
		}
		if t, ok := v.Params.Get("tag"); ok {
			return t
		}
	case *sip.ToHeader:
		if v == nil {
			return ""
		}
		if t, ok := v.Params.Get("tag"); ok {
			return t
		}
	}
	return ""
}

// fromTagOf and toTagOf are nil-safe accessors for the two headers.
func fromTagOf(msg sip.Message) string {
	if h := msg.From(); h != nil {
		return tagOf(h)
	}
	return ""
}

func toTagOf(msg sip.Message) string {
	if h := msg.To(); h != nil {
		return tagOf(h)
	}
	return ""
}

// setSDP replaces a message's body with an SDP one, keeping
// Content-Type and Content-Length consistent.
func setSDP(msg editable, body []byte) {
	removeAll(msg, "Content-Type")
	msg.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	msg.SetBody(body)
}

func codecNames(cs []sdpx.Codec) string { return sdpx.Describe(cs) }
