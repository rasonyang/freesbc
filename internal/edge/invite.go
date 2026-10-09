package edge

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// inviteTimeout bounds an INVITE transaction end to end. It is longer than
// a typical ring cap because the far end, not FreeSBC, decides when to
// give up; this is a backstop against a transaction that never finalises
// pinning a media session forever.
const inviteTimeout = 5 * time.Minute

// maxEarlyPerSource caps the calls one public source IP may have in
// flight — media allocated, no answer yet — at once. Media is anchored
// before the INVITE reaches FreeSWITCH, and so before FreeSWITCH has
// authenticated the caller: without a cap, an unauthenticated flood holds
// a port pair per INVITE on each plane (plus, for a browser offer, an ICE
// agent) for the length of FreeSWITCH's 407 round trip, or up to Timer B
// when the upstream is silent. The cap is per IP, not per transport
// address, so it also bounds a flood spread over many source ports; it is
// generous enough for many phones ringing out through one NAT at once.
const maxEarlyPerSource = 64

// onInvite proxies a call in whichever direction it is going and anchors
// its media.
//
// The two directions are genuinely different — one starts from a public
// client and ends at FreeSWITCH, the other starts at FreeSWITCH and ends
// at a registered binding — but they share this shape:
//
//	parse the offer → allocate media → build the far-side offer →
//	forward → on each fork's answer, negotiate codecs and build the
//	near-side answer → on the 2xx, confirm the dialog → relay.
func (s *Server) onInvite(req *sip.Request, tx sip.ServerTransaction, in inbound) {
	src := in.src
	inDialog := isInDialog(req)
	carrier := "" // the carrier a public out-of-dialog INVITE came from, if any
	if !inDialog && !in.private() {
		var kind inviteSource
		if kind, carrier = s.admitPublicInvite(req, src); kind == srcDrop {
			// Admission (issue #86; admission.go): a public out-of-dialog
			// INVITE from a source that is neither a carrier source nor a
			// registered transport address is dropped before anything
			// answers it, so a scanner learns nothing. Returning without a
			// response is the whole mechanism: sipgo's Server.handleRequest
			// calls TerminateGracefully when the handler returns, which, for
			// a transaction with no final response, is Terminate — it stops
			// the Timer_1xx that would otherwise send "100 Trying" at 200
			// ms, removes the transaction and sends nothing. A
			// retransmission of the INVITE opens a fresh transaction and is
			// dropped the same way.
			s.dropSilently(dropInviteNotAdmitted, req, src,
				"to", req.Recipient.User)
			return
		}
	}
	if inDialog {
		s.onReInvite(req, tx, in.private())
		return
	}
	if in.private() {
		s.invitePrivate(req, tx)
		return
	}
	s.inviteToUpstream(req, tx, src, carrier)
}

// inviteReject is why the edge itself refused an out-of-dialog INVITE with a
// final response. The set is fixed, so it is a bounded metric label. A
// silent admission drop is not one (dropReason), nor is a response relayed
// from the far side, a re-INVITE refusal, or the 487 a caller's own CANCEL
// earns.
type inviteReject int

const (
	// rejectEarlyCap: the source has too many unanswered calls (503).
	rejectEarlyCap inviteReject = iota
	// rejectShuttingDown: the proxy is shutting down (503).
	rejectShuttingDown
	// rejectLoopDetected: the INVITE merges with a call in progress (482).
	rejectLoopDetected
	// rejectNoPublicSide: no public listener to carry the call (488, 480, 503).
	rejectNoPublicSide
	// rejectWebRTCDisabled: a call to a browser with WebRTC off (488).
	rejectWebRTCDisabled
	// rejectNoTarget: nowhere to send it: an unknown switch target, a
	// client with no binding, a carrier with no address (404, 503).
	rejectNoTarget
	// rejectTooManyHops: Max-Forwards is exhausted (483).
	rejectTooManyHops
	// rejectMediaFailed: the media could not be negotiated or anchored
	// (488, 500).
	rejectMediaFailed
	// rejectPortExhausted: no media port was free (503).
	rejectPortExhausted
	// rejectUpstreamFailed: every switch or carrier attempt failed (503).
	rejectUpstreamFailed
	// rejectTimeout: the INVITE's own budget ran out (408).
	rejectTimeout
	// rejectSessionCap: shield.max_sessions calls already hold a session
	// slot (503 + Retry-After).
	rejectSessionCap
	// rejectInviteRate: shield.invite_rate_limit is exhausted (503 +
	// Retry-After).
	rejectInviteRate
	// rejectDraining: the edge is in drain mode (503 + Retry-After).
	rejectDraining
	numInviteRejects
)

// inviteRejectLabels are the metric labels of the reject reasons.
var inviteRejectLabels = [numInviteRejects]string{
	rejectEarlyCap:       "early_cap",
	rejectShuttingDown:   "shutting_down",
	rejectLoopDetected:   "loop_detected",
	rejectNoPublicSide:   "no_public_side",
	rejectWebRTCDisabled: "webrtc_disabled",
	rejectNoTarget:       "no_target",
	rejectTooManyHops:    "too_many_hops",
	rejectMediaFailed:    "media_failed",
	rejectPortExhausted:  "port_exhausted",
	rejectUpstreamFailed: "upstream_failed",
	rejectTimeout:        "timeout",
	rejectSessionCap:     "session_cap",
	rejectInviteRate:     "invite_rate",
	rejectDraining:       "draining",
}

func (r inviteReject) String() string { return inviteRejectLabels[r] }

// rejectInvite refuses an out-of-dialog INVITE with a final response and
// counts it. Every handler returns after calling it, and sipgo hands a
// retransmitted INVITE to the existing server transaction rather than to
// the handler, so one INVITE is counted once.
func (s *Server) rejectInvite(req *sip.Request, tx sip.ServerTransaction, code int, reason string, why inviteReject) {
	s.metrics.InviteRejected(why)
	s.reject(req, tx, code, reason)
}

// drainRetryAfter is the Retry-After (seconds) of a 503 refused because the
// edge is draining: long enough for a carrier or the switch to try another
// route, short enough to come back soon after a restart.
const drainRetryAfter = 30

// sessionCapRetryAfter is the Retry-After (seconds) of a 503 for a full
// session cap: a call has to end to free a slot, so the hint is a constant.
const sessionCapRetryAfter = 5

// capWarnEvery is the least time between two WARN lines for the same
// admission-control reason; the rest are logged at DEBUG.
const capWarnEvery = 10 * time.Second

// capWarner rate-limits the WARN for each admission-control reject reason,
// so a flood against a full cap cannot flood the log.
type capWarner struct {
	mu   sync.Mutex
	last [numInviteRejects]time.Time
}

// allow reports whether a WARN for why may be logged now, and if so
// remembers it.
func (w *capWarner) allow(why inviteReject) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now := time.Now(); now.Sub(w.last[why]) >= capWarnEvery {
		w.last[why] = now
		return true
	}
	return false
}

// rejectBusy refuses an out-of-dialog INVITE from an admitted peer with a
// 503 and a Retry-After, through the same counting path as rejectInvite.
func (s *Server) rejectBusy(req *sip.Request, tx sip.ServerTransaction, retryAfter int, why inviteReject, msg string, args ...any) {
	args = append(args, "reason", why.String(), "retry_after", retryAfter, "sip_call_id", fsip.CallID(req))
	if s.capWarn.allow(why) {
		s.log.Warn(msg, args...)
	} else {
		s.log.Debug(msg, args...)
	}
	s.metrics.InviteRejected(why)
	res := sip.NewResponseFromRequest(req, 503, "Service Unavailable", nil)
	res.AppendHeader(sip.NewHeader("Retry-After", strconv.Itoa(retryAfter)))
	s.respond(req, tx, res)
}

// sessionLimit is the effective session cap of cfg: shield.max_sessions,
// never above what the boot rtp range can anchor (rtp is restart-only, so
// a hot value cannot exceed it after validation, but the clamp keeps the
// cap honest if a snapshot ever disagrees).
func (s *Server) sessionLimit(cfg *config.Config) int {
	limit, pairs := cfg.Shield.MaxSessions, s.boot.RTP.Pairs()
	if limit <= 0 || limit > pairs {
		return pairs
	}
	return limit
}

// inviteRetryAfter is the whole seconds (at least 1) until a token of rl
// is free again: ceil(interval / rate).
func inviteRetryAfter(rl config.RateLimit) int {
	if rl.Rate <= 0 {
		return 1
	}
	secs := int(math.Ceil(rl.Interval.Seconds() / float64(rl.Rate)))
	return max(1, secs)
}

// beginDialog opens the call's record, or refuses the INVITE. It is where
// the global admission control applies, once per out-of-dialog INVITE and
// before any media is allocated:
//
//   - 503 + Retry-After while the edge is draining (drain.go), checked
//     first so a refused call takes no slot and no rate token;
//   - 482 when the INVITE merges with one still in progress (RFC 3261
//     §8.2.2.2: same Call-ID and From tag as a transaction the proxy is
//     already working on);
//   - 503 + Retry-After when shield.max_sessions calls already hold a
//     slot (the slot is taken inside dialogTable.begin);
//   - 503 + Retry-After when shield.invite_rate_limit is exhausted. A
//     refused INVITE is ended here, before the response, so its slot is
//     free again by the time the peer sees the 503; an early dialog that
//     never connected is never counted as a call ended.
//
// All four directions reach it after their cheap validation, and
// re-INVITEs never do (they go through onReInvite).
func (s *Server) beginDialog(req *sip.Request, tx sip.ServerTransaction, callerPlane plane) (*dialog, bool) {
	cfg := s.store.Current()
	if s.drain.on() {
		// Before any slot, rate token or media port: drain refuses every
		// new call, the switch's included.
		s.rejectBusy(req, tx, drainRetryAfter, rejectDraining, "rejecting call: draining")
		return nil, false
	}
	limit := s.sessionLimit(cfg)
	d, res := s.dialogs.begin(req, callerPlane, limit)
	switch res {
	case beginClosed:
		s.rejectInvite(req, tx, 503, "Service Unavailable", rejectShuttingDown)
		return nil, false
	case beginMerged:
		s.rejectInvite(req, tx, 482, "Loop Detected", rejectLoopDetected)
		return nil, false
	case beginFull:
		s.rejectBusy(req, tx, sessionCapRetryAfter, rejectSessionCap,
			"rejecting call: session cap reached", "limit", limit)
		return nil, false
	}
	if cfg.Shield.InviteRateLimit != "" {
		// Validated at load; a parse failure here would mean a snapshot
		// that skipped validation, and then no limit applies.
		if rl, err := config.ParseRateLimit(cfg.Shield.InviteRateLimit); err == nil && !s.inviteLimiter.Allow(rl) {
			d.end(endShutdown) // never confirmed: frees the slot, counts nothing
			s.rejectBusy(req, tx, inviteRetryAfter(rl), rejectInviteRate,
				"rejecting call: new-INVITE rate limit reached", "limit", cfg.Shield.InviteRateLimit)
			return nil, false
		}
	}
	return d, true
}

// inviteToUpstream handles a call from the public side to the switch. It
// serves two kinds of caller, told apart by carrier:
//
//   - carrier == "": a registered client placing a call. Everything it
//     does starts on the switch its From user hashes to, at the switch's
//     CLIENT port (edge.switch), where the switch authenticates it.
//   - carrier != "": a carrier delivering a call (the name is its
//     edge.carriers entry, or "unknown"). The node is the hash of the
//     Request-URI user (the DID), the destination is that node's CARRIER
//     port (edge.switch_carrier_port) and never the client port, the
//     Request-URI is left alone, and the request is stamped
//     X-FreeSBC-Carrier. Carriers are exempt from the per-source early-call
//     cap; shield.carrier_rate_limit bounds them.
func (s *Server) inviteToUpstream(req *sip.Request, tx sip.ServerTransaction, src netip.AddrPort, carrier string) {
	from, ok := s.publicSideFor(req)
	if !ok {
		s.rejectInvite(req, tx, 488, "Not Acceptable Here", rejectNoPublicSide)
		return
	}
	body := req.Body()

	if carrier == "" {
		release, ok := s.admitEarly(src.Addr())
		if !ok {
			s.log.Warn("rejecting call: too many unanswered calls from one source",
				"public_remote", src.String(), "limit", maxEarlyPerSource, "sip_call_id", fsip.CallID(req))
			s.rejectInvite(req, tx, 503, "Service Unavailable", rejectEarlyCap)
			return
		}
		defer release()
	} else {
		s.metrics.CarrierRequest(carrier, dirInbound, req.Method.String())
	}

	// ctx is the whole-series backstop: the 5-minute inviteTimeout,
	// cancellable — a client CANCEL cancels the series, never just the
	// attempt in flight.
	ctx, cancel := context.WithTimeout(context.Background(), s.inviteBudget())
	defer cancel()

	// One record from here to teardown: the dialog owns the media session,
	// the CANCEL bridge and the per-fork answers, and end() is the single
	// exit whether the call connects or not.
	d, ok := s.beginDialog(req, tx, planePublic)
	if !ok {
		return
	}
	defer d.endUnlessUp()
	if carrier != "" {
		d.setCarrier(carrier)
	}
	d.setSRTP(s.legSRTPPolicy(carrier, from.transport))

	// An offerless INVITE is forwarded as it is: the offer is the
	// switch's first SDP, built into a public one when it arrives
	// (offerless.go).
	var offer *offerResult
	var offerless func([]byte) (*offerResult, error)
	if len(body) > 0 {
		var err error
		if offer, err = s.buildUpstreamOffer(ctx, d, body, src.Addr()); err != nil {
			s.rejectInviteMedia(req, tx, err)
			return
		}
	} else {
		toBrowser := isBrowserTransport(from.transport)
		offerless = func(b []byte) (*offerResult, error) { return s.buildPublicOffer(d, b, toBrowser) }
	}

	// The CANCEL bridge is registered ONCE, for the whole series: the server
	// transaction the client's INVITE created is a single transaction across
	// every attempt, and its OnCancel hook must cancel whichever attempt is
	// in flight when the client gives up. The pending entry is re-tracked
	// per attempt below, and the cancel it holds is ALWAYS this series'
	// cancel — never a per-attempt one — so a CANCEL landing between two
	// attempts still ends the whole series through the stale entry, and the
	// loop's ctx check stops the next attempt from starting.
	//
	// The hook runs inside sipgo's transaction lock, and sipgo sends the
	// client its 487 only after the hook returns, so it does no network
	// I/O: it marks the call cancelled (from now on no 2xx can confirm it)
	// and hands the CANCEL to a goroutine.
	if !tx.OnCancel(func(*sip.Request) {
		if !s.cancelCall(d, cancelByCaller) {
			// No attempt in flight (between attempts, or before the first):
			// there is nothing to CANCEL on the wire, but the series must
			// still stop.
			cancel()
		}
	}) {
		// The CANCEL beat us here: the server transaction is already
		// terminated, the hook will never fire, and nothing has been sent
		// upstream yet. sipgo has already answered the client; ending the
		// series is the whole of the work left.
		return
	}
	defer d.untrack()

	cooldown := switchCooldown

	// A carrier's call to a registration's Contact names the registering
	// node and carries the switch's own Contact back: it goes to that node
	// only, with that Contact as the Request-URI (carrierreg.go).
	var pinned carrierBinding
	isPinned := false
	resp := respPlain
	if carrier != "" {
		pinned, isPinned = s.carrierRURI(req, carrier)
		resp = respToCarrier
	}

	// The caller's hash order, cooled nodes at the tail: everything this
	// user does starts on the same switch, and a switch that just failed is
	// only dialed once its alternatives have been tried.
	hashUser := hashUserFor(req)
	if carrier != "" {
		hashUser = carrierHashUser(req)
	}
	order := s.upstreamOrder(hashUser)
	if isPinned {
		order = []string{pinned.node}
	}
	for attempt, name := range order {
		if ctx.Err() != nil {
			break // the caller is gone (or the backstop fired) mid-series
		}
		entry := s.topo.upstreamEntryFor(name)

		// Every attempt re-forwards the ORIGINAL request (prepareForward
		// clones, so the client's INVITE stays intact): a fresh Via branch
		// and Record-Route pair per attempt, same Call-ID/CSeq/From/To — it
		// is one dialog the client is still waiting on, whatever we had to
		// try to connect it.
		dest := entry.host
		if carrier != "" {
			dest = entry.carrierAddr().String()
		}
		out, err := s.prepareForward(req, from, s.topo.private, dest, true)
		if err != nil {
			s.rejectInvite(req, tx, 483, "Too Many Hops", rejectTooManyHops)
			return
		}
		if carrier != "" {
			out.AppendHeader(sip.NewHeader(carrierHeader, carrier))
		}
		if isPinned {
			out.Recipient = pinned.contact
		}
		// The client's Contact must not reach FreeSWITCH: it names the
		// client's own address (or, for a browser, an unreachable .invalid
		// host), and FreeSWITCH would send in-dialog requests straight to it,
		// bypassing the SBC entirely.
		fsip.SetContact(out, s.topo.private.uri())
		if offer != nil {
			fsip.SetSDPBody(out, offer.sdp)
		} else {
			stripBody(out)
		}

		s.log.Info("proxying INVITE upstream",
			"sip_call_id", fsip.CallID(req), "direction", "public->private",
			"transport", from.transport, "public_remote", src.String(),
			"carrier", carrier, "upstream", name, "dest", dest, "attempt", attempt+1,
			"offerless", offer == nil)

		// The pending entry points at THIS attempt's forwarded request — its
		// Via branch and destination are what a CANCEL must carry — BEFORE
		// the INVITE is sent, so no CANCEL can land between the two.
		a := &inviteAttempt{req: out, cancel: cancel}
		if !d.track(a) {
			break // the caller cancelled before this attempt started
		}
		// Started on ctx, the series context: the client transaction must
		// outlive the attempt so its CANCEL and its retransmissions are
		// still matched.
		clTx, err := s.clientTx(ctx, out)
		if err != nil {
			s.log.Warn("forward INVITE upstream", "err", err, "sip_call_id", fsip.CallID(req),
				"upstream", name, "attempt", attempt+1)
			if ctx.Err() != nil {
				break // the caller is gone; nothing left to do
			}
			// The INVITE never got out: a zero-response failure while the
			// client is still waiting. Cooldown the node and let the next
			// one try.
			s.upstreamCooldown.Penalize(name, cooldown)
			continue
		}
		if d.markSent(a) {
			// A CANCEL took the attempt while the INVITE was being sent: it
			// could not go out ahead of the INVITE, so it goes out now.
			go s.sendCancel(a)
		}

		// In-dialog traffic rides the WINNING switch: directionFor sends the
		// client's ACKs and BYEs to this address, and the winner's Contact is
		// what their Request-URI names.
		l := &inviteLeg{req: req, tx: tx, out: out, clTx: clTx, d: d, offer: offer, offerless: offerless,
			near: from, far: s.topo.private, callee: calleeUpstream,
			calleeRemote: dest, transport: from.transport, resp: resp}
		r := s.pumpInvite(ctx, l)

		if r.final != nil {
			// ANY final response ends the series — pumpInvite has already
			// relayed it (and, for a 2xx, confirmed the dialog first). A 486
			// is the callee's own judgement and must never be retried on
			// another switch (D7).
			s.upstreamCooldown.Recover(name)
			return
		}
		if r.finalised {
			return // the pump answered the client itself (488)
		}
		responded := r.responded
		// No final response. Retry another node ONLY when this one produced
		// nothing at all AND the attempt failed at the transport level. The
		// `!responded` half is an invariant, not a heuristic: a node that
		// answered had its answer negotiated and its media relay started by
		// pumpInvite, so a second attempt must never run — it would apply a
		// second answer and start the relay twice. A transaction that ended
		// without a transport error (the shared budget, a node that went
		// quiet after answering) is not something another node fixes either.
		if responded || clTx.Err() == nil {
			break
		}
		if ctx.Err() != nil {
			break // the caller is gone; nothing left to try
		}
		s.upstreamCooldown.Penalize(name, cooldown)
		s.log.Warn("upstream INVITE unanswered; entering cooldown",
			"upstream", name, "cooldown", cooldown.String(), "sip_call_id", fsip.CallID(req))
	}

	// Every node failed and nothing was relayed: 503 tells the client's own
	// failover (or the human) to try again rather than pretending the callee
	// is unreachable.
	s.giveUp(ctx, d, req, tx, 503, "Service Unavailable")
}

// giveUp sends the one final response a caller is owed when its INVITE
// ended without one being relayed: nothing when its own CANCEL already got
// it a 487 from sipgo; 408 when the backstop expired (RFC 3261 §16.7 step
// 6, §16.8); 487 when an orphan CANCEL ended it; the path's own status
// otherwise.
func (s *Server) giveUp(ctx context.Context, d *dialog, req *sip.Request, tx sip.ServerTransaction,
	code int, reason string) {
	switch {
	case d.callerCancelled():
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		s.rejectInvite(req, tx, 408, "Request Timeout", rejectTimeout)
	case ctx.Err() != nil || d.wasCancelled():
		s.reject(req, tx, 487, "Request Terminated")
	default:
		s.rejectInvite(req, tx, code, reason, rejectUpstreamFailed)
	}
}

// admitEarly counts a new unanswered call from a public source, refusing
// it when the source already has maxEarlyPerSource in flight. release
// uncounts it, and runs when the INVITE handler returns — by then the call
// is either up (and no longer early) or gone.
func (s *Server) admitEarly(src netip.Addr) (release func(), ok bool) {
	s.earlyMu.Lock()
	defer s.earlyMu.Unlock()
	if s.early[src] >= maxEarlyPerSource {
		return nil, false
	}
	s.early[src]++
	return func() {
		s.earlyMu.Lock()
		defer s.earlyMu.Unlock()
		if s.early[src]--; s.early[src] <= 0 {
			delete(s.early, src)
		}
	}, true
}

// hashUserFor derives the hashing identity of a request: the From user
// part, else the To user, else the Call-ID. From is the caller's own
// identity and is what stays constant across everything a user does, so a
// user's calls land on the switch its REGISTER landed on (aorOf hashes the
// same user for a REGISTER) with no shared state between the two paths.
func hashUserFor(req *sip.Request) string {
	if f := req.From(); f != nil && f.Address.User != "" {
		return f.Address.User
	}
	if t := req.To(); t != nil && t.Address.User != "" {
		return t.Address.User
	}
	return fsip.CallID(req)
}

// inviteToClient handles a call FreeSWITCH is placing to a registered
// client — acceptance criterion 3.
func (s *Server) inviteToClient(req *sip.Request, tx sip.ServerTransaction) {
	binding, ok := s.resolveTarget(req)
	if !ok {
		// Nothing registered under that contact any more. 404 is the
		// correct answer and lets FreeSWITCH fail over or play a
		// treatment, rather than ringing into nothing.
		s.rejectInvite(req, tx, 404, "Not Found", rejectNoTarget)
		return
	}
	dest := binding.Source.String()
	to, ok := s.topo.publicSide(binding.Transport)
	if !ok {
		// A registered client FreeSBC cannot reach is 480: the endpoint is
		// gone, not the service.
		s.rejectInvite(req, tx, 480, "Temporarily Unavailable", rejectNoPublicSide)
		return
	}
	body := req.Body()
	// A client registered over ws or wss is a browser: it accepts only a
	// DTLS-SRTP offer, and without edge.listen.ws or edge.listen.wss there is no
	// DTLS identity to build one with. Offering plain RTP would only ring the browser
	// into a failure it reports as an opaque 480, so refuse here, loudly.
	toBrowser := isBrowserTransport(binding.Transport)
	if toBrowser && !s.webrtcEnabled {
		s.log.Warn("rejecting call to WebSocket client: WebRTC is not enabled, so no DTLS-SRTP offer can be built",
			"sip_call_id", fsip.CallID(req), "aor", binding.AOR, "transport", binding.Transport)
		s.rejectInvite(req, tx, 488, "Not Acceptable Here", rejectWebRTCDisabled)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.inviteBudget())
	defer cancel()

	// One record from here to teardown, as in inviteToUpstream.
	d, ok := s.beginDialog(req, tx, planePrivate)
	if !ok {
		return
	}
	defer d.endUnlessUp()
	d.setSRTP(s.legSRTPPolicy("", binding.Transport))

	// An offerless INVITE is forwarded as it is: the offer is the
	// client's first SDP, built into a private one when it arrives
	// (offerless.go).
	var offer *offerResult
	var offerless func([]byte) (*offerResult, error)
	if len(body) > 0 {
		var err error
		if offer, err = s.buildPublicOffer(d, body, toBrowser); err != nil {
			s.rejectInviteMedia(req, tx, err)
			return
		}
	} else {
		src := binding.Source.Addr()
		offerless = func(b []byte) (*offerResult, error) { return s.buildUpstreamOffer(ctx, d, b, src) }
	}

	out, err := s.prepareForward(req, s.topo.private, to, dest, true)
	if err != nil {
		s.rejectInvite(req, tx, 483, "Too Many Hops", rejectTooManyHops)
		return
	}
	// The Request-URI FreeSWITCH used names FreeSBC's own contact; the
	// client must see one addressed to itself.
	out.Recipient = clientRequestURI(binding)
	fsip.SetContact(out, to.uri())
	if offer != nil {
		fsip.SetSDPBody(out, offer.sdp)
	} else {
		stripBody(out)
	}

	s.log.Info("proxying INVITE to client",
		"sip_call_id", fsip.CallID(req), "direction", "private->public",
		"transport", binding.Transport, "aor", binding.AOR,
		"public_remote", dest,
		"offerless", offer == nil)

	// A CANCEL from FreeSWITCH terminates this server transaction; when it
	// does, the INVITE we sent must be cancelled too or the far side would
	// keep ringing. A false return means the transaction is ALREADY
	// terminated — the CANCEL beat this registration — and nothing has
	// been sent yet: ending here is the whole of the work left.
	if !tx.OnCancel(func(*sip.Request) {
		if !s.cancelCall(d, cancelByCaller) {
			cancel()
		}
	}) {
		return
	}
	a := &inviteAttempt{req: out, cancel: cancel}
	if !d.track(a) {
		return // cancelled before the INVITE went out
	}
	defer d.untrack()

	clTx, err := s.clientTx(ctx, out)
	if err != nil {
		s.log.Warn("forward INVITE to client", "err", err, "aor", binding.AOR)
		s.giveUp(ctx, d, req, tx, 480, "Temporarily Unavailable")
		return
	}
	if d.markSent(a) {
		go s.sendCancel(a)
	}

	l := &inviteLeg{req: req, tx: tx, out: out, clTx: clTx, d: d, offer: offer, offerless: offerless,
		near: s.topo.private, far: to, callee: calleeClient,
		calleeRemote: dest, transport: binding.Transport, fromPrivate: true}
	if r := s.pumpInvite(ctx, l); !r.finalised {
		// The client never gave a final response: its INVITE timed out
		// (Timer B), its transport failed, or the backstop expired. The
		// proxy owes FreeSWITCH a final either way (RFC 3261 §16.7 step 6)
		// rather than leaving it to its own Timer B.
		code, reason := 480, "Temporarily Unavailable"
		if errors.Is(clTx.Err(), sip.ErrTransactionTimeout) {
			code, reason = 408, "Request Timeout"
		}
		s.giveUp(ctx, d, req, tx, code, reason)
	}
}

// publicSideFor returns the public side matching a request's transport.
func (s *Server) publicSideFor(req *sip.Request) (side, bool) {
	return s.topo.publicSide(sip.NetworkToLower(req.Transport()))
}

// resolveTarget finds the binding an inbound request is addressed to by the
// opaque token FreeSBC put in the registered Contact. There is no
// address-of-record fallback: an unknown or expired token is not found.
func (s *Server) resolveTarget(req *sip.Request) (Binding, bool) {
	return s.bindingForRequest(req)
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
	if r := s.firstForeignRoute(req); r != nil {
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

// rejectMedia maps a media-setup failure to the right SIP status: no
// common codec is 488 (the offer is unacceptable), an exhausted port pool
// is 503 (temporary capacity), anything else 500.
func (s *Server) rejectMedia(req *sip.Request, tx sip.ServerTransaction, err error) {
	switch {
	case errors.Is(err, errNoUsableCodec), errors.Is(err, errRenumbered), errors.Is(err, errSDES):
		s.log.Info("rejecting call: media not negotiable", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
	case errors.Is(err, errShuttingDown):
		s.reject(req, tx, 503, "Service Unavailable")
	case errors.Is(err, media.ErrPortsExhausted):
		s.metrics.PortAllocationFailed()
		s.log.Error("rejecting call: media ports exhausted", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 503, "Service Unavailable")
	default:
		s.log.Warn("rejecting call: media setup failed", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
	}
}

// rejectInviteMedia is rejectMedia for an out-of-dialog INVITE: it counts
// the refusal by the same classification that picks the status.
func (s *Server) rejectInviteMedia(req *sip.Request, tx sip.ServerTransaction, err error) {
	switch {
	case errors.Is(err, errShuttingDown):
		s.metrics.InviteRejected(rejectShuttingDown)
	case errors.Is(err, media.ErrPortsExhausted):
		s.metrics.InviteRejected(rejectPortExhausted)
	default:
		s.metrics.InviteRejected(rejectMediaFailed)
	}
	s.rejectMedia(req, tx, err)
}

// isInDialog reports whether a request belongs to an established dialog,
// which RFC 3261 §12.2 identifies by the presence of a To tag.
func isInDialog(req *sip.Request) bool { return fsip.ToTag(req) != "" }

func codecNames(cs []sdp.Codec) string { return sdp.Describe(cs) }
