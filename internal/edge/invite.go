package edge

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// inviteTimeout bounds an INVITE transaction end to end. It is longer than
// a typical ring cap because the far end, not FreeSBC, decides when to
// give up; this is a backstop against a transaction that never finalises
// pinning a media session forever. For a PSTN trunk it is the WHOLE-CALL
// budget the failover series runs under — each gateway attempt gets its own
// (much smaller) budget, attempt_timeout, enforced by the pump.
const inviteTimeout = 5 * time.Minute

// pstnDrain is how long the pump waits after a budget-expiry CANCEL for the
// final response that CANCEL provokes. Long enough for a local gateway's
// 487 (a few RTTs), short enough that a dead gateway cannot stall the
// failover: the attempt is over either way, and the drain only exists to
// classify HOW it ended (a 2xx that raced the CANCEL must be ACKed and
// BYEd, or the gateway retransmits its 200 for up to Timer H).
const pstnDrain = 300 * time.Millisecond

// attemptKind classifies how one gateway attempt ended, for the status the
// exhausted-budget path synthesises when every gateway has failed. The
// precedence is deliberate: a media-anchor failure (failAnchor) outranks
// everything — it means no carrier that answered can use FreeSWITCH's
// offer, which no further attempt can fix; a real final (failReal) is the
// last carrier's honest word on the call; a ring timeout (failRing) is the
// budget the carrier burned in silence; failDial is an attempt that never
// produced anything at all.
type attemptKind int

const (
	failDial   attemptKind = iota // the INVITE never produced an answerable response
	failReal                      // a real final (>=500 or 408) arrived and was held
	failRing                      // the attempt budget expired while it was ringing
	failAnchor                    // an answer arrived but its media could not be anchored
)

// attemptResult is what one gateway attempt reports back to the failover
// loop. ok means a 2xx was accepted and the dialog is confirmed; retryable
// false means the pump already relayed a final response that ends the call
// (3xx, 401/407, a 4xx other than 408, or a 6xx — the server transaction
// can finalise only once, so the series must stop); penalize asks the caller
// to put the gateway into cooldown (it produced no response at all while
// FreeSWITCH was still waiting); kind/code/reason feed the exhausted-budget
// synthesis. global is a 6xx that could not be relayed as it arrived (it
// raced the attempt's expiry CANCEL): the series stops and FreeSWITCH is
// sent that code.
type attemptResult struct {
	ok        bool
	global    bool
	retryable bool
	penalize  bool
	kind      attemptKind
	code      int
	reason    string
}

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
func (s *Server) onInvite(req *sip.Request, tx sip.ServerTransaction, src netip.AddrPort) {
	if isInDialog(req) {
		s.onReInvite(req, tx)
		return
	}
	// FreeSWITCH bridging an outbound PSTN call arrives on the PUBLIC
	// socket (it targets the public listener port over the private link),
	// so the plane dispatch below would misread it as a public phone's
	// call. Classify it first: upstream source + the configured match
	// Request-URI. Ordering against arrivedOnPrivate does not matter for
	// correctness — such a request can never be in privSources — but this
	// keeps "most specific first".
	if s.isPSTNBridgeInvite(req, src) {
		s.inviteToPSTN(req, tx)
		return
	}
	if s.arrivedOnPrivate(req) {
		s.inviteToClient(req, tx)
		return
	}
	s.inviteToUpstream(req, tx, src)
}

// isPSTNBridgeInvite reports whether an INVITE is FreeSWITCH bridging an
// outbound call to the PSTN carrier: it arrived from the configured
// upstream AND its Request-URI names sip.pstn.match — the address the
// dialplan sends PSTN prefixes to. Both halves are needed. A public phone
// cannot trip this, because the source check fails for anything that did
// not come from the upstream host; and a request from the upstream for any
// other purpose fails the match check, because the match host:port is one
// FreeSWITCH uses for nothing else (validation enforces it does not name
// the SBC's private socket or the upstream itself).
func (s *Server) isPSTNBridgeInvite(req *sip.Request, src netip.AddrPort) bool {
	if !s.topo.pstnEnabled() {
		return false
	}
	if !s.topo.fromUpstream(src.Addr()) {
		return false
	}
	if req.Recipient.Host != s.topo.pstn.match.Host {
		return false
	}
	// A URI without a port means the transport default, as everywhere else
	// in the proxy (isSelf, Via checks).
	port := req.Recipient.Port
	if port == 0 {
		port = 5060
	}
	return port == s.topo.pstn.match.Port
}

// beginDialog opens the call's record, or answers 482 when the INVITE
// merges with one still in progress (RFC 3261 §8.2.2.2: same Call-ID and
// From tag as a transaction the proxy is already working on).
func (s *Server) beginDialog(req *sip.Request, tx sip.ServerTransaction, callerPlane plane) (*dialog, bool) {
	d, ok := s.dialogs.begin(req, callerPlane)
	if !ok {
		s.reject(req, tx, 482, "Loop Detected")
		return nil, false
	}
	return d, true
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

	offer, err := s.buildUpstreamOffer(ctx, d, body)
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	sess := offer.sess()

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

	// The failure budget is re-read from the store on EVERY call, so a
	// reload changes it for the next call without a restart; the node set is
	// a startup snapshot like the rest of the topology.
	cooldown := s.store.Current().SIP.Upstreams.Cooldown.Std()

	// The caller's hash order, cooled nodes at the tail: everything this
	// user does starts on the same switch, and a switch that just failed is
	// only dialed once its alternatives have been tried.
	for attempt, name := range s.upstreamOrder(hashUserFor(req)) {
		if ctx.Err() != nil {
			break // the caller is gone (or the backstop fired) mid-series
		}
		entry := s.topo.upstreamEntryFor(name)

		// Every attempt re-forwards the ORIGINAL request (prepareForward
		// clones, so the client's INVITE stays intact): a fresh Via branch
		// and Record-Route pair per attempt, same Call-ID/CSeq/From/To — it
		// is one dialog the client is still waiting on, whatever we had to
		// try to connect it.
		out, err := s.prepareForward(req, from, s.topo.private, entry.host, true)
		if err != nil {
			s.reject(req, tx, 483, "Too Many Hops")
			return
		}
		// The client's Contact must not reach FreeSWITCH: it names the
		// client's own address (or, for a browser, an unreachable .invalid
		// host), and FreeSWITCH would send in-dialog requests straight to it,
		// bypassing the SBC entirely.
		fsip.SetContact(out, s.topo.private.uri())
		fsip.SetSDPBody(out, offer.sdp)

		s.log.Info("proxying INVITE upstream",
			"sip_call_id", fsip.CallID(req), "direction", "public->private",
			"transport", from.transport, "public_remote", src.String(),
			"upstream", name, "attempt", attempt+1,
			"rtp_public_port", sess.publicPort,
			"rtp_private_port", sess.privatePort,
			"codec", codecNames(sess.negotiated()))

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
		clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
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
		l := &inviteLeg{req: req, tx: tx, out: out, clTx: clTx, offer: offer,
			near: from, far: s.topo.private, callee: calleeUpstream,
			calleeRemote: entry.host, transport: from.transport}
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
		s.reject(req, tx, 408, "Request Timeout")
	case ctx.Err() != nil || d.wasCancelled():
		s.reject(req, tx, 487, "Request Terminated")
	default:
		s.reject(req, tx, code, reason)
	}
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
		s.reject(req, tx, 404, "Not Found")
		return
	}
	dest := binding.Source.String()
	to, ok := s.topo.publicSide(binding.Transport)
	if !ok {
		// A registered client FreeSBC cannot reach is 480: the endpoint is
		// gone, not the service.
		s.reject(req, tx, 480, "Temporarily Unavailable")
		return
	}
	body := req.Body()
	if len(body) == 0 {
		// An offerless INVITE would make FreeSBC the offerer toward the
		// far side and then require a second negotiation against the ACK.
		// Not supported in this phase; refusing is honest.
		s.reject(req, tx, 488, "Not Acceptable Here")
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

	offer, err := s.buildPublicOffer(d, body)
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	sess := offer.sess()

	out, err := s.prepareForward(req, s.topo.private, to, dest, true)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	// The Request-URI FreeSWITCH used names FreeSBC's own contact; the
	// client must see one addressed to itself.
	out.Recipient = clientRequestURI(binding)
	fsip.SetContact(out, to.uri())
	fsip.SetSDPBody(out, offer.sdp)

	s.log.Info("proxying INVITE to client",
		"sip_call_id", fsip.CallID(req), "direction", "private->public",
		"transport", binding.Transport, "aor", binding.AOR,
		"public_remote", dest,
		"rtp_public_port", sess.publicPort,
		"rtp_private_port", sess.privatePort,
		"codec", codecNames(sess.negotiated()))

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

	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
	if err != nil {
		s.log.Warn("forward INVITE to client", "err", err, "aor", binding.AOR)
		s.giveUp(ctx, d, req, tx, 480, "Temporarily Unavailable")
		return
	}
	if d.markSent(a) {
		go s.sendCancel(a)
	}

	l := &inviteLeg{req: req, tx: tx, out: out, clTx: clTx, offer: offer,
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

// inviteToPSTN handles a call FreeSWITCH is bridging to the PSTN trunk: a
// route picks the gateway list by called number, and the gateways are
// dialed in order until one connects the call. Each attempt is a fresh
// forward of FreeSWITCH's ORIGINAL INVITE — same Call-ID, CSeq, From and
// To, a new Via branch and its own copy of the offer — so every carrier
// sees an ordinary, complete INVITE while the media session and the record
// FreeSWITCH's INVITE opened are shared across all of them.
//
// A failed attempt's final is never relayed to FreeSWITCH: the server
// transaction can finalise only once, and a later gateway may still connect
// the call. Only when the list is exhausted is one status synthesised from
// what the attempts revealed.
//
// The gateway is peer-to-peer: it never registers and FreeSBC never pings
// it (its health is the passive cooldown the gateway cooldown table
// tracks). The call
// shape is exactly FS→client — media anchored on both legs, the private
// identity advertised back to FreeSWITCH.
//
// Precondition (established by onInvite's classification): the request
// arrived from the configured upstream and its Request-URI names
// sip.pstn.match.
func (s *Server) inviteToPSTN(req *sip.Request, tx sip.ServerTransaction) {
	// The trunk rides the public UDP plane, which validation guarantees is
	// configured whenever sip.pstn is. Unlike a client (480), an
	// unreachable carrier is a temporary service failure (503): it is
	// infrastructure FreeSWITCH expects to fail over around, not an
	// endpoint that has gone away.
	to, ok := s.topo.publicSide("udp")
	if !ok {
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	body := req.Body()
	if len(body) == 0 {
		// An offerless INVITE would make FreeSBC the offerer toward the
		// carrier and then require a second negotiation against the ACK.
		// Not supported in this phase; refusing is honest. Same answer as
		// the client path, before any gateway is dialed.
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}

	// wholeCtx is the whole-call backstop the entire attempt series runs
	// under: the 5-minute inviteTimeout, cancellable — a FreeSWITCH CANCEL
	// cancels the series, never just the attempt in flight.
	wholeCtx, wholeCancel := context.WithTimeout(context.Background(), s.inviteBudget())
	defer wholeCancel()

	// One record from here to teardown, as in inviteToUpstream. The whole
	// failover series shares it: one media session, one CANCEL bridge. The
	// caller is FreeSWITCH, whose in-dialog requests arrive on the private
	// socket (the double Record-Route puts it first in its route set).
	d, ok := s.beginDialog(req, tx, planePrivate)
	if !ok {
		return
	}
	defer d.endUnlessUp()

	offer, err := s.buildPublicOffer(d, body)
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	sess := offer.sess()

	// A number no route matches is not a PSTN call as far as this trunk is
	// concerned; 503 tells FreeSWITCH's bridge to fail over rather than
	// treat the number as invalid. No gateway is dialed (the harness and
	// route tests assert exactly that).
	gwNames, ok := resolvePSTNRoute(s.topo.pstn.routes, req.Recipient.User)
	if !ok {
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}

	// The failure budgets are re-read from the store on EVERY call, so a
	// config reload changes them for the next call without a restart; the
	// gateway set and routes are a startup snapshot like the rest of the
	// topology.
	cfg := s.store.Current().SIP.Pstn
	budget := cfg.AttemptTimeout.Std()
	cooldown := cfg.Cooldown.Std()

	// Cooldown ordering: keep the route's failover order, but SKIP every
	// cooling gateway while any alternative is available, so a sick gateway
	// never delays the call to a healthy one (skip-if-alternatives,
	// mirroring the trunk plane's expandTargets). When EVERY candidate is
	// cooling, dial the route's order anyway: a cooldown is a suspicion,
	// not a verdict, and a hard block would turn one dead gateway into a
	// dead route.
	targets, _ := orderByAvailability(gwNames, s.pstnCooldown.Available)

	// The CANCEL bridge is registered ONCE, for the whole series: the
	// server transaction FreeSWITCH's INVITE created is a single
	// transaction across every attempt, and its OnCancel hook must cancel
	// whichever attempt is in flight when FreeSWITCH gives up. The pending
	// entry is re-tracked per attempt below, and the cancel it holds is
	// ALWAYS wholeCancel — never a per-attempt cancel — so a CANCEL landing
	// between two attempts still ends the whole series through the stale
	// entry, and the loop's wholeCtx check stops the next attempt from
	// starting.
	if !tx.OnCancel(func(*sip.Request) {
		if !s.cancelCall(d, cancelByCaller) {
			// No attempt in flight (between attempts, or before the first):
			// there is nothing to CANCEL on the wire, but the series must
			// still stop.
			wholeCancel()
		}
	}) {
		// The CANCEL beat us here: the server transaction is already
		// terminated, the hook will never fire, and there is nothing to
		// forward to. sipgo has already answered FreeSWITCH (200 to the
		// CANCEL, 487 to the INVITE); ending the series is the whole of the
		// work left.
		return
	}
	// One untrack at the end of the whole series: the per-attempt entries
	// deliberately OVERWRITE one another on the record, so a CANCEL in the
	// window between two attempts finds the previous attempt's entry and
	// still fires wholeCancel through it.
	defer d.untrack()

	var (
		haveAnchor     bool
		haveReal       bool
		lastRealCode   int
		lastRealReason string
		haveRing       bool
		attempt        int
	)
	for _, name := range targets {
		if wholeCtx.Err() != nil {
			break // FreeSWITCH cancelled (or the backstop fired) mid-series
		}
		attempt++
		gw, ok := s.topo.pstn.gateways[name]
		if !ok {
			continue
		}

		// Every attempt re-forwards the ORIGINAL request (prepareForward
		// clones, so FreeSWITCH's INVITE stays intact): a fresh Via branch
		// and Record-Route pair per attempt, same Call-ID/CSeq/From/To —
		// it is one call FreeSWITCH is still waiting on, whatever we had
		// to try to connect it.
		out, err := s.prepareForward(req, s.topo.private, to, gw.host, true)
		if err != nil {
			s.reject(req, tx, 483, "Too Many Hops")
			return
		}
		// The Request-URI FreeSWITCH used names FreeSBC's own match
		// address; the carrier must see the called number addressed to
		// itself.
		out.Recipient = pstnRequestURI(req.Recipient, gw.addr)
		fsip.SetContact(out, to.uri())
		fsip.SetSDPBody(out, offer.sdp)

		s.log.Info("dialing pstn gateway",
			"sip_call_id", fsip.CallID(req), "direction", "private->public",
			"number", req.Recipient.User, "gateway", name, "attempt", attempt,
			"public_remote", gw.host,
			"rtp_public_port", sess.publicPort,
			"rtp_private_port", sess.privatePort,
			"codec", codecNames(sess.negotiated()))

		// Tracked before it is sent, as in inviteToUpstream.
		a := &inviteAttempt{req: out, cancel: wholeCancel}
		if !d.track(a) {
			break // FreeSWITCH cancelled before this attempt started
		}
		// Started on wholeCtx, NOT on an attempt context: the client
		// transaction must survive the attempt budget so the expiry path
		// can complete a CANCEL against it (decision #4).
		clTx, err := s.client.TransactionRequest(wholeCtx, out, noBuild)
		if err != nil {
			s.log.Warn("forward PSTN INVITE", "err", err, "sip_call_id", fsip.CallID(req), "gateway", name)
			if wholeCtx.Err() != nil {
				break // the caller is gone; nothing left to do
			}
			// The INVITE never got out: a zero-response failure while
			// FreeSWITCH is still waiting. Cooldown the gateway and let the
			// next one try.
			s.pstnCooldown.Penalize(name, cooldown)
			continue
		}
		if d.markSent(a) {
			go s.sendCancel(a)
		}

		// In-dialog traffic rides the WINNING gateway: directionFor sends
		// FreeSWITCH's ACKs and BYEs to this address, and the winner's
		// Contact is what their Request-URI names.
		l := &inviteLeg{req: req, tx: tx, out: out, clTx: clTx, offer: offer,
			near: s.topo.private, far: to, callee: calleePSTN,
			calleeRemote: gw.host, transport: "udp", fromPrivate: true}
		res := s.pumpPSTNAttempt(wholeCtx, budget, l, name)

		switch {
		case res.ok:
			s.pstnCooldown.Recover(name)
			return
		case res.global:
			s.pstnCooldown.Recover(name)
			s.reject(req, tx, res.code, res.reason)
			return
		case !res.retryable:
			// The pump relayed a final that ends the call (a 3xx, 401/407,
			// a 4xx other than 408, or a 6xx): the server transaction is
			// finalised and nothing more may be sent on it.
			return
		case res.penalize:
			// Zero responses across a whole attempt with FreeSWITCH still
			// waiting: the gateway is suspect. Cooldown it so the NEXT call
			// prefers its alternatives.
			s.log.Warn("pstn gateway unreachable; entering cooldown",
				"gateway", name, "cooldown", cooldown.String(), "sip_call_id", fsip.CallID(req))
			s.pstnCooldown.Penalize(name, cooldown)
		}
		switch res.kind {
		case failAnchor:
			haveAnchor = true
		case failReal:
			haveReal, lastRealCode, lastRealReason = true, res.code, res.reason
		case failRing:
			haveRing = true
		}
		// Between attempts the stale pending entry deliberately stays put:
		// a FreeSWITCH CANCEL in this window still finds it and fires
		// wholeCancel (see the OnCancel hook above).
	}

	if wholeCtx.Err() != nil || d.wasCancelled() {
		// FreeSWITCH cancelled (sipgo answered it), or the backstop expired.
		s.giveUp(wholeCtx, d, req, tx, 408, "Request Timeout")
		return
	}
	// Every gateway failed and nothing was relayed: synthesise the ONE
	// status FreeSWITCH sees. An anchor failure answers 488 (no carrier can
	// use FreeSWITCH's offer — worth more than any gateway's own failure,
	// and what the v1 single-gateway shape answered for the same case);
	// otherwise the last real code, a ring timeout, or the generic 503 in
	// that order.
	switch {
	case haveAnchor:
		s.reject(req, tx, 488, "Not Acceptable Here")
	case haveReal:
		s.reject(req, tx, lastRealCode, lastRealReason)
	case haveRing:
		s.reject(req, tx, 408, "Request Timeout")
	default:
		s.reject(req, tx, 503, "Service Unavailable")
	}
}

// pstnRequestURI re-points a bridged call's Request-URI at the carrier
// gateway: FreeSWITCH dialed FreeSBC's own match address, and the carrier
// must be addressed by its own host:port. Everything else about the URI
// survives — the user part IS the called number, and header-style
// parameters like user=phone ride along — so only the host, the port and
// any transport parameter (which would try to steer the carrier to a
// different transport on a non-default port) change.
func pstnRequestURI(u sip.Uri, gw netip.AddrPort) sip.Uri {
	// Clone first: the clone deep-copies the params, and the request's own
	// URI must not be mutated — it is what the response path matches
	// against.
	u = *u.Clone()
	u.Host = gw.Addr().String()
	u.Port = int(gw.Port())
	if u.UriParams != nil {
		u.UriParams.Remove("transport")
	}
	return u
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

// rejectMedia maps a media-setup failure to the right SIP status: no
// common codec is 488 (the offer is unacceptable), an exhausted port pool
// is 503 (temporary capacity), anything else 500.
func (s *Server) rejectMedia(req *sip.Request, tx sip.ServerTransaction, err error) {
	switch {
	case errors.Is(err, errNoUsableCodec), errors.Is(err, errRenumbered):
		s.log.Info("rejecting call: media not negotiable", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
	case errors.Is(err, media.ErrPortsExhausted):
		s.metrics.PortAllocationFailed()
		s.log.Error("rejecting call: media ports exhausted", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 503, "Service Unavailable")
	default:
		s.log.Warn("rejecting call: media setup failed", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
	}
}

// isInDialog reports whether a request belongs to an established dialog,
// which RFC 3261 §12.2 identifies by the presence of a To tag.
func isInDialog(req *sip.Request) bool { return fsip.ToTag(req) != "" }

func codecNames(cs []sdp.Codec) string { return sdp.Describe(cs) }
