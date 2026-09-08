package proxy

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

	"github.com/freesbc/freesbc/internal/media"
	"github.com/freesbc/freesbc/internal/sdp"
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
// loop. ok means a 2xx was relayed and the dialog is live (final carries
// it); retryable false means the pump already relayed a final response
// that ends the call (3xx, 401/407 or a 4xx other than 408 — the server
// transaction can finalise only once, so the series must stop); penalize
// asks the caller to put the gateway into cooldown (it produced no
// response at all while FreeSWITCH was still waiting); kind/code/reason
// feed the exhausted-budget synthesis.
type attemptResult struct {
	ok        bool
	retryable bool
	penalize  bool
	kind      attemptKind
	code      int
	reason    string
	final     *sip.Response // the relayed 2xx, when ok
}

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

	// The CANCEL bridge is registered ONCE, for the whole series: the server
	// transaction the client's INVITE created is a single transaction across
	// every attempt, and its OnCancel hook must cancel whichever attempt is
	// in flight when the client gives up. The pending entry is re-tracked
	// per attempt below, and the cancel it holds is ALWAYS this series'
	// cancel — never a per-attempt one — so a CANCEL landing between two
	// attempts still ends the whole series through the stale entry, and the
	// loop's ctx check stops the next attempt from starting.
	if !tx.OnCancel(func(*sip.Request) {
		if !s.cancelPending(req) {
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
	defer s.untrackPending(req)

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
		entry, ok := s.topo.upstreamEntryFor(name)
		if !ok {
			continue
		}

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
		setContact(out, s.topo.private.uri())
		setSDP(out, offer.sdp)

		s.log.Info("proxying INVITE upstream",
			"sip_call_id", callIDOf(req), "direction", "public->private",
			"transport", from.transport, "public_remote", src.String(),
			"upstream", name, "attempt", attempt+1,
			"rtp_public_port", offer.sess.publicPort,
			"rtp_private_port", offer.sess.privatePort,
			"codec", codecNames(offer.sess.codecs))

		// Started on ctx, the series context: the client transaction must
		// outlive the attempt so its CANCEL and its retransmissions are
		// still matched.
		clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
		if err != nil {
			s.log.Warn("forward INVITE upstream", "err", err, "sip_call_id", callIDOf(req),
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
		// The pending entry now points at THIS attempt's forwarded request —
		// its Via branch and destination are what a CANCEL must carry.
		s.trackPending(req, &pendingInvite{req: out, dest: entry.host, side: s.topo.private, cancel: cancel})

		final, responded := s.pumpInvite(ctx, req, tx, clTx, offer, s.topo.private, true)
		clTx.Terminate()

		if final != nil {
			// ANY final response ends the series — pumpInvite has already
			// relayed it. A 486 is the callee's own judgement and must never
			// be retried on another switch (D7); only a 2xx commits the call.
			s.upstreamCooldown.Recover(name)
			if final.StatusCode/100 == 2 {
				committed = true
				c := &call{
					CallID: callIDOf(req), FromTag: fromTagOf(req),
					ToTag: toTagOf(final),
					// In-dialog traffic rides the WINNING switch: directionFor
					// sends the client's ACKs and BYEs to this address, and
					// the winner's Contact (below) is what their Request-URI
					// names.
					PublicRemote: req.Source(), PrivateRemote: entry.host,
					Transport: from.transport,
				}
				// The caller is public here, so its Contact came on the INVITE
				// and FreeSWITCH's came back on the 200.
				if u, ok := contactURI(req); ok {
					c.PublicContact = u
				}
				if u, ok := contactURI(final); ok {
					c.PrivateContact = u
				}
				s.commitCall(req, final, offer, c)
			}
			return
		}
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
			"upstream", name, "cooldown", cooldown.String(), "sip_call_id", callIDOf(req))
	}

	if ctx.Err() != nil {
		return // the caller is already answered (the CANCEL handling did it)
	}
	// Every node failed and nothing was relayed: 503 tells the client's own
	// failover (or the human) to try again rather than pretending the callee
	// is unreachable.
	s.reject(req, tx, 503, "Service Unavailable")
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
	return callIDOf(req)
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
	s.forwardInboundInvite(req, tx, inboundInviteTarget{
		dest:        binding.Source.String(),
		recipient:   clientRequestURI(binding),
		transport:   binding.Transport,
		user:        binding.AOR,
		label:       "client",
		unavailable: 480,
	})
}

// inboundInviteTarget is where an INVITE from FreeSWITCH is headed when it
// is a call to a registered client (the PSTN trunk no longer shares this
// machinery — its failover needs differ; see inviteToPSTN). Media is
// anchored on both legs, the SBC's private identity is advertised back to
// FreeSWITCH, and the far side sees its own identity in the Request-URI
// and Contact.
type inboundInviteTarget struct {
	dest      string  // transport destination ("host:port") of the far side
	recipient sip.Uri // Request-URI the far side must see, addressed to itself
	transport string  // public transport to send over ("udp", "ws", "wss")
	user      string  // far-side user for the log: the client's AoR
	label     string  // log label, "client"
	// unavailable is the status to answer when the forward cannot even be
	// attempted. A registered client that cannot be reached is 480 (the
	// endpoint is gone).
	unavailable int
}

// forwardInboundInvite carries an INVITE from FreeSWITCH to the far side
// an inboundInviteTarget names, anchoring the call's media between the
// two planes. It is inviteToClient's original body, parameterised for the
// one caller that still needs it; the PSTN trunk's forwarding (which once
// built a target here) grew failover and now lives in inviteToPSTN.
func (s *Server) forwardInboundInvite(req *sip.Request, tx sip.ServerTransaction, target inboundInviteTarget) {
	to, ok := s.topo.publicSide(target.transport)
	if !ok {
		s.reject(req, tx, target.unavailable, unavailableReason(target.unavailable))
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

	out, err := s.prepareForward(req, s.topo.private, to, target.dest, true)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	// The Request-URI FreeSWITCH used names FreeSBC's own contact (or the
	// match address); the far side must see one addressed to itself.
	out.Recipient = target.recipient
	setContact(out, to.uri())
	setSDP(out, offer.sdp)

	s.log.Info("proxying INVITE to "+target.label,
		"sip_call_id", callIDOf(req), "direction", "private->public",
		"transport", target.transport, "aor", target.user,
		"public_remote", target.dest,
		"rtp_public_port", offer.sess.publicPort,
		"rtp_private_port", offer.sess.privatePort,
		"codec", codecNames(offer.sess.codecs))

	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
	if err != nil {
		s.log.Warn("forward INVITE to "+target.label, "err", err, "aor", target.user)
		s.reject(req, tx, target.unavailable, unavailableReason(target.unavailable))
		return
	}
	defer clTx.Terminate()
	s.trackPending(req, &pendingInvite{req: out, dest: target.dest, side: to, cancel: cancel})
	defer s.untrackPending(req)

	// A CANCEL from FreeSWITCH terminates this server transaction; when it
	// does, the INVITE we sent must be cancelled too or the far side would
	// keep ringing. A false return means the transaction is ALREADY
	// terminated — the CANCEL beat this registration — in which case the
	// hook will never fire and the far-side leg must be cancelled right
	// here instead.
	if !tx.OnCancel(func(*sip.Request) { s.cancelPending(req) }) {
		s.cancelPending(req)
	}

	final, _ := s.pumpInvite(ctx, req, tx, clTx, offer, s.topo.private, false)
	if final != nil && final.StatusCode/100 == 2 {
		committed = true
		c := &call{
			CallID: callIDOf(req), FromTag: fromTagOf(req),
			ToTag: toTagOf(final), Inbound: true,
			PublicRemote: target.dest, PrivateRemote: req.Source(),
			Transport: target.transport,
		}
		// FreeSWITCH is the caller here, so the roles are reversed: its
		// Contact came on the INVITE and the far side's on the 200.
		if u, ok := contactURI(req); ok {
			c.PrivateContact = u
		}
		if u, ok := contactURI(final); ok {
			c.PublicContact = u
		}
		s.commitCall(req, final, offer, c)
	}
}

// unavailableReason is the reason phrase for the status an
// inboundInviteTarget chose for a forward that cannot start. Only two
// statuses are used, so the mapping is a switch rather than a phrase
// carried through the target: code 503 means "Service Unavailable"
// (carrier), anything else means 480 "Temporarily Unavailable" (client).
func unavailableReason(code int) string {
	if code == 503 {
		return "Service Unavailable"
	}
	return "Temporarily Unavailable"
}

// inviteToPSTN handles a call FreeSWITCH is bridging to the PSTN trunk: a
// route picks the gateway list by called number, and the gateways are
// dialed in order until one connects the call. Each attempt is a fresh
// forward of FreeSWITCH's ORIGINAL INVITE — same Call-ID, CSeq, From and
// To, a new Via branch and its own copy of the offer — so every carrier
// sees an ordinary, complete INVITE while the media session and the dialog
// FreeSWITCH sees are shared across all of them.
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
	wholeCtx, wholeCancel := context.WithTimeout(context.Background(), inviteTimeout)
	defer wholeCancel()

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

	// Cooldown ordering: keep the route's failover order but pull every
	// available gateway ahead of every cooling one, so a sick gateway never
	// delays the call to a healthy alternative (skip-if-alternatives,
	// mirroring the trunk plane's expandTargets). When EVERY candidate is
	// cooling, dial the route's order anyway: a cooldown is a suspicion,
	// not a verdict, and a hard block would turn one dead gateway into a
	// dead route.
	targets := make([]string, 0, len(gwNames))
	var cooled []string
	for _, name := range gwNames {
		if s.pstnCooldown.Available(name) {
			targets = append(targets, name)
		} else {
			cooled = append(cooled, name)
		}
	}
	if len(targets) == 0 {
		targets = cooled
	}

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
		if !s.cancelPending(req) {
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
	// deliberately OVERWRITE one another under the same key, so a CANCEL in
	// the window between two attempts finds the previous attempt's entry
	// and still fires wholeCancel through it.
	defer s.untrackPending(req)

	// startOnce guards the single media relay Start across every attempt:
	// the relay must not be started twice, but must not wait for a gateway
	// that never answers either.
	var startOnce sync.Once
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
		// it is one dialog FreeSWITCH is still waiting on, whatever we had
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
		setContact(out, to.uri())
		setSDP(out, offer.sdp)

		s.log.Info("dialing pstn gateway",
			"sip_call_id", callIDOf(req), "direction", "private->public",
			"number", req.Recipient.User, "gateway", name, "attempt", attempt,
			"public_remote", gw.host,
			"rtp_public_port", offer.sess.publicPort,
			"rtp_private_port", offer.sess.privatePort,
			"codec", codecNames(offer.sess.codecs))

		// Started on wholeCtx, NOT on an attempt context: the client
		// transaction must survive the attempt budget so the expiry path
		// can complete a CANCEL against it (decision #4).
		clTx, err := s.client.TransactionRequest(wholeCtx, out, noBuild)
		if err != nil {
			s.log.Warn("forward PSTN INVITE", "err", err, "sip_call_id", callIDOf(req), "gateway", name)
			if wholeCtx.Err() != nil {
				break // the caller is gone; nothing left to do
			}
			// The INVITE never got out: a zero-response failure while
			// FreeSWITCH is still waiting. Cooldown the gateway and let the
			// next one try.
			s.pstnCooldown.Penalize(name, cooldown)
			continue
		}
		// The pending entry now points at THIS attempt's forwarded request
		// — its Via branch and destination are what a CANCEL must carry.
		s.trackPending(req, &pendingInvite{req: out, dest: gw.host, side: to, cancel: wholeCancel})

		res := s.pumpPSTNAttempt(wholeCtx, budget, req, out, tx, clTx, offer, to, &startOnce, name)
		clTx.Terminate()

		switch {
		case res.ok:
			s.pstnCooldown.Recover(name)
			committed = true
			c := &call{
				CallID: callIDOf(req), FromTag: fromTagOf(req),
				ToTag: toTagOf(res.final), Inbound: true,
				// In-dialog traffic rides the WINNING gateway: directionFor
				// sends FreeSWITCH's ACKs and BYEs to this address, and the
				// winner's Contact (below) is what their Request-URI names.
				PublicRemote: gw.host, PrivateRemote: req.Source(),
				Transport: "udp",
			}
			// FreeSWITCH is the caller, so its Contact came on the INVITE
			// and the winning gateway's on its 200.
			if u, ok := contactURI(req); ok {
				c.PrivateContact = u
			}
			if u, ok := contactURI(res.final); ok {
				c.PublicContact = u
			}
			s.commitCall(req, res.final, offer, c)
			return
		case !res.retryable:
			// The pump relayed a final that ends the call (a 3xx, 401/407
			// or a 4xx other than 408): the server transaction is finalised
			// and nothing more may be sent on it.
			return
		case res.penalize:
			// Zero responses across a whole attempt with FreeSWITCH still
			// waiting: the gateway is suspect. Cooldown it so the NEXT call
			// prefers its alternatives.
			s.log.Warn("pstn gateway unreachable; entering cooldown",
				"gateway", name, "cooldown", cooldown.String(), "sip_call_id", callIDOf(req))
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

	if wholeCtx.Err() != nil {
		return // the caller is already answered (the CANCEL handling did it)
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
// what ends the attempt). budget bounds the attempt. req is FreeSWITCH's
// original INVITE, toward which responses are relayed; out is THIS
// attempt's forwarded request, whose Via branch and destination the CANCEL
// must echo. startOnce guards the single relay Start shared by every
// attempt; to is the public side the INVITE went out on (the identity a
// teardown toward the gateway must advertise).
func (s *Server) pumpPSTNAttempt(wholeCtx context.Context, budget time.Duration,
	req, out *sip.Request, tx sip.ServerTransaction, clTx sip.ClientTransaction,
	offer *offerResult, to side, startOnce *sync.Once, gateway string) attemptResult {

	// The budget is enforced by a timer, NOT a derived context: the client
	// transaction must outlive the budget so the expiry path can complete a
	// CANCEL against a live transaction.
	timer := time.NewTimer(budget)
	defer timer.Stop()

	answered := false  // this attempt has already negotiated its answer
	responded := false // any response was received (liveness evidence)
	for {
		select {
		case res, ok := <-clTx.Responses():
			if !ok {
				// sipgo never closes this channel; defensive only.
				return attemptResult{retryable: true, kind: failDial, code: 503,
					reason: "Service Unavailable", penalize: !responded && wholeCtx.Err() == nil}
			}
			if !forwardable(res) {
				continue // a 100 Trying is hop-by-hop; ours already went out
			}
			if wholeCtx.Err() != nil {
				// FreeSWITCH cancelled while this response was in flight:
				// nothing may be relayed (its transaction is already
				// terminated). A 2xx that raced the CANCEL still believes
				// it has a live dialog — complete and tear it down.
				if res.StatusCode/100 == 2 {
					go s.ackThenBye(res, to)
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
			relayed := res.Clone()
			if !s.popOwnVia(relayed) {
				s.log.Debug("dropping unroutable pstn response", "code", res.StatusCode,
					"sip_call_id", callIDOf(req), "gateway", gateway)
				continue
			}
			// FreeSWITCH must see FreeSBC as the dialog's remote target, or
			// its in-dialog requests would bypass the SBC and its media
			// anchor.
			setContact(relayed, s.topo.private.uri())

			if len(res.Body()) > 0 {
				var body []byte
				if answered {
					// A restated answer (the 200 echoing a body-bearing 183,
					// say): repeat the body FreeSWITCH already accepted —
					// re-negotiating would re-latch media under it.
					body = offer.sess.lastAnswer
				} else {
					// Only the first body-bearing response OF THIS ATTEMPT
					// is negotiated. rePoint tells applyPSTNAnswer whether
					// an EARLIER attempt already latched the public side to
					// a failed gateway: the latch must be re-armed to this
					// gateway's address, or its media would be refused as a
					// hijack.
					var err error
					body, err = s.applyPSTNAnswer(offer, res.Body(), offer.sess.lastAnswer != nil)
					if err != nil {
						s.log.Warn("pstn media negotiation failed", "err", err,
							"sip_call_id", callIDOf(req), "gateway", gateway)
						if res.StatusCode/100 == 2 {
							// The gateway believes the dialog is live and
							// will retransmit its 200: complete and tear it
							// down. The teardown goes out the PUBLIC side —
							// the gateway can only route responses back to
							// the public identity.
							go s.ackThenBye(res, to)
						}
						// Nothing of this response reaches FreeSWITCH — not
						// even a media-bearing provisional that could not be
						// anchored. 488 outranks every other failure at
						// exhaustion.
						return attemptResult{retryable: true, kind: failAnchor,
							code: 488, reason: "Not Acceptable Here"}
					}
					answered = true
					// The relay starts on the first anchorable answer,
					// exactly once across every attempt of the call.
					startOnce.Do(func() { offer.sess.rtp.Start() })
				}
				setSDP(relayed, body)
				offer.sess.lastAnswer = relayed.Body()
			}

			relayed.SetDestination(req.Source())
			s.metrics.ResponseOut(relayed.StatusCode)
			if err := tx.Respond(relayed); err != nil {
				s.log.Debug("relay pstn response", "err", err, "sip_call_id", callIDOf(req))
			}
			switch {
			case res.StatusCode < 200:
				// A provisional; keep pumping.
			case res.StatusCode < 300:
				// The call is up: the dialog is committed from this 2xx.
				return attemptResult{ok: true, final: res}
			default:
				// Relayed and final: a 3xx, 401/407, or a 4xx other than
				// the held 408. These are the far end's verdict on THIS
				// call — a wrong number will be wrong on every gateway
				// (404/486) and a redirect is a response to this dialog —
				// so the series stops here.
				return attemptResult{retryable: false}
			}
		case <-clTx.Done():
			// The transaction died without a final: the INVITE never got
			// out, or the remote vanished mid-ring. Zero responses while
			// FreeSWITCH is still waiting is the cooldown case.
			return attemptResult{retryable: true, kind: failDial, code: 503,
				reason: "Service Unavailable", penalize: !responded && wholeCtx.Err() == nil}
		case <-wholeCtx.Done():
			// FreeSWITCH cancelled (or the 5-minute backstop fired): the
			// attempt ends, and the series with it. No penalize: the caller
			// gave up; the gateway was not given its chance to fail.
			return attemptResult{retryable: true, kind: failDial, code: 503,
				reason: "Service Unavailable"}
		case <-timer.C:
			return s.expirePSTNAttempt(wholeCtx, req, out, tx, clTx, to, responded, gateway)
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
func (s *Server) expirePSTNAttempt(wholeCtx context.Context, req, out *sip.Request,
	tx sip.ServerTransaction, clTx sip.ClientTransaction, to side, responded bool,
	gateway string) attemptResult {
	s.log.Warn("pstn attempt budget expired; cancelling",
		"gateway", gateway, "sip_call_id", callIDOf(req))

	// A short-lived transaction of its own: per RFC 3261 §9.1 the CANCEL
	// echoes the INVITE's branch, which buildCancel(out) provides.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.client.TransactionRequest(ctx, buildCancel(out), noBuild); err != nil {
		s.log.Debug("cancel pstn attempt", "err", err, "sip_call_id", callIDOf(req))
		return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout",
			penalize: !responded && wholeCtx.Err() == nil}
	}

	// Drain briefly. Nothing read here is relayed — the attempt is over —
	// but what arrives classifies how it ended.
	drain := time.NewTimer(pstnDrain)
	defer drain.Stop()
	for {
		select {
		case res, ok := <-clTx.Responses():
			if !ok {
				return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout",
					penalize: !responded && wholeCtx.Err() == nil}
			}
			if !forwardable(res) {
				continue
			}
			switch {
			case res.StatusCode == 200:
				// A 2xx raced the CANCEL: the gateway accepted a call the
				// budget had already given up on. It responded, so no
				// cooldown; complete and tear down the dialog it believes
				// exists.
				s.log.Warn("pstn gateway answered as its attempt expired",
					"gateway", gateway, "sip_call_id", callIDOf(req))
				go s.ackThenBye(res, to)
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
			return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout",
				penalize: !responded && wholeCtx.Err() == nil}
		case <-wholeCtx.Done():
			// The call ended while we were draining the attempt; nothing
			// more may be relayed either way.
			return attemptResult{retryable: true, kind: failRing, code: 408, reason: "Request Timeout",
				penalize: !responded && wholeCtx.Err() == nil}
		}
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

// pumpInvite relays every response of a forwarded INVITE, rewriting the
// Contact and negotiating the SDP answer on whichever response carries
// one. It returns the final response, or nil if the transaction died, plus
// whether the far side responded AT ALL — any forwardable response, even a
// provisional one, counts.
//
// The responded flag is what makes retrying another node safe: a retry is
// only allowed when nothing was answered, so a node that spoke is always
// heard out and a call whose answer was already applied can never be
// re-negotiated against a second node (see inviteToUpstream).
//
// toUpstream selects which direction's answer processing applies.
func (s *Server) pumpInvite(ctx context.Context, req *sip.Request, tx sip.ServerTransaction,
	clTx sip.ClientTransaction, offer *offerResult, near side, toUpstream bool) (*sip.Response, bool) {

	answered := false
	responded := false
	for {
		select {
		case res, ok := <-clTx.Responses():
			if !ok {
				s.reject(req, tx, 500, "Server Internal Error")
				return nil, responded
			}
			if !forwardable(res) {
				continue // a 100 Trying is hop-by-hop; ours already went out
			}
			responded = true
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
					return nil, responded
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
				return res, responded
			}
		case <-clTx.Done():
			if err := clTx.Err(); err != nil {
				s.log.Debug("invite client transaction ended", "err", err, "sip_call_id", callIDOf(req))
			}
			return nil, responded
		case <-ctx.Done():
			return nil, responded
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
		s.log.Warn("forward in-dialog request failed", "err", err,
			"method", req.Method.String(), "sip_call_id", callIDOf(req))
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
					"sip_call_id", callIDOf(req))
			}
			s.respond(req, tx, sip.NewResponseFromRequest(req, 200, "OK", nil))
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
	// The dialog's own record of which switch carries it beats hashing: an
	// inbound call placed BY fs-b (forwardInboundInvite records
	// PrivateRemote = its source) must have the client's ACK and BYE return
	// to fs-b even though the client's user hashes to fs-a. That record is
	// the whole stickiness guarantee — a dialog must never migrate between
	// switches mid-call.
	if c, found := s.calls.get(callIDOf(req)); found && c.PrivateRemote != "" {
		return from, s.topo.private, c.PrivateRemote, true
	}
	// No dialog on record — a race where the ACK beat commitCall, or a
	// dialog already evicted. Recompute the node from the same identity and
	// the same pool the INVITE was hashed with: for every request the caller
	// itself causes that is the node the INVITE went to, so the dialog stays
	// put without any shared state. It deliberately NEVER 481s: a request
	// the SBC cannot place is still better forwarded to the most plausible
	// switch than refused, and the switch itself answers honestly if the
	// dialog is unknown to it.
	if name, entry, found := s.selectUpstream(hashUserFor(req)); found {
		s.log.Debug("in-dialog request without a dialog record; hashing upstream",
			"sip_call_id", callIDOf(req), "upstream", name)
		return from, s.topo.private, entry.host, true
	}
	// An empty pool cannot happen on a validated config: sip.upstream.address
	// or sip.upstreams.nodes is exactly what enables the proxy at all.
	return side{}, side{}, "", false
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

func codecNames(cs []sdp.Codec) string { return sdp.Describe(cs) }
