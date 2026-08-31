package sig

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/callstate"
	"github.com/freesbc/freesbc/media"
)

// legSRTP is the negotiated SRTP state for one leg. secure=false means the
// leg is plaintext and inbound/outbound are nil. When secure, inbound
// decrypts what we receive from the peer (built from the peer's advertised
// key) and outbound encrypts what we send to the peer (built from
// ourKeyValue, which we advertise to the peer in SDP). suite is the
// negotiated suite. Keys are never copied between legs: each leg's inbound
// context is built from THAT peer's own advertised key, and each leg's
// outbound context is built from a key WE generated fresh for that leg.
type legSRTP struct {
	secure      bool
	suite       media.CryptoSuite
	inbound     *media.SRTPContext // nil until the peer's key is known
	outbound    *media.SRTPContext
	ourKeyValue []byte // advertised to the peer (a=crypto)

	// tag is the a=crypto tag WE advertise this leg's key under. For the
	// A-leg (the SBC as answerer), it must echo the tag of the offered line
	// selectCrypto picked — RFC 4568 §5.1.3 — so it's copied from sel.tag in
	// onInvite, not left at zero. For the B-leg (the SBC as offerer), the
	// SBC always offers exactly one line, so its offer always uses tag 1
	// directly rather than via this field.
	tag int

	// required is true only when this leg's peer policy is "srtp: required"
	// (never for "optional", even when the leg ended up secure=true because
	// the other leg happened to be secure). processAnswerSDP consults it to
	// decide how to treat an answer with no usable/matching crypto: required
	// fails the attempt (→ failover); optional bridges as plaintext instead
	// (RFC 3264-style graceful downgrade — "SRTP if the peer accepts, else
	// plaintext"). Currently only ever set on the B-leg's legSRTP built in
	// dialTarget; the A-leg already rejects an insecure offer against a
	// required policy with 488 in onInvite, before any legSRTP is built, so
	// it has no analogous use there.
	required bool
}

// errSRTPRequiredMismatch marks a processAnswerSDP failure caused
// specifically by a B-leg policy of required SRTP whose answer turned out
// not to be secure. Unlike a malformed/unparseable answer (a genuine carrier
// failure that ends the call with 502 — see TestBridgeBrokenAnswerSDPGets502),
// this one is retryable: the carrier answered and is reachable, it just
// doesn't meet our policy, so placeCall should fail over to the next target
// instead of giving up on the whole call.
var errSRTPRequiredMismatch = errors.New("srtp required by policy but answer has no usable a=crypto")

// bridge is the B2BUA: it pairs an inbound A-leg with an outbound B-leg,
// anchoring media and hiding topology. One bridge instance is shared; each
// call runs in its own onInvite goroutine (sipgo dispatches OnInvite in a
// fresh goroutine per request).
type bridge struct {
	s *Server
}

// onInvite handles an inbound INVITE end to end: identify the source,
// route it, place the B-leg (failing over across decision.Targets and
// applying each target's outbound digest auth as it goes — Task 8),
// anchor media, answer the A-leg, and hold the call open until either leg
// ends the dialog or media goes silent.
func (b *bridge) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	defer b.recoverCall(req)

	name, fromPeer, ok := b.s.identify(req)
	if !ok {
		b.s.dropUnidentified(req)
		return
	}

	// In-dialog INVITE (re-INVITE: hold/resume, codec change, target
	// refresh, session-timer refresh, ...) vs. initial INVITE is
	// distinguished by the To-tag: an initial INVITE never carries one (RFC
	// 3261 §8.1.1.2), an in-dialog INVITE always does (it's the tag the
	// dialog was established with).
	//
	// sipgo v1.4.3's DialogServerSession.ReadInvite is single-use: calling
	// it again for a re-INVITE on an already-established dialog corrupts
	// that dialog's To-tag rather than answering the renegotiation — so a
	// re-INVITE must never be handed to ReadInvite/aLeg. A session-timer
	// refresh re-INVITE (Session-Expires present, offered SDP matching what
	// we established modulo an o= version bump — isRefreshReInvite)
	// sidesteps that entirely: it is answered locally, with a 200 OK sent
	// directly on the re-INVITE's own raw server transaction, never
	// touching dialogSrv. (M4.3 Task 6 spike: verified against sipgo
	// v1.4.3 that this is safe — see timers.go and
	// TestBridgeAnswersSessionTimerRefresh.) Any other re-INVITE (a genuine
	// media change, or one we can't recognize as a refresh — e.g. no
	// established SDP on record) still gets 501 Not Implemented on the raw
	// transaction, exactly as M3.3 left it. Per RFC 3261 §14.1, a failed
	// re-INVITE does not terminate the dialog, so the established call
	// stays up with its existing media either way. Full mid-dialog media
	// renegotiation support is deferred beyond M4.3.
	//
	// req.CallID() is looked up directly — not assumed to be the A-leg's —
	// because b.s.sdps now holds an entry per LEG (see callSDPStore): a
	// refresh from the CALLER carries the A-leg's Call-ID and is answered
	// with aAnswer, while a refresh from the CARRIER carries the B-leg's
	// own, distinct Call-ID and is answered with bOffer. Same code path,
	// correct answer either way (Fix 2).
	//
	// Limitation: this bare-tx.Respond path does NOT retransmit the 2xx
	// (sipgo's TU retransmit-until-ACK loop lives in
	// DialogServerSession.WriteResponse, which we deliberately bypass). If
	// the refresh 200 is lost, the refresher's re-INVITE transaction times
	// out and per RFC 4028 §10 it may BYE at session expiry. Acceptable on a
	// reliable link; a retransmit loop is deferred (a hand-rolled one outside
	// the dialog layer is the "fragile hack" the M4.3 spike avoided).
	if tag, hasTag := req.To().Params.Get("tag"); hasTag && tag != "" {
		if entry, ok := b.s.callSDP(callID(req)); ok && isRefreshReInvite(req, entry.compare) {
			// The refresh's 200 OK MUST carry a Contact (RFC 3261 §12.1.1:
			// every 2xx to INVITE does), which
			// sip.NewResponseFromRequest does not add on its own — build
			// the same per-transport Contact the leg's original 200 used,
			// from the current config and the re-INVITE's own transport
			// (req.Transport(): whichever leg sent this refresh).
			cfg := b.s.store.Current()
			transport := sip.NetworkToLower(req.Transport())
			contact := b.buildContact(b.s.ourIP(cfg), b.s.ourSigPort(cfg, transport), transport)

			res := sip.NewResponseFromRequest(req, 200, "OK", entry.answer)
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			res.AppendHeader(contact)
			res.AppendHeader(sessionExpiresHeader(headerSeconds(req, "Session-Expires"), refresherOf(req)))
			if err := tx.Respond(res); err != nil {
				b.s.log.Error("respond session-timer refresh", "err", err, "call_id", callID(req))
				b.reject(req, tx, 501, "Not Implemented")
			}
			return
		}
		b.reject(req, tx, 501, "Not Implemented")
		return
	}

	cfg := b.s.store.Current()

	// M4.3 front-door gating for INITIAL INVITEs only (the in-dialog
	// re-INVITE branch above already returned): reject anything we cannot
	// honor before Resolve/ReadInvite ever run, so neither routing nor a
	// dialog is spent on a request that's going nowhere.
	if requires100rel(req) {
		// We do not implement RFC 3262 reliable provisionals. Require:
		// 100rel mandates them, so the only correct response is 420 Bad
		// Extension with the offending option tag echoed back in
		// Unsupported (RFC 3261 §21.4.20) — responding via the raw tx,
		// same as the reject helper, since no dialog exists yet.
		res := sip.NewResponseFromRequest(req, sip.StatusBadExtension, "Bad Extension", nil)
		res.AppendHeader(sip.NewHeader("Unsupported", "100rel"))
		_ = tx.Respond(res)
		b.s.log.Info("declined Require: 100rel", "source", req.Source())
		return
	}
	if se := headerSeconds(req, "Session-Expires"); se > 0 {
		if minSE := cfg.MinSE.Std(); se < minSE {
			// sip.NewResponseFromRequest has no named constant for 422
			// (sipgo only defines the common codes) — RFC 4028 §5 defines
			// it as "422 Session Interval Too Small" with a mandatory
			// Min-SE header advertising our floor, so the caller can retry
			// with an acceptable value.
			res := sip.NewResponseFromRequest(req, 422, "Session Interval Too Small", nil)
			res.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(int(minSE.Seconds()))))
			_ = tx.Respond(res)
			b.s.log.Info("rejected low Session-Expires", "requested", se, "min_se", minSE)
			return
		}
	}

	decision, ok := Resolve(cfg, name, req.Recipient.User)
	if !ok || decision.OutNumber == "" || len(decision.Targets) == 0 {
		b.reject(req, tx, 404, "Not Found")
		return
	}

	aLeg, err := b.s.dialogSrv.ReadInvite(req, tx)
	if err != nil {
		// ReadInvite's failures are all request-shape problems (most
		// commonly sipgo.ErrDialogInviteNoContact: no Contact header —
		// see DialogUA.ReadInvite's own minimal validation) — the far
		// end's fault, not an SBC-side failure, so 400 Bad Request
		// rather than a 5xx that would misattribute the problem to us.
		b.s.log.Info("malformed invite", "err", err, "source", req.Source())
		b.reject(req, tx, 400, "Bad Request")
		return
	}
	defer aLeg.Close()

	remoteA, err := remoteMediaIP(req.Body())
	if err != nil {
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return
	}

	// A-leg SRTP negotiation (M5 Task 6): decide, from fromPeer's srtp
	// policy and what the caller actually offered, whether this leg will be
	// secure — and if so, build both SRTP contexts up front so they can be
	// installed on sess (via SetSRTP, right after Allocate below) before
	// anything Starts relaying. "required" never silently downgrades to
	// plaintext: an insecure offer against a required policy is rejected
	// here with 488, before any B-leg is even dialed. "optional" mirrors
	// whatever the caller offered; "disabled" (including any unrecognized
	// value) is always plaintext, byte-identical to pre-M5 behavior.
	aSecureOffer, aLines := offeredCrypto(req.Body())
	var aSRTP legSRTP
	switch fromPeer.SRTP {
	case "required":
		if !aSecureOffer || len(aLines) == 0 {
			_ = aLeg.Respond(488, "Not Acceptable Here", nil)
			return
		}
		aSRTP.secure = true
	case "optional":
		aSRTP.secure = aSecureOffer && len(aLines) > 0
	default: // "disabled" (config's normalized default) or anything unrecognized
		aSRTP.secure = false
	}
	if aSRTP.secure {
		sel, ok := selectCrypto(aLines)
		ourKey, keyErr := newCryptoKeyValue()
		var inbound, outbound *media.SRTPContext
		var ctxErr error
		if ok && keyErr == nil {
			inbound, ctxErr = media.NewSRTPContext(sel.suite, sel.keyValue)
		}
		if ok && keyErr == nil && ctxErr == nil {
			outbound, ctxErr = media.NewSRTPContext(sel.suite, ourKey)
		}
		if !ok || keyErr != nil || ctxErr != nil {
			// Unusable crypto (no supported suite selected, key generation
			// failed, or a malformed key rejected by NewSRTPContext) under a
			// policy that requires SRTP: treat exactly like "not secure" —
			// 488, never a silent plaintext fallback.
			_ = aLeg.Respond(488, "Not Acceptable Here", nil)
			return
		}
		aSRTP.suite = sel.suite
		aSRTP.ourKeyValue = ourKey
		aSRTP.inbound = inbound
		aSRTP.outbound = outbound
		aSRTP.tag = sel.tag

		// Non-TLS warn: SDES carries the master key in the clear inside the
		// SDP body, so negotiating it over a non-TLS signaling transport
		// leaks it to anyone who can see the signaling. We still negotiate
		// (the operator's policy said secure media is wanted; downgrading
		// behind their back would be worse), but log once per secure leg.
		if aTransport := sip.NetworkToLower(req.Transport()); aTransport != "tls" {
			b.s.log.Warn("SDES key negotiated over non-TLS signaling transport",
				"transport", aTransport, "peer", name)
		}
	}

	// Side-B's latch mode here is only a pre-first-attempt default, seeded
	// from Targets[0] because Allocate needs *some* mode before any target
	// has been dialed. dialTarget calls sess.SetLatchMode(SideB, ...) with
	// each target's own media_latch before dialing it, so the mode actually
	// in effect always matches whichever target ends up winning failover —
	// see placeCall/dialTarget for the loop.
	sess, err := b.s.pool.Allocate(media.SessionConfig{
		Latch: [2]media.LatchMode{
			media.ParseLatchMode(fromPeer.MediaLatch),
			media.ParseLatchMode(decision.Targets[0].Peer.MediaLatch),
		},
	})
	if err != nil {
		_ = aLeg.Respond(503, "Service Unavailable", nil)
		return
	}
	defer sess.Close()
	sess.SetExpectedRemote(media.SideA, remoteA)
	// Install the A-side SRTP contexts (nil/nil when plaintext) before
	// anything can Start relaying — SetSRTP must run strictly before Start,
	// and Start is only ever reached later, once the B-leg answers (see
	// processAnswerSDP), so doing this right after Allocate is always early
	// enough.
	sess.SetSRTP(media.SideA, aSRTP.inbound, aSRTP.outbound)

	ourIP := b.s.mediaIP(cfg)

	bLeg, target, aAnswer, bOffer, ok := b.placeCall(aLeg, decision.Targets, decision.OutNumber, req.Body(), ourIP, sess, aSRTP)
	if !ok {
		return // placeCall already sent the A-leg's final response.
	}
	defer bLeg.Close()

	call := callstate.Call{
		ID:            callID(req),
		FromPeer:      name,
		ToPeer:        target.Name,
		StartUnixNano: startNano(),
	}

	// killCtx is this call's admin kick-call hook (Task 1): registered
	// BEFORE the call joins the registry (KillCall looks calls up by the
	// same A-leg Call-ID /api/calls lists), so there is never a window
	// where a call is listed by /api/calls but KillCall would return false
	// for it. An orphan killer entry for a not-yet-listed call is harmless.
	// Torn down via defer no matter how this call ends — LIFO order runs
	// killCancel first and unregisterKiller second, but the order between
	// those two doesn't matter (killCancel firing on an already-unregistered
	// id, or unregistering before cancelling, are both safe) — so a kick
	// that races a natural end always finds either a live entry (fires
	// once) or none at all (KillCall returns false), never a stale one.
	killCtx, killCancel := context.WithCancel(context.Background())
	b.s.registerKiller(call.ID, killCancel)
	defer b.s.unregisterKiller(call.ID)
	defer killCancel()

	b.s.registry.Add(call)
	defer b.s.registry.Remove(call.ID)

	// Remember BOTH legs' established SDP pairs (Task 6 fix wave), keyed by
	// each leg's OWN Call-ID, so a later session-timer refresh re-INVITE on
	// EITHER leg is recognized (isRefreshReInvite, compared against
	// .compare) and answered with the SBC's own established answer for
	// THAT leg (.answer) — never the peer's offer, and never the other
	// leg's SDP. See callSDP's doc and the in-dialog branch above.
	//
	// A-leg: the caller offered req.Body(); we answered aAnswer.
	// B-leg: we offered bOffer; the carrier answered bLeg.InviteResponse.Body().
	bCallID := callID(bLeg.InviteRequest)
	b.s.sdps.set(call.ID, callSDP{compare: req.Body(), answer: aAnswer})
	b.s.sdps.set(bCallID, callSDP{compare: bLeg.InviteResponse.Body(), answer: bOffer})
	defer b.s.sdps.delete(call.ID)
	defer b.s.sdps.delete(bCallID)

	// Hold the call open until either leg ends the dialog or media goes
	// silent, tearing down whatever is left.
	select {
	case <-aLeg.Context().Done():
		byeCtx, cancel := byeContext()
		_ = bLeg.Bye(byeCtx)
		cancel()
	case <-bLeg.Context().Done():
		byeCtx, cancel := byeContext()
		_ = aLeg.Bye(byeCtx)
		cancel()
	case <-sess.Done():
		b.byeBoth(aLeg, bLeg)
	case <-killCtx.Done():
		// Admin kick-call (Task 1): neither leg initiated, so BYE both —
		// same teardown as a media-silence timeout (byeBoth), never a
		// separate path.
		b.byeBoth(aLeg, bLeg)
	}
}

// byeBoth sends an independently-5s-bounded teardown BYE to each leg (each
// Bye gets its own byeContext so a slow first Bye can't eat into the second
// leg's budget). Shared by both onInvite's natural media-silence teardown
// (sess.Done) and the admin kick-call teardown (killCtx.Done) — the same
// path, not a new one.
func (b *bridge) byeBoth(aLeg *sipgo.DialogServerSession, bLeg *sipgo.DialogClientSession) {
	aByeCtx, aCancel := byeContext()
	_ = aLeg.Bye(aByeCtx)
	aCancel()
	bByeCtx, bCancel := byeContext()
	_ = bLeg.Bye(bByeCtx)
	bCancel()
}

// byeContext bounds a teardown BYE to 5s instead of inheriting a
// possibly-cancelled call context or blocking up to Timer F (~32s) on
// context.Background(): these are best-effort teardown sends to a peer
// that may already be gone, and callers ignore the error either way.
func byeContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// failKind classifies a non-2xx dialTarget outcome so placeCall can decide
// what code the caller ultimately sees. Only failReal carries a genuine
// carrier status; failDial and failUnusable are our own synthesized codes
// and must never be allowed to clobber an earlier failReal in placeCall's
// final pick (see attemptResult and placeCall's precedence loop below).
//
// failRing (ring-timeout, our own 408) is Task 4's addition — it slots in
// here as another synthetic kind alongside failDial/failUnusable, with no
// changes needed to placeCall's failReal-precedence logic itself.
type failKind int

const (
	failDial     failKind = iota // couldn't reach the target / no usable final response → 503
	failReal                     // a genuine SIP final failure from the target → its own code
	failUnusable                 // 2xx received but unusable on our side (bad/missing SDP, ACK failure, ...) → 502
	failRing                     // this attempt's ring timer expired before the target answered → 408
)

// attemptResult is dialTarget's outcome for one target. ok is the only
// field that matters on success (a live bridge) — along with aAnswer, the
// SBC's own established A-side answer SDP for this call (Task 6 fix wave:
// placeCall/onInvite need it verbatim to answer a later A-leg session-timer
// refresh with, rather than the caller's own offer — see callSDP). On
// failure, retryable tells placeCall whether there is anything left to do:
// true means the B-leg never got past the answer (nothing committed, safe
// to try the next candidate); false means dialTarget already finished the
// call itself (bridged and responded, or answered-then-failed and already
// responded/torn down) — placeCall must stop, not send anything further.
// kind/code/reason are only meaningful when retryable is true; placeCall
// uses them solely to remember the last failReal code, for the case where
// every target is exhausted.
//
// penalize marks a result as a genuine connect failure (no response from a
// reachable endpoint / caller still present) that should cool the endpoint
// down. Only set true at true connect-failure sites; everything relying on
// the zero-value default (caller CANCEL, auth challenge, raced/stale
// response) stays false.
//
// bOffer (M5 Task 6) is the SBC's own B-side offer SDP actually sent to THIS
// target — only meaningful when ok is true. It moved from a single
// placeCall-hoisted value to a per-attempt one because each target's SRTP
// policy can differ, so the offer (plaintext vs RTP/SAVP+a=crypto) is now
// built fresh per attempt in dialTarget; placeCall reads it off the winning
// attemptResult instead of building it once itself.
type attemptResult struct {
	ok        bool
	aAnswer   []byte
	bOffer    []byte
	retryable bool
	kind      failKind
	code      int
	reason    string
	penalize  bool
}

// dialEndpoint pairs a resolved dial destination with the Target (peer) it
// came from — dialing needs the endpoint's host/port, but auth credentials,
// From/Contact, and session-timer headers still come from the peer.
type dialEndpoint struct {
	Target   Target
	Endpoint Endpoint
}

// expandTargets flattens the ordered failover Targets into the concrete
// endpoints to dial, in order: each peer is resolved (DNS SRV → priority/
// weight-ordered endpoints, or a single endpoint for an IP/host:port), and a
// register:true peer we have not registered with is skipped entirely (the
// far end has no idea who we are). Task 5: endpoints currently in cooldown
// (b.s.health, populated by placeCall's Penalize on a failDial) are skipped
// in favor of healthy ones — but only when at least one healthy endpoint
// exists; see the dial-anyway fallback below.
func (b *bridge) expandTargets(targets []Target) []dialEndpoint {
	cfg := b.s.store.Current()
	var available, cooled []dialEndpoint
	for _, t := range targets {
		// b.s.registrar is nil only in tests that build a bridge without
		// Server.Run; treat that as "no gating" rather than skipping every
		// target (mirrors the pre-M4.4 inline gate this replaces).
		if t.Peer.Register && b.s.registrar != nil && !b.s.registrar.IsRegistered(t.Name) {
			b.s.log.Debug("skipping unregistered target", "peer", t.Name)
			continue
		}
		for _, ep := range b.s.resolver.Resolve(t.Peer, cfg.SRVCacheTTL.Std()) {
			de := dialEndpoint{Target: t, Endpoint: ep}
			if b.s.health.Available(ep) {
				available = append(available, de)
			} else {
				cooled = append(cooled, de)
			}
		}
	}
	// Cooldown is a skip-if-alternatives, never a hard block: if every
	// endpoint is cooled down, dial them all anyway rather than fail the call.
	if len(available) > 0 {
		return available
	}
	return cooled
}

// placeCall is Task 8's failover loop: it validates the A-leg's offer once
// up front (a target-independent parse/no-audio check — the same offerBody
// is used on every attempt, so a malformed offer fails identically on all of
// them; see the pre-loop check below), then tries targets in order via
// dialTarget until one is bridged. The actual per-target B-leg offer is no
// longer built here (M5 Task 6): each target's SRTP policy can differ, so
// dialTarget rebuilds bOffer fresh — plaintext or RTP/SAVP+a=crypto — for
// every attempt; placeCall reads the winning attempt's bOffer off its
// attemptResult.
//
// dialTarget draws a hard line at the B-leg's answer: everything before it
// (dial failure, no/non-2xx WaitAnswer) is target-specific and safe to
// retry on the next candidate, so placeCall just remembers the failure and
// keeps going. Everything from the answer onward is a committed, billable
// carrier call — dialTarget always finishes it there itself (bridge or
// tear down + finalize the A-leg) rather than reporting a retryable
// failure, so placeCall stops the moment dialTarget reports one of those:
// there is nothing left to try (the A-leg has already gotten its final
// response, or — the RespondSDP-failure case — deliberately hasn't,
// because it's already gone).
//
// If every target is exhausted without an answer, placeCall responds the
// A-leg with the last genuine carrier code any target sent (failReal),
// falling back to 503 only if no target ever produced one — a trailing
// dial failure (no response, or a stale provisional; see dialTarget) must
// never clobber an earlier target's real code just because it happened
// last. Task 4 slots a ring timeout into this same precedence: if no target
// ever produced a real code but at least one attempt was cut short by its
// own ring timer (failRing), the caller gets 408 Request Timeout rather
// than a bare 503 — still only as a fallback behind any genuine carrier
// code, since a real (if late) carrier response is always more informative
// than our own synthesized timeout. This is the only path here that sends
// a final response itself, since it's the only one not already covered by
// rewriteSDP's own failure (488, target-independent — same offer, same
// failure, on every attempt) or dialTarget's post-answer paths.
//
// After each retryable failure, placeCall also checks whether the A-leg is
// still there (aLeg.Context().Err()) before starting the next candidate: a
// caller CANCEL/hangup mid-setup cancels that context, and without this
// check the loop would keep dialing (and waiting up to Timer B, ~32s, on)
// remaining carriers for a caller who already left.
// The bOffer return is the SBC's own B-side offer SDP (what we sent the
// winning target) — like aAnswer (see attemptResult), the caller needs it
// verbatim to answer a later B-LEG session-timer refresh with (Task 6 fix
// wave), rather than the carrier's own answer.
func (b *bridge) placeCall(aLeg *sipgo.DialogServerSession, targets []Target, outNumber string, offerBody []byte, ourIP netip.Addr, sess *media.Session, aSRTP legSRTP) (bLeg *sipgo.DialogClientSession, winner Target, aAnswer []byte, bOffer []byte, ok bool) {
	// Pre-loop validation only (the actual per-target offer, including any
	// SRTP crypto, is built fresh inside dialTarget — see its doc comment):
	// a parse/no-audio failure in offerBody is target-independent, so 488
	// here before any target is dialed rather than discovering the same
	// failure on every attempt.
	if _, err := rewriteSDP(offerBody, ourIP, sess.RTPPort(media.SideB)); err != nil {
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return nil, Target{}, nil, nil, false
	}

	cfg := b.s.store.Current()

	// startOnce is created here — not per attempt — and threaded through
	// every dialTarget call so the media session Starts exactly once for
	// the whole call: if an earlier, ultimately-failed target already sent
	// early media, its 18x may have Started the session; a later target's
	// answer still only Relatches (processAnswerSDP), never re-Starts.
	var startOnce sync.Once
	haveReal := false
	haveRing := false
	lastRealCode, lastRealReason := 0, ""
	for _, de := range b.expandTargets(targets) {
		dialedLeg, res := b.dialTarget(aLeg, de.Target, de.Endpoint, outNumber, offerBody, sess, ourIP, &startOnce, aSRTP)
		if res.ok {
			// A bridged call proves this endpoint is reachable — clear any
			// prior cooldown so it is usable immediately on the next call.
			b.s.health.Recover(de.Endpoint)
			return dialedLeg, de.Target, res.aAnswer, res.bOffer, true
		}
		if !res.retryable {
			return nil, Target{}, nil, nil, false
		}
		// Only a genuine connect failure (attemptResult.penalize) cools an
		// endpoint down; failDial is a catch-all that also covers caller
		// CANCEL, an unsatisfied auth challenge, and a raced/stale response —
		// all cases where the endpoint was demonstrably reachable, so kind
		// alone is not a safe signal here (see attemptResult's doc).
		if res.penalize {
			b.s.health.Penalize(de.Endpoint, cfg.PeerCooldown.Std())
		}
		if res.kind == failReal {
			haveReal = true
			lastRealCode, lastRealReason = res.code, res.reason
		}
		if res.kind == failRing {
			haveRing = true
		}

		// The A-leg may have gone away (caller CANCEL/hangup) while this
		// target was being dialed — dialTarget dials via aLeg.Context(), so
		// a cancelled A-leg doesn't stop the B-leg invite from going out,
		// only from being waited on indefinitely. Check here, before
		// starting the next candidate: there is no caller left to bridge to,
		// so dialing the remaining targets (each up to Timer B, ~32s) would
		// only hammer real carriers for no reason. The eventual
		// aLeg.Respond below (all-targets-exhausted path) is a harmless
		// no-op against the already-gone dialog.
		if aLeg.Context().Err() != nil {
			return nil, Target{}, nil, nil, false
		}
	}

	switch {
	case haveReal:
		_ = aLeg.Respond(lastRealCode, lastRealReason, nil)
	case haveRing:
		_ = aLeg.Respond(408, "Request Timeout", nil)
	default:
		_ = aLeg.Respond(503, "Service Unavailable", nil)
	}
	return nil, Target{}, nil, nil, false
}

// dialTarget places one B-leg to target and waits for its answer via
// WaitAnswer, passing target's digest credentials (empty strings for an
// IP-auth trunk — WaitAnswer only attempts digest when Password is
// non-empty) so a 401/407 challenge is retried transparently inside
// WaitAnswer itself; the caller never sees the intermediate challenge. If
// the retry itself is still rejected (or there was no password to retry
// with at all), the resulting 401/407 final is a hop-by-hop negotiation
// failure with THIS target, not something the caller can use — it is
// classified as failDial/503, never relayed as-is (see the WaitAnswer-error
// classification below).
//
// Two regimes, split at the B-leg's answer:
//
//   - Before it (dial error, or WaitAnswer returning any error — including
//     a non-2xx final): the B-leg never reached Established, so ordinarily
//     there is nothing to ACK or BYE, just Close (drops the local
//     dialog-cache entry only) — and nothing target-specific has committed,
//     so this is exactly what placeCall retries the next candidate on. The
//     one exception is a raced 2xx (WaitAnswer returned an error — a
//     cancelled ctx or a malformed-response DialogIDFromResponse failure —
//     while bLeg.InviteResponse nonetheless holds a genuine 2xx): that IS a
//     live, billable carrier call, so it gets a real ACK+BYE teardown
//     first, even though this is still the "before answer" branch as far
//     as placeCall's retry decision is concerned. No A-leg response is sent
//     here; retryable=true and the result's kind/code/reason (failReal with
//     the upstream status — restricted to genuine failure finals, >= 300
//     and not 401/407 — or failDial/503 for everything else: dial error,
//     timeout, CANCEL race, unsatisfied auth challenge, the raced-2xx
//     teardown, or a stale provisional left over from a dead transaction —
//     see the classification switch below) are placeCall's to use if every
//     candidate is exhausted.
//
//   - From it onward (2xx received): the B-leg is now a live, billable
//     carrier call, so dialTarget always finishes the call itself from
//     here — anchoring media and RespondSDP-ing the A-leg on success, or
//     tearing the B-leg down and finalizing the A-leg on failure — rather
//     than reporting a retryable failure. retryable=false in every path
//     past this point: a carrier that already answered is not something
//     you abandon to try a different one. These paths already send (or
//     deliberately don't send — the RespondSDP-failure case) the A-leg's
//     response themselves, so their result's kind/code/reason are only
//     documentation; placeCall never consults them once retryable is
//     false.
//
// Early media: for every 18x the B-leg sends, relayProvisional (via
// WaitAnswer's OnResponse) may reach processAnswerSDP/startOnce.Do(Start)
// before dialTarget's own post-answer processing does; both share the same
// startOnce so Start runs at most once regardless of which path wins.
//
// B-leg SRTP offer (M5 Task 6): bSecure is decided from THIS target's own
// peer policy — required always secure, disabled always plaintext, optional
// mirrors whatever the A-leg negotiated (aSRTP.secure) — never from a global
// or A-leg-only decision, since failover can hop across peers with different
// policies. When secure, the SBC offers exactly one suite (AES_CM_128_HMAC_
// SHA1_80, tag 1) with one freshly generated key: SDES lets an offer carry
// multiple a=crypto lines/suites, but doing so correctly means tracking
// which suite the answerer picked across two independent keys — offering
// suite 80 only is a documented, interop-negligible simplification (every
// SDES peer supports it). The A-leg ANSWER side has no such restriction:
// selectCrypto/parseCryptoAttrs already accept whichever supported suite the
// caller offered.
func (b *bridge) dialTarget(aLeg *sipgo.DialogServerSession, target Target, ep Endpoint, outNumber string, offerBody []byte, sess *media.Session, ourIP netip.Addr, startOnce *sync.Once, aSRTP legSRTP) (bLeg *sipgo.DialogClientSession, res attemptResult) {
	// Align SideB's latch policy with THIS target before dialing it — not
	// just whichever target happened to be Targets[0] at Allocate time — so
	// early media (relayProvisional) and the eventual answer both apply the
	// media_latch of the carrier actually being tried on this attempt. On
	// failover, a later attempt overwrites this before it arms/relays any
	// SideB traffic, so the winning target's policy is always what ends up
	// governing the session.
	sess.SetLatchMode(media.SideB, media.ParseLatchMode(target.Peer.MediaLatch))

	var bSRTP legSRTP
	switch target.Peer.SRTP {
	case "required":
		bSRTP.secure = true
		bSRTP.required = true
	case "optional":
		bSRTP.secure = aSRTP.secure
	default: // "disabled" (config's normalized default) or anything unrecognized
		bSRTP.secure = false
	}
	var bOffer []byte
	if bSRTP.secure {
		// Non-TLS warn (spec §4.5: one WARN per secure leg over non-TLS
		// signaling) — mirrors the A-leg's identical warn in onInvite. The
		// SBC is the one dialing this leg, so the transport is what WE chose
		// for this target (target.Peer.Transport, normalized to "udp" by
		// config.Parse when unset), not something read off an inbound
		// request.
		if bTransport := target.Peer.Transport; bTransport != "tls" {
			b.s.log.Warn("SDES key negotiated over non-TLS signaling transport",
				"transport", bTransport, "peer", target.Name)
		}
		bKey, err := newCryptoKeyValue()
		var outbound *media.SRTPContext
		if err == nil {
			outbound, err = media.NewSRTPContext(media.SuiteAES128CM80, bKey)
		}
		if err != nil {
			// Fresh-key generation or context construction failed (e.g. the
			// CSPRNG is unavailable) — a transient, this-attempt-only
			// problem, not the caller's or this carrier's fault: classify
			// like any other pre-dial failure so placeCall tries the next
			// candidate rather than failing the whole call.
			b.s.log.Error("build b-leg srtp context", "err", err, "target", target.Name)
			return nil, attemptResult{retryable: true, kind: failDial, code: 503, reason: "Service Unavailable"}
		}
		bSRTP.suite = media.SuiteAES128CM80
		bSRTP.ourKeyValue = bKey
		bSRTP.outbound = outbound
		rewritten, err := rewriteSDPCrypto(offerBody, ourIP, sess.RTPPort(media.SideB), &sdpCrypto{suite: bSRTP.suite, keyValue: bKey, tag: 1})
		if err != nil {
			return nil, attemptResult{retryable: true, kind: failDial, code: 503, reason: "Service Unavailable"}
		}
		bOffer = rewritten
	} else {
		// Plaintext: rewriteSDPCrypto with a nil *sdpCrypto, NOT the plain
		// rewriteSDP — offerBody is the CALLER's raw offer, which may itself
		// be RTP/SAVP+a=crypto when the A-leg is secure (e.g. optional/
		// required on fromPeer while THIS target's peer is disabled).
		// rewriteSDP only rewrites port/connection info and leaves proto and
		// attributes (including any a=crypto) untouched — using it here
		// would leak the caller's own SRTP proto/key straight through to a
		// peer whose policy says plaintext. rewriteSDPCrypto(..., nil)
		// forces RTP/AVP and strips every a=crypto line, and produces
		// byte-identical output to rewriteSDP when offerBody was already
		// plaintext (see TestBridgePlaintextUnchanged), so this is safe for
		// both cases. placeCall's pre-loop check already proved offerBody
		// parses, so this is not expected to fail here.
		rewritten, err := rewriteSDPCrypto(offerBody, ourIP, sess.RTPPort(media.SideB), nil)
		if err != nil {
			return nil, attemptResult{retryable: true, kind: failDial, code: 503, reason: "Service Unavailable"}
		}
		bOffer = rewritten
	}
	// bsrtpArg is nil for a plaintext B-leg — both relayProvisional and
	// processAnswerSDP treat a nil *legSRTP as "nothing to negotiate",
	// exactly the pre-M5 behavior.
	var bsrtpArg *legSRTP
	if bSRTP.secure {
		bsrtpArg = &bSRTP
	}

	// peerURI builds only the trunk endpoint (host/port/transport); the
	// dialed number (post-transform) is the Request-URI user part, so it
	// must be set here — without it the carrier receives an INVITE with
	// no destination number.
	bTarget := peerURI(ep)
	bTarget.User = outNumber

	cfg := b.s.store.Current()
	sigPort := b.s.ourSigPort(cfg, target.Peer.Transport)
	from := b.buildFrom(aLeg.InviteRequest, ourIP, sigPort)
	contact := b.buildContact(ourIP, sigPort, target.Peer.Transport)

	// bHeaders carries From/Contact plus the Task 4 session-timer headers,
	// all as one slice so it can be passed as Invite's variadic headers on
	// every (re-)attempt. Index 3 (Session-Expires) is the only one ever
	// rebuilt — see the 422 retry below, which replaces it with the
	// carrier's own Min-SE while leaving From/Contact/Supported/Min-SE (our
	// floor) untouched.
	bHeaders := []sip.Header{
		from,
		contact,
		sip.NewHeader("Supported", "timer"),
		sessionExpiresHeader(cfg.SessionExpires.Std(), "uas"),
		sip.NewHeader("Min-SE", strconv.Itoa(int(cfg.MinSE.Std().Seconds()))),
	}

	// retried422 bounds the loop below to AT MOST ONE retry per target
	// (Task 5): a carrier that 422s again on the retry, or 422s without a
	// usable Min-SE, falls through to the ordinary failReal classification
	// below instead of retrying indefinitely.
	retried422 := false

	for {
		var err error
		bLeg, err = b.s.dialogCli.Invite(aLeg.Context(), bTarget, bOffer, bHeaders...)
		if err != nil {
			b.s.log.Error("invite b-leg", "err", err, "target", target.Name)
			// Invite() itself failed (dial/DNS/transport error before any
			// request even went out, or went out and was synchronously
			// rejected): the endpoint never had a chance to respond — normally
			// a genuine connect failure worth cooling down. But sipgo resolves
			// a hostname/SRV endpoint using aLeg.Context() (the request is
			// dialed via that context), so a caller CANCEL/hangup can itself
			// make Invite() fail instantly here (a cancelled-context resolve
			// error) for a perfectly healthy target — e.g. a 422 retry's
			// Invite() racing a caller hangup. Gate on the same
			// aLeg.Context().Err() signal the WaitAnswer-error classification
			// below already uses, so only a genuine unreachable-host dial
			// error (caller still present) cools the endpoint down; a
			// caller-cancellation-induced Invite failure does not.
			return nil, attemptResult{retryable: true, kind: failDial, code: 503, reason: "Service Unavailable", penalize: aLeg.Context().Err() == nil}
		}

		// attemptCtx caps how long THIS target is allowed to ring before we give
		// up on it and fail over — cfg.RingTimeout, not the whole-call budget.
		// It's a child of aLeg.Context(), not context.Background(): a caller
		// CANCEL/hangup must still abort the attempt immediately rather than
		// waiting out the ring timer. Deriving from aLeg.Context() also means a
		// parent cancellation (caller gone) propagates into attemptCtx as
		// context.Canceled, while an attemptCtx-only expiry propagates as
		// context.DeadlineExceeded — that distinction is exactly how the
		// WaitAnswer-error classification below tells a caller CANCEL apart
		// from a ring timeout (see the comment there). WaitAnswer's own
		// ctx.Done() path (github.com/emiago/sipgo@v1.4.3 dialog_client.go)
		// sends the target a real CANCEL and returns ctx.Err() from
		// inviteCancel — so attemptCtx expiring both cancels the hung target on
		// the wire and gives us a reliable signal to classify on. Each loop
		// iteration (i.e. each of up to two INVITEs) gets its own attemptCtx
		// — a fresh ring-timeout budget for the retry, not a shared one.
		attemptCtx, cancel := context.WithTimeout(aLeg.Context(), cfg.RingTimeout.Std())

		// F1 fix: WaitAnswer alone cannot be trusted to honor attemptCtx.
		// When the target never sends ANY response, sipgo's WaitAnswer enters
		// inviteCancel, which — per RFC 3261 §9.1 (no CANCEL before a
		// provisional) — blocks until the target responds or the INVITE
		// transaction dies on Timer_B (~32s). A silent/blackholed target
		// would therefore pin this attempt for ~32s and ring_timeout/failover
		// would never fire. Race WaitAnswer against the deadline so the
		// per-attempt ring budget always holds; the goroutine finishes on its
		// own (CANCEL+487 once a late response arrives, or Timer_B teardown),
		// which costs nothing extra — the transaction would retransmit for
		// the same ~32s regardless.
		//
		// responded tracks whether the target answered within the ring
		// budget: the deadline path below cools the endpoint down only when
		// nothing at all was heard in time (a mere ring timeout — 180
		// received, no answer — must not penalize, same as the
		// InviteResponse==nil check in the classification path).
		var responded atomic.Bool
		var abandoned atomic.Bool
		waited := make(chan error, 1)
		relay := b.relayProvisional(aLeg, sess, ourIP, startOnce, aSRTP, bsrtpArg)
		// bLeg and attemptCtx are passed as ARGUMENTS, not captured: the
		// compiler may share the captured bLeg cell with dialTarget's return
		// slot (bLeg escapes both ways), and the deadline path's return below
		// would then race the goroutine's read of it (-race catches this as a
		// write at the return statement vs the closure's WaitAnswer call).
		// Argument copies are written once at goroutine start, so the
		// goroutine owns its values and the main flow can return freely.
		go func(bLeg *sipgo.DialogClientSession, attemptCtx context.Context) {
			err := bLeg.WaitAnswer(attemptCtx, sipgo.AnswerOptions{
				OnResponse: func(res *sip.Response) error {
					responded.Store(true)
					return relay(res)
				},
				Username: authUser(target),
				Password: authPass(target),
			})
			// A 2xx can race the deadline: inviteCancel consumes it and
			// returns an error, but the carrier now thinks the call is up —
			// tear that phantom call down here, because the main loop below
			// has already moved on and must never read InviteResponse again
			// for this attempt.
			if abandoned.Load() && bLeg.InviteResponse != nil && bLeg.InviteResponse.IsSuccess() {
				b.ackThenBye(context.Background(), bLeg, target)
			}
			waited <- err
		}(bLeg, attemptCtx)

		var waitErr error
		select {
		case waitErr = <-waited:
			// WaitAnswer returned first: classify below, exactly as before.
		case <-attemptCtx.Done():
			// The ring budget expired before WaitAnswer returned. Give the
			// goroutine a short grace to finish before abandoning the
			// attempt: it may be mid-relay of a provisional response (an
			// aLeg.Respond from OnResponse) or already in the CANCEL dance.
			// Once it delivers, classification runs on this goroutine's
			// sequential path below, so aLeg.Respond is never invoked from
			// two goroutines at once. A target that never sent ANY response
			// leaves the goroutine blocked in sipgo's inviteCancel (RFC 3261
			// §9.1 forbids CANCEL before a provisional) until the INVITE
			// transaction dies on Timer_B (~32s) — the grace expires and we
			// abandon the attempt, so ring_timeout/failover still hold (the
			// F1 fix). 250ms is far more than the relay/CANCEL dance needs;
			// in the abandoned case the goroutine never touches the A-leg
			// again (OnResponse only runs once a response arrived, and an
			// abandoned attempt means none did within the budget).
			grace := time.NewTimer(250 * time.Millisecond)
			defer grace.Stop()
			select {
			case waitErr = <-waited:
				// Delivered within the grace window: fall through to the
				// normal classification below (attemptCtx.Err() is
				// DeadlineExceeded here for a ring timeout, Canceled for a
				// caller hangup — both classified by the existing cases).
			case <-grace.C:
				abandoned.Store(true)
				cancel()
				b.s.log.Info("b-leg not answered", "err", attemptCtx.Err(), "target", target.Name)
				if attemptCtx.Err() == context.DeadlineExceeded {
					// Caller still present (else attemptCtx would carry
					// Canceled, not DeadlineExceeded — it derives from
					// aLeg.Context()).
					return nil, attemptResult{
						retryable: true,
						kind:      failRing,
						code:      408,
						reason:    "Request Timeout",
						penalize:  !responded.Load(),
					}
				}
				// Parent context cancelled: the caller is gone. Mirror the
				// aLeg.Context().Err() classification case below (zero-value
				// kind/code — nothing reaches a caller that no longer
				// exists) and never penalize: this wasn't the endpoint's
				// fault.
				return nil, attemptResult{retryable: true, kind: failDial, code: 503, reason: "Service Unavailable"}
			}
		}
		if waitErr == nil {
			cancel()
			break
		}
		b.s.log.Info("b-leg not answered", "err", waitErr, "target", target.Name)
		// bLeg.InviteResponse is set by sipgo's WaitAnswer for EVERY response
		// it sees, including 1xx provisionals — not just the final one. If
		// the transaction dies mid-ring (e.g. a transport error after a
		// 100/180, or the call context is cancelled while still ringing),
		// WaitAnswer returns an error but InviteResponse is left holding
		// that stale provisional. A 1xx can never legally be relayed as a
		// FINAL response (it would violate the SIP transaction model — see
		// placeCall, which relays a real final code, when every target is
		// exhausted), so only trust InviteResponse here when it is itself a
		// final (non-provisional) response — that's the line between a
		// genuine carrier failure (failReal, its own code) and one of our
		// own synthesized ones (failDial, 503: dial error, timeout, CANCEL
		// race, or a stale provisional).

		// Task 5: a 422 carries the carrier's Min-SE floor in a header —
		// retry THIS target once with Session-Expires raised to meet it,
		// rather than treating it as an ordinary carrier failure. A 422 is
		// a non-2xx final on an unanswered B-leg (same as any other failReal
		// candidate below), so just Close — no ACK/BYE. This must run before
		// the raced-2xx teardown and classification switch below: a 422 is
		// never a success, so neither of those apply to it.
		if !retried422 && bLeg.InviteResponse != nil && bLeg.InviteResponse.StatusCode == 422 {
			if carrierMinSE := headerSeconds(bLeg.InviteResponse, "Min-SE"); carrierMinSE > 0 {
				retried422 = true
				bLeg.Close()
				cancel()
				bHeaders[3] = sessionExpiresHeader(carrierMinSE, "uas")
				continue
			}
		}

		// InviteResponse can also hold a 2xx here: WaitAnswer returns an
		// error (ctx cancellation racing a just-arrived answer, or a
		// malformed 2xx whose DialogIDFromResponse failed) while the
		// carrier has already answered for real. That answer is a live,
		// billable carrier call the carrier now thinks is up — it is
		// classified below, but first (Fix 1) it must be torn down with a
		// real ACK+BYE rather than silently abandoned to ring up ~32s of
		// carrier billing for a call nobody is using.
		res := attemptResult{retryable: true, kind: failDial, code: 503, reason: "Service Unavailable"}
		// The endpoint sent NOTHING at all (no provisional, no final — not
		// even a stale one left over from a dead transaction) and the caller
		// is still present: this is our own ring-timeout or a transport
		// failure with no signal that the endpoint is reachable, which is
		// exactly the genuine-connect-failure case that should cool the
		// endpoint down. This condition is deliberately narrower than
		// "kind == failDial": it excludes the caller-CANCEL case
		// (aLeg.Context().Err() != nil, handled below) and every case where
		// InviteResponse is non-nil — a raced/stale 2xx or provisional, or an
		// unsatisfied 401/407 challenge — all of which prove the endpoint
		// DID respond and so must not be penalized.
		if bLeg.InviteResponse == nil && aLeg.Context().Err() == nil {
			res.penalize = true
		}

		// A target can answer 200 in the window between our CANCEL and its
		// arrival (caller hangup, ring timeout, or a malformed 2xx). This
		// runs UNCONDITIONALLY, above the classification switch below,
		// because the switch's cases are mutually exclusive: if the caller
		// also CANCELed in that same window (the common "impatient caller
		// hangs up as the callee picks up" case), aLeg.Context().Err() != nil
		// is ALSO true, and that case would otherwise win and skip teardown
		// entirely — leaving a live carrier call nobody tears down for
		// ~32s. Tear the phantom call down with ACK+BYE before classifying,
		// regardless of which case ends up classifying the attempt.
		// context.Background() rather than aLeg.Context(): the A-leg's
		// context may already be cancelled (the caller-CANCEL case above),
		// and this is best-effort teardown independent of the A-leg's fate
		// either way; ackThenBye bounds its own BYE via byeContext's 5s.
		if bLeg.InviteResponse != nil && bLeg.InviteResponse.IsSuccess() {
			b.ackThenBye(context.Background(), bLeg, target)
		}
		switch {
		case aLeg.Context().Err() != nil:
			// The A-leg itself is gone (caller CANCEL/hangup): placeCall's
			// own aLeg.Context().Err() check, right after this return, stops
			// the failover loop before trying another target. The exact
			// kind/code here never reaches the caller (there is no caller
			// left to respond to), so failDial's zero-value default is fine
			// — the important thing is NOT to misclassify this as failRing,
			// which would be a lie (nothing "timed out"; the caller left).

		case bLeg.InviteResponse != nil && bLeg.InviteResponse.IsSuccess():
			// Raced 2xx (see the comment above the switch — teardown already
			// ran there, unconditionally). This 2xx must never be relayed to
			// the caller as a success (dialTarget already returned
			// retryable=true; the caller only ever sees the eventual
			// classification below) or counted as failReal (it isn't a
			// failure); it classifies exactly like any other outcome on
			// this attempt — failRing if the ring deadline had already
			// expired, failDial/503 otherwise.
			if attemptCtx.Err() == context.DeadlineExceeded {
				res.kind = failRing
				res.code = 408
				res.reason = "Request Timeout"
			}

		case attemptCtx.Err() == context.DeadlineExceeded:
			// aLeg.Context() is still live (checked above) but the
			// PER-ATTEMPT deadline fired: this target simply rang too long.
			// WaitAnswer already sent it a CANCEL (see attemptCtx's comment
			// above) — placeCall fails over to the next target.
			res.kind = failRing
			res.code = 408
			res.reason = "Request Timeout"

		case bLeg.InviteResponse != nil &&
			bLeg.InviteResponse.StatusCode >= 300 &&
			bLeg.InviteResponse.StatusCode != sip.StatusUnauthorized &&
			bLeg.InviteResponse.StatusCode != sip.StatusProxyAuthRequired:
			// A genuine carrier failure final (>=300), excluding 401/407:
			// those are hop-by-hop challenges, handled in the case below,
			// never a code the caller could act on. A second/unusable 422
			// (retried422 already true, or no usable Min-SE) lands here too
			// — 422 >= 300 and isn't 401/407 — and is reported as failReal
			// with its own code, same as any other genuine carrier decline.
			res.kind = failReal
			res.code = bLeg.InviteResponse.StatusCode
			res.reason = bLeg.InviteResponse.Reason

		case bLeg.InviteResponse != nil &&
			(bLeg.InviteResponse.StatusCode == sip.StatusUnauthorized || bLeg.InviteResponse.StatusCode == sip.StatusProxyAuthRequired):
			// The target challenged and we couldn't (or didn't) satisfy it:
			// WaitAnswer only attempts its own digest retry when
			// opts.Password is non-empty (see authUser/authPass) — an
			// IP-auth trunk that unexpectedly challenges, or a retry whose
			// credentials the target still rejects, ends up here. A 401/407
			// is a negotiation with THIS target, not something the caller
			// can use, so it stays failDial's default 503 rather than
			// leaking the challenge upstream as a bogus 401/407.
			b.s.log.Debug("b-leg auth challenge unsatisfied", "code", bLeg.InviteResponse.StatusCode, "target", target.Name)
		}
		cancel()
		_ = bLeg.Close()
		return nil, res
	}

	// Past this point the B-leg is answered (2xx): a live, billable carrier
	// call. Every remaining path is terminal (retryable=false).
	// Both failures below are POST-answer: the carrier already sent a 2xx,
	// so the offer we sent it was fine — it's the carrier's ANSWER SDP that
	// is missing/unparseable (processAnswerSDP) or that failed to rewrite
	// (rewriteSDP). 488 would wrongly tell the caller ITS OWN offer was
	// unacceptable; 502 Bad Gateway correctly attributes the failure to the
	// upstream leg (spec §6). This is distinct from placeCall's PRE-answer
	// 488 (rewriteSDP of the caller's own offer, before any target is even
	// dialed), which stays 488 — that one really is about the caller's
	// offer.
	answer := bLeg.InviteResponse.Body()
	if err := processAnswerSDP(sess, answer, media.SideB, startOnce, bsrtpArg); err != nil {
		if errors.Is(err, errSRTPRequiredMismatch) {
			// The carrier answered for real (2xx, billable) but its answer
			// doesn't meet our required-SRTP policy for this target: unlike
			// a malformed/unparseable answer (a genuine, terminal carrier
			// failure — see the non-SRTP branch below), this is retryable.
			// The carrier is reachable, it's just unusable under policy, so
			// tear this attempt down and let placeCall try the next
			// candidate rather than finalizing the call with 502. "required"
			// never silently downgrades to plaintext.
			b.s.log.Info("b-leg srtp required by policy but answer not secure", "target", target.Name)
			b.ackThenBye(aLeg.Context(), bLeg, target)
			return nil, attemptResult{retryable: true, kind: failUnusable, code: 502, reason: "Bad Gateway"}
		}
		// Respond the A-leg before tearing the B-leg down: ackThenBye is a
		// network round trip bounded by byeContext's 5s, and there's no
		// reason to hold the caller's final response hostage behind it.
		_ = aLeg.Respond(502, "Bad Gateway", nil)
		b.ackThenBye(aLeg.Context(), bLeg, target)
		return nil, attemptResult{kind: failUnusable, code: 502, reason: "Bad Gateway"}
	}

	// A-leg answer crypto (M5 Task 6): when the A-leg is secure, advertise
	// the SBC's OWN A-outbound key (aSRTP.ourKeyValue) in the answer — the
	// caller encrypts toward us with the key it offered (already used to
	// build aSRTP.inbound in onInvite), and decrypts what we send it with
	// whatever key WE advertise here, i.e. what WE encrypt with
	// (aSRTP.outbound). The caller's own key is never echoed back.
	var aAnswer []byte
	var err error
	if aSRTP.secure {
		aAnswer, err = rewriteSDPCrypto(answer, ourIP, sess.RTPPort(media.SideA), &sdpCrypto{suite: aSRTP.suite, keyValue: aSRTP.ourKeyValue, tag: aSRTP.tag})
	} else {
		// Plaintext A-leg: rewriteSDPCrypto with a nil *sdpCrypto, NOT the
		// plain rewriteSDP — answer is the B-LEG's (carrier's) raw answer,
		// which may itself be RTP/SAVP+a=crypto when the B-leg is secure
		// (e.g. this target's peer is srtp: required/optional while the
		// A-leg is disabled). rewriteSDP only rewrites port/connection info
		// and leaves proto and attributes (including any a=crypto) untouched
		// — using it here would leak the CARRIER's own SRTP master key, and
		// advertise RTP/SAVP, straight through to a plaintext caller (a
		// critical key leak; see TestBridgeSRTPInterworksPlaintextAToSecureB).
		// rewriteSDPCrypto(..., nil) forces RTP/AVP and strips every
		// a=crypto line, and produces byte-identical output to rewriteSDP
		// when answer was already plaintext (see TestBridgePlaintextUnchanged),
		// so this is safe for both cases.
		aAnswer, err = rewriteSDPCrypto(answer, ourIP, sess.RTPPort(media.SideA), nil)
	}
	if err != nil {
		_ = aLeg.Respond(502, "Bad Gateway", nil)
		b.ackThenBye(aLeg.Context(), bLeg, target)
		return nil, attemptResult{kind: failUnusable, code: 502, reason: "Bad Gateway"}
	}

	if err := bLeg.Ack(aLeg.Context()); err != nil {
		// ACK could not be sent: the dialog never reaches Confirmed, so
		// Bye would refuse it too — nothing left to do but Close and tell
		// the A-leg the call failed.
		b.s.log.Error("ack b-leg", "err", err, "target", target.Name)
		_ = bLeg.Close()
		_ = aLeg.Respond(502, "Bad Gateway", nil)
		return nil, attemptResult{kind: failUnusable, code: 502, reason: "Bad Gateway"}
	}
	// The establishing 2xx carries a Contact built for the A-leg's actual
	// inbound transport (spec §5), not necessarily the dialog cache's
	// default (built once in Run from the FIRST configured listener) — so
	// a caller on a secondary transport (e.g. tcp when udp is listeners[0])
	// still gets back a Contact that routes its next in-dialog request
	// (re-INVITE, BYE) to the listener that's actually reachable for that
	// transport. sip.NewSDPResponseFromRequest (what RespondSDP wraps) does
	// nothing beyond NewResponseFromRequest + a Content-Type header — no
	// other dialog-critical work — so Respond here is exactly equivalent
	// modulo the extra Contact header, which cleanly overrides the cache's
	// default: DialogServerSession.WriteResponse only appends its own
	// ContactHDR when the response doesn't already carry one
	// (res.Contact() == nil), and res.Contact() finds ours by header name
	// regardless of when it was appended (see sip/headers.go).
	//
	// RespondSDP blocks until the A-leg ACK arrives (sipgo retransmits the
	// 2xx up to 64*T1 otherwise); onAck routes it to dialogSrv.ReadAck.
	// Respond blocks identically (same WriteResponse underneath).
	aTransport := sip.NetworkToLower(aLeg.InviteRequest.Transport())
	aContact := b.buildContact(ourIP, b.s.ourSigPort(cfg, aTransport), aTransport)
	negotiatedSE := negotiateSE(
		headerSeconds(aLeg.InviteRequest, "Session-Expires"),
		headerSeconds(aLeg.InviteRequest, "Min-SE"),
		cfg.SessionExpires.Std(), cfg.MinSE.Std())
	if err := aLeg.Respond(200, "OK", aAnswer,
		sip.NewHeader("Content-Type", "application/sdp"), aContact,
		sessionExpiresHeader(negotiatedSE, "uac"),
		sip.NewHeader("Supported", "timer")); err != nil {
		// The B-leg is already Acked/Confirmed here, so it's a live carrier
		// call; the A-leg answer attempt itself failed (typically the
		// caller CANCELed), so there is no A-leg response to send — only
		// tear the carrier call down.
		b.s.log.Error("respond a-leg", "err", err)
		byeCtx, cancel := byeContext()
		_ = bLeg.Bye(byeCtx)
		cancel()
		return nil, attemptResult{kind: failUnusable}
	}

	return bLeg, attemptResult{ok: true, aAnswer: aAnswer, bOffer: bOffer}
}

// buildFrom clones the caller's identity onto a B-leg From: the caller's
// user and display name (CLI pass-through, closing the M3.3 blocker where
// the B-leg went out as sipgo's synthesized "From: sipgo@localhost") with
// our own host (topology hiding — the caller's address is never exposed to
// the target) and a fresh local tag, since this From establishes a brand
// new dialog to the target rather than reusing the A-leg's.
func (b *bridge) buildFrom(req *sip.Request, ourIP netip.Addr, port int) *sip.FromHeader {
	caller := req.From()
	params := sip.NewParams()
	params.Add("tag", freshTag())
	return &sip.FromHeader{
		DisplayName: caller.DisplayName,
		Address: sip.Uri{
			Scheme: "sip",
			User:   caller.Address.User,
			Host:   ourIP.String(),
			Port:   port,
		},
		Params: params,
	}
}

// buildContact advertises our address for the given transport so in-dialog
// requests (re-INVITE, BYE, ...) from the target reach us on the right leg.
// UDP is SIP's default transport per RFC 3261 §19.1.2, so the transport
// param is omitted for udp; only tcp and tls carry an explicit transport=
// to ensure the target dials us back on the same non-default transport.
func (b *bridge) buildContact(ourIP netip.Addr, port int, transport string) *sip.ContactHeader {
	c := &sip.ContactHeader{
		Address: sip.Uri{Scheme: "sip", Host: ourIP.String(), Port: port},
	}
	if transport != "" && transport != "udp" {
		params := sip.NewParams()
		params.Add("transport", transport)
		c.Address.UriParams = params
	}
	return c
}

// freshTag returns a random 24-hex-char (12-byte) dialog tag, generated with
// crypto/rand rather than sipgo's own sip.GenerateTagN (which the client's
// clientRequestBuildReq path uses internally when it synthesizes a From) —
// this bridge always supplies its own From/tag explicitly, so it needs its
// own generator rather than depending on that unexported-path behavior.
func freshTag() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing is effectively unrecoverable (the OS CSPRNG
		// is unavailable); a time-varying fallback keeps call setup from
		// panicking while ensuring distinct tags across calls even if the
		// CSPRNG fails repeatedly.
		return "freesbc-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}

// authUser and authPass return target's outbound digest credentials, or
// empty strings when Peer.Auth is nil (an IP-auth trunk) — WaitAnswer only
// attempts a 401/407 digest retry when Password is non-empty, so an empty
// pair is exactly "don't authenticate," not a credential to send.
func authUser(target Target) string {
	if target.Peer.Auth == nil {
		return ""
	}
	return target.Peer.Auth.Username
}

func authPass(target Target) string {
	if target.Peer.Auth == nil {
		return ""
	}
	return target.Peer.Auth.Password
}

// relayProvisional builds dialTarget's WaitAnswer OnResponse callback: it
// fires for every response the B-leg sends, including the eventual final
// one, but only acts on provisionals (18x) — the final response is handled
// by dialTarget itself once WaitAnswer returns. For a provisional
// carrying an SDP body (early media) it arms the B-side and rewrites the
// SDP to the A-side port, sharing processAnswerSDP with the 2xx path so
// Start runs exactly once regardless of which path reaches it first; for a
// provisional with no body it relays status only. Errors processing the
// SDP fall back to a status-only relay rather than failing the call — early
// media is a courtesy, not something worth tearing down the dialog over.
// The returned callback always returns nil: WaitAnswer aborts on a non-nil
// error, which must never happen here.
//
// aSRTP/bsrtp (M5 Task 6) mirror dialTarget's own negotiated state, so the
// SDP relayed in early media is crypto-consistent with what the eventual
// final answer will carry: bsrtp (nil when B is plaintext) drives
// processAnswerSDP's B-inbound install exactly like the final-200 path, and
// aSRTP drives whether the rewritten body relayed to the caller is
// RTP/SAVP+a=crypto (our A-outbound key) or plain RTP/AVP.
func (b *bridge) relayProvisional(aLeg *sipgo.DialogServerSession, sess *media.Session, ourIP netip.Addr, startOnce *sync.Once, aSRTP legSRTP, bsrtp *legSRTP) func(res *sip.Response) error {
	return func(res *sip.Response) error {
		if !res.IsProvisional() {
			return nil
		}

		// 100 Trying is hop-by-hop; each transaction emits its own (sipgo's
		// A-leg server tx auto-generates one). Never forward the B-leg's 100 —
		// doing so double-100s the caller. Only 18x (ringing/session progress)
		// carry end-to-end meaning worth relaying.
		if res.StatusCode <= 100 {
			return nil
		}

		var (
			body    []byte
			headers []sip.Header
		)
		if raw := res.Body(); len(raw) > 0 {
			if err := processAnswerSDP(sess, raw, media.SideB, startOnce, bsrtp); err != nil {
				b.s.log.Error("early media sdp", "err", err, "code", res.StatusCode)
			} else {
				var rewritten []byte
				var err error
				if aSRTP.secure {
					rewritten, err = rewriteSDPCrypto(raw, ourIP, sess.RTPPort(media.SideA), &sdpCrypto{suite: aSRTP.suite, keyValue: aSRTP.ourKeyValue, tag: aSRTP.tag})
				} else {
					// Same C1 fix as dialTarget's final-200 path: raw is the
					// B-leg's early-media SDP, which may carry the carrier's
					// own a=crypto — rewriteSDPCrypto(..., nil) strips it and
					// forces RTP/AVP instead of leaking it through plain
					// rewriteSDP to a plaintext caller.
					rewritten, err = rewriteSDPCrypto(raw, ourIP, sess.RTPPort(media.SideA), nil)
				}
				if err != nil {
					b.s.log.Error("early media rewrite", "err", err, "code", res.StatusCode)
				} else {
					body = rewritten
					headers = []sip.Header{sip.NewHeader("Content-Type", "application/sdp")}
				}
			}
		}
		if err := aLeg.Respond(res.StatusCode, res.Reason, body, headers...); err != nil {
			b.s.log.Error("relay provisional", "err", err, "code", res.StatusCode)
		}
		return nil
	}
}

// processAnswerSDP arms sess's side latch to the media address carried in
// answer and, the first time it's called across either the early-media
// (18x) or final (2xx) path — whichever reaches it first — Starts the
// relay loops, guarded by startOnce so Start runs exactly once per session
// even though both paths call this. Returns the remoteMediaIP parse error
// unchanged so callers can decide how to fail (early media falls back to a
// status-only relay; the final path rejects the call).
//
// bsrtp (M5 Task 6) is the B-leg's offer-side SRTP state — nil when B is
// plaintext. When non-nil and secure, the ANSWER's own crypto is parsed (the
// peer's advertised key is what THEY encrypt with, so it becomes our
// inbound/decrypt context) and, when it's usable, sess.SetSRTP installs both
// contexts for side BEFORE Relatch/Start below — SetSRTP must always run
// strictly before this call's own startOnce.Do(sess.Start), so a fresh
// Session never Starts with a partially-installed side; on an already-Started
// Session (a later failover target's answer, or an early-media path racing
// the final one) SetSRTP's atomic.Pointer fields make the same call race-free
// against the running relay loops (see media.Session.SetSRTP's own doc).
//
// sess.SetSRTP(side, nil, nil) is ALWAYS called for a plaintext outcome —
// bsrtp nil, or bsrtp secure but the answer has no usable/matching crypto and
// isn't required — never merely skipped. This matters across B-leg failover:
// sess/startOnce are shared for the whole call (see placeCall), so an
// EARLIER target's early media (18x) can have already installed secure B
// contexts via this same function before a LATER, plaintext-answering target
// wins; without an explicit clear here the later target's plaintext packets
// would still be run through the stale SRTP contexts and fail
// unprotectRTP/protectRTP, silently going dead (Finding I1).
//
// Whether an unusable/mismatched answer fails the attempt or bridges
// plaintext depends on bsrtp.required AND on what the peer actually
// answered (Finding I2, sharpened by the M5 final-review Finding 4): a
// "required" leg (peer configured srtp: required) never silently
// downgrades — it's reported via errSRTPRequiredMismatch so dialTarget can
// fail over instead of bridging where policy demanded encryption. An
// "optional" leg (peer configured srtp: optional, secure=true only because
// the A-leg happened to be secure) bridges plaintext instead, per spec:
// "SRTP if the peer accepts, else plaintext" — but ONLY when the peer
// actually answered plaintext (RTP/AVP). If an "optional" peer answered
// RTP/SAVP (committed to SRTP in the SDP protocol field) with an unusable or
// mismatched suite, bridging "plaintext" would mean forwarding the peer's
// still-SRTP-protected bytes as if they were plain RTP — garbage audio, not
// a graceful downgrade — so that case fails over exactly like "required"
// does (answerSecure is part of the failure condition below, not just
// bsrtp.required). An answer whose crypto suite doesn't match what we
// offered (Finding M1 — we offer suite 80 only; a carrier answering suite 32
// would otherwise give one-way audio, decrypting with 32 while encrypting
// with 80) is treated identically to "no usable crypto".
func processAnswerSDP(sess *media.Session, answer []byte, side media.Side, startOnce *sync.Once, bsrtp *legSRTP) error {
	remote, err := remoteMediaIP(answer)
	if err != nil {
		return err
	}
	switch {
	case bsrtp == nil:
		sess.SetSRTP(side, nil, nil)
	case !bsrtp.secure:
		sess.SetSRTP(side, nil, nil)
	default:
		answerSecure, lines := offeredCrypto(answer)
		sel, ok := selectCrypto(lines)
		usable := answerSecure && ok && sel.suite == bsrtp.suite
		switch {
		case usable:
			inbound, err := media.NewSRTPContext(sel.suite, sel.keyValue)
			if err != nil {
				return fmt.Errorf("srtp answer key: %w", err)
			}
			sess.SetSRTP(side, inbound, bsrtp.outbound)
		case bsrtp.required || answerSecure:
			// Either policy demanded SRTP, or the peer committed to SAVP
			// with an unusable/mismatched suite — bridging plaintext here
			// would forward the peer's still-protected SRTP as garbage, not
			// a graceful downgrade. Fail over instead.
			return errSRTPRequiredMismatch
		default:
			// optional AND the peer answered plain RTP/AVP: bridge as
			// plaintext rather than fail the call.
			sess.SetSRTP(side, nil, nil)
		}
	}
	sess.Relatch(side, remote)
	startOnce.Do(sess.Start)
	return nil
}

// ackThenBye tears down a B-leg that has been answered (2xx received) but
// not yet ACKed: DialogClientSession.Bye refuses to send on a dialog that
// isn't Confirmed, so this Acks first (best-effort) and only then Byes
// (also best-effort) — both errors are logged, not returned, since the
// caller has already decided to abandon this bLeg regardless.
func (b *bridge) ackThenBye(ctx context.Context, bLeg *sipgo.DialogClientSession, target Target) {
	if err := bLeg.Ack(ctx); err != nil {
		b.s.log.Error("ack b-leg for teardown", "err", err, "target", target.Name)
		_ = bLeg.Close()
		return
	}
	byeCtx, cancel := byeContext()
	defer cancel()
	if err := bLeg.Bye(byeCtx); err != nil {
		b.s.log.Error("bye b-leg for teardown", "err", err, "target", target.Name)
	}
}

// reject answers an INVITE we will not bridge, before any dialog is created.
func (b *bridge) reject(req *sip.Request, tx sip.ServerTransaction, code int, reason string) {
	_ = tx.Respond(sip.NewResponseFromRequest(req, code, reason, nil))
	b.s.log.Info("rejected invite", "code", code, "reason", reason, "source", req.Source())
}

// recoverCall is deferred first thing in onInvite: a panic anywhere in the
// call setup or bridging path kills only this call (never the process),
// leaving a forensic trace. The function's own defers (aLeg/bLeg/sess
// Close, registry.Remove) still run during the panic unwind, since defer
// execution isn't short-circuited by recover — this only stops the crash
// from propagating past onInvite.
func (b *bridge) recoverCall(req *sip.Request) {
	if r := recover(); r != nil {
		b.s.log.Error("bridge call panic; call dropped",
			"panic", r, "stack", string(debug.Stack()), "call_id", callID(req))
	}
}

// callID returns the A-leg's Call-ID, or "" if the request is malformed
// enough to lack one (should not happen past ReadInvite's validation).
func callID(req *sip.Request) string {
	if cid := req.CallID(); cid != nil {
		return cid.Value()
	}
	return ""
}

// startNano is wall-clock time for callstate.Call.StartUnixNano.
func startNano() int64 { return time.Now().UnixNano() }

// peerURI builds the sip.Uri sipgo needs to dial a resolved endpoint
// (host/port/transport). The dialed number is set separately as the
// Request-URI user part by the caller.
func peerURI(ep Endpoint) sip.Uri {
	transport := ep.Transport
	if transport == "" {
		transport = "udp"
	}
	params := sip.NewParams()
	params.Add("transport", transport)
	return sip.Uri{
		Scheme:    "sip",
		Host:      ep.Host,
		Port:      ep.Port,
		UriParams: params,
	}
}
