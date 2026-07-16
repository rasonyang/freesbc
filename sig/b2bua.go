package sig

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/callstate"
	"github.com/freesbc/freesbc/config"
	"github.com/freesbc/freesbc/media"
)

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
	// refresh, ...) vs. initial INVITE is distinguished by the To-tag: an
	// initial INVITE never carries one (RFC 3261 §8.1.1.2), an in-dialog
	// INVITE always does (it's the tag the dialog was established with).
	//
	// sipgo v1.4.3's DialogServerSession.ReadInvite is single-use: calling
	// it again for a re-INVITE on an already-established dialog corrupts
	// that dialog's To-tag rather than answering the renegotiation. Rather
	// than risk that corruption, reject the re-INVITE here — before ever
	// touching dialogSrv — with 501 Not Implemented on the raw server
	// transaction. Per RFC 3261 §14.1, a failed re-INVITE does not
	// terminate the dialog, so the established call stays up with its
	// existing media; the caller/target simply can't renegotiate it. Mid-
	// dialog renegotiation support is deferred to M4.
	if tag, hasTag := req.To().Params.Get("tag"); hasTag && tag != "" {
		b.reject(req, tx, 501, "Not Implemented")
		return
	}

	cfg := b.s.store.Current()
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

	ourIP := b.s.mediaIP(cfg)

	bLeg, target, ok := b.placeCall(aLeg, decision.Targets, decision.OutNumber, req.Body(), ourIP, sess)
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
	b.s.registry.Add(call)
	defer b.s.registry.Remove(call.ID)

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
		// Each Bye gets its own bounded context: sharing one byeContext
		// across both would let a slow first Bye (up to its full 5s) eat
		// into the second leg's budget instead of each being independently
		// bounded to 5s.
		aByeCtx, aCancel := byeContext()
		_ = aLeg.Bye(aByeCtx)
		aCancel()
		bByeCtx, bCancel := byeContext()
		_ = bLeg.Bye(bByeCtx)
		bCancel()
	}
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
	failUnusable                 // 2xx received but unusable on our side (bad/missing SDP, ACK failure, ...) → 488/502
	failRing                     // this attempt's ring timer expired before the target answered → 408
)

// attemptResult is dialTarget's outcome for one target. ok is the only
// field that matters on success (a live bridge). On failure, retryable
// tells placeCall whether there is anything left to do: true means the
// B-leg never got past the answer (nothing committed, safe to try the next
// candidate); false means dialTarget already finished the call itself
// (bridged and responded, or answered-then-failed and already
// responded/torn down) — placeCall must stop, not send anything further.
// kind/code/reason are only meaningful when retryable is true; placeCall
// uses them solely to remember the last failReal code, for the case where
// every target is exhausted.
type attemptResult struct {
	ok        bool
	retryable bool
	kind      failKind
	code      int
	reason    string
}

// placeCall is Task 8's failover loop: it rewrites the A-leg's offer to
// sess's stable B-side port once — that rewrite depends only on sess's own
// ports and ourIP, neither of which changes across attempts, so it's
// hoisted out of the per-target dialTarget below — then tries targets in
// order via dialTarget until one is bridged.
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
func (b *bridge) placeCall(aLeg *sipgo.DialogServerSession, targets []Target, outNumber string, offerBody []byte, ourIP netip.Addr, sess *media.Session) (*sipgo.DialogClientSession, Target, bool) {
	bOffer, err := rewriteSDP(offerBody, ourIP, sess.RTPPort(media.SideB))
	if err != nil {
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return nil, Target{}, false
	}

	// startOnce is created here — not per attempt — and threaded through
	// every dialTarget call so the media session Starts exactly once for
	// the whole call: if an earlier, ultimately-failed target already sent
	// early media, its 18x may have Started the session; a later target's
	// answer still only Relatches (processAnswerSDP), never re-Starts.
	var startOnce sync.Once
	haveReal := false
	haveRing := false
	lastRealCode, lastRealReason := 0, ""
	for _, target := range targets {
		bLeg, res := b.dialTarget(aLeg, target, outNumber, bOffer, sess, ourIP, &startOnce)
		if res.ok {
			return bLeg, target, true
		}
		if !res.retryable {
			return nil, Target{}, false
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
			return nil, Target{}, false
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
	return nil, Target{}, false
}

// dialTarget places one B-leg to target and waits for its answer via
// WaitAnswer, passing target's digest credentials (empty strings for an
// IP-auth trunk — WaitAnswer only attempts digest when Password is
// non-empty) so a 401/407 challenge is retried transparently inside
// WaitAnswer itself; the caller never sees the intermediate challenge.
//
// Two regimes, split at the B-leg's answer:
//
//   - Before it (dial error, or WaitAnswer returning any error — including
//     a non-2xx final): the B-leg never reached Established, so there is
//     nothing to ACK or BYE, just Close (drops the local dialog-cache
//     entry only) — and nothing target-specific has committed, so this is
//     exactly what placeCall retries the next candidate on. No A-leg
//     response is sent here; retryable=true and the result's kind/code/
//     reason (failReal with the upstream status, or failDial/503 when no
//     real final was received — dial error, timeout, CANCEL race, or a
//     stale provisional left over from a dead transaction — see the
//     InviteResponse guard below) are placeCall's to use if every
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
func (b *bridge) dialTarget(aLeg *sipgo.DialogServerSession, target Target, outNumber string, bOffer []byte, sess *media.Session, ourIP netip.Addr, startOnce *sync.Once) (bLeg *sipgo.DialogClientSession, res attemptResult) {
	// Align SideB's latch policy with THIS target before dialing it — not
	// just whichever target happened to be Targets[0] at Allocate time — so
	// early media (relayProvisional) and the eventual answer both apply the
	// media_latch of the carrier actually being tried on this attempt. On
	// failover, a later attempt overwrites this before it arms/relays any
	// SideB traffic, so the winning target's policy is always what ends up
	// governing the session.
	sess.SetLatchMode(media.SideB, media.ParseLatchMode(target.Peer.MediaLatch))

	// peerURI builds only the trunk endpoint (host/port/transport); the
	// dialed number (post-transform) is the Request-URI user part, so it
	// must be set here — without it the carrier receives an INVITE with
	// no destination number.
	bTarget := peerURI(target.Peer)
	bTarget.User = outNumber

	cfg := b.s.store.Current()
	sigPort := b.s.ourSigPort(cfg, target.Peer.Transport)
	from := b.buildFrom(aLeg.InviteRequest, ourIP, sigPort)
	contact := b.buildContact(ourIP, sigPort, target.Peer.Transport)

	bLeg, err := b.s.dialogCli.Invite(aLeg.Context(), bTarget, bOffer, from, contact)
	if err != nil {
		b.s.log.Error("invite b-leg", "err", err, "target", target.Name)
		return nil, attemptResult{retryable: true, kind: failDial, code: 503, reason: "Service Unavailable"}
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
	// the wire and gives us a reliable signal to classify on.
	attemptCtx, cancel := context.WithTimeout(aLeg.Context(), cfg.RingTimeout.Std())
	defer cancel()

	if err := bLeg.WaitAnswer(attemptCtx, sipgo.AnswerOptions{
		OnResponse: b.relayProvisional(aLeg, sess, ourIP, startOnce),
		Username:   authUser(target),
		Password:   authPass(target),
	}); err != nil {
		b.s.log.Info("b-leg not answered", "err", err, "target", target.Name)
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
		res := attemptResult{retryable: true, kind: failDial, code: 503, reason: "Service Unavailable"}
		switch {
		case aLeg.Context().Err() != nil:
			// The A-leg itself is gone (caller CANCEL/hangup): placeCall's
			// own aLeg.Context().Err() check, right after this return, stops
			// the failover loop before trying another target. The exact
			// kind/code here never reaches the caller (there is no caller
			// left to respond to), so failDial's zero-value default is fine
			// — the important thing is NOT to misclassify this as failRing,
			// which would be a lie (nothing "timed out"; the caller left).
		case attemptCtx.Err() == context.DeadlineExceeded:
			// aLeg.Context() is still live (checked above) but the
			// PER-ATTEMPT deadline fired: this target simply rang too long.
			// WaitAnswer already sent it a CANCEL (see attemptCtx's comment
			// above) — placeCall fails over to the next target.
			res.kind = failRing
			res.code = 408
			res.reason = "Request Timeout"
		case bLeg.InviteResponse != nil && !bLeg.InviteResponse.IsProvisional():
			res.kind = failReal
			res.code = bLeg.InviteResponse.StatusCode
			res.reason = bLeg.InviteResponse.Reason
		}
		_ = bLeg.Close()
		return nil, res
	}

	// Past this point the B-leg is answered (2xx): a live, billable carrier
	// call. Every remaining path is terminal (retryable=false).
	answer := bLeg.InviteResponse.Body()
	if err := processAnswerSDP(sess, answer, media.SideB, startOnce); err != nil {
		// Respond the A-leg before tearing the B-leg down: ackThenBye is a
		// network round trip bounded by byeContext's 5s, and there's no
		// reason to hold the caller's final response hostage behind it.
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		b.ackThenBye(aLeg.Context(), bLeg, target)
		return nil, attemptResult{kind: failUnusable, code: 488, reason: "Not Acceptable Here"}
	}

	aAnswer, err := rewriteSDP(answer, ourIP, sess.RTPPort(media.SideA))
	if err != nil {
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		b.ackThenBye(aLeg.Context(), bLeg, target)
		return nil, attemptResult{kind: failUnusable, code: 488, reason: "Not Acceptable Here"}
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
	if err := aLeg.Respond(200, "OK", aAnswer,
		sip.NewHeader("Content-Type", "application/sdp"), aContact); err != nil {
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

	return bLeg, attemptResult{ok: true}
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
func (b *bridge) relayProvisional(aLeg *sipgo.DialogServerSession, sess *media.Session, ourIP netip.Addr, startOnce *sync.Once) func(res *sip.Response) error {
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
			if err := processAnswerSDP(sess, raw, media.SideB, startOnce); err != nil {
				b.s.log.Error("early media sdp", "err", err, "code", res.StatusCode)
			} else if rewritten, err := rewriteSDP(raw, ourIP, sess.RTPPort(media.SideA)); err != nil {
				b.s.log.Error("early media rewrite", "err", err, "code", res.StatusCode)
			} else {
				body = rewritten
				headers = []sip.Header{sip.NewHeader("Content-Type", "application/sdp")}
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
func processAnswerSDP(sess *media.Session, answer []byte, side media.Side, startOnce *sync.Once) error {
	remote, err := remoteMediaIP(answer)
	if err != nil {
		return err
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

// peerURI builds the sip.Uri sipgo needs to dial a peer, from its Address
// (host:port) and Transport. This lives in sig, not on config.Peer,
// because config must not import sipgo.
func peerURI(p *config.Peer) sip.Uri {
	host := p.Address
	port := 5060
	if h, portStr, err := net.SplitHostPort(p.Address); err == nil {
		host = h
		if n, perr := strconv.Atoi(portStr); perr == nil {
			port = n
		}
	}
	transport := p.Transport
	if transport == "" {
		transport = "udp"
	}
	params := sip.NewParams()
	params.Add("transport", transport)
	return sip.Uri{
		Scheme:    "sip",
		Host:      host,
		Port:      port,
		UriParams: params,
	}
}
