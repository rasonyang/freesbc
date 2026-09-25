package trunk

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

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// legSRTP is the negotiated SRTP state for one leg. A nil *legSRTP is the
// one and only representation of "this leg is plaintext" — both legs use it,
// and there is no second, redundant secure bool to keep in step with it.
// inbound decrypts what we receive from the peer (built from the peer's
// advertised key) and outbound encrypts what we send to the peer (built from
// ourKeyValue, which we advertise to the peer in SDP). suite is the
// negotiated suite. Keys are never copied between legs: each leg's inbound
// context is built from THAT peer's own advertised key, and each leg's
// outbound context is built from a key WE generated fresh for that leg.
type legSRTP struct {
	suite       media.CryptoSuite
	inbound     *media.SRTPContext // nil until the peer's key is known
	outbound    *media.SRTPContext
	ourKeyValue []byte // advertised to the peer (a=crypto)

	// tag is the a=crypto tag WE advertise this leg's key under. For the
	// A-leg (the SBC as answerer), it must echo the tag of the offered line
	// onInvite picked — RFC 4568 §5.1.3 — so it's copied from sel.tag in
	// onInvite, not left at zero. For the B-leg (the SBC as offerer), the
	// SBC always offers exactly one line, tagged 1.
	tag int

	// required is true only when this leg's peer policy is "srtp: required"
	// (never for "optional", even when the leg ended up secure because the
	// other leg happened to be secure). processAnswerSDP consults it to
	// decide how to treat an answer with no usable/matching crypto: required
	// fails the attempt (→ failover); optional bridges as plaintext instead
	// (RFC 3264-style graceful downgrade — "SRTP if the peer accepts, else
	// plaintext"). Currently only ever set on the B-leg's legSRTP built in
	// dialTarget; the A-leg already rejects an insecure offer against a
	// required policy with 488 in onInvite, before any legSRTP is built, so
	// it has no analogous use there.
	required bool
}

// sdpCrypto is what to advertise in SDP for this leg: our suite, key and
// tag, or nil (plaintext) for a nil leg.
func (l *legSRTP) sdpCrypto() *sdpCrypto {
	if l == nil {
		return nil
	}
	return &sdpCrypto{suite: l.suite, keyValue: l.ourKeyValue, tag: l.tag}
}

// srtpContexts returns the SRTP context pair to install on a side, reading
// nil (plaintext) as the nil/nil pair — so every SetSRTP call site can pass
// a leg's state straight through without its own nil check.
func (l *legSRTP) srtpContexts() (inbound, outbound *media.SRTPContext) {
	if l == nil {
		return nil, nil
	}
	return l.inbound, l.outbound
}

// errSRTPRequiredMismatch marks a processAnswerSDP failure caused
// specifically by a B-leg policy of required SRTP whose answer turned out
// not to be secure. Unlike a malformed/unparseable answer (a genuine carrier
// failure that ends the call with 502 — see TestBridgeBrokenAnswerSDPGets502),
// this one is retryable: the carrier answered and is reachable, it just
// doesn't meet our policy, so placeCall should fail over to the next target
// instead of giving up on the whole call.
var errSRTPRequiredMismatch = errors.New("srtp required by policy but answer has no usable a=crypto")

// callQuota counts in-flight initial INVITEs per peer and globally:
// a single peer source (forgable, given source-IP-only
// identification) could otherwise stream ~70 INVITE/s and exhaust the whole
// media port pool, each one also triggering a real outbound leg. The caps
// come from peers.<name>.max_concurrent_calls and the global
// max_concurrent_calls; a cap of 0 means unlimited. The zero value is
// usable (nil map is lazily initialized on first acquire).
type callQuota struct {
	mu     sync.Mutex
	peers  map[string]int
	global int
}

// acquire admits one initial INVITE for peer under both caps (a cap of 0
// skips that bound) and returns the release func to call when the call
// ends. onInvite defers it immediately, so every path out of onInvite —
// success, any failure response, or a panic unwind — frees the slot
// exactly once.
func (q *callQuota) acquire(peer string, peerMax, globalMax int) (release func(), admitted bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if peerMax > 0 && q.peers[peer] >= peerMax {
		return nil, false
	}
	if globalMax > 0 && q.global >= globalMax {
		return nil, false
	}
	if q.peers == nil {
		q.peers = make(map[string]int)
	}
	q.peers[peer]++
	q.global++
	return func() {
		q.mu.Lock()
		q.peers[peer]--
		if q.peers[peer] == 0 {
			delete(q.peers, peer)
		}
		q.global--
		q.mu.Unlock()
	}, true
}

// onInvite handles an inbound INVITE end to end: identify the source,
// route it, place the B-leg (failing over across decision.Targets and
// applying each target's outbound digest auth as it goes),
// anchor media, answer the A-leg, and hold the call open until either leg
// ends the dialog or media goes silent.
func (s *Server) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	// Every response on this INVITE — raw rejects and the A-leg dialog's own
	// — goes through ftx, so recoverCall knows whether a final response went
	// out and whether it was a 2xx.
	ftx := &finalTx{ServerTransaction: tx}
	tx = ftx
	guard := &callGuard{tx: ftx}
	defer s.recoverCall(req, guard)

	name, fromPeer, ok := s.identify(req)
	if !ok {
		s.dropUnidentified(req)
		return
	}

	// Refuse it explicitly with 400 (RFC 3261 §8.1.1 mandates all three on
	// an INVITE).
	if req.From() == nil || req.To() == nil || req.CallID() == nil {
		s.reject(req, tx, 400, "Bad Request")
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
	// touching dialogSrv. (Verified against sipgo
	// v1.4.3 that this is safe — see timers.go and
	// TestBridgeAnswersSessionTimerRefresh.) Any other re-INVITE on a live
	// dialog (hold/resume, a codec or address change) is an offer this
	// B2BUA cannot apply mid-call, so it gets 488 Not Acceptable Here (RFC
	// 3261 §14.2) on the raw transaction — not 501, since INVITE itself is
	// implemented. Per RFC 3261 §14.1, a failed re-INVITE does not terminate
	// the dialog, so the established call stays up with its existing media.
	//
	// The request is matched on its full dialog ID — Call-ID, From-tag and
	// To-tag, RFC 3261 §12.2.2 — against both legs of every live call (see
	// Server.lookupDialog): a refresh from the CALLER matches the A-leg and
	// is answered with the A-leg's established answer, while a refresh from
	// the CARRIER matches the B-leg (its own, distinct Call-ID) and is
	// answered with the B-leg's. Same code path, correct answer either way.
	//
	// A request that matches no live dialog gets 481 (RFC 3261 §12.2.2),
	// which tells a UA that lost its dialog to tear it down. That includes a
	// live Call-ID with the wrong tags, so a request that merely replays a
	// sniffed Call-ID and the established SDP gets 481 with no body — never
	// entry.answer, which on a secure leg carries the SDES master key. A
	// matching dialog is then held to the refresh test.
	//
	// The refresh 200 goes out on the raw transaction, bypassing sipgo's
	// retransmit-until-ACK loop in DialogServerSession.WriteResponse, so
	// respond2xxUntilAck retransmits it itself; onAck stops it.
	if tag, hasTag := req.To().Params.Get("tag"); hasTag && tag != "" {
		entry, known := s.lookupDialog(fsip.CallID(req), fsip.FromTag(req), tag)
		if !known && s.settingUp(fsip.CallID(req), fsip.FromTag(req)) {
			// The caller's dialog exists but is not published yet (its
			// INVITE's handler has not reached registerCall): 500 with
			// Retry-After asks the UA to try again (RFC 3261 §14.2), where
			// 481 would tell it to end the dialog it just set up.
			s.reject(req, tx, 500, "Server Internal Error", sip.NewHeader("Retry-After", "1"))
			return
		}
		if !known {
			s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
			return
		}
		if isRefreshReInvite(req, entry.compare) {
			cfg := s.store.Current()
			se := headerSeconds(req, "Session-Expires")
			if minSE := cfg.MinSE.Std(); se < minSE {
				// RFC 4028 §9 applies to a refresh as to the initial
				// INVITE: below our floor is 422, with the floor.
				s.reject(req, tx, 422, "Session Interval Too Small",
					sip.NewHeader("Min-SE", strconv.Itoa(int(minSE.Seconds()))))
				return
			}
			// The refresh's 200 OK MUST carry a Contact (RFC 3261 §12.1.1:
			// every 2xx to INVITE does), which
			// sip.NewResponseFromRequest does not add on its own — build
			// the same per-transport Contact the leg's original 200 used,
			// from the current config and the re-INVITE's own transport
			// (req.Transport(): whichever leg sent this refresh).
			transport := sip.NetworkToLower(req.Transport())
			contact := buildContact(s.sigIP(cfg), s.ourSigPort(cfg, transport), transport)

			res := sip.NewResponseFromRequest(req, 200, "OK", entry.answer)
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
			res.AppendHeader(contact)
			res.AppendHeader(sessionExpiresHeader(se, refresherOf(req)))
			res.AppendHeader(sip.NewHeader("Supported", "timer"))
			if hasOptionTag(req, "Supported", "timer") {
				// §9: a 2xx carrying Session-Expires to a UAC that
				// supports the extension also carries Require: timer.
				res.AppendHeader(sip.NewHeader("Require", "timer"))
			}
			// Retransmitted until the ACK (RFC 3261 §13.3.1.4): answering
			// on the raw transaction bypasses sipgo's own 2xx loop.
			if err := s.respond2xxUntilAck(req, tx, res); err != nil {
				s.log.Info("session-timer refresh 200 not acknowledged", "err", err, "call_id", fsip.CallID(req))
			}
			return
		}
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}

	// Merged-request detection (RFC 3261 §8.2.2.2): the same initial INVITE
	// (Call-ID, From-tag, CSeq) arriving again on a different branch — an
	// upstream proxy forking it to two of our addresses, or a loop — is
	// answered 482 instead of placing a second call for it.
	var cseq uint32
	if h := req.CSeq(); h != nil {
		cseq = h.SeqNo
	}
	doneInvite, fresh := s.beginInvite(mergeKey{callID: fsip.CallID(req), fromTag: fsip.FromTag(req), cseq: cseq})
	if !fresh {
		s.reject(req, tx, 482, "Loop Detected")
		return
	}
	defer doneInvite()

	cfg := s.store.Current()

	// Call-quota gate for initial INVITEs (the in-dialog
	// re-INVITE branch above already returned — a refresh never consumes a
	// new slot): an INVITE past either the peer's or the global
	// concurrent-call cap is refused with 503 + Retry-After (RFC 3261
	// §21.5.4) before routing, dialing, or a media port are spent on it.
	// The slot is released by defer no matter how this onInvite ends, so
	// failed calls can't leak quota.
	release, admitted := s.quota.acquire(name, fromPeer.MaxConcurrentCalls, cfg.MaxConcurrentCalls)
	if !admitted {
		s.reject(req, tx, 503, "Call Quota Exceeded", sip.NewHeader("Retry-After", "30"))
		return
	}
	defer release()

	// Front-door gating for INITIAL INVITEs only (the in-dialog
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
		s.respondTx(tx, res)
		s.log.Info("declined Require: 100rel", "source", req.Source())
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
			s.respondTx(tx, res)
			s.log.Info("rejected low Session-Expires", "requested", se, "min_se", minSE)
			return
		}
	}

	decision, ok := Resolve(cfg, name, req.Recipient.User)
	if !ok || decision.OutNumber == "" || len(decision.Targets) == 0 {
		s.reject(req, tx, 404, "Not Found")
		return
	}

	aLeg, err := s.dialogSrv.ReadInvite(req, tx)
	if err != nil {
		// ReadInvite's failures are all request-shape problems (most
		// commonly sipgo.ErrDialogInviteNoContact: no Contact header —
		// see DialogUA.ReadInvite's own minimal validation) — the far
		// end's fault, not an SBC-side failure, so 400 Bad Request
		// rather than a 5xx that would misattribute the problem to us.
		s.log.Info("malformed invite", "err", err, "source", req.Source())
		s.reject(req, tx, 400, "Bad Request")
		return
	}
	defer aLeg.Close()

	remoteA, err := remoteMediaIP(req.Body())
	if err != nil {
		s.respondA(aLeg, 488, "Not Acceptable Here")
		return
	}

	// A-leg SRTP negotiation: decide, from fromPeer's srtp
	// policy and what the caller actually offered, whether this leg will be
	// secure — and if so, build both SRTP contexts up front so they can be
	// installed on sess (via SetSRTP, right after Allocate below) before
	// anything Starts relaying. "required" never silently downgrades to
	// plaintext: an insecure offer against a required policy is rejected
	// here with 488, before any B-leg is even dialed. "optional" mirrors
	// whatever the caller offered; "disabled" (including any unrecognized
	// value) is always plaintext.
	aSecureOffer, aLines := offeredCrypto(req.Body())
	secureA := false
	switch fromPeer.SRTP {
	case "required":
		if !aSecureOffer || len(aLines) == 0 {
			s.respondA(aLeg, 488, "Not Acceptable Here")
			return
		}
		secureA = true
	case "optional":
		secureA = aSecureOffer && len(aLines) > 0
	default: // "disabled" (config's normalized default) or anything unrecognized
		secureA = false
	}
	// aSRTP stays nil for a plaintext A-leg — the single representation of
	// "this leg is not secure" everywhere below (see legSRTP).
	var aSRTP *legSRTP
	if secureA {
		// parseCryptoAttrs already dropped every unsupported suite, so the
		// first surviving line is the offerer's most-preferred one we can
		// use (RFC 4568 §5.1.2).
		var sel cryptoLine
		ok := len(aLines) > 0
		if ok {
			sel = aLines[0]
		}
		ourKey := media.NewSDESKey()
		var inbound, outbound *media.SRTPContext
		var ctxErr error
		if ok {
			inbound, ctxErr = media.NewSRTPContext(sel.suite, sel.keyValue)
		}
		if ok && ctxErr == nil {
			outbound, ctxErr = media.NewSRTPContext(sel.suite, ourKey)
		}
		if !ok || ctxErr != nil {
			// Unusable crypto (no supported suite selected, or a malformed
			// key rejected by NewSRTPContext) under a policy that requires
			// SRTP: treat exactly like "not secure" — 488, never a silent
			// plaintext fallback.
			s.respondA(aLeg, 488, "Not Acceptable Here")
			return
		}
		aSRTP = &legSRTP{
			suite:       sel.suite,
			inbound:     inbound,
			outbound:    outbound,
			ourKeyValue: ourKey,
			tag:         sel.tag,
		}

		// Non-TLS warn: SDES carries the master key in the clear inside the
		// SDP body, so negotiating it over a non-TLS signaling transport
		// leaks it to anyone who can see the signaling. We still negotiate
		// (the operator's policy said secure media is wanted; downgrading
		// behind their back would be worse), but log once per secure leg.
		if aTransport := sip.NetworkToLower(req.Transport()); aTransport != "tls" {
			s.log.Warn("SDES key negotiated over non-TLS signaling transport",
				"transport", aTransport, "peer", name)
		}
	}

	// Side-B's latch mode here is only a pre-first-attempt default, seeded
	// from Targets[0] because Allocate needs *some* mode before any target
	// has been dialed. dialTarget calls sess.SetLatchMode(SideB, ...) with
	// each target's own media_latch before dialing it, so the mode actually
	// in effect always matches whichever target ends up winning failover —
	// see placeCall/dialTarget for the loop.
	sess, err := s.pool.Allocate(media.SessionConfig{
		Latch: [2]media.LatchMode{
			media.ParseLatchMode(fromPeer.MediaLatch),
			media.ParseLatchMode(decision.Targets[0].Peer.MediaLatch),
		},
	})
	if err != nil {
		s.respondA(aLeg, 503, "Service Unavailable")
		return
	}
	defer sess.Close()
	if !remoteA.IsValid() {
		looseForFQDN(sess, media.SideA)
	}
	sess.SetExpectedRemote(media.SideA, remoteA)
	// Install the A-side SRTP contexts (nil/nil when plaintext) before
	// anything can Start relaying — SetSRTP must run strictly before Start,
	// and Start is only ever reached later, once the B-leg answers (see
	// processAnswerSDP), so doing this right after Allocate is always early
	// enough.
	aIn, aOut := aSRTP.srtpContexts()
	sess.SetSRTP(media.SideA, aIn, aOut)

	mediaIP := s.mediaIP(cfg)

	// c is this call's one state record from here on (see calls.go): the
	// bridge's own locals stop being the source of truth the moment
	// placeCall succeeds.
	c := &call{
		id:       fsip.CallID(req),
		fromPeer: name,
		aLeg:     aLeg,
		sess:     sess,
		aSRTP:    aSRTP,
		aOrigin:  newSDPOrigin(),
		state:    callDialing,
	}
	guard.c = c

	bLeg, target, aAnswer, bOffer, ok := s.placeCall(c, decision.Targets, decision.OutNumber, req.Body(), mediaIP)
	if !ok {
		return // placeCall already sent the A-leg's final response.
	}
	defer bLeg.Close()

	c.bLeg = bLeg
	c.bID = fsip.CallID(bLeg.InviteRequest)
	c.target = target
	c.toPeer = target.Name
	c.start = time.Now()

	// Both legs' established SDP pairs, each keyed (in registerCall) by that
	// leg's OWN Call-ID, so a later session-timer refresh re-INVITE on
	// EITHER leg is recognized (isRefreshReInvite, compared against
	// .compare) and answered with the SBC's own established answer for THAT
	// leg (.answer) — never the peer's offer, and never the other leg's SDP.
	// See legSDP's doc and the in-dialog branch above.
	//
	// A-leg: the caller offered req.Body(); we answered aAnswer.
	// B-leg: we offered bOffer; the carrier answered bLeg.InviteResponse.Body().
	//
	// Each entry also records the From/To tags the leg's REMOTE endpoint
	// will carry in an in-dialog request on this leg for the
	// in-dialog branch's dialog-match check: From always identifies the
	// sender, so the A-leg (caller is remote) stores the caller's From-tag
	// (off the initial INVITE) with OUR To-tag — the one sipgo prebuilt onto
	// ReadInvite's clone (aLeg.InviteRequest.To), which is exactly the tag
	// our 200 OK went out with (WriteResponse validates that equality) —
	// while the B-leg (carrier is remote, and IT was the UAS) stores the
	// carrier's own tag — the To-tag off ITS 200 OK (bLeg.InviteResponse.To)
	// — with OUR From-tag (set by buildFrom on bLeg.InviteRequest), swapped
	// relative to the establishment headers because the carrier's in-dialog
	// request carries ITS identity in From and ours in To. fromTagOf/toTagOf
	// read both kinds of message and return "" on a missing header, which
	// simply never matches a stored tag (stored tags are never empty on an
	// established leg).
	c.aSDP = legSDP{
		compare: req.Body(),
		answer:  aAnswer,
		fromTag: fsip.FromTag(req),
		toTag:   fsip.ToTag(aLeg.InviteRequest),
	}
	c.bSDP = legSDP{
		compare: bLeg.InviteResponse.Body(),
		answer:  bOffer,
		fromTag: fsip.ToTag(bLeg.InviteResponse),
		toTag:   fsip.FromTag(bLeg.InviteRequest),
	}

	// One registration, one teardown (calls.go): registerCall publishes the
	// call — admin listing, KillCall and both legs' in-dialog lookups all at
	// once, under one lock — and the deferred endCall reverses exactly that,
	// however the call ends. killCtx is the kick hook registerCall publishes;
	// the explicit defer keeps the context released even on the paths endCall
	// has already cancelled (cancelling twice is a no-op).
	killCtx, killCancel := context.WithCancel(context.Background())
	defer killCancel()
	c.cancel = killCancel
	s.registerCall(c)
	defer s.endCall(c)
	if s.onBridged != nil {
		s.onBridged(c)
	}
	// Refresh whichever leg's session timer names the SBC as refresher
	// (sessiontimer.go); the loops end with killCtx, which endCall cancels.
	s.startRefreshers(killCtx, c, cfg, c.aTimer, bLegSessionTimer(bLeg.InviteResponse))

	// Hold the call open until either leg ends the dialog or media goes
	// silent, tearing down whatever is left.
	select {
	case <-c.aLeg.Context().Done():
		s.byeLeg("b", c.bLeg.Bye)
	case <-c.bLeg.Context().Done():
		s.byeLeg("a", c.aLeg.Bye)
	case <-c.sess.Done():
		s.byeBoth(c)
	case <-killCtx.Done():
		// Admin kick-call: neither leg initiated, so BYE both —
		// same teardown as a media-silence timeout (byeBoth), never a
		// separate path.
		s.byeBoth(c)
	}
}

// byeBoth sends an independently-5s-bounded teardown BYE to each leg (each
// Bye gets its own byeContext so a slow first Bye can't eat into the second
// leg's budget). Shared by both onInvite's natural media-silence teardown
// (sess.Done) and the admin kick-call teardown (killCtx.Done) — the same
// path, not a new one.
func (s *Server) byeBoth(c *call) {
	s.byeLeg("a", c.aLeg.Bye)
	s.byeLeg("b", c.bLeg.Bye)
}

// byeLeg sends one teardown BYE bounded by its own byeContext. A failure
// is logged at Debug: the call is ending either way, but a BYE that never
// reached the far end leaves it holding a dead dialog, which should be
// visible in the logs.
func (s *Server) byeLeg(leg string, bye func(context.Context) error) {
	ctx, cancel := byeContext()
	defer cancel()
	if err := bye(ctx); err != nil {
		s.log.Debug("teardown bye failed", "leg", leg, "err", err)
	}
}

// respondA sends a response with no body on the A-leg dialog. A failure
// (typically the caller already gone) is logged at Debug, like byeLeg's.
func (s *Server) respondA(aLeg *sipgo.DialogServerSession, code int, reason string) {
	if err := aLeg.Respond(code, reason, nil); err != nil {
		s.log.Debug("respond a-leg failed", "code", code, "err", err, "call_id", fsip.CallID(aLeg.InviteRequest))
	}
}

// respondTx sends res on a raw server transaction, logging a failure at
// Debug.
func (s *Server) respondTx(tx sip.ServerTransaction, res *sip.Response) {
	if err := tx.Respond(res); err != nil {
		s.log.Debug("respond failed", "code", res.StatusCode, "err", err, "call_id", fsip.CallID(res))
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
// carrier status (realCode/realReason); failDial and failRing are our own
// synthesized outcomes, which placeCall itself turns into a 503 or a 408 and
// which must never clobber an earlier failReal in its final pick (see
// attemptResult and placeCall's precedence loop below).
type failKind int

const (
	failDial failKind = iota // no usable final response from the target → the caller's 503 fallback
	failReal                 // a genuine SIP final failure from the target → its own code
	failRing                 // this attempt's ring timer expired before the target answered → 408
)

// attemptResult is dialTarget's outcome for one target. ok is the only
// field that matters on success (a live bridge) — along with aAnswer, the
// SBC's own established A-side answer SDP for this call (placeCall/onInvite
// need it verbatim to answer a later A-leg session-timer
// refresh with, rather than the caller's own offer — see legSDP). On
// failure, retryable tells placeCall whether there is anything left to do:
// true means the B-leg never got past the answer (nothing committed, safe
// to try the next candidate); false means dialTarget already finished the
// call itself (bridged and responded, or answered-then-failed and already
// responded/torn down) — placeCall must stop, not send anything further.
// kind is only meaningful when retryable is true, and realCode/realReason
// only when kind is failReal; placeCall uses them solely to remember the
// last genuine carrier code, for the case where every target is exhausted.
//
// penalize marks a result as a genuine connect failure (no response from a
// reachable endpoint / caller still present) that should cool the endpoint
// down. Only set true at true connect-failure sites; everything relying on
// the zero-value default (caller CANCEL, auth challenge, raced/stale
// response) stays false.
//
// bOffer is the SBC's own B-side offer SDP actually sent to THIS
// target — only meaningful when ok is true.
type attemptResult struct {
	ok         bool
	aAnswer    []byte
	bOffer     []byte
	retryable  bool
	kind       failKind
	realCode   int
	realReason string
	penalize   bool
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
// far end has no idea who we are). Endpoints currently in cooldown
// (s.health, populated by placeCall's Penalize on a failDial) are skipped
// in favor of healthy ones — but only when at least one healthy endpoint
// exists; see the dial-anyway fallback below.
func (s *Server) expandTargets(targets []Target) []dialEndpoint {
	cfg := s.store.Current()
	var available, cooled []dialEndpoint
	for _, t := range targets {
		if t.Peer.Register && !s.IsRegistered(t.Name) {
			s.log.Debug("skipping unregistered target", "peer", t.Name)
			continue
		}
		for _, ep := range s.resolver.Resolve(t.Peer, cfg.SRVCacheTTL.Std()) {
			de := dialEndpoint{Target: t, Endpoint: ep}
			if s.health.Available(ep) {
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
// longer built here: each target's SRTP policy can differ, so
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
// last. Slots a ring timeout into this same precedence: if no target
// ever produced a real code but at least one attempt was cut short by its
// own ring timer (failRing), the caller gets 408 Request Timeout rather
// than a bare 503 — still only as a fallback behind any genuine carrier
// code, since a real (if late) carrier response is always more informative
// than our own synthesized timeout. This is the only path here that sends
// a final response itself, since it's the only one not already covered by
// the offer-validation failure above (488, target-independent — same offer,
// same failure, on every attempt) or dialTarget's post-answer paths.
//
// After each retryable failure, placeCall also checks whether the A-leg is
// still there (aLeg.Context().Err()) before starting the next candidate: a
// caller CANCEL/hangup mid-setup cancels that context, and without this
// check the loop would keep dialing (and waiting up to Timer B, ~32s, on)
// remaining carriers for a caller who already left.
// The bOffer return is the SBC's own B-side offer SDP (what we sent the
// winning target) — like aAnswer (see attemptResult), the caller needs it
// verbatim to answer a later B-LEG session-timer refresh with, rather than
// the carrier's own answer.
func (s *Server) placeCall(c *call, targets []Target, outNumber string, offerBody []byte, mediaIP netip.Addr) (bLeg *sipgo.DialogClientSession, winner Target, aAnswer []byte, bOffer []byte, ok bool) {
	aLeg := c.aLeg
	// Pre-loop validation only (the actual per-target offer, including any
	// SRTP crypto, is built fresh inside dialTarget — see its doc comment):
	// a parse/no-audio failure in offerBody is target-independent, so 488
	// here before any target is dialed rather than discovering the same
	// failure (inside the SDP builder) on every attempt.
	if err := validAudioSDP(offerBody); err != nil {
		s.respondA(aLeg, 488, "Not Acceptable Here")
		return nil, Target{}, nil, nil, false
	}

	cfg := s.store.Current()

	haveReal := false
	haveRing := false
	lastRealCode, lastRealReason := 0, ""
	for _, de := range s.expandTargets(targets) {
		dialedLeg, res := s.dialTarget(c, cfg, de.Target, de.Endpoint, outNumber, offerBody, mediaIP)
		if res.ok {
			// A bridged call proves this endpoint is reachable — clear any
			// prior cooldown so it is usable immediately on the next call.
			s.health.Recover(de.Endpoint)
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
			s.health.Penalize(de.Endpoint, cfg.PeerCooldown.Std())
		}
		if res.kind == failReal {
			haveReal = true
			lastRealCode, lastRealReason = res.realCode, res.realReason
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
		s.respondA(aLeg, lastRealCode, lastRealReason)
	case haveRing:
		s.respondA(aLeg, 408, "Request Timeout")
	default:
		s.respondA(aLeg, 503, "Service Unavailable")
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
// WaitAnswer's OnResponse) may reach processAnswerSDP/sess.Start before
// dialTarget's own post-answer processing does; Session.Start is a single
// CompareAndSwap, so the relay starts at most once regardless of which
// path wins — and the same holds across failover attempts, which share the
// one session.
//
// B-leg SRTP offer: bSecure is decided from THIS target's own
// peer policy — required always secure, disabled always plaintext, optional
// mirrors whatever the A-leg negotiated (aSRTP.secure) — never from a global
// or A-leg-only decision, since failover can hop across peers with different
// policies. When secure, the SBC offers exactly one suite (AES_CM_128_HMAC_
// SHA1_80, tag 1) with one freshly generated key: SDES lets an offer carry
// multiple a=crypto lines/suites, but doing so correctly means tracking
// which suite the answerer picked across two independent keys — offering
// suite 80 only is a documented, interop-negligible simplification (every
// SDES peer supports it). The A-leg ANSWER side has no such restriction:
// parseCryptoAttrs already accepts whichever supported suite the
// caller offered.
func (s *Server) dialTarget(c *call, cfg *config.Config, target Target, ep Endpoint, outNumber string, offerBody []byte, mediaIP netip.Addr) (bLeg *sipgo.DialogClientSession, res attemptResult) {
	aLeg, sess, aSRTP := c.aLeg, c.sess, c.aSRTP
	// Align SideB's latch policy with THIS target before dialing it — not
	// just whichever target happened to be Targets[0] at Allocate time — so
	// early media (relayProvisional) and the eventual answer both apply the
	// media_latch of the carrier actually being tried on this attempt. On
	// failover, a later attempt overwrites this before it arms/relays any
	// SideB traffic, so the winning target's policy is always what ends up
	// governing the session.
	sess.SetLatchMode(media.SideB, media.ParseLatchMode(target.Peer.MediaLatch))

	// bSRTP is nil for a plaintext B-leg — the same single representation
	// the A-leg uses (see legSRTP): relayProvisional and processAnswerSDP
	// both read nil as "nothing to negotiate". It is recorded on the call
	// as the B-side state of the attempt in flight; a later failover attempt
	// replaces it, so the winning attempt's is what the bridged call keeps.
	var bSRTP *legSRTP
	switch target.Peer.SRTP {
	case "required":
		bSRTP = &legSRTP{required: true}
	case "optional":
		if aSRTP != nil {
			bSRTP = &legSRTP{}
		}
	default: // "disabled" (config's normalized default) or anything unrecognized
		bSRTP = nil
	}
	c.bSRTP = bSRTP
	if bSRTP != nil {
		// Non-TLS warn (spec §4.5: one WARN per secure leg over non-TLS
		// signaling) — mirrors the A-leg's identical warn in onInvite. The
		// SBC is the one dialing this leg, so the transport is what WE chose
		// for this target (target.Peer.Transport, normalized to "udp" by
		// config.Parse when unset), not something read off an inbound
		// request.
		if bTransport := target.Peer.Transport; bTransport != "tls" {
			s.log.Warn("SDES key negotiated over non-TLS signaling transport",
				"transport", bTransport, "peer", target.Name)
		}
		bKey := media.NewSDESKey()
		outbound, err := media.NewSRTPContext(media.SuiteAES128CM80, bKey)
		if err != nil {
			// Context construction failed — a transient, this-attempt-only
			// problem, not the caller's or this carrier's fault: classify
			// like any other pre-dial failure so placeCall tries the next
			// candidate rather than failing the whole call.
			s.log.Error("build b-leg srtp context", "err", err, "target", target.Name)
			return nil, attemptResult{retryable: true, kind: failDial}
		}
		bSRTP.suite = media.SuiteAES128CM80
		bSRTP.ourKeyValue = bKey
		bSRTP.outbound = outbound
		bSRTP.tag = 1
	}
	// The offer is built from scratch (sdp.go) out of the caller's offer:
	// RTP/SAVP with our one a=crypto when bSRTP is set, RTP/AVP otherwise,
	// and never any of the caller's own lines — its a=crypto key included.
	// Each target is a new dialog, so each gets its own o= identity.
	// placeCall's pre-loop check already proved offerBody is relayable, so
	// this is not expected to fail here.
	bOffer, err := newSDPOrigin().build(offerBody, mediaIP, sess.RTPPort(media.SideB), bSRTP.sdpCrypto())
	if err != nil {
		return nil, attemptResult{retryable: true, kind: failDial}
	}
	// peerURI builds only the trunk endpoint (host/port/transport); the
	// dialed number (post-transform) is the Request-URI user part, so it
	// must be set here — without it the carrier receives an INVITE with
	// no destination number.
	bTarget := peerURI(ep)
	bTarget.User = outNumber

	sigPort := s.ourSigPort(cfg, target.Peer.Transport)
	from := s.buildFrom(aLeg.InviteRequest, s.sigIP(cfg), sigPort)
	contact := buildContact(s.sigIP(cfg), sigPort, target.Peer.Transport)

	// bHeaders carries From/Contact plus the session-timer headers,
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

	// retried422 bounds the loop below to AT MOST ONE retry per target:
	// a carrier that 422s again on the retry, or 422s without a
	// usable Min-SE, falls through to the ordinary failReal classification
	// below instead of retrying indefinitely.
	retried422 := false

	for {
		attemptLeg, attemptRes, answered, carrierMinSE := s.dialAttempt(c, cfg, target, mediaIP, bTarget, bOffer, bHeaders, retried422)
		if answered {
			bLeg = attemptLeg
			// On record from here on, so a panic before onInvite
			// publishes the call still tears this live B-leg down.
			c.bLeg = bLeg
			break
		}
		if carrierMinSE > 0 {
			// The target 422'd with a usable Min-SE floor and a retry is
			// still owed to it: raise Session-Expires to meet the floor and
			// dial this same target once more.
			retried422 = true
			bHeaders[3] = sessionExpiresHeader(carrierMinSE, "uas")
			continue
		}
		return nil, attemptRes
	}

	// Past this point the B-leg is answered (2xx): a live, billable carrier
	// call. Every remaining path is terminal (retryable=false).
	// Both failures below are POST-answer: the carrier already sent a 2xx,
	// so the offer we sent it was fine — it's the carrier's ANSWER SDP that
	// is missing/unparseable (processAnswerSDP) or that failed to rewrite
	// (rewriteSDPCrypto). 488 would wrongly tell the caller ITS OWN offer was
	// unacceptable; 502 Bad Gateway correctly attributes the failure to the
	// upstream leg (spec §6). This is distinct from placeCall's PRE-answer
	// 488 (validAudioSDP of the caller's own offer, before any target is even
	// dialed), which stays 488 — that one really is about the caller's
	// offer.
	answer := bLeg.InviteResponse.Body()
	if err := processAnswerSDP(sess, answer, media.SideB, bSRTP); err != nil {
		if errors.Is(err, errSRTPRequiredMismatch) {
			// The carrier answered for real (2xx, billable) but its answer
			// doesn't meet our required-SRTP policy for this target: unlike
			// a malformed/unparseable answer (a genuine, terminal carrier
			// failure — see the non-SRTP branch below), this is retryable.
			// The carrier is reachable, it's just unusable under policy, so
			// tear this attempt down and let placeCall try the next
			// candidate rather than finalizing the call with 502. "required"
			// never silently downgrades to plaintext.
			s.log.Info("b-leg srtp required by policy but answer not secure", "target", target.Name)
			s.ackThenBye(bLeg, target)
			return nil, attemptResult{retryable: true, kind: failDial}
		}
		// Respond the A-leg before tearing the B-leg down: ackThenBye is a
		// network round trip bounded by its own 5s contexts, and
		// there's no reason to hold the caller's final response hostage
		// behind it.
		s.respondA(aLeg, 502, "Bad Gateway")
		s.ackThenBye(bLeg, target)
		return nil, attemptResult{}
	}

	// A-leg answer crypto: when the A-leg is secure, advertise
	// the SBC's OWN A-outbound key (aSRTP.ourKeyValue) in the answer — the
	// caller encrypts toward us with the key it offered (already used to
	// build aSRTP.inbound in onInvite), and decrypts what we send it with
	// whatever key WE advertise here, i.e. what WE encrypt with
	// (aSRTP.outbound). The caller's own key is never echoed back.
	//
	// The answer is built from scratch (sdp.go) out of the carrier's answer
	// under the A-leg's own o= identity (c.aOrigin), the same one any early
	// media used, so the caller sees one session whichever carrier answered.
	// It is RTP/SAVP with our a=crypto when the A-leg is secure and RTP/AVP
	// otherwise, and never carries the carrier's own lines — a secure
	// carrier's a=crypto key included (see
	// TestBridgeSRTPInterworksPlaintextAToSecureB).
	aAnswer, err := c.aOrigin.build(answer, mediaIP, sess.RTPPort(media.SideA), aSRTP.sdpCrypto())
	if err != nil {
		s.respondA(aLeg, 502, "Bad Gateway")
		s.ackThenBye(bLeg, target)
		return nil, attemptResult{}
	}

	if err := bLeg.Ack(aLeg.Context()); err != nil {
		// ACK could not be sent: the dialog never reaches Confirmed, so
		// Bye would refuse it too — nothing left to do but Close and tell
		// the A-leg the call failed.
		s.log.Error("ack b-leg", "err", err, "target", target.Name)
		_ = bLeg.Close()
		s.respondA(aLeg, 502, "Bad Gateway")
		return nil, attemptResult{}
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
	aContact := buildContact(s.sigIP(cfg), s.ourSigPort(cfg, aTransport), aTransport)
	timerHeaders, aTimer := aLegSessionTimer(aLeg.InviteRequest, cfg)
	headers := append([]sip.Header{sip.NewHeader("Content-Type", "application/sdp"), aContact}, timerHeaders...)
	if err := aLeg.Respond(200, "OK", aAnswer, headers...); err != nil {
		// The B-leg is already Acked/Confirmed here, so it's a live carrier
		// call; the A-leg answer attempt itself failed (typically the
		// caller CANCELed), so there is no A-leg response to send — only
		// tear the carrier call down.
		s.log.Error("respond a-leg", "err", err)
		s.byeLeg("b", bLeg.Bye)
		return nil, attemptResult{}
	}

	c.aTimer = aTimer
	return bLeg, attemptResult{ok: true, aAnswer: aAnswer, bOffer: bOffer}
}

// dialAttempt drives ONE INVITE to target to the point where the attempt is
// decided: it sends the request, relays the provisional responses
// (relayProvisional via WaitAnswer's OnResponse), bounds the ring with its
// own per-attempt deadline, and classifies the outcome. Everything it owns
// is created and retired inside the attempt — the attempt context and its
// cancel, the waiter goroutine and its grace timer, the responded/abandoned
// flags — so dialTarget's retry loop has nothing to unwind between
// attempts.
//
// It reports the three outcomes that loop distinguishes:
//
//   - answered true: WaitAnswer returned a 2xx and bLeg is the answered
//     B-leg, which dialTarget takes over for the post-answer commit. The
//     returned attemptResult carries nothing in this case.
//   - minSE non-zero: the target replied 422 naming a usable Min-SE floor
//     and a retry is still owed to it. The B-leg is already Closed;
//     dialTarget re-dials this same target with Session-Expires raised to
//     minSE.
//   - otherwise: the attempt failed and the returned attemptResult is what
//     dialTarget hands back to placeCall verbatim.
//
// retried422 is dialTarget's at-most-one-retry-per-target state, passed in
// so that a second 422 asks for no further retry and falls through to the
// ordinary failReal classification below instead. bTarget, bOffer and
// bHeaders are the request this attempt sends, built by dialTarget once per
// target and (index 3 of bHeaders only) rewritten by it between attempts.
func (s *Server) dialAttempt(c *call, cfg *config.Config, target Target, mediaIP netip.Addr, bTarget sip.Uri, bOffer []byte, bHeaders []sip.Header, retried422 bool) (bLeg *sipgo.DialogClientSession, outcome attemptResult, answered bool, minSE time.Duration) {
	aLeg, sess, aSRTP, bSRTP := c.aLeg, c.sess, c.aSRTP, c.bSRTP

	// The attempt's own Call-ID, chosen here rather than by sipgo so its
	// forkWatch can be registered before the INVITE goes out: every 2xx
	// for it, from any fork, is then seen (see forks.go).
	callID := sip.CallIDHeader(freshTag())
	fw := s.watchForks(forkKey{callID: string(callID), fromTag: fromTagOf(bHeaders)}, target.Name)
	headers := append(append(make([]sip.Header, 0, len(bHeaders)+1), bHeaders...), &callID)

	var err error
	bLeg, err = s.dialogCli.Invite(aLeg.Context(), bTarget, bOffer, headers...)
	if err != nil {
		fw.decide("")
		s.log.Error("invite b-leg", "err", err, "target", target.Name)
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
		return nil, attemptResult{retryable: true, kind: failDial, penalize: aLeg.Context().Err() == nil}, false, 0
	}
	fw.setInvite(bLeg.InviteRequest)

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

	// WaitAnswer alone cannot be trusted to honor attemptCtx.
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
	//
	// gate is the one owner of A-leg writes for this attempt: the relay only
	// touches the A-leg inside gate.do, and the main path closes the gate
	// when it abandons the attempt, which waits out any relay already inside
	// it. From then on the main path (the next attempt, or the final
	// response) is the only writer.
	var responded atomic.Bool
	var gate relayGate
	waited := make(chan error, 1)
	relay := s.relayProvisional(aLeg, c.aOrigin, sess, mediaIP, aSRTP, bSRTP)
	// bLeg and attemptCtx are passed as ARGUMENTS, not captured: the
	// compiler may share the captured bLeg cell with dialTarget's return
	// slot (bLeg escapes both ways), and the deadline path's return below
	// would then race the goroutine's read of it (-race catches this as a
	// write at the return statement vs the closure's WaitAnswer call).
	// Argument copies are written once at goroutine start, so the
	// goroutine owns its values and the main flow can return freely.
	go func(bLeg *sipgo.DialogClientSession, attemptCtx context.Context) {
		// This goroutine outlives onInvite's recoverCall umbrella —
		// it keeps running (inviteCancel, ackThenBye) for up to Timer_B
		// (~32s) after dialTarget has already returned on an abandoned or
		// raced attempt — so a panic here (including a nil-deref induced
		// by a data race on shared dialog state) would kill the
		// WHOLE process, not just this call. Contain it: log and exit the
		// goroutine. Nothing is sent on waited after a panic; the main
		// path then simply runs out its ring budget and grace and
		// classifies the attempt as a timeout, which is the same outcome
		// an in-band error would have produced.
		defer s.recoverBWaiter(target.Name)
		// A panic must not leave the fork watch undecided (and so never
		// expired); on the normal path decide has already run.
		defer fw.decide("")
		err := bLeg.WaitAnswer(attemptCtx, sipgo.AnswerOptions{
			OnResponse: func(res *sip.Response) (err error) {
				// Once the main path has abandoned this attempt (ring
				// deadline AND grace both expired), stop touching any
				// shared dialog/media state — relay can reach aLeg.Respond,
				// and the main flow may concurrently be responding the
				// A-leg or dialing the next target. The whole callback runs
				// inside gate.do, so a relay that started before the
				// abandonment finishes before the main path moves on, and
				// one that starts after it does nothing. responded also
				// stays unset for late responses, so the penalize read on
				// the deadline path reflects only what arrived in time.
				if !gate.do(func() {
					// Realm pinning — when THIS target's auth pins a realm,
					// a challenge naming any other realm must never be
					// answered with a digest of our credentials (a rogue or
					// compromised server would harvest the response for
					// offline cracking). OnResponse runs BEFORE sipgo's
					// built-in digest retry, so returning an error here
					// aborts WaitAnswer without any Authorization header
					// ever being sent for this attempt; the classification
					// below then reports it as the ordinary
					// unsatisfied-challenge failDial.
					if auth := target.Peer.Auth; auth != nil && auth.Realm != "" &&
						(res.StatusCode == sip.StatusUnauthorized || res.StatusCode == sip.StatusProxyAuthRequired) &&
						!realmPinned(res, auth.Realm) {
						err = fmt.Errorf("auth challenge realm %q does not match pinned realm %q", challengeRealm(res), auth.Realm)
						return
					}
					responded.Store(true)
					err = relay(res)
				}) {
					return nil
				}
				return err
			},
			Username: authUser(target),
			Password: authPass(target),
		})
		// Tell the fork watch which 2xx this attempt acts on (the one
		// WaitAnswer took, if any); every other forked 2xx is ACKed and
		// BYEd there.
		winner := ""
		if carrierAnswered(bLeg) {
			winner = fsip.ToTag(bLeg.InviteResponse)
		}
		fw.decide(winner)
		// A 2xx can race the deadline: inviteCancel consumes it and
		// returns an error, but the carrier now thinks the call is up —
		// tear that phantom call down here, because the main loop below
		// has already moved on and must never read InviteResponse again
		// for this attempt.
		if gate.isClosed() && carrierAnswered(bLeg) {
			s.ackThenBye(bLeg, target)
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
		// abandon the attempt, so ring_timeout/failover still hold.
		// 250ms is far more than the relay/CANCEL dance needs;
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
			gate.close()
			cancel()
			s.log.Info("b-leg not answered", "err", attemptCtx.Err(), "target", target.Name)
			if attemptCtx.Err() == context.DeadlineExceeded {
				// Caller still present (else attemptCtx would carry
				// Canceled, not DeadlineExceeded — it derives from
				// aLeg.Context()).
				return nil, attemptResult{
					retryable: true,
					kind:      failRing,
					penalize:  !responded.Load(),
				}, false, 0
			}
			// Parent context cancelled: the caller is gone. Mirror the
			// aLeg.Context().Err() classification case below (zero-value
			// kind/code — nothing reaches a caller that no longer
			// exists) and never penalize: this wasn't the endpoint's
			// fault.
			return nil, attemptResult{retryable: true, kind: failDial}, false, 0
		}
	}
	if waitErr == nil {
		cancel()
		return bLeg, attemptResult{}, true, 0
	}
	s.log.Info("b-leg not answered", "err", waitErr, "target", target.Name)
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

	// A 422 carries the carrier's Min-SE floor in a header —
	// retry THIS target once with Session-Expires raised to meet it,
	// rather than treating it as an ordinary carrier failure. A 422 is
	// a non-2xx final on an unanswered B-leg (same as any other failReal
	// candidate below), so just Close — no ACK/BYE. This must run before
	// the raced-2xx teardown and classification switch below: a 422 is
	// never a success, so neither of those apply to it.
	if !retried422 && bLeg.InviteResponse != nil && bLeg.InviteResponse.StatusCode == 422 {
		if carrierMinSE := headerSeconds(bLeg.InviteResponse, "Min-SE"); carrierMinSE > 0 {
			bLeg.Close()
			cancel()
			return nil, attemptResult{}, false, carrierMinSE
		}
	}

	// InviteResponse can also hold a 2xx here: WaitAnswer returns an
	// error (ctx cancellation racing a just-arrived answer, or a
	// malformed 2xx whose DialogIDFromResponse failed) while the
	// carrier has already answered for real. That answer is a live,
	// billable carrier call the carrier now thinks is up — it is
	// classified below, but first it must be torn down with a
	// real ACK+BYE rather than silently abandoned to ring up ~32s of
	// carrier billing for a call nobody is using.
	res := attemptResult{retryable: true, kind: failDial}
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
	// regardless of which case ends up classifying the attempt. Best
	// effort, independent of the A-leg's fate (which may already be
	// cancelled — the caller-CANCEL case above): ackThenBye bounds both
	// its own ACK and BYE via byeContext's 5s.
	if carrierAnswered(bLeg) {
		s.ackThenBye(bLeg, target)
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

	case carrierAnswered(bLeg):
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
		}

	case attemptCtx.Err() == context.DeadlineExceeded:
		// aLeg.Context() is still live (checked above) but the
		// PER-ATTEMPT deadline fired: this target simply rang too long.
		// WaitAnswer already sent it a CANCEL (see attemptCtx's comment
		// above) — placeCall fails over to the next target.
		res.kind = failRing

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
		res.realCode = bLeg.InviteResponse.StatusCode
		res.realReason = bLeg.InviteResponse.Reason

	case bLeg.InviteResponse != nil &&
		(bLeg.InviteResponse.StatusCode == sip.StatusUnauthorized || bLeg.InviteResponse.StatusCode == sip.StatusProxyAuthRequired):
		// The target challenged and we couldn't (or didn't) satisfy it:
		// WaitAnswer only attempts its own digest retry when
		// opts.Password is non-empty (see authUser/authPass) — an
		// IP-auth trunk that unexpectedly challenges, or a retry whose
		// credentials the target still rejects, ends up here. A 401/407
		// is a negotiation with THIS target, not something the caller
		// can use, so it stays failDial — placeCall's 503 — rather than
		// leaking the challenge upstream as a bogus 401/407.
		s.log.Debug("b-leg auth challenge unsatisfied", "code", bLeg.InviteResponse.StatusCode, "target", target.Name)
	}
	cancel()
	_ = bLeg.Close()
	return nil, res, false, 0
}

// relayGate serialises an attempt's provisional relay against the main
// path's abandonment of that attempt (see dialAttempt): do runs f unless the
// gate is closed, and close waits for a running f to finish. The zero value
// is an open gate.
type relayGate struct {
	mu     sync.Mutex
	closed bool
}

// do runs f under the gate and reports whether it ran.
func (g *relayGate) do(f func()) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	f()
	return true
}

// close shuts the gate, after any f already inside do has returned.
func (g *relayGate) close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}

func (g *relayGate) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

// fromTagOf returns the tag of the From header among headers, or "".
func fromTagOf(headers []sip.Header) string {
	for _, h := range headers {
		if f, ok := h.(*sip.FromHeader); ok {
			tag, _ := f.Params.Get("tag")
			return tag
		}
	}
	return ""
}

// carrierAnswered reports whether the B-leg holds a genuine 2xx from the
// carrier — i.e. a live, billable call the carrier believes is up, whether
// or not WaitAnswer returned it as a success. dialTarget asks this in three
// places (the abandoned-attempt teardown in the waiter goroutine, the
// unconditional raced-2xx teardown, and the classification switch), and
// they must agree: a 2xx that one of them sees and another doesn't would
// leave a phantom carrier call standing.
func carrierAnswered(bLeg *sipgo.DialogClientSession) bool {
	return bLeg.InviteResponse != nil && bLeg.InviteResponse.IsSuccess()
}

// buildFrom clones the caller's identity onto a B-leg From: the caller's
// user and display name (CLI pass-through) with our own host (topology
// hiding — the caller's address is never exposed to the target) and a fresh
// local tag, since this From establishes a brand new dialog to the target
// rather than reusing the A-leg's.
func (s *Server) buildFrom(req *sip.Request, sigIP netip.Addr, port int) *sip.FromHeader {
	caller := req.From()
	params := sip.NewParams()
	params.Add("tag", freshTag())
	return &sip.FromHeader{
		DisplayName: caller.DisplayName,
		Address: sip.Uri{
			Scheme: "sip",
			User:   caller.Address.User,
			Host:   sigIP.String(),
			Port:   port,
		},
		Params: params,
	}
}

// buildContact advertises our address for the given transport so requests
// from the far side reach us on the right leg: in-dialog requests
// (re-INVITE, BYE, ...) on a bridged call, and inbound INVITEs against a
// REGISTER binding (see Registrar.paramsFor). UDP is SIP's default transport
// per RFC 3261 §19.1.2, so the transport param is omitted for udp; only tcp
// and tls carry an explicit transport= to ensure the far side dials us back
// on the same non-default transport.
func buildContact(sigIP netip.Addr, port int, transport string) *sip.ContactHeader {
	c := &sip.ContactHeader{
		Address: sip.Uri{Scheme: "sip", Host: sigIP.String(), Port: port},
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
// aSRTP/bsrtp mirror dialTarget's own negotiated state, so the
// SDP relayed in early media is crypto-consistent with what the eventual
// final answer will carry: bsrtp (nil when B is plaintext) drives
// processAnswerSDP's B-inbound install exactly like the final-200 path, and
// aSRTP drives whether the rewritten body relayed to the caller is
// RTP/SAVP+a=crypto (our A-outbound key) or plain RTP/AVP.
//
// Forks: every 18x shares the caller's one early dialog, but each To-tag
// is its own early dialog on the B side (RFC 3261 §12.1). Early media
// belongs to the first fork whose 18x carried usable SDP; an 18x with SDP
// from any other fork is relayed status-only and never relatches side B,
// so media does not flip between forks. The 2xx relatches to whichever
// fork answers (processAnswerSDP in dialTarget).
func (s *Server) relayProvisional(aLeg *sipgo.DialogServerSession, aOrigin *sdpOrigin, sess *media.Session, mediaIP netip.Addr, aSRTP, bsrtp *legSRTP) func(res *sip.Response) error {
	// earlyTag is the To-tag of the fork that owns early media. The
	// callback only ever runs on the attempt's waiter goroutine, one
	// response at a time, so it needs no lock.
	var earlyTag string
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
		tag := fsip.ToTag(res)
		if raw := res.Body(); len(raw) > 0 && earlyTag != "" && tag != earlyTag {
			s.log.Debug("early media from a second fork relayed status-only", "code", res.StatusCode, "to_tag", tag)
		} else if len(raw) > 0 {
			if err := processAnswerSDP(sess, raw, media.SideB, bsrtp); err != nil {
				s.log.Error("early media sdp", "err", err, "code", res.StatusCode)
			} else {
				earlyTag = tag
				// Built like the final answer (dialTarget), under the same
				// A-leg origin, so 18x and 2xx carry one o= session.
				rewritten, err := aOrigin.build(raw, mediaIP, sess.RTPPort(media.SideA), aSRTP.sdpCrypto())
				if err != nil {
					s.log.Error("early media rewrite", "err", err, "code", res.StatusCode)
				} else {
					body = rewritten
					headers = []sip.Header{sip.NewHeader("Content-Type", "application/sdp")}
				}
			}
		}
		if err := aLeg.Respond(res.StatusCode, res.Reason, body, headers...); err != nil {
			s.log.Error("relay provisional", "err", err, "code", res.StatusCode)
		}
		return nil
	}
}

// processAnswerSDP arms sess's side latch to the media address carried in
// answer and Starts the relay loops. Both the early-media (18x) and final
// (2xx) paths call it, and so does every failover attempt; Session.Start
// itself is the single CompareAndSwap that makes only the first of them
// actually start the relay. Returns the remoteMediaIP parse error
// unchanged so callers can decide how to fail (early media falls back to a
// status-only relay; the final path rejects the call).
//
// bsrtp is the B-leg's offer-side SRTP state — nil when B is
// plaintext. When non-nil and secure, the ANSWER's own crypto is parsed (the
// peer's advertised key is what THEY encrypt with, so it becomes our
// inbound/decrypt context) and, when it's usable, sess.SetSRTP installs both
// contexts for side BEFORE Relatch/Start below — SetSRTP must always run
// strictly before this call's own sess.Start, so a fresh Session never
// Starts with a partially-installed side; on an already-Started
// Session (a later failover target's answer, or an early-media path racing
// the final one) SetSRTP's atomic.Pointer fields make the same call race-free
// against the running relay loops (see media.Session.SetSRTP's own doc).
//
// sess.SetSRTP(side, nil, nil) is ALWAYS called for a plaintext outcome —
// bsrtp nil, or bsrtp secure but the answer has no usable/matching crypto and
// isn't required — never merely skipped. This matters across B-leg failover:
// sess is shared for the whole call (see placeCall), so an
// EARLIER target's early media (18x) can have already installed secure B
// contexts via this same function before a LATER, plaintext-answering target
// wins; without an explicit clear here the later target's plaintext packets
// would still be run through the stale SRTP contexts and fail
// unprotectRTP/protectRTP, silently going dead.
//
// Whether an unusable/mismatched answer fails the attempt or bridges
// plaintext depends on bsrtp.required AND on what the peer actually
// answered: a "required" leg (peer configured srtp: required) never
// silently downgrades — it's reported via errSRTPRequiredMismatch so
// dialTarget can fail over instead of bridging where policy demanded
// encryption. An "optional" leg (peer configured srtp: optional,
// secure=true only because the A-leg happened to be secure) bridges
// plaintext instead, per spec:
// "SRTP if the peer accepts, else plaintext" — but ONLY when the peer
// actually answered plaintext (RTP/AVP). If an "optional" peer answered
// RTP/SAVP (committed to SRTP in the SDP protocol field) with an unusable or
// mismatched suite, bridging "plaintext" would mean forwarding the peer's
// still-SRTP-protected bytes as if they were plain RTP — garbage audio, not
// a graceful downgrade — so that case fails over exactly like "required"
// does (answerSecure is part of the failure condition below, not just
// bsrtp.required). An answer whose crypto suite doesn't match what we
// offered (we offer suite 80 only; a carrier answering suite 32
// would otherwise give one-way audio, decrypting with 32 while encrypting
// with 80) is treated identically to "no usable crypto".
func processAnswerSDP(sess *media.Session, answer []byte, side media.Side, bsrtp *legSRTP) error {
	remote, err := remoteMediaIP(answer)
	if err != nil {
		return err
	}
	switch {
	case bsrtp == nil:
		sess.SetSRTP(side, nil, nil)
	default:
		answerSecure, lines := offeredCrypto(answer)
		// parseCryptoAttrs already dropped every unsupported suite; the
		// first surviving line is the answerer's choice (RFC 4568 §5.1.2).
		usable := answerSecure && len(lines) > 0 && lines[0].suite == bsrtp.suite
		var sel cryptoLine
		if len(lines) > 0 {
			sel = lines[0]
		}
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
	if !remote.IsValid() {
		looseForFQDN(sess, side)
	}
	sess.Relatch(side, remote)
	sess.Start()
	return nil
}

// looseForFQDN makes side latch to its first packet. It is for a peer whose
// c= is an FQDN (remoteMediaIP returns the zero Addr for one): the trunk
// does not resolve names on the call path, so there is no address for a
// strict latch to expect, and a strict latch would drop every packet.
func looseForFQDN(sess *media.Session, side media.Side) {
	sess.SetLatchMode(side, media.LatchLoose)
}

// recoverBWaiter is the panic umbrella for the orphan B-leg waiter
// goroutine in dialTarget, deferred at the top of it. That goroutine
// outlives onInvite's own recoverCall umbrella, so an unrecovered panic
// there would kill the whole process rather than one call; this logs it
// with a stack and lets the goroutine exit quietly. Nothing is sent on the
// waited channel afterwards, so the main flow runs out its ring budget and
// classifies the attempt as a timeout.
//
// It is a named method rather than an inline closure so the recovery itself
// is directly testable (see TestBridgeWaiterPanicContained) without a
// production-side injection hook.
func (s *Server) recoverBWaiter(targetName string) {
	if r := recover(); r != nil {
		s.log.Error("b-leg waiter goroutine panic",
			"panic", r, "stack", string(debug.Stack()), "target", targetName)
	}
}

// ackThenBye tears down a B-leg that has been answered (2xx received) but
// not yet ACKed: DialogClientSession.Bye refuses to send on a dialog that
// isn't Confirmed, so this Acks first (best-effort) and only then Byes
// (also best-effort) — both errors are logged, not returned, since the
// caller has already decided to abandon this bLeg regardless.
//
// Both sends get their OWN 5s-bounded contexts (byeContext), never a
// caller's ctx. Two separate budgets, like byeBoth, so a slow Ack can't eat
// the Bye's budget.
func (s *Server) ackThenBye(bLeg *sipgo.DialogClientSession, target Target) {
	ackCtx, ackCancel := byeContext()
	err := bLeg.Ack(ackCtx)
	ackCancel()
	if err != nil {
		s.log.Error("ack b-leg for teardown", "err", err, "target", target.Name)
		_ = bLeg.Close()
		return
	}
	byeCtx, cancel := byeContext()
	defer cancel()
	if err := bLeg.Bye(byeCtx); err != nil {
		s.log.Error("bye b-leg for teardown", "err", err, "target", target.Name)
	}
}

// reject answers an INVITE we will not bridge, before any dialog is
// created. Extra headers (e.g. the quota gate's Retry-After) are appended
// to the response.
func (s *Server) reject(req *sip.Request, tx sip.ServerTransaction, code int, reason string, headers ...sip.Header) {
	res := sip.NewResponseFromRequest(req, code, reason, nil)
	for _, h := range headers {
		res.AppendHeader(h)
	}
	s.respondTx(tx, res)
	s.log.Info("rejected invite", "code", code, "reason", reason, "source", req.Source())
}

// finalTx wraps an INVITE's server transaction and records the first
// final response sent on it, whichever path sent it (a raw reject, or the
// A-leg dialog's own Respond, which writes through the same transaction).
type finalTx struct {
	sip.ServerTransaction
	final atomic.Int32
}

func (t *finalTx) Respond(res *sip.Response) error {
	err := t.ServerTransaction.Respond(res)
	if err == nil && res.StatusCode >= 200 {
		t.final.CompareAndSwap(0, int32(res.StatusCode))
	}
	return err
}

// finalCode is the first final status sent, or 0 if none was.
func (t *finalTx) finalCode() int { return int(t.final.Load()) }

// callGuard is what recoverCall needs to clean up after a panic in
// onInvite: the INVITE's transaction, and the call once one exists.
type callGuard struct {
	tx *finalTx
	c  *call
}

// recoverCall is deferred first thing in onInvite: a panic anywhere in the
// call setup or bridging path kills only this call (never the process),
// leaving a forensic trace. The function's own defers (aLeg/bLeg/sess
// Close, endCall) still run during the panic unwind, since defer execution
// isn't short-circuited by recover; Close only drops local dialog state, so
// the far ends still have to be told (cleanupAfterPanic).
func (s *Server) recoverCall(req *sip.Request, g *callGuard) {
	if r := recover(); r != nil {
		s.log.Error("bridge call panic; call dropped",
			"panic", r, "stack", string(debug.Stack()), "call_id", fsip.CallID(req))
		s.cleanupAfterPanic(req, g)
	}
}

// cleanupAfterPanic finishes a call whose onInvite panicked: an INVITE that
// got no final response gets 500 (RFC 3261 §8.2, §17.2.1), an A-leg that
// was answered 2xx gets a BYE, and a B-leg the carrier answered is ACKed
// (if needed) and BYEd (RFC 3261 §15). Each send is best effort and
// bounded like any other teardown.
func (s *Server) cleanupAfterPanic(req *sip.Request, g *callGuard) {
	code := g.tx.finalCode()
	if code == 0 {
		if err := g.tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Internal Error", nil)); err != nil {
			s.log.Debug("respond 500 after panic", "err", err, "call_id", fsip.CallID(req))
		}
	}
	c := g.c
	if c == nil {
		return
	}
	if code >= 200 && code < 300 && c.aLeg != nil {
		s.byeLeg("a", c.aLeg.Bye)
	}
	if c.bLeg != nil {
		switch c.bLeg.LoadState() {
		case sip.DialogStateConfirmed:
			s.byeLeg("b", c.bLeg.Bye)
		case sip.DialogStateEstablished:
			s.ackThenBye(c.bLeg, c.target)
		}
	}
}

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
