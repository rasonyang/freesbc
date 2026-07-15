package sig

import (
	"context"
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
// route it, place the B-leg, anchor media, answer the A-leg, and hold the
// call open until either leg ends the dialog or media goes silent.
//
// This is the single-target happy path (Task 6), now with early media
// (Task 7): decision.Targets[0] only, via dialAndBridge. Failover across
// the remaining targets and auth challenges are later tasks in this
// milestone and slot in around that seam (retry dialAndBridge over
// decision.Targets until one succeeds, then reject).
func (b *bridge) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	defer b.recoverCall(req)

	name, fromPeer, ok := b.s.identify(req)
	if !ok {
		b.s.dropUnidentified(req)
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
		b.s.log.Error("read invite", "err", err, "source", req.Source())
		b.reject(req, tx, 500, "Server Internal Error")
		return
	}
	defer aLeg.Close()

	remoteA, err := remoteMediaIP(req.Body())
	if err != nil {
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return
	}

	// --- single target (failover loop is Task 8) ---
	target := decision.Targets[0]

	sess, err := b.s.pool.Allocate(media.SessionConfig{
		Latch: [2]media.LatchMode{
			media.ParseLatchMode(fromPeer.MediaLatch),
			media.ParseLatchMode(target.Peer.MediaLatch),
		},
	})
	if err != nil {
		_ = aLeg.Respond(503, "Service Unavailable", nil)
		return
	}
	defer sess.Close()
	sess.SetExpectedRemote(media.SideA, remoteA)

	ourIP := b.s.mediaIP(cfg)

	bLeg, ok := b.dialAndBridge(aLeg, target, decision.OutNumber, req.Body(), ourIP, sess)
	if !ok {
		return // dialAndBridge already sent the A-leg's final response.
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
		byeCtx, cancel := byeContext()
		_ = aLeg.Bye(byeCtx)
		_ = bLeg.Bye(byeCtx)
		cancel()
	}
}

// byeContext bounds a teardown BYE to 5s instead of inheriting a
// possibly-cancelled call context or blocking up to Timer F (~32s) on
// context.Background(): these are best-effort teardown sends to a peer
// that may already be gone, and callers ignore the error either way.
func byeContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// dialAndBridge places the B-leg to target and, on a successful answer,
// anchors media (both SetExpectedRemote calls) and answers the A-leg with
// RespondSDP. On success it returns the established, ACKed bLeg — the
// caller owns it from there (Close it, hold the dialog open, tear down on
// hangup). On failure it returns ok=false and closes/BYEs any bLeg it
// opened. All failure paths up to and including the Ack failure also send
// the A-leg an appropriate final response (488/503/502); the caller has
// nothing further to send in those cases. The one exception is the
// RespondSDP failure path: the A-leg answer attempt itself failed (the
// dialog is typically already gone, e.g. the caller CANCELed), so no A-leg
// response is sent there — only the now-established B-leg is BYE'd.
//
// A B-leg that reached a 2xx answer is a live, billable call at the
// carrier: WaitAnswer succeeding is the point past which "abandon it"
// (relying on DialogClientSession.Close, which only drops the local cache
// entry and sends neither BYE nor CANCEL) is no longer acceptable, and
// every path below either Acks-then-Byes it or, once Acked, Byes it.
//
// sess is shared across attempts (its ports don't change), so this is the
// seam later tasks extend: Task 8's failover loop calls this once per
// candidate in decision.Targets until one returns ok, Task 9 retries once
// on a 401/407 with target.Peer.Auth.
//
// Early media (Task 7): startOnce is created here and threaded through both
// the WaitAnswer OnResponse callback (relayProvisional, fired for every 18x
// the B-leg sends) and the 2xx path below via processAnswerSDP, so the
// media session Starts exactly once — whichever path (an 18x with SDP, or
// the eventual 2xx) reaches it first.
func (b *bridge) dialAndBridge(aLeg *sipgo.DialogServerSession, target Target, outNumber string, offerBody []byte, ourIP netip.Addr, sess *media.Session) (*sipgo.DialogClientSession, bool) {
	bOffer, err := rewriteSDP(offerBody, ourIP, sess.RTPPort(media.SideB))
	if err != nil {
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return nil, false
	}

	// peerURI builds only the trunk endpoint (host/port/transport); the
	// dialed number (post-transform) is the Request-URI user part, so it
	// must be set here — without it the carrier receives an INVITE with
	// no destination number.
	bTarget := peerURI(target.Peer)
	bTarget.User = outNumber

	bLeg, err := b.s.dialogCli.Invite(aLeg.Context(), bTarget, bOffer)
	if err != nil {
		b.s.log.Error("invite b-leg", "err", err, "target", target.Name)
		_ = aLeg.Respond(503, "Service Unavailable", nil)
		return nil, false
	}

	var startOnce sync.Once
	if err := bLeg.WaitAnswer(aLeg.Context(), sipgo.AnswerOptions{
		OnResponse: b.relayProvisional(aLeg, sess, ourIP, &startOnce),
	}); err != nil {
		b.s.log.Info("b-leg not answered", "err", err, "target", target.Name)
		_ = bLeg.Close()
		_ = aLeg.Respond(502, "Bad Gateway", nil)
		return nil, false
	}

	answer := bLeg.InviteResponse.Body()
	if err := processAnswerSDP(sess, answer, media.SideB, &startOnce); err != nil {
		// bLeg is answered (2xx) but not yet ACKed: Bye refuses to send on
		// an unconfirmed client dialog, so Ack first, then Bye to tear the
		// carrier call down rather than abandoning a live/billable call.
		b.ackThenBye(aLeg.Context(), bLeg, target)
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return nil, false
	}

	aAnswer, err := rewriteSDP(answer, ourIP, sess.RTPPort(media.SideA))
	if err != nil {
		b.ackThenBye(aLeg.Context(), bLeg, target)
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return nil, false
	}

	if err := bLeg.Ack(aLeg.Context()); err != nil {
		// ACK could not be sent: the dialog never reaches Confirmed, so
		// Bye would refuse it too — nothing left to do but Close (deferred
		// by the caller would be nil here, so do it now) and tell the
		// A-leg the call failed. This is the path that used to leave the
		// caller hanging with no final response at all.
		b.s.log.Error("ack b-leg", "err", err, "target", target.Name)
		_ = bLeg.Close()
		_ = aLeg.Respond(502, "Bad Gateway", nil)
		return nil, false
	}
	// RespondSDP blocks until the A-leg ACK arrives (sipgo retransmits the
	// 2xx up to 64*T1 otherwise); onAck routes it to dialogSrv.ReadAck.
	if err := aLeg.RespondSDP(aAnswer); err != nil {
		// The B-leg is already Acked/Confirmed here, so it's a live carrier
		// call; the A-leg answer attempt itself failed (typically the
		// caller CANCELed), so there is no A-leg response to send — only
		// tear the carrier call down.
		b.s.log.Error("respond a-leg", "err", err)
		byeCtx, cancel := byeContext()
		_ = bLeg.Bye(byeCtx)
		cancel()
		return nil, false
	}

	return bLeg, true
}

// relayProvisional builds dialAndBridge's WaitAnswer OnResponse callback: it
// fires for every response the B-leg sends, including the eventual final
// one, but only acts on provisionals (18x) — the final response is handled
// by dialAndBridge itself once WaitAnswer returns. For a provisional
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
