package sig

import (
	"context"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
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
// This is the single-target happy path (Task 6): decision.Targets[0] only,
// via dialAndBridge. Failover across the remaining targets, early media,
// and auth challenges are later tasks in this milestone and slot in
// around that seam (retry dialAndBridge over decision.Targets until one
// succeeds, then reject).
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

	sess.Start()
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
		_ = bLeg.Bye(context.Background())
	case <-bLeg.Context().Done():
		_ = aLeg.Bye(context.Background())
	case <-sess.Done():
		_ = aLeg.Bye(context.Background())
		_ = bLeg.Bye(context.Background())
	}
}

// dialAndBridge places the B-leg to target and, on a successful answer,
// anchors media (both SetExpectedRemote calls) and answers the A-leg with
// RespondSDP. On success it returns the established, ACKed bLeg — the
// caller owns it from there (Close it, hold the dialog open, tear down on
// hangup). On failure it returns ok=false, having already sent the A-leg
// an appropriate final response (488/503/502) and closed any bLeg it
// opened; the caller has nothing further to send.
//
// sess is shared across attempts (its ports don't change), so this is the
// seam later tasks extend: Task 8's failover loop calls this once per
// candidate in decision.Targets until one returns ok, Task 7 adds early
// media before the final answer, Task 9 retries once on a 401/407 with
// target.Peer.Auth.
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

	if err := bLeg.WaitAnswer(aLeg.Context(), sipgo.AnswerOptions{}); err != nil {
		b.s.log.Info("b-leg not answered", "err", err, "target", target.Name)
		_ = bLeg.Close()
		_ = aLeg.Respond(502, "Bad Gateway", nil)
		return nil, false
	}

	answer := bLeg.InviteResponse.Body()
	remoteB, err := remoteMediaIP(answer)
	if err != nil {
		_ = bLeg.Close()
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return nil, false
	}
	sess.SetExpectedRemote(media.SideB, remoteB)

	aAnswer, err := rewriteSDP(answer, ourIP, sess.RTPPort(media.SideA))
	if err != nil {
		_ = bLeg.Close()
		_ = aLeg.Respond(488, "Not Acceptable Here", nil)
		return nil, false
	}

	if err := bLeg.Ack(aLeg.Context()); err != nil {
		b.s.log.Error("ack b-leg", "err", err, "target", target.Name)
		_ = bLeg.Close()
		return nil, false
	}
	// RespondSDP blocks until the A-leg ACK arrives (sipgo retransmits the
	// 2xx up to 64*T1 otherwise); onAck routes it to dialogSrv.ReadAck.
	if err := aLeg.RespondSDP(aAnswer); err != nil {
		b.s.log.Error("respond a-leg", "err", err)
		_ = bLeg.Close()
		return nil, false
	}

	return bLeg, true
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
