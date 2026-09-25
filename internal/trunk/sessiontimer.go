package trunk

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Session timers (RFC 4028) on the trunk plane.
//
// Each leg negotiates its own timer. The SBC is the UAS on the A-leg and
// the UAC on the B-leg:
//
//   - A-leg (aLegSessionTimer): the 2xx carries Session-Expires only when
//     the caller said Supported: timer, and then also Require: timer (§9).
//     The refresher is the one the caller asked for, else the caller
//     ("uac"). A caller that did not indicate support gets no session timer
//     at all — the SBC does not take on refreshing a leg whose far end
//     never asked for one.
//   - B-leg (bLegSessionTimer): the INVITE offers Supported: timer and
//     asks the carrier to refresh (refresher=uas). The carrier's 2xx
//     decides: no Session-Expires means no timer; refresher=uac makes the
//     SBC the refresher.
//
// Whichever leg names the SBC as refresher is refreshed by refreshLoop: a
// re-INVITE restating the SBC's established SDP on that leg every half
// interval (§10). A refresh that times out or gets 408/481 ends the call
// (§10: the session is gone), which tears down both legs.

// legTimer is one leg's negotiated session timer: the interval, and whether
// the SBC is the refresher. The zero value is "no session timer".
type legTimer struct {
	interval  time.Duration
	weRefresh bool
}

// aLegSessionTimer returns the session-timer headers for the A-leg 2xx and
// the timer they set up, per RFC 4028 §9.
func aLegSessionTimer(invite *sip.Request, cfg *config.Config) ([]sip.Header, legTimer) {
	supported := sip.NewHeader("Supported", "timer")
	if !hasOptionTag(invite, "Supported", "timer") {
		return []sip.Header{supported}, legTimer{}
	}
	se := negotiateSE(
		headerSeconds(invite, "Session-Expires"),
		headerSeconds(invite, "Min-SE"),
		cfg.SessionExpires.Std(), cfg.MinSE.Std())
	refresher := refresherParam(invite)
	if refresher != "uas" {
		refresher = "uac"
	}
	return []sip.Header{
		sessionExpiresHeader(se, refresher),
		sip.NewHeader("Require", "timer"),
		supported,
	}, legTimer{interval: se, weRefresh: refresher == "uas"}
}

// bLegSessionTimer reads the timer the carrier's 2xx set up on the B-leg,
// where the SBC is the UAC.
func bLegSessionTimer(res *sip.Response) legTimer {
	se := headerSeconds(res, "Session-Expires")
	if se == 0 {
		return legTimer{}
	}
	return legTimer{interval: se, weRefresh: refresherParam(res) == "uac"}
}

// refreshTarget is what refreshLoop needs to refresh one leg: the dialog to
// send on (sipgo's dialog sessions build in-dialog requests themselves),
// the remote target, and the SBC's own established SDP and Contact on that
// leg.
type refreshTarget struct {
	leg     string // "a" or "b", for logs
	do      func(context.Context, *sip.Request) (*sip.Response, error)
	write   func(*sip.Request) error
	remote  sip.Uri
	sdp     []byte
	contact sip.Header
	minSE   time.Duration
}

// refreshLoop refreshes one leg until ctx (the call's kick context, which
// endCall cancels) is done. It stops quietly when the far end takes over
// refreshing; it ends the call (endCall) when a refresh proves the session
// is gone.
func (s *Server) refreshLoop(ctx context.Context, c *call, t refreshTarget, lt legTimer) {
	interval := lt.interval
	wait := interval / 2
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		res, err := s.sendRefresh(ctx, t, interval)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil || res.StatusCode == sip.StatusRequestTimeout || res.StatusCode == sip.StatusCallTransactionDoesNotExists:
			s.log.Info("session refresh failed; ending call", "leg", t.leg, "err", err, "code", statusOf(res), "call", c.adminID)
			c.cancel()
			return
		case res.IsSuccess():
			if se := headerSeconds(res, "Session-Expires"); se > 0 {
				interval = se
			}
			if refresherParam(res) == "uas" {
				s.log.Debug("session refresher moved to the far end", "leg", t.leg, "call", c.adminID)
				return
			}
			wait = interval / 2
		case res.StatusCode == 422:
			// Session Interval Too Small: retry at once with the far
			// end's floor (§6).
			if minSE := headerSeconds(res, "Min-SE"); minSE > interval {
				interval = minSE
			}
			wait = 0
		default:
			// Any other failure (491 glare, 5xx, ...) leaves the session
			// up until it expires; try again at three quarters of the
			// interval.
			s.log.Debug("session refresh rejected", "leg", t.leg, "code", res.StatusCode, "call", c.adminID)
			wait = interval / 4
		}
		timer.Reset(wait)
	}
}

// sendRefresh sends one refresh re-INVITE on the leg (and ACKs a 2xx). The
// request is bounded by 64·T1, the INVITE transaction's own timeout.
func (s *Server) sendRefresh(ctx context.Context, t refreshTarget, interval time.Duration) (*sip.Response, error) {
	req := sip.NewRequest(sip.INVITE, *t.remote.Clone())
	req.SetBody(t.sdp)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.AppendHeader(sip.HeaderClone(t.contact))
	req.AppendHeader(sip.NewHeader("Supported", "timer"))
	req.AppendHeader(sessionExpiresHeader(interval, "uac"))
	req.AppendHeader(sip.NewHeader("Min-SE", strconv.Itoa(int(t.minSE.Seconds()))))
	rctx, cancel := context.WithTimeout(ctx, 64*sip.T1)
	defer cancel()
	res, err := t.do(rctx, req)
	if err != nil {
		return nil, err
	}
	if res.IsSuccess() {
		ack := sip.NewRequest(sip.ACK, *t.remote.Clone())
		if c := res.Contact(); c != nil {
			ack.Recipient = *c.Address.Clone()
		}
		if err := t.write(ack); err != nil {
			s.log.Debug("ack session refresh", "leg", t.leg, "err", err)
		}
	}
	return res, nil
}

func statusOf(res *sip.Response) int {
	if res == nil {
		return 0
	}
	return res.StatusCode
}

// startRefreshers starts refreshLoop on each leg of a bridged call whose
// session timer names the SBC as refresher.
func (s *Server) startRefreshers(ctx context.Context, c *call, cfg *config.Config, aTimer, bTimer legTimer) {
	if aTimer.weRefresh && c.aLeg.InviteRequest.Contact() != nil {
		transport := sip.NetworkToLower(c.aLeg.InviteRequest.Transport())
		go s.refreshLoop(ctx, c, refreshTarget{
			leg:     "a",
			do:      c.aLeg.Do,
			write:   c.aLeg.WriteRequest,
			remote:  c.aLeg.InviteRequest.Contact().Address,
			sdp:     c.aSDP.answer,
			contact: buildContact(s.sigIP(cfg), s.sigPort(transport), transport),
			minSE:   cfg.MinSE.Std(),
		}, aTimer)
	}
	if bTimer.weRefresh {
		remote := c.bLeg.InviteRequest.Recipient
		if ct := c.bLeg.InviteResponse.Contact(); ct != nil {
			remote = ct.Address
		}
		go s.refreshLoop(ctx, c, refreshTarget{
			leg:     "b",
			do:      c.bLeg.Do,
			write:   c.bLeg.WriteRequest,
			remote:  remote,
			sdp:     c.bSDP.answer,
			contact: buildContact(s.sigIP(cfg), s.sigPort(c.target.Peer.Transport), c.target.Peer.Transport),
			minSE:   cfg.MinSE.Std(),
		}, bTimer)
	}
}

// ackKey identifies the ACK for a 2xx the SBC sent to an in-dialog INVITE:
// the dialog's Call-ID, the sender's From-tag and the INVITE's CSeq number.
type ackKey struct {
	callID, fromTag string
	cseq            uint32
}

func ackKeyOf(req *sip.Request) ackKey {
	var seq uint32
	if h := req.CSeq(); h != nil {
		seq = h.SeqNo
	}
	return ackKey{callID: fsip.CallID(req), fromTag: fsip.FromTag(req), cseq: seq}
}

// awaitAck registers interest in the ACK for the 2xx to invite. The
// returned channel closes when onAck sees it; done unregisters.
func (s *Server) awaitAck(invite *sip.Request) (acked <-chan struct{}, done func()) {
	k := ackKeyOf(invite)
	ch := make(chan struct{})
	s.ackMu.Lock()
	if s.acks == nil {
		s.acks = make(map[ackKey]chan struct{})
	}
	s.acks[k] = ch
	s.ackMu.Unlock()
	return ch, func() {
		s.ackMu.Lock()
		if s.acks[k] == ch {
			delete(s.acks, k)
		}
		s.ackMu.Unlock()
	}
}

// ackReceived reports whether ack answers a 2xx the SBC is retransmitting
// (see respond2xxUntilAck), and stops that retransmission.
func (s *Server) ackReceived(ack *sip.Request) bool {
	k := ackKeyOf(ack)
	s.ackMu.Lock()
	ch, ok := s.acks[k]
	if ok {
		delete(s.acks, k)
	}
	s.ackMu.Unlock()
	if ok {
		close(ch)
	}
	return ok
}

// errNoAck reports that a 2xx was never ACKed within 64·T1.
var errNoAck = errors.New("no ACK for 2xx")

// respond2xxUntilAck sends res, a 2xx to the in-dialog INVITE req, on the
// raw transaction tx and retransmits it — at T1, doubling up to T2 — until
// the ACK arrives or 64·T1 pass (RFC 3261 §13.3.1.4). This is the UAS
// core's job, which sipgo's DialogServerSession does only for the initial
// INVITE; the trunk answers refreshes on the raw transaction (sipgo's
// ReadInvite is single-use), so it does it here.
func (s *Server) respond2xxUntilAck(req *sip.Request, tx sip.ServerTransaction, res *sip.Response) error {
	acked, done := s.awaitAck(req)
	defer done()
	if err := tx.Respond(res); err != nil {
		return err
	}
	interval := sip.T1
	retransmit := time.NewTimer(interval)
	defer retransmit.Stop()
	giveUp := time.NewTimer(64 * sip.T1)
	defer giveUp.Stop()
	for {
		select {
		case <-acked:
			return nil
		case <-giveUp.C:
			return errNoAck
		case <-retransmit.C:
			if err := tx.Respond(res); err != nil {
				return err
			}
			interval = min(2*interval, sip.T2)
			retransmit.Reset(interval)
		}
	}
}

// refreshAckState is the Server's table of 2xx awaiting their ACK.
type refreshAckState struct {
	ackMu sync.Mutex
	acks  map[ackKey]chan struct{}
}
