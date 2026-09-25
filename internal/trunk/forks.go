package trunk

import (
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Forked B-leg answers (RFC 3261 §13.2.2.4, §12.1).
//
// A carrier (or a proxy behind it) may fork the B-leg INVITE, so several
// 2xx with different To-tags can come back for one request. sipgo v1.4.3's
// DialogClientSession follows only the first: WaitAnswer returns on it, and
// every later 2xx for the same transaction goes to the transaction's
// retransmission hook, which only re-sends the winning dialog's ACK. The
// other forks would never be ACKed or BYEd, and would stay up (and billing)
// until their own 64·T1 timeout.
//
// forkWatch closes that gap without reaching into sipgo: the trunk
// registers an extra transport-layer message handler (Server.observeMessage,
// installed in Run), which sees every parsed response alongside the
// transaction layer. For each B-leg attempt a forkWatch is registered
// under the attempt's own (Call-ID, From-tag) before its INVITE is sent.
// Once the attempt knows which 2xx it acted on (decide, called by the
// waiter goroutine when WaitAnswer returns), every other 2xx To-tag on the
// attempt is ACKed and then BYEd. A 2xx that arrives before the decision
// is held until it. The watch lives for 64·T1 after the decision, which is
// as long as the INVITE client transaction accepts 2xx (Timer M).

// forkKey identifies one B-leg INVITE: our Call-ID and our From-tag.
type forkKey struct {
	callID, fromTag string
}

// forkWatch is the fork state of one B-leg attempt.
type forkWatch struct {
	s      *Server
	key    forkKey
	target string

	mu      sync.Mutex
	invite  *sip.Request // the B-leg INVITE as sent (From, Call-ID, transport)
	decided bool
	winner  string                  // To-tag of the 2xx the attempt acted on; "" if none
	pending []*sip.Response         // 2xx seen before decide
	acked   map[string]*sip.Request // fork To-tag → the ACK we sent it
}

// watchForks registers a forkWatch under key, before the INVITE carrying
// that Call-ID and From-tag is sent. The caller sets the request with
// setInvite once it exists and must call decide exactly once.
func (s *Server) watchForks(key forkKey, target string) *forkWatch {
	fw := &forkWatch{
		s:      s,
		key:    key,
		target: target,
		acked:  make(map[string]*sip.Request),
	}
	s.forkMu.Lock()
	if s.forks == nil {
		s.forks = make(map[forkKey]*forkWatch)
	}
	s.forks[fw.key] = fw
	s.forkMu.Unlock()
	return fw
}

// setInvite records the INVITE as sent, which ACKs and BYEs to losing
// forks are built from.
func (fw *forkWatch) setInvite(invite *sip.Request) {
	fw.mu.Lock()
	fw.invite = invite
	fw.mu.Unlock()
}

// observeMessage is the transport-layer hook: it hands every 2xx to an
// INVITE that belongs to a watched B-leg attempt to that attempt's
// forkWatch. It runs on the transport read loop, so it only does a map
// lookup and never blocks on the network.
func (s *Server) observeMessage(msg sip.Message) {
	res, ok := msg.(*sip.Response)
	if !ok || !res.IsSuccess() {
		return
	}
	if cseq := res.CSeq(); cseq == nil || cseq.MethodName != sip.INVITE {
		return
	}
	key := forkKey{callID: fsip.CallID(res), fromTag: fsip.FromTag(res)}
	s.forkMu.Lock()
	fw := s.forks[key]
	s.forkMu.Unlock()
	if fw != nil {
		fw.observe(res)
	}
}

// observe handles one 2xx on the watched attempt.
func (fw *forkWatch) observe(res *sip.Response) {
	tag := fsip.ToTag(res)
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if !fw.decided {
		for _, p := range fw.pending {
			if fsip.ToTag(p) == tag {
				return // a retransmission of a 2xx already held
			}
		}
		fw.pending = append(fw.pending, res)
		return
	}
	fw.handleLocked(res)
}

// decide records the To-tag of the 2xx the attempt itself acted on ("" when
// it acted on none) and tears down every other fork seen so far. The watch
// then expires after 64·T1. Only the first call counts, so a deferred
// decide("") can back up the normal one.
func (fw *forkWatch) decide(winner string) {
	fw.mu.Lock()
	if fw.decided {
		fw.mu.Unlock()
		return
	}
	fw.decided = true
	fw.winner = winner
	pending := fw.pending
	fw.pending = nil
	for _, res := range pending {
		fw.handleLocked(res)
	}
	fw.mu.Unlock()
	time.AfterFunc(64*sip.T1, func() {
		fw.s.forkMu.Lock()
		if fw.s.forks[fw.key] == fw {
			delete(fw.s.forks, fw.key)
		}
		fw.s.forkMu.Unlock()
	})
}

// handleLocked ACKs and BYEs a losing fork's 2xx, or re-sends its ACK when
// the 2xx is a retransmission (the UAC core, not the transaction, owns 2xx
// ACK retransmission — RFC 3261 §13.2.2.4). Caller holds fw.mu.
func (fw *forkWatch) handleLocked(res *sip.Response) {
	tag := fsip.ToTag(res)
	if tag == "" || tag == fw.winner || fw.invite == nil {
		return
	}
	if ack, ok := fw.acked[tag]; ok {
		go fw.send(ack.Clone(), nil)
		return
	}
	ack := fw.inDialogRequest(sip.ACK, res, 0)
	fw.acked[tag] = ack
	fw.s.log.Info("tearing down forked b-leg answer", "target", fw.target, "call_id", fw.key.callID, "to_tag", tag)
	go fw.send(ack.Clone(), fw.inDialogRequest(sip.BYE, res, 1))
}

// inDialogRequest builds an ACK (cseqDelta 0) or BYE (cseqDelta 1) on the
// fork's dialog: our From and Call-ID, the fork's To (with its tag), sent to
// the fork's Contact. Like sipgo's own ACK/BYE for the winning leg, it does
// not build a route set from Record-Route.
func (fw *forkWatch) inDialogRequest(method sip.RequestMethod, res *sip.Response, cseqDelta uint32) *sip.Request {
	recipient := fw.invite.Recipient
	if c := res.Contact(); c != nil {
		recipient = c.Address
	}
	req := sip.NewRequest(method, *recipient.Clone())
	req.SipVersion = fw.invite.SipVersion
	if h := fw.invite.From(); h != nil {
		req.AppendHeader(sip.HeaderClone(h))
	}
	if h := res.To(); h != nil {
		req.AppendHeader(sip.HeaderClone(h))
	}
	if h := fw.invite.CallID(); h != nil {
		req.AppendHeader(sip.HeaderClone(h))
	}
	var seq uint32
	if h := res.CSeq(); h != nil {
		seq = h.SeqNo
	}
	req.AppendHeader(&sip.CSeqHeader{SeqNo: seq + cseqDelta, MethodName: method})
	maxFwd := sip.MaxForwardsHeader(70)
	req.AppendHeader(&maxFwd)
	req.SetTransport(fw.invite.Transport())
	return req
}

// send writes the ACK and then, when bye is non-nil, sends the BYE as a
// transaction bounded by byeContext. Errors are logged: nothing else can be
// done for a fork we never wanted.
func (fw *forkWatch) send(ack, bye *sip.Request) {
	client := fw.s.client
	if client == nil {
		return
	}
	if err := client.WriteRequest(ack); err != nil {
		fw.s.log.Debug("ack forked b-leg answer", "err", err, "target", fw.target)
		return
	}
	if bye == nil {
		return
	}
	ctx, cancel := byeContext()
	defer cancel()
	if _, err := client.Do(ctx, bye); err != nil {
		fw.s.log.Debug("bye forked b-leg answer", "err", err, "target", fw.target)
	}
}
