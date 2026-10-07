package edge

import (
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// This file holds the delayed-offer exchanges (RFC 3261 §13.2.1, RFC 3262
// §5): an INVITE or re-INVITE without SDP, whose offer is the callee's
// first SDP, in the 2xx or in a reliable 18x, and whose answer is the
// caller's, in the ACK or in the PRACK.
//
// FreeSBC is neither offerer nor answerer, so it relays the offer, built
// like any other body (the existing offer builders, or rebuildInDialogOffer
// in a confirmed dialog), and records that an answer is still owed
// (dialog.owed). The answer arrives later from the other side and is
// negotiated against the offer FreeSBC relayed and rebuilt toward the
// callee with rebuildInDialogAnswer; only then is the media pointed
// (applyReInvite), so nothing is latched or sent before the answer is
// applied. Nothing is ever copied from one side's body into the other's.
//
// An ACK cannot be refused. When the answer it carries is missing or
// unusable it is forwarded without a body and both ends are ended, as for
// a 2xx FreeSBC cannot anchor (ackThenBye); when it never arrives, the
// same happens after ackTimeout.

// errOfferTwice reports a second offer in a call whose session is already
// allocated: another fork's 2xx or reliable 18x of an offerless INVITE.
var errOfferTwice = errors.New("proxy: a second offer in an offerless call")

// owedAnswer is the answer FreeSBC owes the callee: the callee's offer as
// parsed, who made it and who answers, and where the answer may arrive.
type owedAnswer struct {
	offer             *sdp.Session // the callee's offer
	offerer, answerer plane

	// fork is the early fork the offer was relayed on, set while the
	// offer is in a reliable 18x (the answer then rides the PRACK);
	// nil for an offer in a 2xx. cseq is the CSeq number of the INVITE
	// the offer answers, which the ACK must carry.
	fork *earlyFork
	cseq uint32

	// release frees the dialog's offer slot (a re-INVITE holds one until
	// the ACK); timer is the Timer H style backstop for a lost ACK.
	release func()
	timer   *time.Timer
}

// finish stops the backstop and frees the offer slot once the answer has
// been taken.
func (o *owedAnswer) finish() {
	if o.timer != nil {
		o.timer.Stop()
	}
	if o.release != nil {
		o.release()
	}
}

// ackAnswer is the answer an ACK carried, as rebuilt for the callee, with
// the plane that sent it and the CSeq it answered.
type ackAnswer struct {
	answerer plane
	cseq     uint32
	body     []byte
}

// setOwed records the answer the dialog owes, ending any earlier exchange's
// restatement.
func (d *dialog) setOwed(o *owedAnswer) {
	d.tab.mu.Lock()
	d.owed = o
	d.lastAck = nil
	d.tab.mu.Unlock()
}

// setAckAnswer remembers the body an owed answer was rebuilt into.
func (d *dialog) setAckAnswer(answerer plane, cseq uint32, body []byte) {
	d.tab.mu.Lock()
	d.lastAck = &ackAnswer{answerer: answerer, cseq: cseq, body: body}
	d.tab.mu.Unlock()
}

// ackAnswerFor is the rebuilt answer a retransmitted ACK for cseq from the
// answerer plane is restated with, or nil.
func (d *dialog) ackAnswerFor(answerer plane, cseq uint32) []byte {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	if a := d.lastAck; a != nil && a.answerer == answerer && a.cseq == cseq {
		return a.body
	}
	return nil
}

// takeOwed removes and returns the owed answer when it is one the answerer
// plane's ACK for cseq carries, else nil.
func (d *dialog) takeOwed(answerer plane, cseq uint32) *owedAnswer {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	o := d.owed
	if o == nil || o.answerer != answerer || o.cseq != cseq {
		return nil
	}
	d.owed = nil
	return o
}

// owedForPrack is the owed answer a PRACK from the answerer plane may
// carry: the one whose offer rode a reliable 18x on the fork its tags name.
func (d *dialog) owedForPrack(req *sip.Request, answerer plane) *owedAnswer {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	o := d.owed
	if o == nil || o.fork == nil || o.answerer != answerer || o.fork != d.forkOfLocked(req) {
		return nil
	}
	return o
}

// dropOwed clears o when it is still the owed answer.
func (d *dialog) dropOwed(o *owedAnswer) bool {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	if d.owed != o {
		return false
	}
	d.owed = nil
	return true
}

// owedOnFork reports whether f carries an offer whose answer is still owed.
func (d *dialog) owedOnFork(f *earlyFork) bool {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	return d.owed != nil && d.owed.fork == f
}

// adoptOrigin makes f's o= identity continue the one the dialog already
// used toward plane, so a body built for the caller before the fork is
// confirmed and the ones after it count up from the same version.
func (d *dialog) adoptOrigin(f *earlyFork, p plane) {
	d.tab.mu.Lock()
	f.origin = d.origin[p]
	d.tab.mu.Unlock()
}

// armOwedTimer starts the backstop for an answer still owed once the
// dialog is confirmed: the callee gives up on its 2xx after Timer H, and so
// does FreeSBC, ending both ends rather than leaving a session whose
// offer/answer never completed.
func (s *Server) armOwedTimer(d *dialog) {
	d.tab.mu.Lock()
	defer d.tab.mu.Unlock()
	o := d.owed
	if o == nil || o.timer != nil || d.state != dialogConfirmed {
		return
	}
	o.timer = time.AfterFunc(s.ackBudget(), func() { s.owedExpired(d, o) })
}

func (s *Server) owedExpired(d *dialog, o *owedAnswer) {
	if !d.dropOwed(o) {
		return
	}
	if o.release != nil {
		o.release()
	}
	s.log.Warn("answer to a delayed offer never arrived; ending the call", "sip_call_id", d.callID)
	if d.end() {
		s.byeBothEnds(d)
	}
}

// prepareOwed validates the answer body and rebuilds it for the callee. It
// changes no media; applyOwed does, once the answer is accepted.
func (s *Server) prepareOwed(d *dialog, o *owedAnswer, body []byte) ([]byte, *sdp.Session, error) {
	if len(body) == 0 {
		return nil, nil, errNoAnswer
	}
	if d.session() == nil {
		return nil, nil, errNoAnswer
	}
	out, answer, err := s.rebuildInDialogAnswer(d, o.fork, o.offer, body, o.offerer)
	if err != nil {
		return nil, nil, err
	}
	if sess := d.session(); sess.webrtc != nil && o.answerer == planePublic {
		// The browser answers FreeSBC's DTLS-SRTP offer.
		if err := checkOfferedWebRTC(answer); err != nil {
			return nil, nil, err
		}
	}
	return out, answer, nil
}

// applyOwed completes the exchange: the browser leg is started, and the
// media follows the offer's and the answer's addresses.
func (s *Server) applyOwed(d *dialog, o *owedAnswer, answer *sdp.Session) error {
	if sess := d.session(); sess.webrtc != nil && o.answerer == planePublic {
		if err := s.startOfferedWebRTC(sess.webrtc, answer); err != nil {
			return err
		}
	}
	s.applyReInvite(d, o.offerer, o.offer, o.answerer, answer)
	if o.fork != nil {
		d.noteForkAnswered(o.fork, o.offer)
	}
	return nil
}

// noteForkAnswered records on an early fork that the answer to its offer
// was applied: the callee's media address and codecs are what its offer
// said, and the media follows this fork from here on, so a retransmitted
// 18x or the 2xx restates the offer already relayed.
func (d *dialog) noteForkAnswered(f *earlyFork, offer *sdp.Session) {
	var remote, rtcp netip.AddrPort
	if a := offer.Audio; a.Address.IsValid() && !a.Address.IsUnspecified() && a.Port > 0 {
		remote = netip.AddrPortFrom(a.Address, uint16(a.Port))
		if a.RTCPPort > 0 {
			rtcp = netip.AddrPortFrom(a.Address, uint16(a.RTCPPort))
		}
	}
	d.tab.mu.Lock()
	body := f.answer
	d.tab.mu.Unlock()
	d.noteForkUpdate(f, body, remote, rtcp, d.session().negotiated())
}

// answerFromACK handles the ACK that should carry the owed answer: it
// returns the body the callee's ACK carries instead. On an error the ACK is
// still forwarded, without a body, and the caller ends the call.
func (s *Server) answerFromACK(d *dialog, o *owedAnswer, body []byte) ([]byte, error) {
	out, answer, err := s.prepareOwed(d, o, body)
	if err != nil {
		return nil, err
	}
	if err := s.applyOwed(d, o, answer); err != nil {
		return nil, err
	}
	return out, nil
}

// offerlessFork is forkAnswer for a call whose INVITE carried no SDP. The
// first SDP of the callee that is an offer — in a reliable 18x or in the 2xx
// — allocates the session and is relayed to the caller as a constructed
// offer; an answer is then owed. An SDP in an unreliable 18x is not an
// offer the caller can answer (RFC 3261 §13.2.1 wants it in a reliable
// message), so, as practice has it, the offer is the one in the 2xx or the
// reliable 18x: the body is dropped from the relayed 18x, and no media is
// touched.
//
// It returns nil, nil for a response that carries no body to the caller.
func (s *Server) offerlessFork(l *inviteLeg, f *earlyFork, res *sip.Response) ([]byte, error) {
	d := l.dialog()
	is2xx := res.StatusCode/100 == 2
	if len(res.Body()) == 0 {
		if !is2xx {
			return nil, nil
		}
		// A body-less 2xx on a fork that never offered: the offer rode
		// another fork's response, and the session follows that one.
		if a := d.lastApplied(); a != nil {
			return d.forkAnswer(a), nil
		}
		return nil, errNoAnswer
	}
	if !is2xx && !requiresTag(res, "100rel") {
		return nil, nil
	}
	if d.session() != nil {
		return nil, errOfferTwice
	}
	offer, err := l.offerless(res.Body())
	if err != nil {
		return nil, err
	}
	callerPlane := otherPlane(l.callee.calleePlane())
	d.setForkAnswer(f, offer.sdp, nil, netip.AddrPort{}, netip.AddrPort{})
	d.adoptOrigin(f, callerPlane)
	o := &owedAnswer{offer: offer.offer, offerer: l.callee.calleePlane(), answerer: callerPlane,
		cseq: fsip.CSeqNumber(l.req)}
	if !is2xx {
		o.fork = f
	}
	d.setOwed(o)
	return offer.sdp, nil
}

// requiresTag reports whether any Require header of m lists tag.
func requiresTag(m headerSet, tag string) bool {
	for _, h := range m.GetHeaders("Require") {
		for _, tok := range strings.Split(h.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(tok), tag) {
				return true
			}
		}
	}
	return false
}

// stripBody removes the body and its Content-Type from a message.
func stripBody(m interface {
	SetBody([]byte)
	RemoveHeader(string) bool
}) {
	m.SetBody(nil)
	m.RemoveHeader("Content-Type")
}

// isSDPBody reports whether m's Content-Type is SDP.
func isSDPBody(m headerSet) bool {
	for _, h := range m.GetHeaders("Content-Type") {
		if strings.Contains(strings.ToLower(h.Value()), "application/sdp") {
			return true
		}
	}
	return false
}
