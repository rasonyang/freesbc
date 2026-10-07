package edge

import (
	"errors"
	"net/netip"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// errOfferPending reports an UPDATE offer that arrived while another offer
// of the dialog is outstanding; the requester is answered 491.
var errOfferPending = errors.New("proxy: another offer is pending in this dialog")

// updateExchange is the offer/answer of one UPDATE that carries SDP
// (RFC 3311). It runs on the re-INVITE helpers: the offer is rebuilt with
// rebuildInDialogOffer on the way out and the answer in the 2xx with
// rebuildInDialogAnswer, and the media is moved with applyReInvite once
// the 2xx has been relayed. Nothing passes through unmodified, so a
// carrier leg sees FreeSBC's bodies only, and a non-2xx answer changes
// nothing.
//
// In an early dialog the exchange belongs to one fork (fork is set); the
// session is the one allocated for the INVITE and the fork's state is
// updated with the outcome (dialog.noteForkUpdate), so the INVITE's 2xx and
// any retransmitted 18x on that fork agree with it.
type updateExchange struct {
	s    *Server
	d    *dialog
	fork *earlyFork // nil in a confirmed dialog

	offerer, answerer plane
	offer             *sdp.Session // the offer as the requester sent it
	offerBody         []byte       // what goes to the far end instead
}

// beginUpdate admits an UPDATE with SDP: it claims the dialog's offer slot
// (errOfferPending when taken) and rebuilds the offer for the far side.
// The caller must call end when the exchange is over.
func (s *Server) beginUpdate(req *sip.Request, d *dialog, from, to side) (*updateExchange, error) {
	if d.session() == nil {
		return nil, errNoAnswer
	}
	if !d.beginUpdateOffer() {
		return nil, errOfferPending
	}
	x := &updateExchange{s: s, d: d, fork: d.forkOf(req), offerer: from.plane, answerer: to.plane}
	body, offer, err := s.rebuildInDialogOffer(d, x.fork, req.Body(), to.plane)
	if err != nil {
		d.endUpdateOffer()
		return nil, err
	}
	x.offer, x.offerBody = offer, body
	return x, nil
}

// end releases the offer slot.
func (x *updateExchange) end() { x.d.endUpdateOffer() }

// answered rewrites the far end's 2xx to the UPDATE for the requester and
// applies the exchange to the media. relayed is the clone about to be sent.
// A 2xx without a body is passed as it is: there is no answer to apply.
func (x *updateExchange) answered(relayed *sip.Response) error {
	if len(relayed.Body()) == 0 {
		return nil
	}
	answer, parsed, err := x.s.rebuildInDialogAnswer(x.d, x.fork, x.offer, relayed.Body(), x.offerer)
	if err != nil {
		return err
	}
	fsip.SetSDPBody(relayed, answer)
	x.s.applyReInvite(x.d, x.offerer, x.offer, x.answerer, parsed)
	if x.fork != nil {
		x.noteFork(answer, parsed)
	}
	return nil
}

// noteFork records the outcome on the early fork. The caller-facing body is
// the answer when the caller made the offer and the rebuilt offer when the
// callee did; the callee's address is whichever of the two it signalled.
func (x *updateExchange) noteFork(answerToOfferer []byte, answer *sdp.Session) {
	callerBody, callee := answerToOfferer, answer
	if x.offerer != x.d.callerPlane {
		callerBody, callee = x.offerBody, x.offer
	}
	var remote, rtcp netip.AddrPort
	if a := callee.Audio; a.Address.IsValid() && !a.Address.IsUnspecified() && a.Port > 0 {
		remote = netip.AddrPortFrom(a.Address, uint16(a.Port))
		if a.RTCPPort > 0 {
			rtcp = netip.AddrPortFrom(a.Address, uint16(a.RTCPPort))
		}
	}
	x.d.noteForkUpdate(x.fork, callerBody, remote, rtcp, x.d.session().negotiated())
}
