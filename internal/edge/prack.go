package edge

import (
	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// onPrackUpdate admits a PRACK (RFC 3262) or UPDATE (RFC 3311) and hands it
// to onInDialog, which forwards it by the dialog its tags name and relays
// the answer, with carrier hiding like any in-dialog request. RAck, RSeq
// and CSeq are end-to-end values and are not rewritten.
//
// Both are valid in an early dialog (a reliable 18x is PRACKed before any
// 2xx), so the dialog is looked up among the early forks too (directionFor).
// Both are refused with 481 unless a dialog FreeSBC holds matches the tags:
// there is no fallback by hashing, because a request outside any dialog has
// nothing to be PRACKed or refreshed.
//
// An UPDATE that carries SDP is an offer and is handled by onInDialog with
// the re-INVITE helpers (update.go). A PRACK that carries SDP is the answer
// to the offer of a reliable 18x in an offerless INVITE (offerless.go): it
// is rebuilt for the callee and the media follows it, when such an answer
// is owed on the fork its tags name. A PRACK with SDP that answers no
// pending offer would be a new offer, and an offer in a PRACK is not
// handled (RFC 3262 allows it only as a later exchange of the same kind as
// an UPDATE, which UPDATE already serves): it is answered 488, never
// forwarded unchanged, and the dialog is left untouched. A body-less PRACK
// is forwarded whatever is owed; the answer may still arrive in the ACK.
func (s *Server) onPrackUpdate(req *sip.Request, tx sip.ServerTransaction, in inbound) {
	if fsip.ToTag(req) == "" {
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	from, _, _, d, ok := s.directionFor(req, in.private())
	if !ok || d == nil {
		s.reject(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	if req.Method == sip.PRACK && len(req.Body()) > 0 && d.owedForPrack(req, from.plane) == nil {
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}
	s.onInDialog(req, tx, in)
}
