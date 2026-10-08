package edge

import (
	"context"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// maxMessageBody caps a MESSAGE body at the size RFC 3428 §5 tells a
// sender to stay under (1300 bytes, so a message fits a UDP datagram). The
// edge refuses a larger one with 413 instead of relaying it, so a
// registered client cannot use the proxy to push large payloads at the
// switch.
const maxMessageBody = 1300

// onMessage proxies a SIP MESSAGE (RFC 3428), the pager-mode instant
// message. Bodies are untouched.
//
//   - A MESSAGE in a dialog (To tag), and any MESSAGE from the switch, goes
//     to onInDialog: the dialog's far end, or for an out-of-dialog message
//     from the switch the client its fsbc= token names (classified there).
//   - A public out-of-dialog MESSAGE must pass admitPublicOutOfDialog: the
//     source holds a live registration, else it is dropped silently and
//     counted (message_not_admitted), or answered 405 from a carrier. It
//     goes to the switch node hashed from the sender, which the switch
//     routes on its own like any request from that user.
//
// The body cap applies to every message the edge would forward, but after
// admission, so an unregistered source still gets silence.
func (s *Server) onMessage(req *sip.Request, tx sip.ServerTransaction, in inbound) {
	if fsip.ToTag(req) != "" || in.private() {
		if tooLargeMessage(req) {
			s.reject(req, tx, 413, "Request Entity Too Large")
			return
		}
		s.onInDialog(req, tx, in)
		return
	}
	switch _, v := s.admitPublicOutOfDialog(req, in.src, dropMessageNotAdmitted); v {
	case oodDropped:
		return
	case oodCarrier:
		s.respond(req, tx, methodNotAllowed(req))
		return
	}
	if tooLargeMessage(req) {
		s.reject(req, tx, 413, "Request Entity Too Large")
		return
	}
	pub, ok := s.publicSideFor(req)
	name, entry, found := s.selectUpstream(hashUserFor(req))
	if !ok || !found {
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	out, err := s.prepareForward(req, pub, s.topo.private, entry.host, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	if len(req.GetHeaders("Contact")) > 0 {
		fsip.SetContact(out, s.topo.private.uri())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	// A response Contact (a 3xx) names the switch; the client must see
	// FreeSBC's public side instead, as for a REFER.
	adapt := func(res *sip.Response) error {
		if len(res.GetHeaders("Contact")) > 0 {
			fsip.SetContact(res, pub.uri())
		}
		return nil
	}
	if _, err := s.forwardAndRelay(ctx, req, tx, out, respPlain, adapt); err != nil {
		s.log.Debug("forward MESSAGE", "err", err, "upstream", name, "sip_call_id", fsip.CallID(req))
		if ctx.Err() != nil {
			s.reject(req, tx, 504, "Server Time-out")
		} else {
			s.reject(req, tx, 503, "Service Unavailable")
		}
	}
}

// tooLargeMessage reports whether a MESSAGE's body (or its declared
// Content-Length) exceeds maxMessageBody.
func tooLargeMessage(req *sip.Request) bool {
	if len(req.Body()) > maxMessageBody {
		return true
	}
	if cl := req.ContentLength(); cl != nil && int(*cl) > maxMessageBody {
		return true
	}
	return false
}
