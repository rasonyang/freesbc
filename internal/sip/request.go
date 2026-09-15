package sip

import (
	"net"
	"strconv"

	"github.com/emiago/sipgo/sip"
)

// Forwardable reports whether a response received on a client transaction
// may be passed back to the requester at all.
//
// A 100 Trying is hop-by-hop: RFC 3261 §16.7 step 2 says a proxy MUST NOT
// forward it. The server transaction generates its own 100 for the
// requester, so forwarding the far end's would be both redundant and — for
// a switch that sends it with a single Via — unroutable.
func Forwardable(res *sip.Response) bool { return res.StatusCode != 100 }

// BuildCancel constructs a CANCEL for a request this element sent, per
// RFC 3261 §9.1: same Request-URI, same top Via (branch included), same
// Call-ID, From, To and CSeq number with the method changed. Transport,
// destination and local address are copied so the CANCEL leaves by the
// same path as the INVITE it cancels, which is what lets the far side's
// transaction layer match it.
func BuildCancel(invite *sip.Request) *sip.Request {
	c := sip.NewRequest(sip.CANCEL, invite.Recipient)
	c.SipVersion = invite.SipVersion
	if v := invite.Via(); v != nil {
		c.AppendHeader(sip.HeaderClone(v))
	}
	sip.CopyHeaders("Route", invite, c)
	mf := sip.MaxForwardsHeader(70)
	c.AppendHeader(&mf)
	sip.CopyHeaders("From", invite, c)
	sip.CopyHeaders("To", invite, c)
	sip.CopyHeaders("Call-ID", invite, c)
	if cseq := invite.CSeq(); cseq != nil {
		nc := sip.CSeqHeader{SeqNo: cseq.SeqNo, MethodName: sip.CANCEL}
		c.AppendHeader(&nc)
	}
	c.SetBody(nil)
	c.SetTransport(invite.Transport())
	c.SetDestination(invite.Destination())
	c.Laddr = invite.Laddr
	return c
}

// CSeqNumber returns a message's CSeq sequence number, or 1 when the
// header is missing — the RFC 3261 §8.1.1.5 starting value, and the only
// sequence a dialog built from a message without one could be at.
func CSeqNumber(msg sip.Message) uint32 {
	if c := msg.CSeq(); c != nil {
		return c.SeqNo
	}
	return 1
}

// TeardownRequest builds the in-dialog ACK or BYE that finishes and then
// ends a dialog established by res, a 2xx to an INVITE (RFC 3261 §13.2.2.4
// and §15.1.1). The dialog identifiers are copied from the response, which
// carries the established From/To tags and the Call-ID; via is the single
// Via of the element sending it, and seq the CSeq number this request
// takes — the INVITE's own for the ACK, the next one for the BYE.
//
// It is for a dialog the element tracks itself. Where a dialog is owned by
// sipgo's DialogClientSession, its Ack and Bye methods must be used
// instead: they hold the route set and the remote target this function
// does not see.
func TeardownRequest(method sip.RequestMethod, res *sip.Response, via sip.Header, seq uint32) *sip.Request {
	req := sip.NewRequest(method, ContactOrSource(res))
	req.PrependHeader(via)
	sip.CopyHeaders("From", res, req)
	sip.CopyHeaders("To", res, req)
	sip.CopyHeaders("Call-ID", res, req)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: method})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.SetTransport(res.Transport())
	req.SetDestination(res.Source())
	return req
}

// ContactOrSource is the request target for an in-dialog request built
// from a response: the far end's Contact when it sent one (RFC 3261
// §12.1.2 remote target), else its transport source rendered as a URI,
// which is where the response demonstrably came from.
func ContactOrSource(res *sip.Response) sip.Uri {
	if u, ok := ContactURI(res); ok {
		return u
	}
	host, portStr, err := net.SplitHostPort(res.Source())
	if err != nil {
		return sip.Uri{Host: res.Source()}
	}
	port, _ := strconv.Atoi(portStr)
	return sip.Uri{Host: host, Port: port}
}
