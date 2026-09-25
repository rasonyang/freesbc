package sip

import (
	"net"
	"strconv"
	"strings"

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
// The request follows the dialog's route set: the response's Record-Route
// list reversed (§12.1.2), sent per §12.2.1.1. With a loose router first
// (lr) the Request-URI is the remote target and every route is a Route
// header; with a strict router first the Request-URI is that route and the
// remote target goes last in the Route list. Either way the request is
// sent to the first route. With no route set it goes to the remote target,
// addressed to the transport source of res, where the far end
// demonstrably is.
//
// opts adjust it for the element sending it: OwnRecordRoute to leave out
// the Record-Route entries that element added itself, FromListener to pin
// the socket it leaves by.
//
// It is for a dialog the element tracks itself. Where a dialog is owned by
// sipgo's DialogClientSession, its Ack and Bye methods must be used
// instead.
func TeardownRequest(method sip.RequestMethod, res *sip.Response, via sip.Header, seq uint32, opts ...TeardownOption) *sip.Request {
	var o teardownOptions
	for _, opt := range opts {
		opt(&o)
	}
	target := contactOrSource(res)
	routes := routeSet(res, o.isSelf)

	ruri := target
	var routeHdrs []sip.Uri
	if len(routes) > 0 {
		if _, lr := routes[0].UriParams.Get("lr"); lr {
			routeHdrs = routes
		} else {
			ruri = routes[0]
			routeHdrs = append(append([]sip.Uri(nil), routes[1:]...), target)
		}
	}

	req := sip.NewRequest(method, ruri)
	req.PrependHeader(via)
	for _, u := range routeHdrs {
		req.AppendHeader(&sip.RouteHeader{Address: u})
	}
	sip.CopyHeaders("From", res, req)
	sip.CopyHeaders("To", res, req)
	sip.CopyHeaders("Call-ID", res, req)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: method})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.SetTransport(res.Transport())
	if len(routes) > 0 {
		if t, ok := routes[0].UriParams.Get("transport"); ok && t != "" {
			req.SetTransport(strings.ToUpper(t))
		}
		req.SetDestination(uriHostPort(routes[0], req.Transport()))
	} else {
		req.SetDestination(res.Source())
	}
	req.Laddr = o.laddr
	return req
}

// TeardownOption adjusts a TeardownRequest for the element sending it.
type TeardownOption func(*teardownOptions)

type teardownOptions struct {
	isSelf func(sip.Uri) bool
	laddr  sip.Addr
}

// OwnRecordRoute names the Record-Route entries the sending element added
// itself. A proxy that record-routed the INVITE sits in the response's
// Record-Route list; when it then sends the ACK/BYE itself, its route set
// is only the part of the list beyond it (the entries above its own), so
// every entry from its first own one down is left out.
func OwnRecordRoute(isSelf func(sip.Uri) bool) TeardownOption {
	return func(o *teardownOptions) { o.isSelf = isSelf }
}

// FromListener pins the socket the request leaves by: sipgo's transport
// layer reuses the listener bound at laddr (TransportLayer.
// ClientRequestConnection), so the ACK/BYE comes from the address the far
// end already talks to instead of a fresh ephemeral socket. A zero laddr
// leaves the choice to sipgo, which is right for a WebSocket client, whose
// one connection is found by its remote address.
func FromListener(laddr sip.Addr) TeardownOption {
	return func(o *teardownOptions) { o.laddr = laddr }
}

// routeSet is the UAC route set a 2xx establishes (RFC 3261 §12.1.2): its
// Record-Route list in reverse. With isSelf, the list is cut at the first
// entry isSelf claims, keeping only the entries above it.
func routeSet(res *sip.Response, isSelf func(sip.Uri) bool) []sip.Uri {
	var rr []sip.Uri
	for _, h := range res.GetHeaders("Record-Route") {
		r, ok := h.(*sip.RecordRouteHeader)
		if !ok {
			continue
		}
		if isSelf != nil && isSelf(r.Address) {
			break
		}
		rr = append(rr, *r.Address.Clone())
	}
	for i, j := 0, len(rr)-1; i < j; i, j = i+1, j-1 {
		rr[i], rr[j] = rr[j], rr[i]
	}
	return rr
}

// uriHostPort is where a request routed by u over transport is sent: its
// host and port, the port defaulting by transport.
func uriHostPort(u sip.Uri, transport string) string {
	port := u.Port
	if port == 0 {
		port = DefaultPort(transport)
	}
	return net.JoinHostPort(strings.Trim(u.Host, "[]"), strconv.Itoa(port))
}

// contactOrSource is the request target for an in-dialog request built
// from a response: the far end's Contact when it sent one (RFC 3261
// §12.1.2 remote target), else its transport source rendered as a URI,
// which is where the response demonstrably came from.
func contactOrSource(res *sip.Response) sip.Uri {
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
