package proxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// This file holds the RFC 3261 §16 proxy mechanics: Via insertion and
// removal, Record-Route, Route-set processing, and the response relay.
//
// The rule that shapes all of it: FreeSBC is a proxy, so Call-ID, From,
// To, CSeq and every tag pass through byte-for-byte. Only the hop-by-hop
// headers — Via, Route, Record-Route, Max-Forwards, Contact — are the
// proxy's to touch, plus the SDP body, which it must rewrite because it
// anchors the media.

// errMaxForwards is returned when a request has looped enough.
var errMaxForwards = errors.New("proxy: max forwards reached")

// newBranch generates an RFC 3261 magic-cookie branch.
func newBranch() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("proxy: crypto/rand failed: " + err.Error())
	}
	return "z9hG4bK" + base64.RawURLEncoding.EncodeToString(b[:])
}

// prepareForward turns an inbound request into the request FreeSBC will
// send on the far side. It returns the new request; the caller sets the
// body and sends it.
//
// Steps, in RFC 3261 §16.6 order:
//  1. clone, so the inbound request stays intact for the response path;
//  2. record the sender's real source in ITS Via (received/rport), which
//     is what lets the response find its way back through NAT;
//  3. strip our own Route values (we are the hop they name);
//  4. decrement Max-Forwards and refuse a looped request;
//  5. add Record-Route so in-dialog traffic keeps traversing us;
//  6. add our own Via with a fresh branch;
//  7. pin the outbound socket and destination.
func (s *Server) prepareForward(req *sip.Request, from, to side, dest string, recordRoute bool) (*sip.Request, error) {
	out := req.Clone()

	annotateVia(out, req.Source())
	s.stripOwnRoutes(out)

	if mf := out.MaxForwards(); mf != nil {
		mf.Dec()
		if mf.Val() <= 0 {
			return nil, errMaxForwards
		}
	} else {
		h := sip.MaxForwardsHeader(70)
		out.AppendHeader(&h)
	}

	if recordRoute {
		// RFC 5658 double Record-Route: the two sides of this proxy speak
		// different transports (ws/wss on the public side, udp on the
		// private one), so ONE Record-Route value cannot describe both.
		//
		// Order is what makes it work. A UAS builds its route set from the
		// request's Record-Route list in order (RFC 3261 §12.1.1), so the
		// TOP value must name the interface facing the request's
		// DESTINATION. A UAC builds its route set from the response's list
		// in reverse (§12.1.2), so the BOTTOM value must name the
		// interface facing the request's ORIGIN. Prepending the origin's
		// value first and the destination's second lands them that way
		// round.
		out.PrependHeader(from.recordRoute())
		out.PrependHeader(to.recordRoute())
	}

	out.PrependHeader(to.via(newBranch()))

	out.SetTransport(strings.ToUpper(to.transport))
	out.SetDestination(dest)
	if to.laddr.IP != nil && to.laddr.Port > 0 {
		// Pin the sending socket. sipgo's transport layer looks a
		// connection up by this local address first (see
		// TransportLayer.ClientRequestConnection), which is how a request
		// toward a UDP phone leaves through the same public listener the
		// phone's NAT pinhole points at, and a request toward FreeSWITCH
		// leaves through the private socket FreeSWITCH already talks to.
		out.Laddr = to.laddr
	} else {
		out.Laddr = sip.Addr{}
	}
	return out, nil
}

// annotateVia fills in received and rport on the request's TOP Via — the
// one the previous hop added — per RFC 3261 §18.2.1 and RFC 3581 §4.
// Without it a response cannot be routed back to a client behind NAT,
// because the client's own Via names an address the NAT does not map.
func annotateVia(req *sip.Request, source string) {
	via := req.Via()
	if via == nil {
		return
	}
	host, port, err := net.SplitHostPort(source)
	if err != nil {
		return
	}
	if via.Params == nil {
		via.Params = sip.NewParams()
	}
	if via.Host != host {
		via.Params.Add("received", host)
	}
	// rport is only filled when the client asked for it (an empty rport
	// parameter is the request); inventing one otherwise would change the
	// meaning of the header.
	if v, ok := via.Params.Get("rport"); ok && v == "" {
		via.Params.Add("rport", port)
	}
}

// stripOwnRoutes removes leading Route values that name FreeSBC itself.
// There may be two of them (see the double Record-Route above), and after
// a transport change the pair is exactly what an in-dialog request from
// either endpoint carries.
func (s *Server) stripOwnRoutes(req *sip.Request) {
	for {
		r := req.Route()
		if r == nil || !s.topo.isSelf(r.Address) {
			return
		}
		req.RemoveHeader("Route")
	}
}

// noBuild is a ClientRequestOption that does nothing.
//
// Passing any option to sipgo's TransactionRequest suppresses its default
// request-building pass, which would otherwise add its own Via, From, To,
// Call-ID and CSeq. A proxy must send exactly the headers it assembled —
// especially the Via it built and the Call-ID it is forwarding unchanged —
// so "do nothing" is precisely the behaviour wanted.
func noBuild(*sipgo.Client, *sip.Request) error { return nil }

// relayResponse forwards one response from a client transaction back
// through the server transaction.
//
// The top Via is ours and must come off (RFC 3261 §16.7 step 3); what is
// underneath is the requester's own Via, which the response then routes
// by. Everything else — status, tags, Contact, body — is the far end's and
// is left alone, apart from the Contact and SDP rewriting the caller does.
func (s *Server) relayResponse(orig *sip.Request, tx sip.ServerTransaction, res *sip.Response) error {
	out := res.Clone()
	out.RemoveHeader("Via") // ours
	out.SetDestination(orig.Source())
	s.metrics.ResponseOut(out.StatusCode)
	return tx.Respond(out)
}

// forwardAndRelay is the whole stateful-proxy loop for a non-INVITE
// request: send it on, pump every response back, return the final one.
//
// It blocks until a final response, the transaction dies, or ctx is
// cancelled — which is correct for a handler goroutine: sipgo runs each
// request on its own goroutine, and the transaction layer, not this loop,
// owns retransmission.
func (s *Server) forwardAndRelay(ctx context.Context, req *sip.Request, tx sip.ServerTransaction, out *sip.Request) (*sip.Response, error) {
	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
	if err != nil {
		return nil, fmt.Errorf("proxy: forward %s: %w", out.Method, err)
	}
	defer clTx.Terminate()
	for {
		select {
		case res, ok := <-clTx.Responses():
			if !ok {
				return nil, errors.New("proxy: upstream transaction closed without a final response")
			}
			if err := s.relayResponse(req, tx, res); err != nil {
				s.log.Debug("relay response", "err", err, "sip_call_id", callIDOf(req))
			}
			if res.StatusCode >= 200 {
				return res, nil
			}
		case <-clTx.Done():
			return nil, clTx.Err()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// contactURI returns a request's first Contact URI, if any.
func contactURI(msg sip.Message) (sip.Uri, bool) {
	hs := msg.GetHeaders("Contact")
	if len(hs) == 0 {
		return sip.Uri{}, false
	}
	c, ok := hs[0].(*sip.ContactHeader)
	if !ok {
		return sip.Uri{}, false
	}
	return c.Address, true
}

// editable is a SIP message whose headers can be removed. sipgo's
// Message interface exposes append and prepend but not removal, even
// though both *sip.Request and *sip.Response implement it — a proxy needs
// removal on both, so it is named here rather than duplicating every
// helper for the two concrete types.
type editable interface {
	sip.Message
	RemoveHeader(name string) bool
}

var (
	_ editable = (*sip.Request)(nil)
	_ editable = (*sip.Response)(nil)
)

// removeAll strips every header of a name.
//
// sipgo's RemoveHeader deletes only the FIRST match — the right semantics
// for popping the top Via or Route, and the wrong ones everywhere else. A
// message may legitimately carry several Contacts (a phone registering two
// devices in one REGISTER, a redirect), and leaving the extras in place
// while adding ours would hand the far side the endpoint's own address
// alongside the SBC's, defeating the whole point of anchoring.
func removeAll(msg editable, name string) {
	for msg.RemoveHeader(name) {
	}
}

// setContact replaces every Contact header with one URI. Used on both the
// request and the response path: the proxy anchors signaling, so the
// Contact each side sees must be FreeSBC's, never the far endpoint's.
func setContact(msg editable, u sip.Uri) {
	removeAll(msg, "Contact")
	msg.AppendHeader(&sip.ContactHeader{Address: u})
}
