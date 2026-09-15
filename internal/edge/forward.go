package edge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	fsip "github.com/freesbc/freesbc/internal/sip"
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

	out.PrependHeader(to.via(fsip.NewBranch()))

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

// popOwnVia removes the top Via from a response, but only when it is
// actually ours, and reports whether the result can still be forwarded.
//
// RFC 3261 §16.7 step 3 requires the check: a proxy compares the top Via
// against its own value and discards the response if it does not match.
// Removing it unconditionally is what a naive implementation does, and it
// is wrong in a way that shows up against real switches — sofia sends its
// 100 Trying with ONLY the topmost Via, so a blind pop leaves the response
// with no Via at all and the requester's transaction layer cannot match
// it.
//
// ok=false means the response must not be forwarded.
func (s *Server) popOwnVia(res *sip.Response) (ok bool) {
	top := res.Via()
	if top == nil {
		return false
	}
	if !s.topo.isSelfVia(top) {
		// Not our Via: the response does not belong to a request we sent.
		return false
	}
	res.RemoveHeader("Via")
	// After popping ours there must be a Via left to route by.
	return res.Via() != nil
}

// errResponseDropped reports a response that cannot be routed back: its
// top Via is not ours, or popping ours left none. Every relay loop treats
// it the same way — keep pumping — which is why it is a sentinel rather
// than each loop's own bool.
var errResponseDropped = errors.New("proxy: response cannot be routed back")

// relayResponse forwards one response of a forwarded request back through
// the server transaction, toward whoever sent the original.
//
// This is the whole of the mechanics every relay loop shares: clone (the
// far end's response must stay intact for the transaction layer), pop our
// own Via, let the caller rewrite what it owns, then send it to the
// request's transport SOURCE (symmetric response routing, RFC 3581) and
// count it. Everything else in the response is the far end's and is left
// alone.
//
// adapt runs on the clone after the Via is popped and before anything is
// sent. It is where each loop rewrites the Contact and the SDP body; the
// error it returns is the caller's own (a failed media negotiation), and
// aborts the relay without sending or counting anything.
//
// A failure to send is logged, not returned: the transaction layer owns
// retransmission, and there is nothing a relay loop can do about it.
func (s *Server) relayResponse(orig *sip.Request, tx sip.ServerTransaction, res *sip.Response,
	adapt func(out *sip.Response) error) error {

	out := res.Clone()
	if !s.popOwnVia(out) {
		s.log.Debug("dropping response that cannot be routed back",
			"code", out.StatusCode, "sip_call_id", fsip.CallID(out))
		return errResponseDropped
	}
	if adapt != nil {
		if err := adapt(out); err != nil {
			return err
		}
	}
	out.SetDestination(orig.Source())
	s.metrics.ResponseOut(out.StatusCode)
	if err := tx.Respond(out); err != nil {
		s.log.Debug("relay response", "err", err,
			"code", out.StatusCode, "sip_call_id", fsip.CallID(orig))
	}
	return nil
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
	responses := clTx.Responses()
	for {
		select {
		case res, ok := <-responses:
			if !ok {
				// sipgo never closes this channel — it ends a transaction
				// through Done() — so this arm is unreachable. A closed
				// channel is permanently ready, so stop selecting on it and
				// let the loop end the way it ends for any transaction
				// that produced no further response.
				responses = nil
				continue
			}
			if !fsip.Forwardable(res) {
				continue // a 100 Trying is hop-by-hop; ours already went out
			}
			_ = s.relayResponse(req, tx, res, nil)
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
