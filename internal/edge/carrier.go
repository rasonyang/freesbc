package edge

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file holds the carrier path's classification: who a request is for
// and who it is from. Carriers are the third kind of far end besides
// registered clients and the switch. The directory that resolves them is
// carrierdns.go; the inbound (carrier → switch) call path is
// inviteToUpstream with a carrier name; the outbound (switch → carrier)
// path is inviteToCarrier, optionsToCarrier and registerToCarrier, with the
// topology hiding of hide.go.

// carrierHeader is the header FreeSBC stamps on every request it delivers
// to the switch's carrier port, naming the carrier it came from
// (edge.carriers name, or "unknown" for a carrier_sources address that
// matches no entry). The switch identifies inbound carrier calls by it.
const carrierHeader = "X-FreeSBC-Carrier"

// Directions of the carrier request metric: toward the switch, and toward
// a carrier.
const (
	dirInbound  = "inbound"  // carrier → switch
	dirOutbound = "outbound" // switch → carrier
)

// carrierKey is the canonical "host:port" an edge.carriers entry is
// matched by: host lower-cased without a trailing dot (a literal IP in
// canonical form), port defaulting to 5060.
func carrierKey(host string, port int) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if a, err := netip.ParseAddr(host); err == nil {
		host = a.Unmap().String()
	}
	if port == 0 {
		port = config.DefaultCarrierPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// carrierURIsOf maps each edge.carriers entry's "host:port" to its name.
func carrierURIsOf(cfg *config.Config) map[string]string {
	m := map[string]string{}
	for _, c := range cfg.CarrierList() {
		m[carrierKey(c.Host, c.Port)] = c.Name
	}
	return m
}

// switchTarget is where a request from the switch is addressed.
type switchTarget int

const (
	// targetNotFound: addressed to nothing FreeSBC serves. The switch gets
	// 404; FreeSBC is never an open relay for it.
	targetNotFound switchTarget = iota
	// targetClient: the Request-URI (or topmost remaining Route) carries an
	// fsbc token.
	targetClient
	// targetCarrier: the Request-URI host[:port] is an edge.carriers entry.
	targetCarrier
	// targetSelf: addressed to FreeSBC's own signaling address.
	targetSelf
)

// classifySwitchRequest decides where an out-of-dialog request from the
// switch goes, by Request-URI only and never by registration state (issue
// #96, "Private socket"). A Route naming FreeSBC itself is skipped (loose
// routing). Then, in order:
//
//  1. the Request-URI, or the topmost remaining Route, carries an fsbc
//     token → targetClient (whether the token is live is the client path's
//     business: unknown or expired answers 404);
//  2. the Request-URI host[:port] equals an edge.carriers entry
//     (case-insensitive host, trailing dot ignored, port default 5060) →
//     targetCarrier, with the carrier's name;
//  3. the Request-URI names FreeSBC → targetSelf;
//  4. anything else → targetNotFound.
func (s *Server) classifySwitchRequest(req *sip.Request) (switchTarget, string) {
	if _, ok := tokenOf(req.Recipient); ok {
		return targetClient, ""
	}
	if r := s.firstForeignRoute(req); r != nil {
		if _, ok := tokenOf(r.Address); ok {
			return targetClient, ""
		}
	}
	if name, ok := s.carrierURIs[carrierKey(req.Recipient.Host, req.Recipient.Port)]; ok {
		return targetCarrier, name
	}
	if s.topo.isSelf(req.Recipient) {
		return targetSelf, ""
	}
	return targetNotFound, ""
}

// firstForeignRoute is the topmost Route header that does not name FreeSBC
// itself, or nil. FreeSBC's own Route (the switch's outbound proxy, or the
// private Record-Route coming back) is removed from the route set before
// anything else looks at it.
func (s *Server) firstForeignRoute(req *sip.Request) *sip.RouteHeader {
	for _, h := range req.GetHeaders("Route") {
		if r, ok := h.(*sip.RouteHeader); ok && !s.topo.isSelf(r.Address) {
			return r
		}
	}
	return nil
}

// carrierHashUser is the hashing identity of a carrier's request: the
// lower-cased Request-URI user (the DID), else the To user, else the
// Call-ID. Call-ID is the last resort so a request with neither still
// lands somewhere stable.
func carrierHashUser(req *sip.Request) string {
	if u := req.Recipient.User; u != "" {
		return strings.ToLower(u)
	}
	if t := req.To(); t != nil && t.Address.User != "" {
		return strings.ToLower(t.Address.User)
	}
	return fsip.CallID(req)
}

// carrierFallback reports whether a public request that matches no dialog
// record is a carrier's: its source is a carrier source and no live
// registration owns that transport address (a registration wins, as in
// admission).
func (s *Server) carrierFallback(req *sip.Request) (name string, ok bool) {
	src, ok := fsip.SourceAddrPort(req)
	if !ok || s.loc.HasSource(sip.NetworkToLower(req.Transport()), src) {
		return "", false
	}
	return s.carriers.snapshot().carrierFor(src)
}

// stampCarrier adds X-FreeSBC-Carrier to a request forwarded from the
// public side to the switch when it belongs to a carrier call: the
// dialog's carrier when the dialog is on record, else the carrier whose
// source it came from.
func (s *Server) stampCarrier(out, req *sip.Request, d *dialog) {
	name := ""
	if d != nil {
		name = d.carrierName()
	} else if n, ok := s.carrierFallback(req); ok {
		name = n
	}
	if name == "" {
		return
	}
	out.AppendHeader(sip.NewHeader(carrierHeader, name))
	s.metrics.CarrierRequest(name, dirInbound, req.Method.String())
}

// invitePrivate routes an out-of-dialog INVITE from the switch.
func (s *Server) invitePrivate(req *sip.Request, tx sip.ServerTransaction) {
	switch kind, name := s.classifySwitchRequest(req); kind {
	case targetClient:
		s.inviteToClient(req, tx)
	case targetCarrier:
		s.inviteToCarrier(req, tx, name)
	default:
		s.reject(req, tx, 404, "Not Found")
	}
}

// inviteToCarrier handles a call the switch places to a carrier: one
// attempt to the carrier's first resolved address (line selection and
// failover belong to the switch), shaped like inviteToClient. The dialog
// begins on the private plane, the Request-URI is never changed, signaling
// toward the carrier is hidden (hide.go) and both SDPs are FreeSBC's own:
// the carrier is offered a public anchor port, the switch is answered with
// a private one.
func (s *Server) inviteToCarrier(req *sip.Request, tx sip.ServerTransaction, carrier string) {
	dest, ok := s.carrierDest(carrier)
	if !ok {
		s.log.Warn("carrier has no resolved address", "carrier", carrier, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	to, ok := s.topo.publicSide("udp")
	if !ok {
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	body := req.Body()
	s.metrics.CarrierRequest(carrier, dirOutbound, "INVITE")

	ctx, cancel := context.WithTimeout(context.Background(), s.inviteBudget())
	defer cancel()

	d, ok := s.beginDialog(req, tx, planePrivate)
	if !ok {
		return
	}
	defer d.endUnlessUp()
	d.setCarrier(carrier)

	// An offerless INVITE is forwarded as it is: the offer is the
	// carrier's first SDP, built into a private one when it arrives
	// (offerless.go).
	var offer *offerResult
	var offerless func([]byte) (*offerResult, error)
	if len(body) > 0 {
		var err error
		if offer, err = s.buildPublicOffer(d, body, false); err != nil {
			s.rejectMedia(req, tx, err)
			return
		}
	} else {
		var src netip.Addr
		if ap, err := netip.ParseAddrPort(dest); err == nil {
			src = ap.Addr()
		}
		offerless = func(b []byte) (*offerResult, error) { return s.buildUpstreamOffer(ctx, d, b, src) }
	}

	out, err := s.prepareForwardHidden(req, s.topo.private, to, dest, true)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	// The Request-URI is the switch's, unchanged. The Contact is ours: the
	// carrier's in-dialog requests come back to the public address.
	contact := to.uri()
	if f := req.From(); f != nil {
		contact.User = f.Address.User
	}
	fsip.SetContact(out, contact)
	if offer != nil {
		fsip.SetSDPBody(out, offer.sdp)
	} else {
		stripBody(out)
	}

	s.log.Info("proxying INVITE to carrier",
		"sip_call_id", fsip.CallID(req), "direction", "private->public",
		"carrier", carrier, "dest", dest,
		"offerless", offer == nil)

	// A CANCEL from the switch ends this server transaction; the INVITE
	// sent to the carrier must be cancelled too (see inviteToClient).
	if !tx.OnCancel(func(*sip.Request) {
		if !s.cancelCall(d, cancelByCaller) {
			cancel()
		}
	}) {
		return
	}
	a := &inviteAttempt{req: out, cancel: cancel}
	if !d.track(a) {
		return
	}
	defer d.untrack()

	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
	if err != nil {
		s.log.Warn("forward INVITE to carrier", "err", err, "carrier", carrier)
		s.giveUp(ctx, d, req, tx, 503, "Service Unavailable")
		return
	}
	if d.markSent(a) {
		go s.sendCancel(a)
	}

	l := &inviteLeg{req: req, tx: tx, out: out, clTx: clTx, d: d, offer: offer, offerless: offerless,
		near: s.topo.private, far: to, callee: calleeCarrier,
		calleeRemote: dest, transport: "udp", fromPrivate: true, resp: respToSwitch}
	if r := s.pumpInvite(ctx, l); !r.finalised {
		code, reason := 503, "Service Unavailable"
		if errors.Is(clTx.Err(), sip.ErrTransactionTimeout) {
			code, reason = 408, "Request Timeout"
		}
		s.giveUp(ctx, d, req, tx, code, reason)
	}
}

// optionsToCarrier proxies an OPTIONS the switch sends to a carrier (a
// gateway keepalive): forwarded to the carrier's first resolved address
// with the signaling hidden, and the carrier's answer relayed back.
func (s *Server) optionsToCarrier(req *sip.Request, tx sip.ServerTransaction, carrier string) {
	dest, ok := s.carrierDest(carrier)
	pub, pubOK := s.topo.publicSide("udp")
	if !ok || !pubOK {
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	out, err := s.prepareForwardHidden(req, s.topo.private, pub, dest, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	s.metrics.CarrierRequest(carrier, dirOutbound, "OPTIONS")
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	if _, err := s.forwardAndRelay(ctx, req, tx, out, respToSwitch, func(res *sip.Response) error {
		// A keepalive's SDP is the carrier's own media address.
		if isSDPBody(res) {
			stripBody(res)
		}
		return nil
	}); err != nil {
		s.log.Debug("forward carrier OPTIONS", "err", err, "carrier", carrier)
		if ctx.Err() != nil {
			s.reject(req, tx, 504, "Server Time-out")
		} else {
			s.reject(req, tx, 503, "Service Unavailable")
		}
	}
}
