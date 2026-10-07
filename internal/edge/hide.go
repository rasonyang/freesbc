package edge

import (
	"net/netip"
	"regexp"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file holds topology hiding on carrier legs (issue #96). On a client
// call the proxy keeps every Via below its own and double Record-Routes,
// because both sides are its own to show. A carrier is different: it is on
// the public internet and the switch behind FreeSBC is on a private LAN, so
// nothing toward the carrier may name a private address.
//
// The rules, per message:
//
// Request toward a carrier (out-of-dialog REGISTER, INVITE, OPTIONS and
// every in-dialog request of a carrier call that goes public):
//   - Via: every Via the switch added is removed; the one Via is FreeSBC's
//     public one (hideToCarrier).
//   - Record-Route: only FreeSBC's public entry, and only when the request
//     opens a dialog. Nothing the switch sent survives.
//   - Route: FreeSBC's own entries were stripped as the request was
//     prepared. On an out-of-dialog request every remaining Route is
//     removed (switch-preloaded routes may be private). On an in-dialog
//     request the remaining Routes are the route set learned from the
//     carrier's own Record-Routes (a multi-hop carrier proxy chain needs
//     them) and are kept: the only private entry in the switch's route set
//     is FreeSBC's, already stripped. The send-to address is unchanged.
//   - Identity: the host of From, To, P-Asserted-Identity,
//     P-Preferred-Identity, Remote-Party-ID, Diversion, Call-Info and
//     Alert-Info is rewritten to public.ip (port dropped) when it is
//     private.ip or the IP of an edge.switch node (Asterisk and FreeSWITCH
//     default to their own IP).
//     User, parameters and tags are kept. Any other host (a carrier
//     domain) is left alone. Call-ID is the switch's and passes through
//     unchanged.
//   - Contact: FreeSBC's public address (REGISTER carries the rewritten
//     binding instead, carrierreg.go).
//   - X-FreeSBC-*: removed, as for every forwarded request.
//
// Response to the switch (respToSwitch): our public Via is popped, then the
// switch's original Vias are restored, so its transaction matches, and the
// original From and To addresses are restored (the tags stay as answered). An
// INVITE's 1xx/2xx additionally gets FreeSBC's private Record-Route
// inserted right after the public one (addPrivateRecordRoute): the switch,
// as UAC, reverses the list, so its route set starts at private.ip:5060 and
// its in-dialog requests reach the private socket.
//
// Response to a carrier (respToCarrier, a carrier-originated request that
// went to the switch): any Record-Route naming the private socket is
// removed, and a Contact, if present, is FreeSBC's public one, so no
// private address leaves in a response either.
//
// ACK, CANCEL, BYE, re-INVITE, PRACK, UPDATE, INFO and NOTIFY in a carrier dialog
// all take the same rules because they all leave through
// prepareForwardHidden / relayResponseHide. SDP is rebuilt from scratch on
// every leg already, so no body carries a foreign address.

// respHide selects the topology-hiding rewrite a relayed response gets.
type respHide int

const (
	respPlain     respHide = iota // client legs: nothing hidden
	respToSwitch                  // carrier leg's response, going to the switch
	respToCarrier                 // switch's response to a carrier's request
)

// prepareForwardFor is prepareForward, hidden when the request goes to a
// carrier (carrierLeg says so).
func (s *Server) prepareForwardFor(req *sip.Request, from, to side, dest string, recordRoute, hide bool) (*sip.Request, error) {
	if hide {
		return s.prepareForwardHidden(req, from, to, dest, recordRoute)
	}
	return s.prepareForward(req, from, to, dest, recordRoute)
}

// prepareForwardHidden is prepareForward for a request going to a carrier.
func (s *Server) prepareForwardHidden(req *sip.Request, from, to side, dest string, recordRoute bool) (*sip.Request, error) {
	out, err := s.prepareForward(req, from, to, dest, recordRoute)
	if err != nil {
		return nil, err
	}
	s.hideToCarrier(out, to, recordRoute, fsip.ToTag(req) != "")
	return out, nil
}

// identityHeaders are the generic headers whose URI hosts are masked.
// Call-Info and Alert-Info carry switch-generated SIP URIs such as
// FreeSWITCH's intercom hint `Call-Info: <sip:10.77.0.10>;answer-after=0`.
var identityHeaders = []string{"P-Asserted-Identity", "P-Preferred-Identity", "Remote-Party-ID", "Diversion", "Call-Info", "Alert-Info"}

var uriHostRe = regexp.MustCompile(`(sips?:(?:[^@\s>;,]*@)?)([^\s:>;,]+)(:\d+)?`)

// isSwitchHost reports whether host is the private socket's IP or the IP of
// an edge.switch node.
func (s *Server) isSwitchHost(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if s.topo.private.advIP == ip {
		return true
	}
	for _, e := range s.topo.upstreams {
		if e.addr.Addr().Unmap() == ip {
			return true
		}
	}
	return false
}

// maskURI rewrites a private host to the public address, dropping the port.
func (s *Server) maskURI(u *sip.Uri, pub netip.Addr) {
	if s.isSwitchHost(u.Host) {
		u.Host, u.Port = pub.String(), 0
	}
}

// maskIdentity applies the identity rule of the file comment to a request
// going to a carrier.
func (s *Server) maskIdentity(out *sip.Request, pub netip.Addr) {
	if f := out.From(); f != nil {
		s.maskURI(&f.Address, pub)
	}
	if t := out.To(); t != nil {
		s.maskURI(&t.Address, pub)
	}
	for _, name := range identityHeaders {
		hs := out.GetHeaders(name)
		if len(hs) == 0 {
			continue
		}
		vals := make([]string, len(hs))
		changed := false
		for i, h := range hs {
			vals[i] = uriHostRe.ReplaceAllStringFunc(h.Value(), func(m string) string {
				g := uriHostRe.FindStringSubmatch(m)
				if !s.isSwitchHost(g[2]) {
					return m
				}
				changed = true
				return g[1] + pub.String()
			})
		}
		if changed {
			hn := hs[0].Name()
			fsip.RemoveHeaders(out, hn)
			for _, v := range vals {
				out.AppendHeader(sip.NewHeader(hn, v))
			}
		}
	}
}

// hideToCarrier strips everything private from a prepared request: all Vias
// but the top one (ours, public), every Record-Route and Route, and
// whatever internal headers remain. recordRoute adds back FreeSBC's public
// Record-Route alone.
func (s *Server) hideToCarrier(out *sip.Request, to side, recordRoute, inDialog bool) {
	if top := out.Via(); top != nil {
		fsip.RemoveHeaders(out, "Via")
		out.PrependHeader(top)
	}
	fsip.RemoveHeaders(out, "Record-Route")
	if recordRoute {
		out.PrependHeader(to.recordRoute())
	}
	if !inDialog {
		fsip.RemoveHeaders(out, "Route")
	}
	s.maskIdentity(out, to.advIP)
	if len(out.GetHeaders("Contact")) > 0 {
		// An ACK or BYE may carry the switch's own Contact.
		fsip.SetContact(out, to.uri())
	}
	stripInternalHeaders(out)
}

// hideResponse applies mode's rewrite to a response clone whose own Via has
// been popped (see the file comment).
func (s *Server) hideResponse(res *sip.Response, orig *sip.Request, mode respHide) {
	switch mode {
	case respToSwitch:
		fsip.RemoveHeaders(res, "Via")
		var vias []sip.Header
		for _, h := range orig.GetHeaders("Via") {
			if v, ok := h.(*sip.ViaHeader); ok {
				vias = append(vias, v.Clone())
			}
		}
		res.PrependHeader(vias...)
		if f, of := res.From(), orig.From(); f != nil && of != nil {
			f.Address = *of.Address.Clone()
		}
		if t, ot := res.To(), orig.To(); t != nil && ot != nil {
			t.Address = *ot.Address.Clone()
		}
	case respToCarrier:
		var keep []*sip.RecordRouteHeader
		for _, h := range res.GetHeaders("Record-Route") {
			if rr, ok := h.(*sip.RecordRouteHeader); ok && !s.isPrivateURI(rr.Address) {
				keep = append(keep, rr)
			}
		}
		fsip.RemoveHeaders(res, "Record-Route")
		for _, rr := range keep {
			res.AppendHeader(rr)
		}
		if len(res.GetHeaders("Contact")) > 0 {
			if pub, ok := s.publicSideFor(orig); ok {
				fsip.SetContact(res, pub.uri())
			} else {
				fsip.RemoveHeaders(res, "Contact")
			}
		}
	}
}

// addPrivateRecordRoute inserts FreeSBC's private Record-Route into a
// carrier INVITE response bound for the switch, immediately after the
// public one the carrier echoed (or at the end of the list when the carrier
// dropped it: FreeSBC's entries are the last it added on the way out, so
// the bottom of the list is where they belong).
func (s *Server) addPrivateRecordRoute(res *sip.Response) {
	var all []*sip.RecordRouteHeader
	for _, h := range res.GetHeaders("Record-Route") {
		if rr, ok := h.(*sip.RecordRouteHeader); ok {
			all = append(all, rr)
		}
	}
	at := len(all)
	for i := len(all) - 1; i >= 0; i-- {
		if s.isPublicURI(all[i].Address) {
			at = i + 1
			break
		}
	}
	fsip.RemoveHeaders(res, "Record-Route")
	priv := s.topo.private.recordRoute()
	for i, rr := range all {
		if i == at {
			res.AppendHeader(priv)
		}
		res.AppendHeader(rr)
	}
	if at == len(all) {
		res.AppendHeader(priv)
	}
}

// isPrivateURI reports whether u names the private socket.
func (s *Server) isPrivateURI(u sip.Uri) bool { return sideMatches(s.topo.private, u) }

// isPublicURI reports whether u names one of FreeSBC's public listeners.
func (s *Server) isPublicURI(u sip.Uri) bool {
	for _, p := range s.topo.public {
		if sideMatches(p, u) {
			return true
		}
	}
	return false
}

func sideMatches(sd side, u sip.Uri) bool {
	ip, err := netip.ParseAddr(u.Host)
	if err != nil {
		return false
	}
	port := u.Port
	if port == 0 {
		port = 5060
	}
	return sd.advIP == ip.Unmap() && sd.advPort == port
}

// carrierLeg names the carrier a request of an in-dialog exchange belongs
// to, and which hiding applies: reqHide says the request is going to a
// carrier (public side) and must be hidden, resp is the rewrite its
// response gets. A request on a client dialog, or one with no carrier at
// all, gets neither.
func (s *Server) carrierLeg(req *sip.Request, d *dialog, from, to side) (reqHide bool, resp respHide) {
	name := ""
	if d != nil {
		name = d.carrierName()
	} else if from.plane == planePublic {
		name, _ = s.carrierFallback(req)
	}
	switch {
	case name == "":
		return false, respPlain
	case to.plane == planePublic:
		return true, respToSwitch
	case from.plane == planePublic:
		return false, respToCarrier
	}
	return false, respPlain
}

// noteOutbound counts a request of a carrier dialog going to the carrier.
func (s *Server) noteOutbound(req *sip.Request, d *dialog, hide bool) {
	if hide && d != nil {
		s.metrics.CarrierRequest(d.carrierName(), dirOutbound, req.Method.String())
	}
}

// restoreCarrierRURI puts a registered switch Contact back as the
// Request-URI of a carrier's request that matches no dialog record and
// names an outbound-registration token (see directionFor).
func (s *Server) restoreCarrierRURI(req, out *sip.Request) {
	if carrier, ok := s.carrierFallback(req); ok {
		if b, found := s.carrierRURI(req, carrier); found {
			out.Recipient = b.contact
		}
	}
}
