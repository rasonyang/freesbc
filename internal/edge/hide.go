package edge

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file holds topology hiding on every public leg: carriers (issue
// #96) and registered clients (issues #166, #167). The switch behind
// FreeSBC is on a private LAN, so nothing toward a public party may name a
// private address or identify the switch. On a call the proxy keeps every
// Via below its own; the rules below are what a public party is shown
// instead. A carrier and a client differ in one way only: a client leg also
// gets the header allowlist (filterToClient), because a client has no use
// for a header the switch added, whereas a carrier legitimately receives
// the switch's dialplan headers (P-Charge-Info, X-Account...).
//
// The rules, per message:
//
// Request toward a public party (a carrier's out-of-dialog REGISTER,
// INVITE and OPTIONS and every in-dialog request of a carrier call; a
// switch-originated INVITE, SUBSCRIBE, NOTIFY, MESSAGE and every in-dialog
// request toward a client), hideToPublic:
//   - Via: every Via the switch added is removed; the one Via is FreeSBC's
//     public one. The switch's own Vias are restored on the response.
//   - Record-Route: only FreeSBC's public entry, and only when the request
//     opens a dialog. Nothing the switch sent survives.
//   - Route: FreeSBC's own entries were stripped as the request was
//     prepared. On an out-of-dialog request every remaining Route is
//     removed (switch-preloaded routes may be private). On an in-dialog
//     request the remaining Routes are the route set learned from the far
//     end's own Record-Routes (a multi-hop carrier proxy chain needs them)
//     and are kept: the only private entry in the switch's route set is
//     FreeSBC's, already stripped. The send-to address is unchanged.
//   - Identity: the host of From, To, P-Asserted-Identity,
//     P-Preferred-Identity, Remote-Party-ID, Diversion, History-Info,
//     Referred-By, Refer-To, Call-Info, Alert-Info and Error-Info is
//     rewritten to public.ip (port dropped) when it is private.ip or the IP
//     of an edge.switch node (Asterisk and FreeSWITCH default to their own
//     IP). User, parameters and tags are kept. Any other host (a carrier
//     domain) is left alone. Call-ID is the switch's and passes through
//     unchanged (its host, if any, is the switch's business, #168).
//   - Contact: FreeSBC's public address (a carrier REGISTER carries the
//     rewritten binding instead, carrierreg.go).
//   - X-FreeSBC-*: removed, as for every forwarded request.
//   - Client legs only: every header outside clientHeaderAllowlist is
//     removed (Server, User-Agent, Warning, X-*, P-* other than the
//     identity ones).
//
// Request from a public party toward the switch (a client's, or a carrier's
// in-dialog request): From and To are restored to the switch's own URIs
// where the dialog or subscription record knows them (restoreIdentity),
// since the far end echoes the masked form in its in-dialog requests.
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
// Response to a client (respToClient, the switch's answer to a
// client-originated request): Record-Routes naming the private socket or
// the switch are removed (a client sees FreeSBC's public entry alone),
// the identity rule above is applied, a Contact is FreeSBC's public one
// (except in a REGISTER response, whose Contact list is the client's own
// bindings, restored by register.go), and the allowlist is applied. That
// drops Path, Service-Route and P-Associated-URI from a REGISTER 200. A
// digest challenge passes verbatim: its realm may name the switch's
// domain, but the client's digest is computed over it, so rewriting it would
// break the credential.
//
// ACK, CANCEL, BYE, re-INVITE, PRACK, UPDATE, INFO and NOTIFY in a dialog
// all take the same rules because they all leave through
// prepareForwardFor / relayResponseHide. SDP is rebuilt from scratch on
// every leg already, so no body carries a foreign address.

// respHide selects the topology-hiding rewrite a relayed response gets.
type respHide int

const (
	respPlain     respHide = iota // nothing hidden
	respToSwitch                  // a public party's response, going to the switch
	respToCarrier                 // switch's response to a carrier's request
	respToClient                  // switch's response to a client's request
)

// hideKind selects the topology-hiding rewrite a request going to a public
// party gets (hideToPublic).
type hideKind int

const (
	hideNone    hideKind = iota // toward the switch: nothing hidden
	hideCarrier                 // toward a carrier
	hideClient                  // toward a client: also the header allowlist
)

// prepareForwardFor is prepareForward, hidden per kind.
func (s *Server) prepareForwardFor(req *sip.Request, from, to side, dest string, recordRoute bool, kind hideKind) (*sip.Request, error) {
	out, err := s.prepareForward(req, from, to, dest, recordRoute)
	if err != nil || kind == hideNone {
		return out, err
	}
	s.hideToPublic(out, to, recordRoute, fsip.ToTag(req) != "", kind)
	return out, nil
}

// prepareForwardHidden is prepareForward for a request going to a carrier.
func (s *Server) prepareForwardHidden(req *sip.Request, from, to side, dest string, recordRoute bool) (*sip.Request, error) {
	return s.prepareForwardFor(req, from, to, dest, recordRoute, hideCarrier)
}

// identityHeaders are the generic headers whose URI hosts are masked.
// Call-Info and Alert-Info carry switch-generated SIP URIs such as
// FreeSWITCH's intercom hint `Call-Info: <sip:10.77.0.10>;answer-after=0`;
// History-Info, Referred-By and Refer-To name the switch in a redirect or a
// transfer. A Replaces header carries only a Call-ID and tags, and the
// Replaces escaped inside a Refer-To URI stays behind the host, which is
// the only part rewritten.
var identityHeaders = []string{"P-Asserted-Identity", "P-Preferred-Identity", "Remote-Party-ID", "Diversion",
	"History-Info", "Referred-By", "Refer-To", "Call-Info", "Alert-Info", "Error-Info"}

// The host is a bracketed IPv6 literal or anything up to a port, parameter,
// header or delimiter; the brackets stay in group 2.
var uriHostRe = regexp.MustCompile(`(sips?:(?:[^@\s>;,]*@)?)(\[[0-9a-fA-F:.]+\]|[^\s:>;,?\[\]]+)(:\d+)?`)

// isSwitchHost reports whether host is the private socket's IP or the IP of
// an edge.switch node.
func (s *Server) isSwitchHost(host string) bool {
	ip, ok := parseIPHost(strings.Trim(host, "[]"))
	if !ok {
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
		u.Host, u.Port = s.topo.hostOf(pub), 0
	}
}

// identityMsg is a request or a response whose identity headers can be
// masked.
type identityMsg interface {
	fsip.Editable
	Headers() []sip.Header
	From() *sip.FromHeader
	To() *sip.ToHeader
}

// identityHeaderIndex is the index of name in identityHeaders, compared
// without ASCII case as sipgo's GetHeaders compares, or -1.
func identityHeaderIndex(name string) int {
	for i, n := range identityHeaders {
		if asciiEqualFold(name, n) {
			return i
		}
	}
	return -1
}

// headersNamed is m.GetHeaders(name) without its cost: sipgo lower-cases
// the name of every header the message carries on each call, allocating
// for each one outside its short list of common names. The match is the
// same, ASCII letters without case.
func headersNamed(m interface{ Headers() []sip.Header }, name string) []sip.Header {
	var hs []sip.Header
	for _, h := range m.Headers() {
		if asciiEqualFold(h.Name(), name) {
			hs = append(hs, h)
		}
	}
	return hs
}

// hasHeader is len(m.GetHeaders(name)) > 0, allocation-free.
func hasHeader(m interface{ Headers() []sip.Header }, name string) bool {
	for _, h := range m.Headers() {
		if asciiEqualFold(h.Name(), name) {
			return true
		}
	}
	return false
}

// maskIdentity applies the identity rule of the file comment to a message
// going to a public party.
func (s *Server) maskIdentity(out identityMsg, pub netip.Addr) {
	if f := out.From(); f != nil {
		s.maskURI(&f.Address, pub)
	}
	if t := out.To(); t != nil {
		s.maskURI(&t.Address, pub)
	}
	// One pass says which identity headers the message carries at all;
	// most carry none, and then nothing below runs. Rewriting one name's
	// headers neither adds nor removes another's, so the set holds.
	var present uint32
	for _, h := range out.Headers() {
		if i := identityHeaderIndex(h.Name()); i >= 0 {
			present |= 1 << i
		}
	}
	if present == 0 {
		return
	}
	pubHost := s.topo.hostOf(pub)
	for k, name := range identityHeaders {
		if present&(1<<k) == 0 {
			continue
		}
		hs := headersNamed(out, name)
		vals := make([]string, len(hs))
		changed := false
		for i, h := range hs {
			vals[i] = uriHostRe.ReplaceAllStringFunc(h.Value(), func(m string) string {
				g := uriHostRe.FindStringSubmatch(m)
				if !s.isSwitchHost(g[2]) {
					return m
				}
				changed = true
				if pub.Is6() {
					return g[1] + "[" + pubHost + "]"
				}
				return g[1] + pubHost
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

// restoreURI undoes maskURI for a URI a public party echoed back: when real
// is a switch address and cur is the masked form of it (same user, host
// public.ip), cur becomes real again.
func (s *Server) restoreURI(cur *sip.Uri, real sip.Uri, pub netip.Addr) {
	if s.isSwitchHost(real.Host) && cur.Host == s.topo.hostOf(pub) && cur.User == real.User {
		cur.Host, cur.Port = real.Host, real.Port
	}
}

// restoreIdentity puts the switch's own From and To addresses back on an
// in-dialog request going to the switch from a public party, which echoes
// the masked form it was given. uriOf maps a From/To tag to the real
// address the record kept for it; pub is the public address masked to.
func (s *Server) restoreIdentity(out *sip.Request, pub netip.Addr, uriOf func(tag string) (sip.Uri, bool)) {
	if f, tag := out.From(), fsip.FromTag(out); f != nil && tag != "" {
		if real, ok := uriOf(tag); ok {
			s.restoreURI(&f.Address, real, pub)
		}
	}
	if t, tag := out.To(), fsip.ToTag(out); t != nil && tag != "" {
		if real, ok := uriOf(tag); ok {
			s.restoreURI(&t.Address, real, pub)
		}
	}
}

// clientHeaderAllowlist is every header (lower case) a client leg may
// carry toward a client (responses and switch-originated requests; a
// client's own User-Agent and X-* reach the switch). It is an allowlist because the switch adds
// headers FreeSBC cannot enumerate (Server, User-Agent, Warning, X-*, P-*)
// and each names or fingerprints it. What stays is the RFC 3261 core and
// the headers a client acts on; the identity ones have their hosts masked
// (identityHeaders). Organization is dropped with Server and User-Agent;
// Path, Service-Route and P-Associated-URI (a REGISTER 200) name the
// switch. The compact forms are listed for headers sipgo does not
// canonicalise.
var clientHeaderAllowlist = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range []string{
		"via", "from", "to", "call-id", "cseq", "contact", "record-route", "route", "max-forwards",
		"content-length", "content-type", "content-disposition", "content-encoding", "content-language",
		"mime-version", "expires", "min-expires", "allow", "supported", "require", "proxy-require", "unsupported",
		"rseq", "rack", "www-authenticate", "proxy-authenticate", "authorization", "proxy-authorization",
		"authentication-info", "event", "allow-events", "subscription-state", "refer-to", "referred-by",
		"refer-sub", "replaces", "join", "target-dialog", "session-expires", "min-se", "retry-after", "reason",
		"privacy", "accept", "accept-encoding", "accept-language", "accept-contact", "reject-contact",
		"request-disposition", "date", "timestamp", "subject", "priority", "call-info", "alert-info",
		"error-info", "diversion", "history-info", "p-asserted-identity", "p-preferred-identity",
		"remote-party-id", "recv-info", "info-package", "reply-to", "in-reply-to", "identity", "identity-info",
		"flow-timer",
		"v", "f", "t", "i", "m", "l", "c", "e", "k", "s", "o", "u", "b", "r", "x", "a", "j", "y", "n",
	} {
		m[n] = true
	}
	return m
}()

// filterToClient removes every header outside clientHeaderAllowlist.
// sipgo's RemoveHeader is exact-name and removes one header per call, so
// the names are collected first, one per occurrence.
func filterToClient(m headerSet) {
	var drop []string
	for _, h := range m.Headers() {
		if !allowedToClient(h.Name()) {
			drop = append(drop, h.Name())
		}
	}
	for _, n := range drop {
		m.RemoveHeader(n)
	}
}

// allowedToClient is clientHeaderAllowlist[strings.ToLower(name)] without
// the allocation ToLower makes for every name with a capital letter. An
// ASCII name is lower-cased into a stack buffer, which is exactly what
// ToLower does to it; any other name (or one too long for the buffer,
// which no allowlisted name is) goes through ToLower itself, since a
// non-ASCII rune can lower-case into ASCII (the Kelvin sign to k).
func allowedToClient(name string) bool {
	var buf [32]byte
	if len(name) > len(buf) {
		return clientHeaderAllowlist[strings.ToLower(name)]
	}
	b := buf[:len(name)]
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= utf8.RuneSelf {
			return clientHeaderAllowlist[strings.ToLower(name)]
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return clientHeaderAllowlist[string(b)]
}

// hideToPublic strips everything private from a prepared request going to a
// carrier or a client: all Vias but the top one (ours, public), every
// Record-Route and Route, the switch's identity, and whatever internal
// headers remain. recordRoute adds back FreeSBC's public Record-Route
// alone. kind hideClient also applies the header allowlist.
func (s *Server) hideToPublic(out *sip.Request, to side, recordRoute, inDialog bool, kind hideKind) {
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
	if hasHeader(out, "Contact") {
		// An ACK or BYE may carry the switch's own Contact.
		fsip.SetContact(out, to.uri())
	}
	stripInternalHeaders(out)
	if kind == hideClient {
		filterToClient(out)
	}
}

// hideResponse applies mode's rewrite to a response clone whose own Via has
// been popped (see the file comment).
func (s *Server) hideResponse(res *sip.Response, orig *sip.Request, mode respHide) {
	switch mode {
	case respToSwitch:
		fsip.RemoveHeaders(res, "Via")
		var vias []sip.Header
		for _, h := range headersNamed(orig, "Via") {
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
		for _, h := range headersNamed(res, "Record-Route") {
			if rr, ok := h.(*sip.RecordRouteHeader); ok && !s.isPrivateURI(rr.Address) {
				keep = append(keep, rr)
			}
		}
		fsip.RemoveHeaders(res, "Record-Route")
		for _, rr := range keep {
			res.AppendHeader(rr)
		}
		if hasHeader(res, "Contact") {
			if pub, ok := s.publicSideFor(orig); ok {
				fsip.SetContact(res, pub.uri())
			} else {
				fsip.RemoveHeaders(res, "Contact")
			}
		}
	case respToClient:
		// A 3xx Contact is FreeSBC's too: the issue asks for every client-bound
		// Contact, so a switch redirect is not usable as a redirect target.
		s.hideRecordRoutesToClient(res)
		if pub, ok := s.publicSideFor(orig); ok {
			s.maskIdentity(res, pub.advIP)
			// A REGISTER response lists the client's own bindings, which
			// register.go restores; every other Contact is the switch's.
			if orig.Method != sip.REGISTER && hasHeader(res, "Contact") {
				fsip.SetContact(res, pub.uri())
			}
		}
		filterToClient(res)
	}
}

// hideRecordRoutesToClient removes every Record-Route naming the private
// socket or a switch from a response going to a public client, so what the
// switch echoed (FreeSBC's private entry) or added (its own) never reaches
// it. Entries of other hops, such as the client's own proxies, stay.
func (s *Server) hideRecordRoutesToClient(res *sip.Response) {
	var keep []*sip.RecordRouteHeader
	for _, h := range headersNamed(res, "Record-Route") {
		if rr, ok := h.(*sip.RecordRouteHeader); ok && !s.isPrivateURI(rr.Address) && (s.isPublicURI(rr.Address) || !s.isSwitchHost(rr.Address.Host)) {
			keep = append(keep, rr)
		}
	}
	fsip.RemoveHeaders(res, "Record-Route")
	for _, rr := range keep {
		res.AppendHeader(rr)
	}
}

// addPrivateRecordRoute inserts FreeSBC's private Record-Route into an
// INVITE or SUBSCRIBE response bound for the switch (from a carrier or a
// client: neither echoes it), immediately after the
// public one the carrier echoed (or at the end of the list when the carrier
// dropped it: FreeSBC's entries are the last it added on the way out, so
// the bottom of the list is where they belong).
func (s *Server) addPrivateRecordRoute(res *sip.Response) {
	var all []*sip.RecordRouteHeader
	for _, h := range headersNamed(res, "Record-Route") {
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
	ip, ok := parseIPHost(u.Host)
	if !ok {
		return false
	}
	port := u.Port
	if port == 0 {
		port = 5060
	}
	return sd.advIP == ip.Unmap() && sd.advPort == port
}

// hideLeg decides which topology hiding a request of an in-dialog exchange
// gets and what its response gets: kind says how the request is hidden when
// it goes to a public party (carrier or client), resp is the rewrite its
// response gets. A request toward the switch is never hidden. A carrier
// dialog (or a request from a carrier's source) takes the carrier rules, any
// other the client rules.
func (s *Server) hideLeg(req *sip.Request, d *dialog, from, to side) (kind hideKind, resp respHide) {
	name := ""
	if d != nil {
		name = d.carrierName()
	} else if from.plane == planePublic {
		name, _ = s.carrierFallback(req)
	}
	switch {
	case to.plane == planePublic && name != "":
		return hideCarrier, respToSwitch
	case to.plane == planePublic:
		return hideClient, respToSwitch
	case from.plane == planePublic && name != "":
		return hideNone, respToCarrier
	case from.plane == planePublic:
		return hideNone, respToClient
	}
	return hideNone, respPlain
}

// noteOutbound counts a request of a carrier dialog going to the carrier.
func (s *Server) noteOutbound(req *sip.Request, d *dialog, kind hideKind) {
	if kind == hideCarrier && d != nil {
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
