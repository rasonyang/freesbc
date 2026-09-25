package edge

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// registerTimeout bounds one REGISTER round trip upstream. A registrar
// that has not answered in this long is not going to, and the phone will
// retry on its own schedule.
const registerTimeout = 32 * time.Second

// onRegister proxies a REGISTER to FreeSWITCH and, on success, records the
// binding needed to deliver inbound requests back to the client.
//
// FreeSWITCH stays the authoritative registrar: the digest challenge and
// the client's Authorization header are forwarded verbatim in both
// directions, and FreeSBC never computes, stores or inspects a credential.
// The ONLY thing it changes is the Contact — because the contact
// FreeSWITCH stores has to be an address that routes back through the
// SBC, and for a browser the client's own Contact is a deliberately
// unreachable ".invalid" host.
func (s *Server) onRegister(req *sip.Request, tx sip.ServerTransaction, src netip.AddrPort) {
	if s.arrivedOnPrivate(req) {
		// FreeSWITCH does not register through its own edge proxy.
		s.reject(req, tx, 403, "Forbidden")
		return
	}
	from, ok := s.publicSideFor(req)
	if !ok {
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}

	aor, user, ok := aorOf(req)
	if !ok {
		s.reject(req, tx, 400, "Bad Request")
		return
	}
	clientContact, hasContact := fsip.ContactURI(req)
	expires, unregister := requestedExpires(req)
	wildcard := hasWildcardContact(req)
	if wildcard && (!unregister || len(req.GetHeaders("Contact")) != 1) {
		// RFC 3261 §10.3 step 6: "*" is only valid alone and with an
		// expires of 0.
		s.reject(req, tx, 400, "Bad Request")
		return
	}

	// The token must be stable across a registration's whole lifetime:
	// FreeSWITCH stores the Contact we send now and uses it as the
	// Request-URI of every future inbound call, so a refresh that changed
	// the token would strand the earlier one. Location.Put reuses the
	// token of an existing (AoR, Call-ID) binding for exactly this reason;
	// here we look it up first so the REGISTER we forward already carries
	// it.
	token := s.existingToken(aor, fsip.CallID(req))
	if token == "" {
		token = fsip.NewToken()
	}
	in := bindingInput{
		token: token, aor: aor, user: user, callID: fsip.CallID(req),
		transport: from.transport, source: src,
		requested: expires, unregister: unregister,
		clientContact: clientContact, hasContact: hasContact,
		wildcard: wildcard,
	}

	// ONE budget for the whole attempt series, not one per node (D2): on
	// UDP a silent node is indistinguishable from a slow one, so N per-node
	// budgets would multiply the worst-case REGISTER latency by N. A node
	// that answered nothing is penalized instead, and the phone's own next
	// REGISTER (it retries on its own schedule) skips it.
	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	defer cancel()

	// The budget is re-read from the store on every REGISTER, so a reload
	// changes it for the next registration without a restart; the node set
	// is a startup snapshot like the rest of the topology.
	cooldown := s.store.Current().SIP.Upstreams.Cooldown.Std()

	// The user's hash order, cooled nodes at the tail: the registrar a
	// refresh lands on is the one that holds the binding, and a node that
	// just failed is only dialed once its alternatives have been tried.
	for attempt, name := range s.upstreamOrder(user) {
		if ctx.Err() != nil {
			break // the shared budget is spent; the phone will retry
		}
		entry := s.topo.upstreamEntryFor(name)

		// A FRESH forward per attempt (prepareForward clones, so the
		// client's request is never mutated): new Via branch per node, the
		// same Call-ID/CSeq/From/To/Authorization, which is what makes the
		// digest the phone computed valid at any node that shares the
		// registration database.
		out, err := s.prepareForward(req, from, s.topo.private, entry.host, false)
		if err != nil {
			s.reject(req, tx, 483, "Too Many Hops")
			return
		}
		// Rewrite the Contact toward the registrar. transport=udp is explicit
		// because FreeSWITCH copies the stored contact into the Request-URI of
		// an inbound INVITE: a leftover transport=ws there would make it try
		// to open a WebSocket to the SBC.
		//
		// An un-REGISTER is rewritten the same way and for the same reason: it
		// must name the contact that was registered, or the registrar will not
		// match it and the binding would linger upstream.
		//
		// A wildcard un-REGISTER ("Contact: *", RFC 3261 §10.2.2) is the
		// exception: it names every binding of the AoR, including the ones
		// other devices registered through FreeSBC under their own tokens,
		// so it goes upstream as "*" and is not narrowed to one token.
		if hasContact && !wildcard {
			fsip.SetContact(out, s.registeredContact(user, token))
		}
		// The Request-URI is NOT rewritten. It is part of the digest
		// calculation the phone already performed (RFC 3261 §22.4 uses the
		// "uri" of the Authorization header, which the phone derived from
		// this Request-URI), so changing it would break every authenticated
		// REGISTER.

		clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
		if err != nil {
			s.log.Warn("forward REGISTER upstream", "err", err, "aor", aor,
				"upstream", name, "attempt", attempt+1)
			if ctx.Err() != nil {
				break
			}
			// The REGISTER never got out — a transport error, not a
			// timeout: a zero-response failure while the phone is still
			// waiting. Cooldown the node and let the next one try.
			s.upstreamCooldown.Penalize(name, cooldown)
			continue
		}
		final, responded := s.pumpRegister(ctx, req, tx, clTx, in)
		clTx.Terminate()

		if final != nil {
			// ANY final response is a real judgement — accept, challenge or
			// rejection — and ends the series (D3/D7). The 401/407 case is
			// the notable one: after a failover the new node re-challenges,
			// and because the switches share a registration database the
			// phone's digest answer is valid there too. One extra round
			// trip, not a broken registration.
			s.upstreamCooldown.Recover(name)
			return
		}
		if !responded {
			// Zero responses across a whole attempt with the phone still
			// waiting: the node is suspect. Cooldown it so the NEXT
			// registration prefers its alternatives.
			s.upstreamCooldown.Penalize(name, cooldown)
			s.log.Warn("upstream REGISTER unanswered; entering cooldown",
				"aor", aor, "upstream", name, "cooldown", cooldown.String())
		}
	}

	// Every node failed and nothing was relayed: one status, synthesised
	// from what the series revealed. The shared budget expiring is a
	// timeout (504); anything else — transport errors, transactions that
	// died unanswered — is the nodes being unavailable (503).
	s.metrics.RegistrationFailed()
	if ctx.Err() != nil {
		s.reject(req, tx, 504, "Server Time-out")
	} else {
		s.reject(req, tx, 503, "Service Unavailable")
	}
}

// pumpRegister relays ONE attempt's REGISTER exchange with one upstream
// node. It returns the final response it relayed (nil when none arrived)
// and whether the node responded at all — any fsip.Forwardable response, even a
// non-final one, counts: the node is alive, and what it said must be
// relayed, not failed over.
//
// It is the response loop onRegister has always had, lifted out so the
// retry loop above can run it once per node; the response handling itself
// is unchanged.
func (s *Server) pumpRegister(ctx context.Context, req *sip.Request, tx sip.ServerTransaction, clTx sip.ClientTransaction, in bindingInput) (*sip.Response, bool) {
	responded := false
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
				continue // hop-by-hop 100 Trying
			}
			responded = true
			final := res.StatusCode >= 200
			err := s.relayResponse(req, tx, res, func(relayed *sip.Response) error {
				if final && res.StatusCode/100 == 2 {
					granted := s.recordBinding(res, in)
					// The client compares the Contact in the 200 OK
					// against the one it sent; sip.js treats a mismatch as
					// a failed registration. Put its own contact back,
					// carrying the expiry the registrar actually granted.
					// After a wildcard un-REGISTER the AoR has no binding
					// left to list, and the Contacts upstream are
					// FreeSBC's private ones, so none is relayed.
					switch {
					case in.wildcard:
						fsip.RemoveHeaders(relayed, "Contact")
					case in.hasContact:
						restoreContact(relayed, in.clientContact, granted)
					}
				}
				return nil
			})
			if err != nil {
				// The only failure this adapt can produce is the
				// unroutable-response drop: the binding was not recorded
				// and nothing was sent, so keep pumping.
				s.log.Debug("dropping unroutable REGISTER response", "code", res.StatusCode, "aor", in.aor)
				continue
			}
			if final {
				s.logRegister(res, in.aor, in.transport, in.source, in.unregister)
				return res, true
			}
		case <-clTx.Done():
			return nil, responded
		case <-ctx.Done():
			return nil, responded
		}
	}
}

// logRegister records the outcome. It deliberately never logs the
// Authorization header, the challenge nonce, or any credential (spec §16):
// the AoR, transport, source and status are the whole operational story.
func (s *Server) logRegister(res *sip.Response, aor, transport string, src netip.AddrPort, unregister bool) {
	switch {
	case res.StatusCode/100 == 2 && unregister:
		s.log.Info("registration removed", "aor", aor, "transport", transport, "public_remote", src.String())
	case res.StatusCode/100 == 2:
		s.log.Info("registration accepted", "aor", aor, "transport", transport, "public_remote", src.String())
	case res.StatusCode == 401 || res.StatusCode == 407:
		s.log.Debug("registration challenged", "aor", aor, "transport", transport)
	default:
		s.metrics.RegistrationFailed()
		s.log.Info("registration rejected", "aor", aor, "transport", transport,
			"public_remote", src.String(), "status", res.StatusCode)
	}
}

type bindingInput struct {
	token, aor, user, callID, transport string
	source                              netip.AddrPort
	requested                           time.Duration
	unregister                          bool
	// clientContact/hasContact are the client's own Contact as received,
	// carried so pumpRegister can put it back in the 200 OK.
	clientContact sip.Uri
	hasContact    bool
	// wildcard is a "Contact: *" un-REGISTER: every binding of the AoR.
	wildcard bool
}

// recordBinding installs or removes the binding after a successful
// REGISTER, and returns the expiry the registrar granted (in seconds).
//
// The lifetime comes from the RESPONSE, never the request: RFC 3261
// §10.2.4 lets a registrar grant less than was asked for, and a binding
// that outlived the registrar's own would make FreeSBC accept calls
// FreeSWITCH no longer routes.
//
// The registrar's 200 lists every binding of the AoR, so the expiry read is
// the one on the Contact carrying this binding's token, not whichever
// Contact comes first. A wildcard un-REGISTER removes every binding of the
// AoR, from every device, as it did upstream.
func (s *Server) recordBinding(res *sip.Response, in bindingInput) int {
	if in.wildcard {
		for _, b := range s.loc.ByAOR(in.aor) {
			s.loc.Remove(in.aor, b.CallID)
		}
		s.metrics.SetRegistrations(s.loc.Count())
		return 0
	}
	granted := fsip.GrantedExpires(res, in.requested, func(u sip.Uri) bool {
		t, ok := u.UriParams.Get(contactTokenParam)
		return ok && t == in.token
	})
	if in.unregister || granted <= 0 {
		s.loc.Remove(in.aor, in.callID)
		s.metrics.SetRegistrations(s.loc.Count())
		return 0
	}
	b := Binding{
		Token: in.token, AOR: in.aor, User: in.user,
		Transport: in.transport,
		CallID:    in.callID,
		Source:    in.source,
		ExpiresAt: time.Now().Add(granted),
	}
	if _, err := s.loc.Put(b); err != nil {
		// The table is full. The registration itself succeeded upstream,
		// so the client is registered — FreeSBC just cannot deliver
		// inbound calls to it. Say so loudly rather than failing silently.
		s.log.Error("registration binding rejected", "err", err, "aor", in.aor)
		s.metrics.RegistrationFailed()
		return int(granted / time.Second)
	}
	s.metrics.Registered()
	s.metrics.SetRegistrations(s.loc.Count())
	return int(granted / time.Second)
}

// existingToken returns the token already registered for this (AoR,
// Call-ID) pair, or "" if this is a new registration.
func (s *Server) existingToken(aor, callID string) string {
	for _, b := range s.loc.ByAOR(aor) {
		if b.CallID == callID {
			return b.Token
		}
	}
	return ""
}

// registeredContact is the Contact FreeSBC registers upstream on a
// client's behalf: FreeSBC's own private signaling address, carrying the
// opaque token that identifies which device the binding is for.
func (s *Server) registeredContact(user, token string) sip.Uri {
	params := sip.NewParams()
	params.Add("transport", "udp")
	params.Add(contactTokenParam, token)
	return sip.Uri{
		User:      user,
		Host:      s.topo.private.advIP.String(),
		Port:      s.topo.private.advPort,
		UriParams: params,
	}
}

// contactTokenParam is the URI parameter carrying the binding token. It is
// deliberately not a standard parameter name: it is FreeSBC's own, and
// FreeSWITCH treats it as opaque and echoes it back in the Request-URI of
// an inbound request.
const contactTokenParam = "fsbc"

// restoreContact puts the client's own Contact back into a 200 OK,
// carrying the granted expiry so the client refreshes on the registrar's
// schedule rather than its own.
func restoreContact(res *sip.Response, client sip.Uri, granted int) {
	fsip.RemoveHeaders(res, "Contact")
	h := &sip.ContactHeader{Address: client, Params: sip.NewParams()}
	h.Params.Add("expires", strconv.Itoa(granted))
	res.AppendHeader(h)
}

// aorOf derives the address-of-record from a REGISTER's To header, which
// RFC 3261 §10.2 defines as the AoR being registered.
func aorOf(req *sip.Request) (aor, user string, ok bool) {
	to := req.To()
	if to == nil || to.Address.User == "" || to.Address.Host == "" {
		return "", "", false
	}
	u := to.Address.User
	// A user part is copied into a Request-URI and a log line; anything
	// with structural characters in it is malformed, not merely unusual.
	if strings.ContainsAny(u, "@ \t\r\n<>;,\"") || len(u) > 128 {
		return "", "", false
	}
	host := to.Address.Host
	if strings.ContainsAny(host, " \t\r\n<>;,\"") || len(host) > 255 {
		return "", "", false
	}
	return strings.ToLower(u + "@" + host), u, true
}

// hasWildcardContact reports whether any Contact of req is "*".
func hasWildcardContact(req *sip.Request) bool {
	for _, h := range req.GetHeaders("Contact") {
		if c, ok := h.(*sip.ContactHeader); ok && c.Address.Wildcard {
			return true
		}
	}
	return false
}

// requestedExpires reads the lifetime the client asked for, from the
// Contact's expires parameter (which wins, RFC 3261 §10.2.1) or the
// Expires header, as delta-seconds (fsip.DeltaSeconds: a negative or
// malformed value is ignored). A zero value is an un-REGISTER.
func requestedExpires(req *sip.Request) (time.Duration, bool) {
	if hs := req.GetHeaders("Contact"); len(hs) > 0 {
		if c, ok := hs[0].(*sip.ContactHeader); ok && c.Params != nil {
			if v, ok := c.Params.Get("expires"); ok {
				if d, ok := fsip.DeltaSeconds(v); ok {
					return d, d == 0
				}
			}
		}
	}
	if h := req.GetHeader("Expires"); h != nil {
		if d, ok := fsip.DeltaSeconds(h.Value()); ok {
			return d, d == 0
		}
	}
	// No Expires at all: the registrar decides. Treat it as a
	// registration (not an un-REGISTER) and let fsip.GrantedExpires read the
	// answer off the response.
	return 0, false
}
