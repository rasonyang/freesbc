package edge

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file is the switch's registration at a carrier (issue #96, "Carrier
// path"): the switch REGISTERs a gateway through FreeSBC, and FreeSBC
// proxies it with the Contact rewritten to a public address that carries an
// opaque token. The carrier then sends inbound calls to that Contact, and
// the token tells FreeSBC which switch node registered it and what the
// switch's own Contact was, so the call is delivered to that node with its
// own Contact as the Request-URI (what FreeSWITCH gw+<name> and Asterisk
// line= identify an inbound call by).
//
// The table is separate from the client Location on purpose: a client token
// is random and names a public client, a carrier token is derived and names
// a switch registration. Neither lookup ever resolves the other's token.
//
// FreeSBC holds no credential here either: the 401/407 challenge and the
// retried REGISTER pass through untouched.

// carrierBinding is one live carrier registration.
type carrierBinding struct {
	token   string
	carrier string  // edge.carriers name
	node    string  // edge.switch node name ("IP:port")
	contact sip.Uri // the switch's original Contact
	expires time.Time
}

// carrierRegTable is the set of live carrier registrations by token.
type carrierRegTable struct {
	mu      sync.Mutex
	byToken map[string]carrierBinding
}

func newCarrierRegTable() *carrierRegTable {
	return &carrierRegTable{byToken: map[string]carrierBinding{}}
}

// put installs or refreshes a binding.
func (t *carrierRegTable) put(b carrierBinding) {
	t.mu.Lock()
	t.byToken[b.token] = b
	t.mu.Unlock()
}

// remove deletes the binding with this token.
func (t *carrierRegTable) remove(token string) {
	t.mu.Lock()
	delete(t.byToken, token)
	t.mu.Unlock()
}

// removeNode deletes every binding a switch node holds at a carrier (a
// wildcard un-REGISTER).
func (t *carrierRegTable) removeNode(carrier, node string) {
	t.mu.Lock()
	for k, b := range t.byToken {
		if b.carrier == carrier && b.node == node {
			delete(t.byToken, k)
		}
	}
	t.mu.Unlock()
}

// lookup finds a live binding. An expired one is not found (the periodic
// prune only reclaims it).
func (t *carrierRegTable) lookup(token string) (carrierBinding, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.byToken[token]
	if !ok || !time.Now().Before(b.expires) {
		return carrierBinding{}, false
	}
	return b, true
}

// prune drops expired bindings and reports how many.
func (t *carrierRegTable) prune() int {
	now := time.Now()
	n := 0
	t.mu.Lock()
	for k, b := range t.byToken {
		if !now.Before(b.expires) {
			delete(t.byToken, k)
			n++
		}
	}
	t.mu.Unlock()
	return n
}

// counts is the live binding count per carrier, with every configured
// carrier present (zero included) so a gauge drops to 0 instead of
// vanishing.
func (t *carrierRegTable) counts(names []string) map[string]int {
	out := make(map[string]int, len(names))
	for _, n := range names {
		out[n] = 0
	}
	now := time.Now()
	t.mu.Lock()
	for _, b := range t.byToken {
		if now.Before(b.expires) {
			out[b.carrier]++
		}
	}
	t.mu.Unlock()
	return out
}

// publishCarrierRegistrations refreshes the per-carrier gauge.
func (s *Server) publishCarrierRegistrations() {
	names := make([]string, 0, len(s.carrierURIs))
	for _, n := range s.carrierURIs {
		names = append(names, n)
	}
	s.metrics.SetCarrierRegistrations(s.carrierRegs.counts(names))
}

// carrierToken derives the opaque token of a carrier registration from the
// switch node and its original Contact. It is deterministic so a FreeSBC
// restart does not strand the Contact the carrier already holds: the
// switch's next refresh recreates the same token. Anyone who can guess a
// node name and a Contact can compute it; the token is an identifier, not a
// secret, and the carrier path admits only carrier sources.
func carrierToken(node, contact string) string {
	sum := sha256.Sum256([]byte(node + "\n" + contact))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return strings.ToLower(enc[:26])
}

// carrierDest is where a request for a carrier is sent: the first resolved
// address of its edge.carriers entry. There is no failover across a DNS
// name's targets inside FreeSBC; the switch fails over between gateways.
func (s *Server) carrierDest(name string) (string, bool) {
	addrs := s.carriers.snapshot().addrs[name]
	if len(addrs) == 0 {
		return "", false
	}
	return addrs[0].String(), true
}

// switchNodeFor names the edge.switch node a request from the private
// socket came from: the entry with the source's IP, preferring an equal
// port, else the first (by name).
func (s *Server) switchNodeFor(src netip.AddrPort) (string, bool) {
	first := ""
	for _, name := range s.topo.upstreamNames {
		a := s.topo.upstreams[name].addr
		if a.Addr().Unmap() != src.Addr().Unmap() {
			continue
		}
		if a.Port() == src.Port() {
			return name, true
		}
		if first == "" {
			first = name
		}
	}
	return first, first != ""
}

// carrierContactURI is the Contact toward a carrier for a REGISTER: the
// switch's user at FreeSBC's public address on the carrier's transport
// (;transport=tcp|tls when not udp), carrying the token. For a tcp or tls
// carrier with no matching public listener the port is the transport's
// default and nothing listens there: the carrier can only send back over the
// connection FreeSBC opened to it.
func (s *Server) carrierContactURI(pub side, user, token string) sip.Uri {
	params := sip.NewParams()
	params.Add(contactTokenParam, token)
	if pub.transport != "udp" {
		params.Add("transport", pub.transport)
	}
	return sip.Uri{User: user, Host: pub.advIP.String(), Port: pub.advPort, UriParams: params}
}

// registerToCarrier proxies a REGISTER the switch sent for a carrier.
func (s *Server) registerToCarrier(req *sip.Request, tx sip.ServerTransaction, in inbound, carrier string) {
	dest, ok := s.carrierDest(carrier)
	if !ok {
		s.log.Warn("carrier has no resolved address", "carrier", carrier, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	pub, ok := s.carrierSide(carrier)
	node, nodeOK := s.switchNodeFor(in.src)
	if !ok || !nodeOK {
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	wildcard := hasWildcardContact(req)
	requested, unregister := requestedExpires(req)
	if wildcard && (!unregister || len(req.GetHeaders("Contact")) != 1) {
		s.reject(req, tx, 400, "Bad Request")
		return
	}
	orig, hasContact := fsip.ContactURI(req)

	out, err := s.prepareForwardHidden(req, s.topo.private, pub, dest, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	token := ""
	if hs := req.GetHeaders("Contact"); len(hs) > 0 {
		if oc, isC := hs[0].(*sip.ContactHeader); isC {
			// The Contact header keeps its own parameters (expires, q); only
			// its address changes. A wildcard "*" goes upstream as it is.
			c := oc.Clone()
			if hasContact && !wildcard {
				token = carrierToken(node, orig.String())
				c.Address = s.carrierContactURI(pub, orig.User, token)
			}
			fsip.RemoveHeaders(out, "Contact")
			out.AppendHeader(c)
		}
	}
	// The Request-URI, Authorization and Call-ID are untouched: the digest
	// the switch computed covers them.

	s.metrics.CarrierRequest(carrier, dirOutbound, "REGISTER")
	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	defer cancel()
	_, err = s.forwardAndRelay(ctx, req, tx, out, respToSwitch, func(relayed *sip.Response) error {
		if relayed.StatusCode/100 != 2 {
			return nil // challenges and failures pass through untouched
		}
		switch {
		case wildcard:
			s.carrierRegs.removeNode(carrier, node)
			fsip.RemoveHeaders(relayed, "Contact")
		case hasContact:
			granted := fsip.GrantedExpires(relayed, requested, func(u sip.Uri) bool {
				t, ok := u.UriParams.Get(contactTokenParam)
				return ok && t == token
			})
			secs := int(granted / time.Second)
			if unregister || granted <= 0 {
				s.carrierRegs.remove(token)
				secs = 0
			} else {
				s.carrierRegs.put(carrierBinding{
					token: token, carrier: carrier, node: node,
					contact: orig, expires: time.Now().Add(granted),
				})
			}
			restoreContact(relayed, orig, secs)
			s.log.Info("carrier registration", "carrier", carrier, "switch", node,
				"expires", strconv.Itoa(secs))
		}
		s.publishCarrierRegistrations()
		return nil
	})
	if err != nil {
		s.log.Warn("forward carrier REGISTER", "err", err, "carrier", carrier, "sip_call_id", fsip.CallID(req))
		if ctx.Err() != nil {
			s.reject(req, tx, 504, "Server Time-out")
		} else {
			s.reject(req, tx, 503, "Service Unavailable")
		}
	}
}

// carrierRURI resolves the outbound-registration token in a carrier's
// Request-URI. found is false for no token, or an unknown or expired one
// (logged: the request then falls back to the hash pool, Request-URI
// unchanged). A node that is no longer in the topology is treated the same.
func (s *Server) carrierRURI(req *sip.Request, carrier string) (carrierBinding, bool) {
	tok, ok := tokenOf(req.Recipient)
	if !ok {
		return carrierBinding{}, false
	}
	b, found := s.carrierRegs.lookup(tok)
	if found {
		if _, inPool := s.topo.upstreams[b.node]; inPool {
			return b, true
		}
	}
	s.log.Warn("carrier request names an unknown or expired registration token; treating it as addressed to the DID",
		"carrier", carrier, "sip_call_id", fsip.CallID(req))
	return carrierBinding{}, false
}

// CarrierRegistrationInfo is the operator view of one live carrier
// registration. The switch's original Contact is not included.
type CarrierRegistrationInfo struct {
	Carrier string
	User    string // user part of the switch's Contact
	Token   string
	Node    string // switch node "IP:port"
	Expires time.Time
}

// snapshot copies the live bindings under the lock, ordered by carrier,
// user, node and token. The result is never nil.
func (t *carrierRegTable) snapshot() []CarrierRegistrationInfo {
	now := time.Now()
	t.mu.Lock()
	out := make([]CarrierRegistrationInfo, 0, len(t.byToken))
	for _, b := range t.byToken {
		if now.Before(b.expires) {
			out = append(out, CarrierRegistrationInfo{Carrier: b.carrier, User: b.contact.User,
				Token: b.token, Node: b.node, Expires: b.expires})
		}
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Carrier != b.Carrier {
			return a.Carrier < b.Carrier
		}
		if a.User != b.User {
			return a.User < b.User
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.Token < b.Token
	})
	return out
}
