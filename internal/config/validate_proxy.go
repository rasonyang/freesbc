package config

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
)

// validateProxy checks the edge-proxy plane (network/sip.public/
// sip.private/sip.upstream/sip.pstn/rtp.public/rtp.private/webrtc). It is
// a no-op for a trunk-only config apart from rejecting half-written
// sections: a public listener, a media plane or a PSTN trunk configured
// WITHOUT an upstream is a mistake worth naming, not a silent no-op.
//
// fail is validate's error collector, so every problem in the file is
// reported in one pass.
func (c *Config) validateProxy(fail failFunc) {
	if !c.ProxyEnabled() {
		if c.proxyPartlyConfigured() {
			fail("sip.upstream: required to enable the edge proxy — set sip.upstream.address or sip.upstreams.nodes; sip.public/sip.private/sip.pstn/rtp.public/rtp.private/webrtc are configured but there is no upstream to proxy to")
		}
		return
	}

	// A trunk listener with no peers can only drop traffic: the trunk
	// plane identifies every inbound request by matching its source
	// against a peer's allowed_ips, so with no peers configured the
	// listener is dead weight. Without the edge proxy this is already
	// rejected ("peers: at least one peer required"); with it, the
	// listener would otherwise bind silently and serve nothing.
	if len(c.Peers) == 0 && (len(c.Listen.SIP) > 0 || c.SIP.BindIP != "") {
		fail("listen.sip/sip.bind_ip: configured with no peers — the trunk plane identifies callers by peer allowed_ips, so this listener could only drop traffic. Remove it, or add the peers it is for.")
	}

	c.validateUpstreams(fail)
	if c.SIP.Pstn.configured() {
		c.validatePSTN(fail)
	}
	c.validatePlane("network.public", c.Network.Public, fail)
	c.validatePlane("network.private", c.Network.Private, fail)
	c.validatePublicListeners(fail)
	c.validatePrivateSIP(fail)
	c.validateMediaPlanes(fail)
	c.validatePoolOverlap(fail)
	c.validateWebRTC(fail)
}

// proxyPartlyConfigured reports whether any edge-only section was written.
func (c *Config) proxyPartlyConfigured() bool {
	ups := c.SIP.Upstreams
	upsSet := len(ups.Nodes) > 0 || ups.Algorithm != "" || ups.Cooldown != 0
	return len(c.PublicSIPListeners()) > 0 || c.RTP.Public.configured() || c.RTP.Private.configured() ||
		c.WebRTC.Enabled || !c.SIP.Private.Bind.IsZero() || c.SIP.Pstn.configured() || upsSet
}

// validateUpstreams checks the upstream in either shape.
func (c *Config) validateUpstreams(fail failFunc) {
	// Two mutually exclusive shapes, exactly like sip.pstn: the v1 alias
	// (sip.upstream.address) and the multi-switch pool (sip.upstreams.nodes).
	// The alias converges on the pool at topology build time as node
	// "default", so the runtime never knows which shape produced it — but
	// writing both is a mistake worth naming, not a merge to guess at.
	ups := c.SIP.Upstreams
	if c.SIP.Upstream.Address != "" && len(ups.Nodes) > 0 {
		fail("sip.upstreams: sip.upstream.address and sip.upstreams.nodes are mutually exclusive — use the single-upstream alias or the multi-switch pool, not both")
	}
	if c.SIP.Upstream.Address != "" {
		checkIPPort(fail, "sip.upstream.address", c.SIP.Upstream.Address)
		// Deliberately narrow: §2 of the spec scopes the private/upstream
		// transport to UDP for this phase. Reject anything else loudly rather
		// than binding a transport the forwarding path can't route responses
		// back through.
		checkUDPOnly(fail, "sip.upstream.transport", c.SIP.Upstream.Transport)
	}
	if len(ups.Nodes) > 0 {
		// The algorithm field is a forward-compatibility seam: exactly one
		// value is implemented, so anything else is a config error rather
		// than a silent fallback to hashing. Each node is checked like the
		// alias and like a pstn gateway — literal IP:port, UDP only.
		if ups.Algorithm != "hash-user" {
			fail("sip.upstreams.algorithm: only \"hash-user\" is supported, got %q", ups.Algorithm)
		}
		for _, name := range sortedKeys(ups.Nodes) {
			n := ups.Nodes[name]
			label := "sip.upstreams.nodes." + name
			if n == nil || n.Address == "" {
				fail("%s.address: required", label)
				continue
			}
			checkIPPort(fail, label+".address", n.Address)
			// Same reasoning as the alias transport: the private leg is UDP in
			// this phase, and the forwarding path has no way to route a
			// TCP/TLS response back to the right transaction.
			checkUDPOnly(fail, label+".transport", n.Transport)
		}
	}
	if ups.Cooldown < 0 {
		// Like the pstn budgets: zero means "use the default", so a
		// negative value is an operator mistake to name, not to default
		// away.
		fail("sip.upstreams.cooldown: must not be negative, got %v", ups.Cooldown.Std())
	}
}

// validatePSTN checks sip.pstn, which is optional: an outbound PSTN trunk
// riding the public UDP plane, in one of two mutually exclusive shapes — the
// v1 single-gateway alias (address + match) or the multi form (gateways +
// routes + match). Either way its match must not collide with an address
// FreeSWITCH already uses for other traffic, or the classification in the
// proxy's onInvite would misroute calls that are not PSTN bridges at all.
func (c *Config) validatePSTN(fail failFunc) {
	pstn := c.SIP.Pstn
	// Both budgets are optional but signed: zero means "use the
	// default", so a negative value is an operator mistake to name
	// here, not a value to default away.
	if pstn.AttemptTimeout < 0 {
		fail("sip.pstn.attempt_timeout: must not be negative, got %v", pstn.AttemptTimeout.Std())
	}
	if pstn.Cooldown < 0 {
		fail("sip.pstn.cooldown: must not be negative, got %v", pstn.Cooldown.Std())
	}

	alias := pstn.Address != ""
	gws := len(pstn.Gateways) > 0
	routes := len(pstn.Routes) > 0
	switch {
	case alias && (gws || routes):
		fail("sip.pstn: address and gateways are mutually exclusive — use the single-gateway alias (address) or the multi-gateway form (gateways + routes), not both")
	case alias:
		// ---- v1 alias: a strict address AND match pair, byte-for-byte
		// the checks the deployed shape has always had.
		checkIPPort(fail, "sip.pstn.address", pstn.Address)
		c.validatePSTNMatch(pstn, "sip.pstn.address", fail)
	case gws:
		c.validatePSTNMulti(pstn, fail)
		c.validatePSTNMatch(pstn, "sip.pstn.gateways", fail)
	default:
		// The section exists but names no gateway in either form:
		// match/routes/timers alone are configuration with nothing to
		// route to.
		if !pstn.Match.IsZero() {
			fail("sip.pstn.match: requires sip.pstn.address")
		} else if routes {
			fail("sip.pstn.routes: require sip.pstn.gateways — a route can only name configured gateways")
		} else {
			fail("sip.pstn: address or gateways required — match/attempt_timeout/cooldown alone configure nothing")
		}
	}

	if pstn.Transport != "" {
		// The carrier leg rides the public UDP plane, which is the only
		// public transport the forwarding path can send a peer-to-peer
		// call over without a registration to bind it to.
		checkUDPOnly(fail, "sip.pstn.transport", pstn.Transport)
	}
	if !c.SIP.Public.UDP.Enabled {
		fail("sip.pstn: requires sip.public.udp.enabled — the carrier leg rides the public UDP side")
	}
}

// validatePSTNMulti checks the multi shape: named gateways plus the routes
// that select and order them. Both halves are required — a gateway that no
// route names is dead config, and a route with nothing to name cannot
// exist.
func (c *Config) validatePSTNMulti(pstn PstnConfig, fail failFunc) {
	if len(pstn.Routes) == 0 {
		fail("sip.pstn.routes: at least one route required when gateways are configured — the route is what selects which gateways a called number fails over across")
	}
	for _, name := range sortedKeys(pstn.Gateways) {
		g := pstn.Gateways[name]
		label := "sip.pstn.gateways." + name
		if g == nil || g.Address == "" {
			fail("%s.address: required", label)
			continue
		}
		checkIPPort(fail, label+".address", g.Address)
		// Same reasoning as the alias transport: the carrier leg rides
		// the public UDP plane, the only public transport the
		// forwarding path can use without a registration.
		checkUDPOnly(fail, label+".transport", g.Transport)
	}
	for i, r := range pstn.Routes {
		label := fmt.Sprintf("sip.pstn.routes[%d]", i)
		if len(r.To) == 0 {
			fail("%s: to: at least one gateway required", label)
		}
		for _, t := range r.To {
			if _, ok := pstn.Gateways[t]; !ok {
				fail("%s: to: unknown gateway %q", label, t)
			}
		}
		r.matchTo = nil
		if r.Match != "" {
			// Compiled once at validate time, exactly like the trunk
			// routes (validate.go): a bad pattern is a config error,
			// not a discovery on the first matching call.
			re, err := regexp.Compile(r.Match)
			if err != nil {
				fail("%s: match: %v", label, c.envRedact.detail(r.Match, err))
			} else {
				r.matchTo = re
			}
		}
	}
}

// validatePublicListeners checks the enabled public listeners. Their binds
// are never empty here: proxyWithDefaults gives every enabled listener a
// default bind (audit P2-CFG-010), and socket collisions across every
// plane are validateSockets' job.
func (c *Config) validatePublicListeners(fail failFunc) {
	listeners := c.PublicSIPListeners()
	if len(listeners) == 0 {
		fail("sip.public: at least one of udp/ws/wss must be enabled when the edge proxy is on")
	}
	for _, l := range listeners {
		label := "sip.public." + l.Transport
		if _, err := netip.ParseAddr(l.Bind.Host); err != nil {
			fail("%s.bind: %q is not a valid IP", label, l.Bind.Host)
		}
		if l.Transport == "wss" {
			checkFilePair(fail, "sip.public.wss", "cert_file", l.CertFile, "key_file", l.KeyFile)
		}
	}
	if !c.PublicAdvertisedIP().IsValid() {
		fail("network.public.advertised_ip: required — the public bind address is unspecified/unset, so Contact, Via and SDP would have no routable address to advertise")
	}
	if !c.PrivateAdvertisedIP().IsValid() {
		fail("network.private.advertised_ip: required — the private bind address is unspecified/unset, so FreeSWITCH would have no routable address to reach the SBC on")
	}
}

// validatePrivateSIP checks the private SIP socket. Its bind is always set
// here: proxyWithDefaults defaults it whenever the proxy is on (audit
// P2-CFG-010).
func (c *Config) validatePrivateSIP(fail failFunc) {
	if _, err := netip.ParseAddr(c.SIP.Private.Bind.Host); err != nil {
		fail("sip.private.bind: %q is not a valid IP", c.SIP.Private.Bind.Host)
	}
	checkAdvertisedIP(fail, "sip.private.advertised_ip", c.SIP.Private.AdvertisedIP, "FreeSWITCH could not route to it")
	checkPort(fail, "sip.private.advertised_port", c.SIP.Private.AdvertisedPort)
}

// validateMediaPlanes checks rtp.public and rtp.private.
func (c *Config) validateMediaPlanes(fail failFunc) {
	c.validateRTPPlane("rtp.public", c.RTP.Public, fail)
	c.validateRTPPlane("rtp.private", c.RTP.Private, fail)
	if !c.RTP.Public.configured() {
		fail("rtp.public: port_min/port_max required when the edge proxy is on")
	}
	if !c.RTP.Private.configured() {
		fail("rtp.private: port_min/port_max required when the edge proxy is on")
	}
	if !c.PublicRTPAdvertisedIP().IsValid() {
		fail("rtp.public.advertised_ip: required — no advertised public media address, so SDP toward phones/browsers would be unroutable")
	}
	if !c.PrivateRTPAdvertisedIP().IsValid() {
		fail("rtp.private.advertised_ip: required — no advertised private media address, so SDP toward FreeSWITCH would be unroutable")
	}
}

// validatePoolOverlap rejects media pools that could hand out the same
// port. Each pool tracks its own in-use set, so the second bind merely
// fails and the call is rejected — a silent capacity cliff. The trunk
// plane's own range is included: with a shared bind address it draws from
// the same port space.
func (c *Config) validatePoolOverlap(fail failFunc) {
	type namedRange struct {
		label string
		bind  string
		r     PortRange
	}
	ranges := []namedRange{
		{"rtp.public", c.RTP.Public.BindIP, c.RTP.Public.Range()},
		{"rtp.private", c.RTP.Private.BindIP, c.RTP.Private.Range()},
	}
	if tr := c.RTPPortRange(); tr != (PortRange{}) && len(c.Peers) > 0 {
		ranges = append(ranges, namedRange{"the trunk media range (rtp.port_min/port_max or listen.media.port_range)", c.RTP.BindIP, tr})
	}
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			a, b := ranges[i], ranges[j]
			if a.r == (PortRange{}) || b.r == (PortRange{}) || !bindsCanCollide(a.bind, b.bind) {
				continue
			}
			if a.r.Min <= b.r.Max && b.r.Min <= a.r.Max {
				fail("%s and %s overlap on %d-%d: each media pool needs its own port range",
					a.label, b.label, maxU16(a.r.Min, b.r.Min), minU16(a.r.Max, b.r.Max))
			}
		}
	}
}

// validateWebRTC checks the browser media leg.
func (c *Config) validateWebRTC(fail failFunc) {
	if !c.WebRTC.Enabled {
		return
	}
	if c.WebRTC.ICEMode != "lite" {
		fail("webrtc.ice_mode: only \"lite\" is supported, got %q", c.WebRTC.ICEMode)
	}
	if c.WebRTC.RTCPMux != nil && !*c.WebRTC.RTCPMux {
		fail("webrtc.rtcp_mux: must be true — FreeSBC allocates one ICE component per session and cannot serve a non-muxed browser leg")
	}
	checkFilePair(fail, "webrtc", "dtls_cert_file", c.WebRTC.DTLSCertFile, "dtls_key_file", c.WebRTC.DTLSKeyFile)
	if !c.SIP.Public.WS.Enabled && !c.SIP.Public.WSS.Enabled {
		fail("webrtc.enabled: requires sip.public.ws or sip.public.wss — a browser has no other way to signal")
	}
}

// boundSocket is one listening socket the process will bind at startup.
type boundSocket struct {
	label string // config key, for the error
	proto string // "udp" or "tcp"
	host  string
	port  int
}

// validateSockets rejects two listeners that would bind the same socket, on
// either plane or the admin API: `run` would fail with "address already in
// use", so `check` must too (audit P2-CFG-004). tcp, tls, ws and wss all
// listen on TCP; a wildcard bind collides with every address on its port.
func (c *Config) validateSockets(fail failFunc) {
	var socks []boundSocket
	if c.SIP.BindIP != "" {
		socks = append(socks, boundSocket{"sip.bind_ip", sockProto(c.SIP.Transport), c.SIP.BindIP, c.SIP.BindPort})
	}
	for i, l := range c.Listen.SIP {
		socks = append(socks, boundSocket{fmt.Sprintf("listen.sip[%d]", i), sockProto(l.Transport), l.Host, l.Port})
	}
	if c.ProxyEnabled() {
		for _, l := range c.PublicSIPListeners() {
			socks = append(socks, boundSocket{"sip.public." + l.Transport + ".bind", sockProto(l.Transport), l.Bind.Host, l.Bind.Port})
		}
		b := c.SIP.Private.Bind
		socks = append(socks, boundSocket{"sip.private.bind", "udp", b.Host, b.Port})
	}
	if c.Admin != nil {
		if ap, err := netip.ParseAddrPort(c.Admin.Listen); err == nil {
			socks = append(socks, boundSocket{"admin.listen", "tcp", ap.Addr().String(), int(ap.Port())})
		}
	}
	for i := 1; i < len(socks); i++ {
		for _, prev := range socks[:i] {
			s := socks[i]
			if s.proto == prev.proto && s.port == prev.port && hostsCollide(s.host, prev.host) {
				fail("%s: %s/%s already bound by %s", s.label, s.proto, net.JoinHostPort(s.host, strconv.Itoa(s.port)), prev.label)
				break
			}
		}
	}
}

// hostsCollide reports whether two listeners on one protocol and port bind
// overlapping addresses: an empty or unspecified host is every interface
// and collides with anything; two IPs collide only when equal. A hostname
// (legal in listen.sip) binds whatever it resolves to at startup, which
// validation cannot know, so it collides only with the same name.
func hostsCollide(a, b string) bool {
	wildcard := func(h string) bool {
		ip, err := netip.ParseAddr(h)
		return h == "" || (err == nil && ip.IsUnspecified())
	}
	if wildcard(a) || wildcard(b) {
		return true
	}
	ia, errA := netip.ParseAddr(a)
	ib, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return ia == ib
}

// sockProto maps a SIP transport to the socket protocol it listens on.
func sockProto(transport string) string {
	if transport == "udp" {
		return "udp"
	}
	return "tcp"
}

// sortedKeys returns m's keys in order, so errors come out stable.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// validatePSTNMatch checks sip.pstn.match, required by both pstn shapes
// (withKey names the key that requires it). Like every edge address it must
// be a literal IP, since the edge plane does no DNS. The classification
// keys on the match host:port alone (the called number varies per call),
// so a match that names an address FreeSWITCH legitimately uses for other
// traffic would shadow it: every such call would be routed to the carrier
// instead of its real destination. The private SIP socket and the upstream
// are exactly the two addresses FreeSWITCH talks to for everything else —
// and in the pool shape "the upstream" is every node, not just the one the
// operator happened to be thinking of, so the alias and all nodes are
// checked alike.
func (c *Config) validatePSTNMatch(pstn PstnConfig, withKey string, fail failFunc) {
	if pstn.Match.IsZero() {
		fail("sip.pstn.match: required with %s", withKey)
		return
	}
	if _, err := netip.ParseAddr(pstn.Match.Host); err != nil {
		fail("sip.pstn.match: %q is not a literal IP — the edge plane does no DNS", pstn.Match.Host)
	}
	if pstn.Match.Host == c.SIP.Private.Bind.Host && pstn.Match.Port == c.SIP.Private.Bind.Port {
		fail("sip.pstn.match: must not name the SBC's private SIP address")
	}
	if pstn.Match.Host == c.PrivateAdvertisedIP().String() && pstn.Match.Port == c.PrivateSIPAdvertisedPort() {
		fail("sip.pstn.match: must not name the SBC's private SIP address")
	}
	collidesUpstream := func(address string) bool {
		uh, up, err := net.SplitHostPort(address)
		if err != nil {
			return false
		}
		p, err := strconv.Atoi(up)
		return err == nil && pstn.Match.Host == uh && pstn.Match.Port == p
	}
	if c.SIP.Upstream.Address != "" && collidesUpstream(c.SIP.Upstream.Address) {
		fail("sip.pstn.match: must not name the upstream")
	}
	for _, n := range c.SIP.Upstreams.Nodes {
		if n != nil && n.Address != "" && collidesUpstream(n.Address) {
			fail("sip.pstn.match: must not name the upstream")
		}
	}
}

func (c *Config) validatePlane(label string, p NetworkPlane, fail failFunc) {
	checkIP(fail, label+".bind_ip", p.BindIP)
	checkAdvertisedIP(fail, label+".advertised_ip", p.AdvertisedIP, "advertising it would blackhole signaling and media")
}

func (c *Config) validateRTPPlane(label string, p RTPPlaneConfig, fail failFunc) {
	if !p.configured() {
		return
	}
	checkIP(fail, label+".bind_ip", p.BindIP)
	checkAdvertisedIP(fail, label+".advertised_ip", p.AdvertisedIP, "SDP would blackhole media")
	if (p.PortMin == 0) != (p.PortMax == 0) {
		fail("%s: port_min and port_max must be set together", label)
		return
	}
	if p.PortMin == 0 {
		fail("%s: port_min/port_max required", label)
		return
	}
	checkPortRange(fail, label, label, "session", p.PortMin, p.PortMax)
	// An edge session binds one pair per plane; a range such as
	// 30001-30002 passes min < max yet holds none (audit P2-CFG-009).
	if p.PortMin < p.PortMax && rtpPairs(p.PortMin, p.PortMax) < 1 {
		fail("%s: %d-%d holds no RTP/RTCP pair (RTP on an even port, RTCP on RTP+1) — widen it", label, p.PortMin, p.PortMax)
	}
}

// checkIPPort fails unless address is a literal "IP:port" with a port in
// 1-65535. Every edge-plane address is one: the edge plane does no DNS
// (edge/topology.go parseEndpoint), so `check` rejects a hostname exactly
// as `run` would (audit P2-CFG-004). label is the full config key.
func checkIPPort(fail failFunc, label, address string) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		fail("%s: %q is not \"host:port\"", label, address)
		return
	}
	if host == "" {
		fail("%s: host required", label)
	} else if _, err := netip.ParseAddr(host); err != nil {
		fail("%s: %q is not a literal IP — the edge plane does no DNS", label, host)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		fail("%s: bad port in %q", label, address)
	}
}

// checkUDPOnly rejects every transport but UDP. Both the private/upstream
// leg and the carrier leg are UDP-only in this phase: the forwarding path
// has no way to route a TCP/TLS response back to the right transaction.
func checkUDPOnly(fail failFunc, label, transport string) {
	if transport != "udp" {
		fail("%s: only \"udp\" is supported, got %q", label, transport)
	}
}

// bindsCanCollide reports whether two pools' bind addresses draw from the
// same host port space. An empty or unspecified bind means "every
// interface", which collides with everything; two different specific
// addresses do not.
func bindsCanCollide(a, b string) bool {
	wildcard := func(s string) bool {
		if s == "" {
			return true
		}
		ip, err := netip.ParseAddr(s)
		return err != nil || ip.IsUnspecified()
	}
	if wildcard(a) || wildcard(b) {
		return true
	}
	return a == b
}

func maxU16(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
}

func minU16(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}
