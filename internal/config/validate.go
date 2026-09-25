package config

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// failFunc is validate's error collector. Every section check takes it, so
// every problem in the file is reported in one pass.
type failFunc func(format string, args ...any)

// validate checks cross-references and value constraints, collecting every
// problem instead of stopping at the first. On success it also compiles
// derived state (peer allowed-IP prefixes, route match regexes). It is
// unexported: Parse is the only supported entry point into the lifecycle
// described on Config.
func (c *Config) validate() error {
	var errs []string
	// Messages may name a value, and validation runs after ${VAR}
	// expansion, so every argument is redacted: an error must never echo
	// an environment value (it reaches `freesbc check` output and the
	// admin PUT response).
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, c.envRedact.args(args)...))
	}

	c.validateTrunkListen(fail)
	c.validateTrunkNAT(fail)
	c.validateTrunkMediaRange(fail)
	c.validateTimers(fail)
	c.validatePeers(fail)
	c.validateRoutes(fail)
	c.validateShield(fail)
	c.validateAdmin(fail)
	c.validateTLSPairs(fail)
	c.validateProxy(fail)
	c.validateSockets(fail)

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// validateTrunkListen checks listen.sip/listen.media.
func (c *Config) validateTrunkListen(fail failFunc) {
	// The trunk B2BUA plane needs a listener and at least one peer — but a
	// proxy-only deployment (edge proxy on, no trunks) legitimately has
	// neither. Both requirements are therefore conditional on the proxy
	// plane being off; validateProxy enforces the proxy plane's own
	// listener requirement.
	if len(c.Listen.SIP) == 0 && c.SIP.BindIP == "" && !c.ProxyEnabled() {
		fail("listen.sip or sip.bind_ip: at least one SIP listener required")
	}
	if pr := c.Listen.Media.PortRange; pr != (PortRange{}) && pr.Min < 1024 {
		fail("listen.media.port_range: must start at or above 1024, got %d-%d", pr.Min, pr.Max)
	}
	if pub := c.Listen.Media.PublicIP; pub != "auto" {
		if _, err := netip.ParseAddr(pub); err != nil {
			fail("listen.media.public_ip: %q is neither \"auto\" nor a valid IP", pub)
		}
	}
	if c.Listen.Media.RTPTimeout.Std() <= 0 {
		fail("listen.media.rtp_timeout: must be > 0, got %v", c.Listen.Media.RTPTimeout.Std())
	}
}

// validateTrunkNAT checks the sip/rtp bind-advertised topology (NAT/VPN).
func (c *Config) validateTrunkNAT(fail failFunc) {
	// Any configured sip.* field requires the full bind pair, and the
	// section is mutually exclusive with the legacy listen.sip list — two
	// listener sources would be ambiguous.
	sipSet := c.SIP.BindIP != "" || c.SIP.BindPort != 0 ||
		c.SIP.AdvertisedIP != "" || c.SIP.AdvertisedPort != 0
	if sipSet && c.SIP.BindIP == "" {
		fail("sip.bind_ip: required when any sip.* field is configured")
	}
	if sipSet && c.SIP.BindPort == 0 {
		fail("sip.bind_port: required when any sip.* field is configured")
	}
	if c.SIP.BindIP != "" {
		checkIP(fail, "sip.bind_ip", c.SIP.BindIP)
		if len(c.Listen.SIP) > 0 {
			fail("sip.bind_ip and listen.sip are mutually exclusive: the sip section replaces the listen.sip listener list — configure one or the other")
		}
	}
	checkPort(fail, "sip.bind_port", c.SIP.BindPort)
	switch c.SIP.Transport {
	case "udp", "tcp", "tls":
	default:
		fail("sip.transport: must be udp, tcp, or tls, got %q", c.SIP.Transport)
	}
	checkAdvertisedIP(fail, "sip.advertised_ip", c.SIP.AdvertisedIP, "advertising it in Contact/From would be unroutable")
	checkPort(fail, "sip.advertised_port", c.SIP.AdvertisedPort)
	checkIP(fail, "rtp.bind_ip", c.RTP.BindIP)
	checkAdvertisedIP(fail, "rtp.advertised_ip", c.RTP.AdvertisedIP, "advertising it in SDP would blackhole media")
	// Blackhole guard for the NAT/VPN topology: with sip.bind_ip configured
	// there are no listen.sip hosts for the SDP media IP to fall back on
	// (see Server.mediaIP), so without an explicit rtp.advertised_ip — and
	// with public_ip left "auto", since STUN discovery isn't implemented —
	// every SDP would advertise 127.0.0.1.
	if c.SIP.BindIP != "" && c.RTP.AdvertisedIP == "" && c.Listen.Media.PublicIP == "auto" {
		fail("rtp.advertised_ip: required when sip.bind_ip is configured and listen.media.public_ip is \"auto\" — otherwise SDP media would advertise 127.0.0.1")
	}
}

// trunkPairsPerCall is how many RTP/RTCP port pairs one trunk call binds:
// PlanePool.Allocate anchors both legs on the SBC, one pair per leg.
const trunkPairsPerCall = 2

// validateTrunkMediaRange checks rtp.port_min/port_max against the legacy
// listen.media.port_range, and that the effective trunk range holds a call.
func (c *Config) validateTrunkMediaRange(fail failFunc) {
	// rtp.port_min/port_max: both-or-neither, and mutually exclusive with
	// the legacy listen.media.port_range — two range sources would be
	// ambiguous. Bounds mirror the legacy range (>= 1024 keeps the pool
	// unprivileged; <= 65535 is the UDP port ceiling).
	rtpRangeSet := c.RTP.PortMin != 0 || c.RTP.PortMax != 0
	if rtpRangeSet && (c.RTP.PortMin == 0 || c.RTP.PortMax == 0) {
		fail("rtp.port_min and rtp.port_max must be set together")
	}
	if c.RTP.PortMin != 0 {
		if c.Listen.Media.PortRange != (PortRange{}) {
			fail("rtp.port_min/port_max and listen.media.port_range are mutually exclusive: the rtp section replaces the legacy range — configure one or the other")
		}
		// A degenerate (min == max) range can never hold an RTP+RTCP pair —
		// checkPortRange rejects it up front rather than let every call fail
		// with "exhausted".
		checkPortRange(fail, "rtp", "rtp.port_min/port_max", "call", c.RTP.PortMin, c.RTP.PortMax)
	}
	// Only the trunk plane allocates from this range, and a trunk call
	// needs two pairs: a range that validates must hold at least one call,
	// or every INVITE would be answered 503 (audit P2-CFG-009).
	if len(c.Peers) == 0 {
		return
	}
	tr := c.RTPPortRange()
	if tr == (PortRange{}) || tr.Min >= tr.Max {
		return // no range, or already reported as inverted
	}
	if n := rtpPairs(int(tr.Min), int(tr.Max)); n < trunkPairsPerCall {
		label := "listen.media.port_range"
		if c.RTP.PortMin != 0 {
			label = "rtp.port_min/port_max"
		}
		fail("%s: %d-%d holds %d RTP/RTCP pair(s) (RTP on even ports), but a trunk call needs %d — widen it to at least 4 ports starting on an even port",
			label, tr.Min, tr.Max, n, trunkPairsPerCall)
	}
}

// validateTimers checks the global durations and the global call quota.
func (c *Config) validateTimers(fail failFunc) {
	if c.RingTimeout.Std() <= 0 {
		fail("ring_timeout: must be > 0, got %v", c.RingTimeout.Std())
	}
	if c.RegisterExpires.Std() < time.Second {
		fail("register_expires: must be at least 1s, got %v", c.RegisterExpires.Std())
	}
	if c.MinSE.Std() < time.Second {
		fail("min_se: must be at least 1s, got %v", c.MinSE.Std())
	}
	if c.SessionExpires.Std() < c.MinSE.Std() {
		fail("session_expires: must be >= min_se (%v), got %v", c.MinSE.Std(), c.SessionExpires.Std())
	}
	if c.PeerCooldown.Std() <= 0 {
		fail("peer_cooldown: must be > 0, got %v", c.PeerCooldown.Std())
	}
	if c.SRVCacheTTL.Std() < time.Second {
		fail("srv_cache_ttl: must be at least 1s, got %v", c.SRVCacheTTL.Std())
	}
	if c.MaxConcurrentCalls < 0 {
		fail("max_concurrent_calls: must be >= 0 (0 = unlimited), got %d", c.MaxConcurrentCalls)
	}
}

// validatePeers checks every peer, in name order, and compiles allowed_ips.
func (c *Config) validatePeers(fail failFunc) {
	if len(c.Peers) == 0 && !c.ProxyEnabled() {
		fail("peers: at least one peer required")
	}
	peerNames := make([]string, 0, len(c.Peers))
	for name := range c.Peers {
		peerNames = append(peerNames, name)
	}
	sort.Strings(peerNames)
	for _, name := range peerNames {
		validatePeer(fail, name, c.Peers[name])
	}
}

func validatePeer(fail failFunc, name string, p *Peer) {
	if p.Address == "" {
		fail("peers.%s: address required", name)
	}
	switch p.Transport {
	case "udp", "tcp", "tls":
	default:
		fail("peers.%s: transport must be udp, tcp, or tls, got %q", name, p.Transport)
	}
	switch p.MediaLatch {
	case "strict", "loose":
	default:
		fail("peers.%s: media_latch must be strict or loose, got %q", name, p.MediaLatch)
	}
	switch p.SRTP {
	case "disabled", "optional", "required":
	default:
		fail("peers.%s: srtp must be disabled, optional, or required, got %q", name, p.SRTP)
	}
	// Sub-second is rejected (not just <= 0): registerOnce's Expires
	// header is uint32(expires.Seconds()), which truncates e.g. 500ms to
	// 0 — silently turning a "register" into an un-register that then
	// leaves the peer falsely marked registered.
	if p.RegisterExpires != 0 && p.RegisterExpires.Std() < time.Second {
		fail("peers.%s: register_expires must be at least 1s when set, got %v", name, p.RegisterExpires.Std())
	}
	if p.Register && p.Auth == nil {
		fail("peers.%s: register: true requires auth credentials", name)
	}
	if p.MaxConcurrentCalls < 0 {
		fail("peers.%s: max_concurrent_calls: must be >= 0 (0 = unlimited), got %d", name, p.MaxConcurrentCalls)
	}
	p.allowedNets = nil
	if len(p.AllowedIPs) == 0 {
		// An empty list silently failed closed before —
		// the peer could never be identified and the operator got no
		// signal. That's a config mistake, not a posture: refuse it.
		fail("peers.%s: allowed_ips: at least one prefix required", name)
	}
	for _, s := range p.AllowedIPs {
		if pfx, ok := allowedPrefix(fail, name, s); ok {
			p.allowedNets = append(p.allowedNets, pfx)
		}
	}
}

// allowedPrefix parses and checks one allowed_ips entry, returning the
// canonical prefix to match sources against.
func allowedPrefix(fail failFunc, peer, s string) (netip.Prefix, bool) {
	pfx, err := parsePrefixOrAddr(s)
	if err != nil {
		fail("peers.%s: allowed_ips: %v", peer, err)
		return netip.Prefix{}, false
	}
	// Transport sources are Unmap()ed before matching (sip/addr.go), and an
	// IPv6 prefix never contains an IPv4 address, so an IPv4-mapped entry
	// as written could never match anything (audit P2-CFG-008). Match what
	// the operator meant: the IPv4 prefix it maps.
	if pfx.Addr().Is4In6() {
		if pfx.Bits() < 96 {
			fail("peers.%s: allowed_ips: %q mixes IPv4-mapped and native IPv6 addresses; write the IPv4 prefix instead", peer, s)
			return netip.Prefix{}, false
		}
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
	}
	// Cap prefix width. allowed_ips IS the whole
	// inbound trust boundary (source-IP identification), so a
	// fat-fingered 0.0.0.0/0 — or an over-wide range — silently
	// opens toll fraud to every host it covers. The floors are /8
	// (IPv4) and /32 (IPv6): the widest real-world allocation
	// boundaries (10/8, an RIR site allocation), because this
	// repo's own example config ships a 10.0.0.0/8 peer. A bare IP
	// parses as its full-length prefix and always passes.
	minBits := 8
	if pfx.Addr().Is6() {
		minBits = 32
	}
	if pfx.Bits() < minBits {
		fail("peers.%s: allowed_ips: %q is wider than /%d (T-11 width cap)", peer, s, minBits)
		return netip.Prefix{}, false
	}
	// Store the canonical (Masked) form: a non-canonical input like
	// 10.0.1.5/16 matches exactly what the operator intended once
	// normalized, instead of silently mismatching netip semantics.
	return pfx.Masked(), true
}

// validateRoutes checks every trunk route and compiles match.to.
func (c *Config) validateRoutes(fail failFunc) {
	for i, r := range c.Routes {
		label := r.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
			fail("routes[%d]: name required", i)
		}
		if _, ok := c.Peers[r.From]; !ok {
			fail("routes.%s: from: unknown peer %q", label, r.From)
		}
		if len(r.To) == 0 {
			fail("routes.%s: to: at least one target peer required", label)
		}
		for _, t := range r.To {
			if _, ok := c.Peers[t]; !ok {
				fail("routes.%s: to: unknown peer %q", label, t)
			}
		}
		r.matchTo = nil
		if r.Match != nil && r.Match.To != "" {
			re, err := regexp.Compile(r.Match.To)
			if err != nil {
				fail("routes.%s: match.to: %v", label, c.envRedact.detail(r.Match.To, err))
			} else {
				r.matchTo = re
			}
		}
		if r.Transform != nil && r.Transform.To != "" {
			validateTransform(fail, label, r)
		}
	}
}

// validateTransform checks transform.to against the compiled match.to.
func validateTransform(fail failFunc, label string, r *Route) {
	if r.Match == nil || r.Match.To == "" {
		fail("routes.%s: transform.to requires match.to (capture groups come from it)", label)
		return
	}
	if r.matchTo == nil {
		return // match.to did not compile; already reported
	}
	g, names := groupRefs(r.Transform.To)
	if g > r.matchTo.NumSubexp() {
		fail("routes.%s: transform.to references capture group %d but match.to has %d group(s)", label, g, r.matchTo.NumSubexp())
	}
	// transform.to is not ${ENV}-expanded, so ${name} is always a group
	// reference; one match.to does not define would expand to nothing at
	// call time. Only env-shaped names are checked (the ones expansion
	// used to substitute), so a config that relied on that fails loudly
	// instead of losing the value; digit-led names such as $01 keep
	// regexp.Expand's semantics.
	for _, n := range names {
		if envRef.MatchString("${"+n+"}") && r.matchTo.SubexpIndex(n) < 0 {
			fail("routes.%s: transform.to references capture group %q but match.to has no group of that name (transform.to is a regexp template; ${ENV} is not expanded there)", label, n)
		}
	}
}

// validateShield checks the shield section.
func (c *Config) validateShield(fail failFunc) {
	if _, err := ParseRateLimit(c.Shield.RateLimit); err != nil {
		fail("shield.rate_limit: %v", c.envRedact.detail(c.Shield.RateLimit, err))
	}
	if _, err := ParseRateLimit(c.Shield.PeerRateLimit); err != nil {
		fail("shield.peer_rate_limit: %v", c.envRedact.detail(c.Shield.PeerRateLimit, err))
	}
	// withDefaults fills a zero value before validate normally runs, so this
	// only trips on an explicitly negative value reaching here (e.g. a
	// Config built directly without withDefaults). Checked defensively
	// regardless.
	if c.Shield.AutoBan.Duration <= 0 {
		fail("shield.auto_ban.duration: must be > 0, got %s", c.Shield.AutoBan.Duration.Std())
	}
}

// validateAdmin checks the optional admin section.
func (c *Config) validateAdmin(fail failFunc) {
	if c.Admin == nil {
		return
	}
	ap, err := netip.ParseAddrPort(c.Admin.Listen)
	if err != nil {
		fail("admin.listen: %q is not host:port", c.Admin.Listen)
	} else if !ap.Addr().IsLoopback() && !c.Admin.AllowRemote {
		// The admin API is the full-config exposure point
		// guarded only by Basic auth — non-loopback binding must be an
		// explicit opt-in, and the error points at the TLS route.
		fail("admin.listen: %q is not loopback; set admin.allow_remote: true to bind it "+
			"(prefer admin.tls_cert/tls_key or a TLS reverse proxy — this listener serves the full config over plaintext otherwise)", c.Admin.Listen)
	}
	if c.Admin.Auth.Username == "" {
		fail("admin.auth.username: required when admin is configured")
	}
	cost, cerr := bcrypt.Cost([]byte(c.Admin.Auth.PasswordHash))
	if cerr != nil {
		fail("admin.auth.password_hash: must be a bcrypt hash: %v", c.envRedact.detail(c.Admin.Auth.PasswordHash, cerr))
	} else if cost < 10 {
		// Cost 4 (min) makes offline cracking ~50x cheaper;
		// the hash travels in backups, logs, and the config itself.
		fail("admin.auth.password_hash: bcrypt cost %d is below the minimum of 10; regenerate the hash at cost 10 or higher", cost)
	}
	// Both-or-neither, so a half-configured pair can't leave the
	// operator believing TLS is on while it silently isn't.
	checkFilePair(fail, "admin", "tls_cert", c.Admin.TLSCert, "tls_key", c.Admin.TLSKey)
}

// validateTLSPairs checks the SIP-plane TLS pairs — same both-or-neither
// rationale as the admin pair.
func (c *Config) validateTLSPairs(fail failFunc) {
	checkFilePair(fail, "listen", "tls_cert", c.Listen.TLSCert, "tls_key", c.Listen.TLSKey)
	if c.Listen.TLSClientCA != "" && c.Listen.TLSCert == "" {
		fail("listen.tls_client_ca requires listen.tls_cert and tls_key")
	}
	for name, p := range c.Peers {
		checkFilePair(fail, "peers."+name, "tls_client_cert", p.TLSClientCert, "tls_client_key", p.TLSClientKey)
	}
}

// groupRefs parses a regexp replacement template the way regexp.Expand
// does: $$ is a literal dollar; $name or ${name} is a reference where name
// is a run of [A-Za-z0-9_]; a purely numeric name without a leading zero is
// a group index ($0 = whole match), anything else a group name. It returns
// the highest index (-1 if none) and the names, in order of appearance.
func groupRefs(template string) (max int, names []string) {
	max = -1
	for i := 0; i < len(template); {
		if template[i] != '$' {
			i++
			continue
		}
		i++ // consume '$'
		if i >= len(template) {
			break
		}
		if template[i] == '$' {
			i++ // literal "$$"
			continue
		}
		braced := false
		if template[i] == '{' {
			braced = true
			i++
		}
		start := i
		for i < len(template) && isNameByte(template[i]) {
			i++
		}
		name := template[start:i]
		closedBrace := false
		if braced && i < len(template) && template[i] == '}' {
			closedBrace = true
			i++
		}
		// Unterminated brace: treat as literal text, not a reference
		if braced && !closedBrace {
			continue
		}
		if name == "" {
			continue
		}
		// Leading zeros: $01, $012, $00 etc. are named refs in Go regexp, not group indices
		if !allDigits(name) || (len(name) > 1 && name[0] == '0') {
			names = append(names, name)
			continue
		}
		n, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return max, names
}

func isNameByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// checkIP fails unless value is empty or a valid IP literal. label is the
// full config key ("rtp.bind_ip"), so the message reads the same as a
// hand-written one.
func checkIP(fail failFunc, label, value string) {
	if value == "" {
		return
	}
	if _, err := netip.ParseAddr(value); err != nil {
		fail("%s: %q is not a valid IP", label, value)
	}
}

// checkAdvertisedIP is checkIP plus the unspecified-address rejection every
// advertised_ip key needs: 0.0.0.0/:: is a valid literal but putting it in
// Contact/Via/SDP is never routable. why completes the sentence after the
// em dash, which is the only part that differs between the keys.
func checkAdvertisedIP(fail failFunc, label, value, why string) {
	if value == "" {
		return
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		fail("%s: %q is not a valid IP", label, value)
	} else if ip.IsUnspecified() {
		fail("%s: %q is unspecified — %s", label, value, why)
	}
}

// checkFilePair enforces the both-or-neither rule shared by every
// cert/key pair: half a pair would leave the operator believing TLS (or
// DTLS) is configured while it silently isn't.
func checkFilePair(fail failFunc, prefix, aKey, aVal, bKey, bVal string) {
	if (aVal == "") != (bVal == "") {
		fail("%s: %s and %s must be set together", prefix, aKey, bKey)
	}
}

// checkPortRange validates one RTP port pool: each end unprivileged and
// within the UDP port space, and min strictly below max because every
// session needs an RTP+RTCP port pair. boundsLabel prefixes the per-key
// messages ("rtp" -> "rtp.port_min: ..."), rangeLabel the pair-wide one,
// and unit names what a pair is allocated for on this plane.
func checkPortRange(fail failFunc, boundsLabel, rangeLabel, unit string, min, max int) {
	if min < 1024 || min > 65535 {
		fail("%s.port_min: must be 1024-65535, got %d", boundsLabel, min)
	}
	if max < 1024 || max > 65535 {
		fail("%s.port_max: must be 1024-65535, got %d", boundsLabel, max)
	}
	if min >= max {
		fail("%s: port_min must be less than port_max (each %s needs an RTP+RTCP port pair), got %d-%d", rangeLabel, unit, min, max)
	}
}

// rtpPairs is how many RTP/RTCP pairs the media pool can bind in
// [min, max]: RTP on an even port, RTCP on RTP+1 (media.PlanePool.sweep).
func rtpPairs(min, max int) int {
	if min%2 != 0 {
		min++
	}
	if max < min {
		return 0
	}
	return (max - min + 1) / 2
}

// checkPort fails unless port is unset (0) or 1-65535.
func checkPort(fail failFunc, label string, port int) {
	if port != 0 && (port < 1 || port > 65535) {
		fail("%s: must be 1-65535, got %d", label, port)
	}
}

// parsePrefixOrAddr accepts "10.0.0.0/8" or a bare "203.0.113.7"
// (treated as a single-host prefix).
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is neither a CIDR nor an IP", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
