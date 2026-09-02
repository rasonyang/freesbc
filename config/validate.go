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

// validate checks cross-references and value constraints, collecting every
// problem instead of stopping at the first. On success it also compiles
// derived state (peer allowed-IP prefixes, route match regexes). It is
// unexported: Parse is the only supported entry point into the lifecycle
// described on Config.
func (c *Config) validate() error {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

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

	// sip/rtp bind-advertised topology (NAT/VPN): any configured sip.*
	// field requires the full bind pair, and the section is mutually
	// exclusive with the legacy listen.sip list — two listener sources
	// would be ambiguous.
	sipSet := c.SIP.BindIP != "" || c.SIP.BindPort != 0 ||
		c.SIP.AdvertisedIP != "" || c.SIP.AdvertisedPort != 0
	if sipSet && c.SIP.BindIP == "" {
		fail("sip.bind_ip: required when any sip.* field is configured")
	}
	if sipSet && c.SIP.BindPort == 0 {
		fail("sip.bind_port: required when any sip.* field is configured")
	}
	if c.SIP.BindIP != "" {
		if _, err := netip.ParseAddr(c.SIP.BindIP); err != nil {
			fail("sip.bind_ip: %q is not a valid IP", c.SIP.BindIP)
		}
		if len(c.Listen.SIP) > 0 {
			fail("sip.bind_ip and listen.sip are mutually exclusive: the sip section replaces the listen.sip listener list — configure one or the other")
		}
	}
	if c.SIP.BindPort != 0 && (c.SIP.BindPort < 1 || c.SIP.BindPort > 65535) {
		fail("sip.bind_port: must be 1-65535, got %d", c.SIP.BindPort)
	}
	switch c.SIP.Transport {
	case "udp", "tcp", "tls":
	default:
		fail("sip.transport: must be udp, tcp, or tls, got %q", c.SIP.Transport)
	}
	if c.SIP.AdvertisedIP != "" {
		ip, err := netip.ParseAddr(c.SIP.AdvertisedIP)
		if err != nil {
			fail("sip.advertised_ip: %q is not a valid IP", c.SIP.AdvertisedIP)
		} else if ip.IsUnspecified() {
			fail("sip.advertised_ip: %q is unspecified — advertising it in Contact/From would be unroutable", c.SIP.AdvertisedIP)
		}
	}
	if c.SIP.AdvertisedPort != 0 && (c.SIP.AdvertisedPort < 1 || c.SIP.AdvertisedPort > 65535) {
		fail("sip.advertised_port: must be 1-65535, got %d", c.SIP.AdvertisedPort)
	}
	if c.RTP.BindIP != "" {
		if _, err := netip.ParseAddr(c.RTP.BindIP); err != nil {
			fail("rtp.bind_ip: %q is not a valid IP", c.RTP.BindIP)
		}
	}
	if c.RTP.AdvertisedIP != "" {
		ip, err := netip.ParseAddr(c.RTP.AdvertisedIP)
		if err != nil {
			fail("rtp.advertised_ip: %q is not a valid IP", c.RTP.AdvertisedIP)
		} else if ip.IsUnspecified() {
			fail("rtp.advertised_ip: %q is unspecified — advertising it in SDP would blackhole media", c.RTP.AdvertisedIP)
		}
	}
	// Blackhole guard for the NAT/VPN topology: with sip.bind_ip configured
	// there are no listen.sip hosts for the SDP media IP to fall back on
	// (see Server.mediaIP), so without an explicit rtp.advertised_ip — and
	// with public_ip left "auto", since STUN discovery isn't implemented —
	// every SDP would advertise 127.0.0.1.
	if c.SIP.BindIP != "" && c.RTP.AdvertisedIP == "" && c.Listen.Media.PublicIP == "auto" {
		fail("rtp.advertised_ip: required when sip.bind_ip is configured and listen.media.public_ip is \"auto\" — otherwise SDP media would advertise 127.0.0.1")
	}

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
		if c.RTP.PortMin < 1024 || c.RTP.PortMin > 65535 {
			fail("rtp.port_min: must be 1024-65535, got %d", c.RTP.PortMin)
		}
		if c.RTP.PortMax < 1024 || c.RTP.PortMax > 65535 {
			fail("rtp.port_max: must be 1024-65535, got %d", c.RTP.PortMax)
		}
		if c.RTP.PortMin >= c.RTP.PortMax {
			// A degenerate (min == max) range can never hold an RTP+RTCP
			// pair — reject it up front rather than fail every call with
			// "exhausted".
			fail("rtp.port_min/port_max: port_min must be less than port_max (each call needs an RTP+RTCP port pair), got %d-%d", c.RTP.PortMin, c.RTP.PortMax)
		}
	}
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

	if len(c.Peers) == 0 && !c.ProxyEnabled() {
		fail("peers: at least one peer required")
	}
	peerNames := make([]string, 0, len(c.Peers))
	for name := range c.Peers {
		peerNames = append(peerNames, name)
	}
	sort.Strings(peerNames)
	for _, name := range peerNames {
		p := c.Peers[name]
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
			// T-11 (F-16): an empty list silently failed closed before —
			// the peer could never be identified and the operator got no
			// signal. That's a config mistake, not a posture: refuse it.
			fail("peers.%s: allowed_ips: at least one prefix required", name)
		}
		for _, s := range p.AllowedIPs {
			pfx, err := parsePrefixOrAddr(s)
			if err != nil {
				fail("peers.%s: allowed_ips: %v", name, err)
				continue
			}
			// T-11 (F-16): cap prefix width. allowed_ips IS the whole
			// inbound trust boundary (source-IP identification), so a
			// fat-fingered 0.0.0.0/0 — or an over-wide range — silently
			// opens toll fraud to every host it covers. The floors are /8
			// (IPv4) and /32 (IPv6): the widest real-world allocation
			// boundaries (10/8, an RIR site allocation), deliberately more
			// permissive than the review's suggested /16//48 because this
			// repo's own example config ships a 10.0.0.0/8 peer. A bare IP
			// parses as its full-length prefix and always passes.
			minBits := 8
			if pfx.Addr().Is6() {
				minBits = 32
			}
			if pfx.Bits() < minBits {
				fail("peers.%s: allowed_ips: %q is wider than /%d (T-11 width cap)", name, s, minBits)
				continue
			}
			// Store the canonical (Masked) form: a non-canonical input like
			// 10.0.1.5/16 matches exactly what the operator intended once
			// normalized, instead of silently mismatching netip semantics.
			p.allowedNets = append(p.allowedNets, pfx.Masked())
		}
	}

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
				fail("routes.%s: match.to: %v", label, err)
			} else {
				r.matchTo = re
			}
		}
		if r.Transform != nil && r.Transform.To != "" && (r.Match == nil || r.Match.To == "") {
			fail("routes.%s: transform.to requires match.to (capture groups come from it)", label)
		}
		if r.Transform != nil && r.Transform.To != "" && r.matchTo != nil {
			if g := maxGroupRef(r.Transform.To); g > r.matchTo.NumSubexp() {
				fail("routes.%s: transform.to references capture group %d but match.to has %d group(s)", label, g, r.matchTo.NumSubexp())
			}
		}
	}

	if _, err := ParseRateLimit(c.Shield.RateLimit); err != nil {
		fail("shield.rate_limit: %v", err)
	}
	if _, err := ParseRateLimit(c.Shield.PeerRateLimit); err != nil {
		fail("shield.peer_rate_limit: %v", err)
	}
	switch c.Shield.NFTables {
	case "auto", "on", "off":
	default:
		fail("shield.nftables: must be auto, on, or off, got %q", c.Shield.NFTables)
	}
	// withDefaults fills zero values before validate normally runs, so these
	// only trip on an explicitly negative/non-positive value reaching here
	// (e.g. a Config built directly without withDefaults). Checked
	// defensively regardless.
	if c.Shield.AutoBan.Failures < 1 {
		fail("shield.auto_ban.failures: must be >= 1, got %d", c.Shield.AutoBan.Failures)
	}
	if c.Shield.AutoBan.Window <= 0 {
		fail("shield.auto_ban.window: must be > 0, got %s", c.Shield.AutoBan.Window.Std())
	}
	if c.Shield.AutoBan.Duration <= 0 {
		fail("shield.auto_ban.duration: must be > 0, got %s", c.Shield.AutoBan.Duration.Std())
	}

	if c.Admin != nil {
		ap, err := netip.ParseAddrPort(c.Admin.Listen)
		if err != nil {
			fail("admin.listen: %q is not host:port", c.Admin.Listen)
		} else if !ap.Addr().IsLoopback() && !c.Admin.AllowRemote {
			// T-26 (D4-6): the admin API is the full-config exposure point
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
			fail("admin.auth.password_hash: must be a bcrypt hash: %v", cerr)
		} else if cost < 10 {
			// T-26 (D4-6): cost 4 (min) makes offline cracking ~50x cheaper;
			// the hash travels in backups, logs, and the config itself.
			fail("admin.auth.password_hash: bcrypt cost %d is below the minimum of 10; regenerate the hash at cost 10 or higher", cost)
		}
		if (c.Admin.TLSCert == "") != (c.Admin.TLSKey == "") {
			// T-26b: both-or-neither, so a half-configured pair can't leave
			// the operator believing TLS is on while it silently isn't.
			fail("admin: tls_cert and tls_key must be set together")
		}
	}

	// T-17 (F-13): SIP-plane TLS pairs — same both-or-neither rationale as
	// the admin pair above.
	if (c.Listen.TLSCert == "") != (c.Listen.TLSKey == "") {
		fail("listen: tls_cert and tls_key must be set together")
	}
	if c.Listen.TLSClientCA != "" && c.Listen.TLSCert == "" {
		fail("listen.tls_client_ca requires listen.tls_cert and tls_key")
	}
	for name, p := range c.Peers {
		if (p.TLSClientCert == "") != (p.TLSClientKey == "") {
			fail("peers.%s: tls_client_cert and tls_client_key must be set together", name)
		}
	}

	c.validateProxy(fail)

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// maxGroupRef returns the highest numeric capture-group index referenced by
// a regexp replacement template, or -1 if it references none. It mirrors
// regexp.Expand's parsing: $$ is a literal dollar; $name or ${name} is a
// reference where name is a run of [A-Za-z0-9_]; a purely numeric name is a
// group index ($0 = whole match). Named (non-numeric) refs are ignored here.
func maxGroupRef(template string) int {
	max := -1
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
		if name == "" || !allDigits(name) {
			continue
		}
		// Leading zeros: $01, $012, $00 etc. are named refs in Go regexp, not group indices
		if len(name) > 1 && name[0] == '0' {
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
	return max
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
