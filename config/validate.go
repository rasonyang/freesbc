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

	if len(c.Listen.SIP) == 0 {
		fail("listen.sip: at least one listener required")
	}
	if pr := c.Listen.Media.PortRange; pr.Min < 1024 {
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
	if c.RingTimeout.Std() <= 0 {
		fail("ring_timeout: must be > 0, got %v", c.RingTimeout.Std())
	}
	if c.RegisterExpires.Std() < time.Second {
		fail("register_expires: must be at least 1s, got %v", c.RegisterExpires.Std())
	}

	if len(c.Peers) == 0 {
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
		p.allowedNets = nil
		for _, s := range p.AllowedIPs {
			pfx, err := parsePrefixOrAddr(s)
			if err != nil {
				fail("peers.%s: allowed_ips: %v", name, err)
				continue
			}
			p.allowedNets = append(p.allowedNets, pfx)
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
		if _, err := netip.ParseAddrPort(c.Admin.Listen); err != nil {
			fail("admin.listen: %q is not host:port", c.Admin.Listen)
		}
	}

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
