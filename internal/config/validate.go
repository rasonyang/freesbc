package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// failFunc is validate's error collector. Every section check takes it, so
// every problem in the file is reported in one pass.
type failFunc func(format string, args ...any)

// validate checks value constraints and cross-references, collecting every
// problem instead of stopping at the first, and compiles derived state
// (switch nodes, carrier list, carrier source prefixes). It does no
// locality checks (whether an address is assigned to this host is `run`'s
// business) and opens no files. It is unexported: Parse is the only
// supported entry point into the lifecycle described on Config.
func (c *Config) validate() error {
	var errs []string
	// Messages may name a value, and validation runs after ${VAR}
	// expansion, so every argument is redacted: an error must never echo
	// an environment value (it reaches `freesbc check` output and the
	// admin validate response).
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, c.envRedact.args(args)...))
	}

	c.validateTopology(fail)
	c.validateRTP(fail)
	c.validateTLS(fail)
	c.validateEdge(fail)
	c.validateCarriers(fail)
	c.validateShield(fail)
	c.validateAdmin(fail)
	c.validateSockets(fail)

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// specificIP parses an address that must be a specific unicast-style
// literal: set, valid, not 0.0.0.0 / ::.
func specificIP(fail failFunc, label, value string) (netip.Addr, bool) {
	if value == "" {
		fail("%s: required", label)
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		fail("%s: %q is not a valid IP", label, value)
		return netip.Addr{}, false
	}
	if ip.IsUnspecified() {
		fail("%s: %q is unspecified; a specific local address is required (no wildcard binds)", label, value)
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// validateTopology checks public and private.
func (c *Config) validateTopology(fail failFunc) {
	specificIP(fail, "public.ip", c.Public.IP)
	bind, bindOK := specificIP(fail, "public.bind", c.Public.Bind)
	priv, privOK := specificIP(fail, "private.ip", c.Private.IP)
	if bindOK && privOK && bind == priv {
		fail("private.ip: %q must differ from public.bind; the two sides need separate sockets", c.Private.IP)
	}
}

// validateRTP checks the RTP range. PortRange already guarantees 0 < min <
// max; the pool needs an unprivileged range that holds a pair.
func (c *Config) validateRTP(fail failFunc) {
	r := c.RTP
	if r.Min < 1024 {
		fail("rtp: must start at or above 1024, got %d-%d", r.Min, r.Max)
		return
	}
	if r.Pairs() < 1 {
		fail("rtp: %d-%d holds no RTP/RTCP pair (RTP on an even port, RTCP on RTP+1) — widen it", r.Min, r.Max)
	}
}

// validateTLS checks the top-level tls pair and who requires it.
func (c *Config) validateTLS(fail failFunc) {
	if c.TLS != nil {
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			fail("tls: cert and key must both be set")
		}
		return
	}
	if c.Edge.Listen.WSS != 0 {
		fail("tls: required by edge.listen.wss (browsers refuse an untrusted WSS certificate)")
	}
	if c.Admin != nil && c.Admin.AllowRemote {
		fail("tls: required by admin.allow_remote (the admin API must not serve Basic credentials in the clear)")
	}
}

// validateEdge checks edge.switch, switch_carrier_port, listen and
// carrier_sources.
func (c *Config) validateEdge(fail failFunc) {
	e := &c.Edge
	priv := c.PrivateAddr()
	e.switches = nil
	if len(e.Switch) == 0 {
		fail("edge.switch: at least one switch node (literal IP:port) required")
	}
	seen := map[netip.AddrPort]bool{}
	for i, s := range e.Switch {
		label := fmt.Sprintf("edge.switch[%d]", i)
		ap, ok := parseIPPort(fail, label, s)
		if !ok {
			continue
		}
		if seen[ap] {
			fail("%s: %q is listed twice", label, s)
			continue
		}
		seen[ap] = true
		if c.Private.IP != "" && ap == priv {
			fail("%s: %q is FreeSBC's own private socket", label, s)
			continue
		}
		e.switches = append(e.switches, ap)
	}
	if p := e.SwitchCarrierPort; p < 0 || p > 65535 {
		fail("edge.switch_carrier_port: must be 1-65535 (0 = the node's switch port), got %d", p)
	}

	l := e.Listen
	if l.UDP == 0 && l.WS == 0 && l.WSS == 0 {
		fail("edge.listen: at least one of udp, ws, wss required")
	}
	checkPort(fail, "edge.listen.udp", l.UDP)
	checkPort(fail, "edge.listen.ws", l.WS)
	checkPort(fail, "edge.listen.wss", l.WSS)
	if l.WS != 0 && l.WS == l.WSS {
		fail("edge.listen.wss: port %d already used by edge.listen.ws", l.WSS)
	}

	e.carrierNets = nil
	for _, s := range e.CarrierSources {
		if pfx, ok := allowedPrefix(fail, "edge.carrier_sources", s); ok {
			e.carrierNets = append(e.carrierNets, pfx)
		}
	}
}

// dnsLabel is one DNS label: letters, digits and interior hyphens.
var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// carrierName is the allowed shape of an edge.carriers key: it ends up in
// logs, metrics labels and a SIP header value.
var carrierName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ParseCarrierHost splits an edge.carriers value "host[:port]" (port
// default 5060; IPv6 literals with a port need brackets) into its parts.
// host is a literal IP or a DNS name; the returned host is lower-cased
// without a trailing dot. It exists so the edge applies the same grammar
// the validator did.
func ParseCarrierHost(s string) (host string, port int, addr netip.Addr, err error) {
	port = DefaultCarrierPort
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, netip.Addr{}, errors.New("empty")
	}
	if a, perr := netip.ParseAddr(s); perr == nil { // bare IP, incl. IPv6
		return finishCarrierHost(a.Unmap().String(), port)
	}
	h := s
	if strings.HasPrefix(s, "[") || strings.Count(s, ":") == 1 {
		hh, ps, serr := net.SplitHostPort(s)
		if serr != nil {
			return "", 0, netip.Addr{}, fmt.Errorf("%q is not host[:port]", s)
		}
		p, perr := strconv.Atoi(ps)
		if perr != nil || p < 1 || p > 65535 {
			return "", 0, netip.Addr{}, fmt.Errorf("bad port in %q", s)
		}
		h, port = hh, p
	} else if strings.Contains(s, ":") {
		return "", 0, netip.Addr{}, fmt.Errorf("%q is not host[:port] (bracket an IPv6 literal that has a port)", s)
	}
	return finishCarrierHost(h, port)
}

// carrierHasPort reports whether a (valid) edge.carriers value wrote a
// port: a bare IP never does, anything bracketed or with exactly one colon
// does.
func carrierHasPort(s string) bool {
	s = strings.TrimSpace(s)
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	return strings.HasPrefix(s, "[") || strings.Count(s, ":") == 1
}

func finishCarrierHost(h string, port int) (string, int, netip.Addr, error) {
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		if a.IsUnspecified() {
			return "", 0, netip.Addr{}, fmt.Errorf("%q is an unspecified address", h)
		}
		return a.String(), port, a, nil
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" || len(h) > 253 {
		return "", 0, netip.Addr{}, fmt.Errorf("%q is not a valid host name", h)
	}
	for _, lab := range strings.Split(h, ".") {
		if !dnsLabel.MatchString(lab) {
			return "", 0, netip.Addr{}, fmt.Errorf("%q is not a valid host name", h)
		}
	}
	return h, port, netip.Addr{}, nil
}

// validateCarriers checks edge.carriers and compiles the carrier list.
func (c *Config) validateCarriers(fail failFunc) {
	e := &c.Edge
	e.carriers = nil
	if len(e.Carriers) == 0 {
		return
	}
	if e.Listen.UDP == 0 {
		fail("edge.carriers: requires edge.listen.udp (carrier traffic is SIP over UDP on the public side)")
	}
	own := netip.AddrPort{}
	if e.Listen.UDP != 0 {
		own = netip.AddrPortFrom(c.PublicBind(), uint16(e.Listen.UDP))
	}
	pubAdv := netip.AddrPort{}
	if e.Listen.UDP != 0 {
		pubAdv = netip.AddrPortFrom(c.PublicIP(), uint16(e.Listen.UDP))
	}
	taken := map[string]string{}
	for _, name := range sortedKeys(e.Carriers) {
		label := "edge.carriers." + name
		if !carrierName.MatchString(name) {
			fail("edge.carriers: name %q must match [A-Za-z0-9._-]+", name)
			continue
		}
		host, port, addr, err := ParseCarrierHost(e.Carriers[name])
		if err != nil {
			fail("%s: %v", label, c.envRedact.detail(e.Carriers[name], err))
			continue
		}
		key := net.JoinHostPort(host, strconv.Itoa(port))
		if prev, dup := taken[key]; dup {
			fail("%s: %s is already used by edge.carriers.%s", label, key, prev)
			continue
		}
		taken[key] = name
		if addr.IsValid() {
			ap := netip.AddrPortFrom(addr, uint16(port))
			if ap == own || ap == pubAdv {
				fail("%s: %s is FreeSBC's own public UDP socket", label, key)
				continue
			}
			for _, sw := range e.switches {
				if sw == ap {
					fail("%s: %s is an edge.switch node, not a carrier", label, key)
					break
				}
			}
		}
		e.carriers = append(e.carriers, Carrier{Name: name, Host: host, Port: port, Addr: addr,
			ExplicitPort: carrierHasPort(e.Carriers[name])})
	}
}

// validateShield checks the shield section.
func (c *Config) validateShield(fail failFunc) {
	if _, err := ParseRateLimit(c.Shield.RateLimit); err != nil {
		fail("shield.rate_limit: %v", c.envRedact.detail(c.Shield.RateLimit, err))
	}
	if _, err := ParseRateLimit(c.Shield.CarrierRateLimit); err != nil {
		fail("shield.carrier_rate_limit: %v", c.envRedact.detail(c.Shield.CarrierRateLimit, err))
	}
	if c.Shield.Ban <= 0 {
		fail("shield.ban: must be > 0, got %s", c.Shield.Ban.Std())
	}
	if c.Shield.MaxSessions < 0 {
		fail("shield.max_sessions: must be >= 0, got %d", c.Shield.MaxSessions)
	} else if pairs := c.RTP.Pairs(); c.RTP.Min >= 1024 && pairs >= 1 && c.Shield.MaxSessions > pairs {
		fail("shield.max_sessions: %d exceeds the %d calls rtp %d-%d can anchor (one RTP/RTCP pair per call per plane)",
			c.Shield.MaxSessions, pairs, c.RTP.Min, c.RTP.Max)
	}
	if c.Shield.InviteRateLimit != "" {
		if rl, err := ParseRateLimit(c.Shield.InviteRateLimit); err != nil {
			fail("shield.invite_rate_limit: %v", c.envRedact.detail(c.Shield.InviteRateLimit, err))
		} else if rl.PerIP {
			fail("shield.invite_rate_limit: per_ip is not allowed, the limit is global (per-source limits are shield.rate_limit)")
		}
	}
}

// validateAdmin checks the optional admin section.
func (c *Config) validateAdmin(fail failFunc) {
	if c.Admin == nil {
		return
	}
	ap, err := netip.ParseAddrPort(c.Admin.Listen)
	if err != nil {
		fail("admin.listen: %q is not IP:port", c.Admin.Listen)
	} else if !ap.Addr().IsLoopback() && !c.Admin.AllowRemote {
		// The admin API exposes the full config guarded only by Basic
		// auth: a non-loopback bind must be an explicit opt-in.
		fail("admin.listen: %q is not loopback; set admin.allow_remote: true (requires tls) to bind it", c.Admin.Listen)
	}
	seen := make(map[string]bool, len(c.Admin.AllowedHosts))
	for i, h := range c.Admin.AllowedHosts {
		if msg := checkAllowedHost(h); msg != "" {
			fail("admin.allowed_hosts[%d]: %q %s", i, h, msg)
			continue
		}
		k := CanonicalHost(h)
		if seen[k] {
			fail("admin.allowed_hosts[%d]: %q is a duplicate", i, h)
		}
		seen[k] = true
	}
	cost, cerr := bcrypt.Cost([]byte(c.Admin.PasswordHash))
	if cerr != nil {
		fail("admin.password_hash: must be a bcrypt hash: %v", c.envRedact.detail(c.Admin.PasswordHash, cerr))
	} else if cost < 10 {
		// Cost 4 (min) makes offline cracking ~50x cheaper; the hash
		// travels in backups, logs and the config itself.
		fail("admin.password_hash: bcrypt cost %d is below the minimum of 10; regenerate the hash at cost 10 or higher", cost)
	}
}

// validateSockets rejects two listeners that would bind the same socket:
// `run` would fail with "address already in use", so `check` must too. The
// public UDP and TCP ports are separate namespaces; the admin API shares
// the TCP one with ws/wss when it binds the same address.
func (c *Config) validateSockets(fail failFunc) {
	if c.Admin == nil {
		return
	}
	ap, err := netip.ParseAddrPort(c.Admin.Listen)
	if err != nil {
		return
	}
	bind := c.Public.Bind
	for _, l := range []struct {
		key  string
		port int
	}{{"edge.listen.ws", c.Edge.Listen.WS}, {"edge.listen.wss", c.Edge.Listen.WSS}} {
		if l.port != 0 && l.port == int(ap.Port()) && hostsCollide(bind, ap.Addr().String()) {
			fail("admin.listen: tcp/%s already bound by %s", c.Admin.Listen, l.key)
		}
	}
}

// hostsCollide reports whether two listeners on one protocol and port bind
// overlapping addresses: an empty or unspecified host is every interface
// and collides with anything; two IPs collide only when equal.
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
	return ia.Unmap() == ib.Unmap()
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

// parseIPPort parses a literal "IP:port" with a port in 1-65535. The edge
// does no DNS for its switch nodes, so `check` rejects a hostname exactly
// as `run` would. label is the full config key.
func parseIPPort(fail failFunc, label, address string) (netip.AddrPort, bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		fail("%s: %q is not \"IP:port\"", label, address)
		return netip.AddrPort{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		fail("%s: %q is not a literal IP — the switch is addressed by IP, no DNS", label, host)
		return netip.AddrPort{}, false
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		fail("%s: bad port in %q", label, address)
		return netip.AddrPort{}, false
	}
	if ip.IsUnspecified() {
		fail("%s: %q is an unspecified address", label, address)
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)), true
}

// allowedPrefix parses and checks one source-prefix entry — the edge's
// carrier_sources — returning the
// canonical prefix to match sources against. label names the list in the
// error messages (e.g. "edge.carrier_sources").
func allowedPrefix(fail failFunc, label, s string) (netip.Prefix, bool) {
	pfx, err := parsePrefixOrAddr(s)
	if err != nil {
		fail("%s: %v", label, err)
		return netip.Prefix{}, false
	}
	// Transport sources are Unmap()ed before matching (sip/addr.go), and an
	// IPv6 prefix never contains an IPv4 address, so an IPv4-mapped entry
	// as written could never match anything (audit P2-CFG-008). Match what
	// the operator meant: the IPv4 prefix it maps.
	if pfx.Addr().Is4In6() {
		if pfx.Bits() < 96 {
			fail("%s: %q mixes IPv4-mapped and native IPv6 addresses; write the IPv4 prefix instead", label, s)
			return netip.Prefix{}, false
		}
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
	}
	// Cap prefix width. carrier_sources is a trust boundary (source-IP
	// admission), so a fat-fingered 0.0.0.0/0 — or an over-wide range —
	// silently admits every host it covers. The floors are /8 (IPv4) and
	// /32 (IPv6): the widest real-world allocation boundaries. A bare IP
	// parses as its full-length prefix and always passes.
	minBits := 8
	if pfx.Addr().Is6() {
		minBits = 32
	}
	if pfx.Bits() < minBits {
		fail("%s: %q is wider than /%d", label, s, minBits)
		return netip.Prefix{}, false
	}
	// Store the canonical (Masked) form: a non-canonical input like
	// 10.0.1.5/16 matches exactly what the operator intended once
	// normalized, instead of silently mismatching netip semantics.
	return pfx.Masked(), true
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

// hostNameRE is a DNS-style host name: dot-separated labels of letters,
// digits, hyphens and underscores, with an optional trailing dot.
var hostNameRE = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$`)

// checkAllowedHost returns why h is not a valid admin.allowed_hosts entry
// (a bare host name or IP literal), or "" when it is.
func checkAllowedHost(h string) string {
	switch {
	case h == "":
		return "is empty"
	case strings.Contains(h, "://") || strings.Contains(h, "/"):
		return "must be a bare host, not a URL"
	case strings.Contains(h, "*"):
		return "must not contain a wildcard"
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return ""
	}
	if strings.ContainsAny(h, ":[]") {
		return "must not carry a port or brackets (the listen port is implied)"
	}
	if !hostNameRE.MatchString(h) {
		return "is not a valid host name or IP address"
	}
	return ""
}

// CanonicalHost normalises a host name or IP literal for comparison: IP
// literals in their canonical form, names lower-cased without a trailing dot.
func CanonicalHost(h string) string {
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
