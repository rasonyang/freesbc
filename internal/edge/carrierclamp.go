package edge

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/freesbc/freesbc/internal/config"
)

// This file is the carrier address clamp: the classes of address a DNS
// answer for a DNS-name carrier may not contribute. A resolved address is
// both where FreeSBC sends that carrier's requests (carrierDest) and a
// carrier source admitted and rate-limited as one (isSource, isAddress,
// carrierFor), so whoever controls the carrier's zone, or spoofs its
// answer (there is no DNSSEC), could otherwise point the public side at the
// host itself, the switch or the private LAN, or make a private address a
// trusted carrier source. Literal-IP entries are written by the operator and
// are never clamped: a carrier on a private network is configured by IP.

// Reason classes of a refused carrier address, as logged and as written in
// the lookup error.
const (
	clampUnspecified = "unspecified" // ::, 0.0.0.0/8
	clampLoopback    = "loopback"
	clampLinkLocal   = "link-local"
	clampMulticast   = "multicast" // any multicast, and the IPv4 limited broadcast
	clampOwn         = "own address"
	clampSwitch      = "switch address"
	clampPrivate     = "private" // RFC 1918, IPv6 ULA, CGNAT 100.64.0.0/10
)

// thisNetwork is 0.0.0.0/8, "this host on this network" (RFC 1122): never a
// destination.
var thisNetwork = netip.MustParsePrefix("0.0.0.0/8")

// carrierAddrPolicy is the clamp. The zero value refuses every class,
// private and loopback included, and knows no own or switch address.
type carrierAddrPolicy struct {
	// allowPrivate lifts the refusal of the private classes. It is set when
	// public.ip is itself private or CGNAT (a lab, a private peering), the
	// same condition that lifts the public media plane's (publicDestPolicy).
	allowPrivate bool
	// allowLoopback admits a loopback answer, and skips the own and switch
	// checks for it. It is set only when the public plane is itself on
	// loopback (public.ip or public.bind), the rule the media pools apply to
	// AllowLoopback (newMediaPools): on a single-host lab FreeSBC, the switch
	// and the carrier all share 127.0.0.1 and differ by port alone. A
	// public.ip reachable from anywhere else never sets it.
	allowLoopback bool
	// own is public.ip, public.bind and the private SIP socket's address;
	// switches is every edge.switch IP. Both are refused whatever the lift.
	own      []netip.Addr
	switches []netip.Addr
}

// newCarrierAddrPolicy builds the clamp from the startup snapshot. priv is
// the effective private SIP socket (Config.PrivateAddr, or the
// WithPrivateAddr test seam).
func newCarrierAddrPolicy(cfg *config.Config, priv netip.Addr) carrierAddrPolicy {
	pub, bind := cfg.PublicIP(), cfg.PublicBind()
	p := carrierAddrPolicy{
		allowPrivate:  config.PrivateOrCGNAT(pub),
		allowLoopback: pub.IsLoopback() || bind.IsLoopback(),
	}
	for _, a := range []netip.Addr{pub, bind, priv} {
		if a.IsValid() {
			p.own = append(p.own, a.Unmap())
		}
	}
	for _, s := range cfg.Switches() {
		p.switches = append(p.switches, s.Addr().Unmap())
	}
	return p
}

// refuses returns the reason class ip is refused for, or "" when a DNS
// answer may contribute it. ip is unmapped and zoneless.
func (p carrierAddrPolicy) refuses(ip netip.Addr) string {
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), thisNetwork.Contains(ip):
		return clampUnspecified
	case ip.IsMulticast(), ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return clampMulticast
	case ip.IsLoopback():
		if p.allowLoopback {
			return ""
		}
		return clampLoopback
	case ip.IsLinkLocalUnicast():
		return clampLinkLocal
	}
	for _, o := range p.own {
		if o == ip {
			return clampOwn
		}
	}
	for _, s := range p.switches {
		if s == ip {
			return clampSwitch
		}
	}
	if !p.allowPrivate && config.PrivateOrCGNAT(ip) {
		return clampPrivate
	}
	return ""
}

// refusedAddr is one address of a DNS answer the clamp refused.
type refusedAddr struct {
	host   string // the name whose A/AAAA answer held it
	addr   netip.Addr
	reason string
}

// refusedError is the lookup error when no address of an answer survived the
// clamp: it names each refused address and its class, so the operator view
// (CarrierInfo.LastError, the carrier_dns health condition) says why.
func refusedError(host string, refused []refusedAddr) error {
	parts := make([]string, 0, len(refused))
	seen := map[netip.Addr]bool{}
	for _, r := range refused {
		if !seen[r.addr] {
			seen[r.addr] = true
			parts = append(parts, fmt.Sprintf("%s (%s)", r.addr, r.reason))
		}
	}
	return fmt.Errorf("lookup %s: every address refused: %s", host, strings.Join(parts, ", "))
}
