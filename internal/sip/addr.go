package sip

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"
)

// The addresses in this file all come from the TRANSPORT layer — the real
// remote socket a datagram or connection arrived on — never from a Via or
// From host, which the sender controls. Every one Unmaps: an IPv4 peer
// reaching a dual-stack listener is reported as ::ffff:a.b.c.d, and a
// comparison against a configured IPv4 literal would silently fail.

// SourceAddrPort parses a request's transport source into an address and
// port. ok is false when the source is missing or unparseable, which is
// grounds for dropping the request before anything else looks at it.
func SourceAddrPort(req *sip.Request) (netip.AddrPort, bool) {
	host, portStr, err := net.SplitHostPort(req.Source())
	if err != nil {
		return netip.AddrPort{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), true
}

// ParseHostPortAddr parses a transport-level "host:port" into its address.
func ParseHostPortAddr(hostPort string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// AddrOf is ParseHostPortAddr for a net.Addr, tolerating a nil one.
func AddrOf(a net.Addr) (netip.Addr, bool) {
	if a == nil {
		return netip.Addr{}, false
	}
	return ParseHostPortAddr(a.String())
}

// SameAddr compares two "host:port" strings, treating a wildcard host as
// equal to any host on the same port — a listener bound to 0.0.0.0 reports
// its own address that way while individual reads report the concrete
// local address the packet arrived on.
func SameAddr(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	if ap != bp {
		return false
	}
	if ah == bh {
		return true
	}
	wildcard := func(h string) bool {
		ip, err := netip.ParseAddr(h)
		return err == nil && ip.IsUnspecified()
	}
	return wildcard(ah) || wildcard(bh)
}

// DefaultPort is the conventional port for a transport, used when a Via or
// a configured peer address omits one: RFC 3261 §19.1.2 and RFC 3263 §4.1
// give 5061 to the TLS-protected transports and 5060 to the rest, and
// RFC 7118 §5 puts plain SIP-over-WebSocket on the HTTP port.
func DefaultPort(transport string) int {
	switch strings.ToLower(transport) {
	case "tls", "wss":
		return 5061
	case "ws":
		return 80
	default:
		return 5060
	}
}
