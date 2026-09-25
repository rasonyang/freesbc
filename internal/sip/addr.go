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

// SameListener reports whether a read that arrived on transport at local
// address local belongs to the listener bound with bindTransport at bind.
//
// Both the transport and the address must match. Transport matters because
// different transports keep separate port spaces: a WebSocket connection
// accepted on TCP port 5060 is not a read on a UDP listener bound to 5060.
// Once the transport is known to be the same, a wildcard bind host is
// equal to any host on its port (sameAddr): the kernel lets only one
// socket of a transport own that port, so the read can have arrived on no
// other listener. "ws" and "wss" are carried over TCP and so compare equal
// to "tcp" and "tls" only by name, not by port space; they never match
// "udp".
func SameListener(transport, local, bindTransport, bind string) bool {
	if !strings.EqualFold(transport, bindTransport) {
		return false
	}
	return sameAddr(local, bind)
}

// sameAddr compares two "host:port" strings, treating a wildcard host as
// equal to any host on the same port — a listener bound to 0.0.0.0 reports
// its own address that way while individual reads report the concrete
// local address the packet arrived on. It compares addresses only; to ask
// whether a read arrived on a given listener, use SameListener, which also
// compares the transport.
func sameAddr(a, b string) bool {
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
// give 5061 to TLS and 5060 to UDP and TCP, and RFC 7118 §5 puts
// SIP-over-WebSocket on the HTTP ports: 80 for ws and 443 for wss.
func DefaultPort(transport string) int {
	switch strings.ToLower(transport) {
	case "tls":
		return 5061
	case "ws":
		return 80
	case "wss":
		return 443
	default:
		return 5060
	}
}
