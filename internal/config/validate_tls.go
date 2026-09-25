package config

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

// validateTLSPeerHosts rejects two transport: tls peers that share an
// address host (a hostname, or an IP, whatever the ports). The trunk's
// outbound TLS picks a peer's trust roots by the host it dialled — the
// handshake's ServerName, or for an IP literal the certificate's IP SAN —
// and a port never reaches that choice, so such peers could not be told
// apart (P2-TRK-016).
func (c *Config) validateTLSPeerHosts(fail failFunc) {
	names := make([]string, 0, len(c.Peers))
	for name, p := range c.Peers {
		if p != nil && p.Transport == "tls" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	owner := map[string]string{}
	for _, name := range names {
		host := tlsPeerHost(c.Peers[name].Address)
		if host == "" {
			continue
		}
		if first, dup := owner[host]; dup {
			fail("peers.%s: address host %q is shared with TLS peer %s; TLS peers must have distinct hosts", name, host, first)
			continue
		}
		owner[host] = name
	}
}

// tlsPeerHost is the normalised host of a peer address: the host part of
// host:port (or the whole address without a port), an IP in canonical
// form, a name lowercased without a trailing dot.
func tlsPeerHost(address string) string {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
