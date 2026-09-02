package trunk

import (
	"net"
	"net/netip"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
)

// preParseFilter returns the transport-layer read filter installed on the
// sipgo UA in Run. It is the outermost edge of the trust boundary
// (T-01, F-01/F-10): bytes whose source IP matches no peer's allowed_ips
// are dropped BEFORE the SIP parser, so they never reach the transaction
// layer (no stateless 400 for malformed requests, no stray-response
// goroutines), the handler/shield plane, the per-source connection pool, or
// any log line. sipgo runs the filter ahead of pool.Add and parseAndHandle
// on UDP (transport_udp.go) and ahead of the stream parser on TCP
// (transport_tcp.go); an empty return discards the read there.
//
// The filter deliberately never returns an error: sipgo treats a filter
// error as fatal to the whole read loop (transport_udp.go logs it and
// returns), which would let one bad datagram kill a listener. Anything with
// an unparseable source is simply dropped.
func (s *Server) preParseFilter() sip.TransportReadFilter {
	return func(info sip.TransportReadProps, data []byte) ([]byte, error) {
		addr, ok := remoteAddr(info.RemoteAddr)
		if !ok {
			return nil, nil
		}
		if !anyPeerAllows(s.store.Current(), addr) {
			return nil, nil
		}
		return data, nil
	}
}

// remoteAddr extracts the IP from a transport remote address (UDP yields
// *net.UDPAddr, TCP/TLS *net.TCPAddr).
func remoteAddr(a net.Addr) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// anyPeerAllows reports whether any configured peer allows addr. The filter
// needs only this boolean — not IdentifyPeer's deterministic winner — so it
// skips the name-sort identify() performs per handled request; the filter
// runs once per datagram, including garbage that never becomes a request.
// (IPv4-mapped IPv6 Unmap normalization is T-10's job; until then this
// mirrors sourceAddr/IdentifyPeer exactly so the two gates agree.)
func anyPeerAllows(cfg *config.Config, addr netip.Addr) bool {
	for _, p := range cfg.Peers {
		if p.AllowsIP(addr) {
			return true
		}
	}
	return false
}
