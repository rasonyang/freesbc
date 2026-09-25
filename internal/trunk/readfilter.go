package trunk

import (
	"net"

	"github.com/emiago/sipgo/sip"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// preParseFilter returns the transport-layer read filter installed on the
// sipgo UA in Run. It is the outermost edge of the trust boundary:
// bytes whose source IP matches no peer's allowed_ips
// are dropped BEFORE the SIP parser, so they never reach the transaction
// layer (no stateless 400 for malformed requests, no stray-response
// goroutines), the handler/shield plane, the per-source connection pool, or
// any log line. sipgo runs the filter ahead of pool.Add and parseAndHandle
// on UDP (transport_udp.go) and ahead of the stream parser on TCP
// (transport_tcp.go); an empty return discards the read there.
//
// The never-return-an-error rule that makes that safe lives in
// fsip.ReadFilter; what is here is the trunk plane's own gate. No size cap
// is applied (the 0): a trunk peer is an identified carrier, and its
// message sizes are its own business.
func (s *Server) preParseFilter() sip.TransportReadFilter {
	return fsip.ReadFilter(0, func(info sip.TransportReadProps) bool {
		return s.fromPeer(info.RemoteAddr)
	})
}

// fromPeer reports whether remote's IP matches some peer's allowed_ips in
// the current config. It is the gate both the read filter and the TCP/TLS
// accept path (tcpLimitListener.admit) use. Same gate as the per-request
// one (identify → IdentifyPeer), by construction: one matcher, so they
// cannot drift apart. Only the boolean is needed, not the winning peer.
func (s *Server) fromPeer(remote net.Addr) bool {
	if remote == nil {
		return false
	}
	addr, ok := fsip.ParseHostPortAddr(remote.String())
	if !ok {
		return false
	}
	_, _, ok = IdentifyPeer(s.store.Current(), addr)
	return ok
}
