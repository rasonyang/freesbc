package trunk

import (
	"github.com/emiago/sipgo/sip"
	fsip "github.com/freesbc/freesbc/internal/sip"
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
// The never-return-an-error rule that makes that safe lives in
// fsip.ReadFilter; what is here is the trunk plane's own gate. No size cap
// is applied (the 0): a trunk peer is an identified carrier, and its
// message sizes are its own business.
func (s *Server) preParseFilter() sip.TransportReadFilter {
	return fsip.ReadFilter(0, func(info sip.TransportReadProps) bool {
		addr, ok := fsip.ParseHostPortAddr(info.RemoteAddr.String())
		if !ok {
			return false
		}
		// Same gate as the per-request one (identify → IdentifyPeer), by
		// construction: one matcher, so the two cannot drift apart. The
		// filter needs only the boolean, not the winning peer.
		_, _, ok = IdentifyPeer(s.store.Current(), addr)
		return ok
	})
}
