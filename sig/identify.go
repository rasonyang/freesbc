// Package sig implements the SIP signaling plane: the sipgo server
// assembly, inbound peer identification, and (in later M3 slices) the
// B2BUA bridge, routing, and SDP rewrite.
package sig

import (
	"net/netip"
	"sort"

	"github.com/freesbc/freesbc/config"
)

// IdentifyPeer returns the peer whose allowed_ips contains addr. When more
// than one peer matches, the lexicographically-first name wins, so the
// result is deterministic regardless of map iteration order. ok is false
// when no peer matches (the caller hands such requests to the shield seam).
func IdentifyPeer(cfg *config.Config, addr netip.Addr) (name string, peer *config.Peer, ok bool) {
	names := make([]string, 0, len(cfg.Peers))
	for n := range cfg.Peers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := cfg.Peers[n]
		if p.AllowsIP(addr) {
			return n, p, true
		}
	}
	return "", nil, false
}
