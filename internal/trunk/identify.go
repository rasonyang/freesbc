// Package trunk implements the trunk-interconnect plane: a B2BUA between
// carriers and a PBX. It owns the sipgo server assembly for that plane,
// identifies inbound requests by peer source IP, and hosts the bridge,
// routing engine and SDP rewrite.
//
// It is one of FreeSBC's two SIP planes; the other is package proxy, the
// phone- and browser-facing edge proxy. They share no state and run
// independently — hence the names, which say which side each serves
// rather than which protocol both speak.
package trunk

import (
	"net/netip"
	"sort"

	"github.com/freesbc/freesbc/internal/config"
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
