// Package trunk implements the trunk-interconnect plane: a B2BUA between
// carriers and a PBX. It owns the sipgo server assembly for that plane,
// identifies inbound requests by peer source IP, and hosts the bridge,
// routing engine and SDP rewrite.
//
// It is one of FreeSBC's two SIP planes; the other is package edge, the
// phone- and browser-facing edge proxy. They share no state and run
// independently — hence the names, which say which side each serves
// rather than which protocol both speak.
package trunk

import (
	"net/netip"

	"github.com/freesbc/freesbc/internal/config"
)

// IdentifyPeer returns the peer whose allowed_ips contains addr. When more
// than one peer matches, the lexicographically-first name wins, so the
// result is deterministic regardless of map iteration order. ok is false
// when no peer matches (the caller hands such requests to the shield seam).
//
// It is the only peer gate: both the per-request path (Server.identify) and
// the pre-parse read filter go through it, so the two cannot diverge. The
// filter runs once per datagram — including garbage that never becomes a
// request — so the deterministic winner is picked by a single allocation-free
// pass that keeps the smallest matching name, not by sorting the peer names.
// (IPv4-mapped IPv6 Unmap normalization is T-10's job.)
func IdentifyPeer(cfg *config.Config, addr netip.Addr) (name string, peer *config.Peer, ok bool) {
	for n, p := range cfg.Peers {
		if !p.AllowsIP(addr) {
			continue
		}
		if !ok || n < name {
			name, peer, ok = n, p, true
		}
	}
	return name, peer, ok
}
