package edge

import (
	"net/netip"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
)

// newMediaPools builds the edge proxy's two RTP port pools: public bound to
// public.bind and private bound to the effective private IP, both over the
// one rtp range. Each bind IP has its own port namespace, so the pools can
// never hand out the same socket even though they share a range.
//
// Addresses and range come from boot, the startup snapshot: SDP advertises
// the topology's media addresses, which are built once, so a reload that
// moved the range would make SDP and sockets disagree. rtp is therefore
// restart-only. timeout is read for every new session.
func newMediaPools(boot *config.Config, topo *topology, timeout func() time.Duration) (public, private *media.PlanePool) {
	r := boot.RTP
	plane := func(name string, bind, advertised netip.Addr, dest media.DestPolicy) *media.PlanePool {
		return media.NewPlanePool(name, func() media.PlaneParams {
			return media.PlaneParams{
				MinPort: r.Min,
				MaxPort: r.Max,
				BindIP:  bind,
				Timeout: timeout(),
				// A plane that is itself on loopback (a single-host lab)
				// may send to loopback peers; any other plane never does.
				AllowLoopback: bind.IsLoopback() || advertised.IsLoopback(),
				Dest:          dest,
			}
		})
	}
	return plane("public", boot.PublicBind(), topo.publicMediaIP, publicDestPolicy(boot.PublicBind(), topo)),
		plane("private", topo.privateMediaIP, topo.privateMediaIP, media.DestPolicy{})
}

// publicDestPolicy is the destination policy of the public plane, applied
// to a peer that is not pinned to its signalling source (a carrier): its
// SDP may not steer the SBC's media socket into the private LAN or at
// the SBC itself. The private classes are allowed only when the plane's
// ADVERTISED address (public.ip) is itself in one of them (a lab, the test
// suites, the examples). It is not keyed on public.bind: a 1:1 NAT host
// binds a private address behind a public public.ip and must keep the
// protection. The private plane has no policy: the switch is on the LAN.
func publicDestPolicy(bind netip.Addr, topo *topology) media.DestPolicy {
	adv := topo.publicMediaIP.Unmap()
	return media.DestPolicy{
		Restrict:     true,
		AllowPrivate: adv.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(adv),
		Own:          []netip.Addr{adv, bind, topo.privateMediaIP},
	}
}
