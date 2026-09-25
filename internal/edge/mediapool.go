package edge

import (
	"net/netip"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// newMediaPools builds the edge proxy's two RTP port pools from the public
// and private media planes. The ranges are validated to be disjoint at
// config time (see config.validateProxy), so the two pools can never hand
// out the same port even when they bind the same interface.
//
// A plane's range and bind address come from boot, the startup snapshot:
// the address the plane advertises in SDP is part of the topology, which is
// built once (topology.publicMediaIP/privateMediaIP), so a reload that
// moved the bind or the range would make SDP advertise one address while
// the sockets sit on another (audit P2-EDG-025). rtp.public/rtp.private
// are therefore restart-only. Only the silence timeout
// (listen.media.rtp_timeout) is re-read from the store, for new sessions.
func newMediaPools(store *config.Store, boot *config.Config) (public, private *media.PlanePool) {
	plane := func(name string, p config.RTPPlaneConfig, advertised netip.Addr) *media.PlanePool {
		r := p.Range()
		bind, err := fsip.ParseBindIP(p.BindIP)
		return media.NewPlanePool(name, func() media.PlaneParams {
			if err != nil {
				// Unreachable for a validated config. Fail closed: an
				// empty range allocates nothing (ErrPortsExhausted, a
				// 503) instead of binding every interface.
				return media.PlaneParams{MinPort: 1, MaxPort: 0}
			}
			return media.PlaneParams{
				MinPort: r.Min,
				MaxPort: r.Max,
				BindIP:  bind,
				Timeout: store.Current().Listen.Media.RTPTimeout.Std(),
				// A plane that is itself on loopback (a single-host lab)
				// may send to loopback peers; any other plane never does.
				AllowLoopback: bind.IsLoopback() || advertised.IsLoopback(),
			}
		})
	}
	return plane("public", boot.RTP.Public, boot.PublicRTPAdvertisedIP()),
		plane("private", boot.RTP.Private, boot.PrivateRTPAdvertisedIP())
}
