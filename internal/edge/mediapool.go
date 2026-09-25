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
// out the same port even when they bind the same interface. Both re-read
// the live config on every allocation, so a hot reload applies to new
// sessions only.
func newMediaPools(store *config.Store) (public, private *media.PlanePool) {
	plane := func(name string, get func(*config.Config) config.RTPPlaneConfig, advertised func(*config.Config) netip.Addr) *media.PlanePool {
		return media.NewPlanePool(name, func() media.PlaneParams {
			cfg := store.Current()
			p := get(cfg)
			r := p.Range()
			bind, err := fsip.ParseBindIP(p.BindIP)
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
				Timeout: cfg.Listen.Media.RTPTimeout.Std(),
				// A plane that is itself on loopback (a single-host lab)
				// may send to loopback peers; any other plane never does.
				AllowLoopback: bind.IsLoopback() || advertised(cfg).IsLoopback(),
			}
		})
	}
	return plane("public", func(c *config.Config) config.RTPPlaneConfig { return c.RTP.Public }, (*config.Config).PublicRTPAdvertisedIP),
		plane("private", func(c *config.Config) config.RTPPlaneConfig { return c.RTP.Private }, (*config.Config).PrivateRTPAdvertisedIP)
}
