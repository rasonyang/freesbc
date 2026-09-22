package edge

import (
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
	plane := func(name string, get func(*config.Config) config.RTPPlaneConfig) *media.PlanePool {
		return media.NewPlanePool(name, func() media.PlaneParams {
			cfg := store.Current()
			p := get(cfg)
			r := p.Range()
			return media.PlaneParams{
				MinPort: r.Min,
				MaxPort: r.Max,
				BindIP:  fsip.ParseBindIP(p.BindIP),
				Timeout: cfg.Listen.Media.RTPTimeout.Std(),
			}
		})
	}
	return plane("public", func(c *config.Config) config.RTPPlaneConfig { return c.RTP.Public }),
		plane("private", func(c *config.Config) config.RTPPlaneConfig { return c.RTP.Private })
}
