package trunk

import (
	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// NewMediaPool builds the trunk B2BUA plane's RTP port pool from the live
// config: the range is rtp.port_min/port_max when set, else
// listen.media.port_range (Config.RTPPortRange), sockets bind rtp.bind_ip,
// and sessions inherit listen.media.rtp_timeout. Every value is re-read on
// each allocation, so a hot reload applies to new sessions without
// disturbing established ones.
func NewMediaPool(store *config.Store) *media.PlanePool {
	return media.NewPlanePool("trunk", func() media.PlaneParams {
		cfg := store.Current()
		r := cfg.RTPPortRange()
		return media.PlaneParams{
			MinPort: r.Min,
			MaxPort: r.Max,
			BindIP:  fsip.ParseBindIP(cfg.RTP.BindIP),
			Timeout: cfg.Listen.Media.RTPTimeout.Std(),
		}
	})
}
