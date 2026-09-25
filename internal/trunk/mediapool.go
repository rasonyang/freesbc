package trunk

import (
	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// NewMediaPool builds the trunk B2BUA plane's RTP port pool from the live
// config: the range is rtp.port_min/port_max when set, else
// listen.media.port_range (Config.RTPPortRange), sockets bind rtp.bind_ip,
// and sessions inherit listen.media.rtp_timeout. A call allocates with the
// parameters of its own snapshot (planeParams, via AllocateWith); the
// store is read here only for Stats and for an allocation that has none,
// so a hot reload applies to new sessions without disturbing established
// ones.
func NewMediaPool(store *config.Store) *media.PlanePool {
	return media.NewPlanePool("trunk", func() media.PlaneParams {
		return planeParams(store.Current())
	})
}

// planeParams is the trunk media pool's configuration in cfg.
func planeParams(cfg *config.Config) media.PlaneParams {
	r := cfg.RTPPortRange()
	bind, err := fsip.ParseBindIP(cfg.RTP.BindIP)
	if err != nil {
		// Unreachable for a validated config. Fail closed: an empty range
		// allocates nothing (ErrPortsExhausted, a 503) instead of binding
		// every interface.
		return media.PlaneParams{MinPort: 1, MaxPort: 0}
	}
	return media.PlaneParams{
		MinPort: r.Min,
		MaxPort: r.Max,
		BindIP:  bind,
		Timeout: cfg.Listen.Media.RTPTimeout.Std(),
		// Loopback peers only when the relay itself is on loopback (a
		// single-host lab): an answer's c= must never point the relay at a
		// service on the SBC host.
		AllowLoopback: bind.IsLoopback(),
	}
}
