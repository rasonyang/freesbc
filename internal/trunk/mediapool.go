package trunk

import (
	"net/netip"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
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
			BindIP:  parseBindIP(cfg.RTP.BindIP),
			Timeout: cfg.Listen.Media.RTPTimeout.Std(),
		}
	})
}

// parseBindIP turns a configured bind address into a netip.Addr, or the
// zero Addr (every interface) when unset or unparseable. Only the bind
// plane — the advertised SDP address lives on the signaling side; the two
// stay independent so NAT/VPN deployments can bind privately and advertise
// publicly.
func parseBindIP(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return ip
}
