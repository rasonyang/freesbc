package trunk

import (
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
)

// TestNewMediaPoolRangePrecedence proves the trunk pool is fed from
// rtp.port_min/port_max when those are set, and from
// listen.media.port_range otherwise (Config.RTPPortRange). Stats' total is
// the observable: it is the pair capacity of whichever range won.
func TestNewMediaPoolRangePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   *config.Config
		pairs int
	}{
		{
			name: "rtp section",
			cfg: &config.Config{
				Listen: config.ListenConfig{Media: config.MediaConfig{RTPTimeout: config.Duration(5 * time.Minute)}},
				RTP:    config.RTPNetConfig{PortMin: 15000, PortMax: 15003}, // 4 ports → 2 pairs
			},
			pairs: 2,
		},
		{
			name: "legacy listen.media range",
			cfg: &config.Config{
				Listen: config.ListenConfig{Media: config.MediaConfig{
					PortRange:  config.PortRange{Min: 15100, Max: 15107}, // 8 ports → 4 pairs
					RTPTimeout: config.Duration(5 * time.Minute),
				}},
			},
			pairs: 4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewMediaPool(config.NewStore(tc.cfg))
			if inUse, total := p.Stats(); inUse != 0 || total != tc.pairs {
				t.Fatalf("Stats() = %d/%d, want 0/%d", inUse, total, tc.pairs)
			}
			sess, err := p.Allocate(media.SessionConfig{})
			if err != nil {
				t.Fatalf("allocate: %v", err)
			}
			defer sess.Close()
			port := sess.RTPPort(media.SideA)
			if lo, hi := int(tc.cfg.RTPPortRange().Min), int(tc.cfg.RTPPortRange().Max); port < lo || port > hi {
				t.Errorf("allocated RTP port %d outside range %d-%d", port, lo, hi)
			}
		})
	}
}
