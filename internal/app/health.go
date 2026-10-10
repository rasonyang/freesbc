package app

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/admin"
	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/edge"
)

// Health thresholds. They are fixed on purpose: alerting and tunable
// thresholds stay in Prometheus Alertmanager (issue #122).
const (
	// portsDegradedPercent is the RTP pool use, in percent of pairs, from
	// which rtp_ports is degraded; a full pool is critical.
	portsDegradedPercent = 90
	// banCapQuiet is how long the shield's BanAddsRejected counter must
	// stand still before shield_ban_cap clears.
	banCapQuiet = 60 * time.Second
)

// Conditions deliberately absent:
//   - Listener not bound. A listener is bound before the edge reports ready
//     and a serve error afterwards makes edge.Server.Run return, which
//     cancels the errgroup and ends the process, so no running process has
//     a stopped listener to report.
//   - TLS certificate near expiry: absent until #119 lands.
//   - Drain mode is not a condition: it has its own gauge and endpoint.

// healthInputs is everything the conditions are derived from, as plain
// values, so a test can set each one without a running edge.
type healthInputs struct {
	Switch   []edge.SwitchNodeInfo
	Carriers []edge.CarrierInfo
	// Reload is the config watcher's last outcome.
	Reload     config.ReloadStatus
	PortsInUse int
	PortsTotal int
	// BanRejected is the shield's BanAddsRejected counter.
	BanRejected int64
	// AdminPlainRemote is true when admin serves plain HTTP on a
	// non-loopback address.
	AdminPlainRemote bool
}

// healthSource derives the raw active conditions from healthInputs. Only
// the shield ban-cap condition has memory: it needs the previous counter
// and when the counter last rose.
type healthSource struct {
	read func() healthInputs
	now  func() time.Time // nil is time.Now

	mu       sync.Mutex
	rejected int64     // BanRejected at the previous evaluation
	lastRise time.Time // when it last increased; zero if it never has
}

func newHealthSource(edgeSrv *edge.Server, running *config.Config, reload func() config.ReloadStatus) *healthSource {
	plain := adminPlainRemote(running.Admin, running.TLS)
	return &healthSource{read: func() healthInputs {
		inUse, total := edgeSrv.PortStats()
		var rs config.ReloadStatus
		if reload != nil {
			rs = reload()
		}
		return healthInputs{
			Switch:           edgeSrv.SwitchNodes(),
			Carriers:         edgeSrv.Carriers(),
			Reload:           rs,
			PortsInUse:       inUse,
			PortsTotal:       total,
			BanRejected:      edgeSrv.ShieldStats().BanAddsRejected,
			AdminPlainRemote: plain,
		}
	}}
}

// adminPlainRemote reports whether admin would serve plain HTTP on a
// non-loopback address, which config validation rejects.
func adminPlainRemote(a *config.AdminConfig, tls *config.TLSConfig) bool {
	if a == nil || (a.AllowRemote && tls != nil) {
		return false
	}
	ap, err := netip.ParseAddrPort(a.Listen)
	return err != nil || !ap.Addr().IsLoopback()
}

func (h *healthSource) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

// conditions is admin.Deps.Health.
func (h *healthSource) conditions() []admin.HealthCondition {
	return h.derive(h.read())
}

func (h *healthSource) derive(in healthInputs) []admin.HealthCondition {
	var out []admin.HealthCondition

	cooling := 0
	for _, n := range in.Switch {
		if n.State == edge.NodeCoolingDown {
			cooling++
		}
	}
	for _, n := range in.Switch {
		if n.State != edge.NodeCoolingDown {
			continue
		}
		c := admin.HealthCondition{
			ID:       "switch_cooldown:" + n.Address,
			Severity: admin.HealthDegraded,
			Message:  fmt.Sprintf("switch node %s answered nothing and is cooling down", n.Address),
		}
		if cooling == len(in.Switch) {
			c.Severity = admin.HealthCritical
			c.Detail = "every switch node is cooling down"
		}
		out = append(out, c)
	}

	for _, d := range in.Carriers {
		if !d.Failing {
			continue
		}
		c := admin.HealthCondition{
			ID:       "carrier_dns:" + d.Name,
			Severity: admin.HealthDegraded,
			Message:  fmt.Sprintf("carrier %s: DNS lookup failing, serving a stale set of %d address(es)", d.Name, len(d.Addresses)),
			Detail:   d.LastError,
		}
		if len(d.Addresses) == 0 {
			c.Severity = admin.HealthCritical
			c.Message = fmt.Sprintf("carrier %s: DNS lookup failing and no address is known", d.Name)
		}
		out = append(out, c)
	}

	if in.Reload.LastError != "" {
		out = append(out, admin.HealthCondition{
			ID:       "config_reload_failed",
			Severity: admin.HealthDegraded,
			Message:  "the last config reload failed; the previous configuration is still running: " + in.Reload.LastError,
			Detail:   "failed at " + in.Reload.LastErrorAt.UTC().Format(time.RFC3339),
		})
	}
	if len(in.Reload.RestartRequired) > 0 {
		out = append(out, admin.HealthCondition{
			ID:       "config_restart_required",
			Severity: admin.HealthDegraded,
			Message:  "the config file changes settings that need a restart",
			Detail:   "restart-only keys: " + strings.Join(in.Reload.RestartRequired, ", "),
		})
	}

	if in.PortsTotal > 0 && in.PortsInUse*100 >= in.PortsTotal*portsDegradedPercent {
		c := admin.HealthCondition{
			ID:       "rtp_ports",
			Severity: admin.HealthDegraded,
			Message:  fmt.Sprintf("RTP port pool is %d%% used (%d of %d pairs)", in.PortsInUse*100/in.PortsTotal, in.PortsInUse, in.PortsTotal),
		}
		if in.PortsInUse >= in.PortsTotal {
			c.Severity = admin.HealthCritical
			c.Message = fmt.Sprintf("RTP port pool is exhausted (%d of %d pairs)", in.PortsInUse, in.PortsTotal)
		}
		out = append(out, c)
	}

	if h.banCapActive(in.BanRejected) {
		out = append(out, admin.HealthCondition{
			ID:       "shield_ban_cap",
			Severity: admin.HealthDegraded,
			Message:  "the shield ban table is at its cap and refusing new bans",
			Detail:   fmt.Sprintf("%d ban additions refused so far", in.BanRejected),
		})
	}

	if in.AdminPlainRemote {
		out = append(out, admin.HealthCondition{
			ID:       "admin_plain_remote",
			Severity: admin.HealthCritical,
			Message:  "admin serves plain HTTP on a non-loopback address",
		})
	}
	return out
}

// banCapActive records the counter and reports whether it rose within
// banCapQuiet: raised when it increased since the previous evaluation,
// cleared once it has not increased for banCapQuiet.
func (h *healthSource) banCapActive(rejected int64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.clock()
	if rejected > h.rejected {
		h.lastRise = now
	}
	h.rejected = rejected
	return !h.lastRise.IsZero() && now.Sub(h.lastRise) < banCapQuiet
}
