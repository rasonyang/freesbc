package admin

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// collector samples the live Deps on each scrape — no duplicated state.
type collector struct {
	deps Deps
	// descriptors
	activeCalls   *prometheus.Desc
	portsInUse    *prometheus.Desc
	portsTotal    *prometheus.Desc
	peerReg       *prometheus.Desc
	bannedCurrent *prometheus.Desc
	dropsTotal    *prometheus.Desc
	buildInfo     *prometheus.Desc
}

func newCollector(deps Deps) *collector {
	return &collector{
		deps:          deps,
		activeCalls:   prometheus.NewDesc("freesbc_active_calls", "Currently active bridged calls.", nil, nil),
		portsInUse:    prometheus.NewDesc("freesbc_media_ports_in_use", "RTP port pairs in use.", nil, nil),
		portsTotal:    prometheus.NewDesc("freesbc_media_ports_total", "RTP port pairs the range can hold.", nil, nil),
		peerReg:       prometheus.NewDesc("freesbc_peer_registered", "1 if a register:true peer is currently registered.", []string{"peer"}, nil),
		bannedCurrent: prometheus.NewDesc("freesbc_shield_banned_current", "Sources currently in the shield ban table.", nil, nil),
		dropsTotal:    prometheus.NewDesc("freesbc_shield_drops_total", "Total shield drops by reason.", []string{"reason"}, nil),
		buildInfo:     prometheus.NewDesc("freesbc_build_info", "Build info; always 1.", []string{"version"}, nil),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.activeCalls
	ch <- c.portsInUse
	ch <- c.portsTotal
	ch <- c.peerReg
	ch <- c.bannedCurrent
	ch <- c.dropsTotal
	ch <- c.buildInfo
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	g := func(d *prometheus.Desc, v float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
	}
	g(c.activeCalls, float64(c.deps.ActiveCalls()))
	inUse, total := c.deps.Ports()
	g(c.portsInUse, float64(inUse))
	g(c.portsTotal, float64(total))
	for _, p := range c.deps.Peers() {
		if !p.Register {
			continue
		}
		v := 0.0
		if p.Registered {
			v = 1
		}
		g(c.peerReg, v, p.Name)
	}
	st := c.deps.Shield()
	g(c.bannedCurrent, float64(st.BannedCurrent))
	for reason, n := range st.DropsByReason {
		ch <- prometheus.MustNewConstMetric(c.dropsTotal, prometheus.CounterValue, float64(n), reason)
	}
	g(c.buildInfo, 1, c.deps.Version)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.registry().ServeHTTP(w, r)
}

// registry builds the private Prometheus registry on first use (Go runtime
// metrics + the freesbc collector) and returns an http.Handler for it.
func (s *Server) registry() http.Handler {
	s.metricsOnce.Do(func() {
		reg := prometheus.NewRegistry()
		reg.MustRegister(collectors.NewGoCollector())
		reg.MustRegister(newCollector(s.deps))
		s.metricsHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	})
	return s.metricsHandler
}
