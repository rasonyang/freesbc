package admin

import (
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// collector samples the live Deps on each scrape — no duplicated state.
type collector struct {
	deps Deps
	// descriptors
	activeCalls     *prometheus.Desc
	portsInUse      *prometheus.Desc
	portsTotal      *prometheus.Desc
	peerReg         *prometheus.Desc
	bannedCurrent   *prometheus.Desc
	banAddsRejected *prometheus.Desc
	dropsTotal      *prometheus.Desc
	buildInfo       *prometheus.Desc

	// Edge-proxy plane (nil-safe: Deps.Proxy is nil in a trunk-only
	// deployment, and Collect skips the whole block then).
	proxyRegs       *prometheus.Desc
	proxyDialogs    *prometheus.Desc
	proxyMedia      *prometheus.Desc
	proxyWebRTC     *prometheus.Desc
	proxyRegTotal   *prometheus.Desc
	proxyRegFailure *prometheus.Desc
	proxyReqIn      *prometheus.Desc
	proxyResOut     *prometheus.Desc
	proxyRTPPktRx   *prometheus.Desc
	proxyRTPPktTx   *prometheus.Desc
	proxyRTPByteRx  *prometheus.Desc
	proxyRTPByteTx  *prometheus.Desc
	proxyPortFail   *prometheus.Desc
	proxyICEFail    *prometheus.Desc
	proxyDTLSFail   *prometheus.Desc
	proxyPanics     *prometheus.Desc
}

func newCollector(deps Deps) *collector {
	return &collector{
		deps:            deps,
		activeCalls:     prometheus.NewDesc("freesbc_active_calls", "Currently active bridged calls.", nil, nil),
		portsInUse:      prometheus.NewDesc("freesbc_media_ports_in_use", "RTP port pairs in use.", nil, nil),
		portsTotal:      prometheus.NewDesc("freesbc_media_ports_total", "RTP port pairs the range can hold.", nil, nil),
		peerReg:         prometheus.NewDesc("freesbc_peer_registered", "1 if a register:true peer is currently registered.", []string{"peer"}, nil),
		bannedCurrent:   prometheus.NewDesc("freesbc_shield_banned_current", "Sources currently in the shield ban table.", nil, nil),
		banAddsRejected: prometheus.NewDesc("freesbc_shield_ban_adds_rejected_total", "Total shield ban additions refused at the hard table cap.", nil, nil),
		dropsTotal:      prometheus.NewDesc("freesbc_shield_drops_total", "Total shield drops by reason.", []string{"reason"}, nil),
		buildInfo:       prometheus.NewDesc("freesbc_build_info", "Build info; always 1.", []string{"version"}, nil),

		proxyRegs:       prometheus.NewDesc("freesbc_active_registrations", "Registration bindings the edge proxy currently holds.", nil, nil),
		proxyDialogs:    prometheus.NewDesc("freesbc_active_sip_dialogs", "Dialogs the edge proxy is currently on the path of.", nil, nil),
		proxyMedia:      prometheus.NewDesc("freesbc_active_media_sessions", "Media sessions the edge proxy is anchoring.", nil, nil),
		proxyWebRTC:     prometheus.NewDesc("freesbc_active_webrtc_sessions", "Anchored media sessions whose public leg is WebRTC.", nil, nil),
		proxyRegTotal:   prometheus.NewDesc("freesbc_registration_total", "Registrations accepted by the upstream registrar through the proxy.", nil, nil),
		proxyRegFailure: prometheus.NewDesc("freesbc_registration_failure_total", "Registrations that failed at or through the proxy.", nil, nil),
		// method and transport are bounded sets; a Call-ID label here would
		// create a permanent series per call (spec §17).
		proxyReqIn:     prometheus.NewDesc("freesbc_sip_requests_total", "SIP requests received by the edge proxy.", []string{"method", "transport"}, nil),
		proxyResOut:    prometheus.NewDesc("freesbc_sip_responses_total", "SIP responses sent by the edge proxy, by status class.", []string{"class"}, nil),
		proxyRTPPktRx:  prometheus.NewDesc("freesbc_rtp_packets_rx_total", "RTP packets received across finished media sessions.", nil, nil),
		proxyRTPPktTx:  prometheus.NewDesc("freesbc_rtp_packets_tx_total", "RTP packets sent across finished media sessions.", nil, nil),
		proxyRTPByteRx: prometheus.NewDesc("freesbc_rtp_bytes_rx_total", "RTP bytes received across finished media sessions.", nil, nil),
		proxyRTPByteTx: prometheus.NewDesc("freesbc_rtp_bytes_tx_total", "RTP bytes sent across finished media sessions.", nil, nil),
		proxyPortFail:  prometheus.NewDesc("freesbc_media_port_allocation_failure_total", "Calls rejected because a media port pool was exhausted.", nil, nil),
		proxyICEFail:   prometheus.NewDesc("freesbc_webrtc_ice_failure_total", "WebRTC legs that never completed ICE.", nil, nil),
		proxyDTLSFail:  prometheus.NewDesc("freesbc_webrtc_dtls_failure_total", "WebRTC legs that failed the DTLS handshake or fingerprint check.", nil, nil),
		proxyPanics:    prometheus.NewDesc("freesbc_sip_handler_panics_total", "Edge SIP handler panics recovered (each one lost a request).", nil, nil),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.activeCalls
	ch <- c.portsInUse
	ch <- c.portsTotal
	ch <- c.peerReg
	ch <- c.bannedCurrent
	ch <- c.banAddsRejected
	ch <- c.dropsTotal
	ch <- c.buildInfo
	for _, d := range []*prometheus.Desc{
		c.proxyRegs, c.proxyDialogs, c.proxyMedia, c.proxyWebRTC,
		c.proxyRegTotal, c.proxyRegFailure, c.proxyReqIn, c.proxyResOut,
		c.proxyRTPPktRx, c.proxyRTPPktTx, c.proxyRTPByteRx, c.proxyRTPByteTx,
		c.proxyPortFail, c.proxyICEFail, c.proxyDTLSFail, c.proxyPanics,
	} {
		ch <- d
	}
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
	g(c.banAddsRejected, float64(st.BanAddsRejected))
	for reason, n := range st.DropsByReason {
		ch <- prometheus.MustNewConstMetric(c.dropsTotal, prometheus.CounterValue, float64(n), reason)
	}
	g(c.buildInfo, 1, c.deps.Version)

	if c.deps.Proxy == nil {
		return // trunk-only deployment: the edge proxy is not running
	}
	p := c.deps.Proxy()
	counter := func(d *prometheus.Desc, v float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, lv...)
	}
	g(c.proxyRegs, float64(p.ActiveRegistrations))
	g(c.proxyDialogs, float64(p.ActiveDialogs))
	g(c.proxyMedia, float64(p.ActiveMediaSessions))
	g(c.proxyWebRTC, float64(p.ActiveWebRTCSessions))
	counter(c.proxyRegTotal, float64(p.RegistrationTotal))
	counter(c.proxyRegFailure, float64(p.RegistrationFailure))
	for k, v := range p.RequestsIn {
		method, transport, _ := strings.Cut(k, "/")
		counter(c.proxyReqIn, float64(v), method, transport)
	}
	for class, v := range p.ResponsesOut {
		counter(c.proxyResOut, float64(v), class)
	}
	counter(c.proxyRTPPktRx, float64(p.RTPPacketsRx))
	counter(c.proxyRTPPktTx, float64(p.RTPPacketsTx))
	counter(c.proxyRTPByteRx, float64(p.RTPBytesRx))
	counter(c.proxyRTPByteTx, float64(p.RTPBytesTx))
	counter(c.proxyPortFail, float64(p.PortAllocationFailures))
	counter(c.proxyICEFail, float64(p.ICEFailures))
	counter(c.proxyDTLSFail, float64(p.DTLSFailures))
	counter(c.proxyPanics, float64(p.HandlerPanics))
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
