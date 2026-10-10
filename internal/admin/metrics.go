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
	deps     Deps
	audit    *auditLog
	authFail *prometheus.Desc
	// descriptors
	activeCalls *prometheus.Desc
	portsInUse  *prometheus.Desc
	portsTotal  *prometheus.Desc
	dropsTotal  *prometheus.Desc
	buildInfo   *prometheus.Desc

	// Edge-proxy plane (nil-safe: Deps.Proxy is nil when no stats
	// source is wired, and Collect skips the whole block then).
	proxyRegs       *prometheus.Desc
	proxySubs       *prometheus.Desc
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
	proxySessions   *prometheus.Desc
	proxyDraining   *prometheus.Desc
	proxyAdmission  *prometheus.Desc
	proxyCallsEnded *prometheus.Desc
	proxyRejects    *prometheus.Desc
	proxyParseFail  *prometheus.Desc
	proxyStreams    *prometheus.Desc
	proxyStreamRef  *prometheus.Desc
	proxyStreamCls  *prometheus.Desc
	proxyCarrierReq *prometheus.Desc
	proxyCarrierReg *prometheus.Desc

	restartRequired *prometheus.Desc
	reloadFailed    *prometheus.Desc
}

func newCollector(deps Deps, audit *auditLog) *collector {
	return &collector{
		deps:        deps,
		audit:       audit,
		authFail:    prometheus.NewDesc("freesbc_admin_auth_failures_total", "Admin API authentication failures, by reason (bad_credentials, rate_limited).", []string{"reason"}, nil),
		activeCalls: prometheus.NewDesc("freesbc_active_calls", "Currently active bridged calls.", nil, nil),
		portsInUse:  prometheus.NewDesc("freesbc_media_ports_in_use", "RTP port pairs in use.", nil, nil),
		portsTotal:  prometheus.NewDesc("freesbc_media_ports_total", "RTP port pairs the range can hold.", nil, nil),
		dropsTotal:  prometheus.NewDesc("freesbc_shield_drops_total", "Total shield drops by reason.", []string{"reason"}, nil),
		buildInfo:   prometheus.NewDesc("freesbc_build_info", "Build info; always 1.", []string{"version"}, nil),

		restartRequired: prometheus.NewDesc("freesbc_config_restart_required", "Restart-only config keys changed on disk and not applied until restart.", nil, nil),
		reloadFailed:    prometheus.NewDesc("freesbc_config_reload_failed", "1 while the last config reload failed and the previous config is still active, else 0.", nil, nil),

		proxyRegs:       prometheus.NewDesc("freesbc_active_registrations", "Registration bindings the edge proxy currently holds.", nil, nil),
		proxySubs:       prometheus.NewDesc("freesbc_edge_subscriptions", "SUBSCRIBE dialogs the edge routes NOTIFYs for, pending or active.", nil, nil),
		proxyDialogs:    prometheus.NewDesc("freesbc_active_sip_dialogs", "Dialogs the edge proxy is currently on the path of.", nil, nil),
		proxySessions:   prometheus.NewDesc("freesbc_edge_sessions", "Calls holding a session slot, ringing or up; the number shield.max_sessions caps.", nil, nil),
		proxyDraining:   prometheus.NewDesc("freesbc_edge_draining", "1 while the edge is in drain mode and refuses new INVITEs, else 0.", nil, nil),
		proxyMedia:      prometheus.NewDesc("freesbc_active_media_sessions", "Media sessions the edge proxy is anchoring.", nil, nil),
		proxyWebRTC:     prometheus.NewDesc("freesbc_active_webrtc_sessions", "Anchored media sessions whose public leg is WebRTC.", nil, nil),
		proxyRegTotal:   prometheus.NewDesc("freesbc_registration_total", "Registrations accepted by the upstream registrar through the proxy.", nil, nil),
		proxyRegFailure: prometheus.NewDesc("freesbc_registration_failure_total", "Registrations that failed at or through the proxy.", nil, nil),
		// method and transport are bounded sets; a Call-ID label here would
		// create a permanent series per call (spec §17).
		proxyReqIn:      prometheus.NewDesc("freesbc_sip_requests_total", "SIP requests received by the edge proxy.", []string{"method", "transport"}, nil),
		proxyResOut:     prometheus.NewDesc("freesbc_sip_responses_total", "SIP responses sent by the edge proxy, by status class.", []string{"class"}, nil),
		proxyRTPPktRx:   prometheus.NewDesc("freesbc_rtp_packets_rx_total", "RTP packets received across finished media sessions.", nil, nil),
		proxyRTPPktTx:   prometheus.NewDesc("freesbc_rtp_packets_tx_total", "RTP packets sent across finished media sessions.", nil, nil),
		proxyRTPByteRx:  prometheus.NewDesc("freesbc_rtp_bytes_rx_total", "RTP bytes received across finished media sessions.", nil, nil),
		proxyRTPByteTx:  prometheus.NewDesc("freesbc_rtp_bytes_tx_total", "RTP bytes sent across finished media sessions.", nil, nil),
		proxyPortFail:   prometheus.NewDesc("freesbc_media_port_allocation_failure_total", "Calls rejected because a media port pool was exhausted.", nil, nil),
		proxyICEFail:    prometheus.NewDesc("freesbc_webrtc_ice_failure_total", "WebRTC legs that never completed ICE.", nil, nil),
		proxyDTLSFail:   prometheus.NewDesc("freesbc_webrtc_dtls_failure_total", "WebRTC legs that failed the DTLS handshake or fingerprint check.", nil, nil),
		proxyPanics:     prometheus.NewDesc("freesbc_sip_handler_panics_total", "Edge SIP handler panics recovered (each one lost a request).", nil, nil),
		proxyParseFail:  prometheus.NewDesc("freesbc_sip_parse_failures_total", "Reads the SIP parser rejected (malformed messages), by transport; the payload is never logged.", []string{"transport"}, nil),
		proxyAdmission:  prometheus.NewDesc("freesbc_edge_admission_drops_total", "Public requests the edge proxy dropped silently by admission, by reason.", []string{"reason"}, nil),
		proxyCallsEnded: prometheus.NewDesc("freesbc_edge_calls_ended_total", "Confirmed calls that ended, by reason.", []string{"reason"}, nil),
		proxyStreams:    prometheus.NewDesc("freesbc_edge_stream_connections", "Open public stream connections (tcp, tls, ws, wss), by transport.", []string{"transport"}, nil),
		proxyStreamRef:  prometheus.NewDesc("freesbc_edge_stream_refused_total", "Stream connections refused at accept, by reason (global_cap, ip_cap, banned, rate).", []string{"reason"}, nil),
		proxyStreamCls:  prometheus.NewDesc("freesbc_edge_stream_closed_total", "Stream connections closed by policy, by reason (idle, slow, oversize, malformed, handshake, rate).", []string{"reason"}, nil),
		proxyRejects:    prometheus.NewDesc("freesbc_edge_invite_rejects_total", "Out-of-dialog INVITEs the edge answered with a final response itself, by reason.", []string{"reason"}, nil),
		// carrier is a configured name or "unknown"; direction and method
		// are bounded sets.
		proxyCarrierReq: prometheus.NewDesc("freesbc_edge_carrier_requests_total", "SIP requests of the carrier path, by carrier, direction (inbound: carrier to switch, outbound: switch to carrier) and method.", []string{"carrier", "direction", "method"}, nil),
		proxyCarrierReg: prometheus.NewDesc("freesbc_edge_carrier_registrations", "Live carrier registrations (switch to carrier) the edge holds, by carrier.", []string{"carrier"}, nil),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.activeCalls
	ch <- c.portsInUse
	ch <- c.portsTotal
	ch <- c.dropsTotal
	ch <- c.buildInfo
	ch <- c.authFail
	ch <- c.restartRequired
	ch <- c.reloadFailed
	for _, d := range []*prometheus.Desc{
		c.proxyRegs, c.proxySubs, c.proxyDialogs, c.proxySessions, c.proxyDraining, c.proxyMedia, c.proxyWebRTC,
		c.proxyRegTotal, c.proxyRegFailure, c.proxyReqIn, c.proxyResOut,
		c.proxyRTPPktRx, c.proxyRTPPktTx, c.proxyRTPByteRx, c.proxyRTPByteTx,
		c.proxyPortFail, c.proxyICEFail, c.proxyDTLSFail, c.proxyPanics,
		c.proxyAdmission, c.proxyCallsEnded, c.proxyRejects, c.proxyParseFail, c.proxyStreams, c.proxyStreamRef, c.proxyStreamCls, c.proxyCarrierReq, c.proxyCarrierReg,
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
	st := c.deps.Shield()
	for reason, n := range st.DropsByReason {
		ch <- prometheus.MustNewConstMetric(c.dropsTotal, prometheus.CounterValue, float64(n), reason)
	}
	g(c.buildInfo, 1, c.deps.Version)
	fails := c.audit.failures()
	for _, reason := range authFailureReasons {
		ch <- prometheus.MustNewConstMetric(c.authFail, prometheus.CounterValue, float64(fails[reason]), string(reason))
	}

	if c.deps.Reload != nil {
		rs := c.deps.Reload()
		failed := 0.0
		if rs.LastError != "" {
			failed = 1
		}
		g(c.restartRequired, float64(len(rs.RestartRequired)))
		g(c.reloadFailed, failed)
	}

	if c.deps.Proxy == nil {
		return // no edge stats wired
	}
	p := c.deps.Proxy()
	counter := func(d *prometheus.Desc, v float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, lv...)
	}
	g(c.proxyRegs, float64(p.ActiveRegistrations))
	g(c.proxySubs, float64(p.ActiveSubscriptions))
	g(c.proxyDialogs, float64(p.ActiveDialogs))
	g(c.proxySessions, float64(p.ActiveSessions))
	draining := 0.0
	if p.Draining {
		draining = 1
	}
	g(c.proxyDraining, draining)
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
	for transport, v := range p.ParseFailures {
		counter(c.proxyParseFail, float64(v), transport)
	}
	for transport, v := range p.StreamConnections {
		g(c.proxyStreams, float64(v), transport)
	}
	for reason, v := range p.StreamRefused {
		counter(c.proxyStreamRef, float64(v), reason)
	}
	for reason, v := range p.StreamClosed {
		counter(c.proxyStreamCls, float64(v), reason)
	}
	for reason, v := range p.AdmissionDrops {
		counter(c.proxyAdmission, float64(v), reason)
	}
	for reason, v := range p.CallsEnded {
		counter(c.proxyCallsEnded, float64(v), reason)
	}
	for reason, v := range p.InviteRejects {
		counter(c.proxyRejects, float64(v), reason)
	}
	for name, n := range p.CarrierRegistrations {
		g(c.proxyCarrierReg, float64(n), name)
	}
	for k, v := range p.CarrierRequests {
		parts := strings.SplitN(k, "/", 3)
		if len(parts) == 3 {
			counter(c.proxyCarrierReq, float64(v), parts[0], parts[1], parts[2])
		}
	}
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
		reg.MustRegister(newCollector(s.deps, &s.audit))
		s.metricsHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	})
	return s.metricsHandler
}
