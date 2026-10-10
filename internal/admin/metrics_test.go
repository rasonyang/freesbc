package admin

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// testServerWithMetrics returns a test server whose Deps are overridden with
// known values for exercising /metrics exposition.
func testServerWithMetrics(t *testing.T, activeCalls, portsInUse, portsTotal int, shield ShieldStats) *Server {
	t.Helper()
	deps := emptyDeps()
	deps.ActiveCalls = func() int { return activeCalls }
	deps.Ports = func() (int, int) { return portsInUse, portsTotal }
	deps.Shield = func() ShieldStats { return shield }
	return newTestServer(t, deps)
}

func TestMetricsExposition(t *testing.T) {
	// deps with known values
	s := testServerWithMetrics(t /*activeCalls*/, 3 /*ports*/, 2, 4,
		ShieldStats{DropsByReason: map[string]int64{"rate": 7, "scanner": 0, "banned": 0}})
	body := authGET(t, s, "/metrics")
	str := string(body)
	for _, want := range []string{
		"freesbc_active_calls 3",
		"freesbc_media_ports_in_use 2",
		"freesbc_media_ports_total 4",
		`freesbc_shield_drops_total{reason="rate"} 7`,
	} {
		if !strings.Contains(str, want) {
			t.Errorf("/metrics missing %q\n---\n%s", want, str)
		}
	}
}

// The stream connection gauge and its refusal and close counters render one
// series per transport and reason, zeros included.
func TestMetricsStreamConnections(t *testing.T) {
	deps := emptyDeps()
	deps.Proxy = func() ProxyStats {
		return ProxyStats{
			StreamConnections: map[string]int64{"tcp": 3, "tls": 0},
			StreamRefused:     map[string]uint64{"ip_cap": 5, "global_cap": 0},
			StreamClosed:      map[string]uint64{"idle": 2, "slow": 0},
		}
	}
	body := string(authGET(t, newTestServer(t, deps), "/metrics"))
	for _, want := range []string{
		`freesbc_edge_stream_connections{transport="tcp"} 3`,
		`freesbc_edge_stream_connections{transport="tls"} 0`,
		`freesbc_edge_stream_refused_total{reason="ip_cap"} 5`,
		`freesbc_edge_stream_refused_total{reason="global_cap"} 0`,
		`freesbc_edge_stream_closed_total{reason="idle"} 2`,
		`freesbc_edge_stream_closed_total{reason="slow"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n---\n%s", want, body)
		}
	}
}

// The end-reason and reject counters render one series per reason, zeros
// included, so a rate() has a baseline from the first scrape.
func TestMetricsCallEndAndRejectCounters(t *testing.T) {
	deps := emptyDeps()
	deps.Proxy = func() ProxyStats {
		return ProxyStats{
			CallsEnded:     map[string]uint64{"bye_caller": 2, "rtp_silence": 0},
			InviteRejects:  map[string]uint64{"early_cap": 1, "port_exhausted": 0, "session_cap": 3, "invite_rate": 0},
			ActiveSessions: 4, ActiveSubscriptions: 7,
		}
	}
	body := string(authGET(t, newTestServer(t, deps), "/metrics"))
	for _, want := range []string{
		`freesbc_edge_calls_ended_total{reason="bye_caller"} 2`,
		`freesbc_edge_calls_ended_total{reason="rtp_silence"} 0`,
		`freesbc_edge_invite_rejects_total{reason="early_cap"} 1`,
		`freesbc_edge_invite_rejects_total{reason="port_exhausted"} 0`,
		`freesbc_edge_invite_rejects_total{reason="session_cap"} 3`,
		`freesbc_edge_invite_rejects_total{reason="invite_rate"} 0`,
		"freesbc_edge_sessions 4",
		"freesbc_edge_subscriptions 7",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n---\n%s", want, body)
		}
	}
}

// The certificate expiry gauge carries not-after as Unix seconds under the
// cert file path, and is absent when no certificate is loaded.
func TestMetricsTLSCertExpiry(t *testing.T) {
	notAfter := time.Now().Add(40 * 24 * time.Hour).Truncate(time.Second)
	cert, key := writeTLSPair(t, t.TempDir(), "m.example.test", notAfter, false)
	body := string(authGET(t, tlsServer(t, cert, key), "/metrics"))
	want := fmt.Sprintf("freesbc_tls_cert_expiry_timestamp_seconds{path=%q} %s", cert, strconv.FormatFloat(float64(notAfter.Unix()), 'g', -1, 64))
	if !strings.Contains(body, want) {
		t.Errorf("/metrics missing %q\n---\n%s", want, body)
	}
	if body := string(authGET(t, testServer(t), "/metrics")); strings.Contains(body, "freesbc_tls_cert_expiry_timestamp_seconds") {
		t.Errorf("gauge exported with no certificate loaded")
	}
}

// The config reload gauges are exported when Deps.Reload is wired and
// absent when it is not.
func TestMetricsConfigReload(t *testing.T) {
	deps := emptyDeps()
	deps.Reload = func() config.ReloadStatus {
		return config.ReloadStatus{RestartRequired: []string{"public", "rtp"}, LastError: "boom"}
	}
	str := string(authGET(t, newTestServer(t, deps), "/metrics"))
	for _, want := range []string{"freesbc_config_restart_required 2", "freesbc_config_reload_failed 1"} {
		if !strings.Contains(str, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	deps.Reload = func() config.ReloadStatus { return config.ReloadStatus{} }
	str = string(authGET(t, newTestServer(t, deps), "/metrics"))
	for _, want := range []string{"freesbc_config_restart_required 0", "freesbc_config_reload_failed 0"} {
		if !strings.Contains(str, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	str = string(authGET(t, testServer(t), "/metrics"))
	if strings.Contains(str, "freesbc_config_") {
		t.Error("config gauges exported with no Reload dep")
	}
}
