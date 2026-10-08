package admin

import (
	"strings"
	"testing"
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

// The end-reason and reject counters render one series per reason, zeros
// included, so a rate() has a baseline from the first scrape.
func TestMetricsCallEndAndRejectCounters(t *testing.T) {
	deps := emptyDeps()
	deps.Proxy = func() ProxyStats {
		return ProxyStats{
			CallsEnded:     map[string]uint64{"bye_caller": 2, "rtp_silence": 0},
			InviteRejects:  map[string]uint64{"early_cap": 1, "port_exhausted": 0, "session_cap": 3, "invite_rate": 0},
			ActiveSessions: 4,
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
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n---\n%s", want, body)
		}
	}
}
