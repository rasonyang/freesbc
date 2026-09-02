package admin

import (
	"strings"
	"testing"
)

// testServerWithMetrics returns a test server whose Deps are overridden with
// known values for exercising /metrics exposition.
func testServerWithMetrics(t *testing.T, activeCalls, portsInUse, portsTotal int, peers []PeerStatus, shield ShieldStats) *Server {
	t.Helper()
	deps := emptyDeps()
	deps.ActiveCalls = func() int { return activeCalls }
	deps.Ports = func() (int, int) { return portsInUse, portsTotal }
	deps.Peers = func() []PeerStatus { return peers }
	deps.Shield = func() ShieldStats { return shield }
	return newTestServer(t, deps)
}

func TestMetricsExposition(t *testing.T) {
	// deps with known values
	s := testServerWithMetrics(t /*activeCalls*/, 3 /*ports*/, 2, 4,
		[]PeerStatus{{Name: "carrier", Register: true, Registered: true}},
		ShieldStats{BannedCurrent: 5, DropsByReason: map[string]int64{"rate": 7, "scanner": 0, "banned": 0}})
	body := authGET(t, s, "/metrics")
	str := string(body)
	for _, want := range []string{
		"freesbc_active_calls 3",
		"freesbc_media_ports_in_use 2",
		"freesbc_media_ports_total 4",
		`freesbc_peer_registered{peer="carrier"} 1`,
		"freesbc_shield_banned_current 5",
		`freesbc_shield_drops_total{reason="rate"} 7`,
	} {
		if !strings.Contains(str, want) {
			t.Errorf("/metrics missing %q\n---\n%s", want, str)
		}
	}
}
