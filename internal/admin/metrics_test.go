package admin

import (
	"net/http"
	"net/http/httptest"
	"runtime"
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

// The process collector is registered next to the Go collector. Its series
// beyond process_start_time_seconds are Linux-only, so only that one is
// required everywhere.
func TestMetricsProcessCollector(t *testing.T) {
	str := string(authGET(t, testServer(t), "/metrics"))
	for _, want := range []string{"go_goroutines", "process_start_time_seconds"} {
		if !strings.Contains(str, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	if runtime.GOOS == "linux" {
		for _, want := range []string{"process_cpu_seconds_total", "process_resident_memory_bytes", "process_open_fds"} {
			if !strings.Contains(str, want) {
				t.Errorf("/metrics missing %q", want)
			}
		}
	}
}

func pprofServer(t *testing.T, on bool) *Server {
	t.Helper()
	s := testServer(t)
	s.cfg.Pprof = on
	return s
}

func TestPprofOffIs404(t *testing.T) {
	s := pprofServer(t, false)
	rr := httptest.NewRecorder()
	req := newReq("GET", "/debug/pprof/", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("pprof off: got %d want 404", rr.Code)
	}
}

func TestPprofOnNeedsAuth(t *testing.T) {
	s := pprofServer(t, true)
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, newReq("GET", "/debug/pprof/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("pprof without creds: got %d want 401", rr.Code)
	}
	if body := string(authGET(t, s, "/debug/pprof/")); !strings.Contains(body, "goroutine") {
		t.Errorf("pprof index lacks goroutine profile: %s", body)
	}
	if body := authGET(t, s, "/debug/pprof/cmdline"); len(body) == 0 {
		t.Error("pprof cmdline empty")
	}
	if body := authGET(t, s, "/debug/pprof/heap?debug=1"); len(body) == 0 {
		t.Error("pprof heap empty")
	}
}
