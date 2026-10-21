package admin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

func TestAPIStatus(t *testing.T) {
	s := testServer(t) // from server_test.go; wire ActiveCalls/Ports to known values
	body := authGET(t, s, "/api/status")
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("status json: %v", err)
	}
	for _, k := range []string{"version", "uptime_seconds", "active_calls", "ports"} {
		if _, ok := st[k]; !ok {
			t.Errorf("status missing %q", k)
		}
	}
}

// The version is shown as the build set it: a release tag already carries
// its "v", so neither the API nor the header adds one (#254).
func TestAPIStatusVersionVerbatim(t *testing.T) {
	deps := emptyDeps()
	deps.Version = "v0.6.0"
	var st struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(authGET(t, newTestServer(t, deps), "/api/status"), &st); err != nil {
		t.Fatal(err)
	}
	if st.Version != "v0.6.0" {
		t.Errorf("version = %q, want v0.6.0", st.Version)
	}
	js := uiGet(t, testServer(t), "/assets/app.js", true).Body.String()
	if !strings.Contains(js, `$("header-version").textContent = data.version;`) {
		t.Error("app.js must show the header version as the API reports it")
	}
}

// listener_info pairs each bound listener with its advertised address, and
// the older listeners strings stay.
func TestAPIStatusListenerInfo(t *testing.T) {
	deps := emptyDeps()
	deps.Listeners = func() []string { return []string{"udp://172.20.0.4:5060"} }
	deps.ListenerInfos = func() []Listener {
		return []Listener{{Transport: "udp", Bind: "172.20.0.4:5060", Advertised: "223.76.90.4:5060"}}
	}
	var st struct {
		Listeners []string `json:"listeners"`
		Info      []struct {
			Transport, Bind, Advertised string
			Private                     bool
		} `json:"listener_info"`
	}
	if err := json.Unmarshal(authGET(t, newTestServer(t, deps), "/api/status"), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Listeners) != 1 || len(st.Info) != 1 || st.Info[0].Advertised != "223.76.90.4:5060" || st.Info[0].Bind != "172.20.0.4:5060" {
		t.Errorf("status = %+v", st)
	}
	var none struct {
		Info []any `json:"listener_info"`
	}
	if err := json.Unmarshal(authGET(t, testServer(t), "/api/status"), &none); err != nil || none.Info == nil {
		t.Errorf("listener_info without deps = %v (err %v), want []", none.Info, err)
	}
}

func TestAPICalls(t *testing.T) {
	// override the Calls dep to return one call, assert it's reflected.
	s := testServerWithCalls(t, []Call{{ID: "abc", FromPeer: "a", ToPeer: "b", StartUnixNano: time.Now().UnixNano()}})
	body := authGET(t, s, "/api/calls")
	var calls []map[string]any
	if err := json.Unmarshal(body, &calls); err != nil {
		t.Fatalf("calls json: %v", err)
	}
	if len(calls) != 1 || calls[0]["id"] != "abc" || calls[0]["from"] != "a" {
		t.Fatalf("calls not reflected: %v", calls)
	}
}

func TestAPICallsEmptyIsEmptyArray(t *testing.T) {
	// An empty call list must serialize as [] not null, so API consumers
	// can rely on a stable array shape.
	s := testServer(t)
	body := authGET(t, s, "/api/calls")
	if strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("empty calls: got %q want []", string(body))
	}
}

func TestAPIConfigRedactsSecrets(t *testing.T) {
	// a config with an admin hash; assert redaction.
	s := testServerWithSecretConfig(t, "s3cr3t-admin-hash")
	body := authGET(t, s, "/api/config")
	str := string(body)
	if strings.Contains(str, "s3cr3t-admin-hash") {
		t.Fatal("admin password hash LEAKED in /api/config")
	}
	if !strings.Contains(str, "***") {
		t.Fatal("redaction marker missing")
	}
}

func statusReload(t *testing.T, s *Server) map[string]any {
	t.Helper()
	var st map[string]any
	if err := json.Unmarshal(authGET(t, s, "/api/status"), &st); err != nil {
		t.Fatalf("status json: %v", err)
	}
	rl, ok := st["reload"].(map[string]any)
	if !ok {
		t.Fatalf("status has no reload object: %v", st)
	}
	return rl
}

// With no Reload dep the reload object is still present, with an empty
// (never null) restart_required and null times and error.
func TestAPIStatusReloadNilDeps(t *testing.T) {
	rl := statusReload(t, testServer(t))
	keys, ok := rl["restart_required"].([]any)
	if !ok || len(keys) != 0 {
		t.Errorf("restart_required = %#v, want []", rl["restart_required"])
	}
	for _, k := range []string{"last_ok", "last_error", "last_error_at"} {
		if v, present := rl[k]; !present || v != nil {
			t.Errorf("%s = %#v, want null", k, v)
		}
	}
}

func TestAPIStatusReloadPopulated(t *testing.T) {
	ok := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	bad := ok.Add(time.Minute)
	deps := emptyDeps()
	deps.Reload = func() config.ReloadStatus {
		return config.ReloadStatus{LastOK: ok, RestartRequired: []string{"edge.listen", "public"}, LastError: "bad yaml", LastErrorAt: bad}
	}
	rl := statusReload(t, newTestServer(t, deps))
	if rl["last_ok"] != "2026-01-02T03:04:05Z" || rl["last_error"] != "bad yaml" || rl["last_error_at"] != "2026-01-02T03:05:05Z" {
		t.Errorf("reload = %v", rl)
	}
	keys, _ := rl["restart_required"].([]any)
	if len(keys) != 2 || keys[0] != "edge.listen" || keys[1] != "public" {
		t.Errorf("restart_required = %v", rl["restart_required"])
	}
}
