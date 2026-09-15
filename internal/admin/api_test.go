package admin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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
	// a config with a peer password and admin hash; assert redaction.
	s := testServerWithSecretConfig(t, "s3cr3t-carrier-pw")
	body := authGET(t, s, "/api/config")
	str := string(body)
	if strings.Contains(str, "s3cr3t-carrier-pw") {
		t.Fatal("peer password LEAKED in /api/config")
	}
	if !strings.Contains(str, "***") {
		t.Fatal("redaction marker missing")
	}
}
