package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stateDeps returns Deps whose state closures return the given data.
func stateDeps() Deps {
	d := emptyDeps()
	now := time.Now()
	d.Registrations = func(user string, limit, offset int) ([]Registration, int) {
		return []Registration{{AOR: "sip:1000@example.com", User: "1000", Transport: "wss",
			Source: "198.51.100.9:44321", ExpiresAt: now.Add(300 * time.Second)}}, 7
	}
	d.CarrierRegistrations = func() []CarrierRegistration {
		return []CarrierRegistration{{Carrier: "acme", User: "line1", Token: "abc123", Node: "10.0.0.5:5060",
			Expires: now.Add(120 * time.Second)}}
	}
	d.Bans = func(limit, offset int) ([]Ban, int, int64) {
		return []Ban{{Source: "203.0.113.50", Kind: "ip", Reason: "scanner",
			Since: now.Add(-time.Minute), Until: now.Add(90 * time.Second)}}, 3, 5
	}
	d.SwitchNodes = func() []SwitchNode {
		return []SwitchNode{
			{Address: "10.0.0.5:5060", State: "cooling_down", CooldownRemaining: 20 * time.Second, LastFailure: now.Add(-10 * time.Second)},
			{Address: "10.0.0.6:5060", State: "healthy"},
		}
	}
	d.Carriers = func() []Carrier {
		return []Carrier{{Name: "acme", Host: "sip.acme.example", Transport: "tls", Mode: "srv",
			Addresses:  []CarrierAddress{{Address: "192.0.2.1:5061", InUse: true}, {Address: "192.0.2.2:5061"}},
			ResolvedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(270 * time.Second),
			Failing: true, LastError: "lookup failed"}}
	}
	return d
}

func stateEmptyDeps() Deps {
	d := emptyDeps()
	d.Registrations = func(string, int, int) ([]Registration, int) { return nil, 0 }
	d.CarrierRegistrations = func() []CarrierRegistration { return nil }
	d.Bans = func(int, int) ([]Ban, int, int64) { return nil, 0, 0 }
	d.SwitchNodes = func() []SwitchNode { return nil }
	d.Carriers = func() []Carrier { return nil }
	return d
}

var statePaths = []string{
	"/api/registrations", "/api/carrier-registrations", "/api/shield/bans",
	"/api/switch-nodes", "/api/carriers",
}

func TestStateEndpointsRequireAuth(t *testing.T) {
	h := newTestServer(t, stateDeps()).handler()
	for _, p := range statePaths {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newReq("GET", p, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s without credentials: got %d want 401", p, rr.Code)
		}
	}
}

// Empty tables encode as [] (lists) or {"items":[]} (pages), never null.
func TestStateEndpointsEmpty(t *testing.T) {
	s := newTestServer(t, stateEmptyDeps())
	tests := []struct{ path, want string }{
		{"/api/registrations", `{"items":[],"limit":100,"offset":0,"total":0}`},
		{"/api/carrier-registrations", `[]`},
		{"/api/shield/bans", `{"ban_adds_rejected":0,"items":[],"limit":100,"offset":0,"total":0}`},
		{"/api/switch-nodes", `[]`},
		{"/api/carriers", `[]`},
	}
	for _, tc := range tests {
		got := strings.TrimSpace(string(authGET(t, s, tc.path)))
		if got != tc.want {
			t.Errorf("GET %s = %s, want %s", tc.path, got, tc.want)
		}
	}
}

func TestStateEndpointsData(t *testing.T) {
	s := newTestServer(t, stateDeps())
	get := func(path string) any {
		var v any
		if err := json.Unmarshal(authGET(t, s, path), &v); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return v
	}
	first := func(v any) map[string]any { return v.([]any)[0].(map[string]any) }
	page := func(v any) map[string]any { return first(v.(map[string]any)["items"]) }

	reg := get("/api/registrations")
	r := page(reg)
	if r["aor"] != "sip:1000@example.com" || r["user"] != "1000" || r["transport"] != "wss" || r["source"] != "198.51.100.9:44321" {
		t.Errorf("registration = %v", r)
	}
	if e := r["expires_in"].(float64); e < 298 || e > 300 {
		t.Errorf("expires_in = %v, want about 300", e)
	}
	if reg.(map[string]any)["total"] != float64(7) {
		t.Errorf("registrations total = %v, want 7", reg.(map[string]any)["total"])
	}

	c := first(get("/api/carrier-registrations"))
	if c["carrier"] != "acme" || c["user"] != "line1" || c["token"] != "abc123" || c["node"] != "10.0.0.5:5060" || c["expires_in"].(float64) < 118 {
		t.Errorf("carrier registration = %v", c)
	}

	bans := get("/api/shield/bans").(map[string]any)
	b := page(bans)
	if b["source"] != "203.0.113.50" || b["kind"] != "ip" || b["reason"] != "scanner" || b["remaining"].(float64) < 88 || b["since"] == nil {
		t.Errorf("ban = %v", b)
	}
	if bans["total"] != float64(3) || bans["ban_adds_rejected"] != float64(5) {
		t.Errorf("bans total/rejected = %v/%v, want 3/5", bans["total"], bans["ban_adds_rejected"])
	}

	nodes := get("/api/switch-nodes").([]any)
	n0, n1 := nodes[0].(map[string]any), nodes[1].(map[string]any)
	if n0["state"] != "cooling_down" || n0["cooldown_remaining"].(float64) != 20 || n0["last_failure"] == nil {
		t.Errorf("cooling node = %v", n0)
	}
	if n1["state"] != "healthy" || n1["cooldown_remaining"].(float64) != 0 || n1["last_failure"] != nil {
		t.Errorf("healthy node = %v, want last_failure null", n1)
	}

	car := first(get("/api/carriers"))
	addrs := car["addresses"].([]any)
	if car["name"] != "acme" || car["mode"] != "srv" || car["transport"] != "tls" || car["failing"] != true ||
		car["last_error"] != "lookup failed" || len(addrs) != 2 || addrs[0].(map[string]any)["in_use"] != true ||
		addrs[1].(map[string]any)["in_use"] != false || car["cache_age_seconds"].(float64) < 29 ||
		car["resolved_at"] == nil || car["expires_at"] == nil {
		t.Errorf("carrier = %v", car)
	}
}

// A literal carrier was never resolved: its times and cache age are null.
func TestCarriersUnresolvedNulls(t *testing.T) {
	d := emptyDeps()
	d.Carriers = func() []Carrier {
		return []Carrier{{Name: "lit", Host: "192.0.2.9:5060", Transport: "udp", Mode: "literal"}}
	}
	body := string(authGET(t, newTestServer(t, d), "/api/carriers"))
	for _, want := range []string{`"addresses":[]`, `"resolved_at":null`, `"expires_at":null`, `"cache_age_seconds":null`} {
		if !strings.Contains(body, want) {
			t.Errorf("body %s missing %s", body, want)
		}
	}
}

// Paging parameters reach the closure, are clamped, and bad values are 400.
func TestStatePagingParams(t *testing.T) {
	type call struct {
		user          string
		limit, offset int
	}
	var gotReg, gotBan call
	d := emptyDeps()
	d.Registrations = func(user string, limit, offset int) ([]Registration, int) {
		gotReg = call{user, limit, offset}
		return nil, 0
	}
	d.Bans = func(limit, offset int) ([]Ban, int, int64) {
		gotBan = call{"", limit, offset}
		return nil, 0, 0
	}
	s := newTestServer(t, d)
	h := s.handler()

	tests := []struct {
		path   string
		code   int
		reg    call // expected when path is registrations and code 200
		ban    call
		isBans bool
	}{
		{path: "/api/registrations", code: 200, reg: call{"", 100, 0}},
		{path: "/api/registrations?user=Ali&limit=10&offset=20", code: 200, reg: call{"Ali", 10, 20}},
		{path: "/api/registrations?limit=99999", code: 200, reg: call{"", 1000, 0}},
		{path: "/api/registrations?limit=0", code: 400},
		{path: "/api/registrations?limit=-1", code: 400},
		{path: "/api/registrations?limit=abc", code: 400},
		{path: "/api/registrations?offset=-5", code: 400},
		{path: "/api/registrations?offset=x", code: 400},
		{path: "/api/registrations?user=" + strings.Repeat("a", 257), code: 400},
		{path: "/api/shield/bans", code: 200, isBans: true, ban: call{"", 100, 0}},
		{path: "/api/shield/bans?limit=25&offset=50", code: 200, isBans: true, ban: call{"", 25, 50}},
		{path: "/api/shield/bans?limit=5000", code: 200, isBans: true, ban: call{"", 1000, 0}},
		{path: "/api/shield/bans?limit=-3", code: 400, isBans: true},
		{path: "/api/shield/bans?offset=-1", code: 400, isBans: true},
	}
	for _, tc := range tests {
		gotReg, gotBan = call{}, call{}
		rr := httptest.NewRecorder()
		req := newReq("GET", tc.path, nil)
		req.SetBasicAuth("admin", "secret")
		h.ServeHTTP(rr, req)
		if rr.Code != tc.code {
			t.Errorf("GET %s = %d, want %d", tc.path, rr.Code, tc.code)
			continue
		}
		if tc.code != 200 {
			if gotReg != (call{}) || gotBan != (call{}) {
				t.Errorf("GET %s: closure called despite 400", tc.path)
			}
			continue
		}
		if tc.isBans && gotBan != tc.ban {
			t.Errorf("GET %s: Bans called with %+v, want %+v", tc.path, gotBan, tc.ban)
		}
		if !tc.isBans && gotReg != tc.reg {
			t.Errorf("GET %s: Registrations called with %+v, want %+v", tc.path, gotReg, tc.reg)
		}
	}
}

// Only GET is allowed, and a nil closure answers 404.
func TestStateMethodAndNilClosure(t *testing.T) {
	withData := newTestServer(t, stateDeps()).handler()
	bare := newTestServer(t, emptyDeps()).handler()
	for _, p := range statePaths {
		rr := httptest.NewRecorder()
		req := newReq("POST", p, nil)
		req.SetBasicAuth("admin", "secret")
		withData.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != "GET" {
			t.Errorf("POST %s = %d Allow=%q, want 405 GET", p, rr.Code, rr.Header().Get("Allow"))
		}
		rr = httptest.NewRecorder()
		req = newReq("GET", p, nil)
		req.SetBasicAuth("admin", "secret")
		bare.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("GET %s with a nil closure = %d, want 404", p, rr.Code)
		}
	}
}

// The State tab is wired and builds its rows with textContent only.
func TestUIStateTab(t *testing.T) {
	s := testServer(t)
	page := uiGet(t, s, "/", true).Body.String()
	for _, want := range []string{`data-view="state"`, `id="view-state"`, `id="reg-user"`, `id="reg-body"`, `id="reg-empty"`,
		`id="creg-empty"`, `id="bans-empty"`, `id="bans-rejected"`, `id="nodes-empty"`, `id="carriers-empty"`, `id="reg-next"`, `id="bans-next"`} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	js := uiGet(t, s, "/assets/app.js", true).Body.String()
	for _, want := range []string{`"/api/registrations"`, `"/api/carrier-registrations"`, `"/api/shield/bans"`,
		`"/api/switch-nodes"`, `"/api/carriers"`, "function loadState", "function renderCarriers"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	i, j := strings.Index(js, "// ---- state tables"), strings.Index(js, "// ---- start ----")
	if i < 0 || j < i || strings.Contains(js[i:j], "innerHTML") {
		t.Error("state tables must build rows with textContent, not innerHTML")
	}
}
