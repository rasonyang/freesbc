package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDrain is an in-memory stand-in for the edge's drain state with the
// same semantics (idempotent, keeps the original since).
type fakeDrain struct {
	mu    sync.Mutex
	on    bool
	since time.Time
	calls int // SetDraining calls that changed the state
}

func (f *fakeDrain) state() (bool, time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.on, f.since
}

func (f *fakeDrain) set(on bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.on == on {
		return false
	}
	f.on = on
	f.since = time.Time{}
	if on {
		f.since = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	}
	f.calls++
	return true
}

func drainServer(t *testing.T, calls int) (*Server, *fakeDrain) {
	t.Helper()
	f := &fakeDrain{}
	deps := emptyDeps()
	deps.ActiveCalls = func() int { return calls }
	deps.DrainState = f.state
	deps.SetDraining = f.set
	return newTestServer(t, deps), f
}

func drainDo(s *Server, method string, auth bool) *httptest.ResponseRecorder {
	req := newReq(method, "/api/drain", nil)
	if auth {
		req.SetBasicAuth("admin", "secret")
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	return rr
}

func decodeDrain(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", rr.Code, rr.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v: %s", err, rr.Body.String())
	}
	if len(m) != 3 {
		t.Errorf("body has %d keys, want draining, since, active_calls: %v", len(m), m)
	}
	return m
}

func TestDrainRequiresAuth(t *testing.T) {
	s, f := drainServer(t, 0)
	for _, m := range []string{"GET", "POST", "DELETE"} {
		if rr := drainDo(s, m, false); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s without credentials: %d, want 401", m, rr.Code)
		}
	}
	if on, _ := f.state(); on || f.calls != 0 {
		t.Error("an unauthenticated request changed the drain state")
	}
}

func TestDrainLifecycle(t *testing.T) {
	s, f := drainServer(t, 3)

	m := decodeDrain(t, drainDo(s, "GET", true))
	if m["draining"] != false || m["since"] != nil || m["active_calls"] != float64(3) {
		t.Errorf("initial GET = %v", m)
	}

	for i := 0; i < 2; i++ { // the second POST is a no-op with the same body
		m = decodeDrain(t, drainDo(s, "POST", true))
		if m["draining"] != true || m["since"] != "2026-01-02T03:04:05Z" || m["active_calls"] != float64(3) {
			t.Errorf("POST #%d = %v", i+1, m)
		}
	}
	if f.calls != 1 {
		t.Errorf("state changed %d times after two POSTs, want 1", f.calls)
	}
	if m = decodeDrain(t, drainDo(s, "GET", true)); m["draining"] != true {
		t.Errorf("GET while draining = %v", m)
	}

	for i := 0; i < 2; i++ {
		m = decodeDrain(t, drainDo(s, "DELETE", true))
		if m["draining"] != false || m["since"] != nil {
			t.Errorf("DELETE #%d = %v", i+1, m)
		}
	}
	if f.calls != 2 {
		t.Errorf("state changed %d times after POST+DELETE, want 2", f.calls)
	}
}

func TestDrainMethodNotAllowed(t *testing.T) {
	s, _ := drainServer(t, 0)
	for _, m := range []string{"PUT", "PATCH"} {
		rr := drainDo(s, m, true)
		if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != "GET, POST, DELETE" {
			t.Errorf("%s: %d Allow=%q", m, rr.Code, rr.Header().Get("Allow"))
		}
	}
}

// A mutating method needs the same-origin proof like every other one; the
// refusal comes before auth and changes nothing.
func TestDrainMutationNeedsSameOrigin(t *testing.T) {
	s, f := drainServer(t, 0)
	for _, m := range []string{"POST", "DELETE"} {
		req := newReq(m, "/api/drain", nil)
		req.Header.Set("Origin", "http://evil.example.com")
		req.SetBasicAuth("admin", "secret")
		rr := httptest.NewRecorder()
		s.handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s cross-origin: %d, want 403", m, rr.Code)
		}
		req = newReq(m, "/api/drain", nil)
		req.Header.Del("Origin")
		req.SetBasicAuth("admin", "secret")
		rr = httptest.NewRecorder()
		s.handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s without Origin: %d, want 403", m, rr.Code)
		}
	}
	if on, _ := f.state(); on || f.calls != 0 {
		t.Error("a refused request changed the drain state")
	}
}

func TestDrainUnwired(t *testing.T) {
	s := testServer(t)
	if rr := drainDo(s, "GET", true); rr.Code != http.StatusNotFound {
		t.Errorf("unwired GET: %d, want 404", rr.Code)
	}
}

func TestDrainGaugeExported(t *testing.T) {
	deps := emptyDeps()
	deps.Proxy = func() ProxyStats { return ProxyStats{Draining: true} }
	s := newTestServer(t, deps)
	req := newReq("GET", "/metrics", nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "freesbc_edge_draining 1") {
		t.Errorf("gauge missing from /metrics:\n%s", rr.Body.String())
	}
}
