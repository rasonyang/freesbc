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

// drainAuditTypes returns the drain events in the ring (newest first) with
// their sources; sign-in events are filtered out.
func drainAuditTypes(s *Server) (types []AuditType, sources []string) {
	for _, ev := range s.audit.snapshot() {
		if ev.Type == AuditDrainOn || ev.Type == AuditDrainOff {
			types = append(types, ev.Type)
			sources = append(sources, ev.Source)
			if ev.Result != AuditResultOK {
				types = append(types, "bad-result")
			}
		}
	}
	return
}

func drainDoFrom(s *Server, method, remote string) *httptest.ResponseRecorder {
	req := newReq(method, "/api/drain", nil)
	req.RemoteAddr = remote
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	return rr
}

// Only an actual change is an audit event, with the request's source IP, and
// the ring lists them newest first.
func TestDrainAuditOnlyActualChanges(t *testing.T) {
	s, _ := drainServer(t, 3)
	check := func(step string, want ...AuditType) {
		t.Helper()
		got, _ := drainAuditTypes(s)
		if len(got) != len(want) {
			t.Fatalf("%s: drain events %v, want %v", step, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: drain events %v, want %v", step, got, want)
			}
		}
	}
	check("start")
	if rr := drainDoFrom(s, "GET", "192.0.2.9:1111"); rr.Code != 200 {
		t.Fatalf("GET: %d", rr.Code)
	}
	check("GET")
	drainDoFrom(s, "POST", "192.0.2.10:2222")
	check("POST", AuditDrainOn)
	if _, src := drainAuditTypes(s); src[0] != "192.0.2.10" {
		t.Errorf("source %q, want 192.0.2.10", src[0])
	}
	drainDoFrom(s, "POST", "192.0.2.10:2222")
	check("second POST", AuditDrainOn)
	drainDoFrom(s, "DELETE", "192.0.2.11:3333")
	check("DELETE", AuditDrainOff, AuditDrainOn)
	if _, src := drainAuditTypes(s); src[0] != "192.0.2.11" {
		t.Errorf("source %q, want 192.0.2.11", src[0])
	}
	drainDoFrom(s, "DELETE", "192.0.2.11:3333")
	drainDoFrom(s, "GET", "192.0.2.11:3333")
	check("second DELETE and GET", AuditDrainOff, AuditDrainOn)
	if n := s.audit.failures()[AuditResultBadCredentials] + s.audit.failures()[AuditResultRateLimited]; n != 0 {
		t.Errorf("drain events touched the auth failure counters: %d", n)
	}
}

// A mutation refused by the Origin check, a bad method or missing deps
// records nothing.
func TestDrainAuditRefusedRequestsRecordNothing(t *testing.T) {
	s, f := drainServer(t, 0)
	req := newReq("POST", "/api/drain", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST: %d, want 403", rr.Code)
	}
	if rr2 := drainDoFrom(s, "PUT", "192.0.2.9:1"); rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: %d", rr2.Code)
	}
	if got, _ := drainAuditTypes(s); len(got) != 0 || f.calls != 0 {
		t.Errorf("refused requests recorded %v (toggle calls %d)", got, f.calls)
	}
	s2 := newTestServer(t, emptyDeps())
	if rr3 := drainDoFrom(s2, "POST", "192.0.2.9:1"); rr3.Code != http.StatusNotFound {
		t.Fatalf("nil deps POST: %d", rr3.Code)
	}
	if got, _ := drainAuditTypes(s2); len(got) != 0 {
		t.Errorf("nil deps recorded %v", got)
	}
}
