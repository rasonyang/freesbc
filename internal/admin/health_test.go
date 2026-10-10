package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHealth is a controllable condition source with a settable clock.
type fakeHealth struct {
	mu    sync.Mutex
	conds []HealthCondition
	t     time.Time
}

func newFakeHealth() *fakeHealth { return &fakeHealth{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }

func (f *fakeHealth) set(c ...HealthCondition) {
	f.mu.Lock()
	f.conds = c
	f.mu.Unlock()
}

func (f *fakeHealth) get() []HealthCondition {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]HealthCondition(nil), f.conds...)
}

func (f *fakeHealth) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeHealth) advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func healthServer(t *testing.T) (*Server, *fakeHealth) {
	t.Helper()
	f := newFakeHealth()
	deps := emptyDeps()
	deps.Health = f.get
	s := newTestServer(t, deps)
	s.health.now = f.now
	return s, f
}

func cond(id string, sev HealthSeverity) HealthCondition {
	return HealthCondition{ID: id, Severity: sev, Message: "msg " + id}
}

type healthBody struct {
	Status     string            `json:"status"`
	Conditions []ActiveCondition `json:"conditions"`
}

func getHealth(t *testing.T, s *Server) healthBody {
	t.Helper()
	var b healthBody
	if err := json.Unmarshal(authGET(t, s, "/api/health"), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func getHistory(t *testing.T, s *Server) []HealthEvent {
	t.Helper()
	var b struct {
		Events []HealthEvent `json:"events"`
	}
	if err := json.Unmarshal(authGET(t, s, "/api/health/history"), &b); err != nil {
		t.Fatal(err)
	}
	return b.Events
}

func TestHealthRequiresAuth(t *testing.T) {
	s, _ := healthServer(t)
	for _, path := range []string{"/api/health", "/api/health/history"} {
		rr := httptest.NewRecorder()
		s.handler().ServeHTTP(rr, newReq("GET", path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without credentials = %d, want 401", path, rr.Code)
		}
		req := newReq("GET", path, nil)
		req.SetBasicAuth("admin", "wrong")
		rr = httptest.NewRecorder()
		s.handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with bad credentials = %d, want 401", path, rr.Code)
		}
		req = newReq("POST", path, nil)
		req.SetBasicAuth("admin", "secret")
		rr = httptest.NewRecorder()
		s.handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, rr.Code)
		}
	}
}

// Empty lists encode as [] and a server with no Deps.Health reports ok.
func TestHealthEmptyListsAreArrays(t *testing.T) {
	for name, s := range map[string]*Server{"nil closure": testServer(t), "none active": func() *Server { s, _ := healthServer(t); return s }()} {
		h := string(authGET(t, s, "/api/health"))
		if !strings.Contains(h, `"conditions":[]`) || !strings.Contains(h, `"status":"ok"`) {
			t.Errorf("%s: /api/health = %s, want status ok and conditions []", name, h)
		}
		if ev := strings.TrimSpace(string(authGET(t, s, "/api/health/history"))); ev != `{"events":[]}` {
			t.Errorf("%s: /api/health/history = %s, want {\"events\":[]}", name, ev)
		}
	}
}

// The overall status is the worst active severity; conditions sort by
// severity descending, then id.
func TestHealthStatusIsWorstSeverity(t *testing.T) {
	s, f := healthServer(t)
	if got := getHealth(t, s).Status; got != "ok" {
		t.Fatalf("status with none active = %q, want ok", got)
	}
	f.set(cond("b", HealthDegraded), cond("a", HealthDegraded))
	b := getHealth(t, s)
	if b.Status != "degraded" {
		t.Errorf("status = %q, want degraded", b.Status)
	}
	f.set(cond("b", HealthDegraded), cond("z", HealthCritical), cond("a", HealthDegraded))
	b = getHealth(t, s)
	if b.Status != "critical" {
		t.Errorf("status = %q, want critical", b.Status)
	}
	var ids []string
	for _, c := range b.Conditions {
		ids = append(ids, c.ID)
	}
	if got := strings.Join(ids, ","); got != "z,a,b" {
		t.Errorf("order = %s, want z,a,b (critical first, then by id)", got)
	}
	f.set()
	if got := getHealth(t, s).Status; got != "ok" {
		t.Errorf("status after clearing = %q, want ok", got)
	}
}

// Raise, change and clear are recorded newest first with the right
// timestamps; since survives a severity change.
func TestHealthHistoryRaiseChangeClear(t *testing.T) {
	s, f := healthServer(t)
	t0 := f.now()
	f.set(cond("x", HealthDegraded))
	if c := getHealth(t, s).Conditions; len(c) != 1 || !c[0].Since.Equal(t0) {
		t.Fatalf("conditions = %+v, want x since %v", c, t0)
	}
	f.advance(10 * time.Second)
	f.set(cond("x", HealthCritical))
	c := getHealth(t, s).Conditions
	if len(c) != 1 || c[0].Severity != HealthCritical || !c[0].Since.Equal(t0) {
		t.Fatalf("after change = %+v, want critical with since kept at %v", c, t0)
	}
	f.advance(10 * time.Second)
	f.set()
	getHealth(t, s)

	ev := getHistory(t, s)
	if len(ev) != 3 {
		t.Fatalf("history = %+v, want 3 events", ev)
	}
	for i, want := range []struct {
		e   HealthEventType
		sev HealthSeverity
	}{{HealthCleared, HealthCritical}, {HealthChanged, HealthCritical}, {HealthRaised, HealthDegraded}} {
		if ev[i].Event != want.e || ev[i].Severity != want.sev || ev[i].ID != "x" {
			t.Errorf("event %d = %+v, want %s %s", i, ev[i], want.e, want.sev)
		}
	}
	if !ev[2].Time.Equal(t0) || !ev[0].Time.Equal(t0.Add(20*time.Second)) {
		t.Errorf("event times = %v .. %v", ev[2].Time, ev[0].Time)
	}
	// A message that moves with the same id and severity is no transition.
	f.set(HealthCondition{ID: "y", Severity: HealthDegraded, Message: "1"})
	getHealth(t, s)
	f.set(HealthCondition{ID: "y", Severity: HealthDegraded, Message: "2"})
	if c := getHealth(t, s).Conditions; c[0].Message != "2" {
		t.Errorf("message = %q, want the latest", c[0].Message)
	}
	if n := len(getHistory(t, s)); n != 4 {
		t.Errorf("history has %d events, want 4 (only y raised)", n)
	}
}

// The ring is capped at healthRingSize, dropping the oldest first.
func TestHealthHistoryCapped(t *testing.T) {
	s, f := healthServer(t)
	for i := 0; i < healthRingSize+50; i++ {
		f.set(cond(fmt.Sprintf("c%03d", i), HealthDegraded))
		s.health.evaluate() // raises c(i), clears c(i-1)
	}
	ev := s.health.history()
	if len(ev) != healthRingSize {
		t.Fatalf("history holds %d, want %d", len(ev), healthRingSize)
	}
	// The last evaluation raised c249 and, after it, cleared c248.
	if ev[0].ID != fmt.Sprintf("c%03d", healthRingSize+48) || ev[0].Event != HealthCleared ||
		ev[1].ID != fmt.Sprintf("c%03d", healthRingSize+49) || ev[1].Event != HealthRaised {
		t.Errorf("newest = %+v, %+v", ev[0], ev[1])
	}
}

// Concurrent evaluation and reads are race-free (go test -race) and leave
// the tracker consistent.
func TestHealthConcurrentEvaluate(t *testing.T) {
	s, f := healthServer(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if (i+g)%2 == 0 {
					f.set(cond("a", HealthDegraded), cond(fmt.Sprintf("n%d", i%5), HealthCritical))
				} else {
					f.set()
				}
				s.health.evaluate()
				_ = s.health.history()
			}
		}(g)
	}
	wg.Wait()
	f.set()
	if c := s.health.evaluate(); len(c) != 0 {
		t.Errorf("conditions after clearing = %+v, want none", c)
	}
	if n := len(s.health.history()); n != healthRingSize {
		t.Errorf("history holds %d, want the full ring of %d", n, healthRingSize)
	}
}

// The ticker evaluates with nobody polling and stops when its context ends.
func TestHealthTickerRecordsAndStops(t *testing.T) {
	f := newFakeHealth()
	f.set(cond("x", HealthDegraded))
	tr := &healthTracker{src: f.get, now: f.now}
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.run(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(tr.history()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the ticker never evaluated")
		}
		time.Sleep(time.Millisecond)
	}
	f.set()
	for len(tr.history()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the ticker never recorded the clear")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
	// The goroutine that closed done may not have exited yet: poll.
	deadline = time.Now().Add(5 * time.Second)
	for after := runtime.NumGoroutine(); after > before; after = runtime.NumGoroutine() {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines %d -> %d after stop", before, after)
		}
		time.Sleep(time.Millisecond)
	}
}

// Run starts the ticker and does not return before it stops.
func TestServerRunStopsHealthTicker(t *testing.T) {
	s, f := healthServer(t)
	f.set(cond("x", HealthDegraded))
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(s.health.history()) == 0 { // the first evaluation runs at start
		if time.Now().After(deadline) {
			t.Fatal("Run never evaluated health")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestMetricsHealthStatus(t *testing.T) {
	s, f := healthServer(t)
	for _, tc := range []struct {
		conds []HealthCondition
		want  string
	}{
		{nil, "freesbc_admin_health_status 0"},
		{[]HealthCondition{cond("a", HealthDegraded)}, "freesbc_admin_health_status 1"},
		{[]HealthCondition{cond("a", HealthDegraded), cond("b", HealthCritical)}, "freesbc_admin_health_status 2"},
	} {
		f.set(tc.conds...)
		if body := string(authGET(t, s, "/metrics")); !strings.Contains(body, tc.want) {
			t.Errorf("/metrics missing %q", tc.want)
		}
	}
}

func TestHealthDuplicateIDKeepsWorst(t *testing.T) {
	s, f := healthServer(t)
	f.set(cond("a", HealthCritical), cond("a", HealthDegraded), HealthCondition{ID: "b", Severity: "bogus"})
	b := getHealth(t, s)
	if len(b.Conditions) != 2 || b.Conditions[0].Severity != HealthCritical || b.Conditions[1].Severity != HealthDegraded {
		t.Errorf("conditions = %+v", b.Conditions)
	}
}
