package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// auditReq sends one request to /api/status with the given Basic
// credentials (none when pass is nil) from remote.
func auditReq(s *Server, remote string, user string, pass *string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := newReq("GET", "/api/status", nil)
	req.RemoteAddr = remote
	if pass != nil {
		req.SetBasicAuth(user, *pass)
	}
	s.handler().ServeHTTP(rr, req)
	return rr
}

func sp(s string) *string { return &s }

func TestAuditEventTypes(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		user   string
		pass   *string
		prep   func(*Server) // run before the request under test
		code   int
		want   *AuditEvent // nil: no event expected
	}{
		{"login ok", "198.51.100.9:4000", "admin", sp("secret"), nil, 200,
			&AuditEvent{Type: AuditLoginOK, Source: "198.51.100.9", Result: AuditResultOK}},
		{"bad password", "198.51.100.10:4000", "admin", sp("nope"), nil, 401,
			&AuditEvent{Type: AuditLoginFailed, Source: "198.51.100.10", Result: AuditResultBadCredentials}},
		{"bad user", "198.51.100.11:4000", "root", sp("secret"), nil, 401,
			&AuditEvent{Type: AuditLoginFailed, Source: "198.51.100.11", Result: AuditResultBadCredentials}},
		{"no header is not an event", "198.51.100.12:4000", "", nil, nil, 401, nil},
		{"limited", "198.51.100.13:4000", "admin", sp("nope"), func(s *Server) {
			for i := 0; i < authFailLimit; i++ {
				auditReq(s, "198.51.100.13:4000", "admin", sp("nope"))
			}
		}, 429, &AuditEvent{Type: AuditLoginLimited, Source: "198.51.100.13", Result: AuditResultRateLimited}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			if c.prep != nil {
				c.prep(s)
			}
			before := len(s.audit.snapshot())
			start := time.Now().Add(-time.Second)
			if rr := auditReq(s, c.remote, c.user, c.pass); rr.Code != c.code {
				t.Fatalf("code %d want %d", rr.Code, c.code)
			}
			evs := s.audit.snapshot()
			if c.want == nil {
				if len(evs) != before {
					t.Fatalf("unexpected event: %+v", evs[0])
				}
				return
			}
			if len(evs) != before+1 {
				t.Fatalf("events %d want %d", len(evs), before+1)
			}
			got := evs[0] // newest first
			if got.Type != c.want.Type || got.Source != c.want.Source || got.Result != c.want.Result {
				t.Errorf("got %+v want %+v", got, *c.want)
			}
			if got.Time.Before(start) || got.Time.After(time.Now().Add(time.Second)) {
				t.Errorf("time %v out of range", got.Time)
			}
		})
	}
}

func TestAuditCachedCredentialLogsNothing(t *testing.T) {
	s := testServer(t)
	for i := 0; i < 3; i++ {
		if rr := auditReq(s, "198.51.100.9:4000", "admin", sp("secret")); rr.Code != 200 {
			t.Fatalf("code %d", rr.Code)
		}
	}
	evs := s.audit.snapshot()
	if len(evs) != 1 || evs[0].Type != AuditLoginOK {
		t.Fatalf("want exactly one login_ok, got %+v", evs)
	}
	// Same credential from another source is still a cache hit.
	auditReq(s, "198.51.100.77:1", "admin", sp("secret"))
	if n := len(s.audit.snapshot()); n != 1 {
		t.Fatalf("cached credential from another source logged: %d events", n)
	}
}

func TestAuditNeverRecordsSecrets(t *testing.T) {
	var logs bytes.Buffer
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cr3t-pw-value"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: string(hash)}
	s := New(cfg, nil, config.NewStore(mustCfg(t)), emptyDeps(),
		slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), "")

	const badPass = "wrong-pw-value"
	var authz []string
	for _, c := range []struct{ u, p string }{{"admin", "s3cr3t-pw-value"}, {"admin", badPass}, {"mallory", badPass}} {
		req := newReq("GET", "/api/status", nil)
		req.RemoteAddr = "198.51.100.9:1"
		req.SetBasicAuth(c.u, c.p)
		authz = append(authz, req.Header.Get("Authorization"))
		s.handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	for i := 0; i < authFailLimit; i++ {
		auditReq(s, "198.51.100.9:1", "admin", sp(badPass))
	}
	ring, _ := json.Marshal(s.audit.snapshot())
	rr := httptest.NewRecorder()
	req := newReq("GET", "/api/audit", nil)
	req.SetBasicAuth("admin", "s3cr3t-pw-value")
	s.handler().ServeHTTP(rr, req)

	hay := string(ring) + logs.String() + rr.Body.String()
	needles := []string{"s3cr3t-pw-value", badPass, "mallory", string(hash), hash2(string(hash))}
	for _, a := range authz {
		needles = append(needles, a, strings.TrimPrefix(a, "Basic "))
	}
	for _, n := range needles {
		if n != "" && strings.Contains(hay, n) {
			t.Errorf("secret %q leaked into ring/log/response", n)
		}
	}
	if !strings.Contains(logs.String(), "admin audit") {
		t.Error("no `admin audit` log line")
	}
}

// hash2 is the hash body without the cost prefix, in case a leak is partial.
func hash2(h string) string {
	if len(h) > 7 {
		return h[7:]
	}
	return ""
}

func TestAuditLogLineFields(t *testing.T) {
	var logs bytes.Buffer
	a := &auditLog{log: slog.New(slog.NewJSONHandler(&logs, nil))}
	a.record(AuditLoginFailed, "203.0.113.5", AuditResultBadCredentials)
	var m map[string]any
	if err := json.Unmarshal(logs.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["msg"] != "admin audit" || m["type"] != "login_failed" || m["source"] != "203.0.113.5" ||
		m["result"] != "bad_credentials" || m["at"] == nil {
		t.Errorf("fields: %v", m)
	}
}

func TestAuditRingCapacity(t *testing.T) {
	var a auditLog
	total := auditRingSize + 44
	for i := 0; i < total; i++ {
		a.count(AuditResultBadCredentials)
		a.record(AuditLoginFailed, fmt.Sprintf("10.0.%d.%d", i/256, i%256), AuditResultBadCredentials)
	}
	evs := a.snapshot()
	if len(evs) != auditRingSize {
		t.Fatalf("len %d want %d", len(evs), auditRingSize)
	}
	newest := fmt.Sprintf("10.0.%d.%d", (total-1)/256, (total-1)%256)
	oldestIdx := total - auditRingSize
	oldest := fmt.Sprintf("10.0.%d.%d", oldestIdx/256, oldestIdx%256)
	if evs[0].Source != newest || evs[len(evs)-1].Source != oldest {
		t.Errorf("order: first %s last %s, want %s .. %s", evs[0].Source, evs[len(evs)-1].Source, newest, oldest)
	}
	if got := a.failures()[AuditResultBadCredentials]; got != uint64(total) {
		t.Errorf("counter %d want %d (counts are not bounded by the ring)", got, total)
	}
}

func TestAuditConcurrent(t *testing.T) {
	var a auditLog
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				a.count(AuditResultRateLimited)
				a.record(AuditLoginLimited, "192.0.2.1", AuditResultRateLimited)
			}
		}()
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if n := len(a.snapshot()); n > auditRingSize {
					t.Errorf("snapshot len %d", n)
				}
				_ = a.failures()
			}
		}()
	}
	wg.Wait()
	if n := len(a.snapshot()); n != auditRingSize {
		t.Errorf("len %d want %d", n, auditRingSize)
	}
	if got := a.failures()[AuditResultRateLimited]; got != 1600 {
		t.Errorf("counter %d want 1600", got)
	}
}

func TestAPIAuditAuthAndShape(t *testing.T) {
	s := testServer(t)
	if rr := auditReq2(s, "/api/audit", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no creds: %d want 401", rr.Code)
	}
	// A 401 for a missing header is not an event, so the ring is still empty
	// when handled directly.
	rr := httptest.NewRecorder()
	s.handleAudit(rr, newReq("GET", "/api/audit", nil))
	if got := strings.TrimSpace(rr.Body.String()); got != "[]" {
		t.Fatalf("empty ring body %q want []", got)
	}
	rr = httptest.NewRecorder()
	s.handleAudit(rr, newReq("POST", "/api/audit", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d want 405", rr.Code)
	}

	body := authGET(t, s, "/api/audit")
	var evs []map[string]any
	if err := json.Unmarshal(body, &evs); err != nil {
		t.Fatalf("not a JSON array: %v: %s", err, body)
	}
	if len(evs) != 1 || evs[0]["type"] != "login_ok" || evs[0]["result"] != "ok" ||
		evs[0]["source"] == "" || evs[0]["time"] == "" {
		t.Errorf("events: %v", evs)
	}
}

func auditReq2(s *Server, path string, pass *string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := newReq("GET", path, nil)
	if pass != nil {
		req.SetBasicAuth("admin", *pass)
	}
	s.handler().ServeHTTP(rr, req)
	return rr
}

func TestAuthFailuresMetric(t *testing.T) {
	s := testServer(t)
	body := string(authGET(t, s, "/metrics"))
	for _, want := range []string{
		`freesbc_admin_auth_failures_total{reason="bad_credentials"} 0`,
		`freesbc_admin_auth_failures_total{reason="rate_limited"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	for i := 0; i < authFailLimit+2; i++ {
		auditReq(s, "198.51.100.30:1", "admin", sp("nope"))
	}
	body = string(authGET(t, s, "/metrics"))
	for _, want := range []string{
		`freesbc_admin_auth_failures_total{reason="bad_credentials"} 10`,
		`freesbc_admin_auth_failures_total{reason="rate_limited"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q in:\n%s", want, body)
		}
	}
}

func TestAuditLimitedOncePerWindow(t *testing.T) {
	s := testServer(t)
	clock := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return clock }
	const src = "198.51.100.40:1"
	for i := 0; i < authFailLimit; i++ {
		auditReq(s, src, "admin", sp("nope"))
	}
	const denials = 300 // more than the ring holds
	for i := 0; i < denials; i++ {
		if rr := auditReq(s, src, "admin", sp("nope")); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("code %d want 429", rr.Code)
		}
	}
	count := func(t AuditType) (n int) {
		for _, e := range s.audit.snapshot() {
			if e.Type == t {
				n++
			}
		}
		return
	}
	if n := count(AuditLoginLimited); n != 1 {
		t.Fatalf("login_limited events %d want 1", n)
	}
	if n := count(AuditLoginFailed); n != authFailLimit {
		t.Fatalf("login_failed events %d want %d (must not be flushed)", n, authFailLimit)
	}
	if got := s.audit.failures()[AuditResultRateLimited]; got != denials {
		t.Fatalf("rate_limited count %d want %d", got, denials)
	}
	// Another source locked out in the same window is its own event.
	for i := 0; i < authFailLimit+2; i++ {
		auditReq(s, "198.51.100.41:1", "admin", sp("nope"))
	}
	if n := count(AuditLoginLimited); n != 2 {
		t.Fatalf("second source: login_limited events %d want 2", n)
	}
	// The window rolls over; locking out again records a new event.
	clock = clock.Add(authFailWindow + time.Second)
	for i := 0; i < authFailLimit+3; i++ {
		auditReq(s, src, "admin", sp("nope"))
	}
	if n := count(AuditLoginLimited); n != 3 {
		t.Fatalf("after rollover: login_limited events %d want 3", n)
	}
	if got := s.audit.failures()[AuditResultRateLimited]; got != denials+2+3 {
		t.Fatalf("rate_limited count %d want %d", got, denials+5)
	}
}
