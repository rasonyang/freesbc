package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServerUnban(t *testing.T, unban func(string) bool) *Server {
	t.Helper()
	d := emptyDeps()
	d.Unban = unban
	return newTestServer(t, d)
}

func TestUnbanDeletes(t *testing.T) {
	var gotIP string
	s := newTestServerUnban(t, func(ip string) bool { gotIP = ip; return true })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/bans/203.0.113.7", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE known ban: %d want 204", rr.Code)
	}
	if gotIP != "203.0.113.7" {
		t.Fatalf("Unban got %q, want 203.0.113.7 (PathValue decoded)", gotIP)
	}
}

func TestUnbanNotFound(t *testing.T) {
	s := newTestServerUnban(t, func(ip string) bool { return false })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/bans/198.51.100.1", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("DELETE unknown ban: %d want 404", rr.Code)
	}
}

func TestUnbanRequiresAuth(t *testing.T) {
	s := newTestServerUnban(t, func(ip string) bool { return true })
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("DELETE", "/api/bans/203.0.113.7", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE no creds: %d want 401", rr.Code)
	}
}

// TestUnbanNilDepIsNotFound proves a server built without the Unban dep
// (e.g. emptyDeps) answers 404 rather than panicking on the nil closure.
func TestUnbanNilDepIsNotFound(t *testing.T) {
	s := testServer(t) // emptyDeps leaves Unban nil
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/bans/203.0.113.7", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("DELETE with nil Unban dep: %d want 404", rr.Code)
	}
}
