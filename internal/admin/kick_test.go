package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServerKick(t *testing.T, kill func(string) bool) *Server {
	d := emptyDeps()
	d.KillCall = kill
	return newTestServer(t, d)
}

func TestKickCallDeletes(t *testing.T) {
	var gotID string
	s := newTestServerKick(t, func(id string) bool { gotID = id; return true })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/calls/abc%40host", nil) // abc@host encoded
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE known: %d want 204", rr.Code)
	}
	if gotID != "abc@host" {
		t.Fatalf("KillCall got %q, want abc@host (PathValue decoded)", gotID)
	}
}

func TestKickCallNotFound(t *testing.T) {
	s := newTestServerKick(t, func(id string) bool { return false })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/calls/gone", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("DELETE unknown: %d want 404", rr.Code)
	}
}

func TestKickCallRequiresAuth(t *testing.T) {
	s := newTestServerKick(t, func(id string) bool { return true })
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("DELETE", "/api/calls/abc", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE no creds: %d want 401", rr.Code)
	}
}
