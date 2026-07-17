package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUIServedBehindAuth(t *testing.T) {
	s := testServer(t)
	// no creds → 401
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET / no creds: %d want 401", rr.Code)
	}
	// with creds → 200 HTML
	rr = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET / with creds: %d want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "FreeSBC") {
		t.Error("UI body missing FreeSBC marker")
	}
	// the SPA must actually wire the API endpoints it depends on
	for _, ep := range []string{"/api/status", "/api/config/raw", "/api/config"} {
		if !strings.Contains(body, ep) {
			t.Errorf("UI does not reference %q — is the SPA wired?", ep)
		}
	}
}

func TestUIDoesNotShadowAPI(t *testing.T) {
	s := testServer(t)
	// /api/status must still hit the JSON handler, not the UI catch-all.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("/api/status Content-Type = %q, want application/json (UI shadowed it?)", ct)
	}
	// /healthz still open (no auth)
	rr = httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz: %d want 200", rr.Code)
	}
}
