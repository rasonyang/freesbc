package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// testListen is the admin.listen every test server uses; newReq addresses it.
const testListen = "127.0.0.1:0"

// newReq builds a request as the UI would send it: Host is the test
// server's listen address, and a state-changing method carries the matching
// Origin. Guard tests that probe the checks build their requests explicitly.
func newReq(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Host = testListen
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		r.Header.Set("Origin", "http://"+testListen)
	}
	return r
}

func guardServer(t *testing.T, listen string, allowed []string) *Server {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: listen, PasswordHash: string(hash), AllowedHosts: allowed}
	path := filepath.Join(t.TempDir(), "freesbc.yaml")
	if err := os.WriteFile(path, []byte(minimalConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(cfg, nil, config.NewStore(mustCfg(t)), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), path)
}

func hostStatus(s *Server, host, path string, auth bool) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	if auth {
		req.SetBasicAuth("admin", "secret")
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	return rr.Code
}

func TestHostCheck(t *testing.T) {
	loop := guardServer(t, "127.0.0.1:8080", []string{"Admin.Example.net"})
	for _, tc := range []struct {
		host string
		want int
	}{
		{"127.0.0.1:8080", 200},
		{"localhost:8080", 200},
		{"LocalHost.:8080", 200},
		{"[::1]:8080", 200},
		{"admin.example.net:8080", 200},
		{"ADMIN.EXAMPLE.NET.:8080", 200},
		{"127.0.0.1:9999", 421},
		{"127.0.0.1", 421}, // bare host only on the scheme default port
		{"evil.example.com:8080", 421},
		{"evil.example.com", 421},
		{"10.0.0.5:8080", 421}, // an IP literal is not accepted on a non-wildcard listen
		{"", 421},
	} {
		if got := hostStatus(loop, tc.host, "/api/status", true); got != tc.want {
			t.Errorf("Host %q: got %d want %d", tc.host, got, tc.want)
		}
	}

	// A non-loopback listen accepts its own IP, not the loopback names.
	remote := guardServer(t, "192.0.2.10:8443", nil)
	if got := hostStatus(remote, "192.0.2.10:8443", "/api/status", true); got != 200 {
		t.Errorf("listen IP: got %d", got)
	}
	if got := hostStatus(remote, "localhost:8443", "/api/status", true); got != 421 {
		t.Errorf("loopback name on a remote listen: got %d", got)
	}

	// IPv6 literal listen, canonicalised.
	v6 := guardServer(t, "[2001:db8::1]:8443", nil)
	if got := hostStatus(v6, "[2001:0db8:0:0:0:0:0:1]:8443", "/api/status", true); got != 200 {
		t.Errorf("IPv6 literal: got %d", got)
	}
}

func TestHostCheckWildcardListen(t *testing.T) {
	s := guardServer(t, "0.0.0.0:8443", []string{"sbc.example.net"})
	for host, want := range map[string]int{
		"192.0.2.77:8443":       200, // any IP literal: it cannot be DNS-rebound
		"[2001:db8::9]:8443":    200,
		"sbc.example.net:8443":  200,
		"evil.example.com:8443": 421,
		"192.0.2.77:1":          421,
	} {
		if got := hostStatus(s, host, "/api/status", true); got != want {
			t.Errorf("Host %q: got %d want %d", host, got, want)
		}
	}
}

func TestHostCheckDefaultPort(t *testing.T) {
	// Plain HTTP on 80: a browser omits the port.
	s := guardServer(t, "127.0.0.1:80", nil)
	if got := hostStatus(s, "localhost", "/api/status", true); got != 200 {
		t.Errorf("bare host on port 80: got %d", got)
	}
	// TLS on 443: same. TLS needs allow_remote plus a tls identity.
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "192.0.2.10:443", AllowRemote: true, PasswordHash: string(hash)}
	ts := New(cfg, &config.TLSConfig{Cert: "c", Key: "k"}, config.NewStore(mustCfg(t)), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	if got := hostStatus(ts, "192.0.2.10", "/api/status", true); got != 200 {
		t.Errorf("bare host on 443/TLS: got %d", got)
	}
	// Port 80 is not the TLS default.
	if got := hostStatus(s, "localhost", "/api/status", true); got != 200 {
		t.Errorf("sanity: %d", got)
	}
	s8 := guardServer(t, "127.0.0.1:8080", nil)
	if got := hostStatus(s8, "localhost", "/api/status", true); got != 421 {
		t.Errorf("bare host on a non-default port: got %d", got)
	}
}

// A foreign Host is refused before any auth work: bad credentials from it
// neither run bcrypt nor take a limiter slot, on every route but /healthz.
func TestHostCheckBeforeAuth(t *testing.T) {
	s := guardServer(t, "127.0.0.1:8080", nil)
	h := s.handler()
	for i := 0; i < authFailLimit+5; i++ {
		for _, path := range []string{"/", "/assets/app.js", "/metrics", "/api/status", "/api/calls", "/api/config", "/api/config/raw"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Host = "evil.example.com"
			req.RemoteAddr = "198.51.100.9:1234"
			req.SetBasicAuth("admin", "wrong")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusMisdirectedRequest {
				t.Fatalf("%s: got %d want 421", path, rr.Code)
			}
		}
	}
	s.limiter.mu.Lock()
	n := len(s.limiter.perIP)
	s.limiter.mu.Unlock()
	if n != 0 {
		t.Fatalf("limiter tracked %d sources after foreign-Host requests; auth work ran", n)
	}
	// The same source is still not locked out for a legitimate request.
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Host = "127.0.0.1:8080"
	req.RemoteAddr = "198.51.100.9:1234"
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("legit request after foreign ones: %d", rr.Code)
	}
	// /healthz answers any Host.
	if got := hostStatus(s, "evil.example.com", "/healthz", false); got != 200 {
		t.Fatalf("/healthz foreign Host: %d", got)
	}
}

func TestOriginCheck(t *testing.T) {
	s := guardServer(t, "127.0.0.1:8080", nil)
	post := func(hdr map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader("x"))
		req.Host = "127.0.0.1:8080"
		req.SetBasicAuth("admin", "secret")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		s.handler().ServeHTTP(rr, req)
		return rr.Code
	}
	// A refusal is 403; an accepted request reaches the handler, which
	// answers anything but 403.
	ok := func(code int) bool { return code != http.StatusForbidden }
	for _, tc := range []struct {
		name string
		hdr  map[string]string
		pass bool
	}{
		{"matching origin", map[string]string{"Origin": "http://127.0.0.1:8080"}, true},
		{"matching origin, case", map[string]string{"Origin": "HTTP://127.0.0.1:8080"}, true},
		{"foreign origin", map[string]string{"Origin": "http://evil.example.com"}, false},
		{"https origin on http listener", map[string]string{"Origin": "https://127.0.0.1:8080"}, false},
		{"null origin", map[string]string{"Origin": "null"}, false},
		{"no origin, same-origin fetch metadata", map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
		{"no origin, none", nil, false},
		{"no origin, cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"no origin, same-site", map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"foreign origin beats same-origin metadata", map[string]string{"Origin": "http://evil.example.com", "Sec-Fetch-Site": "same-origin"}, false},
	} {
		if got := ok(post(tc.hdr)); got != tc.pass {
			t.Errorf("%s: passed=%v want %v", tc.name, got, tc.pass)
		}
	}
	// Safe methods need no Origin.
	if got := hostStatus(s, "127.0.0.1:8080", "/api/status", true); got != 200 {
		t.Errorf("GET without Origin: %d", got)
	}
	// A refused Origin runs before auth: no credentials, still 403 not 401.
	req := httptest.NewRequest(http.MethodPost, "/api/config/validate", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example.com")
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("foreign Origin without credentials: %d want 403", rr.Code)
	}
}

func TestOriginCheckTLSScheme(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/config/validate", nil)
	r.Host = "sbc.example.net:8443"
	r.Header.Set("Origin", "https://sbc.example.net:8443")
	if !originAllowed(r, true) || originAllowed(r, false) {
		t.Fatal("scheme must follow the listener's TLS state")
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s := guardServer(t, "127.0.0.1:8080", nil)
	h := s.handler()
	type tc struct {
		name, method, path, host, user, pass string
		want                                 int
	}
	cases := []tc{
		{"api", "GET", "/api/status", "127.0.0.1:8080", "admin", "secret", 200},
		{"raw config", "GET", "/api/config/raw", "127.0.0.1:8080", "admin", "secret", 200},
		{"metrics", "GET", "/metrics", "127.0.0.1:8080", "admin", "secret", 200},
		{"healthz", "GET", "/healthz", "127.0.0.1:8080", "", "", 200},
		{"401", "GET", "/api/status", "127.0.0.1:8080", "", "", 401},
		{"421", "GET", "/api/status", "evil.example.com", "admin", "secret", 421},
		{"403", "POST", "/api/config/validate", "127.0.0.1:8080", "admin", "secret", 403},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Host = c.host
		if c.user != "" {
			req.SetBasicAuth(c.user, c.pass)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, rr.Code, c.want)
		}
		for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
			if vals := rr.Header().Values(k); len(vals) != 1 || vals[0] != v {
				t.Errorf("%s: %s = %q want exactly %q", c.name, k, vals, v)
			}
		}
	}
	// 429: exhaust the limiter from one source.
	for i := 0; i < authFailLimit; i++ {
		r := httptest.NewRequest("GET", "/api/status", nil)
		r.Host = "127.0.0.1:8080"
		r.RemoteAddr = "198.51.100.1:1"
		r.SetBasicAuth("admin", "wrong")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Host = "127.0.0.1:8080"
	req.RemoteAddr = "198.51.100.1:1"
	req.SetBasicAuth("admin", "wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 429 || rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("429: code %d headers %v", rr.Code, rr.Header())
	}
}

// The Prometheus scrape authenticates with Basic Auth and sends neither
// Origin nor Sec-Fetch headers; it must keep working.
func TestMetricsScrapeWithBasicAuth(t *testing.T) {
	s := guardServer(t, "127.0.0.1:8080", nil)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Host = "127.0.0.1:8080"
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "go_goroutines") {
		t.Fatalf("scrape: %d", rr.Code)
	}
}
