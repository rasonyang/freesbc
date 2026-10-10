package admin

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func uiGet(t *testing.T, s *Server, path string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := newReq("GET", path, nil)
	if auth {
		req.SetBasicAuth("admin", "secret")
	}
	s.handler().ServeHTTP(rr, req)
	return rr
}

func TestUIServedBehindAuth(t *testing.T) {
	s := testServer(t)
	// no creds → 401
	if rr := uiGet(t, s, "/", false); rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET / no creds: %d want 401", rr.Code)
	}
	// with creds → 200 HTML
	rr := uiGet(t, s, "/", true)
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
	for _, a := range []string{"/assets/tokens.css", "/assets/ui.css", "/assets/theme.js", "/assets/app.js"} {
		if !strings.Contains(body, a) {
			t.Errorf("UI does not load %q", a)
		}
	}
	// the SPA must actually wire the API endpoints it depends on
	app := uiGet(t, s, "/assets/app.js", true).Body.String()
	for _, ep := range []string{"/api/status", "/api/calls", "/api/drain", "/api/config/raw", "/api/config"} {
		if !strings.Contains(app, ep) {
			t.Errorf("app.js does not reference %q — is the SPA wired?", ep)
		}
	}
}

func TestUIAssets(t *testing.T) {
	s := testServer(t)
	for path, ct := range map[string]string{
		"/assets/tokens.css": "text/css",
		"/assets/ui.css":     "text/css",
		"/assets/theme.js":   "text/javascript",
		"/assets/app.js":     "text/javascript",
	} {
		if rr := uiGet(t, s, path, false); rr.Code != http.StatusUnauthorized {
			t.Errorf("GET %s no creds: %d want 401", path, rr.Code)
		}
		rr := uiGet(t, s, path, true)
		if rr.Code != http.StatusOK {
			t.Errorf("GET %s: %d want 200", path, rr.Code)
			continue
		}
		if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, ct) {
			t.Errorf("GET %s Content-Type = %q, want %s", path, got, ct)
		}
	}
	// Unknown assets and the directory itself are 404, not the SPA and not
	// a listing: a typo in index.html must fail loudly.
	for _, path := range []string{"/assets/", "/assets/missing.css"} {
		if rr := uiGet(t, s, path, true); rr.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d want 404", path, rr.Code)
		}
	}
}

func TestUISecurityHeaders(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{"/", "/assets/app.js"} {
		h := uiGet(t, s, path, true).Header()
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q missing %q", path, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP must not relax inline/eval: %q", path, csp)
		}
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q", path, got)
		}
	}
}

// The CSP blocks inline script and style without an error the operator would
// see, so the page would silently lose behaviour or styling. Keep every
// script and style in /assets/.
func TestUIHasNoInlineScriptOrStyle(t *testing.T) {
	inlineScript := regexp.MustCompile(`(?i)<script(\s[^>]*)?>\s*[^<\s]`)
	scriptNoSrc := regexp.MustCompile(`(?i)<script\b[^>]*>`)
	err := fs.WalkDir(webuiFS, "webui", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, err := webuiFS.ReadFile(path)
		if err != nil {
			return err
		}
		html := string(b)
		if inlineScript.MatchString(html) {
			t.Errorf("%s: inline <script> body", path)
		}
		for _, tag := range scriptNoSrc.FindAllString(html, -1) {
			if !strings.Contains(tag, "src=") {
				t.Errorf("%s: <script> without src: %s", path, tag)
			}
		}
		if strings.Contains(strings.ToLower(html), "<style") {
			t.Errorf("%s: inline <style>", path)
		}
		if regexp.MustCompile(`(?i)\sstyle\s*=`).MatchString(html) {
			t.Errorf("%s: inline style attribute", path)
		}
		if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(html) {
			t.Errorf("%s: inline event handler", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Components must consume tokens, not literal colours: a hex or rgb()/oklch()
// colour outside tokens.css bypasses theming and dark mode.
func TestUIColoursComeFromTokens(t *testing.T) {
	literal := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|\b(rgb|rgba|hsl|hsla|oklch|oklab|lab|lch)\(`)
	err := fs.WalkDir(webuiFS, "webui/assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".css") || strings.HasSuffix(path, "/tokens.css") {
			return err
		}
		b, err := webuiFS.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if j := strings.Index(code, "/*"); j >= 0 {
				code = code[:j]
			}
			if literal.MatchString(code) {
				t.Errorf("%s:%d: literal colour, use a token: %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUIDoesNotShadowAPI(t *testing.T) {
	s := testServer(t)
	// /api/status must still hit the JSON handler, not the UI catch-all.
	rr := uiGet(t, s, "/api/status", true)
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("/api/status Content-Type = %q, want application/json (UI shadowed it?)", ct)
	}
	// /healthz still open (no auth)
	if rr := uiGet(t, s, "/healthz", false); rr.Code != http.StatusOK {
		t.Fatalf("/healthz: %d want 200", rr.Code)
	}
}

// The Config tab offers a download of the on-disk file, with the warning that
// it is unredacted. The script must fetch it fresh and save the response
// bytes (a Blob), not the textarea or re-encoded text.
func TestUIConfigDownload(t *testing.T) {
	read := func(name string) string {
		b, err := webuiFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	html := read("webui/index.html")
	for _, want := range []string{`id="btn-download"`, `id="download-note"`, "not redacted", "password hash"} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	js := read("webui/assets/app.js")
	for _, want := range []string{"res.blob()", "URL.createObjectURL", "URL.revokeObjectURL", ".download = downloadName(", `"freesbc-"`, "[^A-Za-z0-9.-]"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	if i := strings.Index(js, "function downloadConfig"); i < 0 || strings.Contains(js[i:], "configText.value") {
		t.Error("downloadConfig must not read the editor text")
	}
}

// The Config tab is read-only: the file is shown in a readonly textarea and
// the only write-shaped call is the side-effect-free candidate validation.
// Nothing in the UI may save, send If-Match, or PUT.
func TestUIConfigIsReadOnly(t *testing.T) {
	read := func(name string) string {
		b, err := webuiFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	html := read("webui/index.html")
	for _, want := range []string{
		`id="config-text" readonly`, `id="config-candidate"`, `id="btn-validate"`,
		`id="config-diff"`, `id="validate-errors"`, `id="validate-restart"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	for _, bad := range []string{`id="btn-save"`, "#i-save", "Not saved"} {
		if strings.Contains(html, bad) {
			t.Errorf("index.html still has save UI %q", bad)
		}
	}
	js := read("webui/assets/app.js")
	for _, want := range []string{`"/api/config/validate"`, `method: "POST"`, "function diffLines", "res.json()"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	for _, bad := range []string{`"PUT"`, "If-Match", "ETag", "btnSave", "configEtag", "innerHTML"} {
		if strings.Contains(js, bad) {
			t.Errorf("app.js still has %q", bad)
		}
	}
	// API strings reach the DOM through textContent only.
	for _, id := range []string{"validate-errors-text", "validate-restart-keys"} {
		if !strings.Contains(js, `$("`+id+`").textContent =`) {
			t.Errorf("%s must be filled via textContent", id)
		}
	}
}

// The Drain panel shows state, remaining calls and elapsed time, and never
// acts without the in-page confirmation (no window.confirm or alert).
func TestUIDrainPanel(t *testing.T) {
	read := func(name string) string {
		b, err := webuiFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	html := read("webui/index.html")
	for _, want := range []string{
		`id="drain-card"`, `id="drain-badge"`, `id="drain-detail"`, `id="btn-drain"`,
		`id="drain-confirm"`, `id="btn-drain-confirm"`, `id="btn-drain-cancel"`, `id="drain-status"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	js := read("webui/assets/app.js")
	for _, want := range []string{`"/api/drain"`, `"POST"`, `"DELETE"`, "function renderDrain", "fetchJSON(DRAIN_URL)", `$("drain-detail").textContent =`} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	for _, bad := range []string{"confirm(", "alert(", "prompt(", "innerHTML"} {
		if strings.Contains(js, bad) {
			t.Errorf("app.js uses %q", bad)
		}
	}
}

// The Audit tab is wired: nav link, view section, the API it reads, and its
// rows are built with textContent (no innerHTML).
func TestUIAuditTab(t *testing.T) {
	s := testServer(t)
	page := uiGet(t, s, "/", true).Body.String()
	for _, want := range []string{`data-view="audit"`, `id="view-audit"`, `id="audit-body"`, `id="audit-empty"`, "256"} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	js := uiGet(t, s, "/assets/app.js", true).Body.String()
	for _, want := range []string{`"/api/audit"`, `"audit"`, "function renderAudit", "function loadAudit"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	i := strings.Index(js, "function renderAudit")
	j := strings.Index(js, "function loadAudit")
	if i < 0 || j < i || strings.Contains(js[i:j], "innerHTML") {
		t.Error("renderAudit must build rows with textContent, not innerHTML")
	}
}

// The TLS card is wired: hidden until /api/tls reports a loaded leaf, filled
// with textContent, and the banner follows the server's verdicts.
func TestUITLSCard(t *testing.T) {
	read := func(name string) string {
		b, err := webuiFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	html := read("webui/index.html")
	for _, want := range []string{`id="tls-card"`, `id="tls-banner"`, `id="tls-badge"`, `id="tls-fields"`} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	js := read("webui/assets/app.js")
	for _, want := range []string{`"/api/tls"`, "function renderTLS", "fetchJSON(TLS_URL)", "t.expiring_soon", "t.expired", `card.hidden = true`} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}
