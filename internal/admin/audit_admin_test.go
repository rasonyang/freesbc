package admin

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// Audit tests (docs/audit/REPORT.md). A failing test here is the
// deliverable: it demonstrates a defect. Do not make it pass by editing the
// test; fix the production code instead.

// audit: P2-ADM-001 (also P2-CFG-003)
// design.md §14.2 names ${ENV} references as the protection for secrets in
// the config file. PUT /api/config returns validation errors computed after
// expansion, so any process environment variable can be read back.
func TestAuditConfigPutDoesNotEchoEnv(t *testing.T) {
	const sentinel = "audit-sentinel-env-value"
	t.Setenv("AUDIT_SECRET", sentinel)
	s, _ := newTestServerWithFile(t, validCfg)
	body := strings.Replace(validCfg, "public_ip: 127.0.0.1", `public_ip: "${AUDIT_SECRET}"`, 1)
	rr := authPUT(t, s, "/api/config", body, "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT status %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), sentinel) {
		t.Errorf("400 body reveals the environment variable's value:\n%s", rr.Body.String())
	}
}

// audit: P2-ADM-002
// design.md §13.4: 10 auth failures per minute per IP. over() and
// recordFail() are separate critical sections around bcrypt, so concurrent
// requests from one IP all pass the check.
func TestAuditAuthLimiterHoldsUnderConcurrency(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	acfg := &config.AdminConfig{Listen: "127.0.0.1:0"}
	acfg.Auth.Username = "admin"
	acfg.Auth.PasswordHash = string(hash)
	s := New(acfg, config.NewStore(mustCfg(t)), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	h := s.handler()

	const n = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			req.SetBasicAuth("admin", "wrong")
			h.ServeHTTP(rr, req)
			mu.Lock()
			codes[rr.Code]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if got := codes[http.StatusUnauthorized]; got > authFailLimit {
		t.Errorf("%d concurrent wrong-password requests were checked by bcrypt (401), limit is %d per window; codes=%v",
			got, authFailLimit, codes)
	}
}

// audit: P2-ADM-003
// Once authFailMaxIPs distinct IPs have failed, the whole table is cleared,
// which resets an attacker's own exhausted budget.
func TestAuditAuthLimiterCapDoesNotResetAttacker(t *testing.T) {
	var l authLimiter
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < authFailLimit; i++ {
		l.recordFail("198.51.100.1", now)
	}
	if !l.over("198.51.100.1", now) {
		t.Fatal("attacker not over budget after authFailLimit failures")
	}
	// Distinct IPv6 /128s from one /64; each starts a new window.
	for i := 0; i < authFailMaxIPs; i++ {
		l.recordFail(fmt.Sprintf("2001:db8::%x", i+1), now.Add(time.Second))
	}
	if !l.over("198.51.100.1", now.Add(2*time.Second)) {
		t.Errorf("%d fresh source IPs reset the attacker's exhausted budget", authFailMaxIPs)
	}
}

// audit: P2-ADM-004
// Concurrent PUTs carrying the same (valid) If-Match must not both succeed:
// the second one overwrites a change it never saw.
func TestAuditConfigPutIfMatchIsAtomic(t *testing.T) {
	s, path := newTestServerWithFile(t, validCfg)
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	etag := etagOf(cur)
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		body := validCfg + fmt.Sprintf("# writer %d\n", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rr := authPUT(t, s, "/api/config", body, etag)
			if rr.Code == http.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok > 1 {
		t.Errorf("%d PUTs with the same If-Match all succeeded; only the first may (lost update)", ok)
	}
}

// audit: P2-ADM-005
// A config path that is a symlink must stay a symlink and its target must
// receive the new content.
func TestAuditConfigPutFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	link := filepath.Join(dir, "sbc.yaml")
	if err := os.WriteFile(target, []byte(validCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	cfg, err := config.Parse([]byte(validCfg))
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	acfg := &config.AdminConfig{Listen: "127.0.0.1:0"}
	acfg.Auth.Username = "admin"
	acfg.Auth.PasswordHash = string(hash)
	s := New(acfg, config.NewStore(cfg), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), link)

	body := validCfg + "# edited\n"
	if rr := authPUT(t, s, "/api/config", body, ""); rr.Code != http.StatusOK {
		t.Fatalf("PUT status %d: %s", rr.Code, rr.Body.String())
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("config symlink %s was replaced by a regular file", link)
	}
	if got, _ := os.ReadFile(target); string(got) != body {
		t.Errorf("symlink target not updated")
	}
}
