package admin

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// Audit tests. A failing test here is the
// deliverable: it demonstrates a defect. Do not make it pass by editing the
// test; fix the production code instead.

// audit: P2-ADM-002
// design.md §13.4: 10 auth failures per minute per IP. over() and
// recordFail() are separate critical sections around bcrypt, so concurrent
// requests from one IP all pass the check.
func TestAuditAuthLimiterHoldsUnderConcurrency(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	acfg := &config.AdminConfig{Listen: "127.0.0.1:0", PasswordHash: string(hash)}
	s := New(acfg, nil, config.NewStore(mustCfg(t)), emptyDeps(), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
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
			req := newReq(http.MethodGet, "/api/status", nil)
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
