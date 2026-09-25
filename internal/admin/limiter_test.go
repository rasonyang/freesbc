package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// doAuth sends GET /api/status from remote with the given Basic
// credentials (none when user is empty) and returns the status code.
func doAuth(h http.Handler, remote, user, pass string) int {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = remote
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	h.ServeHTTP(rr, req)
	return rr.Code
}

// audit: P2-ADM-003
// An operator (or the Prometheus scrape) that already authenticated keeps
// working when someone else's failures exhaust the budget of the shared
// source address (loopback, a reverse proxy). Credentials never verified
// before are still refused, so this gives a guesser nothing.
func TestAuthVerifiedCredentialsSurviveLockout(t *testing.T) {
	h := testServer(t).handler()
	const shared = "127.0.0.1:40000"
	if got := doAuth(h, shared, "admin", "secret"); got != http.StatusOK {
		t.Fatalf("first valid login: %d", got)
	}
	for i := 0; i < authFailLimit; i++ {
		doAuth(h, shared, "admin", "guess")
	}
	if got := doAuth(h, shared, "admin", "guess"); got != http.StatusTooManyRequests {
		t.Fatalf("attacker after the budget: %d, want 429", got)
	}
	if got := doAuth(h, shared, "admin", "secret"); got != http.StatusOK {
		t.Errorf("verified operator locked out: %d, want 200", got)
	}
	if got := doAuth(h, shared, "admin", "secret2"); got != http.StatusTooManyRequests {
		t.Errorf("unverified credentials while over budget: %d, want 429", got)
	}
}

// audit: P2-ADM-003
// A request with no Authorization header costs no bcrypt and guesses
// nothing, so it does not spend the budget: a browser's first request to
// the dashboard is always headerless.
func TestAuthHeaderlessRequestsNotCounted(t *testing.T) {
	h := testServer(t).handler()
	const remote = "192.0.2.10:40000"
	for i := 0; i < 3*authFailLimit; i++ {
		if got := doAuth(h, remote, "", ""); got != http.StatusUnauthorized {
			t.Fatalf("headerless request %d: %d, want 401", i, got)
		}
	}
	if got := doAuth(h, remote, "admin", "secret"); got != http.StatusOK {
		t.Errorf("valid login after headerless requests: %d, want 200", got)
	}
}

// audit: P2-ADM-003
// IPv6 sources share one budget per /64: a host that owns a /64 cannot get
// a fresh budget by changing its interface identifier.
func TestAuthLimiterKeysIPv6By64(t *testing.T) {
	var l authLimiter
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < authFailLimit; i++ {
		l.recordFail("2001:db8:1:2::1", now)
	}
	if !l.over("2001:db8:1:2:ffff::9", now) {
		t.Error("another address in the same /64 has a fresh budget")
	}
	if l.over("2001:db8:1:3::1", now) {
		t.Error("a different /64 shares the budget")
	}
	for i := 0; i < authFailLimit; i++ {
		l.recordFail("198.51.100.1", now)
	}
	if !l.over("::ffff:198.51.100.1", now) {
		t.Error("an IPv4-mapped source is keyed apart from its IPv4 address")
	}
}

// audit: P2-ADM-003
// When the table is full the least significant entry is evicted, not the
// whole table, and an exhausted source is the last to go.
func TestAuthLimiterEvictsFewestFailures(t *testing.T) {
	var l authLimiter
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < authFailLimit; i++ {
		l.recordFail("198.51.100.1", now)
	}
	for i := 0; i < 2*authFailMaxIPs; i++ {
		l.recordFail(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), now.Add(time.Second))
	}
	if len(l.perIP) > authFailMaxIPs {
		t.Errorf("table grew to %d entries, cap is %d", len(l.perIP), authFailMaxIPs)
	}
	if !l.over("198.51.100.1", now.Add(2*time.Second)) {
		t.Error("the exhausted source was evicted")
	}
}

// audit: P2-ADM-002
// A refunded reservation (valid credentials) does not count as a failure.
func TestAuthLimiterRefund(t *testing.T) {
	var l authLimiter
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 3*authFailLimit; i++ {
		slot, ok := l.reserve("192.0.2.1", now)
		if !ok {
			t.Fatalf("reservation %d refused although every one was refunded", i)
		}
		l.refund(slot)
	}
	if l.over("192.0.2.1", now) {
		t.Error("refunded reservations were counted as failures")
	}
}
