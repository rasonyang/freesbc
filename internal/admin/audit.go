package admin

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// AuditType is the kind of admin event an audit entry records. It is a closed
// set so a future action (a config write, say) adds a constant here and reuses
// the same ring, log line and API.
type AuditType string

const (
	// AuditLoginOK is the first successful verification of a credential
	// from a source. Requests that hit the verified-credentials cache are
	// not logged.
	AuditLoginOK AuditType = "login_ok"
	// AuditLoginFailed is a request that carried Basic credentials that did
	// not verify. A request with no Authorization header is not an event.
	AuditLoginFailed AuditType = "login_failed"
	// AuditLoginLimited is a request answered 429 by the per-source
	// auth-failure limiter.
	AuditLoginLimited AuditType = "login_limited"
)

// AuditResult is the outcome recorded with an event; a fixed set, also the
// label of freesbc_admin_auth_failures_total (minus "ok").
type AuditResult string

const (
	AuditResultOK             AuditResult = "ok"
	AuditResultBadCredentials AuditResult = "bad_credentials"
	AuditResultRateLimited    AuditResult = "rate_limited"
)

// authFailureReasons is the label set of freesbc_admin_auth_failures_total,
// exported from zero.
var authFailureReasons = []AuditResult{AuditResultBadCredentials, AuditResultRateLimited}

// auditRingSize is how many events the in-memory ring keeps; the oldest is
// dropped first.
const auditRingSize = 256

// AuditEvent is one entry of the admin audit log. It never carries a
// username, password, Authorization header or hash.
type AuditEvent struct {
	Time   time.Time   `json:"time"`
	Type   AuditType   `json:"type"`
	Source string      `json:"source"` // remoteIP of the request; the proxy's address behind a proxy
	Result AuditResult `json:"result"`
}

// auditLog is a bounded ring of events plus the failure counters. The zero
// value is usable (nil logger discards the structured line).
type auditLog struct {
	mu    sync.Mutex
	buf   [auditRingSize]AuditEvent
	start int // index of the oldest event
	n     int // number of events held
	fails map[AuditResult]uint64
	log   *slog.Logger
	now   func() time.Time
}

// count adds one to the failure counter for res. It is separate from record
// because the counter sees every failure while the ring and log see only some
// (login_limited is recorded once per lockout window).
func (a *auditLog) count(res AuditResult) {
	a.mu.Lock()
	if a.fails == nil {
		a.fails = make(map[AuditResult]uint64)
	}
	a.fails[res]++
	a.mu.Unlock()
}

// record appends an event to the ring and writes the
// "admin audit" log line with a fixed field set.
func (a *auditLog) record(t AuditType, source string, res AuditResult) {
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	ev := AuditEvent{Time: now().UTC(), Type: t, Source: source, Result: res}
	a.mu.Lock()
	if a.n < auditRingSize {
		a.buf[(a.start+a.n)%auditRingSize] = ev
		a.n++
	} else {
		a.buf[a.start] = ev
		a.start = (a.start + 1) % auditRingSize
	}
	a.mu.Unlock()
	if a.log != nil {
		a.log.Info("admin audit", "type", string(t), "source", source, "result", string(res), "at", ev.Time.Format(time.RFC3339))
	}
}

// snapshot returns the events newest first; never nil.
func (a *auditLog) snapshot() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEvent, 0, a.n)
	for i := a.n - 1; i >= 0; i-- {
		out = append(out, a.buf[(a.start+i)%auditRingSize])
	}
	return out
}

// failures returns a copy of the failure counters by result.
func (a *auditLog) failures() map[AuditResult]uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[AuditResult]uint64, len(a.fails))
	for k, v := range a.fails {
		out[k] = v
	}
	return out
}

// handleAudit serves GET /api/audit: the ring, newest first, always an array.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.audit.snapshot())
}
