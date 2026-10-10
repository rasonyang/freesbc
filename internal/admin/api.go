package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// writeJSON encodes v as the JSON response body.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// reloadBody is the "reload" object of /api/status. Times are RFC3339 UTC;
// last_ok, last_error and last_error_at are null until they apply, and
// restart_required is always an array.
type reloadBody struct {
	LastOK          *string  `json:"last_ok"`
	RestartRequired []string `json:"restart_required"`
	LastError       *string  `json:"last_error"`
	LastErrorAt     *string  `json:"last_error_at"`
}

func reloadResponse(st config.ReloadStatus) reloadBody {
	b := reloadBody{RestartRequired: append([]string{}, st.RestartRequired...)}
	if !st.LastOK.IsZero() {
		t := st.LastOK.UTC().Format(time.RFC3339)
		b.LastOK = &t
	}
	if st.LastError != "" {
		at := st.LastErrorAt.UTC().Format(time.RFC3339)
		b.LastError, b.LastErrorAt = &st.LastError, &at
	}
	return b
}

// handleStatus reports process/service-level status: version, uptime, active
// call count, media port usage, and the SIP listeners the running planes
// bound (not the hot-reloaded config's, which may name sockets nothing is
// bound to: the listener set is restart-only).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	inUse, total := s.deps.Ports()
	listeners := []string{}
	if s.deps.Listeners != nil {
		listeners = append(listeners, s.deps.Listeners()...)
	}
	var rs config.ReloadStatus
	if s.deps.Reload != nil {
		rs = s.deps.Reload()
	}
	writeJSON(w, map[string]any{
		"version":        s.deps.Version,
		"uptime_seconds": int(time.Since(s.started).Seconds()),
		"active_calls":   s.deps.ActiveCalls(),
		"ports":          map[string]int{"in_use": inUse, "total": total},
		"listeners":      listeners,
		"reload":         reloadResponse(rs),
	})
}

// handleCalls lists currently active calls. Always writes a JSON array
// (never null) even when there are no active calls.
func (s *Server) handleCalls(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	out := []map[string]any{}
	for _, c := range s.deps.Calls() {
		start := time.Unix(0, c.StartUnixNano)
		out = append(out, map[string]any{
			"id":               c.ID,
			"call_id":          c.CallID,
			"from":             c.FromPeer,
			"to":               c.ToPeer,
			"started":          start.Format(time.RFC3339),
			"duration_seconds": int(now.Sub(start).Seconds()),
		})
	}
	writeJSON(w, out)
}

// handleConfigGet returns the running configuration with secrets redacted.
// See redact.go: redactConfig never returns a live secret value.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, redactConfig(s.store.Current()))
}

// handleConfig serves /api/config: GET returns the redacted running config
// (handleConfigGet). The API is read-only; every other method is rejected.
// Editing means changing the file, running `freesbc check` and letting the
// watcher reload it; POST /api/config/validate checks a candidate.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.handleConfigGet(w, r)
}

// drainBody is the /api/drain response. Since is null when not draining.
type drainBody struct {
	Draining    bool    `json:"draining"`
	Since       *string `json:"since"`
	ActiveCalls int     `json:"active_calls"`
}

// drainResponse renders the current drain state.
func (s *Server) drainResponse() drainBody {
	on, since := s.deps.DrainState()
	b := drainBody{Draining: on, ActiveCalls: s.deps.ActiveCalls()}
	if on && !since.IsZero() {
		t := since.UTC().Format(time.RFC3339)
		b.Since = &t
	}
	return b
}

// handleDrain serves /api/drain: GET reports the drain state, POST enters
// drain mode and DELETE leaves it; both mutations are idempotent and answer
// with the same body as GET. Auth, the Host check and (for POST and DELETE)
// the Origin check run before it. The state is runtime only (edge drain.go).
// Each actual change is logged and audited (drain_on, drain_off, audit.go).
// A request that changes nothing records nothing.
func (s *Server) handleDrain(w http.ResponseWriter, r *http.Request) {
	if s.deps.DrainState == nil || s.deps.SetDraining == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost, http.MethodDelete:
		on := r.Method == http.MethodPost
		if s.deps.SetDraining(on) {
			msg, typ := "admin: edge drain left", AuditDrainOff
			if on {
				msg, typ = "admin: edge drain entered", AuditDrainOn
			}
			s.audit.record(typ, remoteIP(r), AuditResultOK)
			s.log.Info(msg, "remote", r.RemoteAddr, "active_calls", s.deps.ActiveCalls())
		}
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.drainResponse())
}
