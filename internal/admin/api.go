package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// writeJSON encodes v as the JSON response body.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// handleStatus reports process/service-level status: version, uptime, active
// call count, media port usage, and configured SIP listeners.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	inUse, total := s.deps.Ports()
	listeners := []string{}
	for _, l := range s.store.Current().Listeners() {
		listeners = append(listeners, fmt.Sprintf("%s://%s:%d", l.Transport, l.Host, l.Port))
	}
	writeJSON(w, map[string]any{
		"version":        s.deps.Version,
		"uptime_seconds": int(time.Since(s.started).Seconds()),
		"active_calls":   s.deps.ActiveCalls(),
		"ports":          map[string]int{"in_use": inUse, "total": total},
		"listeners":      listeners,
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

// handlePeers lists configured peers and their operator-visible status.
func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := s.deps.Peers()
	if peers == nil {
		peers = []PeerStatus{}
	}
	writeJSON(w, peers)
}

// handleConfigGet returns the running configuration with secrets redacted.
// See redact.go: redactConfig never returns a live secret value.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, redactConfig(s.store.Current()))
}

// handleConfig dispatches /api/config by method: GET returns the redacted
// running config (handleConfigGet); PUT validates and atomically writes a
// new config file (handleConfigWrite, in config_write.go); any other method
// is rejected.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleConfigGet(w, r)
	case http.MethodPut:
		s.handleConfigWrite(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
