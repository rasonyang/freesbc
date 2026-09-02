package admin

import (
	"embed"
	"net/http"
)

//go:embed webui/index.html
var webuiFS embed.FS

// handleUI serves the embedded single-page web UI. It is the catch-all route
// ("/"), so the explicit /api/*, /metrics, and /healthz routes take precedence
// in the mux; any other path serves the SPA (one page).
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	data, err := webuiFS.ReadFile("webui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
