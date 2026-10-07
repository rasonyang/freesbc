package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/freesbc/freesbc/internal/config"
)

const maxConfigBytes = 1 << 20 // 1 MiB

// handleConfigRaw returns the on-disk config file verbatim, for an operator
// to read or download. Unlike handleConfigGet, this is NOT redacted: the
// caller is already authenticated as an admin.
func (s *Server) handleConfigRaw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := os.ReadFile(s.cfgPath)
	if err != nil {
		s.log.Error("read config for raw view", "err", err)
		http.Error(w, "cannot read config", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	_, _ = w.Write(data)
}

// validateResult is the POST /api/config/validate response.
type validateResult struct {
	Valid           bool     `json:"valid"`
	Errors          []string `json:"errors"`
	RestartRequired []string `json:"restart_required"`
}

// handleConfigValidate checks a candidate config file without writing
// anything. It runs the same config.Parse as `freesbc check`, which expands
// ${VAR} only after unmarshal and redacts expanded values from validation
// messages, so no environment value reaches the response. restart_required
// lists the restart-only keys the candidate changes relative to the config
// the process started with (Deps.Running), the same comparison the config
// watcher logs on a reload. It is empty when the candidate is invalid.
func (s *Server) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigBytes+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxConfigBytes {
		http.Error(w, "config too large", http.StatusRequestEntityTooLarge)
		return
	}
	res := validateResult{Errors: []string{}, RestartRequired: []string{}}
	cand, err := config.Parse(body)
	if err != nil {
		res.Errors = splitErrors(err)
	} else {
		res.Valid = true
		running := s.store.Current()
		if s.deps.Running != nil {
			running = s.deps.Running()
		}
		if changed := config.RestartOnlyChanges(running, cand); len(changed) > 0 {
			res.RestartRequired = changed
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// splitErrors turns a config.Parse error into one string per problem. A YAML
// syntax error is one multi-line message (with a source excerpt) and stays
// whole; validation errors are one per line.
func splitErrors(err error) []string {
	msg := err.Error()
	if rest, ok := strings.CutPrefix(msg, "invalid config:\n"); ok {
		var out []string
		for _, line := range strings.Split(rest, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				out = append(out, line)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{strings.TrimSpace(msg)}
}
