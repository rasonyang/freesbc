package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/freesbc/freesbc/config"
)

// etagOf returns a quoted strong ETag (sha256 hex) for data.
func etagOf(data []byte) string {
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// writeFileAtomic writes data to path atomically: a temp file in the same
// directory is written, synced, chmod'd to mode, then renamed over path
// (atomic on one filesystem). On any failure the temp file is removed and the
// original path is left untouched. The submitted bytes are written verbatim —
// no transformation, so comments and ${ENV} references are preserved.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

const maxConfigBytes = 1 << 20 // 1 MiB

// handleConfigRaw returns the on-disk config file verbatim (with its ETag),
// for an operator to edit and PUT back. Unlike handleConfigGet, this is NOT
// redacted — the caller is already authenticated as an admin.
func (s *Server) handleConfigRaw(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.cfgPath)
	if err != nil {
		s.log.Error("read config for raw view", "err", err)
		http.Error(w, "cannot read config", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("ETag", etagOf(data))
	_, _ = w.Write(data)
}

// handleConfigWrite validates and atomically writes a new config file. The
// submitted bytes are written verbatim (never the ${ENV}-expanded form):
// config.Parse is used only to validate a throwaway *Config, not to produce
// the bytes that get written. On any validation failure the file is left
// untouched.
func (s *Server) handleConfigWrite(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigBytes+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxConfigBytes {
		http.Error(w, "config too large", http.StatusRequestEntityTooLarge)
		return
	}
	// optimistic concurrency: compare If-Match to the CURRENT file's etag.
	if want := r.Header.Get("If-Match"); want != "" {
		cur, err := os.ReadFile(s.cfgPath)
		if err != nil {
			http.Error(w, "cannot read current config", http.StatusInternalServerError)
			return
		}
		if want != etagOf(cur) {
			http.Error(w, "config changed since read (stale If-Match)", http.StatusConflict)
			return
		}
	}
	// validate before writing — Parse expands ${ENV} and validates a COPY.
	if _, err := config.Parse(body); err != nil {
		http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
		return
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(s.cfgPath); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileAtomic(s.cfgPath, body, mode); err != nil {
		s.log.Error("write config", "err", err)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	s.log.Warn("config written via admin API", "path", s.cfgPath, "bytes", len(body))
	w.Header().Set("ETag", etagOf(body))
	w.WriteHeader(http.StatusOK)
}
