// Package admin serves the read-only operator HTTP surface: a Prometheus
// /metrics endpoint and a JSON status API, behind bcrypt HTTP Basic Auth.
// It imports only config and the dependency-free callstate; sig-side data
// arrives via the Deps closures (main adapts sig.Server).
package admin

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/freesbc/freesbc/callstate"
	"github.com/freesbc/freesbc/config"
	"golang.org/x/crypto/bcrypt"
)

// PeerStatus is one peer's operator-visible status.
type PeerStatus struct {
	Name, Address, Transport, SRTP string
	Register, Registered           bool
}

// ShieldStats mirrors the shield's activity snapshot for the API/metrics.
type ShieldStats struct {
	BannedCurrent int
	DropsByReason map[string]int64
}

// Deps are the live-data closures the admin surface reads. All must be safe
// for concurrent use (they read already-synchronized structures).
type Deps struct {
	Calls       func() []callstate.Call
	Peers       func() []PeerStatus
	Ports       func() (inUse, total int)
	Shield      func() ShieldStats
	ActiveCalls func() int
	Version     string
}

// Server is the admin HTTP server.
type Server struct {
	cfg     *config.AdminConfig
	store   *config.Store
	deps    Deps
	log     *slog.Logger
	started time.Time
	cfgPath string

	metricsOnce    sync.Once
	metricsHandler http.Handler
}

func New(cfg *config.AdminConfig, store *config.Store, deps Deps, log *slog.Logger, cfgPath string) *Server {
	return &Server{cfg: cfg, store: store, deps: deps, log: log, started: time.Now(), cfgPath: cfgPath}
}

// handler composes the mux with the recover and (per-route) auth middleware.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz) // no auth
	mux.HandleFunc("/metrics", s.requireAuth(s.handleMetrics))
	mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/calls", s.requireAuth(s.handleCalls))
	mux.HandleFunc("/api/peers", s.requireAuth(s.handlePeers))
	mux.HandleFunc("/api/config", s.requireAuth(s.handleConfig))
	mux.HandleFunc("/api/config/raw", s.requireAuth(s.handleConfigRaw))
	mux.HandleFunc("/", s.requireAuth(s.handleUI)) // SPA catch-all (behind auth)
	return s.recoverMW(mux)
}

// Run serves until ctx is cancelled, then shuts down gracefully. A bind
// failure returns an error (fatal to the process).
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{Addr: s.cfg.Listen, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	s.log.Info("admin server listening", "addr", s.cfg.Listen)
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// requireAuth wraps h with HTTP Basic Auth: constant-time username compare AND
// bcrypt password compare, both evaluated before deciding (no timing oracle),
// generic 401 on any failure (no user enumeration). /healthz is not wrapped.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.cfg.Auth.Username)) == 1
		passOK := bcrypt.CompareHashAndPassword([]byte(s.cfg.Auth.PasswordHash), []byte(pass)) == nil
		if !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="freesbc"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// recoverMW turns a handler panic into a 500 without leaking a stack trace.
func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// http.ErrAbortHandler is the stdlib's signal to abort the
				// response without logging or writing an error body; the
				// net/http server itself handles it. Re-panic so that
				// convention is honored instead of being swallowed here.
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("admin handler panic", "err", rec, "path", r.URL.Path)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleStatus, handleCalls, handlePeers, handleConfig, and handleConfigGet
// are implemented in api.go. handleConfigRaw and handleConfigWrite are
// implemented in config_write.go. handleMetrics is implemented in
// metrics.go. handleUI is implemented in webui.go.
