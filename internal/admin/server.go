// Package admin serves the read-only operator HTTP surface: a Prometheus
// /metrics endpoint and a JSON status API, behind bcrypt HTTP Basic Auth.
// It imports only config; plane-side data arrives via the Deps closures
// over admin's own DTOs (internal/app adapts trunk.Server and edge.Server).
package admin

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// Call is one active call as the admin surface sees it: plain metadata,
// no SIP dialog or media session. app converts the planes' own records
// into these.
type Call struct {
	ID            string // admin call ID: what KillCall takes
	CallID        string // A-leg SIP Call-ID, for correlating with traces
	FromPeer      string
	ToPeer        string
	StartUnixNano int64
}

// PeerStatus is one peer's operator-visible status.
type PeerStatus struct {
	Name, Address, Transport, SRTP string
	Register, Registered           bool
}

// ShieldStats mirrors the shield's activity snapshot for the API/metrics.
type ShieldStats struct {
	DropsByReason map[string]int64
}

// Deps are the live-data closures the admin surface reads. All must be safe
// for concurrent use (they read already-synchronized structures).
type Deps struct {
	Calls       func() []Call
	Peers       func() []PeerStatus
	Ports       func() (inUse, total int)
	Shield      func() ShieldStats
	ActiveCalls func() int
	KillCall    func(id string) bool
	Version     string
	// Proxy reports the edge-proxy plane's counters, or is nil when that
	// plane is not running (a trunk-only deployment).
	Proxy func() ProxyStats
}

// ProxyStats is the edge proxy's operator-visible state: registrations,
// dialogs, media sessions and the failure counters that distinguish "the
// browser never reached us" from "it reached us and the handshake failed".
//
// Deliberately label-free apart from bounded sets (SIP method/transport,
// response class): a Call-ID here would create a permanent time series per
// call.
type ProxyStats struct {
	ActiveRegistrations  int64 `json:"active_registrations"`
	ActiveDialogs        int64 `json:"active_dialogs"`
	ActiveMediaSessions  int64 `json:"active_media_sessions"`
	ActiveWebRTCSessions int64 `json:"active_webrtc_sessions"`

	RegistrationTotal   uint64 `json:"registration_total"`
	RegistrationFailure uint64 `json:"registration_failure_total"`

	RequestsIn   map[string]uint64 `json:"sip_requests_total"`
	ResponsesOut map[string]uint64 `json:"sip_responses_total"`

	RTPPacketsRx uint64 `json:"rtp_packets_rx_total"`
	RTPPacketsTx uint64 `json:"rtp_packets_tx_total"`
	RTPBytesRx   uint64 `json:"rtp_bytes_rx_total"`
	RTPBytesTx   uint64 `json:"rtp_bytes_tx_total"`

	PortAllocationFailures uint64 `json:"media_port_allocation_failure_total"`
	ICEFailures            uint64 `json:"webrtc_ice_failure_total"`
	DTLSFailures           uint64 `json:"webrtc_dtls_failure_total"`
	HandlerPanics          uint64 `json:"sip_handler_panics_total"`
}

// Server is the admin HTTP server.
type Server struct {
	cfg     *config.AdminConfig
	store   *config.Store
	deps    Deps
	log     *slog.Logger
	started time.Time
	cfgPath string

	limiter authLimiter // per-IP auth-failure rate limit

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
	mux.HandleFunc("DELETE /api/calls/{id}", s.requireAuth(s.handleKickCall))
	mux.HandleFunc("/api/peers", s.requireAuth(s.handlePeers))
	mux.HandleFunc("/api/config", s.requireAuth(s.handleConfig))
	mux.HandleFunc("/api/config/raw", s.requireAuth(s.handleConfigRaw))
	mux.HandleFunc("/", s.requireAuth(s.handleUI)) // SPA catch-all (behind auth)
	return s.recoverMW(mux)
}

// Run serves until ctx is cancelled, then shuts down gracefully. A bind
// failure returns an error (fatal to the process). When the construction
// config carries tls_cert/tls_key, the listener serves HTTPS (TLS >= 1.2);
// a non-loopback listen WITHOUT TLS logs a prominent startup warning (the
// operator opted in via allow_remote, but Basic credentials and the full
// config then travel in the clear).
func (s *Server) Run(ctx context.Context) error {
	stopWatch := s.watchListenChange(ctx)
	defer stopWatch()

	if s.cfg.TLSCert == "" && !isLoopbackListen(s.cfg.Listen) {
		s.log.Warn("admin serving PLAINTEXT on a non-loopback address — Basic credentials and the full config are readable on the network; set admin.tls_cert/tls_key or front with a TLS reverse proxy",
			"listen", s.cfg.Listen)
	}

	srv := s.newHTTPServer()
	errc := make(chan error, 1)
	go func() {
		if s.cfg.TLSCert == "" {
			errc <- srv.ListenAndServe()
			return
		}
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			errc <- fmt.Errorf("admin tls cert/key: %w", err)
			return
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		errc <- srv.ListenAndServeTLS("", "")
	}()
	s.log.Info("admin server listening", "addr", s.cfg.Listen, "tls", s.cfg.TLSCert != "")
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
//
// Hardening: (1) a request with no Authorization header at all
// is rejected 401 before any bcrypt work — paying a full KDF for a request
// that carries no credentials is exactly the unauthenticated CPU-DoS the
// audit found, and the header's presence is public information, so skipping
// bcrypt on its absence leaks nothing about the secret. (2) auth failures
// are rate-limited per source IP (authFailLimit per authFailWindow): once an
// IP exhausts its budget, every further request from it — even with valid
// credentials — gets 429 until the window rolls over, bounding both
// brute-force attempts and the bcrypt CPU a single address can demand.
//
// The credentials compared are the store's CURRENT admin
// snapshot (adminAuth), not the construction-time cfg — a hot reload's new
// password_hash takes effect on the very next request.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if s.limiter.over(ip, time.Now()) {
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		}
		if r.Header.Get("Authorization") == "" {
			s.limiter.recordFail(ip, time.Now())
			w.Header().Set("WWW-Authenticate", `Basic realm="freesbc"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		user, pass, _ := r.BasicAuth()
		auth := s.adminAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(auth.Username)) == 1
		passOK := bcrypt.CompareHashAndPassword([]byte(auth.PasswordHash), []byte(pass)) == nil
		if !userOK || !passOK {
			s.limiter.recordFail(ip, time.Now())
			w.Header().Set("WWW-Authenticate", `Basic realm="freesbc"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// newHTTPServer builds the http.Server: IdleTimeout reclaims keep-alive
// connections that would otherwise pile up fd/goroutine pairs indefinitely
// (the unauthenticated /healthz is a favorite poll target, so idle
// keep-alive is a real leak), and Read/WriteTimeout bound slow clients —
// 30s leaves generous headroom for the 1MiB config PUT. Extracted so a
// test can pin the exact timeout set without waiting out any of them.
func (s *Server) newHTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

// isLoopbackListen reports whether addr is a loopback host:port
// (startup-warning check — config validation has already admitted whatever
// is here).
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// adminAuth returns the LIVE admin auth credentials: read from the store on
// every request, so a hot reload that swaps in a new password_hash revokes
// the old password immediately — no restart, no grace window. When the
// reloaded config carries no admin section at all (Admin nil), the
// construction-time credentials keep applying — the API keeps serving
// rather than flipping to an empty auth that would deny everyone.
func (s *Server) adminAuth() config.AdminAuth {
	if cur := s.store.Current().Admin; cur != nil {
		return cur.Auth
	}
	return s.cfg.Auth
}

// watchListenChange logs a prominent warning whenever a hot-reloaded config
// changes admin.listen: the listener is fixed at bind time, so
// the new address only takes effect after a restart — silently keeping the
// old one would make operators believe the change applied. Returns a stop
// func; the subscription itself is deliberately left registered (Store
// has no unsubscribe).
func (s *Server) watchListenChange(ctx context.Context) func() {
	ch := s.store.Subscribe()
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ch:
				if cur := s.store.Current().Admin; cur != nil && cur.Listen != s.cfg.Listen {
					s.log.Warn("admin.listen changed by hot reload; requires restart to take effect",
						"bound", s.cfg.Listen, "configured", cur.Listen)
				}
			}
		}
	}()
	return func() { close(done) }
}

// authFailLimit, authFailWindow, and authFailMaxIPs bound the per-IP
// auth-failure rate limiter: an IP is allowed authFailLimit
// failures per authFailWindow; the next request from it within the window is
// answered 429 instead of 401, and it stays 429 until the window rolls over.
// authFailMaxIPs caps the tracked-IP table so its state can never grow
// without bound.
const (
	authFailLimit  = 10
	authFailWindow = time.Minute
	authFailMaxIPs = 4096
)

// authLimiter is the per-IP auth-failure tracker behind requireAuth's 429.
// The zero value is usable (the map is created lazily). Expired windows are
// pruned on every access — the request stream itself is the cleanup clock,
// so the table holds at most the current minute's failing IPs — and the
// hard cap drops the whole table rather than letting a flood of >4096
// distinct source IPs grow memory unboundedly (losing the counts at that
// point is harmless: no more than a handful of failures per IP per minute
// was being tracked anyway).
type authLimiter struct {
	mu    sync.Mutex
	perIP map[string]authFailEntry
}

type authFailEntry struct {
	start    time.Time
	failures int
}

// over reports whether ip has already exhausted its failure budget for the
// current window — i.e. whether the next failure (or any further request)
// from ip must be refused with 429. It does not change state; recordFail
// does.
func (l *authLimiter) over(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.perIP[ip]
	return ok && now.Sub(w.start) < authFailWindow && w.failures >= authFailLimit
}

// recordFail counts one auth failure for ip, creating the table (and
// lazily pruning expired entries / applying the cap) as needed.
func (l *authLimiter) recordFail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP == nil {
		l.perIP = make(map[string]authFailEntry)
	}
	w := l.perIP[ip]
	if now.Sub(w.start) >= authFailWindow {
		// New window for this IP — sweep every expired entry while we're
		// here, then enforce the cap.
		for k, v := range l.perIP {
			if now.Sub(v.start) >= authFailWindow {
				delete(l.perIP, k)
			}
		}
		if len(l.perIP) >= authFailMaxIPs {
			clear(l.perIP)
		}
		w = authFailEntry{start: now}
	}
	w.failures++
	l.perIP[ip] = w
}

// remoteIP extracts the client's IP from RemoteAddr, falling back to the raw
// string when it isn't host:port-shaped.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// recoverMW turns a handler panic into a 500 without leaking a stack trace.
// It also injects Cache-Control: no-store on every response:
// the API serves live state and, on /api/config/raw, the FULL config —
// every peer credential in plaintext — none of which belongs in a
// browser's on-disk cache. /healthz is exempt: it is static and is what
// load balancers poll, where no-store would be noise. ETag/If-Match
// semantics are untouched.
func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.Header().Set("Cache-Control", "no-store")
		}
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

// handleKickCall tears down a live call by id (URL-decoded by PathValue).
// 204 if the call was found and killed, 404 otherwise.
func (s *Server) handleKickCall(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.deps.KillCall != nil && s.deps.KillCall(id) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, "no such active call", http.StatusNotFound)
}

// handleStatus, handleCalls, handlePeers, handleConfig, and handleConfigGet
// are implemented in api.go. handleConfigRaw and handleConfigWrite are
// implemented in config_write.go. handleMetrics is implemented in
// metrics.go. handleUI is implemented in webui.go.
