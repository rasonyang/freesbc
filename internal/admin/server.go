// Package admin serves the read-only operator HTTP surface: a Prometheus
// /metrics endpoint and a JSON status API, behind bcrypt HTTP Basic Auth.
// It imports only config; plane-side data arrives via the Deps closures
// over admin's own DTOs (internal/app adapts edge.Server).
package admin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// Call is one active call as the admin surface sees it: plain metadata,
// no SIP dialog or media session. app converts the planes' own records
// into these.
type Call struct {
	ID            string // admin call ID: admin call ID
	CallID        string // A-leg SIP Call-ID, for correlating with traces
	FromPeer      string
	ToPeer        string
	StartUnixNano int64
}

// ShieldStats mirrors the shield's activity snapshot for the API/metrics.
type ShieldStats struct {
	DropsByReason map[string]int64
}

// Deps are the live-data closures the admin surface reads. All must be safe
// for concurrent use (they read already-synchronized structures).
type Deps struct {
	Calls       func() []Call
	Ports       func() (inUse, total int)
	Shield      func() ShieldStats
	ActiveCalls func() int
	Version     string
	// Listeners lists the SIP listeners the running planes bound, as
	// transport://host:port. They are restart-only, so this comes from the
	// startup snapshot, never the hot-reloaded config. Nil lists none.
	Listeners func() []string
	// Running returns the config snapshot the process started with, the
	// baseline POST /api/config/validate compares a candidate against to
	// list restart-only changes. Nil falls back to the store's current
	// snapshot.
	Running func() *config.Config
	// Proxy reports the edge plane's counters; nil reports none.
	Proxy func() ProxyStats
	// DrainState reports whether the edge is draining and since when.
	// SetDraining enters (true) or leaves (false) drain and reports whether
	// the state changed. Nil on either makes /api/drain answer 404.
	DrainState  func() (draining bool, since time.Time)
	SetDraining func(on bool) (changed bool)
}

// ProxyStats is the edge proxy's operator-visible state: registrations,
// dialogs, media sessions and the failure counters that distinguish "the
// browser never reached us" from "it reached us and the handshake failed".
//
// Deliberately label-free apart from bounded sets (SIP method/transport,
// response class): a Call-ID here would create a permanent time series per
// call.
type ProxyStats struct {
	ActiveRegistrations int64 `json:"active_registrations"`
	// ActiveSubscriptions is the SUBSCRIBE dialogs the edge routes NOTIFYs
	// for (pending or active).
	ActiveSubscriptions int64 `json:"active_subscriptions"`
	ActiveDialogs       int64 `json:"active_dialogs"`
	// ActiveSessions is the calls holding a session slot (ringing or up),
	// the number shield.max_sessions caps.
	ActiveSessions int64 `json:"active_sessions"`
	// Draining is true while the edge refuses new INVITEs.
	Draining             bool  `json:"draining"`
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

	// ParseFailures counts reads sipgo's parser rejected, by transport
	// (UDP, TCP, TLS, WS, WSS, OTHER).
	ParseFailures map[string]uint64 `json:"sip_parse_failures_total"`

	// StreamConnections is the open stream connections by transport (tcp,
	// tls, ws, wss); StreamRefused counts connections refused at accept by
	// reason (global_cap, ip_cap, banned, rate) and StreamClosed connections
	// closed by policy by reason (idle, slow, oversize, malformed,
	// handshake, rate).
	StreamConnections map[string]int64  `json:"stream_connections"`
	StreamRefused     map[string]uint64 `json:"stream_refused_total"`
	StreamClosed      map[string]uint64 `json:"stream_closed_total"`

	// AdmissionDrops counts public requests the edge admission policy
	// dropped silently, by reason (a fixed set: invite_not_admitted,
	// register_enumeration, subscribe_not_admitted, message_not_admitted).
	AdmissionDrops map[string]uint64 `json:"admission_drops_total"`

	// CallsEnded counts confirmed calls that ended, by reason (a fixed set,
	// edge endReasonLabels).
	CallsEnded map[string]uint64 `json:"calls_ended_total"`

	// InviteRejects counts final responses the edge itself sent to an
	// out-of-dialog INVITE, by reason (a fixed set, edge
	// inviteRejectLabels).
	InviteRejects map[string]uint64 `json:"invite_rejects_total"`

	// CarrierRequests counts carrier-path requests, keyed
	// "carrier/direction/method" (direction: inbound or outbound).
	CarrierRequests map[string]uint64 `json:"carrier_requests_total"`

	// CarrierRegistrations is the live switch-to-carrier registration
	// count per carrier name.
	CarrierRegistrations map[string]int64 `json:"carrier_registrations"`
}

// Server is the admin HTTP server.
type Server struct {
	cfg     *config.AdminConfig // the startup snapshot: admin is restart-only
	tls     *config.TLSConfig   // top-level tls identity; served when cfg.AllowRemote
	store   *config.Store
	deps    Deps
	log     *slog.Logger
	started time.Time
	cfgPath string

	hosts    *hostPolicy      // accepted Host header values
	limiter  authLimiter      // per-source auth-failure rate limit
	verified verifiedCreds    // credentials already verified by bcrypt
	audit    auditLog         // bounded ring of auth events (audit.go)
	now      func() time.Time // test seam for the limiter clock; nil is time.Now

	metricsOnce    sync.Once
	metricsHandler http.Handler
}

// New builds the admin server from the startup admin section and the
// top-level tls identity (used only when cfg.AllowRemote). Admin is
// restart-only, so cfg is never re-read from the store.
func New(cfg *config.AdminConfig, tlsCfg *config.TLSConfig, store *config.Store, deps Deps, log *slog.Logger, cfgPath string) *Server {
	s := &Server{cfg: cfg, tls: tlsCfg, store: store, deps: deps, log: log, started: time.Now(), cfgPath: cfgPath}
	s.audit.log = log
	s.hosts = newHostPolicy(cfg.Listen, cfg.AllowedHosts, s.useTLS())
	return s
}

// handler composes the mux with the recover, Host/Origin guard and (per-route) auth middleware.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz) // no auth
	mux.HandleFunc("/metrics", s.requireAuth(s.handleMetrics))
	mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/calls", s.requireAuth(s.handleCalls))
	mux.HandleFunc("/api/drain", s.requireAuth(s.handleDrain))
	mux.HandleFunc("/api/audit", s.requireAuth(s.handleAudit))
	mux.HandleFunc("/api/config", s.requireAuth(s.handleConfig))
	mux.HandleFunc("/api/config/raw", s.requireAuth(s.handleConfigRaw))
	mux.HandleFunc("/api/config/validate", s.requireAuth(s.handleConfigValidate))
	mux.HandleFunc("/", s.requireAuth(s.handleUI)) // SPA catch-all (behind auth)
	return s.recoverMW(s.guardMW(mux))
}

// useTLS reports whether the listener serves HTTPS: with allow_remote the
// top-level tls identity is mandatory (validation enforces it).
func (s *Server) useTLS() bool { return s.cfg.AllowRemote && s.tls != nil }

// Run serves until ctx is cancelled, then shuts down gracefully. A bind
// failure returns an error (fatal to the process). With allow_remote the
// listener serves HTTPS (TLS >= 1.2) using the top-level tls identity;
// otherwise it serves plain HTTP, which validation only admits on loopback.
func (s *Server) Run(ctx context.Context) error {
	srv := s.newHTTPServer()
	errc := make(chan error, 1)
	go func() {
		if !s.useTLS() {
			errc <- srv.ListenAndServe()
			return
		}
		cert, err := tls.LoadX509KeyPair(s.tls.Cert, s.tls.Key)
		if err != nil {
			errc <- fmt.Errorf("admin tls cert/key: %w", err)
			return
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		errc <- srv.ListenAndServeTLS("", "")
	}()
	s.log.Info("admin server listening", "addr", s.cfg.Listen, "tls", s.useTLS())
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
// Hardening: (1) a request with no Authorization header at all is rejected
// 401 before any bcrypt work — paying a full KDF for a request that carries
// no credentials is exactly the unauthenticated CPU-DoS the audit found. It
// is not counted as a failure either: it guesses nothing, and a browser's
// first request to the dashboard always looks like this. (2) Auth failures
// are rate-limited per source (authFailLimit per authFailWindow, IPv6 per
// /64): a slot is reserved under the limiter's lock BEFORE bcrypt runs, so
// concurrent requests cannot all pass the check (audit P2-ADM-002); a
// success refunds its slot. Once a source's budget is spent, further
// requests get 429 without any bcrypt, bounding both brute force and the
// KDF CPU one address can demand. (3) Credentials this process has already
// verified are remembered (verifiedCreds), so an operator or the Prometheus
// scrape that authenticated before keeps working while its address is
// locked out by someone else's failures (loopback or a shared proxy).
// Only an exact, previously verified header passes that way, so it gives a
// guesser nothing.
//
// Auth events are audited (audit.go): login_ok on the first verification of
// a credential (the verifiedCreds add, not a cached request), login_failed
// for credentials that do not verify, login_limited for the first 429 of a
// source's lockout window (the rest only count in
// freesbc_admin_auth_failures_total, so a locked-out source cannot flush
// the ring or flood the log). A request with no Authorization header is not
// an event. Only the source IP is recorded, never the user, password, header
// or hash.
//
// The user is always config.AdminUser; the hash is the startup snapshot's
// (admin is restart-only, so there is no hot password rotation).
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="freesbc"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		hash := s.cfg.PasswordHash
		if s.verified.has(hash, user, pass) {
			h(w, r)
			return
		}
		ip := remoteIP(r)
		slot, ok, first := s.limiter.reserve(ip, s.clock())
		if !ok {
			// Every 429 counts; only the first of a lockout window is an event.
			s.audit.count(AuditResultRateLimited)
			if first {
				s.audit.record(AuditLoginLimited, ip, AuditResultRateLimited)
			}
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		}
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(config.AdminUser)) == 1
		passOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
		if !userOK || !passOK {
			// The reserved slot stays: it is this failure.
			s.audit.count(AuditResultBadCredentials)
			s.audit.record(AuditLoginFailed, ip, AuditResultBadCredentials)
			w.Header().Set("WWW-Authenticate", `Basic realm="freesbc"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.limiter.refund(slot)
		s.verified.add(hash, user, pass)
		s.audit.record(AuditLoginOK, ip, AuditResultOK)
		h(w, r)
	}
}

// newHTTPServer builds the http.Server: IdleTimeout reclaims keep-alive
// connections that would otherwise pile up fd/goroutine pairs indefinitely
// (the unauthenticated /healthz is a favorite poll target, so idle
// keep-alive is a real leak), and Read/WriteTimeout bound slow clients —
// 30s leaves generous headroom for the 1MiB config validate POST. Extracted so a
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

// authFailLimit, authFailWindow, and authFailMaxIPs bound the per-source
// auth-failure rate limiter: a source is allowed authFailLimit failures per
// authFailWindow; the next request from it within the window is answered
// 429 instead of 401, and it stays 429 until the window rolls over.
// authFailMaxIPs caps the tracked-source table so its state can never grow
// without bound.
const (
	authFailLimit  = 10
	authFailWindow = time.Minute
	authFailMaxIPs = 4096
)

// authLimiter is the per-source auth-failure tracker behind requireAuth's
// 429. The zero value is usable (the map is created lazily).
//
// Sources are keyed by limiterKey: an IPv4 address, or the /64 of an IPv6
// one, since a single host usually controls a whole /64 (audit P2-ADM-003).
// Expired windows are pruned whenever a new window starts — the request
// stream itself is the cleanup clock. When the table is full the entry with
// the fewest failures (oldest first on a tie) is evicted, never the whole
// table: clearing it let a flood of fresh sources reset an attacker's
// exhausted budget.
type authLimiter struct {
	mu    sync.Mutex
	perIP map[string]authFailEntry
}

type authFailEntry struct {
	start    time.Time
	failures int  // includes slots reserved by requests still in bcrypt
	denied   bool // a 429 for this window was already reported (audit)
}

// authSlot is one reservation made by reserve, for refund.
type authSlot struct {
	key   string
	start time.Time
}

// limiterKey maps a source address to its limiter key: the unmapped IPv4
// address, or the IPv6 /64. Anything unparsable is used verbatim.
func limiterKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr.WithZone(""), 64).Masked().String()
}

// over reports whether ip has already exhausted its failure budget for the
// current window — i.e. whether the next failure (or any further request)
// from ip must be refused with 429. It does not change state.
func (l *authLimiter) over(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.perIP[limiterKey(ip)]
	return ok && now.Sub(w.start) < authFailWindow && w.failures >= authFailLimit
}

// recordFail counts one auth failure for ip.
func (l *authLimiter) recordFail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.countLocked(limiterKey(ip), now)
}

// reserve counts a failure for ip in advance, under the lock, unless its
// budget is already spent (ok=false: answer 429). The caller refunds the
// slot if the credentials turn out to be valid. Check and count are one
// critical section, so N concurrent requests can take at most the
// remaining budget between them.
//
// When ok is false, first reports whether this is the first denial in the
// source's current window (the flag clears with the window), so the audit
// log records one login_limited per lockout, not one per 429.
func (l *authLimiter) reserve(ip string, now time.Time) (slot authSlot, ok, first bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := limiterKey(ip)
	if w, found := l.perIP[key]; found && now.Sub(w.start) < authFailWindow && w.failures >= authFailLimit {
		first = !w.denied
		w.denied = true
		l.perIP[key] = w
		return authSlot{}, false, first
	}
	return authSlot{key: key, start: l.countLocked(key, now)}, true, false
}

// refund returns a reserved slot. A slot from a window that has since
// rolled over is simply dropped: the new window never counted it.
func (l *authLimiter) refund(slot authSlot) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if w, ok := l.perIP[slot.key]; ok && w.start.Equal(slot.start) && w.failures > 0 {
		w.failures--
		l.perIP[slot.key] = w
	}
}

// countLocked adds one failure to key's window, starting a new window (and
// pruning / evicting) as needed. It returns the window's start.
func (l *authLimiter) countLocked(key string, now time.Time) time.Time {
	if l.perIP == nil {
		l.perIP = make(map[string]authFailEntry)
	}
	w, ok := l.perIP[key]
	if !ok || now.Sub(w.start) >= authFailWindow {
		// New window for this key — sweep every expired entry while we're
		// here, then enforce the cap.
		for k, v := range l.perIP {
			if now.Sub(v.start) >= authFailWindow {
				delete(l.perIP, k)
			}
		}
		if _, still := l.perIP[key]; !still && len(l.perIP) >= authFailMaxIPs {
			l.evictLocked()
		}
		w = authFailEntry{start: now}
	}
	w.failures++
	l.perIP[key] = w
	return w.start
}

// evictLocked drops the entry that matters least: fewest failures, oldest
// window on a tie. An exhausted source is therefore the last to go.
func (l *authLimiter) evictLocked() {
	var victim string
	var vw authFailEntry
	first := true
	for k, w := range l.perIP {
		if first || w.failures < vw.failures || (w.failures == vw.failures && w.start.Before(vw.start)) {
			victim, vw, first = k, w, false
		}
	}
	delete(l.perIP, victim)
}

// verifiedCredsMax bounds how many distinct verified credentials are
// remembered; verifiedCredsTTL is how long one is remembered after its last
// use.
const (
	verifiedCredsMax = 16
	verifiedCredsTTL = time.Hour
)

// verifiedCreds remembers Basic credentials that passed bcrypt, so their
// holder is not locked out by the failure limiter and a repeated scrape
// skips the KDF. Entries are HMAC-SHA256 digests under a per-process random
// key — never the password — over (hash, username, password). The zero value is
// usable.
type verifiedCreds struct {
	mu   sync.Mutex
	key  []byte
	seen map[[sha256.Size]byte]time.Time // digest -> last use
}

func (v *verifiedCreds) digestLocked(hash, user, pass string) [sha256.Size]byte {
	if v.key == nil {
		v.key = make([]byte, 32)
		if _, err := rand.Read(v.key); err != nil {
			panic("admin: crypto/rand: " + err.Error()) // never fails on supported platforms
		}
	}
	m := hmac.New(sha256.New, v.key)
	for _, part := range []string{hash, user, pass} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		m.Write(n[:])
		m.Write([]byte(part))
	}
	var d [sha256.Size]byte
	copy(d[:], m.Sum(nil))
	return d
}

// has reports whether (user, pass) was verified against hash before and is
// still fresh, refreshing its last use.
func (v *verifiedCreds) has(hash, user, pass string) bool {
	now := time.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	d := v.digestLocked(hash, user, pass)
	last, ok := v.seen[d]
	if !ok || now.Sub(last) >= verifiedCredsTTL {
		return false
	}
	v.seen[d] = now
	return true
}

// add remembers (user, pass) as verified against hash.
func (v *verifiedCreds) add(hash, user, pass string) {
	now := time.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = make(map[[sha256.Size]byte]time.Time)
	}
	d := v.digestLocked(hash, user, pass)
	if _, ok := v.seen[d]; !ok && len(v.seen) >= verifiedCredsMax {
		var oldest [sha256.Size]byte
		first := true
		for k, t := range v.seen {
			if first || t.Before(v.seen[oldest]) {
				oldest, first = k, false
			}
		}
		delete(v.seen, oldest)
	}
	v.seen[d] = now
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

// recoverMW turns a handler panic into a 500 without leaking a stack trace
// to the client; the stack is logged.
// It also sets the security headers (nosniff, X-Frame-Options DENY,
// Referrer-Policy no-referrer) on every response, errors included; the
// UI-only Content-Security-Policy stays in handleUI. And it injects
// Cache-Control: no-store on every response:
// the API serves live state and, on /api/config/raw, the FULL config —
// the admin password hash — none of which belongs in a
// browser's on-disk cache. /healthz is exempt: it is static and is what
// load balancers poll, where no-store would be noise.
func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if r.URL.Path != "/healthz" {
			h.Set("Cache-Control", "no-store")
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
				// The stack goes to the log only, never to the client.
				s.log.Error("admin handler panic", "err", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
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

// handleStatus, handleCalls, handleConfig, and handleConfigGet
// are implemented in api.go. handleConfigRaw and handleConfigValidate are
// implemented in config_validate.go. handleMetrics is implemented in
// metrics.go. handleUI is implemented in webui.go.

// clock returns the limiter's notion of now.
func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}
