package trunk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/call"
	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	"github.com/freesbc/freesbc/internal/shield"
)

// Server is the SIP signaling front door. It binds the configured
// listeners, identifies inbound requests by transport source IP, answers
// OPTIONS health checks, and (M3.3) hosts the B2BUA bridge for INVITE.
type Server struct {
	store *config.Store
	pool  *media.Pool
	log   *slog.Logger

	registry *call.Registry

	// sdps remembers each established call LEG's SDP pair (Task 6 fix
	// wave), keyed by that leg's own Call-ID — see callSDPStore and
	// callSDP. Kept separate from registry: package call must stay
	// dependency-free of sig/SDP.
	sdps *callSDPStore

	client    *sipgo.Client
	dialogSrv *sipgo.DialogServerCache
	dialogCli *sipgo.DialogClientCache
	br        *bridge
	registrar *Registrar

	// shield is the front-door security plane (M6): consulted before
	// identify() on every inbound request (see withShield). Built in Run,
	// so it is nil on a *Server constructed directly by unit tests (e.g.
	// NewServer without Run) — withShield and dropUnidentified nil-guard
	// against that. Stored via atomic.Pointer (rather than a plain field)
	// because integration tests deliberately reach into it from the test
	// goroutine (srv.shield.Load().Check(...)) after Run has started on its
	// own goroutine — a plain field there would be an unsynchronized
	// cross-goroutine access (no happens-before edge exists between Run's
	// assignment and a test goroutine merely polling the listener socket for
	// readiness), which the race detector correctly flags.
	shield atomic.Pointer[shield.Shield]

	// resolver turns a peer into ordered dialable endpoints (DNS SRV with
	// A/AAAA fallback, priority/weight); health tracks per-endpoint cooldowns
	// after connect failures. Both are internally synchronized and shared
	// across concurrent calls. (M4.4)
	resolver *Resolver
	health   *endpointHealth

	// warnAutoIPOnce gates advertisedIP's "can't resolve a routable
	// address" warning to a single log line for the life of the process:
	// advertisedIP is called on every INVITE (mediaIP/sigIP's per-call
	// resolution), and without this the same warning would otherwise spam
	// the log once per call.
	warnAutoIPOnce sync.Once

	// killMu guards killers: the admin kick-call mechanism (KillCall). Each
	// live call's onInvite goroutine registers its own killCtx cancel func
	// under the A-leg Call-ID right after adding itself to the registry, and
	// unregisters it (via defer) when the call ends. Kept separate from
	// registry: killers holds a context.CancelFunc, not call metadata.
	killMu  sync.Mutex
	killers map[string]context.CancelFunc // Call-ID → cancel its killCtx

	// T-05 (F-02) TCP/TLS listener resource bounds — see listenerlimit.go.
	// tcpConns counts live connections across every tcp/tls listener; a
	// single shared counter makes the cap global (N listeners can't each
	// admit the full quota). tcpMaxConns is the cap itself and tcpIdleTimeout
	// the per-connection idle read deadline; both are set by NewServer and
	// only tests override them (via startServerConfigured's hook, which runs
	// before the Run goroutine spawns — never a cross-goroutine write).
	// The values may move into config later (REMEDIATION-PLAN T-05 defers
	// that).
	tcpConns       atomic.Int64
	tcpMaxConns    int64
	tcpIdleTimeout time.Duration

	// quota counts in-flight initial INVITEs per peer and globally (T-06,
	// F-06 — see callQuota in b2bua.go and bridge.onInvite's gate). The
	// zero value is usable; it needs no Run-time wiring.
	quota callQuota
}

func NewServer(store *config.Store, pool *media.Pool, log *slog.Logger) *Server {
	return &Server{
		store:    store,
		pool:     pool,
		log:      log,
		registry: call.NewRegistry(),
		sdps:     newCallSDPStore(),
		resolver: newResolver(time.Now().UnixNano()),
		health:   newEndpointHealth(),
		killers:  make(map[string]context.CancelFunc),

		// T-05 defaults (see listenerlimit.go): 1024 concurrent TCP/TLS
		// connections and a 120s idle read deadline per connection.
		tcpMaxConns:    1024,
		tcpIdleTimeout: 120 * time.Second,
	}
}

// registerKiller records cancel as the way to kick the live call with the
// given (A-leg) Call-ID — called once, right after the call is added to the
// registry (see bridge.onInvite).
func (s *Server) registerKiller(id string, cancel context.CancelFunc) {
	s.killMu.Lock()
	s.killers[id] = cancel
	s.killMu.Unlock()
}

// unregisterKiller removes id's kill-cancel entry — called (via defer) when
// the call ends, however it ends, so KillCall never targets a stale entry.
func (s *Server) unregisterKiller(id string) {
	s.killMu.Lock()
	delete(s.killers, id)
	s.killMu.Unlock()
}

// KillCall tears down the live call with the given A-leg Call-ID by
// cancelling its kill context (the onInvite goroutine then BYEs both legs
// via the normal teardown — see byeBoth). Returns false if no such active
// call is tracked. Idempotent: cancelling an already-cancelled
// context.CancelFunc is a safe no-op, and unregisterKiller removes the
// entry once the call actually ends, so a second call for the same id (or
// one racing a natural end) returns false rather than firing twice.
func (s *Server) KillCall(id string) bool {
	s.killMu.Lock()
	cancel, ok := s.killers[id]
	s.killMu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// callSDP returns callID's established SDP pair (see callSDP), or ok=false
// if there is no established call leg on record for it.
func (s *Server) callSDP(callID string) (callSDP, bool) {
	return s.sdps.get(callID)
}

// ActiveCalls returns the number of calls currently tracked in the call
// registry, for metrics.
func (s *Server) ActiveCalls() int { return s.registry.Count() }

// IsRegistered reports whether the peer is currently registered (nil-safe:
// false before Run builds the registrar).
func (s *Server) IsRegistered(name string) bool {
	if s.registrar == nil {
		return false
	}
	return s.registrar.IsRegistered(name)
}

// ShieldStats returns the current shield activity snapshot (nil-safe: zero
// value before Run builds the shield).
func (s *Server) ShieldStats() shield.Stats {
	sh := s.shield.Load()
	if sh == nil {
		return shield.Stats{DropsByReason: map[string]int64{}}
	}
	return sh.Stats()
}

// Unban removes any shield ban on ip (in-memory table + kernel set) and
// reports whether one existed. Nil-safe: false before Run builds the
// shield. Wired to the admin API's DELETE /api/bans/{ip} (T-02, F-04).
func (s *Server) Unban(ip netip.Addr) bool {
	sh := s.shield.Load()
	if sh == nil {
		return false
	}
	return sh.Unban(ip)
}

// Calls returns a snapshot of the active-call registry (for the admin API).
func (s *Server) Calls() []call.Record { return s.registry.Snapshot() }

// Run builds the sipgo server, binds every listen.sip entry, and blocks
// until ctx is cancelled. It returns the first fatal listener error (e.g.
// a bind failure), or nil on clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	sipgoLog := s.log.With("caller", "sipgo")
	// T-17 (F-13): outbound TLS trust anchors/client certs, merged from the
	// per-peer config into sipgo's single UA-wide tls.Config (see
	// buildClientTLSConfig). Built once at startup — cert material is not
	// hot-rotated.
	clientTLS, err := buildClientTLSConfig(s.store.Current().Peers)
	if err != nil {
		return fmt.Errorf("client tls config: %w", err)
	}
	uaOpts := []sipgo.UserAgentOption{
		sipgo.WithUserAgentTransportLayerOptions(
			sip.WithTransportLayerLogger(sipgoLog),
			// T-01 (F-01/F-10): drop non-peer source bytes before parsing
			// (see preParseFilter in readfilter.go).
			sip.WithTransportLayerReadFilter(s.preParseFilter()),
		),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(sipgoLog)),
	}
	if clientTLS != nil {
		uaOpts = append(uaOpts, sipgo.WithUserAgenTLSConfig(clientTLS))
	}
	ua, err := sipgo.NewUA(uaOpts...)
	if err != nil {
		return fmt.Errorf("sipgo ua: %w", err)
	}
	defer ua.Close()
	srv, err := sipgo.NewServer(ua, sipgo.WithServerLogger(sipgoLog))
	if err != nil {
		return fmt.Errorf("sipgo server: %w", err)
	}

	client, err := sipgo.NewClient(ua)
	if err != nil {
		return fmt.Errorf("sipgo client: %w", err)
	}
	defer client.Close()
	s.client = client

	cfg := s.store.Current()
	listeners := cfg.Listeners()
	// The Contact host must be an address the far side can actually reach —
	// see sigIP: same resolution (sip.advertised_ip, else the public_ip
	// literal, else a non-unspecified listen.sip host) so a Contact built
	// from listeners[0]'s raw host (which may be 0.0.0.0 when listening on
	// all interfaces) doesn't advertise an unroutable sip:0.0.0.0:port.
	// The port is the advertised signaling port for listeners[0]'s
	// transport (sip.advertised_port when configured), never a hardcoded
	// 5060. Resolved once here from the config Run started with;
	// hot-reloaded changes to advertised/listener settings don't
	// retroactively update this cached Contact (mediaIP/sigIP's per-call
	// uses, by contrast, are resolved fresh from the current config). The
	// len guard mirrors the pre-existing listeners[0] guard: validated
	// configs always have at least one listener, but a *Server built
	// directly by tests (without Parse) may have none.
	var contact sip.ContactHeader
	if len(listeners) > 0 {
		contact = sip.ContactHeader{Address: sip.Uri{Host: s.sigIP(cfg).String(), Port: s.ourSigPort(cfg, listeners[0].Transport)}}
	}
	s.dialogSrv = sipgo.NewDialogServerCache(client, contact)
	s.dialogCli = sipgo.NewDialogClientCache(client, contact)
	s.br = &bridge{s: s}

	// s.shield is built here (not in NewServer) so unit tests that
	// construct a *Server directly (without Run) exercise handlers with a
	// nil shield — see the nil guards in withShield/dropUnidentified.
	// Close is deferred immediately: Run's body only returns after the
	// synchronous shutdown tail below (registrar drained, then listener
	// sockets closed, then their goroutines joined via wg.Wait()), so this
	// defer necessarily fires after every listener has stopped accepting
	// requests — never while an in-flight Check/RecordUnidentified could
	// still race the nftables teardown.
	sh := shield.New(s.store, s.log)
	defer sh.Close()
	s.shield.Store(sh)

	srv.OnRequest(sip.OPTIONS, s.withShield(s.onOptions))
	srv.OnInvite(s.withShield(s.br.onInvite))
	srv.OnAck(s.withShield(s.onAck))
	srv.OnBye(s.withShield(s.onBye))
	srv.OnNoRoute(s.withShield(s.onNoRoute))

	// Shutdown sequencing (deliberately NOT one shared ctx for the registrar
	// and the listeners): in sipgo, a UDP listener's connection is pooled
	// under every remote addr it has received a packet from, and an
	// outbound request from the same UA/transport REUSES that pooled conn
	// (connectionReuse default true). So once a real carrier has sent us
	// inbound traffic (e.g. an OPTIONS keepalive) on a listener, the
	// registrar's shutdown Expires:0 un-REGISTER to that same carrier is
	// exactly the kind of outbound request that can land on the pooled
	// listener conn. If the listener socket closes CONCURRENTLY with that
	// un-REGISTER (as it did when both watched one shared ctx), the
	// un-REGISTER can route onto the just-closed socket and fail with
	// net.ErrClosed — defeating spec Decision #3 (clean shutdown
	// un-register) against exactly the carriers it matters most for.
	//
	// The fix: give the registrar and the listeners independent contexts,
	// rooted below (not derived from one another, and NOT children of the
	// same WithCancel — a child automatically cancels when its parent does,
	// which would reintroduce the same race the instant the caller's ctx is
	// cancelled). stopCh is the single "begin shutdown" trigger — fired by
	// either the caller cancelling ctx or a fatal listener bind failure —
	// and its only job is to kick off a strictly ordered tail: cancel the
	// registrar and wait for it to finish (un-REGISTERing while every
	// listener socket is still open), THEN cancel the listeners (closing
	// their sockets), THEN wait for their goroutines to actually exit.
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(stopCh) }) }
	// Watch the caller's ctx, but also exit when shutdown was triggered some
	// other way (e.g. a fatal bind failure closing stopCh) so this goroutine
	// can't park forever if the caller never cancels ctx.
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-stopCh:
		}
	}()

	regCtx, regCancel := context.WithCancel(context.Background())
	defer regCancel()
	listenCtx, listenCancel := context.WithCancel(context.Background())
	defer listenCancel()

	s.registrar = NewRegistrar(s.store, client, s, s.log)
	regDone := make(chan struct{})
	go func() { _ = s.registrar.Run(regCtx); close(regDone) }()

	errs := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for _, l := range listeners {
		l := l
		addr := net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
		wg.Add(1)
		go func() {
			defer wg.Done()
			lerr := s.bindListener(listenCtx, srv, l, addr)
			if lerr != nil && listenCtx.Err() == nil {
				errs <- fmt.Errorf("listen %s://%s: %w", l.Transport, addr, lerr)
				stop()
			}
		}()
	}
	s.log.Info("sip server listening", "listeners", len(listeners))

	<-stopCh
	// Registrar first: every un-REGISTER attempt completes (success or its
	// own bounded 2s timeout) while listener sockets are still open.
	regCancel()
	<-regDone
	// Only now is it safe to close the listener sockets.
	listenCancel()
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

// bindListener opens the raw socket/listener for l, drives it through
// sipgo's transport layer, and closes it when ctx is cancelled. It blocks
// until the listener stops (error, or ctx cancellation unblocking the
// read/accept loop via the closed handle).
//
// This deliberately bypasses sipgo's Server.ListenAndServe /
// ListenAndServeTLS convenience wrappers: as of sipgo v1.4.3 they close
// their internal listener from a bare io.Closer variable ("connCloser")
// written by the Serve call and read by a separate shutdown-watcher
// goroutine with no synchronization between the two — the race detector
// correctly flags this as a data race on every graceful (ctx-cancel)
// shutdown (verified against v1.4.3 source, github.com/emiago/sipgo/server.go).
// sipgo's own Server.Close is a no-op and TransportLayer.Close explicitly
// documents "closing listeners is caller thing", so there is no race-free
// shutdown hook exposed by the high-level API. Opening the socket
// ourselves and closing that handle from a small watcher goroutine
// reproduces the same behavior with a clean happens-before edge: the
// listener handle is fully constructed before the watcher goroutine is
// spawned, and nothing else writes it afterward.
func (s *Server) bindListener(ctx context.Context, srv *sipgo.Server, l config.SIPListen, addr string) error {
	tl := srv.TransportLayer()
	switch l.Transport {
	case "tcp":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); ln.Close() }()
		return tl.ServeTCP(newTCPLimitListener(ln, s))
	case "tls":
		// T-17 (F-13): a CONFIGURED certificate replaces the fallback
		// self-signed one — clients (or our own outbound side, with a
		// matching trust anchor) can then verify this listener for real.
		// mTLS engages when tls_client_ca is set. Read at bind time from
		// the startup config; cert material is not hot-rotated.
		cfg := s.store.Current()
		var tlsConf *tls.Config
		if cfg.Listen.TLSCert != "" {
			conf, err := loadServerTLSConfig(cfg.Listen.TLSCert, cfg.Listen.TLSKey, cfg.Listen.TLSClientCA)
			if err != nil {
				return err
			}
			tlsConf = conf
		} else {
			conf, err := selfSignedTLSConfig()
			if err != nil {
				return err
			}
			tlsConf = conf
			s.log.Warn("TLS listener using self-signed certificate", "addr", addr)
		}
		ln, err := tls.Listen("tcp", addr, tlsConf)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); ln.Close() }()
		return tl.ServeTLS(newTCPLimitListener(ln, s))
	default: // "udp"
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); conn.Close() }()
		return tl.ServeUDP(conn)
	}
}

// identify resolves the peer for an inbound request by its transport
// source address. sipgo sets req.Source() from the real remote socket on
// receive, so this is the trust boundary — never the Via/From host.
func (s *Server) identify(req *sip.Request) (string, *config.Peer, bool) {
	addr, ok := sourceAddr(req)
	if !ok {
		return "", nil, false
	}
	return IdentifyPeer(s.store.Current(), addr)
}

// withShield wraps a request handler so every inbound request passes the
// security plane before identification. A Drop verdict silently discards the
// request (no response); sipgo terminates the unfinalized transaction when the
// handler returns (see dropUnidentified). Since T-01, non-peer source bytes
// are dropped by the transport-layer read filter before they can become a
// request (see preParseFilter), so the shield here only ever sees requests
// from allowed sources — configured-peer exemptions apply. s.shield is nil on
// a *Server built directly by unit tests (without Run), so this is
// nil-guarded to a no-op in that case.
func (s *Server) withShield(next func(*sip.Request, sip.ServerTransaction)) func(*sip.Request, sip.ServerTransaction) {
	return func(req *sip.Request, tx sip.ServerTransaction) {
		// T-20 (D1-8): ONE panic umbrella for every handler path — a panic
		// anywhere in handler code (onOptions/onAck/onBye/onNoRoute and the
		// sipgo dialog code they call) kills only this request, never the
		// process, and leaves a forensic trace. onInvite additionally keeps
		// its own recoverCall (call-ID-annotated); the inner recover runs
		// first and this one simply never sees its panics.
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("sip handler panic",
					"panic", r, "stack", string(debug.Stack()), "method", req.Method.String())
				// Best-effort 500 — the transaction may already be gone.
				_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Internal Error", nil))
			}
		}()
		sh := s.shield.Load()
		src, ok := sourceAddr(req)
		if sh != nil && ok && sh.Check(src, userAgent(req), sip.NetworkToLower(req.Transport())) == shield.Drop {
			return // silent
		}
		next(req, tx)
	}
}

// sourceAddr parses the transport source of req into a netip.Addr. sipgo
// sets req.Source() from the real remote socket on receive, so this is the
// trust boundary — never the Via/From host.
func sourceAddr(req *sip.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(req.Source())
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// userAgent returns req's User-Agent header value, or "" if absent.
func userAgent(req *sip.Request) string {
	hs := req.GetHeaders("User-Agent")
	if len(hs) == 0 {
		return ""
	}
	return hs[0].Value()
}

// dropUnidentified is the shield seam (M6): a request from a source that
// matches no peer is silently dropped (spec §6 step 2). No response is
// sent; sipgo calls tx.TerminateGracefully() immediately after the handler
// returns (server.go handleRequest), which terminates the unfinalized
// transaction right away — stopping its auto-100 timer and keeping the
// drop silent instead of merely letting the transaction age out.
//
// Since T-01 this handler never runs for udp/tcp/tls traffic: the
// pre-parse read filter drops non-peer bytes before parsing, so no such
// request can reach identify() over the wire. It remains as the guard for
// any future transport path that bypasses the filter, and for *Server
// instances unit tests build directly.
func (s *Server) dropUnidentified(req *sip.Request) {
	s.log.Info("dropping request from unidentified source",
		"method", req.Method.String(), "source", req.Source())
	// Feed the shield's auto-ban failure counter so repeated unidentified
	// traffic from the same source eventually bans it (spec §3). Nil-guarded:
	// unit tests build a *Server directly (without Run), where s.shield is nil.
	if sh := s.shield.Load(); sh != nil {
		if src, ok := sourceAddr(req); ok {
			sh.RecordUnidentified(src)
		}
	}
}

// advertisedIP resolves an IP the SBC advertises as its own to the outside
// world, preferring `preferred` — the NAT/VPN advertised address
// (sip.advertised_ip or rtp.advertised_ip) when configured. Resolution
// order:
//
//  1. `preferred`, when set and a valid IP (validation guarantees it is not
//     unspecified — advertising 0.0.0.0/:: would be unroutable/a blackhole).
//  2. The configured listen.media.public_ip, when it is a literal address
//     (not "auto" — STUN-based discovery for "auto" is a later milestone).
//  3. Otherwise, the first listen.sip host that is NOT unspecified (0.0.0.0
//     / ::): a listener commonly binds every interface (0.0.0.0) while the
//     SBC still has one real, routable address to advertise, so an
//     unspecified listener host is skipped rather than handed to the far
//     side.
//  4. If every listen.sip host is itself unspecified (or there are none),
//     fall back to 127.0.0.1 and log a warning — once per process
//     (warnAutoIPOnce), not per call, since this is called on every INVITE.
func (s *Server) advertisedIP(cfg *config.Config, preferred string) netip.Addr {
	if preferred != "" {
		if ip, err := netip.ParseAddr(preferred); err == nil {
			return ip
		}
	}
	if pub := cfg.Listen.Media.PublicIP; pub != "auto" {
		if ip, err := netip.ParseAddr(pub); err == nil {
			return ip
		}
	}
	for _, l := range cfg.Listen.SIP {
		if ip, err := netip.ParseAddr(l.Host); err == nil && !ip.IsUnspecified() {
			return ip
		}
	}
	s.warnAutoIPOnce.Do(func() {
		s.log.Warn("no advertised address configured (sip/rtp advertised_ip unset, listen.media.public_ip is auto — STUN discovery isn't implemented yet) and no listen.sip host is a specific, routable address; falling back to 127.0.0.1 — SDP media and the Contact header will be unroutable from any other host")
	})
	return netip.MustParseAddr("127.0.0.1")
}

// sigIP is the IP advertised in externally visible signaling (Contact,
// From, REGISTER Contact): sip.advertised_ip when configured, else the
// legacy resolution chain (see advertisedIP).
func (s *Server) sigIP(cfg *config.Config) netip.Addr {
	return s.advertisedIP(cfg, cfg.SIP.AdvertisedIP)
}

// mediaIP is the IP advertised in SDP (o= and c=): rtp.advertised_ip when
// configured, else the legacy resolution chain. Called once per bridged
// INVITE (see bridge.onInvite), it re-resolves from cfg each time so a
// hot-reloaded advertised address takes effect on the next call without
// restarting the process.
func (s *Server) mediaIP(cfg *config.Config) netip.Addr {
	return s.advertisedIP(cfg, cfg.RTP.AdvertisedIP)
}

// ourSigPort returns the port we advertise for our signaling on the given
// transport: sip.advertised_port when the sip bind/advertised topology is
// configured, else the first matching listen.sip port, else the first
// listener's port — mirrors the Contact-port resolution Run does once at
// startup (see the contact comment above), but re-resolved per call /
// per-target so it tracks whichever transport the B-leg is actually being
// placed on. Validation guarantees at least one listener (listen.sip or
// sip.bind_ip), so a parsed Config never falls through to the zero return;
// 0 only serves Configs built directly by unit tests without Parse. There
// is deliberately no 5060 fallback: the configured ports are the source of
// truth.
func (s *Server) ourSigPort(cfg *config.Config, transport string) int {
	if cfg.SIP.AdvertisedPort > 0 {
		return cfg.SIP.AdvertisedPort
	}
	for _, l := range cfg.Listen.SIP {
		if l.Transport == transport {
			return l.Port
		}
	}
	if len(cfg.Listen.SIP) > 0 {
		return cfg.Listen.SIP[0].Port
	}
	return 0
}

func (s *Server) onOptions(req *sip.Request, tx sip.ServerTransaction) {
	name, _, ok := s.identify(req)
	if !ok {
		s.dropUnidentified(req)
		return
	}
	if err := tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil)); err != nil {
		s.log.Error("respond OPTIONS", "peer", name, "err", err)
	}
}

// onAck routes an in-dialog ACK to the dialog-server cache so sipgo's
// dialog layer can transition the A-leg dialog to confirmed. INVITEs we
// reject before ReadInvite (Task 5's 404s) have no dialog registered, so
// ReadAck's "no such dialog" case is expected and merely logged.
func (s *Server) onAck(req *sip.Request, tx sip.ServerTransaction) {
	if _, _, ok := s.identify(req); !ok {
		s.dropUnidentified(req)
		return
	}
	if err := s.dialogSrv.ReadAck(req, tx); err != nil {
		s.log.Debug("dialog ack", "err", err, "source", req.Source())
	}
}

// onBye routes an in-dialog BYE to whichever dialog cache owns it: the
// A-leg (we are the UAS, dialogSrv) or the B-leg (we are the UAC,
// dialogCli). Exactly one of the two caches will recognize the dialog.
//
// If NEITHER does, the BYE matches no call we know about and must be
// answered 481 Call/Transaction Does Not Exist (RFC 3261 §15) rather than
// silently dropped — this is not the M3.1 "unknown source" shield (the
// peer IS known; its BYE just doesn't correspond to anything). Both
// ReadBye implementations (dialog_server.go/dialog_client.go) only ever
// call tx.Respond after their own dialog lookup succeeds, so when
// noMatchingDialog is true for BOTH, neither cache has responded to tx
// yet — the 481 below is the only response sent, never a double-send. Any
// OTHER error (e.g. sipgo.ErrDialogInvalidCseq on a dialog that WAS found)
// is left exactly as before: merely logged, since a 481 would misreport
// that no dialog exists when one actually does.
func (s *Server) onBye(req *sip.Request, tx sip.ServerTransaction) {
	if _, _, ok := s.identify(req); !ok {
		s.dropUnidentified(req)
		return
	}
	srvErr := s.dialogSrv.ReadBye(req, tx)
	if srvErr == nil {
		return
	}
	cliErr := s.dialogCli.ReadBye(req, tx)
	if cliErr == nil {
		return
	}
	if noMatchingDialog(srvErr) && noMatchingDialog(cliErr) {
		if err := tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil)); err != nil {
			s.log.Error("respond 481 bye", "err", err, "source", req.Source())
		}
		return
	}
	s.log.Debug("dialog bye", "srvErr", srvErr, "cliErr", cliErr, "source", req.Source())
}

// noMatchingDialog reports whether err is one of sipgo's two "this request
// doesn't correspond to any dialog we have" sentinels:
// sipgo.ErrDialogDoesNotExists (a valid dialog ID was computed but nothing
// is stored under it) or sipgo.ErrDialogOutsideDialog (the request itself
// is missing a tag needed to even compute an ID — see
// sip.DialogIDFromRequestUAS/UAC). Both mean the same thing from onBye's
// perspective: no dialog owns this BYE. This is distinct from e.g.
// sipgo.ErrDialogInvalidCseq, which means a dialog WAS found but this
// particular request is invalid against it — that must never trip the 481
// path.
func noMatchingDialog(err error) bool {
	return errors.Is(err, sipgo.ErrDialogDoesNotExists) || errors.Is(err, sipgo.ErrDialogOutsideDialog)
}

// onNoRoute is sipgo's catch-all for every SIP method without a dedicated
// handler (REGISTER, BYE, SUBSCRIBE, MESSAGE, ...). Without this override,
// sipgo's default no-route handler replies "405 Method Not Allowed" before
// ever calling identify(), which would let an unauthorized source detect
// the SBC's existence — defeating the "silently drop unknown sources"
// guarantee (spec §6 step 2). Every method must pass through identify()
// first: unknown sources get silence, known peers get a normal 405 until
// M3.3/M4 add dialog and REGISTER support for their respective methods.
func (s *Server) onNoRoute(req *sip.Request, tx sip.ServerTransaction) {
	name, _, ok := s.identify(req)
	if !ok {
		s.dropUnidentified(req)
		return
	}
	s.log.Debug("method not implemented", "peer", name, "method", req.Method.String())
	if err := tx.Respond(sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)); err != nil {
		s.log.Error("respond 405", "peer", name, "err", err)
	}
}
