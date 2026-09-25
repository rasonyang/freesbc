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

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	"github.com/freesbc/freesbc/internal/shield"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Server is the SIP signaling front door. It binds the configured
// listeners, identifies inbound requests by transport source IP, answers
// OPTIONS health checks, and hosts the B2BUA bridge for INVITE.
type Server struct {
	store *config.Store
	pool  *media.PlanePool
	log   *slog.Logger

	// callMu guards the one call store (calls.go): calls is every bridged
	// call keyed by its admin ID — the identity the admin API and KillCall
	// use — and legs indexes the SAME *call under EACH leg's own Call-ID,
	// one entry per leg, so an in-dialog request is matched on the full
	// dialog ID (Call-ID plus both tags) and live calls that share a
	// Call-ID coexist. registerCall/endCall are the only writers of both,
	// and they move a call through callState under this one lock. inviting
	// holds the initial INVITEs being handled, for merged-request (482)
	// detection (beginInvite).
	callMu   sync.Mutex
	calls    map[string]*call
	legs     map[string][]legRef
	inviting map[mergeKey]struct{}

	dialogSrv *sipgo.DialogServerCache
	dialogCli *sipgo.DialogClientCache
	registrar *Registrar

	// client is the plane's sipgo client, set once in Run; forkWatch uses
	// it to ACK and BYE forked B-leg answers. forks holds the live
	// forkWatches by (Call-ID, From-tag), under forkMu (see forks.go).
	client *sipgo.Client
	forkMu sync.Mutex
	forks  map[forkKey]*forkWatch

	// refreshAckState tracks the 2xx to refresh re-INVITEs that are being
	// retransmitted until their ACK (sessiontimer.go).
	refreshAckState

	// onBridged, when non-nil, runs right after registerCall publishes a
	// call. Only tests set it (before Run), to exercise recoverCall on a
	// bridged call.
	onBridged func(*call)

	// shield is the front-door security plane: consulted before
	// identify() on every inbound request (see withShield). Built in Run,
	// so it is nil on a *Server constructed directly by unit tests (e.g.
	// NewServer without Run) — withShield nil-guards against that. Stored via atomic.Pointer (rather than a plain field)
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
	// across concurrent calls.
	resolver *Resolver
	health   *endpointHealth

	// warnAutoIPOnce gates advertisedIP's "can't resolve a routable
	// address" warning to a single log line for the life of the process:
	// advertisedIP is called on every INVITE (mediaIP/sigIP's per-call
	// resolution), and without this the same warning would otherwise spam
	// the log once per call.
	warnAutoIPOnce sync.Once

	// TCP/TLS listener resource bounds — see listenerlimit.go.
	// tcpConns counts live connections across every tcp/tls listener; a
	// single shared counter makes the cap global (N listeners can't each
	// admit the full quota). tcpMaxConns is the cap itself and tcpIdleTimeout
	// the per-connection idle read deadline; both are set by NewServer and
	// only tests override them (via startServerConfigured's hook, which runs
	// before the Run goroutine spawns — never a cross-goroutine write).
	// The values may move into config later (deferred).
	tcpConns       atomic.Int64
	tcpMaxConns    int64
	tcpIdleTimeout time.Duration

	// quota counts in-flight initial INVITEs per peer and globally
	// (see callQuota in b2bua.go and bridge.onInvite's gate). The
	// zero value is usable; it needs no Run-time wiring.
	quota callQuota

	// onListening, when non-nil, is called once per listener immediately
	// after its socket is bound and before it is handed to the transport
	// layer. Only tests set it (from startServerAt, before the Run
	// goroutine is spawned, so the write happens-before bindListener's
	// read and -race stays clean); production leaves it nil. It exists
	// because there is no other race-free way for a test to learn that a
	// listener is genuinely up: a UDP "probe dial" succeeds against an
	// address nothing is bound to, so it cannot distinguish a live
	// listener from a bind that failed.
	onListening func(config.SIPListen)
}

func NewServer(store *config.Store, pool *media.PlanePool, log *slog.Logger) *Server {
	return &Server{
		store:    store,
		pool:     pool,
		log:      log,
		calls:    make(map[string]*call),
		legs:     make(map[string][]legRef),
		inviting: make(map[mergeKey]struct{}),
		resolver: newResolver(time.Now().UnixNano()),
		health:   newEndpointHealth(),

		// Defaults (see listenerlimit.go): 1024 concurrent TCP/TLS
		// connections and a 120s idle read deadline per connection.
		tcpMaxConns:    1024,
		tcpIdleTimeout: 120 * time.Second,
	}
}

// IsRegistered reports whether the peer is available to route to as far as
// registration is concerned. It is the single gate behind both the admin
// peer view and the B2BUA's target skip (expandTargets), so the two cannot
// disagree about what "registered" means.
//
// Peers that don't register are always true (there is nothing to wait for)
// — that is Registrar.IsRegistered's rule, and the same answer is given
// before Run has built the registrar at all: no registrar means no
// registration gating, not "every peer is down".
func (s *Server) IsRegistered(name string) bool {
	if s.registrar == nil {
		return true
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

// Unban removes any shield ban on ip and reports whether one existed. Nil-safe: false before Run builds the
// shield. Wired to the admin API's DELETE /api/bans/{ip}.
func (s *Server) Unban(ip netip.Addr) bool {
	sh := s.shield.Load()
	if sh == nil {
		return false
	}
	return sh.Unban(ip)
}

// Run builds the sipgo server, binds every listen.sip entry, and blocks
// until ctx is cancelled. It returns the first fatal listener error (e.g.
// a bind failure), or nil on clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	sipgoLog := s.log.With("caller", "sipgo")
	// Outbound TLS trust anchors/client certs, merged from the
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
			// Drop non-peer source bytes before parsing
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
	s.client = client
	// Forked B-leg 2xx never reach the dialog layer (see forks.go); see
	// every parsed message alongside the transaction layer instead.
	ua.TransportLayer().OnMessage(s.observeMessage)

	// s.shield is built here (not in NewServer) so unit tests that
	// construct a *Server directly (without Run) exercise handlers with a
	// nil shield — see the nil guard in withShield. Close (which stops the
	// prune loop) is deferred immediately: Run's body only returns after
	// the synchronous shutdown tail below, so it fires after every
	// listener has stopped accepting requests.
	sh := shield.New(s.store, s.log)
	defer sh.Close()
	s.shield.Store(sh)

	srv.OnRequest(sip.OPTIONS, s.withShield(s.onOptions))
	srv.OnInvite(s.withShield(s.onInvite))
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
	go func() {
		if err := s.registrar.Run(regCtx); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Debug("registrar stopped", "err", err)
		}
		close(regDone)
	}()

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

// listening notifies the (test-only) onListening hook that l's socket is
// bound. No-op in production, where the hook is nil.
func (s *Server) listening(l config.SIPListen) {
	if s.onListening != nil {
		s.onListening(l)
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
		s.listening(l)
		return tl.ServeTCP(newTCPLimitListener(ln, s))
	case "tls":
		// A CONFIGURED certificate replaces the fallback
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
			conf, err := fsip.SelfSignedTLS("FreeSBC self-signed", nil)
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
		s.listening(l)
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
		s.listening(l)
		return tl.ServeUDP(conn)
	}
}

// identify resolves the peer for an inbound request by its transport
// source address. sipgo sets req.Source() from the real remote socket on
// receive, so this is the trust boundary — never the Via/From host.
func (s *Server) identify(req *sip.Request) (string, *config.Peer, bool) {
	addr, ok := fsip.ParseHostPortAddr(req.Source())
	if !ok {
		return "", nil, false
	}
	return IdentifyPeer(s.store.Current(), addr)
}

// withShield wraps a request handler so every inbound request passes the
// security plane before identification. A Drop verdict silently discards the
// request (no response); sipgo calls tx.TerminateGracefully() right after the
// handler returns, which ends the unfinalized transaction and its auto-100
// timer, so the drop stays silent. Non-peer source bytes
// are dropped by the transport-layer read filter before they can become a
// request (see preParseFilter), so the shield here only ever sees requests
// from allowed sources — configured-peer exemptions apply. s.shield is nil on
// a *Server built directly by unit tests (without Run), so this is
// nil-guarded to a no-op in that case.
func (s *Server) withShield(next func(*sip.Request, sip.ServerTransaction)) func(*sip.Request, sip.ServerTransaction) {
	return func(req *sip.Request, tx sip.ServerTransaction) {
		// ONE panic umbrella for every handler path — a panic
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
				if err := tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Internal Error", nil)); err != nil {
					s.log.Debug("respond 500 after panic", "err", err, "method", req.Method.String())
				}
			}
		}()
		sh := s.shield.Load()
		src, ok := fsip.ParseHostPortAddr(req.Source())
		if sh != nil && ok && sh.Check(src, fsip.UserAgent(req), sip.NetworkToLower(req.Transport())) == shield.Drop {
			return // silent
		}
		next(req, tx)
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
//     (not "auto").
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
		return // unidentified source: silent drop
	}
	if err := tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil)); err != nil {
		s.log.Error("respond OPTIONS", "peer", name, "err", err)
	}
}

// onAck routes an in-dialog ACK to the dialog-server cache so sipgo's
// dialog layer can transition the A-leg dialog to confirmed. INVITEs we
// reject before ReadInvite (404s) have no dialog registered, so
// ReadAck's "no such dialog" case is expected and merely logged.
func (s *Server) onAck(req *sip.Request, tx sip.ServerTransaction) {
	if _, _, ok := s.identify(req); !ok {
		return // unidentified source: silent drop
	}
	// The ACK for a 2xx to a locally answered refresh re-INVITE stops that
	// 2xx's retransmission; it belongs to no dialog-cache transaction.
	if s.ackReceived(req) {
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
// silently dropped — this is not the "unknown source" shield (the
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
		return // unidentified source: silent drop
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
// first: unknown sources get silence, known peers get a normal 405 for any
// method this plane doesn't implement. (The trunk plane never acts as a
// registrar — its Registrar is the outbound REGISTER client — so inbound
// REGISTER belongs here too.)
func (s *Server) onNoRoute(req *sip.Request, tx sip.ServerTransaction) {
	name, _, ok := s.identify(req)
	if !ok {
		return // unidentified source: silent drop
	}
	// A CANCEL only reaches a handler when sipgo's transaction layer found
	// no INVITE transaction for it to cancel: that is 481 (RFC 3261 §9.2),
	// not 405 — CANCEL itself is supported.
	if req.Method == sip.CANCEL {
		if err := tx.Respond(sip.NewResponseFromRequest(req, 481, "Call/Transaction Does Not Exist", nil)); err != nil {
			s.log.Error("respond 481 cancel", "peer", name, "err", err)
		}
		return
	}
	s.log.Debug("method not implemented", "peer", name, "method", req.Method.String())
	// A 405 MUST list the methods we do support (RFC 3261 §21.4.6).
	res := sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
	res.AppendHeader(sip.NewHeader("Allow", allowedMethods))
	if err := tx.Respond(res); err != nil {
		s.log.Error("respond 405", "peer", name, "err", err)
	}
}

// allowedMethods is the Allow list for this plane's 405s: the methods with a
// handler, plus CANCEL, which sipgo's transaction layer answers.
const allowedMethods = "INVITE, ACK, BYE, CANCEL, OPTIONS"
