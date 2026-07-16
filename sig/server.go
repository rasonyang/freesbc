package sig

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/callstate"
	"github.com/freesbc/freesbc/config"
	"github.com/freesbc/freesbc/media"
)

// Server is the SIP signaling front door. It binds the configured
// listeners, identifies inbound requests by transport source IP, answers
// OPTIONS health checks, and (M3.3) hosts the B2BUA bridge for INVITE.
type Server struct {
	store *config.Store
	pool  *media.Pool
	log   *slog.Logger

	registry *callstate.Registry

	client    *sipgo.Client
	dialogSrv *sipgo.DialogServerCache
	dialogCli *sipgo.DialogClientCache
	br        *bridge
	registrar *Registrar

	// warnAutoIPOnce gates ourIP's "can't resolve a routable address"
	// warning to a single log line for the life of the process: ourIP is
	// called on every INVITE (mediaIP's per-call SDP rewrite), and without
	// this the same warning would otherwise spam the log once per call.
	warnAutoIPOnce sync.Once
}

func NewServer(store *config.Store, pool *media.Pool, log *slog.Logger) *Server {
	return &Server{
		store:    store,
		pool:     pool,
		log:      log,
		registry: callstate.NewRegistry(),
	}
}

// ActiveCalls returns the number of calls currently tracked in the call
// registry, for metrics.
func (s *Server) ActiveCalls() int { return s.registry.Count() }

// Run builds the sipgo server, binds every listen.sip entry, and blocks
// until ctx is cancelled. It returns the first fatal listener error (e.g.
// a bind failure), or nil on clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	sipgoLog := s.log.With("caller", "sipgo")
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(sipgoLog)),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(sipgoLog)),
	)
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
	listeners := cfg.Listen.SIP
	contactPort := 5060
	if len(listeners) > 0 {
		contactPort = listeners[0].Port
	}
	// The Contact host must be an address the far side can actually reach —
	// see ourIP: same resolution (public_ip literal, else a non-unspecified
	// listen.sip host) as the SDP media IP, so a Contact built from
	// listeners[0]'s raw host (which may be 0.0.0.0 when listening on all
	// interfaces) doesn't advertise an unroutable sip:0.0.0.0:port. Resolved
	// once here from the config Run started with; hot-reloaded changes to
	// public_ip/listeners don't retroactively update this cached Contact
	// (mediaIP/ourIP's SDP-facing use, by contrast, is resolved fresh per
	// call from the current config).
	contact := sip.ContactHeader{Address: sip.Uri{Host: s.ourIP(cfg).String(), Port: contactPort}}
	s.dialogSrv = sipgo.NewDialogServerCache(client, contact)
	s.dialogCli = sipgo.NewDialogClientCache(client, contact)
	s.br = &bridge{s: s}

	srv.OnRequest(sip.OPTIONS, s.onOptions)
	srv.OnInvite(s.br.onInvite)
	srv.OnAck(s.onAck)
	srv.OnBye(s.onBye)
	srv.OnNoRoute(s.onNoRoute)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The Registrar shares this same ctx: a fatal listener bind failure
	// (which also cancels ctx, above) stops it just like a normal shutdown
	// would, rather than leaving outbound REGISTERs running against a
	// server that never came up. Run blocks on <-ctx.Done() below before
	// ever reaching this function's defers, so by the time the deferred
	// wait on regDone executes, ctx is already cancelled and the registrar
	// goroutine is already unwinding (or done) — the un-REGISTER on every
	// registered peer completes before Run returns.
	s.registrar = NewRegistrar(s.store, client, s, s.log)
	regDone := make(chan struct{})
	go func() { _ = s.registrar.Run(ctx); close(regDone) }()
	defer func() { <-regDone }()

	errs := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for _, l := range listeners {
		l := l
		addr := net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
		wg.Add(1)
		go func() {
			defer wg.Done()
			lerr := s.bindListener(ctx, srv, l, addr)
			if lerr != nil && ctx.Err() == nil {
				errs <- fmt.Errorf("listen %s://%s: %w", l.Transport, addr, lerr)
				cancel()
			}
		}()
	}
	s.log.Info("sip server listening", "listeners", len(listeners))

	<-ctx.Done()
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
		return tl.ServeTCP(ln)
	case "tls":
		tlsConf, err := selfSignedTLSConfig()
		if err != nil {
			return err
		}
		s.log.Warn("TLS listener using self-signed certificate", "addr", addr)
		ln, err := tls.Listen("tcp", addr, tlsConf)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); ln.Close() }()
		return tl.ServeTLS(ln)
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
	host, _, err := net.SplitHostPort(req.Source())
	if err != nil {
		return "", nil, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", nil, false
	}
	return IdentifyPeer(s.store.Current(), addr)
}

// dropUnidentified is the shield seam (M6): a request from a source that
// matches no peer is silently dropped (spec §6 step 2). No response is
// sent; sipgo calls tx.TerminateGracefully() immediately after the handler
// returns (server.go handleRequest), which terminates the unfinalized
// transaction right away — stopping its auto-100 timer and keeping the
// drop silent instead of merely letting the transaction age out.
func (s *Server) dropUnidentified(req *sip.Request) {
	s.log.Info("dropping request from unidentified source",
		"method", req.Method.String(), "source", req.Source())
}

// ourIP resolves the IP the SBC advertises as its own to the outside world:
// the media IP rewritten into SDP (mediaIP's per-call use, below) and the
// dialog Contact host built in Run. Resolution order:
//
//  1. The configured public_ip, when it is a literal address (not "auto" —
//     STUN-based discovery for "auto" is a later milestone).
//  2. Otherwise, the first listen.sip host that is NOT unspecified (0.0.0.0
//     / ::): a listener commonly binds every interface (0.0.0.0) while the
//     SBC still has one real, routable address to advertise, so an
//     unspecified listener host is skipped rather than handed to the far
//     side — advertising 0.0.0.0 in SDP is a media blackhole, and in a
//     Contact header is unroutable.
//  3. If every listen.sip host is itself unspecified (or there are none),
//     fall back to 127.0.0.1 and log a warning — once per process
//     (warnAutoIPOnce), not per call, since this is called on every INVITE.
func (s *Server) ourIP(cfg *config.Config) netip.Addr {
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
		s.log.Warn("listen.media.public_ip is auto (STUN discovery isn't implemented yet) and no listen.sip host is a specific, routable address; falling back to 127.0.0.1 — SDP media and the Contact header will be unroutable from any other host")
	})
	return netip.MustParseAddr("127.0.0.1")
}

// ourSigPort returns our listening port for the given transport (the first
// matching listen.sip entry), or the first listener's port as a fallback —
// mirrors the Contact-port resolution Run does once at startup (see the
// contactPort comment above), but re-resolved per call/per-target so it
// tracks whichever transport the B-leg is actually being placed on.
func (s *Server) ourSigPort(cfg *config.Config, transport string) int {
	for _, l := range cfg.Listen.SIP {
		if l.Transport == transport {
			return l.Port
		}
	}
	if len(cfg.Listen.SIP) > 0 {
		return cfg.Listen.SIP[0].Port
	}
	return 5060
}

// mediaIP is ourIP's per-call entry point for the SDP media address: called
// once per bridged INVITE (see bridge.onInvite), it re-resolves from cfg
// each time so a hot-reloaded public_ip takes effect on the next call
// without restarting the process.
func (s *Server) mediaIP(cfg *config.Config) netip.Addr {
	return s.ourIP(cfg)
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
