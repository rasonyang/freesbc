package sig

import (
	"context"
	"crypto/tls"
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

	listeners := s.store.Current().Listen.SIP
	contact := sip.ContactHeader{Address: sip.Uri{Host: "127.0.0.1", Port: 5060}}
	if len(listeners) > 0 {
		contact.Address = sip.Uri{Host: listeners[0].Host, Port: listeners[0].Port}
	}
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
	if err := s.dialogSrv.ReadAck(req, tx); err != nil {
		s.log.Debug("dialog ack", "err", err, "source", req.Source())
	}
}

// onBye routes an in-dialog BYE to whichever dialog cache owns it: the
// A-leg (we are the UAS, dialogSrv) or the B-leg (we are the UAC,
// dialogCli). Exactly one of the two caches will recognize the dialog.
func (s *Server) onBye(req *sip.Request, tx sip.ServerTransaction) {
	if err := s.dialogSrv.ReadBye(req, tx); err == nil {
		return
	}
	if err := s.dialogCli.ReadBye(req, tx); err != nil {
		s.log.Debug("dialog bye", "err", err, "source", req.Source())
	}
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
