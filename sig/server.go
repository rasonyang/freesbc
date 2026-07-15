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

	"github.com/freesbc/freesbc/config"
)

// Server is the SIP signaling front door. It binds the configured
// listeners, identifies inbound requests by transport source IP, and
// answers OPTIONS health checks. The B2BUA bridge is wired in M3.3.
type Server struct {
	store *config.Store
	log   *slog.Logger
}

func NewServer(store *config.Store, log *slog.Logger) *Server {
	return &Server{store: store, log: log}
}

// Run builds the sipgo server, binds every listen.sip entry, and blocks
// until ctx is cancelled. It returns the first fatal listener error (e.g.
// a bind failure), or nil on clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	ua, err := sipgo.NewUA()
	if err != nil {
		return fmt.Errorf("sipgo ua: %w", err)
	}
	defer ua.Close()
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		return fmt.Errorf("sipgo server: %w", err)
	}
	srv.OnRequest(sip.OPTIONS, s.onOptions)
	srv.OnInvite(s.onInvite)
	srv.OnAck(s.onAck)

	listeners := s.store.Current().Listen.SIP
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
// sent; the transaction ages out on its own.
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

func (s *Server) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	name, _, ok := s.identify(req)
	if !ok {
		s.dropUnidentified(req)
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
	// M3.3 replaces this stub with the B2BUA bridge (routing → media
	// allocate → SDP rewrite → B-leg INVITE).
	if err := tx.Respond(sip.NewResponseFromRequest(req, 501, "Not Implemented", nil)); err != nil {
		s.log.Error("respond INVITE stub", "peer", name, "err", err)
	}
	s.log.Info("INVITE received (bridge not yet implemented)", "peer", name)
}

// onAck absorbs ACKs (e.g. the ACK to the 501 stub's final response) so
// sipgo does not log them as unhandled. Real in-dialog ACK handling is M3.3.
func (s *Server) onAck(req *sip.Request, tx sip.ServerTransaction) {}
