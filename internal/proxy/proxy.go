package proxy

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
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	"github.com/freesbc/freesbc/internal/shield"
)

// Server is the edge proxy: public SIP listeners, one upstream, a
// registration binding table and the media plane that anchors every call.
type Server struct {
	store *config.Store
	log   *slog.Logger

	topo *topology

	pubPool  *media.PlanePool
	privPool *media.PlanePool
	identity *media.DTLSIdentity

	loc     *Location
	calls   *callTable
	metrics *Metrics

	// pstnHealth tracks the passive cooldowns of the PSTN carrier gateways
	// (see pstnhealth.go). Always allocated; harmless when sip.pstn is off.
	pstnHealth *pstnHealth

	ua     *sipgo.UserAgent
	srv    *sipgo.Server
	client *sipgo.Client

	shield *shield.Shield

	// privSources records which transport addresses reached us on the
	// private listener; see plane.go for why the source IP alone is not
	// enough to tell the two planes apart.
	privSources *privateSources

	// pending maps an in-flight INVITE's server-transaction identity to
	// the client transaction it was forwarded on, so a CANCEL can be
	// propagated upstream (or downstream).
	pendingMu sync.Mutex
	pending   map[string]*pendingInvite

	webrtcEnabled bool

	// ready is closed once every listener is bound and serving.
	ready chan struct{}
}

// pendingInvite is one INVITE the proxy has forwarded and not yet seen a
// final response for.
type pendingInvite struct {
	req    *sip.Request // the request as forwarded (for building CANCEL)
	dest   string
	side   side
	cancel context.CancelFunc
}

// udpMTUOnce raises sipgo's UDP send ceiling, once per process.
var udpMTUOnce sync.Once

// raiseUDPSendLimit lifts the size at which sipgo refuses to send a SIP
// message over UDP.
//
// sipgo defaults to UDPMTUSize=1500 and refuses anything above
// UDPMTUSize-200, i.e. 1300 bytes. That is a faithful reading of RFC 3261
// §18.1.1 ("larger than 1300 bytes and the path MTU is unknown ... MUST be
// sent using a congestion-controlled transport"), and it is unusable here:
// a perfectly ordinary FreeSWITCH INVITE — five codecs, the usual Allow /
// Supported / User-Agent set, and the proxy's own Via and two
// Record-Routes on top — clears 1300 bytes easily. Verified against a live
// FreeSWITCH: every inbound call failed with "size of packet larger than
// MTU" before this.
//
// The RFC's remedy is to switch to TCP, which is not available: the
// upstream transport is UDP by design in this phase, and a UDP phone
// cannot be switched either. So FreeSBC does what every production SIP
// element does on UDP — send the datagram and let IP fragmentation carry
// it — while keeping a real ceiling rather than none: 8 KiB is far above
// any legitimate SIP message and far below anything that could be used to
// amplify traffic.
//
// This is a process-wide setting in sipgo with no per-user-agent override,
// so it also applies to the trunk plane. That plane has the same limit and
// the same failure mode, so raising it fixes both rather than trading one
// for the other.
func raiseUDPSendLimit() {
	udpMTUOnce.Do(func() {
		if sip.UDPMTUSize < 8192 {
			sip.UDPMTUSize = 8192
		}
	})
}

// New builds the proxy from the current config. It binds nothing; Run
// does that.
func New(store *config.Store, log *slog.Logger) (*Server, error) {
	cfg := store.Current()
	if !cfg.ProxyEnabled() {
		return nil, errors.New("proxy: sip.upstream.address is not configured")
	}
	topo, err := buildTopology(cfg)
	if err != nil {
		return nil, err
	}
	raiseUDPSendLimit()
	pub, priv := media.NewProxyPools(store)
	s := &Server{
		store:         store,
		log:           log.With("component", "proxy"),
		topo:          topo,
		pubPool:       pub,
		privPool:      priv,
		loc:           NewLocation(),
		calls:         newCallTable(),
		metrics:       NewMetrics(),
		pstnHealth:    newPSTNHealth(),
		pending:       map[string]*pendingInvite{},
		privSources:   newPrivateSources(),
		ready:         make(chan struct{}),
		webrtcEnabled: cfg.WebRTC.Enabled,
	}
	if s.webrtcEnabled {
		if cfg.WebRTC.DTLSCertFile != "" {
			s.identity, err = media.LoadDTLSIdentity(cfg.WebRTC.DTLSCertFile, cfg.WebRTC.DTLSKeyFile)
		} else {
			s.identity, err = media.ProcessDTLSIdentity()
		}
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Ready is closed once every listener is bound and serving, so a caller
// knows the proxy is actually reachable. It is never closed if Run returns
// a bind error.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Location exposes the registration table (admin API, metrics).
func (s *Server) Location() *Location { return s.loc }

// Metrics exposes the proxy's counters.
func (s *Server) Metrics() *Metrics { return s.metrics }

// ActiveCalls is the number of proxied dialogs currently tracked.
func (s *Server) ActiveCalls() int { return s.calls.count() }

// Run binds every listener and blocks until ctx is cancelled. It returns
// the first fatal bind error, or nil on clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	sipgoLog := s.log.With("caller", "sipgo")
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgentTransportLayerOptions(
			sip.WithTransportLayerLogger(sipgoLog),
			// The edge proxy accepts traffic from anywhere — phones and
			// browsers have no fixed address — so unlike the trunk plane
			// there is no source-IP allowlist here. The read filter still
			// enforces two things that do not depend on knowing the
			// sender: a hard size cap before the parser touches anything,
			// and the private listener's own trust boundary.
			sip.WithTransportLayerReadFilter(s.readFilter()),
		),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(sipgoLog)),
	)
	if err != nil {
		return fmt.Errorf("proxy: sipgo ua: %w", err)
	}
	defer ua.Close()
	s.ua = ua

	srv, err := sipgo.NewServer(ua, sipgo.WithServerLogger(sipgoLog))
	if err != nil {
		return fmt.Errorf("proxy: sipgo server: %w", err)
	}
	s.srv = srv
	client, err := sipgo.NewClient(ua)
	if err != nil {
		return fmt.Errorf("proxy: sipgo client: %w", err)
	}
	defer client.Close()
	s.client = client

	sh := shield.NewNoKernel(s.store, s.log)
	defer sh.Close()
	s.shield = sh

	srv.OnRegister(s.guard(s.onRegister))
	srv.OnInvite(s.guard(s.onInvite))
	srv.OnAck(s.guard(s.onAck))
	srv.OnCancel(s.guard(s.onCancel))
	srv.OnBye(s.guard(s.onInDialog))
	srv.OnInfo(s.guard(s.onInDialog))
	srv.OnOptions(s.guard(s.onOptions))
	srv.OnNoRoute(s.guard(s.onNoRoute))

	listenCtx, listenCancel := context.WithCancel(context.Background())
	defer listenCancel()

	type bound struct {
		transport string
		addr      string
	}
	var listeners []bound
	for _, l := range s.store.Current().PublicSIPListeners() {
		listeners = append(listeners, bound{l.Transport, l.Bind.String()})
	}
	listeners = append(listeners, bound{"udp-private", s.store.Current().SIP.Private.Bind.String()})

	// Bind every socket SYNCHRONOUSLY before serving any of them. Binding
	// inside the serving goroutines would make a bind failure racy to
	// report and would leave callers with no way to know when the proxy is
	// actually reachable — Ready() below is only honest if every socket is
	// already open when it fires.
	opened := make([]listener, 0, len(listeners))
	for _, l := range listeners {
		ln, err := s.openListener(l.transport, l.addr)
		if err != nil {
			for _, o := range opened {
				o.Close()
			}
			return fmt.Errorf("proxy listen %s://%s: %w", l.transport, l.addr, err)
		}
		opened = append(opened, ln)
	}

	// A wildcard bind does not come up as the address it was written
	// with. On a dual-stack host Go gives 0.0.0.0 an IPv6 socket whose
	// local address is "[::]:port"; with IPv6 disabled it stays
	// "0.0.0.0:port". sipgo's transport layer keys its connection pool by
	// each socket's REAL local address (transport_udp.Serve registers
	// conn.LocalAddr()), so an outbound request pinned to the configured
	// address — see prepareForward — misses the pool whenever the two
	// differ, and sipgo answers by opening a second socket on the same
	// port, which the listener already owns: EADDRINUSE before a byte is
	// written. Every FreeSWITCH-initiated request toward the public plane
	// (an inbound INVITE, a session-timer refresh, a callee-side BYE) died
	// that way in production while the phone-facing direction worked. Re-pin
	// each UDP side to its socket's actual local address before serving
	// begins, so the pool lookup hits the listener connection itself.
	s.pinOutboundToSockets(opened)

	errs := make(chan error, len(opened))
	var wg sync.WaitGroup
	for _, ln := range opened {
		ln := ln
		go func() { <-listenCtx.Done(); ln.Close() }()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ln.Serve(s.srv.TransportLayer()); err != nil && listenCtx.Err() == nil {
				errs <- fmt.Errorf("proxy serve %s: %w", ln.Describe(), err)
			}
		}()
	}
	s.log.Info("edge proxy listening",
		"public_listeners", len(s.topo.public),
		"private", s.topo.private.laddr.String(),
		"upstream", s.topo.upstreamHost,
		"webrtc", s.webrtcEnabled)

	// Ready fires only after every startup read of the topology above: the
	// close is the happens-before edge that ends the window in which the
	// topology snapshot is single-writer. Everything that reads it after
	// this point (request handlers) is then ordered after any write that
	// precedes Ready, which is what makes the startup-only mutation
	// invariant hold for the race detector as well as by convention.
	close(s.ready)

	// Registration bindings whose client vanished without un-registering
	// must not outlive their registrar-granted expiry.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-listenCtx.Done():
				return
			case <-t.C:
				if n := s.loc.Prune(); n > 0 {
					s.log.Debug("pruned expired registration bindings", "count", n)
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errs:
		listenCancel()
		wg.Wait()
		s.calls.closeAll()
		return err
	}
	listenCancel()
	wg.Wait()
	// Every media session is torn down explicitly at shutdown: no socket,
	// port reservation or relay goroutine outlives Run.
	s.calls.closeAll()
	return nil
}

// pinOutboundToSockets completes the topology's outbound pins from the
// sockets that were actually bound. The pins are built from the config in
// buildTopology; where the config names a wildcard (0.0.0.0), the address
// a pin must name to hit sipgo's connection pool is the listener socket's
// real local address — see Run for why the two can differ. UDP only: the
// ws/wss sides never pin (their outbound path is the client's own inbound
// connection).
func (s *Server) pinOutboundToSockets(opened []listener) {
	// No request can be handled yet — the sockets below are only just being
	// served — but the re-pin is a write to a map the request path reads,
	// and the tests that sabotage a pin take the same lock; take it here so
	// the write discipline is uniform.
	s.topo.mu.Lock()
	defer s.topo.mu.Unlock()
	for _, ln := range opened {
		if ln.packet == nil {
			continue
		}
		ua, ok := ln.packet.LocalAddr().(*net.UDPAddr)
		if !ok || ua.IP == nil {
			continue
		}
		laddr := sip.Addr{IP: ua.IP, Port: ua.Port, Zone: ua.Zone}
		switch ln.transport {
		case "udp":
			pub := s.topo.public["udp"]
			pub.laddr = laddr
			s.topo.public["udp"] = pub
		case "udp-private":
			s.topo.private.laddr = laddr
		}
	}
}

// listener is one bound socket, separated from serving it so Run can bind
// everything up front and report a failure before claiming to listen.
type listener struct {
	transport string
	addr      string
	packet    net.PacketConn // udp
	stream    net.Listener   // ws / wss
}

func (l listener) Describe() string { return l.transport + "://" + l.addr }

func (l listener) Close() {
	if l.packet != nil {
		_ = l.packet.Close()
	}
	if l.stream != nil {
		_ = l.stream.Close()
	}
}

// Serve drives the socket through sipgo's transport layer until it closes.
//
// This deliberately bypasses sipgo's ListenAndServe wrappers, for the same
// reason package trunk does: as of v1.4.3 those close their internal
// listener from an unsynchronised variable written by Serve and read by a
// separate shutdown goroutine, which the race detector correctly flags on
// every graceful shutdown. Owning the handle here gives a clean
// happens-before edge — it is fully constructed before any goroutine that
// closes it exists.
func (l listener) Serve(tl *sip.TransportLayer) error {
	switch l.transport {
	case "udp", "udp-private":
		return tl.ServeUDP(l.packet)
	case "ws":
		return tl.ServeWS(l.stream)
	case "wss":
		return tl.ServeWSS(l.stream)
	}
	return fmt.Errorf("proxy: unsupported transport %q", l.transport)
}

// openListener binds one socket.
func (s *Server) openListener(transport, addr string) (listener, error) {
	l := listener{transport: transport, addr: addr}
	switch transport {
	case "udp", "udp-private":
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return l, err
		}
		conn, err := net.ListenUDP("udp", ua)
		if err != nil {
			return l, err
		}
		l.packet = conn
		return l, nil
	case "ws":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return l, err
		}
		l.stream = s.watchConnections(ln)
		return l, nil
	case "wss":
		cfg := s.store.Current().SIP.Public.WSS
		var tlsConf *tls.Config
		if cfg.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return l, fmt.Errorf("wss certificate: %w", err)
			}
			tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		} else {
			// A browser refuses an untrusted WSS certificate outright, so
			// a self-signed fallback is close to useless — but failing to
			// bind would take the whole process down over a missing file.
			// Bind, and say loudly why it will not work.
			conf, err := selfSignedTLS()
			if err != nil {
				return l, err
			}
			tlsConf = conf
			s.log.Warn("wss listener has no cert_file/key_file and is using a self-signed certificate; browsers will refuse to connect", "addr", addr)
		}
		ln, err := tls.Listen("tcp", addr, tlsConf)
		if err != nil {
			return l, err
		}
		l.stream = s.watchConnections(ln)
		return l, nil
	default:
		return l, fmt.Errorf("unsupported transport %q", transport)
	}
}

// watchConnections wraps a WebSocket listener so that when a client's
// connection closes, the registration bindings made over it are dropped.
//
// A WebSocket registration is only reachable through its own connection —
// there is no address to re-dial. Keeping the binding after the socket is
// gone would make FreeSBC accept inbound calls it cannot deliver and leak
// a table entry until the registrar-granted expiry, so spec §3's
// "connection close" case needs an actual hook. FreeSBC owns these
// listeners (sipgo is handed the wrapper), which is what makes the hook
// possible at all.
func (s *Server) watchConnections(ln net.Listener) net.Listener {
	return &closeNotifyListener{Listener: ln, onClose: func(remote string) {
		ap, err := netip.ParseAddrPort(remote)
		if err != nil {
			return
		}
		if n := s.loc.RemoveBySource(ap); n > 0 {
			s.metrics.SetRegistrations(s.loc.Count())
			s.log.Debug("websocket closed; dropped its registration bindings",
				"public_remote", remote, "count", n)
		}
	}}
}

type closeNotifyListener struct {
	net.Listener
	onClose func(remote string)
}

func (l *closeNotifyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &closeNotifyConn{Conn: c, onClose: l.onClose}, nil
}

type closeNotifyConn struct {
	net.Conn
	onClose func(remote string)
	once    sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	// Once: sipgo's pool may close a connection more than once, and the
	// hook must not run again after the address has been reused.
	c.once.Do(func() { c.onClose(c.Conn.RemoteAddr().String()) })
	return err
}

// maxMessageSize caps an inbound SIP message before the parser sees it
// (spec §16). Real requests — even a WebRTC INVITE with a full candidate
// list — stay well under 8 KiB; 64 KiB is a generous ceiling that still
// bounds what one datagram or one WebSocket frame can cost.
const maxMessageSize = 64 << 10

// readFilter is the transport-layer trust boundary. It runs before the SIP
// parser on every read.
func (s *Server) readFilter() sip.TransportReadFilter {
	privateAddr := s.store.Current().SIP.Private.Bind.String()
	return func(info sip.TransportReadProps, data []byte) ([]byte, error) {
		if len(data) > maxMessageSize {
			return nil, nil
		}
		// The private listener speaks to exactly one peer: FreeSWITCH.
		// Anything else reaching it is either misrouted or hostile, and is
		// dropped before it can become a request — this is what keeps the
		// upstream-trusted path (see topology.fromUpstream) from being
		// reachable by a spoofed source on a public listener.
		if info.LocalAddr != nil && sameAddr(info.LocalAddr.String(), privateAddr) {
			ip, ok := addrIP(info.RemoteAddr)
			if !ok || !s.topo.fromUpstream(ip) {
				return nil, nil
			}
			// Record the exact source so handlers can tell this plane
			// apart from the public one even when both share an IP.
			if info.RemoteAddr != nil {
				s.privSources.note(info.RemoteAddr.String())
			}
		}
		// Never returns an error: sipgo treats a filter error as fatal to
		// the entire read loop, so one bad datagram would kill a listener.
		return data, nil
	}
}

// sameAddr compares two "host:port" strings, treating a wildcard host as
// equal to any host on the same port — a listener bound to 0.0.0.0
// reports its own address that way while individual reads report the
// concrete local address the packet arrived on.
func sameAddr(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	if ap != bp {
		return false
	}
	if ah == bh {
		return true
	}
	wildcard := func(h string) bool {
		ip, err := netip.ParseAddr(h)
		return err == nil && ip.IsUnspecified()
	}
	return wildcard(ah) || wildcard(bh)
}

func addrIP(a net.Addr) (netip.Addr, bool) {
	if a == nil {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// guard wraps every handler with the panic umbrella and the security
// plane. A panic anywhere in handler code kills only this request, never
// the process, and leaves a forensic trace.
func (s *Server) guard(next func(*sip.Request, sip.ServerTransaction)) func(*sip.Request, sip.ServerTransaction) {
	return func(req *sip.Request, tx sip.ServerTransaction) {
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("proxy handler panic",
					"panic", r, "stack", string(debug.Stack()),
					"method", req.Method.String(), "sip_call_id", callIDOf(req))
				_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Server Internal Error", nil))
			}
		}()
		if _, ok := sourceAddrPort(req); !ok {
			return
		}
		s.metrics.RequestIn(req.Method.String(), req.Transport())
		// FreeSWITCH is not subject to the public abuse plane: it is the
		// element the proxy exists to serve, and rate-limiting it would
		// turn a busy switch into a dropped call.
		if !s.arrivedOnPrivate(req) {
			src, _ := sourceAddrPort(req)
			if s.shield.Check(src.Addr(), userAgentOf(req), sip.NetworkToLower(req.Transport())) == shield.Drop {
				s.metrics.Dropped()
				return // silent
			}
		}
		next(req, tx)
	}
}

// onOptions answers a keepalive locally. An OPTIONS ping is a liveness
// check on FreeSBC itself; forwarding every phone's keepalive upstream
// would multiply load on FreeSWITCH for no information gain.
func (s *Server) onOptions(req *sip.Request, tx sip.ServerTransaction) {
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader("Allow", strings.Join(allowedMethods, ", ")))
	s.respond(req, tx, res)
}

// allowedMethods is what FreeSBC advertises it will proxy.
var allowedMethods = []string{"INVITE", "ACK", "CANCEL", "BYE", "OPTIONS", "INFO", "REGISTER"}

// onNoRoute answers any method the proxy does not handle. A 405 naming the
// methods it does handle is the honest answer; silence would leave a
// client retransmitting.
func (s *Server) onNoRoute(req *sip.Request, tx sip.ServerTransaction) {
	res := sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
	res.AppendHeader(sip.NewHeader("Allow", strings.Join(allowedMethods, ", ")))
	s.respond(req, tx, res)
}

// respond sends a locally generated response back to the requester.
//
// The destination is the request's transport source, not anything in the
// Via: that is symmetric response routing (RFC 3581), which is what makes
// a response reach a phone behind NAT at all.
func (s *Server) respond(req *sip.Request, tx sip.ServerTransaction, res *sip.Response) {
	res.SetDestination(req.Source())
	s.metrics.ResponseOut(res.StatusCode)
	if err := tx.Respond(res); err != nil {
		s.log.Debug("respond", "err", err, "code", res.StatusCode, "sip_call_id", callIDOf(req))
	}
}

// reject is respond for an error status.
func (s *Server) reject(req *sip.Request, tx sip.ServerTransaction, code int, reason string) {
	s.respond(req, tx, sip.NewResponseFromRequest(req, code, reason, nil))
}

func sourceAddrPort(req *sip.Request) (netip.AddrPort, bool) {
	host, portStr, err := net.SplitHostPort(req.Source())
	if err != nil {
		return netip.AddrPort{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), true
}

func callIDOf(msg sip.Message) string {
	if h := msg.CallID(); h != nil {
		return h.Value()
	}
	return ""
}

func userAgentOf(req *sip.Request) string {
	hs := req.GetHeaders("User-Agent")
	if len(hs) == 0 {
		return ""
	}
	return hs[0].Value()
}
