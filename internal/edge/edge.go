package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
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

// Server is the edge proxy: public SIP listeners, one or more upstream
// FreeSWITCHes, a registration binding table and the media plane that
// anchors every call.
type Server struct {
	store *config.Store
	log   *slog.Logger

	// boot is the snapshot the plane was built from (store.Current() in
	// New). Restart-only settings are read from it and never from the
	// store: the listener set, the WSS certificate, the media planes. Only
	// shield is hot, and the shield reads it itself. Written once in New.
	boot *config.Config

	// tlsLeaf is the leaf (Certificate[0]) of the top-level tls pair, kept
	// the first time a tls or wss listener loads it, with the load time and
	// the transports that loaded it. Read by TLSCert for the admin surface.
	tlsMu     sync.Mutex
	tlsLeaf   *x509.Certificate
	tlsLoaded time.Time
	tlsUsers  []string

	// privAddr is the private SIP socket: private.ip:5060, unless a test
	// overrode it with WithPrivateAddr. Written once in New.
	privAddr netip.AddrPort

	topo *topology

	// carriers is the carrier directory: what edge.carriers resolves to and
	// the carrier source set (carrierdns.go). carrierURIs maps the
	// "host:port" a carrier is addressed by in a Request-URI to its name.
	// Both are written once in New.
	carriers    *carrierDirectory
	carrierURIs map[string]string
	// carrierByName holds each edge.carriers entry; carrierConns dials and
	// pools the tcp and tls connections to them (carrierconn.go). Both are
	// written once in New.
	carrierByName map[string]config.Carrier
	carrierConns  *carrierConns

	// carrierRegs holds the switch's live registrations at carriers
	// (carrierreg.go), by token. Separate from loc, the client table.
	carrierRegs *carrierRegTable

	pubPool  *media.PlanePool
	privPool *media.PlanePool
	identity *media.DTLSIdentity

	loc     *Location
	dialogs *dialogTable

	// draining refuses new out-of-dialog INVITEs (drain.go). Runtime state
	// only: never in config, and a restart starts not draining.
	drain drainState
	// subs is the SUBSCRIBE dialog records (subscribe.go); subWarn spaces
	// the WARN of a subscription cap reject.
	subs    *subTable
	subWarn subCapWarner
	// afterSubBegin is a test seam, called between the insertion of a
	// subscription record and the re-check of its binding.
	afterSubBegin atomic.Pointer[func()]
	metrics       *Metrics

	// upstreamCooldown is the passive health penalty of the switch nodes
	// (see cooldown.go).
	upstreamCooldown *cooldownTable

	srv    *sipgo.Server
	client *sipgo.Client

	shield   *shield.Shield
	shieldMu sync.RWMutex // guards the assignment in Run against ShieldStats

	// marker stamps requests that reach the trusted private bind and
	// recognises the stamp again in guard. It is the only carrier of "which local socket did this arrive on"; see
	// arrival.go. Created in New, never replaced.
	marker *arrivalMarker

	webrtcEnabled bool

	// rtpTimeout is the media silence timeout in nanoseconds: the
	// rtpSilenceTimeout constant unless a test shortened it with
	// setRTPTimeout. Pools read it for every new session.
	rtpTimeout atomic.Int64

	// inviteBackstop, when non-zero, replaces inviteTimeout as the INVITE
	// backstop (nanoseconds). Only tests set it: the 5-minute default is
	// otherwise untestable.
	inviteBackstop atomic.Int64

	// ackWait, when non-zero, replaces ackTimeout as how long an answer
	// owed in an ACK or PRACK may stay outstanding (nanoseconds). Only
	// tests set it.
	ackWait atomic.Int64

	// ready is closed once every listener is bound and served, and every
	// UDP listener is in sipgo's connection pool (see awaitUDPServing).
	// Nothing in production waits on it; it is the happens-before edge the
	// tests use to read srv and client safely.
	ready chan struct{}

	// early counts, per public source IP, the INVITEs this proxy has taken
	// media for and not yet seen answered (see admitEarly).
	earlyMu sync.Mutex
	early   map[netip.Addr]int

	// inviteLimiter is the global new-INVITE bucket behind
	// shield.invite_rate_limit; capWarn rate-limits the WARN of each
	// admission-control reject (invite.go beginDialog).
	inviteLimiter *shield.Limiter
	capWarn       capWarner

	// dropWarned limits admission-drop WARNs to one per source IP and
	// reason; enumLimit is the REGISTER enumeration limit (admission.go).
	dropWarned *warnOnce
	enumLimit  *enumLimiter

	// streams counts open tcp/tls/ws/wss connections for the caps; streamLim
	// is the bounds they live under (stream.go). Tests shorten streamLim
	// before Run.
	streams   *streamTable
	streamLim streamLimits
}

const (
	// rtpSilenceTimeout tears a call down after this much RTP silence. It
	// is the only automatic reclaim for a confirmed call whose BYE was lost.
	rtpSilenceTimeout = 5 * time.Minute

	// switchCooldown is how long a switch node that answered nothing is
	// skipped in favour of its alternatives (passive; see cooldown.go).
	switchCooldown = 30 * time.Second
)

// Option customises New.
type Option func(*options)

type options struct {
	privateAddr netip.AddrPort
}

// WithPrivateAddr overrides the private SIP socket, which is otherwise the
// fixed private.ip:5060. It is a TEST SEAM: the private socket's port is
// not configurable in production, but tests run the whole topology on one
// host and need to separate the private socket from the switch and the
// public side by port. The address is used for both the bind and the
// advertised side, and its IP replaces private.ip for media.
func WithPrivateAddr(a netip.AddrPort) Option {
	return func(o *options) { o.privateAddr = a }
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
// This is a process-wide setting in sipgo with no per-user-agent override.
func raiseUDPSendLimit() {
	udpMTUOnce.Do(func() {
		if sip.UDPMTUSize < 8192 {
			sip.UDPMTUSize = 8192
		}
	})
}

// New builds the proxy from the current config. It binds nothing; Run
// does that.
func New(store *config.Store, log *slog.Logger, opts ...Option) (*Server, error) {
	cfg := store.Current()
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	priv := cfg.PrivateAddr()
	if o.privateAddr.IsValid() {
		priv = o.privateAddr
	}
	topo := buildTopology(cfg, priv)
	marker, err := newArrivalMarker()
	if err != nil {
		return nil, err
	}
	raiseUDPSendLimit()
	s := &Server{
		store:            store,
		boot:             cfg,
		privAddr:         priv,
		log:              slog.New(newRedactHandler(log.Handler())).With("component", "proxy"),
		topo:             topo,
		carriers:         newCarrierDirectory(cfg, log.With("component", "carriers")),
		carrierURIs:      carrierURIsOf(cfg),
		carrierRegs:      newCarrierRegTable(),
		loc:              NewLocation(),
		metrics:          NewMetrics(),
		upstreamCooldown: newCooldownTable(),
		marker:           marker,
		ready:            make(chan struct{}),
		early:            map[netip.Addr]int{},
		dropWarned:       newWarnOnce(maxWarnedSources),
		enumLimit:        newEnumLimiter(),
		inviteLimiter:    shield.NewLimiter(),
		webrtcEnabled:    cfg.WebRTC(),
		streams:          newStreamTable(),
		streamLim:        defaultStreamLimits(),
	}
	s.carrierByName = map[string]config.Carrier{}
	for _, c := range cfg.CarrierList() {
		s.carrierByName[c.Name] = c
	}
	if s.carrierConns, err = newCarrierConns(s, cfg); err != nil {
		return nil, err
	}
	s.rtpTimeout.Store(int64(rtpSilenceTimeout))
	s.pubPool, s.privPool = newMediaPools(cfg, topo, s.mediaTimeout)
	s.dialogs = newDialogTable(s.metrics, s.log)
	s.subs = newSubTable(s.metrics)
	// A subscription belongs to a registration binding: when the binding
	// goes (un-REGISTER, WebSocket close, expiry) its records go too.
	s.loc.SetOnRemove(s.subs.dropTokens)
	s.dialogs.onMediaEnd = s.byeBothEnds
	if s.webrtcEnabled {
		s.identity, err = media.ProcessDTLSIdentity()
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// mediaTimeout is the RTP silence timeout for a new media session.
func (s *Server) mediaTimeout() time.Duration { return time.Duration(s.rtpTimeout.Load()) }

// setRTPTimeout shortens the RTP silence timeout. Tests only: the
// production value is the rtpSilenceTimeout constant.
func (s *Server) setRTPTimeout(d time.Duration) { s.rtpTimeout.Store(int64(d)) }

// inviteBudget is the INVITE backstop: inviteTimeout unless a test
// shortened it.
func (s *Server) inviteBudget() time.Duration {
	if d := s.inviteBackstop.Load(); d > 0 {
		return time.Duration(d)
	}
	return inviteTimeout
}

// ackTimeout is how long FreeSBC waits for the answer it owes the callee
// (offerless INVITE or re-INVITE, answer in the ACK): RFC 3261 Timer H,
// the time after which the callee gives up on the ACK itself.
const ackTimeout = 32 * time.Second

// ackBudget is ackTimeout unless a test shortened it.
func (s *Server) ackBudget() time.Duration {
	if d := s.ackWait.Load(); d > 0 {
		return time.Duration(d)
	}
	return ackTimeout
}

// Metrics exposes the proxy's counters.
func (s *Server) Metrics() *Metrics { return s.metrics }

// ActiveCalls is the number of proxied dialogs currently tracked.
func (s *Server) ActiveCalls() int { return s.dialogs.count() }

// Registrations is one page of the live client bindings, optionally
// filtered by user, with the total matching. See Location.Registrations.
func (s *Server) Registrations(user string, limit, offset int) ([]RegistrationInfo, int) {
	return s.loc.Registrations(user, limit, offset)
}

// CarrierRegistrations lists the switch's live registrations at carriers.
func (s *Server) CarrierRegistrations() []CarrierRegistrationInfo {
	return s.carrierRegs.snapshot()
}

// SwitchNodes reports the passive health of every configured switch node,
// sorted by address.
func (s *Server) SwitchNodes() []SwitchNodeInfo {
	return s.upstreamCooldown.snapshot(s.topo.upstreamNames, time.Now())
}

// Carriers reports the resolution state of every configured carrier, sorted
// by name.
func (s *Server) Carriers() []CarrierInfo { return s.carriers.snapshotInfo() }

// SetDraining enters (on) or leaves (!on) drain mode and reports whether the
// state changed. See drain.go.
func (s *Server) SetDraining(on bool) (changed bool) {
	changed = s.drain.set(on)
	if changed {
		s.metrics.SetDraining(on)
		if on {
			s.log.Info("edge drain entered", "active_calls", s.ActiveCalls())
		} else {
			s.log.Info("edge drain left", "active_calls", s.ActiveCalls())
		}
	}
	return changed
}

// DrainState reports whether the edge is draining and, if so, since when
// (the zero time otherwise).
func (s *Server) DrainState() (draining bool, since time.Time) { return s.drain.get() }

// Calls lists the confirmed dialogs ActiveCalls counts, for the admin call
// list.
func (s *Server) Calls() []CallRecord { return s.dialogs.calls() }

// PortStats is the RTP port usage of the public and private media pools
// together: pairs allocated and pairs the two ranges hold.
func (s *Server) PortStats() (inUse, total int) {
	pu, pt := s.pubPool.Stats()
	qu, qt := s.privPool.Stats()
	return pu + qu, pt + qt
}

// ShieldStats is the shield's drop counters for the admin API. It is the
// zero value until Run has created the shield.
func (s *Server) ShieldStats() shield.Stats {
	s.shieldMu.RLock()
	sh := s.shield
	s.shieldMu.RUnlock()
	if sh == nil {
		return shield.Stats{DropsByReason: map[string]int64{}}
	}
	return sh.Stats()
}

// Bans is one page of the shield's live bans, the total, and the cumulative
// ban additions refused at the table cap. Before Run has created the shield
// it is an empty page.
func (s *Server) Bans(limit, offset int) (page []shield.BanInfo, total int, addsRejected int64) {
	s.shieldMu.RLock()
	sh := s.shield
	s.shieldMu.RUnlock()
	if sh == nil {
		return []shield.BanInfo{}, 0, 0
	}
	page, total = sh.Bans(limit, offset)
	return page, total, sh.Stats().BanAddsRejected
}

// Listeners is the listener set Run binds, as transport://host:port, from
// the startup snapshot (the set is restart-only).
func (s *Server) Listeners() []string {
	var out []string
	for _, l := range s.publicListeners() {
		out = append(out, l.transport+"://"+l.addr)
	}
	out = append(out, "udp://"+s.privAddr.String()+" (private)")
	return out
}

// noteTLSLeaf records the leaf of a pair a tls or wss listener just loaded.
// The pair is the one top-level tls pair, so the first load is the record
// and later ones only add their transport.
func (s *Server) noteTLSLeaf(cert tls.Certificate, transport string) {
	s.tlsMu.Lock()
	defer s.tlsMu.Unlock()
	if s.tlsLeaf == nil {
		leaf := cert.Leaf
		if leaf == nil {
			var err error
			if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
				return // LoadX509KeyPair already parsed it; unreachable
			}
		}
		s.tlsLeaf, s.tlsLoaded = leaf, time.Now()
	}
	for _, u := range s.tlsUsers {
		if u == transport {
			return
		}
	}
	s.tlsUsers = append(s.tlsUsers, transport)
}

// TLSCert returns the leaf of the top-level tls pair the tls and wss
// listeners loaded, when it was loaded and which transports use it. The
// leaf is nil when no listener loaded it. The pair is restart-only, so this
// is what the process serves, whatever is on disk now.
func (s *Server) TLSCert() (leaf *x509.Certificate, loadedAt time.Time, users []string) {
	s.tlsMu.Lock()
	defer s.tlsMu.Unlock()
	return s.tlsLeaf, s.tlsLoaded, append([]string(nil), s.tlsUsers...)
}

type bound struct {
	transport string
	addr      string
}

// publicListeners is the public socket set, udp, tcp, tls, ws then wss, on
// public.bind.
func (s *Server) publicListeners() []bound {
	bind := s.boot.PublicBind()
	var out []bound
	for _, l := range []struct {
		transport string
		port      int
	}{{"udp", s.boot.Edge.Listen.UDP}, {"tcp", s.boot.Edge.Listen.TCP}, {"tls", s.boot.Edge.Listen.TLS},
		{"ws", s.boot.Edge.Listen.WS}, {"wss", s.boot.Edge.Listen.WSS}} {
		if l.port != 0 {
			out = append(out, bound{l.transport, netip.AddrPortFrom(bind, uint16(l.port)).String()})
		}
	}
	return out
}

// localInterface returns the name of the interface that owns ip. It is the
// one lookup behind checkLocalAddr and the private socket's ingress filter
// (privateSocketFilter): both need the interface, and private.ip must be
// assigned to a local interface for either to mean anything.
func localInterface(ip netip.Addr) (string, bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false, err
	}
	want := ip.Unmap()
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue // an interface that cannot list its addresses has none to match
		}
		for _, a := range addrs {
			p, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if got, ok := netip.AddrFromSlice(p.IP); ok && got.Unmap() == want {
				return iface.Name, true, nil
			}
		}
	}
	return "", false, nil
}

// checkLocalAddr fails unless ip is assigned to a local interface: a bind
// to anything else fails late and obscurely, and an address that is not
// ours would be advertised to peers that can never reach it.
func checkLocalAddr(key string, ip netip.Addr) error {
	_, ok, err := localInterface(ip)
	if err != nil {
		return fmt.Errorf("proxy: list local addresses: %w", err)
	}
	if !ok {
		return fmt.Errorf("proxy: %s %s is not assigned to any local interface", key, ip)
	}
	return nil
}

// Run binds every listener and blocks until ctx is cancelled. It returns
// the first fatal bind error, or nil on clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	if err := checkLocalAddr("public.bind", s.boot.PublicBind()); err != nil {
		return err
	}
	if err := checkLocalAddr("private.ip", s.privAddr.Addr()); err != nil {
		return err
	}
	// Every sipgo record goes through sipgoHandler: a failed parse would
	// otherwise log the raw message at Error (sipgolog.go).
	sipgoLog := slog.New(newSipgoHandler(s.log.Handler(), s.metrics.ParseFailed)).With("caller", "sipgo")
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgentTransportLayerOptions(
			sip.WithTransportLayerLogger(sipgoLog),
			// The edge proxy accepts traffic from anywhere — phones and
			// browsers have no fixed address — so there is no source-IP
			// allowlist on the public sockets. The filter enforces two
			// things that do not depend on knowing the sender: a hard size
			// cap before the parser touches anything, and the private
			// socket's own trust boundary. Who may push an out-of-dialog
			// INVITE or a REGISTER into the switch is decided after
			// parsing, per request type (admission.go).
			sip.WithTransportLayerReadFilter(s.readFilter()),
		),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(sipgoLog)),
		// sipgo never dials a TLS connection to a carrier (carrierconn.go
		// does, with the carrier's own settings). Should it ever try, in a
		// race with a connection that just closed, an empty root set makes
		// the handshake fail closed.
		sipgo.WithUserAgenTLSConfig(&tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}),
	)
	if err != nil {
		return fmt.Errorf("proxy: sipgo ua: %w", err)
	}
	defer ua.Close()

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

	sh := shield.New(s.store, s.log, func(ip netip.Addr) bool { return s.carriers.snapshot().isSource(ip) })
	defer sh.Close()
	s.shieldMu.Lock()
	s.shield = sh
	s.shieldMu.Unlock()

	srv.OnRegister(s.guard(s.onRegister))
	srv.OnInvite(s.guard(s.onInvite))
	srv.OnAck(s.guard(s.onAck))
	srv.OnCancel(s.guard(s.onCancel))
	srv.OnBye(s.guard(s.onInDialog))
	srv.OnInfo(s.guard(s.onInDialog))
	srv.OnPrack(s.guard(s.onPrackUpdate))
	srv.OnUpdate(s.guard(s.onPrackUpdate))
	srv.OnNotify(s.guard(s.onInDialog))
	srv.OnSubscribe(s.guard(s.onSubscribe))
	srv.OnRefer(s.guard(s.onInDialog))
	srv.OnMessage(s.guard(s.onMessage))
	srv.OnOptions(s.guard(s.onOptions))
	srv.OnNoRoute(s.guard(s.onNoRoute))

	listenCtx, listenCancel := context.WithCancel(context.Background())
	defer listenCancel()

	listeners := append(s.publicListeners(), bound{"udp-private", s.privAddr.String()})

	// Bind every socket SYNCHRONOUSLY before serving any of them. Binding
	// inside the serving goroutines would make a bind failure racy to
	// report and would leave callers with no way to know when the proxy is
	// actually reachable — ready below is only honest if every socket is
	// already open when it is closed.
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
	// The connections FreeSBC dials to tcp and tls carriers enter sipgo
	// through listeners of their own (carrierconn.go).
	opened = append(opened, s.carrierConns.listeners()...)

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
	// Ready must mean "a request can be sent from every socket". sipgo
	// adds a UDP listener to its connection pool only inside ServeUDP, on
	// the goroutine just started; until then a request pinned to that
	// listener's address (every forward: see prepareForward) misses the
	// pool, and sipgo binds a second socket there — "address already in
	// use", a 503 to the first callers after a restart.
	if err := s.awaitUDPServing(ctx, opened, errs); err != nil {
		listenCancel()
		wg.Wait()
		s.dialogs.closeAll()
		s.subs.closeAll()
		return err
	}
	s.log.Info("edge proxy listening",
		"public_listeners", len(s.publicListeners()),
		"private", s.privAddr.String(),
		"switches", len(s.topo.upstreamNames),
		"switch_nodes", strings.Join(s.topo.upstreamNames, ","),
		// The INVITE admission posture (admission.go): edge.carrier_sources
		// and literal-IP edge.carriers. Empty means only registered clients
		// may place calls on a public listener.
		"carrier_sources", s.carriers.snapshot().sourcesString(),
		"max_sessions", s.sessionLimit(s.store.Current()),
		"invite_rate_limit", s.store.Current().Shield.InviteRateLimit,
		"webrtc", s.webrtcEnabled)

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
				if n := s.subs.prune(time.Now()); n > 0 {
					s.log.Debug("pruned expired subscriptions", "count", n)
				}
				if n := s.carrierRegs.prune(); n > 0 {
					s.log.Debug("pruned expired carrier registrations", "count", n)
				}
				s.publishCarrierRegistrations()
			}
		}
	}()

	// The carrier directory resolves DNS-name carriers in the background; a
	// resolver that is down at startup delays those carriers, nothing else.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.carriers.Run(listenCtx)
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errs:
	}
	// Shutdown. First close the dialog table, while the listeners are
	// still up: an INVITE handler still in flight can then open no dialog
	// and attach no media (it answers 503, and a session it already
	// allocated is closed by attach), so nothing is allocated after this
	// point or outlives Run (audit P2-EDG-027). Then close the listeners
	// and wait for them, and end every dialog: every media session is torn
	// down explicitly, so no socket, port reservation or relay goroutine
	// outlives Run. There is no BYE on this plane's shutdown: the calls
	// are dropped (docs/design.md §4.5).
	s.dialogs.close()
	s.subs.close()
	listenCancel()
	wg.Wait()
	s.dialogs.closeAll()
	s.subs.closeAll()
	return runErr
}

// udpServingTimeout bounds how long Run waits for sipgo to pool its UDP
// listeners. It takes microseconds; the bound only turns a wedged serving
// goroutine into a startup error instead of a proxy that never gets ready.
const udpServingTimeout = 5 * time.Second

// awaitUDPServing returns once every UDP listener in opened is in the sipgo
// transport's connection pool, keyed by the socket's real local address as
// ServeUDP keys it. WS/WSS listeners need no wait: nothing is ever sent
// pinned to their address. It returns early with a listener's serve error,
// or nil when ctx ends (Run then shuts down as usual).
func (s *Server) awaitUDPServing(ctx context.Context, opened []listener, errs <-chan error) error {
	tl := s.srv.TransportLayer()
	deadline := time.NewTimer(udpServingTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for _, ln := range opened {
		if ln.packet == nil {
			continue
		}
		addr := ln.packet.LocalAddr().String()
		for {
			if c, err := tl.GetConnection("udp", addr); err == nil && c != nil {
				break
			}
			select {
			case <-tick.C:
			case err := <-errs:
				return err
			case <-ctx.Done():
				return nil
			case <-deadline.C:
				return fmt.Errorf("proxy serve %s: not serving after %s", ln.Describe(), udpServingTimeout)
			}
		}
	}
	return nil
}

// listener is one bound socket, separated from serving it so Run can bind
// everything up front and report a failure before claiming to listen.
type listener struct {
	transport string
	addr      string
	packet    net.PacketConn // udp
	stream    net.Listener   // tcp / tls / ws / wss (a *streamListener)
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
// This deliberately bypasses sipgo's ListenAndServe wrappers, because as of v1.4.3 those close their internal
// listener from an unsynchronised variable written by Serve and read by a
// separate shutdown goroutine, which the race detector correctly flags on
// every graceful shutdown. Owning the handle here gives a clean
// happens-before edge — it is fully constructed before any goroutine that
// closes it exists.
func (l listener) Serve(tl *sip.TransportLayer) error {
	switch l.transport {
	case "udp", "udp-private":
		return tl.ServeUDP(l.packet)
	case "tcp":
		return tl.ServeTCP(l.stream)
	case "tls":
		return tl.ServeTLS(l.stream)
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
		lc := net.ListenConfig{}
		if transport == "udp-private" {
			// Filter the trusted socket's receive path down to the
			// interface that owns private.ip. Linux's weak host model
			// otherwise delivers a datagram addressed to private.ip and
			// sent into the public NIC to this socket, where a spoofed
			// switch source is believed (issue #90). The filter drops it
			// before FreeSBC ever sees it and leaves the send path alone;
			// docs/edge.md states the topology requirement.
			ifname, ok, err := localInterface(s.privAddr.Addr())
			if err != nil {
				return l, fmt.Errorf("private.ip: list local addresses: %w", err)
			}
			if !ok {
				return l, fmt.Errorf("private.ip %s is not assigned to any local interface", s.privAddr.Addr())
			}
			control, err := privateSocketFilter(ifname)
			if err != nil {
				return l, fmt.Errorf("private socket filter on %s: %w", ifname, err)
			}
			lc.Control = control
			if lc.Control == nil {
				s.log.Warn("private socket not filtered to its interface; the weak-host fix is Linux-only",
					"private", s.privAddr.String(), "interface", ifname)
			}
		}
		pc, err := lc.ListenPacket(context.Background(), "udp", ua.String())
		if err != nil {
			return l, err
		}
		l.packet = pc
		return l, nil
	case "tcp", "ws":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return l, err
		}
		l.stream = s.newStreamListener(ln, transport, nil)
		return l, nil
	case "tls", "wss":
		// validate guarantees tls is set whenever tls or wss is.
		if s.boot.TLS == nil {
			return l, fmt.Errorf("%s needs the top-level tls cert and key", transport)
		}
		cert, err := tls.LoadX509KeyPair(s.boot.TLS.Cert, s.boot.TLS.Key)
		if err != nil {
			return l, fmt.Errorf("%s certificate: %w", transport, err)
		}
		s.noteTLSLeaf(cert, transport)
		tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return l, err
		}
		l.stream = s.newStreamListener(ln, transport, tlsConf)
		return l, nil
	default:
		return l, fmt.Errorf("unsupported transport %q", transport)
	}
}

// maxMessageSize caps an inbound read before the parser sees it (spec
// §16): one UDP datagram or one WebSocket frame. It is fsip.MaxReadSize,
// which sits below sipgo's read buffer so the cap can actually fire; see
// its comment for why that matters. A tcp or tls read is a chunk of a byte
// stream, not a message, so it is not capped here: dropping a chunk would
// corrupt the framing. The stream connection (stream.go) bounds the message
// instead and closes the connection.
const maxMessageSize = fsip.MaxReadSize

// readFilter is the transport-layer trust boundary. It runs before the SIP
// parser on every read. The size cap and the rule that a filter must never
// return an error live in fsip.ReadFilter; what is here is the proxy's own
// trust decision.
//
// There are two kinds of socket. The private bind is TRUSTED: it speaks
// to FreeSWITCH only, so a read from any other IP is dropped before it can
// become a request, and a request from an upstream IP is stamped with the
// arrival marker (see arrival.go) so guard can tell it reached that socket.
// Every other read is PUBLIC and gets no stamp, whoever it claims to be from.
// Trust is keyed on the local socket alone: there is no table of "known
// FreeSWITCH source addresses", so a datagram that reaches a public
// listener from FreeSWITCH's own address and port is a public datagram.
func (s *Server) readFilter() sip.TransportReadFilter {
	privateAddr := s.privAddr.String()
	// trusted names the trusted socket a read arrived on, or arrPublic. The
	// trusted socket is UDP only; a stream read on the same port number
	// is a public client in a different port space.
	trusted := func(info sip.TransportReadProps) arrival {
		if info.LocalAddr == nil {
			return arrPublic
		}
		local := info.LocalAddr.String()
		if fsip.SameListener(info.Transport, local, "udp", privateAddr) {
			return arrPrivate
		}
		return arrPublic
	}
	base := fsip.ReadFilter(maxMessageSize, func(info sip.TransportReadProps) bool {
		if trusted(info) != arrPublic {
			// Only an upstream IP may speak on a trusted socket. Anything
			// else is misrouted or hostile.
			ip, ok := fsip.AddrOf(info.RemoteAddr)
			return ok && s.topo.fromUpstream(ip)
		}
		// A public read. A source the shield has banned gets nothing back
		// at all: guard would drop its requests silently, but sipgo answers
		// some messages on its own before any handler runs — a stateless
		// 400 to a malformed request, a 200 to a CANCEL that matches a
		// transaction — so the ban is enforced here, before parsing. There
		// is no FreeSWITCH exemption: FreeSWITCH does not use a public
		// listener, so a public read from its address is just a public read.
		s.shieldMu.RLock()
		sh := s.shield
		s.shieldMu.RUnlock()
		if sh != nil && info.RemoteAddr != nil {
			if ap, err := netip.ParseAddrPort(info.RemoteAddr.String()); err == nil {
				if sh.BannedFrom(ap, info.Transport) {
					// A stream from a banned source is closed on its next
					// read, so a ban also ends connections opened before it.
					s.closeStream(info.Transport, info.RemoteAddr.String())
					return false
				}
				// The rate token is charged here, once per datagram or
				// frame, parsable or not: a malformed flood must not reach
				// the parser (and sipgo's failure log) for free. guard
				// charges nothing. Over the limit is a silent drop.
				//
				// A tcp or tls read is a chunk, and dropping one would
				// desynchronise the stream, so the connection charges
				// those per message it sees start instead and closes
				// when the budget is gone (streamConn.observe).
				if !fsip.IsByteStream(info.Transport) && !sh.AllowRate(ap.Addr()) {
					return false
				}
			}
		}
		return true
	})
	return func(info sip.TransportReadProps, data []byte) ([]byte, error) {
		out, err := base(info, data)
		if len(out) == 0 || err != nil {
			return out, err
		}
		if a := trusted(info); a != arrPublic {
			return s.marker.stamp(a, out), nil
		}
		return out, nil
	}
}

// guard wraps every handler with the panic umbrella and the security
// plane. A panic anywhere in handler code kills only this request, never
// the process, leaves a forensic trace and is counted
// (freesbc_sip_handler_panics_total), so it cannot pass unnoticed. The
// requester is answered 500 only when it has not already had a final
// response: a transaction finalises once, and a 500 after, say, a relayed
// 200 would only be counted, never delivered.
// The transport source address is parsed ONCE here and handed to the
// handler with the request's arrival: a request whose source cannot be
// parsed is dropped before anything else looks at it, and the handlers that
// need either (the REGISTER binding, the INVITE plane dispatch) do not
// re-derive them.
//
// The arrival marker is read and stripped FIRST, for every request on every
// transport, before anything can copy, log or forward the headers.
func (s *Server) guard(next handler) func(*sip.Request, sip.ServerTransaction) {
	return func(req *sip.Request, stx sip.ServerTransaction) {
		req, arr := s.marker.take(req)
		tx := &finalTracker{ServerTransaction: stx}
		defer func() {
			if r := recover(); r != nil {
				s.metrics.HandlerPanicked()
				s.log.Error("proxy handler panic",
					"panic", r, "stack", string(debug.Stack()),
					"method", req.Method.String(), "sip_call_id", fsip.CallID(req))
				if !tx.finalised.Load() && req.Method != sip.ACK {
					s.respond(req, tx, sip.NewResponseFromRequest(req, 500, "Server Internal Error", nil))
				}
			}
		}()
		src, ok := fsip.SourceAddrPort(req)
		if !ok {
			return
		}
		// FreeSWITCH is not subject to the public abuse plane: it is the
		// element the proxy exists to serve, and rate-limiting it would
		// turn a busy switch into a dropped call. That exemption belongs
		// to the trusted sockets, and only to them.
		if arr == arrPublic {
			network := sip.NetworkToLower(req.Transport())
			// The rate token was already charged by the read filter; a
			// parsable request costs one token end to end.
			if s.shield.CheckScanner(src, fsip.UserAgent(req), network) == shield.Drop {
				if s.shield.BannedFrom(src, network) {
					s.closeStream(network, req.Source())
				}
				return // silent
			}
		}
		// Counted after the shield: a dropped flood is the shield's to
		// account for, not a request the proxy handled.
		s.metrics.RequestIn(req.Method.String(), req.Transport())
		next(req, tx, inbound{src: src, arr: arr})
	}
}

// closeStream hard-closes the tcp/tls/ws/wss connection from raddr, if
// there is one, when its source is banned (P2-SHD-006): a verdict alone
// would leave the client a socket whose every later message is still read
// and parsed. sipgo's read loop then sees the error and drops the
// connection from its pool. Closing sends nothing, so the ban stays silent.
// UDP has no connection and is left alone.
func (s *Server) closeStream(network, raddr string) {
	network = sip.NetworkToLower(network)
	if s.srv == nil || network == "udp" {
		return
	}
	if c, err := s.srv.TransportLayer().GetConnection(network, raddr); err == nil {
		_ = c.Close()
	}
}

// finalTracker is the server transaction guard hands a handler: it
// records whether a final response has gone out on it, which is what the
// panic path needs to know.
type finalTracker struct {
	sip.ServerTransaction
	finalised atomic.Bool
}

func (t *finalTracker) Respond(res *sip.Response) error {
	if res.StatusCode >= 200 {
		t.finalised.Store(true)
	}
	return t.ServerTransaction.Respond(res)
}

// inbound is what guard hands a handler besides the request: the parsed
// transport source it has already validated, and the socket class the
// request arrived on (see arrival.go).
type inbound struct {
	src netip.AddrPort
	arr arrival
}

// private reports whether the request reached the private bind: it is
// FreeSWITCH talking to its own edge proxy. This is the direction switch
// every handler uses.
func (in inbound) private() bool { return in.arr == arrPrivate }

// handler is a guarded request handler: sipgo's shape plus the inbound
// facts guard has already established.
type handler func(*sip.Request, sip.ServerTransaction, inbound)

// onOptions answers a keepalive locally. An OPTIONS ping is a liveness
// check on FreeSBC itself; forwarding every phone's keepalive upstream
// would multiply load on FreeSWITCH for no information gain.
//
// From the switch an OPTIONS is classified by its Request-URI like every
// other out-of-dialog request (classifySwitchRequest): addressed to
// FreeSBC itself or to a registered client's token it is answered here; to
// a carrier it is proxied to it (optionsToCarrier); to anything else, 404.
// A public OPTIONS, a carrier's keepalive included, is answered here.
func (s *Server) onOptions(req *sip.Request, tx sip.ServerTransaction, in inbound) {
	if in.private() && fsip.ToTag(req) == "" {
		switch kind, name := s.classifySwitchRequest(req); kind {
		case targetCarrier:
			s.optionsToCarrier(req, tx, name)
			return
		case targetNotFound:
			s.reject(req, tx, 404, "Not Found")
			return
		}
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader("Allow", strings.Join(allowedMethods, ", ")))
	s.respond(req, tx, res)
}

// allowedMethods is what FreeSBC advertises it will proxy.
var allowedMethods = []string{"INVITE", "ACK", "CANCEL", "BYE", "PRACK", "UPDATE", "OPTIONS", "INFO", "NOTIFY", "SUBSCRIBE", "REFER", "MESSAGE", "REGISTER"}

// onNoRoute answers any method the proxy does not handle. A 405 naming the
// methods it does handle is the honest answer; silence would leave a
// client retransmitting.
func (s *Server) onNoRoute(req *sip.Request, tx sip.ServerTransaction, _ inbound) {
	s.respond(req, tx, methodNotAllowed(req))
}

// methodNotAllowed is the 405 naming the methods the proxy does handle.
func methodNotAllowed(req *sip.Request) *sip.Response {
	res := sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
	res.AppendHeader(sip.NewHeader("Allow", strings.Join(allowedMethods, ", ")))
	return res
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
		s.log.Debug("respond", "err", err, "code", res.StatusCode, "sip_call_id", fsip.CallID(req))
	}
}

// reject is respond for an error status.
func (s *Server) reject(req *sip.Request, tx sip.ServerTransaction, code int, reason string) {
	s.respond(req, tx, sip.NewResponseFromRequest(req, code, reason, nil))
}
