package edge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// This file builds a complete, real deployment on loopback: a FreeSBC edge
// proxy, a fake FreeSWITCH upstream, and clients that speak SIP/UDP or
// SIP/WS. Nothing is mocked below the socket — the tests exercise the same
// sipgo transports, transactions and media sockets a production run uses.

// Ports for these tests come from this package's slice of the test port
// map (CLAUDE.md, "Test ports"), not from the kernel's ephemeral range.
//
// Asking the kernel for a port (bind :0, read it, close) and then binding
// it again is racy in two ways that both bite here: another test can win
// the second bind, and — more often — the kernel hands out the same
// ephemeral port to one of sipgo's own outbound client sockets. Since the
// harness needs a port it will hold for the whole test anyway, taking it
// from a band below the ephemeral range removes both races.
//
// Every package's band sits below 32768, where Linux's ephemeral range
// starts (macOS's starts at 49152), and no two packages' bands overlap, so
// `go test ./...` can run the packages in parallel. Within a band the
// cursor wraps, so -count=N never runs out, and every port is probed
// before it is handed out, so a port still held by an earlier test or by
// another process on the machine is skipped rather than failed on.
var (
	sipPorts   = &portBand{min: 25000, max: 27999}
	mediaPorts = &portBand{min: 28000, max: 32399}
)

// mediaWindow is how many ports each harness gets: 200 for the public RTP
// range and 200 for the private one.
const mediaWindow = 400

// portBand hands out runs of free ports from [min, max], wrapping around.
type portBand struct {
	mu       sync.Mutex
	min, max int
	next     int // 0 until first use
}

// take returns the first port of n consecutive ports that probe free,
// advancing the cursor past them. It gives up after one full lap.
func (b *portBand) take(t *testing.T, n int, free func(port int) bool) int {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.next == 0 {
		b.next = b.min
	}
	for scanned := 0; scanned <= b.max-b.min+1; {
		if b.next+n-1 > b.max {
			scanned += b.max - b.next + 1
			b.next = b.min
			continue
		}
		base, ok := b.next, true
		for p := base; p < base+n; p++ {
			if !free(p) {
				// Resume after the busy port: no run through it can be free.
				scanned += p - b.next + 1
				b.next = p + 1
				ok = false
				break
			}
		}
		if ok {
			b.next = base + n
			return base
		}
	}
	t.Fatalf("test port band %d-%d has no %d free consecutive ports", b.min, b.max, n)
	return 0
}

// udpFree probes a UDP port on the wildcard address, which fails if the
// port is bound on any local address.
func udpFree(port int) bool {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// sipFree probes both transports: a harness port may carry UDP or a
// WebSocket listener.
func sipFree(port int) bool {
	if !udpFree(port) {
		return false
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func nextPort(t *testing.T) int { return sipPorts.take(t, 1, sipFree) }

func freePort(t *testing.T) int    { return nextPort(t) }
func freeTCPPort(t *testing.T) int { return nextPort(t) }

// nextMediaBase hands each harness its own media port window. Windows are
// reused once the cursor wraps, but only after every port in the window
// probes free again.
func nextMediaBase(t *testing.T) int { return mediaPorts.take(t, mediaWindow, udpFree) }

// harness is one running proxy plus the addresses everything talks to.
type harness struct {
	t *testing.T

	srv   *Server
	store *config.Store

	publicUDP  string // where a SIP/UDP phone sends
	publicWS   string // where a browser connects
	privateSIP string // the proxy's FreeSWITCH-facing socket
	upstream   string // the fake FreeSWITCH

	fs *fakeSwitch

	// upstreams holds the fake switches of a multi-switch sip.upstreams
	// harness (startHarnessUpstreams), keyed by the node NAME the config and
	// the cooldown table use. Nodes deliberately left unreachable (a
	// documentation address, to force a transport error) have no entry.
	// Stopped with the rest of the harness.
	upstreams map[string]*fakeSwitch

	// carrier is the PSTN gateway fake when the harness configured
	// sip.pstn (startHarnessPSTN). It is stopped with the rest of the
	// harness.
	carrier *fakeSwitch

	// pstnGateways holds every gateway fake of a multi-gateway sip.pstn
	// harness (startHarnessPSTNGateways), keyed by the gateway NAME the
	// config and the cooldown health table are keyed by. Stopped with the
	// rest of the harness.
	pstnGateways map[string]*fakeSwitch

	cancel context.CancelFunc
	done   chan struct{}
}

// startHarness brings up the proxy and a fake FreeSWITCH.
func startHarness(t *testing.T, webrtc bool) *harness {
	return startHarnessOn(t, webrtc, "127.0.0.1")
}

// startHarnessOn is startHarness with the public UDP listener's bind host
// chosen by the caller. The wildcard host is how production binds the
// public plane (0.0.0.0) while the private plane sits on a specific
// address — a shape some transport-pool behaviour only distinguishes by
// the socket's local address, so the suite needs both forms.
func startHarnessOn(t *testing.T, webrtc bool, pubBindIP string) *harness {
	return startHarnessCfg(t, webrtc, pubBindIP, "127.0.0.1", nil)
}

// startHarnessCfg is startHarness with the upstream's IP and an optional
// sip.pstn block chosen by the caller. pstn, when non-nil, is called with
// the public UDP port once it is allocated and must return the YAML for
// the sip.pstn section ("" disables the trunk).
func startHarnessCfg(t *testing.T, webrtc bool, pubBindIP, upstreamIP string, pstn func(pubUDP int) string) *harness {
	t.Helper()
	pubUDP := freePort(t)
	pubWS := freeTCPPort(t)
	priv := freePort(t)
	up := freePort(t)
	// Media ranges are per-harness so no two tests contend for a port.
	mediaBase := nextMediaBase(t)

	pstnBlock := ""
	if pstn != nil {
		pstnBlock = pstn(pubUDP)
	}
	yaml := fmt.Sprintf(`
network:
  public:
    bind_ip: 127.0.0.1
    advertised_ip: 127.0.0.1
  private:
    bind_ip: 127.0.0.1
    advertised_ip: 127.0.0.1
sip:
  public:
    udp: {enabled: true, bind: "%s:%d"}
    ws:  {enabled: true, bind: "127.0.0.1:%d"}
  private:
    bind: "127.0.0.1:%d"
  upstream:
    address: %s:%d
%s
rtp:
  public:  {bind_ip: 127.0.0.1, advertised_ip: 127.0.0.1, port_min: %d, port_max: %d}
  private: {bind_ip: 127.0.0.1, advertised_ip: 127.0.0.1, port_min: %d, port_max: %d}
webrtc:
  enabled: %v
listen:
  media:
    rtp_timeout: 60s
shield:
  # Every test client shares 127.0.0.1, so the production default of
  # 20/s per_ip would throttle the harness itself rather than the code
  # under test. The rate limiter has its own tests in package shield.
  rate_limit: "5000/s per_ip"
`, pubBindIP, pubUDP, pubWS, priv, upstreamIP, up, pstnBlock, mediaBase, mediaBase+199, mediaBase+200, mediaBase+399, webrtc)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("harness config: %v", err)
	}
	store := config.NewStore(cfg)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	srv, err := New(store, log)
	if err != nil {
		t.Fatal(err)
	}

	h := &harness{
		t: t, srv: srv, store: store,
		publicUDP:  fmt.Sprintf("127.0.0.1:%d", pubUDP),
		publicWS:   fmt.Sprintf("127.0.0.1:%d", pubWS),
		privateSIP: fmt.Sprintf("127.0.0.1:%d", priv),
		upstream:   fmt.Sprintf("%s:%d", upstreamIP, up),
		done:       make(chan struct{}),
	}
	h.fs = startFakeSwitch(t, h.upstream)

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("proxy Run: %v", err)
		}
	}()
	select {
	case <-srv.ready:
	case <-h.done:
		t.Fatal("proxy exited before it was ready")
	case <-time.After(10 * time.Second):
		t.Fatal("proxy never became ready")
	}
	t.Cleanup(h.stop)
	assertProxyServing(t, srv)
	return h
}

// startHarnessPSTN is startHarness with a configured sip.pstn trunk: the
// same proxy, plus a fake PSTN carrier gateway on the public side that
// FreeSWITCH-bridged calls get forwarded to. It returns the carrier switch
// so a test can install its answer hooks and assert on what it receives.
//
// The upstream FreeSWITCH is placed on 127.0.0.2 rather than loopback's
// 127.0.0.1: the proxy classifies a PSTN bridge by the request's SOURCE
// being the upstream, and the classification's other half is a Request-URI
// a phone could just as well dial — all on one loopback address, the
// source gate could never be exercised, because the upstream and every
// client would be the same IP. Splitting them makes "the upstream bridged
// it" and "a phone dialed it" distinguishable, which is exactly the
// distinction the feature depends on.
func startHarnessPSTN(t *testing.T) (*harness, *fakeSwitch) {
	t.Helper()
	// The carrier gateway address must be in the config, so its port is
	// fixed up front; the switch itself is only started once the harness
	// is up, since the proxy never pings a peer-to-peer gateway (there is
	// nothing to ping: no registration, no keepalives).
	carrierAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h := startHarnessCfg(t, false, "127.0.0.1", "127.0.0.2", func(pubUDP int) string {
		return fmt.Sprintf("  pstn:\n    address: %s\n    match: 127.0.0.1:%d\n", carrierAddr, pubUDP)
	})
	carrier := startFakeSwitch(t, carrierAddr)
	h.carrier = carrier
	return h, carrier
}

// startHarnessPSTNGateways is startHarness with a configured MULTI-gateway
// sip.pstn block. gwAddrs names every gateway — map key is the gateway's
// config name, map value the "host:port" it lives on (fixed up front by the
// caller, exactly as startHarnessPSTN fixes the carrier's, because the
// address must be in the config before the switch can be started) — and the
// harness writes one {address, transport: udp} gateway per name into the
// config, starts a fake carrier switch on each address, and returns the
// switches keyed by gateway NAME: the name a route's `to:` list refers to,
// and the name a cooldown penalizes.
//
// routesYAML is spliced verbatim under the config's `routes:` key — the
// caller's lines must carry the six-space indent the examples in pstn_test
// use — so the failover ORDER and the match prefixes are the caller's to
// choose. attemptTimeout, when non-empty, is spliced under `attempt_timeout:`
// (the tests that need a fast-failing gateway pass "300ms"); the match is
// always the harness's own public UDP socket, and cooldown rides the
// 30-second default unless the caller wants otherwise.
func startHarnessPSTNGateways(t *testing.T, attemptTimeout, routesYAML string, gwAddrs map[string]string) (*harness, map[string]*fakeSwitch) {
	t.Helper()
	if len(gwAddrs) == 0 {
		t.Fatal("startHarnessPSTNGateways needs at least one gateway")
	}
	// Deterministic config: sort the names so the YAML — and with it the
	// topology the proxy builds — never depends on map iteration order.
	names := make([]string, 0, len(gwAddrs))
	for name := range gwAddrs {
		names = append(names, name)
	}
	sort.Strings(names)
	var gateways strings.Builder
	for _, name := range names {
		fmt.Fprintf(&gateways, "      %s:\n        address: %s\n", name, gwAddrs[name])
	}
	budget := ""
	if attemptTimeout != "" {
		budget = "    attempt_timeout: " + attemptTimeout + "\n"
	}
	h := startHarnessCfg(t, false, "127.0.0.1", "127.0.0.2", func(pubUDP int) string {
		return fmt.Sprintf("  pstn:\n    match: 127.0.0.1:%d\n%s    gateways:\n%s    routes:\n%s",
			pubUDP, budget, gateways.String(), routesYAML)
	})
	switches := make(map[string]*fakeSwitch, len(names))
	h.pstnGateways = make(map[string]*fakeSwitch, len(names))
	for _, name := range names {
		gw := startFakeSwitch(t, gwAddrs[name])
		h.pstnGateways[name] = gw
		switches[name] = gw
	}
	return h, switches
}

// startHarnessUpstreams is startHarness with a configured MULTI-switch
// sip.upstreams pool. nodes maps the node NAME — the name the cooldown
// table, the logs and the tests use — to its "host:port" address.
//
// The YAML template is a deliberate COPY of startHarnessCfg's rather than a
// call into it: the existing single-upstream harness must stay
// byte-for-byte unchanged (D9), and startHarnessCfg's shape — one
// `upstream:` stanza — cannot express a pool anyway. The copy also has no
// `fs:` field to fill, so h.fs stays nil and stop() guards it.
//
// A fake switch is started for every node on a LOOPBACK address. A node on
// any other address (the documentation range, e.g. 192.0.2.1:5060)
// deliberately gets none: the proxy's private socket binds loopback, and a
// UDP socket bound to loopback cannot send to a documentation address at
// all — the send fails immediately with EINVAL. That deterministic
// transport error is exactly what the failover tests need; a closed socket
// would instead swallow the datagram silently, and a silent node is
// indistinguishable from a slow one (D5).
func startHarnessUpstreams(t *testing.T, algorithm, cooldown string, nodes map[string]string) (*harness, map[string]*fakeSwitch) {
	t.Helper()
	if len(nodes) == 0 {
		t.Fatal("startHarnessUpstreams needs at least one node")
	}
	pubUDP := freePort(t)
	pubWS := freeTCPPort(t)
	priv := freePort(t)
	// Media ranges are per-harness so no two tests contend for a port.
	mediaBase := nextMediaBase(t)

	// Deterministic config: sort the names so neither the YAML nor the
	// topology it produces ever depends on map iteration order.
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	var opts, nodeLines strings.Builder
	if algorithm != "" {
		fmt.Fprintf(&opts, "    algorithm: %s\n", algorithm)
	}
	if cooldown != "" {
		fmt.Fprintf(&opts, "    cooldown: %s\n", cooldown)
	}
	for _, name := range names {
		fmt.Fprintf(&nodeLines, "      %s:\n        address: %s\n", name, nodes[name])
	}

	yaml := fmt.Sprintf(`
network:
  public:
    bind_ip: 127.0.0.1
    advertised_ip: 127.0.0.1
  private:
    bind_ip: 127.0.0.1
    advertised_ip: 127.0.0.1
sip:
  public:
    udp: {enabled: true, bind: "127.0.0.1:%d"}
    ws:  {enabled: true, bind: "127.0.0.1:%d"}
  private:
    bind: "127.0.0.1:%d"
  upstreams:
%s    nodes:
%s
rtp:
  public:  {bind_ip: 127.0.0.1, advertised_ip: 127.0.0.1, port_min: %d, port_max: %d}
  private: {bind_ip: 127.0.0.1, advertised_ip: 127.0.0.1, port_min: %d, port_max: %d}
webrtc:
  enabled: false
listen:
  media:
    rtp_timeout: 60s
shield:
  rate_limit: "5000/s per_ip"
`, pubUDP, pubWS, priv, opts.String(), nodeLines.String(), mediaBase, mediaBase+199, mediaBase+200, mediaBase+399)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("upstreams harness config: %v", err)
	}
	store := config.NewStore(cfg)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	srv, err := New(store, log)
	if err != nil {
		t.Fatal(err)
	}

	h := &harness{
		t: t, srv: srv, store: store,
		publicUDP:  fmt.Sprintf("127.0.0.1:%d", pubUDP),
		publicWS:   fmt.Sprintf("127.0.0.1:%d", pubWS),
		privateSIP: fmt.Sprintf("127.0.0.1:%d", priv),
		upstreams:  map[string]*fakeSwitch{},
		done:       make(chan struct{}),
	}
	switches := map[string]*fakeSwitch{}
	for _, name := range names {
		host, _, err := net.SplitHostPort(nodes[name])
		if err != nil {
			t.Fatalf("node %s address %q: %v", name, nodes[name], err)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			continue // deliberately unreachable; see the doc comment
		}
		fs := startFakeSwitch(t, nodes[name])
		h.upstreams[name] = fs
		switches[name] = fs
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("proxy Run: %v", err)
		}
	}()
	select {
	case <-srv.ready:
	case <-h.done:
		t.Fatal("proxy exited before it was ready")
	case <-time.After(10 * time.Second):
		t.Fatal("proxy never became ready")
	}
	t.Cleanup(h.stop)
	assertProxyServing(t, srv)
	return h, switches
}

func (h *harness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		h.t.Error("proxy did not shut down")
	}
	// h.fs is nil in a pool harness (startHarnessUpstreams): there is no
	// single upstream, and a nil fake must not panic the cleanup path.
	if h.fs != nil {
		h.fs.stop()
	}
	for _, up := range h.upstreams {
		up.stop()
	}
	if h.carrier != nil {
		h.carrier.stop()
	}
	for _, gw := range h.pstnGateways {
		gw.stop()
	}
}

// ---------------------------------------------------------------------
// Fake FreeSWITCH
// ---------------------------------------------------------------------

// fakeSwitch is a minimal upstream: it challenges the first REGISTER,
// accepts the second, and answers INVITEs with an SDP of its own. Every
// request it receives is recorded so a test can assert on exactly what
// FreeSBC sent — which is where the "no private address leaks out, no
// public address leaks in" guarantees are actually checked.
type fakeSwitch struct {
	t    *testing.T
	addr string

	ua  *sipgo.UserAgent
	srv *sipgo.Server
	cli *sipgo.Client

	mu       sync.Mutex
	requests []*sip.Request
	// challenge, when true, makes the next REGISTER get a 401.
	challenge bool
	// registerStatus, when non-zero, is the final status every REGISTER
	// gets instead of the challenge-then-200 exchange — a registrar that
	// refuses the AoR outright.
	registerStatus int
	// answerSDP is what the switch answers an INVITE with; %d is its RTP
	// port.
	rtpPort int
	// registeredContacts records the Contact of every accepted REGISTER,
	// which is what FreeSWITCH would store and later use as a
	// Request-URI.
	registeredContacts []string

	// inviteHook, if set, overrides the default INVITE behaviour. Guarded
	// by mu: the test goroutine installs it while handler goroutines may
	// already be reading it.
	inviteHook func(req *sip.Request, tx sip.ServerTransaction) bool

	conn   *net.UDPConn
	cancel context.CancelFunc
	done   chan struct{}
}

func startFakeSwitch(t *testing.T, addr string) *fakeSwitch {
	t.Helper()
	f := &fakeSwitch{t: t, addr: addr, challenge: true, rtpPort: freePort(t), done: make(chan struct{})}

	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	f.ua = ua
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	cli, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatal(err)
	}
	f.cli = cli

	srv.OnRegister(f.onRegister)
	srv.OnInvite(f.onInvite)
	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) { f.record(req) })
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		f.record(req)
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	srv.OnCancel(func(req *sip.Request, tx sip.ServerTransaction) {
		f.record(req)
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	srv.OnNoRoute(func(req *sip.Request, tx sip.ServerTransaction) {
		f.record(req)
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})

	ua2, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua2)
	if err != nil {
		t.Fatal(err)
	}
	f.conn = conn
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go func() { <-ctx.Done(); conn.Close() }()
	go func() {
		defer close(f.done)
		_ = srv.TransportLayer().ServeUDP(conn)
	}()
	waitUDPServing(t, srv.TransportLayer(), conn)
	return f
}

// assertProxyServing fails the test unless every proxy UDP listener is
// already in its sipgo transport's connection pool the moment Ready has
// closed — without waiting.
//
// sipgo adds a UDP listener to the pool only from the goroutine serving
// it. A request the proxy sends from that listener's address before then
// (forwarding upstream from the private bind) misses the pool, sipgo binds
// a second socket on the same address, and the caller gets a 503. Run
// closes Ready only once every UDP listener is pooled; the harnesses check
// that here, on every start, rather than wait the window out.
//
// The addresses checked are the topology's pins, which Run rewrites to
// each socket's real local address before Ready closes — what outbound
// requests name and what sipgo keys its pool by. A configured wildcard is
// not that address: on a host with IPv6, 0.0.0.0 binds a dual-stack
// socket whose local address is [::]:port.
//
// regression: edge startup race
func assertProxyServing(t *testing.T, srv *Server) {
	t.Helper()
	tl := srv.srv.TransportLayer()             // written before Ready closed
	pins := []sip.Addr{srv.topo.private.laddr} // srv.topo is re-pinned before Ready too
	for _, s := range srv.topo.public {
		if s.transport == "udp" {
			pins = append(pins, s.laddr)
		}
	}
	for _, laddr := range pins {
		addr := laddr.String()
		if c, err := tl.GetConnection("udp", addr); err != nil || c == nil {
			t.Errorf("Ready closed before the proxy's udp listener %s was serving (err=%v)", addr, err)
		}
	}
}

// waitUDPServing returns once sipgo has put conn in its transport's
// connection pool.
//
// ServeUDP adds the listener to the pool from the goroutine that serves
// it. A request sent from the listener's own address (req.Laddr, as the
// fake switch does so the proxy sees the upstream address) before that has
// happened misses the pool, and sipgo tries to bind a second socket on the
// same address: "listen udp ...: bind: address already in use".
func waitUDPServing(t *testing.T, tl *sip.TransportLayer, conn *net.UDPConn) {
	t.Helper()
	addr := conn.LocalAddr().String()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, err := tl.GetConnection("udp", addr); err == nil && c != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sipgo never started serving %s", addr)
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *fakeSwitch) stop() {
	f.cancel()
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
	}
	_ = f.cli.Close()
	_ = f.ua.Close()
}

// setInviteHook installs an INVITE override.
func (f *fakeSwitch) setInviteHook(hook func(req *sip.Request, tx sip.ServerTransaction) bool) {
	f.mu.Lock()
	f.inviteHook = hook
	f.mu.Unlock()
}

// answerHook returns an INVITE override that answers EVERY INVITE with the
// same final status: 2xx carries the switch's own SDP plus a fresh To tag
// and a Contact (a 2xx needs all three for the dialog machinery that
// follows it — the To tag names the dialog, and in-dialog requests are
// routed by the Contact); any other code is a bodyless final. Failover
// tests dial one gateway across several calls, so the hook is stateless by
// design.
func (f *fakeSwitch) answerHook(code int, withBody bool) func(req *sip.Request, tx sip.ServerTransaction) bool {
	return func(req *sip.Request, tx sip.ServerTransaction) bool {
		var body []byte
		if withBody {
			body = []byte(f.answerSDP(req))
		}
		res := sip.NewResponseFromRequest(req, code, pstnReasonFor(code), body)
		if withBody {
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		}
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(f.addr)}})
		if code/100 == 2 {
			res.To().Params.Add("tag", sip.GenerateTagN(12))
		}
		_ = tx.Respond(res)
		return true
	}
}

// silentHook returns an INVITE override that swallows the request the way a
// carrier that accepted the call and never answers does: no provisional, no
// final — the "black hole" an attempt budget exists for.
//
// sipgo destroys a server transaction the moment its handler returns
// without a final response, and a destroyed transaction could never match
// the attempt's CANCEL or send the 487 the budget-expiry path drains for.
// A real gateway holds the transaction while it rings, so this hook holds
// it too: it parks until the CANCEL arrives, then lets sipgo answer the
// CANCEL with 200 and 487 the INVITE. The CANCEL itself is recorded here —
// a matched CANCEL is consumed by the transaction layer and never reaches
// the switch's OnCancel handler.
func (f *fakeSwitch) silentHook() func(req *sip.Request, tx sip.ServerTransaction) bool {
	return func(req *sip.Request, tx sip.ServerTransaction) bool {
		cancelled := make(chan struct{})
		armed := tx.OnCancel(func(cancelReq *sip.Request) {
			f.record(cancelReq)
			close(cancelled)
		})
		if !armed {
			// The CANCEL beat the hook to it; nothing is left to answer.
			return true
		}
		select {
		case <-cancelled:
		case <-time.After(10 * time.Second):
		}
		return true
	}
}

// pstnReasonFor is the reason phrase for the statuses answerHook uses; the
// wire format wants one, and the last-real-code synthesis relays it.
func pstnReasonFor(code int) string {
	switch code {
	case 200:
		return "OK"
	case 486:
		return "Busy Here"
	case 500:
		return "Server Internal Error"
	case 503:
		return "Service Unavailable"
	}
	return "Call Failure"
}

func (f *fakeSwitch) record(req *sip.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, req.Clone())
	f.mu.Unlock()
}

// received returns every request of a method the switch has seen.
func (f *fakeSwitch) received(method sip.RequestMethod) []*sip.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*sip.Request
	for _, r := range f.requests {
		if r.Method == method {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeSwitch) waitFor(method sip.RequestMethod, n int, d time.Duration) []*sip.Request {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if got := f.received(method); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return f.received(method)
}

// waitForAckBranch returns the ACKs whose top Via branch matches branch.
// A non-2xx final's ACK is generated by the transaction layer and echoes the
// INVITE's own branch (RFC 3261 §17.1.1.3); an ACK that a proxy relayed
// carries a branch of its own, so matching on the method alone would count
// the wrong message.
func (f *fakeSwitch) waitForAckBranch(branch string, d time.Duration) []*sip.Request {
	deadline := time.Now().Add(d)
	for {
		var out []*sip.Request
		for _, r := range f.received(sip.ACK) {
			if b, _ := r.Via().Params.Get("branch"); b == branch {
				out = append(out, r)
			}
		}
		if len(out) > 0 || time.Now().After(deadline) {
			return out
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fakeSwitch) contacts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.registeredContacts...)
}

// sendResponse writes a response the switch built earlier, from the switch's
// own socket and without a transaction — the way its transport layer would
// send one, but at the moment a test chooses. A test that needs to control
// WHEN a final goes out (the CANCEL/487 ordering) builds it in an inviteHook
// — where the request still carries the source it came from — and hands it
// here later.
func (f *fakeSwitch) sendResponse(t *testing.T, res *sip.Response) {
	t.Helper()
	if err := f.srv.TransportLayer().WriteMsg(res); err != nil {
		t.Fatalf("fake switch %d response: %v", res.StatusCode, err)
	}
}

// onRegister challenges once, then accepts — the exact two-step digest
// exchange a real registrar performs, so the test can prove the challenge
// and the credential both cross FreeSBC untouched.
func (f *fakeSwitch) onRegister(req *sip.Request, tx sip.ServerTransaction) {
	f.record(req)
	f.mu.Lock()
	challenge := f.challenge && req.GetHeader("Authorization") == nil
	status := f.registerStatus
	f.mu.Unlock()
	if status != 0 {
		_ = tx.Respond(sip.NewResponseFromRequest(req, status, "", nil))
		return
	}
	if challenge {
		res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
		res.AppendHeader(sip.NewHeader("WWW-Authenticate",
			`Digest realm="example.com", nonce="abc123nonce", algorithm=MD5, qop="auth"`))
		_ = tx.Respond(res)
		return
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	if hs := req.GetHeaders("Contact"); len(hs) > 0 {
		c, _ := hs[0].(*sip.ContactHeader)
		f.mu.Lock()
		f.registeredContacts = append(f.registeredContacts, c.Address.String())
		f.mu.Unlock()
		echo := &sip.ContactHeader{Address: c.Address, Params: sip.NewParams()}
		// Grant less than asked for, so the test proves FreeSBC honours
		// the registrar's expiry rather than the client's request.
		echo.Params.Add("expires", "120")
		res.AppendHeader(echo)
	}
	res.AppendHeader(sip.NewHeader("Expires", "120"))
	_ = tx.Respond(res)
}

func (f *fakeSwitch) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	f.record(req)
	f.mu.Lock()
	hook := f.inviteHook
	f.mu.Unlock()
	if hook != nil && hook(req, tx) {
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
	_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
	res := sip.NewResponseFromRequest(req, 200, "OK", []byte(f.answerSDP(req)))
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(f.addr)}})
	_ = tx.Respond(res)
}

// answerSDP answers with PCMU plus whatever telephone-event payload type
// the offer used, so DTMF survives — the RFC 3264 rule that an answerer
// reuses the offerer's payload numbers is exactly what FreeSBC relies on.
func (f *fakeSwitch) answerSDP(req *sip.Request) string {
	dtmf := ""
	body := string(req.Body())
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=rtpmap:") && strings.Contains(line, "telephone-event") {
			pt := strings.TrimPrefix(strings.SplitN(line, " ", 2)[0], "a=rtpmap:")
			dtmf = pt
		}
	}
	fmts := "0"
	attrs := "a=rtpmap:0 PCMU/8000\r\n"
	if dtmf != "" {
		fmts += " " + dtmf
		attrs += fmt.Sprintf("a=rtpmap:%s telephone-event/8000\r\na=fmtp:%s 0-15\r\n", dtmf, dtmf)
	}
	return fmt.Sprintf("v=0\r\no=FreeSWITCH 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
		"m=audio %d RTP/AVP %s\r\n%sa=sendrecv\r\n", f.rtpPort, fmts, attrs)
}

func portOf(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	var n int
	fmt.Sscanf(p, "%d", &n)
	return n
}

// hostOf returns the host half of a "host:port" address.
func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// call places an INVITE from the fake switch toward the proxy's private
// socket, the way FreeSWITCH calls a registered contact, and returns the
// final response.
func (f *fakeSwitch) call(t *testing.T, ruri sip.Uri, dest, body string, extra ...sip.Header) *sip.Response {
	t.Helper()
	req := sip.NewRequest(sip.INVITE, ruri)
	from := &sip.FromHeader{Address: sip.Uri{User: "3003", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(12))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: ruri, Params: sip.NewParams()})
	callID := sip.CallIDHeader(fmt.Sprintf("fs-call-%d", time.Now().UnixNano()))
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: "127.0.0.1", Port: portOf(f.addr)}})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "127.0.0.1", Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	for _, h := range extra {
		req.AppendHeader(h)
	}
	req.SetBody([]byte(body))
	req.SetTransport("UDP")
	req.SetDestination(dest)
	// Send from the switch's own listening socket, so the proxy sees the
	// configured upstream address as the source. A switch that lives on
	// another loopback address (startHarnessPSTN's 127.0.0.2) must source
	// from there too — the proxy's private plane trusts exactly that IP.
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("fake switch INVITE: %v", err)
	}
	defer tx.Terminate()
	for {
		select {
		case res, ok := <-tx.Responses():
			if !ok {
				t.Fatal("fake switch INVITE: no final response")
			}
			if res.StatusCode >= 200 {
				return res
			}
		case <-tx.Done():
			t.Fatalf("fake switch INVITE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("fake switch INVITE timed out")
		}
	}
}

// inDialog sends an in-dialog request from the fake switch, built the way
// a UAS builds one: Request-URI = the remote target (the Contact it
// received), Route = the Record-Route set from the request IN ORDER
// (RFC 3261 §12.1.1 — the UAS does not reverse it), From/To swapped
// relative to the INVITE because the switch is now the sender.
func (f *fakeSwitch) inDialog(t *testing.T, method sip.RequestMethod, invite *sip.Request, toTag string) *sip.Response {
	t.Helper()
	target, ok := fsip.ContactURI(invite)
	if !ok {
		t.Fatal("the INVITE the switch received carried no Contact")
	}
	req := sip.NewRequest(method, target)

	// The switch was the UAS: its own identity was in the To, the peer's
	// in the From. In-dialog, the sender's identity goes in From.
	from := &sip.FromHeader{Address: invite.To().Address, Params: sip.NewParams()}
	from.Params.Add("tag", toTag)
	req.AppendHeader(from)
	to := &sip.ToHeader{Address: invite.From().Address, Params: sip.NewParams()}
	if tag, ok := invite.From().Params.Get("tag"); ok {
		to.Params.Add("tag", tag)
	}
	req.AppendHeader(to)
	sip.CopyHeaders("Call-ID", invite, req)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: method})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(f.addr)}})
	for _, h := range invite.GetHeaders("Record-Route") {
		rr, ok := h.(*sip.RecordRouteHeader)
		if !ok {
			continue
		}
		req.AppendHeader(&sip.RouteHeader{Address: rr.Address})
	}
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: "127.0.0.1", Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)

	// Route to the topmost Route value, as a loose router does.
	dest := f.topRouteDest(t, req)
	req.SetTransport("UDP")
	req.SetDestination(dest)
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("fake switch %s: %v", method, err)
	}
	defer tx.Terminate()
	for {
		select {
		case res, ok := <-tx.Responses():
			if !ok {
				t.Fatalf("fake switch %s: no final response", method)
			}
			if res.StatusCode >= 200 {
				return res
			}
		case <-tx.Done():
			t.Fatalf("fake switch %s: %v", method, tx.Err())
		case <-ctx.Done():
			t.Fatalf("fake switch %s timed out", method)
		}
	}
}

func (f *fakeSwitch) topRouteDest(t *testing.T, req *sip.Request) string {
	t.Helper()
	r := req.Route()
	if r == nil {
		t.Fatal("no Route set: the proxy did not Record-Route")
	}
	port := r.Address.Port
	if port == 0 {
		port = 5060
	}
	return fmt.Sprintf("%s:%d", r.Address.Host, port)
}

// inDialogDest picks where the switch sends an in-dialog request: the top
// Route when the dialog has a route set, else the remote target — the
// Contact of the 2xx that established the dialog. (The second branch is
// the RFC 3261 §12.1.2 fallback; every dialog in this suite carries
// Record-Routes, so it is defence rather than a live path.)
func (f *fakeSwitch) inDialogDest(t *testing.T, req *sip.Request, res *sip.Response) string {
	t.Helper()
	if req.Route() != nil {
		return f.topRouteDest(t, req)
	}
	u, ok := fsip.ContactURI(res)
	if !ok {
		t.Fatal("no Route and no Contact to route the in-dialog request to")
	}
	port := u.Port
	if port == 0 {
		port = 5060
	}
	return fmt.Sprintf("%s:%d", u.Host, port)
}

// sendAckTo2xx sends the ACK for a 2xx the switch received as the UAC of a
// call IT placed (the role f.call leaves it in). The ACK for a 2xx is a
// separate end-to-end transaction (RFC 3261 §17.1.1.3), so it is written
// statelessly — never through a client transaction. Request-URI, From/To
// and Call-ID come from the response, and the route set is the response's
// Record-Route set in reverse, exactly as a UAC builds it.
func (f *fakeSwitch) sendAckTo2xx(t *testing.T, res *sip.Response) {
	t.Helper()
	req := sip.NewRequest(sip.ACK, res.To().Address)
	sip.CopyHeaders("From", res, req)
	sip.CopyHeaders("To", res, req)
	sip.CopyHeaders("Call-ID", res, req)
	seq := uint32(1)
	if c := res.CSeq(); c != nil {
		seq = c.SeqNo
	}
	req.AppendHeader(&sip.CSeqHeader{SeqNo: seq, MethodName: sip.ACK})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	copyRouteFromRecordRoute(res, req)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: hostOf(f.addr), Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	req.SetTransport("UDP")
	req.SetDestination(f.inDialogDest(t, req, res))
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}
	if err := f.cli.WriteRequest(req); err != nil {
		t.Fatalf("fake switch ACK: %v", err)
	}
}

// uacBye sends an in-dialog BYE from the fake switch as the UAC of a call
// IT placed, and waits for the final response. Same shape as fsUacBye —
// Request-URI and headers copied from the final response, Route = the
// Record-Route set in reverse (RFC 3261 §12.1.2) — as a method so a switch
// on any loopback address sources the request from its own socket.
func (f *fakeSwitch) uacBye(t *testing.T, res *sip.Response) *sip.Response {
	t.Helper()
	req := sip.NewRequest(sip.BYE, res.To().Address)
	sip.CopyHeaders("From", res, req)
	sip.CopyHeaders("To", res, req)
	sip.CopyHeaders("Call-ID", res, req)
	seq := uint32(1)
	if c := res.CSeq(); c != nil {
		seq = c.SeqNo
	}
	req.AppendHeader(&sip.CSeqHeader{SeqNo: seq + 1, MethodName: sip.BYE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: hostOf(f.addr), Port: portOf(f.addr)}})
	copyRouteFromRecordRoute(res, req)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: hostOf(f.addr), Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)

	req.SetTransport("UDP")
	req.SetDestination(f.inDialogDest(t, req, res))
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}

	ctx, cancel := timeoutCtx(10 * time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("fake switch BYE: %v", err)
	}
	defer tx.Terminate()
	for {
		select {
		case r, ok := <-tx.Responses():
			if !ok {
				t.Fatal("fake switch BYE: no final response")
			}
			if r.StatusCode >= 200 {
				return r
			}
		case <-tx.Done():
			t.Fatalf("fake switch BYE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("fake switch BYE timed out")
		}
	}
}

// parseLabSDP parses a body the way the harness's SBC does: every media
// plane here is on loopback, so a loopback c= is legitimate.
func parseLabSDP(body []byte) (*sdp.Session, error) {
	return sdp.ParseWithOptions(body, sdp.ParseOptions{AllowLoopback: true})
}
