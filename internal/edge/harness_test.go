package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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

// mediaWindow is how many ports each harness gets: one RTP range shared by
// the public and the private pool (both bind 127.0.0.1 in the harness, so
// they split it by whichever binds first).
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
	publicWSS  string // where a browser connects over TLS ("" unless startHarnessWSS)
	privateSIP string // the proxy's FreeSWITCH-facing socket
	upstream   string // the fake FreeSWITCH

	fs *fakeSwitch

	// upstreams holds the fake switches of a multi-switch edge.switch
	// harness (startHarnessSwitches), keyed by the node name ("IP:port").
	// Nodes deliberately left unreachable (a non-loopback address, to force
	// a transport error) have no entry. Stopped with the rest of the
	// harness.
	upstreams map[string]*fakeSwitch

	cancel context.CancelFunc
	done   chan struct{}
}

// harnessPrivatePlaceholder is private.ip in the harness config: a
// non-local address, because the real private socket is overridden to a
// loopback port by WithPrivateAddr (the test seam), while validation still
// wants private.ip distinct from public.bind.
const harnessPrivatePlaceholder = "192.0.2.250"

// harnessCarrierSources is the carrier_sources of the shared fixtures (see
// startHarnessWith).
const harnessCarrierSources = "127.0.0.1"

// startHarness brings up the proxy and a fake FreeSWITCH. webrtc adds the
// ws listener (WebRTC is enabled iff ws or wss is configured).
func startHarness(t *testing.T, webrtc bool) *harness {
	t.Helper()
	return startHarnessWith(t, webrtc, false)
}

// startHarnessWSS is startHarness with a wss listener as well, serving a
// freshly generated self-signed certificate written to t.TempDir() as the
// top-level tls pair (newWSSClient skips verification).
func startHarnessWSS(t *testing.T, webrtc bool) *harness {
	t.Helper()
	return startHarnessWith(t, webrtc, true)
}

// startHarnessWith builds every single-switch harness variant. The fake
// FreeSWITCH, like every other test endpoint, lives on 127.0.0.1, so the
// suite needs no loopback alias (macOS configures only 127.0.0.1).
//
// Every client shares 127.0.0.1, so the shared fixture lists it in
// edge.carrier_sources (harnessCarrierSources): the INVITE admission check
// (admission.go) then admits every test client's out-of-dialog INVITE, as
// it admits a carrier's, and the call-flow tests stay about call flow. The
// admission tests use startHarnessStrict, which leaves the list out.
func startHarnessWith(t *testing.T, webrtc, wss bool) *harness {
	t.Helper()
	return startHarnessFull(t, webrtc, wss, harnessCarrierSources)
}

// startHarnessStrict is startHarness (plus a wss listener when wss is set)
// WITHOUT edge.carrier_sources, so the INVITE admission check is live for
// 127.0.0.1 clients: only a registered transport address may place a call.
func startHarnessStrict(t *testing.T, webrtc, wss bool) *harness {
	t.Helper()
	return startHarnessFull(t, webrtc, wss, "")
}

// writeTestTLS writes a freshly generated self-signed ECDSA certificate for
// 127.0.0.1 and its key into dir and returns the two paths.
func writeTestTLS(t testing.TB, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "freesbc-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// harnessYAML renders the v2 config every harness shares: public on
// 127.0.0.1, a placeholder private.ip (the private socket is overridden by
// WithPrivateAddr), the given switch nodes, one RTP range for both pools
// and a shield limit high enough that the harness itself is never throttled
// (the rate limiter has its own tests in package shield).
func harnessYAML(t testing.TB, switches []string, pubUDP, pubWS, pubWSS, mediaBase int, carrierSources string) string {
	t.Helper()
	var listen []string
	listen = append(listen, fmt.Sprintf("udp: %d", pubUDP))
	if pubWS != 0 {
		listen = append(listen, fmt.Sprintf("ws: %d", pubWS))
	}
	tlsBlock := ""
	if pubWSS != 0 {
		listen = append(listen, fmt.Sprintf("wss: %d", pubWSS))
		cert, key := writeTestTLS(t, t.TempDir())
		tlsBlock = fmt.Sprintf("tls: {cert: %q, key: %q}\n", cert, key)
	}
	carriers := ""
	if carrierSources != "" {
		carriers = fmt.Sprintf("  carrier_sources: [%s]\n", carrierSources)
	}
	return fmt.Sprintf(`
public: {ip: 127.0.0.1}
private: {ip: %s}
rtp: "%d-%d"
%sedge:
  switch: [%s]
  listen: {%s}
%sshield:
  rate_limit: "5000/s per_ip"
  carrier_rate_limit: "5000/s per_ip"
`, harnessPrivatePlaceholder, mediaBase, mediaBase+mediaWindow-1, tlsBlock,
		strings.Join(switches, ", "), strings.Join(listen, ", "), carriers)
}

// newHarness parses the config, builds the proxy with the private socket on
// 127.0.0.1:priv and starts it; the caller attaches the fake switches.
func newHarness(t *testing.T, yaml string, priv int) *harness {
	t.Helper()
	return newHarnessLog(t, yaml, priv, slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// newHarnessLog is newHarness with the proxy's log handler chosen by the
// caller, so a test can inspect what the proxy logs.
func newHarnessLog(t *testing.T, yaml string, priv int, handler slog.Handler) *harness {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("harness config: %v", err)
	}
	store := config.NewStore(cfg)
	log := slog.New(handler)
	srv, err := New(store, log, WithPrivateAddr(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", priv))))
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Edge.Listen
	h := &harness{
		t: t, srv: srv, store: store,
		publicUDP:  fmt.Sprintf("127.0.0.1:%d", l.UDP),
		privateSIP: fmt.Sprintf("127.0.0.1:%d", priv),
		upstreams:  map[string]*fakeSwitch{},
		done:       make(chan struct{}),
	}
	if l.WS != 0 {
		h.publicWS = fmt.Sprintf("127.0.0.1:%d", l.WS)
	}
	if l.WSS != 0 {
		h.publicWSS = fmt.Sprintf("127.0.0.1:%d", l.WSS)
	}
	return h
}

// run starts the proxy and waits until it serves.
func (h *harness) run() {
	t := h.t
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		if err := h.srv.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("proxy Run: %v", err)
		}
	}()
	select {
	case <-h.srv.ready:
	case <-h.done:
		t.Fatal("proxy exited before it was ready")
	case <-time.After(10 * time.Second):
		t.Fatal("proxy never became ready")
	}
	t.Cleanup(h.stop)
	assertProxyServing(t, h.srv)
}

// startHarnessFull builds the single-switch harness with the given
// edge.carrier_sources list body ("" configures none).
func startHarnessFull(t *testing.T, webrtc, wss bool, carrierSources string) *harness {
	t.Helper()
	pubUDP := freePort(t)
	pubWS, pubWSS := 0, 0
	if webrtc {
		pubWS = freeTCPPort(t)
	}
	if wss {
		pubWSS = freeTCPPort(t)
	}
	priv := freePort(t)
	up := freePort(t)
	// The media range is per-harness so no two tests contend for a port.
	mediaBase := nextMediaBase(t)

	h := newHarness(t, harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, pubWS, pubWSS, mediaBase, carrierSources), priv)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.run()
	return h
}

// callAsync is call() without the wait: it places FreeSWITCH's bridged
// INVITE and returns immediately — the request object, and the channel its
// final response will arrive on (nil if the transaction never finalises).
// Tests that must act while the far end is still ringing use it instead of
// call().
//
// The transaction sends a CLONE: sipgo mutates the request it is sending,
// so the caller's copy is a pristine snapshot that later requests (a
// CANCEL built from it) can read without racing the send.
func (f *fakeSwitch) callAsync(t *testing.T, ruri sip.Uri, dest, body string) (*sip.Request, chan *sip.Response) {
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
	req.SetBody([]byte(body))
	req.SetTransport("UDP")
	req.SetDestination(dest)
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}

	txReq := req.Clone()
	final := make(chan *sip.Response, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := f.cli.TransactionRequest(ctx, txReq)
		if err != nil {
			final <- nil
			return
		}
		defer tx.Terminate()
		for {
			select {
			case res, ok := <-tx.Responses():
				if !ok {
					final <- nil
					return
				}
				if res.StatusCode >= 200 {
					final <- res
					return
				}
			case <-tx.Done():
				final <- nil
				return
			case <-ctx.Done():
				final <- nil
				return
			}
		}
	}()
	return req, final
}

// startHarnessSwitches is startHarness with a MULTI-switch edge.switch
// pool. nodes are the "IP:port" entries, in file order; a node's name in
// the topology, the cooldown table and the logs is that string.
//
// A fake switch is started for every node on a LOOPBACK address. A node on
// any other address (e.g. 10.255.255.1:5060) deliberately gets none: the
// proxy's private socket binds loopback, and a UDP socket bound to
// loopback cannot send to a non-loopback address at all — the send fails
// immediately. That deterministic transport error is exactly what the
// failover tests need; a closed socket would instead swallow the datagram
// silently, and a silent node is indistinguishable from a slow one. The
// dead node's address starts with "10." so it sorts before the loopback
// nodes, which the failover tests rely on.
func startHarnessSwitches(t *testing.T, nodes []string) (*harness, map[string]*fakeSwitch) {
	t.Helper()
	if len(nodes) == 0 {
		t.Fatal("startHarnessSwitches needs at least one node")
	}
	pubUDP := freePort(t)
	pubWS := freeTCPPort(t)
	priv := freePort(t)
	mediaBase := nextMediaBase(t)

	h := newHarness(t, harnessYAML(t, nodes, pubUDP, pubWS, 0, mediaBase, harnessCarrierSources), priv)
	switches := map[string]*fakeSwitch{}
	for _, node := range nodes {
		host, _, err := net.SplitHostPort(node)
		if err != nil {
			t.Fatalf("node %q: %v", node, err)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			continue // deliberately unreachable; see the doc comment
		}
		fs := startFakeSwitch(t, node)
		h.upstreams[node] = fs
		switches[node] = fs
	}
	h.run()
	return h, switches
}

func (h *harness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		h.t.Error("proxy did not shut down")
	}
	// h.fs is nil in a pool harness (startHarnessSwitches): there is no
	// single upstream, and a nil fake must not panic the cleanup path.
	if h.fs != nil {
		h.fs.stop()
	}
	for _, up := range h.upstreams {
		up.stop()
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
	// updateHook, if set, overrides the default UPDATE behaviour (200,
	// answering a body with the switch's own SDP). Guarded by mu.
	updateHook func(req *sip.Request, tx sip.ServerTransaction) bool
	// prackHook, if set, overrides the default PRACK behaviour (200).
	// Guarded by mu.
	prackHook func(req *sip.Request, tx sip.ServerTransaction) bool

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
	srv.OnUpdate(f.onUpdate)
	srv.OnPrack(f.onPrack)
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

func (f *fakeSwitch) setUpdateHook(hook func(req *sip.Request, tx sip.ServerTransaction) bool) {
	f.mu.Lock()
	f.updateHook = hook
	f.mu.Unlock()
}

func (f *fakeSwitch) setPrackHook(hook func(req *sip.Request, tx sip.ServerTransaction) bool) {
	f.mu.Lock()
	f.prackHook = hook
	f.mu.Unlock()
}

func (f *fakeSwitch) onPrack(req *sip.Request, tx sip.ServerTransaction) {
	f.record(req)
	f.mu.Lock()
	hook := f.prackHook
	f.mu.Unlock()
	if hook != nil && hook(req, tx) {
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
}

func (f *fakeSwitch) onUpdate(req *sip.Request, tx sip.ServerTransaction) {
	f.record(req)
	f.mu.Lock()
	hook := f.updateHook
	f.mu.Unlock()
	if hook != nil && hook(req, tx) {
		return
	}
	if len(req.Body()) == 0 {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
		return
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", []byte(f.answerSDP(req)))
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(f.addr)}})
	_ = tx.Respond(res)
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
	granted := "120"
	if d, ok := requestedExpires(req); ok && d == 0 {
		granted = "0"
	}
	if hs := req.GetHeaders("Contact"); len(hs) > 0 {
		c, _ := hs[0].(*sip.ContactHeader)
		f.mu.Lock()
		f.registeredContacts = append(f.registeredContacts, c.Address.String())
		f.mu.Unlock()
		echo := &sip.ContactHeader{Address: c.Address, Params: sip.NewParams()}
		// Grant less than asked for, so the test proves FreeSBC honours
		// the registrar's expiry rather than the client's request. An
		// un-REGISTER is granted 0, as a registrar answers it.
		echo.Params.Add("expires", granted)
		res.AppendHeader(echo)
	}
	res.AppendHeader(sip.NewHeader("Expires", granted))
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
	req := f.callRequest(ruri, dest, body, extra...)

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

// callRequest builds the INVITE call sends, for a test that needs to drive
// the transaction itself (to act while the call is still ringing).
func (f *fakeSwitch) callRequest(ruri sip.Uri, dest, body string, extra ...sip.Header) *sip.Request {
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
	// configured upstream address as the source: the proxy's private plane
	// trusts exactly that address.
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}
	return req
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
