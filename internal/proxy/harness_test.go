package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
)

// This file builds a complete, real deployment on loopback: a FreeSBC edge
// proxy, a fake FreeSWITCH upstream, and clients that speak SIP/UDP or
// SIP/WS. Nothing is mocked below the socket — the tests exercise the same
// sipgo transports, transactions and media sockets a production run uses.

// Ports for these tests are drawn from a fixed, deliberately chosen band
// rather than from the kernel's ephemeral range.
//
// Asking the kernel for a port (bind :0, read it, close) and then binding
// it again is racy in two ways that both bite here: another test can win
// the second bind, and — more often — the kernel hands out the same
// ephemeral port to one of sipgo's own outbound client sockets. Since the
// harness needs a port it will hold for the whole test anyway, taking it
// from a band outside the ephemeral range removes both races entirely.
//
// 24000-44999 is above the privileged range, below macOS's and Linux's
// ephemeral defaults, and disjoint from the media band below.
var portCursor atomic.Int32

func nextPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 200; i++ {
		p := 24000 + int(portCursor.Add(1))
		if p > 44999 {
			t.Fatal("test port band exhausted")
		}
		// Confirm it is actually free before handing it out: another
		// process on the developer's machine may hold it.
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		if err != nil {
			continue
		}
		_ = c.Close()
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		_ = l.Close()
		return p
	}
	t.Fatal("could not find a free port in the test band")
	return 0
}

func freePort(t *testing.T) int    { return nextPort(t) }
func freeTCPPort(t *testing.T) int { return nextPort(t) }

// nextMediaBase hands each harness its own disjoint media port window, so
// no two tests contend for the same RTP ports.
var mediaCursor atomic.Int32

func nextMediaBase() int {
	// 400 ports per harness (200 public + 200 private).
	return 45000 + int(mediaCursor.Add(1)-1)*400
}

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

	// carrier is the PSTN gateway fake when the harness configured
	// sip.pstn (startHarnessPSTN). It is stopped with the rest of the
	// harness.
	carrier *fakeSwitch

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
	mediaBase := nextMediaBase()

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
	case <-srv.Ready():
	case <-h.done:
		t.Fatal("proxy exited before it was ready")
	case <-time.After(10 * time.Second):
		t.Fatal("proxy never became ready")
	}
	t.Cleanup(h.stop)
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

func (h *harness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		h.t.Error("proxy did not shut down")
	}
	h.fs.stop()
	if h.carrier != nil {
		h.carrier.stop()
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
	return f
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

func (f *fakeSwitch) contacts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.registeredContacts...)
}

// onRegister challenges once, then accepts — the exact two-step digest
// exchange a real registrar performs, so the test can prove the challenge
// and the credential both cross FreeSBC untouched.
func (f *fakeSwitch) onRegister(req *sip.Request, tx sip.ServerTransaction) {
	f.record(req)
	f.mu.Lock()
	challenge := f.challenge && req.GetHeader("Authorization") == nil
	f.mu.Unlock()
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
func (f *fakeSwitch) call(t *testing.T, ruri sip.Uri, dest, body string) *sip.Response {
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
	target, ok := contactURI(invite)
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
	u, ok := contactURI(res)
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
