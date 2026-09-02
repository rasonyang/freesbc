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

	"github.com/freesbc/freesbc/config"
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

	cancel context.CancelFunc
	done   chan struct{}
}

// startHarness brings up the proxy and a fake FreeSWITCH.
func startHarness(t *testing.T, webrtc bool) *harness {
	t.Helper()
	pubUDP := freePort(t)
	pubWS := freeTCPPort(t)
	priv := freePort(t)
	up := freePort(t)
	// Media ranges are per-harness so no two tests contend for a port.
	mediaBase := nextMediaBase()

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
  upstream:
    address: 127.0.0.1:%d
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
`, pubUDP, pubWS, priv, up, mediaBase, mediaBase+199, mediaBase+200, mediaBase+399, webrtc)

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
		upstream:   fmt.Sprintf("127.0.0.1:%d", up),
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

func (h *harness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		h.t.Error("proxy did not shut down")
	}
	h.fs.stop()
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
	// configured upstream address as the source.
	req.Laddr = sip.Addr{IP: net.ParseIP("127.0.0.1"), Port: portOf(f.addr)}

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
