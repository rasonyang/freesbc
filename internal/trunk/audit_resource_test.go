package trunk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
)

// Resource-balance tests for the trunk plane (docs/audit/phase3/trunk.md).
// Each scenario drives several real calls over loopback UDP (raw UAC socket
// → trunk.Server → multi-call stub carrier) and then asserts that every
// resource is back to zero: the media pool, the call store and legs index,
// the carrier's live dialogs, and the goroutine count (runtime.NumGoroutine
// with a bounded retry; goleak is deliberately not used).
//
// Ports: SIP 13700-13799, media 14500-14799. Run in a Linux container (own
// network namespace) to avoid fixed-port collisions.

const auditCalls = 4

func auditTrunkCfg(sipPort, carrierPort, mediaLo, mediaHi int, extra string) string {
	return fmt.Sprintf(`
listen:
  sip: [udp://127.0.0.1:%d]
  media:
    port_range: %d-%d
    public_ip: 127.0.0.1
%s
peers:
  local-uac:
    address: 127.0.0.1:5070
    allowed_ips: [127.0.0.1/32]
  carrier:
    address: 127.0.0.1:%d
    allowed_ips: [203.0.113.0/24]
    media_latch: loose
routes:
  - name: out
    from: local-uac
    to: [carrier]
`, sipPort, mediaLo, mediaHi, extra, carrierPort)
}

type auditServer struct {
	srv    *Server
	store  *config.Store
	cancel context.CancelFunc
	runErr chan error
}

// auditStartServer is startServerAt with the Run cancel and the store handed
// back, so a test can reload the config or stop the server mid-call.
func auditStartServer(t *testing.T, cfgYAML string) *auditServer {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore(cfg)
	srv := NewServer(store, NewMediaPool(store), slog.New(slog.NewTextHandler(io.Discard, nil)))
	bound := make(chan struct{}, 8)
	srv.onListening = func(config.SIPListen) { bound <- struct{}{} }
	ctx, cancel := context.WithCancel(context.Background())
	as := &auditServer{srv: srv, store: store, cancel: cancel, runErr: make(chan error, 1)}
	go func() { as.runErr <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-as.runErr:
		case <-time.After(10 * time.Second):
			t.Errorf("server did not stop within 10s")
		}
	})
	for range cfg.Listeners() {
		select {
		case <-bound:
		case err := <-as.runErr:
			as.runErr <- err
			t.Fatalf("server exited before binding: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("server did not bind within 5s")
		}
	}
	time.Sleep(100 * time.Millisecond)
	return as
}

// auditCarrier is a multi-call stub UAS (startStubCarrier supports exactly
// one call: it closes per-carrier channels once per dialog).
type auditCarrier struct {
	answerDelay time.Duration
	invites     atomic.Int64
	answered    atomic.Int64 // 200 OK actually sent
	live        atomic.Int64 // answered dialogs not yet ended
	byes        atomic.Int64 // BYE requests received

	mu         sync.Mutex
	lastInvite *sip.Request
	calls      map[string]*auditCarrierCall // by B-leg Call-ID
}

// auditCarrierCall is what the carrier saw on one B-leg dialog.
type auditCarrierCall struct {
	answered, acked, byeRecv bool
	endCause                 string
}

func (c *auditCarrier) call(id string) *auditCarrierCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls == nil {
		c.calls = map[string]*auditCarrierCall{}
	}
	cc, ok := c.calls[id]
	if !ok {
		cc = &auditCarrierCall{}
		c.calls[id] = cc
	}
	return cc
}

// report lists every B-leg dialog the carrier answered that did not end
// with a BYE from the SBC.
func (c *auditCarrier) report() (answeredNoBye []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, cc := range c.calls {
		if cc.answered && !cc.byeRecv {
			answeredNoBye = append(answeredNoBye, fmt.Sprintf("%s(acked=%v end=%q)", id, cc.acked, cc.endCause))
		}
	}
	return answeredNoBye
}

func (c *auditCarrier) lastContact() *sip.ContactHeader {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastInvite == nil {
		return nil
	}
	return c.lastInvite.Contact()
}

func auditStartCarrier(t *testing.T, addr string, answerDelay time.Duration) *auditCarrier {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	client, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatal(err)
	}
	c := &auditCarrier{answerDelay: answerDelay}
	cache := sipgo.NewDialogServerCache(client, sip.ContactHeader{Address: sip.Uri{Host: host, Port: port}})
	srv.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		c.invites.Add(1)
		c.call(req.CallID().Value())
		c.mu.Lock()
		c.lastInvite = req
		c.mu.Unlock()
		dlg, err := cache.ReadInvite(req, tx)
		if err != nil {
			return
		}
		if c.answerDelay > 0 {
			select {
			case <-time.After(c.answerDelay):
			case <-dlg.Context().Done():
				return
			}
		}
		if err := dlg.RespondSDP(testSDPBody(14990)); err != nil {
			return
		}
		c.answered.Add(1)
		c.live.Add(1)
		c.mu.Lock()
		c.calls[req.CallID().Value()].answered = true
		c.mu.Unlock()
		<-dlg.Context().Done()
		c.mu.Lock()
		c.calls[req.CallID().Value()].endCause = fmt.Sprint(context.Cause(dlg.Context()))
		c.mu.Unlock()
		c.live.Add(-1)
	})
	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		cc := c.call(req.CallID().Value())
		c.mu.Lock()
		cc.acked = true
		c.mu.Unlock()
		_ = cache.ReadAck(req, tx)
	})
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		c.byes.Add(1)
		cc := c.call(req.CallID().Value())
		c.mu.Lock()
		cc.byeRecv = true
		c.mu.Unlock()
		_ = cache.ReadBye(req, tx)
	})
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("carrier listen: %v", err)
	}
	go func() { _ = srv.TransportLayer().ServeUDP(conn) }()
	t.Cleanup(func() {
		conn.Close()
		client.Close()
		ua.Close()
	})
	time.Sleep(50 * time.Millisecond)
	return c
}

// auditUAC is one raw-UDP caller: it owns one socket and one call, answers
// any BYE the SBC sends it, and records that it did.
type auditUAC struct {
	t       *testing.T
	conn    *net.UDPConn
	sbc     *net.UDPAddr
	callID  string
	fromTag string
	gotBye  atomic.Bool
	ok200   *sip.Response
}

func newAuditUAC(t *testing.T, sbcPort int, callID string) *auditUAC {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &auditUAC{t: t, conn: conn, sbc: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sbcPort},
		callID: callID, fromTag: "ft-" + callID}
}

func (u *auditUAC) local() string { return u.conn.LocalAddr().String() }

func (u *auditUAC) send(s string) {
	if _, err := u.conn.WriteToUDP([]byte(s), u.sbc); err != nil {
		u.t.Errorf("uac %s write: %v", u.callID, err)
	}
}

func (u *auditUAC) headers(method, branch, toTag string, cseq int, ruri string) []string {
	to := "<sip:5551234@127.0.0.1>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	return []string{
		fmt.Sprintf("%s %s SIP/2.0", method, ruri),
		fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK-%s", u.local(), branch),
		"From: <sip:tester@127.0.0.1>;tag=" + u.fromTag,
		"To: " + to,
		"Call-ID: " + u.callID,
		fmt.Sprintf("CSeq: %d %s", cseq, method),
		"Contact: <sip:tester@" + u.local() + ">",
		"Max-Forwards: 70",
	}
}

func (u *auditUAC) ruri() string { return fmt.Sprintf("sip:5551234@127.0.0.1:%d", u.sbc.Port) }

func (u *auditUAC) invite() {
	body := string(testSDPBody(14992))
	h := u.headers("INVITE", u.callID+"-inv", "", 1, u.ruri())
	h = append(h, "Content-Type: application/sdp", fmt.Sprintf("Content-Length: %d", len(body)), "", body)
	u.send(strings.Join(h, "\r\n"))
}

func (u *auditUAC) cancelInvite() {
	h := u.headers("CANCEL", u.callID+"-inv", "", 1, u.ruri())
	h = append(h, "Content-Length: 0", "", "")
	u.send(strings.Join(h, "\r\n"))
}

// ack acknowledges a final INVITE response: same branch for non-2xx (part
// of the INVITE transaction, RFC 3261 §17.1.1.3), a new one for 2xx
// (§13.2.2.4).
func (u *auditUAC) ack(res *sip.Response) {
	branch := u.callID + "-inv"
	if res.StatusCode/100 == 2 {
		branch = u.callID + "-ack"
	}
	h := u.headers("ACK", branch, res.To().Params.GetOr("tag", ""), 1, u.ruri())
	h = append(h, "Content-Length: 0", "", "")
	u.send(strings.Join(h, "\r\n"))
}

func (u *auditUAC) bye() {
	h := u.headers("BYE", u.callID+"-bye", u.ok200.To().Params.GetOr("tag", ""), 2, u.ruri())
	h = append(h, "Content-Length: 0", "", "")
	u.send(strings.Join(h, "\r\n"))
}

// read returns the next parsed message, answering any BYE with 200 OK on
// the way (and recording it). Returns nil on timeout.
func (u *auditUAC) read(timeout time.Duration) sip.Message {
	buf := make([]byte, 8192)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = u.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		msg, err := sip.ParseMessage(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue
		}
		if req, ok := msg.(*sip.Request); ok && req.Method == sip.BYE {
			u.gotBye.Store(true)
			u.send(sip.NewResponseFromRequest(req, 200, "OK", nil).String())
			continue
		}
		return msg
	}
	return nil
}

// waitFinal waits for the final response to CSeq method; returns nil on
// timeout.
func (u *auditUAC) waitFinal(method sip.RequestMethod, timeout time.Duration) *sip.Response {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msg := u.read(time.Until(deadline))
		res, ok := msg.(*sip.Response)
		if !ok {
			continue
		}
		if res.CSeq().MethodName == method && res.StatusCode >= 200 {
			return res
		}
	}
	return nil
}

// drainFor keeps answering BYEs for d.
func (u *auditUAC) drainFor(d time.Duration) { _ = u.read(d) }

// establish runs INVITE → 200 → ACK and fails the test otherwise.
func (u *auditUAC) establish() {
	u.t.Helper()
	u.invite()
	res := u.waitFinal(sip.INVITE, 10*time.Second)
	if res == nil || res.StatusCode != 200 {
		u.t.Fatalf("call %s: final response %v, want 200", u.callID, res)
	}
	u.ok200 = res
	u.ack(res)
}

// hangup sends BYE and waits for its 200.
func (u *auditUAC) hangup() {
	u.t.Helper()
	u.bye()
	res := u.waitFinal(sip.BYE, 6*time.Second)
	if res == nil || res.StatusCode != 200 {
		u.t.Errorf("call %s: BYE final response %v, want 200", u.callID, res)
	}
}

// auditGoroutinesSettle waits (bounded) for the goroutine count to drop to
// at most baseline, and returns the last observed count plus a stack dump
// summary when it does not.
func auditGoroutinesSettle(baseline int, within time.Duration) (int, string) {
	deadline := time.Now().Add(within)
	n := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		n = runtime.NumGoroutine()
		if n <= baseline {
			return n, ""
		}
		time.Sleep(250 * time.Millisecond)
	}
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	return n, auditSummarizeStacks(string(buf))
}

// auditSummarizeStacks counts goroutines by their top-most function in
// this module or sipgo, so a failure names what leaked.
func auditSummarizeStacks(dump string) string {
	counts := map[string]int{}
	for _, g := range strings.Split(dump, "\n\n") {
		lines := strings.Split(g, "\n")
		key := ""
		for _, l := range lines[1:] {
			if strings.Contains(l, "freesbc/internal/") || strings.Contains(l, "emiago/sipgo") {
				if !strings.HasPrefix(l, "\t") {
					key = strings.TrimSpace(l)
					break
				}
			}
		}
		if key == "" && len(lines) > 1 {
			key = strings.TrimSpace(lines[1])
		}
		counts[key]++
	}
	var b strings.Builder
	for k, v := range counts {
		fmt.Fprintf(&b, "  %3d  %s\n", v, k)
	}
	return b.String()
}

type auditBalance struct {
	srv       *Server
	carrier   *auditCarrier
	baseline  int
	wantByes  int64
	uacs      []*auditUAC
	uacByes   bool // every UAC must have received a BYE from the SBC
	settleFor time.Duration
}

// assert checks every resource counter and reports all violations.
func (b auditBalance) assert(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		inUse, _ := b.srv.pool.Stats()
		if b.srv.ActiveCalls() == 0 && inUse == 0 && b.carrier.live.Load() == 0 &&
			b.carrier.byes.Load() >= b.wantByes {
			break
		}
		for _, u := range b.uacs {
			u.drainFor(20 * time.Millisecond)
		}
	}
	for _, u := range b.uacs {
		u.drainFor(20 * time.Millisecond)
	}
	if n := b.srv.ActiveCalls(); n != 0 {
		t.Errorf("ActiveCalls = %d, want 0", n)
	}
	b.srv.callMu.Lock()
	nCalls, nLegs := len(b.srv.calls), len(b.srv.legs)
	b.srv.callMu.Unlock()
	if nCalls != 0 || nLegs != 0 {
		t.Errorf("call store not empty: calls=%d legs=%d", nCalls, nLegs)
	}
	if inUse, total := b.srv.pool.Stats(); inUse != 0 {
		t.Errorf("media pool in use = %d of %d pairs, want 0", inUse, total)
	}
	if n := b.carrier.live.Load(); n != 0 {
		t.Errorf("carrier still has %d live (answered, never ended) dialogs", n)
	}
	if got := b.carrier.byes.Load(); got < b.wantByes {
		t.Errorf("carrier received %d BYEs, want %d", got, b.wantByes)
	}
	if b.uacByes {
		missing := 0
		for _, u := range b.uacs {
			if !u.gotBye.Load() {
				missing++
			}
		}
		if missing > 0 {
			t.Errorf("%d of %d callers never received a BYE from the SBC", missing, len(b.uacs))
		}
	}
	within := b.settleFor
	if within == 0 {
		within = 40 * time.Second
	}
	if n, stacks := auditGoroutinesSettle(b.baseline, within); stacks != "" {
		t.Errorf("goroutines = %d after %v, baseline %d; by top frame:\n%s", n, within, b.baseline, stacks)
	}
}

// auditWarmBaseline places and ends one call so lazily created, process-
// lifetime sipgo state (the client's outbound UDP connection and its read
// goroutine) exists before the baseline is taken, then returns the lowest
// goroutine count seen over 3s.
func auditWarmBaseline(t *testing.T, sipPort int, prefix string) int {
	t.Helper()
	u := newAuditUAC(t, sipPort, prefix+"-warmup")
	u.establish()
	u.hangup()
	low := runtime.NumGoroutine()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if n := runtime.NumGoroutine(); n < low {
			low = n
		}
	}
	return low
}

func auditEstablishN(t *testing.T, sipPort int, prefix string, n int) []*auditUAC {
	t.Helper()
	var uacs []*auditUAC
	for i := 0; i < n; i++ {
		u := newAuditUAC(t, sipPort, fmt.Sprintf("%s-%d", prefix, i))
		u.establish()
		uacs = append(uacs, u)
	}
	return uacs
}

// audit: P2-TRK-017 (control for the resource-balance suite)
// (a) normal BYE from the caller.
func TestAuditResourceBalanceNormalBye(t *testing.T) {
	carrier := auditStartCarrier(t, "127.0.0.1:13701", 0)
	as := auditStartServer(t, auditTrunkCfg(13700, 13701, 14500, 14539, ""))
	baseline := auditWarmBaseline(t, 13700, "rb-bye")

	uacs := auditEstablishN(t, 13700, "rb-bye", auditCalls)
	waitForActiveCalls(t, as.srv, auditCalls, 3*time.Second)
	for _, u := range uacs {
		u.hangup()
	}
	auditBalance{srv: as.srv, carrier: carrier, baseline: baseline, wantByes: auditCalls + 1, uacs: uacs}.assert(t)
}

// audit: P2-TRK-017, RFC 3261 §9.1 / §13.2.2.4
// (b) CANCEL racing the carrier's 200. Whoever wins, every dialog the
// carrier answered must end (ACK+BYE), and nothing may stay allocated.
func TestAuditResourceBalanceCancelRace(t *testing.T) {
	const answerDelay = 300 * time.Millisecond
	carrier := auditStartCarrier(t, "127.0.0.1:13711", answerDelay)
	as := auditStartServer(t, auditTrunkCfg(13710, 13711, 14540, 14579, ""))
	baseline := auditWarmBaseline(t, 13710, "rb-cancel")

	var uacs []*auditUAC
	outcomes := map[int]int{}
	const races = 20
	for i := 0; i < races; i++ {
		u := newAuditUAC(t, 13710, fmt.Sprintf("rb-cancel-%d", i))
		uacs = append(uacs, u)
		u.invite()
		// Sweep the CANCEL across the carrier's answer instant.
		time.Sleep(answerDelay - 60*time.Millisecond + time.Duration(i)*10*time.Millisecond)
		u.cancelInvite()
		res := u.waitFinal(sip.INVITE, 10*time.Second)
		if res == nil {
			t.Errorf("race %d: no final INVITE response", i)
			continue
		}
		outcomes[res.StatusCode]++
		u.ack(res)
		if res.StatusCode == 200 {
			u.ok200 = res
			u.hangup()
		}
	}
	t.Logf("final INVITE responses across %d races: %v; carrier invites=%d answered=%d byes=%d",
		races, outcomes, carrier.invites.Load(), carrier.answered.Load(), carrier.byes.Load())
	auditBalance{srv: as.srv, carrier: carrier, baseline: baseline, uacs: uacs}.assert(t)
	carrier.mu.Lock()
	for id, cc := range carrier.calls {
		t.Logf("carrier dialog %s: answered=%v acked=%v bye=%v end=%q", id, cc.answered, cc.acked, cc.byeRecv, cc.endCause)
	}
	carrier.mu.Unlock()
	if missing := carrier.report(); len(missing) > 0 {
		t.Errorf("carrier answered %d dialog(s) that never received a BYE from the SBC: %v", len(missing), missing)
	}
}

// audit: P2-TRK-017, P2-MED-004
// (c) media silence: rtp_timeout expires on every bridged call; the SBC
// must BYE both legs and release everything.
func TestAuditResourceBalanceMediaTimeout(t *testing.T) {
	carrier := auditStartCarrier(t, "127.0.0.1:13721", 0)
	as := auditStartServer(t, auditTrunkCfg(13720, 13721, 14580, 14619, "    rtp_timeout: 1s"))
	baseline := auditWarmBaseline(t, 13720, "rb-timeout")
	carrier.byes.Store(0)

	uacs := auditEstablishN(t, 13720, "rb-timeout", auditCalls)
	// No RTP is ever sent; each session's watchdog fires after ~1s.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && carrier.byes.Load() < auditCalls {
		for _, u := range uacs {
			u.drainFor(50 * time.Millisecond)
		}
	}
	auditBalance{srv: as.srv, carrier: carrier, baseline: baseline, wantByes: auditCalls, uacs: uacs, uacByes: true}.assert(t)
}

// audit: P2-TRK-004, P2-TRK-005, P2-MED-011
// (d) config reload mid-call: the media range moves while calls are live;
// the old calls' ports must still be released, and the pool must account
// correctly under the new range.
func TestAuditResourceBalanceReloadMidCall(t *testing.T) {
	carrier := auditStartCarrier(t, "127.0.0.1:13731", 0)
	as := auditStartServer(t, auditTrunkCfg(13730, 13731, 14620, 14659, ""))
	baseline := auditWarmBaseline(t, 13730, "rb-reload")

	uacs := auditEstablishN(t, 13730, "rb-reload", auditCalls)
	next, err := config.Parse([]byte(auditTrunkCfg(13730, 13731, 14660, 14663, "    rtp_timeout: 2m")))
	if err != nil {
		t.Fatal(err)
	}
	as.store.Replace(next)
	if inUse, total := as.srv.pool.Stats(); inUse > total {
		t.Errorf("after reload shrinking the range: pool reports inUse=%d > total=%d", inUse, total)
	}
	for _, u := range uacs {
		u.hangup()
	}
	auditBalance{srv: as.srv, carrier: carrier, baseline: baseline, wantByes: auditCalls + 1, uacs: uacs}.assert(t)
	// The new range (one call) must be fully usable after the old calls end.
	u := newAuditUAC(t, 13730, "rb-reload-after")
	u.establish()
	u.hangup()
}

// audit: P2-TRK-017, P2-APP-001
// (e) shutdown with live dialogs: cancelling Run must end every bridged
// call (BYE to both legs), release all media ports, and leave no call
// goroutine behind.
func TestAuditResourceBalanceShutdownWithLiveCalls(t *testing.T) {
	carrier := auditStartCarrier(t, "127.0.0.1:13741", 0)
	baseline := runtime.NumGoroutine()
	as := auditStartServer(t, auditTrunkCfg(13740, 13741, 14700, 14739, ""))

	uacs := auditEstablishN(t, 13740, "rb-shutdown", auditCalls)
	waitForActiveCalls(t, as.srv, auditCalls, 3*time.Second)

	as.cancel()
	select {
	case err := <-as.runErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("Run returned %v", err)
		}
		as.runErr <- err // for the cleanup
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return within 15s of cancel")
	}
	// The suite's default 40s settle, not a shorter one: the BYEs this test
	// requires the carrier to receive leave the in-process fake carrier's
	// own sipgo BYE server transactions parked in TerminateGracefully for
	// RFC 3261 Timer J (64*T1 = 32s on UDP), and those goroutines are
	// counted against the baseline like the SBC's.
	auditBalance{srv: as.srv, carrier: carrier, baseline: baseline, wantByes: auditCalls,
		uacs: uacs, uacByes: true}.assert(t)
}

// audit: P2-TRK-004
// The listener set is restart-only (docs/design.md:337-345). After a hot
// reload that edits listen.sip, the SBC is still bound to the old port, so
// the Contact it advertises on new calls must still name the bound port.
func TestAuditReloadListenPortNotAdvertised(t *testing.T) {
	carrier := auditStartCarrier(t, "127.0.0.1:13751", 0)
	as := auditStartServer(t, auditTrunkCfg(13750, 13751, 14740, 14779, ""))

	u := newAuditUAC(t, 13750, "reload-listen-before")
	u.establish()
	before := carrier.lastContact()
	u.hangup()
	if before == nil || before.Address.Port != 13750 {
		t.Fatalf("control: B-leg Contact before reload = %v, want port 13750", before)
	}

	next, err := config.Parse([]byte(auditTrunkCfg(13799, 13751, 14740, 14779, "")))
	if err != nil {
		t.Fatal(err)
	}
	as.store.Replace(next)

	u2 := newAuditUAC(t, 13750, "reload-listen-after") // the socket still bound
	u2.establish()
	after := carrier.lastContact()
	u2.hangup()
	if after == nil || after.Address.Port != 13750 {
		t.Errorf("after reloading listen.sip to :13799 (not bound; restart-only), the B-leg INVITE advertises Contact %v; "+
			"the carrier's in-dialog requests would go to an unbound port", after)
	}
}
