package edge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
)

// End-to-end signaling benchmarks (issue #173). One full client call per
// iteration runs through a real edge over UDP loopback:
//
//	client INVITE(SDP) -> edge -> switch; switch 180, 200(SDP) -> edge ->
//	client; client ACK -> edge -> switch; client BYE -> edge -> switch;
//	switch 200 -> edge -> client
//
// The client and the switch are raw UDP sockets that write pre-rendered
// byte templates and pick the few headers they echo out of what they read
// with byte scans into reused buffers, so they allocate (almost) nothing:
// the allocations reported are the edge's and sipgo's, plus the Go
// runtime's. Every peer socket is connected (DialUDP), so Read and Write
// allocate no address either.
//
// Each client registers once in setup and the edge has no
// carrier_sources, so every INVITE is admitted as a registered client's
// (the client-to-switch path), not as a carrier's.
//
// Ports come from the edge SIP band (25000-27999) and the edge media band
// (28000-32399). Run:
//
//	go test ./internal/edge -run '^$' -bench 'BenchmarkEdgeCall' -benchmem

// benchEdge is a running edge and its raw switch socket.
type benchEdge struct {
	srv    *Server
	cancel context.CancelFunc
	done   chan struct{}

	pubUDP, priv, swPort int
	sw                   *net.UDPConn // the switch, connected to the private socket

	// workers, when the switch is shared (parallel benchmark): the
	// dispatcher routes each switch read to its worker by Call-ID.
	workers []*callWorker
}

// callWorker is one client with its own socket and registration, and its
// view of the switch.
type callWorker struct {
	e      *benchEdge
	id     int
	client *rawPeer // connected to the edge's public UDP
	sw     *rawPeer // shares e.sw; reads come from its inbox when dispatched
	cport  int

	// Per-iteration scratch, reused so the peers allocate nothing.
	callID  []byte // Call-ID of the current call
	route   []byte // the client's Route header value (from Record-Route)
	target  []byte // the client's in-dialog Request-URI (the 200's Contact)
	toLine  []byte // the To value of the 200 (carries the switch's tag)
	invite  []byte // the INVITE the switch last read (kept for its responses)
	bye     []byte // the BYE the switch last read
	sdpBody []byte
}

type rawPeer struct {
	conn *net.UDPConn
	rbuf []byte // read buffer
	wbuf []byte // message being written

	// inbox and free, when set, replace reads from conn: a dispatcher
	// fills a free buffer and hands it over on inbox.
	inbox, free chan []byte
	held        []byte // the inbox buffer being looked at, returned on the next await
	timer       *time.Timer
}

func dialRawUDP(tb testing.TB, local, remote int) *net.UDPConn {
	tb.Helper()
	c, err := net.DialUDP("udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: local},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remote})
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

func newRawPeer(conn *net.UDPConn) *rawPeer {
	return &rawPeer{conn: conn, rbuf: make([]byte, 65536), wbuf: make([]byte, 0, 8192)}
}

func (p *rawPeer) send(tb testing.TB) {
	if _, err := p.conn.Write(p.wbuf); err != nil {
		tb.Fatalf("raw peer write: %v", err)
	}
}

func (p *rawPeer) next(tb testing.TB, deadline time.Time) ([]byte, error) {
	if p.inbox == nil {
		_ = p.conn.SetReadDeadline(deadline)
		n, err := p.conn.Read(p.rbuf)
		return p.rbuf[:n], err
	}
	if p.held != nil {
		p.free <- p.held
		p.held = nil
	}
	// One timer per peer, reset per read (Go 1.23+ timers need no drain).
	if p.timer == nil {
		p.timer = time.NewTimer(time.Until(deadline))
	} else {
		p.timer.Reset(time.Until(deadline))
	}
	select {
	case m := <-p.inbox:
		p.held = m
		return m, nil
	case <-p.timer.C:
		return nil, fmt.Errorf("timeout")
	}
}

// await reads until a message for callID whose start line begins with
// start and whose CSeq equals cseq arrives (anything else, e.g. a 100
// Trying or a stale retransmission, is skipped). It fails the benchmark
// after 5 s. The returned slice is valid until the next await.
func (p *rawPeer) await(tb testing.TB, callID, start, cseq []byte) []byte {
	deadline := time.Now().Add(5 * time.Second)
	for {
		msg, err := p.next(tb, deadline)
		if err != nil {
			tb.Fatalf("raw peer waiting for %q %q %q: %v", start, cseq, callID, err)
		}
		if bytes.HasPrefix(msg, start) && bytes.Equal(rawHeader(msg, hdrCSeq), cseq) &&
			bytes.Equal(rawHeader(msg, hdrCallID), callID) {
			return msg
		}
	}
}

var (
	hdrVia         = []byte("Via: ")
	hdrFrom        = []byte("From: ")
	hdrTo          = []byte("To: ")
	hdrCallID      = []byte("Call-ID: ")
	hdrCSeq        = []byte("CSeq: ")
	hdrRecordRoute = []byte("Record-Route: ")
	hdrContact     = []byte("Contact: ")
	crlf           = []byte("\r\n")
	tagParam       = []byte(";tag=")

	startInvite   = []byte("INVITE ")
	startAck      = []byte("ACK ")
	startBye      = []byte("BYE ")
	startRegister = []byte("REGISTER ")
	start180      = []byte("SIP/2.0 180")
	start200      = []byte("SIP/2.0 200")
	cseqInvite    = []byte("1 INVITE")
	cseqAck       = []byte("1 ACK")
	cseqBye       = []byte("2 BYE")
	cseqRegister  = []byte("1 REGISTER")
)

// rawNextHeader returns the first header line of head (no CRLF) and the
// rest. head starts after the start line and ends before the blank line.
func rawNextHeader(head []byte) (line, rest []byte) {
	if i := bytes.Index(head, crlf); i >= 0 {
		return head[:i], head[i+2:]
	}
	return head, nil
}

// rawHead is msg's header block: after the start line, before CRLFCRLF.
func rawHead(msg []byte) []byte {
	head := msg
	if i := bytes.Index(head, crlfcrlf); i >= 0 {
		head = head[:i]
	}
	if i := bytes.Index(head, crlf); i >= 0 {
		return head[i+2:]
	}
	return nil
}

// rawHeader is the value of the first name header in msg, or nil.
func rawHeader(msg, name []byte) []byte {
	for head := rawHead(msg); len(head) > 0; {
		var line []byte
		line, head = rawNextHeader(head)
		if bytes.HasPrefix(line, name) {
			return line[len(name):]
		}
	}
	return nil
}

// rawAppendEcho appends every Via, From, To, Call-ID and CSeq line of req
// (in order, with CRLF), adding toTag to the To line when it has none, and
// the Record-Route lines too when rr.
func rawAppendEcho(dst, req []byte, toTag string, rr bool) []byte {
	for head := rawHead(req); len(head) > 0; {
		var line []byte
		line, head = rawNextHeader(head)
		switch {
		case bytes.HasPrefix(line, hdrVia), bytes.HasPrefix(line, hdrFrom),
			bytes.HasPrefix(line, hdrCallID), bytes.HasPrefix(line, hdrCSeq),
			rr && bytes.HasPrefix(line, hdrRecordRoute):
			dst = append(dst, line...)
			dst = append(dst, crlf...)
		case bytes.HasPrefix(line, hdrTo):
			dst = append(dst, line...)
			if toTag != "" && !bytes.Contains(line, tagParam) {
				dst = append(dst, tagParam...)
				dst = append(dst, toTag...)
			}
			dst = append(dst, crlf...)
		}
	}
	return dst
}

// startBenchEdge runs an edge with one switch node, served by a raw
// socket. With workers > 0 the switch socket is shared by that many
// clients through a dispatcher; with 0 the single worker reads it itself.
func startBenchEdge(b *testing.B, workers int) *benchEdge {
	b.Helper()
	e := &benchEdge{done: make(chan struct{})}
	// hepmirror_test.go's init installs the HEP tracer for this whole test
	// binary, and that turns on sip.SIPDebug: sipgo then formats both
	// addresses of every UDP read and write for the tracer. Production
	// without a hep: section never sets it, so the benchmark turns it off
	// (benchmarks run after every test, so no test is reading it) unless
	// FREESBC_BENCH_SIPDEBUG=1 asks to measure the tracer's cost.
	if os.Getenv("FREESBC_BENCH_SIPDEBUG") != "1" {
		prev := sip.SIPDebug
		sip.SIPDebug = false
		b.Cleanup(func() { sip.SIPDebug = prev })
	}
	e.pubUDP = sipPorts.take(b, 1, sipFree)
	e.priv = sipPorts.take(b, 1, sipFree)
	e.swPort = sipPorts.take(b, 1, sipFree)
	mediaBase := mediaPorts.take(b, mediaWindow, udpFree)

	// The clients send three requests per call, all from 127.0.0.1, so at
	// the harness's 5000/s per-source limit a fast run would have
	// datagrams rate-dropped (and never retransmitted by a raw peer).
	yaml := strings.Replace(harnessYAML(b, []string{fmt.Sprintf("127.0.0.1:%d", e.swPort)}, e.pubUDP, 0, 0, mediaBase, ""),
		`  rate_limit: "5000/s per_ip"`, `  rate_limit: "1000000/s per_ip"`, 1)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		b.Fatal(err)
	}
	// Production's handler and level (cmd/freesbc: a TextHandler at Info),
	// written to nowhere: Info lines are still formatted, as they are in
	// production.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(config.NewStore(cfg), log, WithPrivateAddr(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", e.priv))))
	if err != nil {
		b.Fatal(err)
	}
	e.srv = srv
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	go func() {
		defer close(e.done)
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			b.Errorf("edge Run: %v", err)
		}
	}()
	select {
	case <-srv.ready:
	case <-e.done:
		b.Fatal("edge exited before it was ready")
	case <-time.After(10 * time.Second):
		b.Fatal("edge never became ready")
	}
	e.sw = dialRawUDP(b, e.swPort, e.priv)
	b.Cleanup(e.stop)

	if workers == 0 {
		w := e.newWorker(b, 0)
		w.sw = newRawPeer(e.sw)
		w.register(b)
		e.workers = []*callWorker{w}
		return e
	}
	for i := 0; i < workers; i++ {
		w := e.newWorker(b, i)
		w.sw = newRawPeer(e.sw)
		w.sw.inbox = make(chan []byte, 8)
		w.sw.free = make(chan []byte, 8)
		for j := 0; j < 8; j++ {
			w.sw.free <- make([]byte, 0, 65536)
		}
		e.workers = append(e.workers, w)
	}
	go e.dispatch()
	for _, w := range e.workers {
		w.register(b)
	}
	return e
}

func (e *benchEdge) newWorker(b *testing.B, id int) *callWorker {
	w := &callWorker{e: e, id: id, cport: sipPorts.take(b, 1, sipFree)}
	w.client = newRawPeer(dialRawUDP(b, w.cport, e.pubUDP))
	return w
}

// dispatch routes every switch read to the worker its Call-ID names
// ("bench-call-<worker>-<n>" or "bench-register-<worker>").
func (e *benchEdge) dispatch() {
	buf := make([]byte, 65536)
	for {
		n, err := e.sw.Read(buf)
		if err != nil {
			return // closed
		}
		msg := buf[:n]
		id := rawHeader(msg, hdrCallID)
		if i := bytes.LastIndexByte(id, '-'); i >= 0 {
			if j := bytes.LastIndexByte(id[:i], '-'); bytes.HasPrefix(id, []byte("bench-call-")) && j >= 0 {
				id = id[j+1 : i]
			} else {
				id = id[i+1:]
			}
		}
		k := 0
		for _, c := range id {
			if c < '0' || c > '9' {
				k = -1
				break
			}
			k = k*10 + int(c-'0')
		}
		if len(id) == 0 || k < 0 || k >= len(e.workers) {
			continue
		}
		p := e.workers[k].sw
		m := <-p.free
		p.inbox <- append(m[:0], msg...)
	}
}

func (e *benchEdge) stop() {
	e.cancel()
	select {
	case <-e.done:
	case <-time.After(10 * time.Second):
	}
	_ = e.sw.Close()
	for _, w := range e.workers {
		_ = w.client.conn.Close()
	}
}

// register makes the client a live registration at its source address, so
// its INVITEs pass admission as a client's.
func (w *callWorker) register(b *testing.B) {
	c, s := w.client, w.sw
	w.callID = fmt.Appendf(w.callID[:0], "bench-register-%d", w.id)
	c.wbuf = fmt.Appendf(c.wbuf[:0], "REGISTER sip:example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bKbenchreg%d;rport\r\n"+
		"Max-Forwards: 70\r\n"+
		"From: <sip:%d@example.com>;tag=benchreg\r\n"+
		"To: <sip:%d@example.com>\r\n"+
		"Call-ID: %s\r\n"+
		"CSeq: 1 REGISTER\r\n"+
		"Contact: <sip:%d@127.0.0.1:%d>\r\n"+
		"Expires: 3600\r\n"+
		"Content-Length: 0\r\n\r\n", w.cport, w.id, 1001+w.id, 1001+w.id, w.callID, 1001+w.id, w.cport)
	c.send(b)
	req := s.await(b, w.callID, startRegister, cseqRegister)
	s.wbuf = append(s.wbuf[:0], "SIP/2.0 200 OK\r\n"...)
	s.wbuf = rawAppendEcho(s.wbuf, req, "swreg", false)
	if v := rawHeader(req, hdrContact); v != nil {
		s.wbuf = append(s.wbuf, hdrContact...)
		s.wbuf = append(s.wbuf, v...)
		s.wbuf = append(s.wbuf, crlf...)
	}
	s.wbuf = append(s.wbuf, "Expires: 3600\r\nContent-Length: 0\r\n\r\n"...)
	s.send(b)
	c.await(b, w.callID, start200, cseqRegister)
	if _, ok := w.e.srv.loc.SourceBinding("udp", netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", w.cport)), strconv.Itoa(1001+w.id)); !ok {
		b.Fatalf("worker %d: registration not recorded", w.id)
	}
}

// The phases of one call. Each step is a write by one peer and the read
// that proves the edge relayed it.

func (w *callWorker) appendTag(dst []byte, i int) []byte {
	dst = strconv.AppendInt(dst, int64(w.id), 10)
	dst = append(dst, '-')
	return strconv.AppendInt(dst, int64(i), 10)
}

func (w *callWorker) stepInvite(b *testing.B, i int) {
	c, s := w.client, w.sw
	w.callID = w.appendTag(append(w.callID[:0], "bench-call-"...), i)
	w.sdpBody = append(w.sdpBody[:0], "v=0\r\no=phone 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
		"m=audio 40000 RTP/AVP 0 8 101\r\n"+
		"a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"+
		"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=sendrecv\r\n"...)
	u := c.wbuf[:0]
	u = append(u, "INVITE sip:2002@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:"...)
	u = strconv.AppendInt(u, int64(w.cport), 10)
	u = w.appendTag(append(u, ";branch=z9hG4bKbi"...), i)
	u = append(u, ";rport\r\nMax-Forwards: 70\r\nFrom: <sip:"...)
	u = strconv.AppendInt(u, int64(1001+w.id), 10)
	u = w.appendTag(append(u, "@example.com>;tag=ft"...), i)
	u = append(u, "\r\nTo: <sip:2002@example.com>\r\nCall-ID: "...)
	u = append(u, w.callID...)
	u = append(u, "\r\nCSeq: 1 INVITE\r\nContact: <sip:"...)
	u = strconv.AppendInt(u, int64(1001+w.id), 10)
	u = append(u, "@127.0.0.1:"...)
	u = strconv.AppendInt(u, int64(w.cport), 10)
	u = append(u, ">\r\nContent-Type: application/sdp\r\nContent-Length: "...)
	u = strconv.AppendInt(u, int64(len(w.sdpBody)), 10)
	u = append(u, "\r\n\r\n"...)
	u = append(u, w.sdpBody...)
	c.wbuf = u
	c.send(b)
	w.invite = append(w.invite[:0], s.await(b, w.callID, startInvite, cseqInvite)...)
}

func (w *callWorker) step180(b *testing.B) {
	c, s := w.client, w.sw
	u := append(s.wbuf[:0], "SIP/2.0 180 Ringing\r\n"...)
	u = rawAppendEcho(u, w.invite, "sw1", true)
	u = append(u, "Contact: <sip:2002@127.0.0.1:"...)
	u = strconv.AppendInt(u, int64(w.e.swPort), 10)
	u = append(u, ">\r\nContent-Length: 0\r\n\r\n"...)
	s.wbuf = u
	s.send(b)
	c.await(b, w.callID, start180, cseqInvite)
}

func (w *callWorker) step200(b *testing.B) {
	c, s := w.client, w.sw
	w.sdpBody = append(w.sdpBody[:0], "v=0\r\no=fs 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
		"m=audio 40002 RTP/AVP 0 101\r\n"+
		"a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=sendrecv\r\n"...)
	u := append(s.wbuf[:0], "SIP/2.0 200 OK\r\n"...)
	u = rawAppendEcho(u, w.invite, "sw1", true)
	u = append(u, "Contact: <sip:2002@127.0.0.1:"...)
	u = strconv.AppendInt(u, int64(w.e.swPort), 10)
	u = append(u, ">\r\nContent-Type: application/sdp\r\nContent-Length: "...)
	u = strconv.AppendInt(u, int64(len(w.sdpBody)), 10)
	u = append(u, "\r\n\r\n"...)
	u = append(u, w.sdpBody...)
	s.wbuf = u
	s.send(b)
	res := c.await(b, w.callID, start200, cseqInvite)

	// The client's dialog state: route set from Record-Route (one public
	// entry), remote target from Contact, remote tag from To.
	w.route = append(w.route[:0], rawHeader(res, hdrRecordRoute)...)
	w.toLine = append(w.toLine[:0], rawHeader(res, hdrTo)...)
	ct := rawHeader(res, hdrContact)
	if l, r := bytes.IndexByte(ct, '<'), bytes.IndexByte(ct, '>'); l >= 0 && r > l {
		ct = ct[l+1 : r]
	}
	w.target = append(w.target[:0], ct...)
	if len(w.route) == 0 || len(w.target) == 0 {
		b.Fatalf("200 has no Record-Route or Contact:\n%s", res)
	}
}

// appendInDialog renders a client in-dialog request (ACK or BYE).
func (w *callWorker) appendInDialog(u []byte, method string, cseq, i int, branch string) []byte {
	u = append(u, method...)
	u = append(u, ' ')
	u = append(u, w.target...)
	u = append(u, " SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:"...)
	u = strconv.AppendInt(u, int64(w.cport), 10)
	u = append(u, ";branch=z9hG4bK"...)
	u = append(u, branch...)
	u = w.appendTag(u, i)
	u = append(u, ";rport\r\nRoute: "...)
	u = append(u, w.route...)
	u = append(u, "\r\nMax-Forwards: 70\r\nFrom: <sip:"...)
	u = strconv.AppendInt(u, int64(1001+w.id), 10)
	u = w.appendTag(append(u, "@example.com>;tag=ft"...), i)
	u = append(u, "\r\nTo: "...)
	u = append(u, w.toLine...)
	u = append(u, "\r\nCall-ID: "...)
	u = append(u, w.callID...)
	u = append(u, "\r\nCSeq: "...)
	u = strconv.AppendInt(u, int64(cseq), 10)
	u = append(u, ' ')
	u = append(u, method...)
	u = append(u, "\r\nContent-Length: 0\r\n\r\n"...)
	return u
}

func (w *callWorker) stepAck(b *testing.B, i int) {
	c, s := w.client, w.sw
	c.wbuf = w.appendInDialog(c.wbuf[:0], "ACK", 1, i, "ba")
	c.send(b)
	s.await(b, w.callID, startAck, cseqAck)
}

func (w *callWorker) stepBye(b *testing.B, i int) {
	c, s := w.client, w.sw
	c.wbuf = w.appendInDialog(c.wbuf[:0], "BYE", 2, i, "bb")
	c.send(b)
	w.bye = append(w.bye[:0], s.await(b, w.callID, startBye, cseqBye)...)
}

func (w *callWorker) stepBye200(b *testing.B) {
	c, s := w.client, w.sw
	u := append(s.wbuf[:0], "SIP/2.0 200 OK\r\n"...)
	u = rawAppendEcho(u, w.bye, "", false)
	u = append(u, "Content-Length: 0\r\n\r\n"...)
	s.wbuf = u
	s.send(b)
	c.await(b, w.callID, start200, cseqBye)
}

// settle waits until the edge has released every call: no dialog, no
// media port in use. Without it the teardown of call i would be charged to
// the INVITE of call i+1, and the media window could run dry.
func (e *benchEdge) settle(b *testing.B) {
	deadline := time.Now().Add(5 * time.Second)
	for spins := 0; ; spins++ {
		pub, _ := e.srv.pubPool.Stats()
		priv, _ := e.srv.privPool.Stats()
		if e.srv.dialogs.count() == 0 && pub == 0 && priv == 0 {
			return
		}
		if time.Now().After(deadline) {
			b.Fatalf("call not released: dialogs=%d public ports=%d private ports=%d", e.srv.dialogs.count(), pub, priv)
		}
		if spins < 100 {
			runtime.Gosched()
		} else {
			time.Sleep(20 * time.Microsecond)
		}
	}
}

// call runs one call without waiting for the edge's teardown.
func (w *callWorker) call(b *testing.B, i int) {
	w.stepInvite(b, i)
	w.step180(b)
	w.step200(b)
	w.stepAck(b, i)
	w.stepBye(b, i)
	w.stepBye200(b)
}

// benchWarmCalls run before the timer starts: first-call lazy
// initialisation (pools, maps, timers) is not per-call cost.
const benchWarmCalls = 50

// BenchmarkEdgeCall is one full relayed call per op: INVITE, 180, 200,
// ACK, BYE, 200, then the edge's teardown of the dialog and its media.
// B/op and allocs/op are the whole process's, which with the raw peers is
// the edge, sipgo and the runtime. Calls are sequential, so ns/op is
// latency, not capacity.
func BenchmarkEdgeCall(b *testing.B) {
	e := startBenchEdge(b, 0)
	w := e.workers[0]
	for i := 0; i < benchWarmCalls; i++ {
		w.call(b, 1_000_000_000+i)
		e.settle(b)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.call(b, i)
		e.settle(b)
	}
}

// BenchmarkEdgeCallParallel runs calls from 32 clients at once (each with
// its own socket and registration; the switch socket is shared through a
// dispatcher), so the edge works under concurrency and GC pressure closer
// to a loaded production run. One op is one call; ns/op is the inverse of
// throughput (calls per second = 1e9 / ns/op). The dispatcher hands
// buffers over through channels, so the peers' own allocations stay near
// zero here too.
func BenchmarkEdgeCallParallel(b *testing.B) {
	const workers = 32
	e := startBenchEdge(b, workers)
	for _, w := range e.workers {
		for i := 0; i < 3; i++ {
			w.call(b, 1_000_000_000+i)
		}
	}
	e.settle(b)
	b.SetParallelism((workers + runtime.GOMAXPROCS(0) - 1) / runtime.GOMAXPROCS(0))
	var next atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		k := int(next.Add(1) - 1)
		if k >= workers {
			b.Errorf("more parallel goroutines than workers (%d)", workers)
			return
		}
		w := e.workers[k]
		for i := 0; pb.Next(); i++ {
			w.call(b, i)
		}
	})
	b.StopTimer()
	// The runtime's adaptive starting stack size (the average scanned
	// stack, GODEBUG adaptivestackstart): every per-message goroutine sipgo
	// starts begins at this size and grows (copystack) from there.
	sample := []metrics.Sample{{Name: "/gc/stack/starting-size:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() == metrics.KindUint64 {
		b.ReportMetric(float64(sample[0].Value.Uint64()), "start-stack-B")
	}
	e.settle(b)
}

// BenchmarkEdgeCallPhases runs the sequential call and charges the
// process's allocations (runtime.MemStats Mallocs and TotalAlloc deltas)
// to each relayed message: a phase starts when one peer writes and ends
// when the other has read what the edge relayed. Work the edge does after
// it has sent (a log line, bookkeeping after the write) can fall into the
// next phase, so the split is approximate; the sum is the full call.
// ReadMemStats stops the world, so ns/op here is not comparable with
// BenchmarkEdgeCall.
func BenchmarkEdgeCallPhases(b *testing.B) {
	e := startBenchEdge(b, 0)
	w := e.workers[0]
	for i := 0; i < benchWarmCalls; i++ {
		w.call(b, 1_000_000_000+i)
		e.settle(b)
	}
	type phase struct {
		name           string
		run            func(i int)
		mallocs, bytes uint64
	}
	phases := []*phase{
		{name: "INVITE", run: func(i int) { w.stepInvite(b, i) }},
		{name: "180", run: func(int) { w.step180(b) }},
		{name: "200", run: func(int) { w.step200(b) }},
		{name: "ACK", run: func(i int) { w.stepAck(b, i) }},
		{name: "BYE", run: func(i int) { w.stepBye(b, i) }},
		{name: "BYE-200", run: func(int) { w.stepBye200(b) }},
		{name: "teardown", run: func(int) { e.settle(b) }},
	}
	var before, after runtime.MemStats
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range phases {
			runtime.ReadMemStats(&before)
			p.run(i)
			runtime.ReadMemStats(&after)
			p.mallocs += after.Mallocs - before.Mallocs
			p.bytes += after.TotalAlloc - before.TotalAlloc
		}
	}
	b.StopTimer()
	var tm, tb uint64
	for _, p := range phases {
		b.ReportMetric(float64(p.mallocs)/float64(b.N), "allocs/"+p.name)
		b.ReportMetric(float64(p.bytes)/float64(b.N), "B/"+p.name)
		tm += p.mallocs
		tb += p.bytes
	}
	b.ReportMetric(float64(tm)/float64(b.N), "allocs/call")
	b.ReportMetric(float64(tb)/float64(b.N), "B/call")
}
