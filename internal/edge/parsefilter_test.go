package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/shield"
)

// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// canary stands in for a credential in a message that fails to parse: it
// must never appear in a log record.
const canary = "CANARY-SECRET-7f3a"

// recordedLog is one captured slog record, flattened.
type recordedLog struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

// logRecorder is a slog.Handler that keeps every record (Debug and up),
// including attributes added through With.
type logRecorder struct {
	mu   *sync.Mutex
	recs *[]recordedLog
	pre  map[string]string
}

func newLogRecorder() *logRecorder {
	return &logRecorder{mu: new(sync.Mutex), recs: new([]recordedLog), pre: map[string]string{}}
}

func (l *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (l *logRecorder) Handle(_ context.Context, r slog.Record) error {
	rec := recordedLog{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	for k, v := range l.pre {
		rec.attrs[k] = v
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	l.mu.Lock()
	*l.recs = append(*l.recs, rec)
	l.mu.Unlock()
	return nil
}

func (l *logRecorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *l
	c.pre = map[string]string{}
	for k, v := range l.pre {
		c.pre[k] = v
	}
	for _, a := range attrs {
		c.pre[a.Key] = a.Value.String()
	}
	return &c
}

func (l *logRecorder) WithGroup(string) slog.Handler { return l }

func (l *logRecorder) snapshot() []recordedLog {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]recordedLog(nil), *l.recs...)
}

// assertNoPayloadLogged fails when any record carries a "data" attribute or
// the canary anywhere, and returns the number of WARN records that mention a
// parse failure.
func assertNoPayloadLogged(t *testing.T, l *logRecorder) (parseWarns int) {
	t.Helper()
	for _, r := range l.snapshot() {
		if _, ok := r.attrs["data"]; ok {
			t.Errorf("record %q carries a data attribute", r.msg)
		}
		if strings.Contains(r.msg, canary) {
			t.Errorf("record message leaks the payload: %q", r.msg)
		}
		for k, v := range r.attrs {
			if strings.Contains(v, canary) || strings.Contains(k, canary) {
				t.Errorf("record %q leaks the payload in attribute %s", r.msg, k)
			}
		}
		if r.level == slog.LevelWarn && strings.Contains(r.msg, "parse failures") {
			parseWarns++
		}
		if r.level >= slog.LevelError && r.attrs["caller"] == "sipgo" && strings.Contains(r.msg, "parse") {
			t.Errorf("sipgo parse failure still logged at ERROR: %q", r.msg)
		}
	}
	return parseWarns
}

// startShieldHarness is a strict single-switch harness whose shield limits
// and log handler are chosen by the test.
func startShieldHarness(t *testing.T, rate, carrierRate, carrierSources string, webrtc, wss bool, handler slog.Handler) *harness {
	t.Helper()
	pubUDP := freePort(t)
	pubWS, pubWSS := 0, 0
	if webrtc {
		pubWS = freePort(t)
	}
	if wss {
		pubWSS = freePort(t)
	}
	priv := freePort(t)
	up := freePort(t)
	mediaBase := nextMediaBase(t)
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, pubWS, pubWSS, mediaBase, carrierSources)
	yaml = strings.Replace(yaml, `rate_limit: "5000/s per_ip"
  carrier_rate_limit: "5000/s per_ip"`, fmt.Sprintf("rate_limit: %q\n  carrier_rate_limit: %q", rate, carrierRate), 1)
	h := newHarnessLog(t, yaml, priv, handler)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.run()
	return h
}

func (h *harness) rateDrops() int64 { return h.srv.ShieldStats().DropsByReason["rate"] }

func (h *harness) parseFailures(transport string) uint64 {
	return h.srv.metrics.Snapshot().ParseFailures[transport]
}

func garbage(i int) []byte {
	return []byte(fmt.Sprintf("NOTSIP %d Authorization: Digest username=\"u\", response=\"%s\"\r\n\r\n", i, canary))
}

func rawOptions(local net.Addr, i int) []byte {
	return []byte(fmt.Sprintf("OPTIONS sip:127.0.0.1 SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP %s;branch=z9hG4bKpf%d\r\nMax-Forwards: 70\r\n"+
		"From: <sip:probe@example.com>;tag=pf%d\r\nTo: <sip:127.0.0.1>\r\n"+
		"Call-ID: pf-%d-%d\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
		local, i, i, i, time.Now().UnixNano()))
}

// udpResponses counts datagrams received on c until it has been quiet for
// quiet.
func udpResponses(c net.Conn, quiet time.Duration) int {
	n := 0
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(quiet))
		if _, err := c.Read(buf); err != nil {
			return n
		}
		n++
	}
}

func dialUDP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// A malformed flood from one public source is rate-limited before the
// parser: only the bucket's burst reaches it, the rest are counted as rate
// drops, no record carries the payload and at most one WARN is written.
// Then a parsable request from the same source finds the same bucket empty.
func TestMalformedFloodIsRateLimitedBeforeParse(t *testing.T) {
	rec := newLogRecorder()
	h := startShieldHarness(t, "10/m per_ip", "10/m per_ip", "", false, false, rec)
	c := dialUDP(t, h.publicUDP)
	const sent = 100
	for i := 0; i < sent; i++ {
		if _, err := c.Write(garbage(i)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.parseFailures("UDP")+uint64(h.rateDrops()) < sent && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := h.parseFailures("UDP"); got != 10 {
		t.Errorf("parse failures = %d, want the bucket's burst of 10", got)
	}
	if got := h.rateDrops(); got != sent-10 {
		t.Errorf("rate drops = %d, want %d", got, sent-10)
	}
	if w := assertNoPayloadLogged(t, rec); w != 1 {
		t.Errorf("parse-failure WARN records = %d, want exactly 1", w)
	}

	// The bucket is empty: a well-formed request from the same source is
	// dropped silently.
	if _, err := c.Write(rawOptions(c.LocalAddr(), 1)); err != nil {
		t.Fatal(err)
	}
	if n := udpResponses(c, 400*time.Millisecond); n != 0 {
		t.Errorf("a parsable request after the flood got %d responses, want none", n)
	}
	if got := h.rateDrops(); got != sent-10+1 {
		t.Errorf("rate drops = %d, want %d (the parsable request shares the bucket)", got, sent-10+1)
	}
}

// A parsable request costs exactly one token end to end: a bucket of 10
// answers 10 OPTIONS and drops the 11th. A double charge would stop at 5.
func TestParsableRequestCostsOneToken(t *testing.T) {
	h := startShieldHarness(t, "10/m per_ip", "10/m per_ip", "", false, false, newLogRecorder())
	c := dialUDP(t, h.publicUDP)
	for i := 0; i < 11; i++ {
		if _, err := c.Write(rawOptions(c.LocalAddr(), i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := udpResponses(c, 500*time.Millisecond); n != 10 {
		t.Errorf("responses = %d, want 10 (one token per request)", n)
	}
	if got := h.rateDrops(); got != 1 {
		t.Errorf("rate drops = %d, want 1", got)
	}
}

// A carrier source is limited by carrier_rate_limit, and the private socket
// is exempt from both.
func TestCarrierSourceAndPrivateSocketLimits(t *testing.T) {
	h := startShieldHarness(t, "5/m per_ip", "20/m per_ip", harnessCarrierSources, false, false, newLogRecorder())
	c := dialUDP(t, h.publicUDP)
	for i := 0; i < 30; i++ {
		if _, err := c.Write(rawOptions(c.LocalAddr(), i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := udpResponses(c, 500*time.Millisecond); n != 20 {
		t.Errorf("carrier source got %d responses, want 20 (carrier_rate_limit)", n)
	}
	if got := h.rateDrops(); got != 10 {
		t.Errorf("rate drops = %d, want 10", got)
	}

	// The private socket: the same IP (an upstream), 60 requests, no limit.
	p := dialUDP(t, h.privateSIP)
	for i := 0; i < 60; i++ {
		if _, err := p.Write(rawOptions(p.LocalAddr(), 100+i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := udpResponses(p, 500*time.Millisecond); n != 60 {
		t.Errorf("private socket answered %d of 60, want all", n)
	}
	if got := h.rateDrops(); got != 10 {
		t.Errorf("rate drops = %d after private traffic, want still 10", got)
	}
}

// rawWSFrame returns a masked client text frame (RFC 6455 §5.2) for a
// payload under 126 bytes.
func rawWSFrame(payload []byte) []byte {
	mask := []byte{1, 2, 3, 4}
	f := []byte{0x81, 0x80 | byte(len(payload))}
	f = append(f, mask...)
	for i, b := range payload {
		f = append(f, b^mask[i%4])
	}
	return f
}

// One malformed WS (or WSS) frame is counted once and never logged.
func TestMalformedWSFrameNotLogged(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "ws"
		if secure {
			name = "wss"
		}
		t.Run(name, func(t *testing.T) {
			rec := newLogRecorder()
			h := startShieldHarness(t, "100/s per_ip", "100/s per_ip", "", !secure, secure, rec)
			addr := h.publicWS
			var conn net.Conn
			var err error
			if secure {
				addr = h.publicWSS
				conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // self-signed test listener
			} else {
				conn, err = net.Dial("tcp", addr)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
				"Sec-WebSocket-Protocol: sip\r\n\r\n", addr)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade: %v %v", resp, err)
			}
			if _, err := conn.Write(rawWSFrame(garbage(1))); err != nil {
				t.Fatal(err)
			}
			label := strings.ToUpper(name)
			deadline := time.Now().Add(3 * time.Second)
			for h.parseFailures(label) == 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if got := h.parseFailures(label); got != 1 {
				t.Errorf("%s parse failures = %d, want 1", label, got)
			}
			assertNoPayloadLogged(t, rec)
		})
	}
}

// If sipgo changes the message, level or attribute names of its parse
// failure log, this fails: the wrapper would silently stop matching and the
// raw payload would be logged again. It uses a real sipgo UDP transport, as
// the edge does.
func TestSipgoParseFailureLogContract(t *testing.T) {
	rec := newLogRecorder()
	var mu sync.Mutex
	counts := map[string]int{}
	log := slog.New(newSipgoHandler(rec, func(tr string) {
		mu.Lock()
		counts[tr]++
		mu.Unlock()
	})).With("caller", "sipgo")
	ua, err := sipgo.NewUA(sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(log)))
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", nextPort(t))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tl := ua.TransportLayer()
	go func() { _ = tl.ServeUDP(pc.(*net.UDPConn)) }()
	defer pc.Close()

	c := dialUDP(t, addr)
	if _, err := c.Write(garbage(1)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := counts["UDP"]
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	got := counts["UDP"]
	mu.Unlock()
	if got != 1 {
		t.Fatalf("UDP parse failures counted = %d, want 1 (counts %v): did sipgo change its \"failed to parse\" log?", got, counts)
	}
	assertNoPayloadLogged(t, rec)
	var debugSeen bool
	for _, r := range rec.snapshot() {
		if r.level == slog.LevelDebug && r.attrs["len"] != "" && r.attrs["transport"] == "UDP" {
			debugSeen = true
		}
	}
	if !debugSeen {
		t.Error("no Debug record with len and transport for the parse failure")
	}
}

// The wrapper's own behaviour: WARN dedupe over the interval, and "data"
// never forwarded by a derived logger.
func TestSipgoHandlerWarnDedupeAndWith(t *testing.T) {
	rec := newLogRecorder()
	h := newSipgoHandler(rec, func(string) {})
	now := time.Unix(1000, 0)
	h.st.now = func() time.Time { return now }
	log := slog.New(h).With("caller", "sipgo").With("caller", "Transport<WS>").With("data", canary)
	fail := func() { log.Error("failed to parse", "data", canary, "error", fmt.Errorf("bad %s", canary)) }
	fail()
	fail()
	fail()
	now = now.Add(parseFailWarnEvery + time.Second)
	fail()
	var warns []recordedLog
	for _, r := range rec.snapshot() {
		if r.level == slog.LevelWarn {
			warns = append(warns, r)
		}
	}
	if len(warns) != 2 {
		t.Fatalf("WARN records = %d, want 2 (one per interval)", len(warns))
	}
	if warns[1].attrs["suppressed"] != "2" || warns[0].attrs["transport"] != "WS" {
		t.Errorf("WARN attrs = %v / %v", warns[0].attrs, warns[1].attrs)
	}
	assertNoPayloadLogged(t, rec)
}

// FuzzReadFilter: whatever the bytes, the source, the transport or the local
// socket, the read filter returns no error and does not panic (a filter
// error would kill sipgo's read loop).
func FuzzReadFilter(f *testing.F) {
	yaml := harnessYAML(f, []string{"127.0.0.1:25999"}, 25998, 25997, 0, 20000, "127.0.0.1")
	yaml = strings.Replace(yaml, "5000/s per_ip", "3/s per_ip", 2)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		f.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(config.NewStore(cfg), log, WithPrivateAddr(netip.MustParseAddrPort("127.0.0.1:25996")))
	if err != nil {
		f.Fatal(err)
	}
	srv.shield = shield.New(srv.store, log, func(ip netip.Addr) bool { return ip == netip.MustParseAddr("127.0.0.1") })
	f.Cleanup(func() { _ = srv.shield.Close() })
	filter := srv.readFilter()

	f.Add([]byte("INVITE sip:a@b SIP/2.0\r\n\r\n"), []byte{127, 0, 0, 1}, uint16(5060), uint8(0), true)
	f.Add([]byte("\r\n\r\n"), []byte{10, 1, 2, 3}, uint16(0), uint8(3), false)
	f.Add([]byte{}, []byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, uint16(1), uint8(9), true)
	f.Add(make([]byte, 30000), []byte{1, 2}, uint16(65535), uint8(1), false)
	nets := []string{"udp", "tcp", "tls", "ws", "wss", "UDP", "", "sctp", "WS", "x"}
	f.Fuzz(func(t *testing.T, data, ip []byte, port uint16, tr uint8, private bool) {
		var addr netip.Addr
		if a, ok := netip.AddrFromSlice(ip); ok {
			addr = a
		}
		props := sip.TransportReadProps{Transport: nets[int(tr)%len(nets)]}
		if addr.IsValid() {
			props.RemoteAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port))
		}
		local := srv.privAddr
		if !private {
			local = netip.MustParseAddrPort("127.0.0.1:25998")
		}
		props.LocalAddr = net.UDPAddrFromAddrPort(local)
		if tr%7 == 0 {
			props.LocalAddr = nil
		}
		if tr%11 == 0 {
			props.RemoteAddr = nil
		}
		if _, err := filter(props, append([]byte(nil), data...)); err != nil {
			t.Fatalf("read filter returned an error: %v", err)
		}
	})
}
