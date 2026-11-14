package media

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// capLog is a slog.Handler that keeps every record (Debug and up).
type capLog struct {
	mu   sync.Mutex
	recs []capRec
}

type capRec struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

func (c *capLog) Enabled(context.Context, slog.Level) bool { return true }
func (c *capLog) Handle(_ context.Context, r slog.Record) error {
	rec := capRec{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool { rec.attrs[a.Key] = a.Value.String(); return true })
	c.mu.Lock()
	c.recs = append(c.recs, rec)
	c.mu.Unlock()
	return nil
}
func (c *capLog) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capLog) WithGroup(string) slog.Handler      { return c }

func (c *capLog) find(msg string) []capRec {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []capRec
	for _, r := range c.recs {
		if r.msg == msg {
			out = append(out, r)
		}
	}
	return out
}

const (
	msgRejected = "media packets rejected by latch"
	msgMoved    = "media latch moved"
	msgSet      = "media latch set"
)

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func dialRTCP(t *testing.T, s *Session, side Side) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(side) + 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// A packet the latch refuses is counted for its side and kind; an accepted
// one is not.
func TestLatchRefusalCountedPlain(t *testing.T) {
	log := &capLog{}
	p := testPool(24000, 24015)
	s, err := AllocateAcross(p, p, SessionConfig{
		Latch: [2]LatchMode{LatchLoose, LatchLoose}, Timeout: time.Minute, Log: slog.New(log)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.Start()
	real, other := dialSide(t, s, SideA), dialSide(t, s, SideA)
	realC, otherC := dialRTCP(t, s, SideA), dialRTCP(t, s, SideA)

	_, _ = real.Write([]byte("rtp"))
	_, _ = realC.Write([]byte("rtcp"))
	eventually(t, "latch", func() bool { return s.Stats().A.RTPPacketsRx == 1 })
	_, _ = real.Write([]byte("rtp"))
	eventually(t, "second accepted", func() bool { return s.Stats().A.RTPPacketsRx == 2 })
	if st := s.Stats().A; st.RTPRejected != 0 || st.RTCPRejected != 0 {
		t.Fatalf("accepted packets counted as rejected: %+v", st)
	}

	// A second source of the same rank cannot take the latch.
	for i := 0; i < 3; i++ {
		_, _ = other.Write([]byte("rtp"))
	}
	_, _ = otherC.Write([]byte("rtcp"))
	eventually(t, "rejections", func() bool {
		st := s.Stats().A
		return st.RTPRejected == 3 && st.RTCPRejected == 1
	})
	if st := s.Stats(); st.B.RTPRejected != 0 || st.B.RTCPRejected != 0 || st.A.RTPPacketsRx != 2 {
		t.Errorf("side B or rx moved: %+v", st)
	}
	// The counter moves before the reporter logs, so wait for the line.
	eventually(t, "rejected-by-latch WARN", func() bool { return len(log.find(msgRejected)) > 0 })
	recs := log.find(msgRejected)
	// The limiter is shared by the RTP and RTCP loops, so either kind may
	// have won the first line.
	r := recs[0]
	pair := map[string][2]string{
		"rtp":  {real.LocalAddr().String(), other.LocalAddr().String()},
		"rtcp": {realC.LocalAddr().String(), otherC.LocalAddr().String()},
	}[r.attrs["kind"]]
	if r.level != slog.LevelWarn || r.attrs["reason"] != "latched" || r.attrs["plane"] != "test" ||
		r.attrs["latched"] != pair[0] || r.attrs["source"] != pair[1] ||
		r.attrs["latched_rank"] != "any" || r.attrs["source_rank"] != "any" {
		t.Errorf("WARN attrs: %+v", r)
	}
}

// The SDES pre-decrypt check counts a refusal too, and leaves the SRTP
// drop counter alone.
func TestLatchRefusalCountedSDES(t *testing.T) {
	r := newSDESRig(t, 24020, 0)
	real, other := dialSide(t, r.s, SideA), dialSide(t, r.s, SideA)
	b := dialSide(t, r.s, SideB)
	latchPlainB(t, r.s, b)
	sendUntil(t, func() { _, _ = real.Write(r.srtpPacket(t, "real")) }, b,
		func(p []byte) bool { return payloadOf(t, p) == "real" })
	if st := r.s.Stats().A; st.RTPRejected != 0 {
		t.Fatalf("accepted counted as rejected: %+v", st)
	}
	_, _ = other.Write(r.srtpPacket(t, "intruder"))
	eventually(t, "rejection", func() bool { return r.s.Stats().A.RTPRejected == 1 })
	if st := r.s.Stats().A; st.SRTPRxDrops != 0 {
		t.Errorf("SRTPRxDrops = %d, want 0 (the latch refused before decrypt)", st.SRTPRxDrops)
	}
}

// The WebRTC session's private side counts refusals as side B. The leg is
// not needed: a refused packet never reaches it.
func TestLatchRefusalCountedWebRTCPrivate(t *testing.T) {
	log := &capLog{}
	p := testPool(24040, 24055)
	s, err := NewWebRTCSession(nil, p, WebRTCSessionConfig{PrivateLatch: LatchStrict, Timeout: time.Minute, Log: slog.New(log)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.priv.Close(); p.release(s.priv.RTPPort()) })
	lo := netip.MustParseAddr("127.0.0.1")
	s.SetPrivateRemote(netip.AddrPortFrom(lo, 24999))
	// Latch a stand-in for FreeSWITCH directly (accepting through the relay
	// would need a verified DTLS leg).
	if v := s.privRTP.decide(netip.AddrPortFrom(lo, 24998), time.Now()); v.ev != evSet {
		t.Fatalf("setup latch: %+v", v)
	}
	go s.privateToPublic(nil, nil, true)
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.PrivateRTPPort()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("x"))
	eventually(t, "rejection", func() bool { return s.Stats().B.RTPRejected == 1 })
	if st := s.Stats(); st.A.RTPRejected != 0 || st.B.RTCPRejected != 0 {
		t.Errorf("wrong side or kind: %+v", st)
	}
	// The counter moves before the reporter logs, so wait for the line.
	eventually(t, "rejected-by-latch WARN", func() bool { return len(log.find(msgRejected)) > 0 })
	if recs := log.find(msgRejected); len(recs) != 1 || recs[0].attrs["plane"] != "test" || recs[0].attrs["kind"] != "rtp" {
		t.Errorf("WARN: %+v", recs)
	}
}

// 100 refusals inside one second make one WARN, carrying the count of
// refusals since the previous line; the next second logs again.
func TestRejectWarnIsRateLimited(t *testing.T) {
	log := &capLog{}
	var c counters
	rep := newLatchReporter(slog.New(log), &c, [2]string{"public", "private"}, [2]*planeBudget{})
	now := time.Unix(1000, 0)
	rep.lim.now = func() time.Time { return now }
	held := netip.MustParseAddrPort("192.0.2.1:20002")
	src := netip.MustParseAddrPort("192.0.2.1:20004")
	refuse := func() {
		rep.observe(SideA, true, src, latchVerdict{ev: evRefused, held: held, heldRank: rankSignalled, rank: rankSignalled})
	}
	for i := 0; i < 100; i++ {
		refuse()
		now = now.Add(5 * time.Millisecond)
	}
	if got := log.find(msgRejected); len(got) != 1 || got[0].attrs["count"] != "1" {
		t.Fatalf("first second: %+v", got)
	}
	now = now.Add(time.Second)
	refuse()
	got := log.find(msgRejected)
	if len(got) != 2 || got[1].attrs["count"] != "100" {
		t.Fatalf("next second: %+v", got)
	}
	if n := c.rtpRejected[SideA].Load(); n != 101 {
		t.Errorf("counted %d, want 101", n)
	}
	// With nothing latched a refusal is counted but never logged.
	rep.observe(SideB, false, src, latchVerdict{ev: evRefused, rank: rankNone})
	if len(log.find(msgRejected)) != 2 || c.rtcpRejected[SideB].Load() != 1 {
		t.Errorf("unlatched refusal: logs %d, rtcp counter %d", len(log.find(msgRejected)), c.rtcpRejected[SideB].Load())
	}
}

// A first latch logs at DEBUG only; a move logs exactly one INFO naming
// both sources.
func TestLatchMoveLogged(t *testing.T) {
	log := &capLog{}
	var c counters
	rep := newLatchReporter(slog.New(log), &c, [2]string{"public", "private"}, [2]*planeBudget{})
	lo := netip.MustParseAddr("127.0.0.1")
	l := &latch{mode: LatchLoose, allowLoopback: true}
	l.seed(netip.AddrPortFrom(lo, 30000))
	first, exact := netip.AddrPortFrom(lo, 29998), netip.AddrPortFrom(lo, 30000)

	if !rep.observe(SideA, true, first, l.decide(first, time.Now())) {
		t.Fatal("first source refused")
	}
	if n := len(log.find(msgMoved)); n != 0 {
		t.Fatalf("first latch logged %d moves", n)
	}
	if sets := log.find(msgSet); len(sets) != 1 || sets[0].level != slog.LevelDebug {
		t.Fatalf("first latch: %+v", sets)
	}
	if !rep.observe(SideA, true, exact, l.decide(exact, time.Now())) {
		t.Fatal("exact source refused")
	}
	moves := log.find(msgMoved)
	if len(moves) != 1 {
		t.Fatalf("moves: %+v", moves)
	}
	m := moves[0]
	if m.level != slog.LevelInfo || m.attrs["from"] != first.String() || m.attrs["to"] != exact.String() ||
		m.attrs["from_rank"] != "signalled" || m.attrs["to_rank"] != "exact" || m.attrs["plane"] != "public" || m.attrs["kind"] != "rtp" {
		t.Errorf("move line: %+v", m)
	}
	// The same source again is silent.
	rep.observe(SideA, true, exact, l.decide(exact, time.Now()))
	if len(log.find(msgMoved)) != 1 || len(log.find(msgSet)) != 1 {
		t.Error("steady state logged")
	}
}

// The #324 shape on a loose public side seeded with an exact SDP address P:
// a stream from P-2 latches and is relayed, three packets from P move the
// latch, and the live stream on P-2 is refused until P has been silent for
// LatchFallback, when the latch follows the live stream back (a fallback
// move). The lock-out is bounded at about LatchFallback of packets (~50 at
// 20 ms), not the rest of the call.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.
func TestLatchMoveLockOutIsBounded(t *testing.T) {
	const P = 24102
	log := &capLog{}
	p := testPool(24200, 24215)
	s, err := AllocateAcross(p, p, SessionConfig{
		Latch: [2]LatchMode{LatchLoose, LatchLoose}, Timeout: time.Minute, Log: slog.New(log)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	lo := netip.MustParseAddr("127.0.0.1")
	s.SetRemote(SideA, netip.AddrPortFrom(lo, P))
	s.Start()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideA)}
	listen := func(port int) *net.UDPConn {
		c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, target)
		if err != nil {
			t.Skipf("port %d busy: %v", port, err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	live, exact := listen(P-2), listen(P)

	_, _ = live.Write([]byte("x"))
	eventually(t, "live latched", func() bool { return s.Stats().A.RTPPacketsRx == 1 })
	for i := 0; i < 3; i++ {
		_, _ = exact.Write([]byte("x"))
	}
	eventually(t, "latch moved", func() bool { return s.Stats().A.RTPPacketsRx == 4 })
	// The live stream at 20 ms until the fallback hands the latch back.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(log.find(msgMoved)) < 2 {
		_, _ = live.Write([]byte("x"))
		time.Sleep(20 * time.Millisecond)
	}
	st := s.Stats().A
	if st.RTPRejected < 20 || st.RTPRejected > 70 {
		t.Errorf("RTPRejected = %d, want about LatchFallback of packets (~50)", st.RTPRejected)
	}
	before := st.RTPPacketsRx
	for i := 0; i < 5; i++ {
		_, _ = live.Write([]byte("x"))
		time.Sleep(20 * time.Millisecond)
	}
	eventually(t, "live stream relayed again", func() bool { return s.Stats().A.RTPPacketsRx >= before+5 })
	if got := s.Stats().A.RTPRejected; got != st.RTPRejected {
		t.Errorf("RTPRejected grew from %d to %d after the fallback", st.RTPRejected, got)
	}
	moves := log.find(msgMoved)
	if len(moves) != 2 ||
		moves[0].attrs["from"] != "127.0.0.1:"+strconv.Itoa(P-2) ||
		moves[0].attrs["to"] != "127.0.0.1:"+strconv.Itoa(P) ||
		moves[0].attrs["fallback"] != "false" ||
		moves[1].attrs["from"] != "127.0.0.1:"+strconv.Itoa(P) ||
		moves[1].attrs["to"] != "127.0.0.1:"+strconv.Itoa(P-2) ||
		moves[1].attrs["fallback"] != "true" {
		t.Errorf("moves: %+v", moves)
	}
	warns := log.find(msgRejected)
	if len(warns) == 0 || len(warns) > 3 {
		t.Errorf("%d rejected WARNs, want 1..3", len(warns))
	}
	for _, w := range warns {
		if strings.Contains(w.attrs["latched"], strconv.Itoa(P-2)) {
			t.Errorf("WARN names the wrong latched source: %+v", w)
		}
	}
}

// Twenty sessions of one pool refuse within the same second: the plane
// budget lets ten WARNs through. The next second the first line carries
// lines_suppressed=10, and a held-back session's line carries its full count.
func TestRejectWarnPlaneBudget(t *testing.T) {
	log := &capLog{}
	now := time.Unix(2000, 0)
	clock := func() time.Time { return now }
	budget := &planeBudget{now: clock}
	held := netip.MustParseAddrPort("192.0.2.1:20002")
	src := netip.MustParseAddrPort("192.0.2.1:20004")
	v := latchVerdict{ev: evRefused, held: held, heldRank: rankSignalled, rank: rankSignalled}
	reps := make([]latchReporter, 20)
	for i := range reps {
		reps[i] = newLatchReporter(slog.New(log), new(counters), [2]string{"public", "private"}, [2]*planeBudget{budget, nil})
		reps[i].lim.now = clock
	}
	for i := range reps {
		reps[i].observe(SideA, true, src, v)
	}
	if got := len(log.find(msgRejected)); got != 10 {
		t.Fatalf("first second: %d WARNs, want 10", got)
	}
	// Session 15 was held back with count 1; it refuses 4 more inside the
	// same second (its own limiter is closed, so they only add up).
	for i := 0; i < 4; i++ {
		reps[15].observe(SideA, true, src, v)
	}
	now = now.Add(1100 * time.Millisecond)
	reps[15].observe(SideA, true, src, v)
	got := log.find(msgRejected)
	if len(got) != 11 {
		t.Fatalf("after advance: %d WARNs, want 11", len(got))
	}
	last := got[10]
	if last.attrs["lines_suppressed"] != "10" || last.attrs["count"] != "6" {
		t.Errorf("held-back session line: %+v", last.attrs)
	}
	if _, ok := got[0].attrs["lines_suppressed"]; ok {
		t.Error("lines_suppressed present when zero")
	}
}
