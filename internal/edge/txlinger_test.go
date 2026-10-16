package edge

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestServeTxDoesNotParkGoroutines is issue #170: once the edge has sent a
// final response on a UDP server transaction, the goroutine that ran the
// handler ends, instead of waiting in sipgo's TerminateGracefully for Timer
// J; and the transaction still absorbs a retransmission, which sipgo
// answers with the same final without running the handler again.
func TestServeTxDoesNotParkGoroutines(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	parked := func() (edge, sipgoServer int) {
		buf := make([]byte, 16<<20)
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if !strings.Contains(g, "TerminateGracefully") {
				continue
			}
			if strings.Contains(g, "edge.(*Server).serveTx") {
				edge++
			}
			if strings.Contains(g, "sipgo.(*Server).handleRequest") {
				sipgoServer++
			}
		}
		return edge, sipgoServer
	}
	_, before := parked()
	const n = 50
	for i := 0; i < n; i++ {
		if r := phone.do(t, buildOptions(phone, fmt.Sprintf("serve-tx-%d", i)), h.publicUDP); r.StatusCode != 200 {
			t.Fatalf("OPTIONS %d: %d", i, r.StatusCode)
		}
	}
	// Give the handler goroutines time to reach the end of serveTx.
	time.Sleep(100 * time.Millisecond)
	// The fake switch and the test phones are plain sipgo servers whose
	// goroutines from earlier tests may still be waiting; none of them
	// took part here, so their count can only fall.
	if edge, server := parked(); edge != 0 || server-before >= n/2 {
		t.Fatalf("server transactions parked a goroutine: %d in serveTx, sipgo Server.handleRequest %d -> %d", edge, before, server)
	}

	// A retransmission (same branch) after the handler returned: the
	// transaction is still in sipgo's store until Timer J, so the final is
	// replayed and the handler does not run a second time.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := buildOptions(phone, "serve-tx-retransmit")
	via := req.Via()
	via.Port = conn.LocalAddr().(*net.UDPAddr).Port
	wire := []byte(req.String())
	dst, err := net.ResolveUDPAddr("udp", h.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	in := func() uint64 { return h.srv.metrics.Snapshot().RequestsIn["OPTIONS/UDP"] }
	start := in()
	buf := make([]byte, 4096)
	for i := 0; i < 2; i++ {
		if _, err := conn.WriteToUDP(wire, dst); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		k, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("send %d: no response: %v", i, err)
		}
		if !strings.HasPrefix(string(buf[:k]), "SIP/2.0 200") {
			t.Fatalf("send %d: %q", i, strings.SplitN(string(buf[:k]), "\r\n", 2)[0])
		}
	}
	if got := in() - start; got != 1 {
		t.Fatalf("handler ran %d times for one transaction and its retransmission, want 1", got)
	}
}

// TestMeasureTxLinger reports what a finished SIP server transaction keeps
// alive (issue #170): goroutines, stack and heap per transaction, right
// after a burst and again once sipgo's 32 s timers have run out. It is a
// measurement, not a check, and takes about 40 s, so it runs only with
// FREESBC_TX_LINGER=1 (FREESBC_TX_LINGER_HEAP=<dir> also writes a heap
// profile per workload, taken right after the burst):
//
//	FREESBC_TX_LINGER=1 go test ./internal/edge -run '^TestMeasureTxLinger$' -count=1 -v
//
// Two workloads, each from a fresh harness:
//   - options: public OPTIONS from a carrier source, answered by the edge
//     itself, so every transaction counted is the edge's own;
//   - call: INVITE, ACK, BYE through the fake switch. The fake switch is a
//     plain sipgo server in this process, so its own two server
//     transactions per call (INVITE and BYE) are in the totals too.
func TestMeasureTxLinger(t *testing.T) {
	if os.Getenv("FREESBC_TX_LINGER") != "1" {
		t.Skip("measurement; set FREESBC_TX_LINGER=1 to run")
	}
	if os.Getenv("FREESBC_TX_LINGER_HEAP") != "" {
		runtime.MemProfileRate = 1 // every allocation, for an exact breakdown
	}
	n := 2000
	t.Run("options", func(t *testing.T) { measureLinger(t, n, lingerOptions) })
	t.Run("call", func(t *testing.T) { measureLinger(t, n/2, lingerCall) })
}

// lingerOptions is one public OPTIONS the edge answers itself: one edge
// server transaction.
func lingerOptions(t *testing.T, h *harness, c *client, i int) int {
	if r := c.do(t, buildOptions(c, fmt.Sprintf("linger-opt-%d-%d", i, time.Now().UnixNano())), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("OPTIONS %d: %d", i, r.StatusCode)
	}
	return 1
}

// lingerCall is INVITE, ACK, BYE with no hold: two edge server
// transactions (INVITE and BYE).
func lingerCall(t *testing.T, h *harness, c *client, i int) int {
	invite := c.buildInvite("1001", "2002", "example.com", phoneOfferSDP(40000+i%1000))
	res := c.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE %d: %d", i, res.StatusCode)
	}
	sendAck(t, c, invite, res, h.publicUDP)
	if r := c.do(t, buildBye(c, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("BYE %d: %d", i, r.StatusCode)
	}
	return 2
}

// TestMeasureTxLingerSustained runs a workload at a fixed rate for 50 s,
// long enough for the 32 s transaction lifetime to reach steady state,
// and reports the plateau (the last 10 s) of RSS, heap, stacks and
// goroutines above the idle baseline, per unit of rate. Like
// TestMeasureTxLinger it is a measurement, gated on an environment
// variable:
//
//	FREESBC_TX_LINGER_RATE=1000 FREESBC_TX_LINGER_WORKLOAD=options \
//	  go test ./internal/edge -run '^TestMeasureTxLingerSustained$' -count=1 -v
//
// WORKLOAD is options (default) or call. Everything runs in one process,
// test clients and (for call) the fake switch included, so the absolute
// figures are this harness's, not a deployment's; compare runs with each
// other. Set GOMEMLIMIT in the environment to see its effect.
func TestMeasureTxLingerSustained(t *testing.T) {
	rate, _ := strconv.Atoi(os.Getenv("FREESBC_TX_LINGER_RATE"))
	if rate <= 0 {
		t.Skip("measurement; set FREESBC_TX_LINGER_RATE=<units per second> to run")
	}
	one := lingerOptions
	if os.Getenv("FREESBC_TX_LINGER_WORKLOAD") == "call" {
		one = lingerCall
	}
	h := startHarness(t, false)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	const workers = 32
	clients := make([]*client, workers)
	for i := range clients {
		clients[i] = newUDPClient(t)
		one(t, h, clients[i], i)
	}
	time.Sleep(time.Second)
	settle()
	base := procSample()
	cpu0, gc0 := cpuSeconds()

	const duration, plateau = 50 * time.Second, 10
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var done atomic.Int64
	interval := time.Duration(float64(time.Second) * workers / float64(rate))
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			tick := time.NewTicker(interval)
			defer tick.Stop()
			for i := w; ; i += workers {
				select {
				case <-stop:
					return
				case <-tick.C:
				}
				one(t, h, clients[w], i)
				done.Add(1)
			}
		}(w)
	}
	var samples []procStats
	start := time.Now()
	for time.Since(start) < duration {
		time.Sleep(time.Second)
		// The fake switch keeps a clone of every request it receives, for
		// the functional tests; that is not FreeSBC's memory.
		h.fs.mu.Lock()
		h.fs.requests = nil
		h.fs.mu.Unlock()
		samples = append(samples, procSample())
	}
	close(stop)
	wg.Wait()
	achieved := float64(done.Load()) / time.Since(start).Seconds()
	cpu1, gc1 := cpuSeconds()
	if dir := os.Getenv("FREESBC_TX_LINGER_HEAP"); dir != "" {
		runtime.GC()
		f, err := os.Create(filepath.Join(dir, "sustained.heap"))
		if err != nil {
			t.Fatal(err)
		}
		_ = pprof.WriteHeapProfile(f)
		_ = f.Close()
	}

	var avg procStats
	peakRSS := uint64(0)
	for _, s := range samples {
		peakRSS = max(peakRSS, s.rss)
	}
	for _, s := range samples[len(samples)-plateau:] {
		avg.rss += s.rss / plateau
		avg.heapInuse += s.heapInuse / plateau
		avg.stackInuse += s.stackInuse / plateau
		avg.goroutines += s.goroutines / plateau
	}
	mib := func(b uint64) float64 { return float64(b) / (1 << 20) }
	per := func(v, b uint64) float64 { return float64(int64(v)-int64(b)) / achieved / 1024 }
	t.Logf("workload=%s rate=%d/s achieved=%.0f/s GOMEMLIMIT=%q", os.Getenv("FREESBC_TX_LINGER_WORKLOAD"), rate, achieved, os.Getenv("GOMEMLIMIT"))
	t.Logf("baseline: RSS %.1f MiB, heap %.1f MiB, stacks %.1f MiB, goroutines %d", mib(base.rss), mib(base.heapInuse), mib(base.stackInuse), base.goroutines)
	t.Logf("plateau:  RSS %.1f MiB (peak %.1f), heap %.1f MiB, stacks %.1f MiB, goroutines %d",
		mib(avg.rss), mib(peakRSS), mib(avg.heapInuse), mib(avg.stackInuse), avg.goroutines)
	t.Logf("CPU: %.1f s for the process over the run, GC %.1f s (%.0f%%)", cpu1-cpu0, gc1-gc0, 100*(gc1-gc0)/(cpu1-cpu0))
	t.Logf("per unit/s above baseline: RSS %.1f KiB, heap %.1f KiB, stacks %.1f KiB, goroutines %.1f",
		per(avg.rss, base.rss), per(avg.heapInuse, base.heapInuse), per(avg.stackInuse, base.stackInuse),
		float64(avg.goroutines-base.goroutines)/achieved)
}

// cpuSeconds is the process's busy CPU time and the GC's share of it, as
// the runtime estimates them (runtime/metrics; total includes idle).
func cpuSeconds() (busy, gc float64) {
	s := []metrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/cpu/classes/idle:cpu-seconds"},
		{Name: "/cpu/classes/gc/total:cpu-seconds"},
	}
	metrics.Read(s)
	return s[0].Value.Float64() - s[1].Value.Float64(), s[2].Value.Float64()
}

type procStats struct {
	rss, heapInuse, stackInuse uint64
	goroutines                 int
}

// procSample reads VmRSS from /proc (Linux) or, elsewhere, the runtime's
// own Sys as a stand-in.
func procSample() procStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := procStats{rss: ms.Sys, heapInuse: ms.HeapInuse, stackInuse: ms.StackInuse, goroutines: runtime.NumGoroutine()}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
				if kb, err := strconv.ParseUint(f[1], 10, 64); err == nil {
					s.rss = kb << 10
				}
			}
		}
	}
	return s
}

type lingerSample struct {
	goroutines, terminating, drainers int
	heapInuse, stackInuse, sys        uint64
}

func sampleLinger() lingerSample {
	settle()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	buf := make([]byte, 64<<20)
	n := runtime.Stack(buf, true)
	s := lingerSample{goroutines: runtime.NumGoroutine(), heapInuse: ms.HeapInuse, stackInuse: ms.StackInuse, sys: ms.Sys}
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "TerminateGracefully") {
			s.terminating++
		}
		if strings.Contains(g, "drainAcks") {
			s.drainers++
		}
	}
	return s
}

func measureLinger(t *testing.T, n int, one func(t *testing.T, h *harness, c *client, i int) int) {
	h := startHarness(t, false)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	const workers = 16
	clients := make([]*client, workers)
	for i := range clients {
		clients[i] = newUDPClient(t)
	}
	// Warm up the allocator, the pools and the stacks before the baseline.
	for i := 0; i < workers; i++ {
		one(t, h, clients[i], i)
	}
	time.Sleep(time.Second)
	before := sampleLinger()

	start := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	txs := 0
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < n; i += workers {
				k := one(t, h, clients[w], i)
				mu.Lock()
				txs += k
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)
	after := sampleLinger()
	report := func(label string, s lingerSample) {
		dg := s.goroutines - before.goroutines
		t.Logf("%s: %d units (%d edge server tx) in %v; goroutines %+d (TerminateGracefully %d, drainAcks %d); "+
			"per edge tx: %.2f goroutines, stack %.0f B, heap %.0f B, sys %.0f B",
			label, n, txs, elapsed.Round(time.Millisecond), dg, s.terminating, s.drainers,
			float64(dg)/float64(txs),
			float64(int64(s.stackInuse)-int64(before.stackInuse))/float64(txs),
			float64(int64(s.heapInuse)-int64(before.heapInuse))/float64(txs),
			float64(int64(s.sys)-int64(before.sys))/float64(txs))
	}
	report("right after", after)
	if dir := os.Getenv("FREESBC_TX_LINGER_HEAP"); dir != "" {
		f, err := os.Create(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "_")+".heap"))
		if err != nil {
			t.Fatal(err)
		}
		_ = pprof.WriteHeapProfile(f)
		_ = f.Close()
	}
	// Timer J/L/H is 64*T1 = 32 s; give it a margin.
	time.Sleep(36 * time.Second)
	report("after 36 s", sampleLinger())
}
