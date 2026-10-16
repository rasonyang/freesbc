package media

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// BenchmarkRelayLoad measures what the media relay costs per forwarded
// packet under paced, call-like load (issue #172): `calls` sessions, each
// receiving G.711 at 50 pps from both ends, the ends played by a generator
// in a child process so their sockets and syscalls are not charged to the
// relay. The figures are the relay process's own CPU (getrusage) over a
// fixed window:
//
//   - cpu-ns/pkt: CPU time per forwarded packet (one read, one write);
//   - pkt/cpu-s: forwarded packets per second of one core;
//   - cores: CPU in use, in cores; pps: forwarded packets per second;
//   - allocs/pkt: heap allocations per forwarded packet.
//
// burst=k sends k packets back to back every k*20 ms (same average rate),
// as a jittery upstream or a relay that fell behind would queue them: the
// case where batched reads can return more than one packet.
//
// It spawns a process and takes about a minute, so it runs only when
// FREESBC_BENCH_RELAY_LOAD=1; `-bench .` skips it. Loopback is not a NIC:
// see docs/notes/172-rtp-batch-io.md. The pool takes ports 21600-24599,
// which tests use too: a benchmark runs after the tests have closed their
// sessions, and the pool skips any port it cannot bind.
func BenchmarkRelayLoad(b *testing.B) {
	if os.Getenv("FREESBC_BENCH_RELAY_LOAD") != "1" {
		b.Skip("set FREESBC_BENCH_RELAY_LOAD=1 to run (spawns a load generator, about a minute)")
	}
	type run struct{ calls, burst int }
	runs := []run{{1, 1}, {100, 1}, {500, 1}, {500, 4}}
	for _, mode := range []string{"plain", "batch"} {
		for _, r := range runs {
			b.Run(fmt.Sprintf("%s/calls=%d/burst=%d", mode, r.calls, r.burst), func(b *testing.B) {
				if mode == "batch" && !batchRelayAvailable {
					b.Skip("no batched relay on this platform")
				}
				old := batchRelay.Load()
				batchRelay.Store(mode == "batch")
				defer batchRelay.Store(old)
				benchRelayLoad(b, r.calls, r.burst)
			})
		}
	}
}

const (
	relayLoadWarmup = 2 * time.Second
	relayLoadWindow = 5 * time.Second
	relayLoadEnv    = "FREESBC_RELAY_LOADGEN"
)

func benchRelayLoad(b *testing.B, calls, burst int) {
	pool := NewPlanePool("load", func() PlaneParams {
		return PlaneParams{MinPort: 21600, MaxPort: 24599, BindIP: netip.MustParseAddr("127.0.0.1"), Timeout: time.Hour, AllowLoopback: true}
	})
	sessions := make([]*Session, 0, calls)
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()
	var spec []string
	for i := 0; i < calls; i++ {
		s, err := AllocateAcross(pool, pool, SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchLoose}, Timeout: time.Hour})
		if err != nil {
			b.Fatal(err)
		}
		sessions = append(sessions, s)
		s.Start()
		spec = append(spec, fmt.Sprintf("%d:%d", s.RTPPort(SideA), s.RTPPort(SideB)))
	}
	gen := exec.Command(os.Args[0], "-test.run=^TestRelayLoadGenerator$", "-test.count=1", "-test.timeout=0")
	gen.Env = append(os.Environ(), relayLoadEnv+"="+strconv.Itoa(burst)+";"+strings.Join(spec, ","))
	gen.Stdout, gen.Stderr = os.Stderr, os.Stderr
	if err := gen.Start(); err != nil {
		b.Fatal(err)
	}
	defer func() {
		_ = gen.Process.Kill()
		_ = gen.Wait()
	}()
	forwarded := func() uint64 {
		var n uint64
		for _, s := range sessions {
			st := s.Stats()
			n += st.A.RTPPacketsTx + st.B.RTPPacketsTx
		}
		return n
	}
	cpu := func() time.Duration {
		var ru syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
			b.Fatal(err)
		}
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	time.Sleep(relayLoadWarmup)
	if forwarded() == 0 {
		b.Fatal("the generator's packets are not being relayed")
	}
	b.ResetTimer()
	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	p0, c0, t0 := forwarded(), cpu(), time.Now()
	time.Sleep(relayLoadWindow * time.Duration(b.N))
	p1, c1, t1 := forwarded(), cpu(), time.Now()
	runtime.ReadMemStats(&ms1)
	b.StopTimer()
	pkts := float64(p1 - p0)
	cpuS := (c1 - c0).Seconds()
	wall := t1.Sub(t0).Seconds()
	want := float64(calls) * 2 * 50 * wall
	if pkts < 0.9*want {
		b.Logf("forwarded %.0f packets, %.0f expected: the generator or the relay fell behind", pkts, want)
	}
	b.ReportMetric(cpuS*1e9/pkts, "cpu-ns/pkt")
	b.ReportMetric(pkts/cpuS, "pkt/cpu-s")
	b.ReportMetric(cpuS/wall, "cores")
	b.ReportMetric(pkts/wall, "pps")
	b.ReportMetric(float64(ms1.Mallocs-ms0.Mallocs)/pkts, "allocs/pkt")
}

// TestRelayLoadGenerator is BenchmarkRelayLoad's generator, run in a
// child process; it skips in a normal test run. For every session it
// plays both ends: one socket per side sends G.711 at 50 pps (in bursts of
// `burst` packets every burst*20 ms) and drains what the relay forwards.
// Sessions are spread over the 20 ms so the load is smooth. It runs until
// the parent kills it.
func TestRelayLoadGenerator(t *testing.T) {
	spec := os.Getenv(relayLoadEnv)
	if spec == "" {
		t.Skip("only run by BenchmarkRelayLoad")
	}
	burstStr, list, _ := strings.Cut(spec, ";")
	burst, err := strconv.Atoi(burstStr)
	if err != nil || burst < 1 {
		t.Fatalf("bad burst %q", burstStr)
	}
	var conns []*net.UDPConn
	for _, pair := range strings.Split(list, ",") {
		pa, pb, _ := strings.Cut(pair, ":")
		for _, p := range []string{pa, pb} {
			port, err := strconv.Atoi(p)
			if err != nil {
				t.Fatal(err)
			}
			c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			if err != nil {
				t.Fatal(err)
			}
			conns = append(conns, c)
		}
	}
	var received atomic.Uint64
	for _, c := range conns {
		go func(c *net.UDPConn) {
			buf := make([]byte, 2048)
			for {
				if _, err := c.Read(buf); err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue // an ICMP error reported on the connected socket
				}
				received.Add(1)
			}
		}(c)
	}
	const slots = 20 // one per millisecond of the 20 ms packet interval
	period := time.Duration(burst) * 20 * time.Millisecond
	tick := time.NewTicker(period / slots)
	defer tick.Stop()
	pkt := g711Packet(0)
	seq := make([]uint16, len(conns))
	for slot := 0; ; slot = (slot + 1) % slots {
		<-tick.C
		for i := slot; i < len(conns); i += slots {
			for k := 0; k < burst; k++ {
				seq[i]++
				pkt[2], pkt[3] = byte(seq[i]>>8), byte(seq[i])
				_, _ = conns[i].Write(pkt)
			}
		}
	}
}
