// Command webrtcload is the WebRTC load client for FreeSBC (test/perf).
//
// SIPp cannot do ICE or DTLS, so this client plays the browser: it opens WS or
// WSS connections to FreeSBC, REGISTERs N users over them, places calls whose
// offer carries ICE candidates, a DTLS fingerprint (setup:actpass) and PCMU,
// completes ICE (as the controlling agent against FreeSBC's ICE-Lite) and
// DTLS-SRTP, then exchanges G.711 20 ms SRTP with the switch behind FreeSBC
// (the SIPp UAS echoes it) and hangs up. It reports REGISTER and setup
// latency, DTLS handshakes per second, packet loss, jitter and round-trip
// time. It uses the same pion ice/dtls/srtp primitives as the edge.
//
// One WebSocket connection carries many users (FreeSBC caps connections at
// 256 per source IP); -conns sets how many connections share the users.
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	target     string
	domain     string
	users      int
	userPrefix string
	userStart  int
	password   string
	number     string
	rate       float64
	duration   time.Duration
	calls      int
	hold       time.Duration
	conns      int
	regRate    float64
	advertise  string
	insecure   bool
	out        string
	quiet      bool
	noMedia    bool
}

func main() {
	var c config
	flag.StringVar(&c.target, "target", "ws://172.28.1.10:8080", "FreeSBC WebSocket URL: ws://host:port (edge.listen.ws) or wss://host:port (edge.listen.wss)")
	flag.StringVar(&c.domain, "domain", "perf.test", "SIP domain for REGISTER and the dialed URI")
	flag.IntVar(&c.users, "users", 100, "users to register; also the cap on concurrent calls (a user is in one call at a time)")
	flag.StringVar(&c.userPrefix, "user-prefix", "w", "user names are <prefix><index, 6 digits>")
	flag.IntVar(&c.userStart, "user-start", 1, "first user index (use different ranges for several client processes)")
	flag.StringVar(&c.password, "password", "", "digest password for every user; empty = answer no challenge (a 401/407 then fails the request)")
	flag.StringVar(&c.number, "number", "2000", "user part of the dialed Request-URI")
	flag.Float64Var(&c.rate, "rate", 5, "calls started per second")
	flag.DurationVar(&c.duration, "duration", 30*time.Second, "how long to keep starting calls (ignored when -calls is set)")
	flag.IntVar(&c.calls, "calls", 0, "total calls to place; 0 = rate x duration")
	flag.DurationVar(&c.hold, "hold", 10*time.Second, "how long each call exchanges media before BYE")
	flag.IntVar(&c.conns, "conns", 20, "WebSocket connections to open (max 256 per source IP); users are spread over them")
	flag.Float64Var(&c.regRate, "reg-rate", 200, "REGISTERs per second while registering the users")
	flag.StringVar(&c.advertise, "advertise", "", "IP to write in the offer's c= line instead of the first candidate's (NAT)")
	flag.BoolVar(&c.insecure, "insecure", true, "do not verify the wss certificate (FreeSBC's is self-signed on the rig)")
	flag.StringVar(&c.out, "out", "", "write one CSV row per call to this file")
	flag.BoolVar(&c.quiet, "quiet", false, "no progress lines")
	flag.BoolVar(&c.noMedia, "no-media", false, "signaling and ICE/DTLS only: skip the SRTP exchange (the call is held with no RTP)")
	flag.Parse()
	os.Exit(run(c))
}

// result is one call's outcome.
type result struct {
	start    time.Time
	dtlsAt   time.Time // when the DTLS handshake completed
	user     string
	callID   string
	regMs    float64
	setupMs  float64 // INVITE -> 200
	iceMs    float64
	dtlsMs   float64
	sent     uint64
	recv     uint64
	lostSeq  uint64
	jitterMs float64
	rttP50   time.Duration
	rttP99   time.Duration
	err      string // "" = success
}

type stats struct {
	mu       sync.Mutex
	results  []result
	regLat   []time.Duration
	regFail  int
	started  int64
	active   int64
	rtts     []time.Duration
	errKinds map[string]int
	skipped  int // call slots dropped because every user was busy (-users too small)
}

func run(c config) int {
	u, err := url.Parse(c.target)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
		fmt.Fprintln(os.Stderr, "webrtcload: -target must be ws://host:port or wss://host:port")
		return 2
	}
	if c.users < 1 || c.conns < 1 || c.rate <= 0 {
		fmt.Fprintln(os.Stderr, "webrtcload: -users, -conns and -rate must be positive")
		return 2
	}
	if c.conns > c.users {
		c.conns = c.users
	}
	loop := false
	if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
		loop = true
	}

	st := &stats{errKinds: map[string]int{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- connections ---
	clients := make([]*wsClient, 0, c.conns)
	for i := 0; i < c.conns; i++ {
		w, err := newWSClient(c, u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "webrtcload: connection %d: %v\n", i+1, err)
			return 1
		}
		clients = append(clients, w)
	}
	defer func() {
		for _, w := range clients {
			_ = w.ws.Close()
		}
	}()

	// --- registration phase ---
	names := make([]string, c.users)
	for i := range names {
		names[i] = fmt.Sprintf("%s%06d", c.userPrefix, c.userStart+i)
	}
	t0 := time.Now()
	var wg sync.WaitGroup
	regTick := time.NewTicker(time.Duration(float64(time.Second) / c.regRate))
	for i, name := range names {
		<-regTick.C
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			d, err := clients[i%len(clients)].register(c, name)
			st.mu.Lock()
			if err != nil {
				st.regFail++
				st.errKinds["register: "+err.Error()]++
			} else {
				st.regLat = append(st.regLat, d)
			}
			st.mu.Unlock()
		}(i, name)
	}
	regTick.Stop()
	wg.Wait()
	regElapsed := time.Since(t0)
	logf(c, "registered %d/%d users in %s", len(st.regLat), c.users, regElapsed.Round(time.Millisecond))
	if len(st.regLat) == 0 {
		fmt.Fprintln(os.Stderr, "webrtcload: no user registered")
		printSummary(c, st, regElapsed, 0)
		return 1
	}

	// --- call phase ---
	total := c.calls
	if total == 0 {
		total = int(c.rate * c.duration.Seconds())
	}
	free := make(chan int, c.users)
	for i := range names {
		free <- i
	}
	interval := time.Duration(float64(time.Second) / c.rate)
	launchStart := time.Now()
	stopProgress := make(chan struct{})
	if !c.quiet {
		go func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-t.C:
					st.mu.Lock()
					n := len(st.results)
					ok := 0
					for _, r := range st.results {
						if r.err == "" {
							ok++
						}
					}
					st.mu.Unlock()
					logf(c, "t=%ds started=%d active=%d done=%d ok=%d", int(time.Since(launchStart).Seconds()),
						atomic.LoadInt64(&st.started), atomic.LoadInt64(&st.active), n, ok)
				}
			}
		}()
	}
	next := time.Now()
	for n := 0; n < total; n++ {
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
		next = next.Add(interval)
		var idx int
		select {
		case idx = <-free:
		case <-time.After(interval):
			st.mu.Lock()
			st.skipped++
			st.mu.Unlock()
			continue
		}
		atomic.AddInt64(&st.started, 1)
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { free <- idx }()
			atomic.AddInt64(&st.active, 1)
			defer atomic.AddInt64(&st.active, -1)
			r := clients[idx%len(clients)].call(ctx, c, names[idx], loop)
			st.mu.Lock()
			st.results = append(st.results, r)
			if r.err != "" {
				st.errKinds[r.err]++
			}
			st.mu.Unlock()
		}(idx)
	}
	launchElapsed := time.Since(launchStart)
	wg.Wait()
	close(stopProgress)

	printSummary(c, st, regElapsed, launchElapsed)
	if c.out != "" {
		if err := writeCSV(c.out, st.results); err != nil {
			fmt.Fprintln(os.Stderr, "webrtcload:", err)
		}
	}
	okN := 0
	for _, r := range st.results {
		if r.err == "" {
			okN++
		}
	}
	if okN == 0 {
		return 1
	}
	return 0
}

func logf(c config, f string, a ...any) {
	if !c.quiet {
		fmt.Fprintf(os.Stderr, "webrtcload: "+f+"\n", a...)
	}
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func quantiles(d []time.Duration) string {
	if len(d) == 0 {
		return "n/a"
	}
	return fmt.Sprintf("p50=%.1f p95=%.1f p99=%.1f max=%.1f ms",
		ms(percentile(d, 50)), ms(percentile(d, 95)), ms(percentile(d, 99)), ms(percentile(d, 100)))
}

func printSummary(c config, st *stats, regElapsed, launch time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	var okRes []result
	var setup, ice, dtlsL, jit, rttAll []time.Duration
	var sent, recv, lost uint64
	for _, r := range st.results {
		if r.err != "" {
			continue
		}
		okRes = append(okRes, r)
		setup = append(setup, time.Duration(r.setupMs*float64(time.Millisecond)))
		ice = append(ice, time.Duration(r.iceMs*float64(time.Millisecond)))
		dtlsL = append(dtlsL, time.Duration(r.dtlsMs*float64(time.Millisecond)))
		jit = append(jit, time.Duration(r.jitterMs*float64(time.Millisecond)))
		sent += r.sent
		recv += r.recv
		lost += r.lostSeq
		rttAll = append(rttAll, r.rttP50)
	}
	attempted := 0
	for _, r := range st.results {
		if r.callID != "" || r.err != "" {
			attempted++
		}
	}
	failed := attempted - len(okRes)
	fmt.Println("== webrtcload summary ==")
	fmt.Printf("target            %s  conns=%d users=%d hold=%s\n", c.target, c.conns, c.users, c.hold)
	fmt.Printf("registrations     ok=%d failed=%d  %s\n", len(st.regLat), st.regFail, quantiles(st.regLat))
	fmt.Printf("calls             attempted=%d ok=%d failed=%d (%.2f%%) skipped=%d (all users busy; raise -users)\n", attempted, len(okRes), failed, pct(failed, attempted), st.skipped)
	fmt.Printf("setup INVITE->200 %s\n", quantiles(setup))
	fmt.Printf("ICE connect       %s\n", quantiles(ice))
	fmt.Printf("DTLS handshake    %s\n", quantiles(dtlsL))
	// Handshake rate: completions over the span from the first call start to
	// the last handshake, and the busiest single second.
	hps, peak := 0.0, 0
	if len(okRes) > 0 {
		first, lastAt := okRes[0].start, okRes[0].dtlsAt
		perSec := map[int64]int{}
		for _, r := range okRes {
			if r.start.Before(first) {
				first = r.start
			}
			if r.dtlsAt.After(lastAt) {
				lastAt = r.dtlsAt
			}
			perSec[r.dtlsAt.Unix()]++
		}
		if span := lastAt.Sub(first).Seconds(); span > 0 {
			hps = float64(len(okRes)) / span
		}
		for _, n := range perSec {
			if n > peak {
				peak = n
			}
		}
	}
	fmt.Printf("DTLS handshakes/s %.2f mean over the run, %d in the busiest second\n", hps, peak)
	if !c.noMedia {
		ratio := 0.0
		if sent > 0 {
			ratio = float64(recv) / float64(sent) * 100
		}
		fmt.Printf("media             sent=%d echoed=%d (%.2f%% returned) seq-gap-lost=%d (%.3f%%)\n", sent, recv, ratio, lost, pct64(lost, recv+lost))
		fmt.Printf("jitter (RFC3550)  mean=%.2f p99=%.2f ms (per-call final values)\n", meanDur(jit), ms(percentile(jit, 99)))
		fmt.Printf("RTT via SBC+echo  per-call p50s: %s\n", quantiles(rttAll))
	}
	if len(st.errKinds) > 0 {
		fmt.Println("errors:")
		keys := make([]string, 0, len(st.errKinds))
		for k := range st.errKinds {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %5d  %s\n", st.errKinds[k], k)
		}
	}
	// Machine-readable lines for run.sh.
	fmt.Printf("RESULT calls_attempted=%d calls_ok=%d calls_failed=%d failed_pct=%.3f\n", attempted, len(okRes), failed, pct(failed, attempted))
	fmt.Printf("RESULT reg_ok=%d reg_failed=%d reg_p95_ms=%.1f\n", len(st.regLat), st.regFail, ms(percentile(st.regLat, 95)))
	fmt.Printf("RESULT setup_p50_ms=%.1f setup_p95_ms=%.1f dtls_p95_ms=%.1f dtls_per_s=%.2f dtls_peak_per_s=%d\n",
		ms(percentile(setup, 50)), ms(percentile(setup, 95)), ms(percentile(dtlsL, 95)), hps, peak)
	if !c.noMedia {
		fmt.Printf("RESULT rtp_sent=%d rtp_echoed=%d seq_gap_lost=%d jitter_mean_ms=%.2f jitter_p99_ms=%.2f rtt_p50_ms=%.1f\n",
			sent, recv, lost, meanDur(jit), ms(percentile(jit, 99)), ms(percentile(rttAll, 50)))
	}
}

func meanDur(d []time.Duration) float64 {
	if len(d) == 0 {
		return 0
	}
	var s time.Duration
	for _, x := range d {
		s += x
	}
	return ms(s) / float64(len(d))
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

func pct64(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

func writeCSV(path string, rs []result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"start_unix", "user", "call_id", "reg_ms", "setup_ms", "ice_ms", "dtls_ms",
		"sent", "echoed", "seq_gap_lost", "jitter_ms", "rtt_p50_ms", "rtt_p99_ms", "error"})
	for _, r := range rs {
		_ = w.Write([]string{
			fmt.Sprintf("%.3f", float64(r.start.UnixNano())/1e9), r.user, r.callID,
			fmt.Sprintf("%.1f", r.regMs), fmt.Sprintf("%.1f", r.setupMs), fmt.Sprintf("%.1f", r.iceMs), fmt.Sprintf("%.1f", r.dtlsMs),
			fmt.Sprint(r.sent), fmt.Sprint(r.recv), fmt.Sprint(r.lostSeq),
			fmt.Sprintf("%.2f", r.jitterMs), fmt.Sprintf("%.1f", ms(r.rttP50)), fmt.Sprintf("%.1f", ms(r.rttP99)),
			strings.ReplaceAll(r.err, ",", ";"),
		})
	}
	w.Flush()
	return w.Error()
}
