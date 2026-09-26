package trunk

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

// Long-running soak for the trunk plane. It reuses the resource-balance
// harness (audit_resource_test.go) and places calls in rounds for
// FREESBC_SOAK (a time.Duration such as "30m"); without it the test skips,
// so a plain `go test ./...` never runs it. The nightly CI workflow
// (.github/workflows/soak.yml) sets it.
//
// After every round it asserts the per-call invariants (pool, call store,
// carrier dialogs back to zero). Goroutines are checked only at the end,
// since sipgo's transaction timers (Timer J, ~32 s) outlive a round. Across the whole run it asserts that the
// goroutine count settles to its warm baseline, that open file descriptors
// (Linux /proc/self/fd) do not grow, and that the live heap after GC does
// not grow beyond soakHeapSlack over the heap measured once the first
// rounds are done. A leak of one socket, goroutine or dialog record per
// call shows up here long before it would in the short suite.
//
// Ports: SIP 13800-13801, media 13900-13999 (inside the trunk band).

const (
	soakCallsPerRound = 8
	soakWarmRounds    = 5
	soakHeapSlack     = 16 << 20 // bytes of live-heap growth tolerated
	soakFDSlack       = 8
)

func TestSoakTrunkCalls(t *testing.T) {
	v := os.Getenv("FREESBC_SOAK")
	if v == "" {
		t.Skip("set FREESBC_SOAK=<duration> (e.g. 10m) to run the trunk soak")
	}
	dur, err := time.ParseDuration(v)
	if err != nil || dur <= 0 {
		t.Fatalf("FREESBC_SOAK=%q: want a positive duration such as 10m", v)
	}

	carrier := auditStartCarrier(t, "127.0.0.1:13801", 0)
	as := auditStartServer(t, auditTrunkCfg(13800, 13801, 13900, 13999, ""))
	baseline := auditWarmBaseline(t, 13800, "soak")

	var (
		heapWarm, heapPeak uint64
		fdWarm                   = openFDs()
		fdPeak                   = fdWarm
		calls              int64 = 1 // the warm-up call
		rounds             int
		start              = time.Now()
	)
	for time.Since(start) < dur && !t.Failed() {
		uacs := auditEstablishN(t, 13800, fmt.Sprintf("soak-r%d", rounds), soakCallsPerRound)
		waitForActiveCalls(t, as.srv, soakCallsPerRound, 3*time.Second)
		for _, u := range uacs {
			u.hangup()
		}
		calls += soakCallsPerRound
		auditBalance{srv: as.srv, carrier: carrier, wantByes: calls, uacs: uacs}.assertCounters(t)
		// The callers' sockets would otherwise stay open until t.Cleanup.
		for _, u := range uacs {
			u.conn.Close()
		}
		rounds++

		heap := liveHeap()
		fds := openFDs()
		if rounds == soakWarmRounds {
			heapWarm, fdWarm = heap, fds
		}
		heapPeak = max(heapPeak, heap)
		fdPeak = max(fdPeak, fds)
		if rounds%50 == 0 {
			t.Logf("soak: %v, %d rounds, %d calls, heap %d KiB, goroutines %d, fds %d",
				time.Since(start).Round(time.Second), rounds, calls, heap>>10, runtime.NumGoroutine(), fds)
		}
	}
	if t.Failed() {
		return
	}
	if rounds <= soakWarmRounds {
		t.Fatalf("only %d rounds in %v; raise FREESBC_SOAK", rounds, dur)
	}

	// End-of-run checks, after the last calls' sipgo timers have expired.
	if n, stacks := auditGoroutinesSettle(baseline, 40*time.Second); stacks != "" {
		t.Errorf("goroutines = %d after soak, baseline %d; by top frame:\n%s", n, baseline, stacks)
	}
	heapEnd := liveHeap()
	if heapEnd > heapWarm+soakHeapSlack {
		t.Errorf("live heap grew from %d KiB (after round %d) to %d KiB after %d calls (peak %d KiB)",
			heapWarm>>10, soakWarmRounds, heapEnd>>10, calls, heapPeak>>10)
	}
	if fdWarm >= 0 {
		if fdEnd := openFDs(); fdEnd > fdWarm+soakFDSlack {
			t.Errorf("open fds grew from %d to %d after %d calls (peak %d)", fdWarm, fdEnd, calls, fdPeak)
		}
	}
	t.Logf("soak done: %v, %d rounds, %d calls, heap %d→%d KiB (peak %d), fds %d→%d",
		time.Since(start).Round(time.Second), rounds, calls, heapWarm>>10, heapEnd>>10, heapPeak>>10,
		fdWarm, openFDs())
}

// liveHeap returns HeapAlloc after a forced collection.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// openFDs counts this process's open file descriptors, or -1 where
// /proc/self/fd does not exist (macOS).
func openFDs() int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(ents)
}
