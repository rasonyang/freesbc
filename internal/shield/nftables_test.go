package shield

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// recordedCmds is a mutex-guarded record of exec argv strings: the nft
// worker goroutine appends while tests read, hence the lock.
type recordedCmds struct {
	mu   sync.Mutex
	cmds []string
}

func (r *recordedCmds) add(s string) {
	r.mu.Lock()
	r.cmds = append(r.cmds, s)
	r.mu.Unlock()
}

func (r *recordedCmds) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cmds)
}

func (r *recordedCmds) joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.cmds, "\n")
}

// newTestNFT builds an nftBackend with a recording exec func and a running
// worker, bypassing availability detection (so tests run on any OS). The
// default listens (udp:5060) let tests that don't care about rule scoping
// call setup without extra plumbing.
func newTestNFT(t *testing.T) (*nftBackend, *recordedCmds) {
	t.Helper()
	rec := &recordedCmds{}
	n := &nftBackend{
		log:     discard(),
		listens: []config.SIPListen{{Transport: "udp", Port: 5060}},
		run: func(ctx context.Context, args ...string) error {
			rec.add(strings.Join(args, " "))
			return nil
		},
	}
	n.start()
	t.Cleanup(func() { n.stopWorker() })
	return n, rec
}

// TestNFTBanRulesScopedToSIPPorts is the T-02 (F-04) red test: the kernel
// drop rules must match only udp/tcp traffic toward configured SIP listen
// ports — a banned source must not be blanket-blackholed for everything on
// the box.
func TestNFTBanRulesScopedToSIPPorts(t *testing.T) {
	n, rec := newTestNFT(t)
	n.listens = []config.SIPListen{
		{Transport: "udp", Port: 5060},
		{Transport: "tcp", Port: 5060},
		{Transport: "tls", Port: 5061}, // tls rides tcp at the kernel layer
	}
	if err := n.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	joined := rec.joined()
	if !strings.Contains(joined, "ip saddr @banned4 udp dport { 5060 } drop") {
		t.Errorf("v4 udp rule not scoped to the SIP port:\n%s", joined)
	}
	if !strings.Contains(joined, "ip saddr @banned4 tcp dport { 5060, 5061 } drop") {
		t.Errorf("v4 tcp rule not scoped to the SIP ports (5060+5061 incl. tls):\n%s", joined)
	}
	if !strings.Contains(joined, "ip6 saddr @banned6 udp dport { 5060 } drop") {
		t.Errorf("v6 udp rule not scoped to the SIP port:\n%s", joined)
	}
	if strings.Contains(joined, "saddr @banned4 drop") {
		t.Errorf("unscoped (no dport) drop rule remains:\n%s", joined)
	}
}

// waitForRecords polls until the worker has executed at least n run calls.
func waitForRecords(t *testing.T, rec *recordedCmds, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rec.count() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("worker executed %d nft calls, want >= %d", rec.count(), n)
}

func TestNFTBanArgv(t *testing.T) {
	n, rec := newTestNFT(t)
	n.ban(netip.MustParseAddr("203.0.113.7"), time.Hour)
	n.ban(netip.MustParseAddr("2001:db8::1"), 30*time.Minute)
	waitForRecords(t, rec, 2) // bans are processed by the async worker
	joined := rec.joined()
	if !strings.Contains(joined, "add element inet freesbc banned4 { 203.0.113.7 timeout 3600s }") {
		t.Errorf("v4 ban argv wrong:\n%s", joined)
	}
	if !strings.Contains(joined, "add element inet freesbc banned6 { 2001:db8::1 timeout 1800s }") {
		t.Errorf("v6 ban argv wrong:\n%s", joined)
	}
}

func TestNFTCloseTearsDown(t *testing.T) {
	n, rec := newTestNFT(t)
	if err := n.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// close stops the worker first, then runs the table delete directly —
	// so the recording is complete by the time it returns.
	if got := rec.joined(); got != "delete table inet freesbc" {
		t.Errorf("close should delete the table (and nothing else), got %q", got)
	}
}

func TestNFTModeOffReturnsNil(t *testing.T) {
	if n := newNFTBackend("off", nil, discard()); n != nil {
		t.Fatal("mode off → nil backend")
	}
}

// TestNFTExecBoundedAndSerialized is the T-04 (F-03) red test: a concurrent
// flood of bans must never translate into a concurrent flood of fork+exec —
// the single worker serializes them (max concurrency 1), and the bounded
// queue drops the overflow (in-memory bans remain authoritative).
func TestNFTExecBoundedAndSerialized(t *testing.T) {
	var (
		mu          sync.Mutex
		records     int
		inflight    atomic.Int64
		maxInflight atomic.Int64
	)
	n := &nftBackend{
		log: discard(),
		run: func(ctx context.Context, args ...string) error {
			cur := inflight.Add(1)
			for {
				max := maxInflight.Load()
				if cur <= max || maxInflight.CompareAndSwap(max, cur) {
					break
				}
			}
			// Slow enough that the 1000-goroutine flood finishes enqueueing
			// while the worker is still on its first item — the queue bound,
			// not the flood's end, is what stops the enqueues.
			time.Sleep(10 * time.Millisecond)
			inflight.Add(-1)
			mu.Lock()
			records++
			mu.Unlock()
			return nil
		},
	}
	n.start()
	defer n.stopWorker()

	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n.ban(capIP(i), time.Hour)
		}(i)
	}
	wg.Wait()

	// At most nftBanQCap+1 bans can be in flight at once (1 being exec'd +
	// the queue full); a couple more may slip in when the worker frees a
	// slot while the flood is still enqueueing — hence the small slack.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		nRec := records
		mu.Unlock()
		if nRec >= nftBanQCap {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // let the worker drain the queue
	mu.Lock()
	final := records
	mu.Unlock()

	if final < nftBanQCap {
		t.Fatalf("executed %d nft bans, want >= %d — the flood never overran the queue, test is vacuous", final, nftBanQCap)
	}
	if final > nftBanQCap+4 {
		t.Fatalf("executed %d nft bans, want <= %d (queue bound + in-flight + slack) — bounded queue not enforced", final, nftBanQCap+4)
	}
	if got := maxInflight.Load(); got != 1 {
		t.Fatalf("max concurrent nft execs = %d, want 1 (single serial worker)", got)
	}
}
