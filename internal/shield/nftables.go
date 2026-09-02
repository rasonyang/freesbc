package shield

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// nftBanQCap bounds the pending kernel-sync queue (T-04, F-03): a ban storm
// (e.g. unique-source auto-ban flood) must not translate into an unbounded
// pile of pending fork+execs. When the queue is full the kernel sync for
// that ban is dropped — the in-memory ban table stays authoritative either
// way, and the kernel copy is a best-effort accelerator.
const nftBanQCap = 256

// nftExecTimeout bounds every nft invocation: a wedged nft binary must not
// stall the worker (or startup/shutdown) forever.
const nftExecTimeout = 2 * time.Second

// nftBanReq is one pending kernel-sync ban.
type nftBanReq struct {
	ip  netip.Addr
	dur time.Duration
}

// nftBackend drops banned sources at the kernel via the `nft` binary. It is a
// best-effort accelerator layered on the always-present in-memory ban table:
// any failure is logged and swallowed, never breaking banning or the SBC. All
// nft invocations go through run (injectable for tests).
//
// Since T-04, bans are applied by a single worker goroutine consuming a
// bounded queue: execs are serialized (one fork+exec at a time) and the
// queue caps how many may pile up — see ban.
type nftBackend struct {
	log *slog.Logger
	run func(ctx context.Context, args ...string) error

	// listens are the SIP listeners the setup rules are scoped to (T-02,
	// F-04): the kernel drop rules match only udp/tcp traffic toward these
	// ports. Captured at construction; hot-reloaded listen changes don't
	// rebuild the rules (same fixed-at-construction caveat as the nftables
	// mode itself).
	listens []config.SIPListen

	// Worker plumbing, initialized by start.
	queue chan nftBanReq
	stop  context.CancelFunc
	done  chan struct{}
}

// newNFTBackend builds a backend for the given mode, or nil when nftables is
// disabled or unavailable:
//   - off  → nil (never touch nft).
//   - on   → require nft; if unavailable/setup fails, log an error and return
//     nil (in-process banning still applies).
//   - auto → use nft only when the binary is present and setup succeeds; else
//     nil, silently.
func newNFTBackend(mode string, listens []config.SIPListen, log *slog.Logger) *nftBackend {
	if mode == "off" {
		return nil
	}
	path, err := exec.LookPath("nft")
	if err != nil {
		if mode == "on" {
			log.Error("nftables mode is 'on' but the nft binary was not found; falling back to in-process bans only")
		}
		return nil
	}
	n := &nftBackend{log: log, listens: listens, run: func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, path, args...).Run()
	}}
	if err := n.setup(); err != nil {
		if mode == "on" {
			log.Error("nftables setup failed; falling back to in-process bans only", "err", err)
		}
		return nil
	}
	n.start()
	return n
}

// start spawns the single ban worker. Called once, after setup, before the
// backend is handed out.
func (n *nftBackend) start() {
	ctx, cancel := context.WithCancel(context.Background())
	n.queue = make(chan nftBanReq, nftBanQCap)
	n.stop = cancel
	n.done = make(chan struct{})
	go n.worker(ctx)
}

// worker serially drains the ban queue: exactly one nft exec runs at a time
// (T-04). On stop it drops whatever is still queued — a shutting-down shield
// tears the whole ruleset down anyway (see close).
func (n *nftBackend) worker(ctx context.Context) {
	defer close(n.done)
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-n.queue:
			n.execBan(ctx, r.ip, r.dur)
		}
	}
}

// stopWorker cancels the worker and waits for it to exit (idempotent: a
// second call returns immediately on the already-closed done channel).
func (n *nftBackend) stopWorker() {
	if n.stop == nil {
		return
	}
	n.stop()
	<-n.done
}

// setup installs the managed ruleset: a dedicated table, two timeout sets
// (v4/v6), and an input-hook chain whose drop rules are scoped (T-02, F-04)
// to udp/tcp traffic toward the configured SIP listener ports — a banned
// source is never blanket-blackholed for everything on the box. If no udp
// or tcp/tls listeners are configured, no drop rules are installed at all
// (in-memory bans still apply; the kernel accelerator just has nothing to
// match on).
func (n *nftBackend) setup() error {
	// Best-effort clean slate, then build. A pre-existing table (unclean prior
	// shutdown) is deleted first; its absence is not an error we surface.
	_ = n.execWithTimeout(context.Background(), "delete", "table", "inet", "freesbc")
	cmds := [][]string{
		{"add", "table", "inet", "freesbc"},
		{"add", "set", "inet", "freesbc", "banned4", "{", "type", "ipv4_addr;", "flags", "timeout;", "}"},
		{"add", "set", "inet", "freesbc", "banned6", "{", "type", "ipv6_addr;", "flags", "timeout;", "}"},
		{"add", "chain", "inet", "freesbc", "input", "{", "type", "filter", "hook", "input", "priority", "-1;", "}"},
	}

	var udpPorts, tcpPorts []int
	seenUDP, seenTCP := map[int]bool{}, map[int]bool{}
	for _, l := range n.listens {
		switch l.Transport {
		case "udp":
			if !seenUDP[l.Port] {
				seenUDP[l.Port] = true
				udpPorts = append(udpPorts, l.Port)
			}
		case "tcp", "tls": // tls rides tcp at the kernel layer
			if !seenTCP[l.Port] {
				seenTCP[l.Port] = true
				tcpPorts = append(tcpPorts, l.Port)
			}
		}
	}
	sort.Ints(udpPorts)
	sort.Ints(tcpPorts)
	if len(udpPorts) > 0 {
		cmds = append(cmds,
			[]string{"add", "rule", "inet", "freesbc", "input", "ip", "saddr", "@banned4", "udp", "dport", portSet(udpPorts), "drop"},
			[]string{"add", "rule", "inet", "freesbc", "input", "ip6", "saddr", "@banned6", "udp", "dport", portSet(udpPorts), "drop"},
		)
	}
	if len(tcpPorts) > 0 {
		cmds = append(cmds,
			[]string{"add", "rule", "inet", "freesbc", "input", "ip", "saddr", "@banned4", "tcp", "dport", portSet(tcpPorts), "drop"},
			[]string{"add", "rule", "inet", "freesbc", "input", "ip6", "saddr", "@banned6", "tcp", "dport", portSet(tcpPorts), "drop"},
		)
	}
	for _, c := range cmds {
		if err := n.execWithTimeout(context.Background(), c...); err != nil {
			return fmt.Errorf("nft %v: %w", c, err)
		}
	}
	return nil
}

// portSet renders an nft port set literal, e.g. "{ 5060, 5061 }".
func portSet(ports []int) string {
	ss := make([]string, len(ports))
	for i, p := range ports {
		ss[i] = strconv.Itoa(p)
	}
	return "{ " + strings.Join(ss, ", ") + " }"
}

// ban enqueues a kernel drop for ip with a timeout matching the in-memory
// ban, so the kernel expires it in step. The enqueue never blocks: at a
// full queue the kernel sync is dropped (the in-memory ban still applies)
// and counted in the log only.
func (n *nftBackend) ban(ip netip.Addr, dur time.Duration) {
	if n.queue == nil {
		return // defensive: backend never started
	}
	select {
	case n.queue <- nftBanReq{ip: ip, dur: dur}:
	default:
		n.log.Debug("nft ban queue full; kernel sync dropped (in-memory ban still applies)", "ip", ip)
	}
}

// execBan runs the worker-side element add. Failures are logged and
// swallowed.
func (n *nftBackend) execBan(ctx context.Context, ip netip.Addr, dur time.Duration) {
	set := "banned4"
	if ip.Is6() {
		set = "banned6"
	}
	timeout := strconv.Itoa(int(dur.Seconds())) + "s"
	elem := "{ " + ip.String() + " timeout " + timeout + " }"
	if err := n.execWithTimeout(ctx, "add", "element", "inet", "freesbc", set, elem); err != nil {
		n.log.Debug("nft ban element failed", "ip", ip, "err", err)
	}
}

// execWithTimeout runs args under nftExecTimeout so a wedged nft binary
// can't stall its caller indefinitely.
func (n *nftBackend) execWithTimeout(ctx context.Context, args ...string) error {
	execCtx, cancel := context.WithTimeout(ctx, nftExecTimeout)
	defer cancel()
	return n.run(execCtx, args...)
}

// unban removes the kernel element for ip directly — not via the worker
// queue: an operator unban is rare and must take effect even when the queue
// is full, since a dropped delete would leave the kernel blackholing a
// source the in-memory table has already forgotten (T-02, F-04).
func (n *nftBackend) unban(ip netip.Addr) {
	set := "banned4"
	if ip.Is6() {
		set = "banned6"
	}
	if err := n.execWithTimeout(context.Background(), "delete", "element", "inet", "freesbc", set, "{ "+ip.String()+" }"); err != nil {
		n.log.Debug("nft unban element failed", "ip", ip, "err", err)
	}
}

// close stops the worker and removes the managed ruleset entirely.
func (n *nftBackend) close() error {
	n.stopWorker()
	return n.execWithTimeout(context.Background(), "delete", "table", "inet", "freesbc")
}
