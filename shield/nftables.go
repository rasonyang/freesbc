package shield

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strconv"
	"time"
)

// nftBackend drops banned sources at the kernel via the `nft` binary. It is a
// best-effort accelerator layered on the always-present in-memory ban table:
// any failure is logged and swallowed, never breaking banning or the SBC. All
// nft invocations go through run (injectable for tests).
type nftBackend struct {
	log *slog.Logger
	run func(args ...string) error
}

// newNFTBackend builds a backend for the given mode, or nil when nftables is
// disabled or unavailable:
//   - off  → nil (never touch nft).
//   - on   → require nft; if unavailable/setup fails, log an error and return
//     nil (in-process banning still applies).
//   - auto → use nft only when the binary is present and setup succeeds; else
//     nil, silently.
func newNFTBackend(mode string, log *slog.Logger) *nftBackend {
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
	n := &nftBackend{log: log, run: func(args ...string) error {
		return exec.Command(path, args...).Run()
	}}
	if err := n.setup(); err != nil {
		if mode == "on" {
			log.Error("nftables setup failed; falling back to in-process bans only", "err", err)
		}
		return nil
	}
	return n
}

// setup installs the managed ruleset: a dedicated table, two timeout sets
// (v4/v6), and an input-hook chain that drops sources in either set.
func (n *nftBackend) setup() error {
	// Best-effort clean slate, then build. A pre-existing table (unclean prior
	// shutdown) is deleted first; its absence is not an error we surface.
	_ = n.run("delete", "table", "inet", "freesbc")
	cmds := [][]string{
		{"add", "table", "inet", "freesbc"},
		{"add", "set", "inet", "freesbc", "banned4", "{", "type", "ipv4_addr;", "flags", "timeout;", "}"},
		{"add", "set", "inet", "freesbc", "banned6", "{", "type", "ipv6_addr;", "flags", "timeout;", "}"},
		{"add", "chain", "inet", "freesbc", "input", "{", "type", "filter", "hook", "input", "priority", "-1;", "}"},
		{"add", "rule", "inet", "freesbc", "input", "ip", "saddr", "@banned4", "drop"},
		{"add", "rule", "inet", "freesbc", "input", "ip6", "saddr", "@banned6", "drop"},
	}
	for _, c := range cmds {
		if err := n.run(c...); err != nil {
			return fmt.Errorf("nft %v: %w", c, err)
		}
	}
	return nil
}

// ban installs a kernel drop for ip with a timeout matching the in-memory ban,
// so the kernel expires it in step. Failures are logged and swallowed.
func (n *nftBackend) ban(ip netip.Addr, dur time.Duration) {
	set := "banned4"
	if ip.Is6() {
		set = "banned6"
	}
	timeout := strconv.Itoa(int(dur.Seconds())) + "s"
	elem := "{ " + ip.String() + " timeout " + timeout + " }"
	if err := n.run("add", "element", "inet", "freesbc", set, elem); err != nil {
		n.log.Debug("nft ban element failed", "ip", ip, "err", err)
	}
}

// close removes the managed ruleset entirely.
func (n *nftBackend) close() error {
	return n.run("delete", "table", "inet", "freesbc")
}
