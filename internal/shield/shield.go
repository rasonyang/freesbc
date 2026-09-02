package shield

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// Verdict is Shield.Check's decision.
type Verdict int

const (
	Allow Verdict = iota
	Drop
)

// Shield is FreeSBC's front-door security plane. It is consulted before peer
// identification on every inbound request; configured peers are exempt from
// the ban/scanner plane but still rate-limited (loosely, T-18/F-19), and
// every denial is a silent Drop. Params (rate limit, auto_ban) hot-reload from
// the config store per call; the nftables mode is fixed at construction.
type Shield struct {
	store       *config.Store
	log         *slog.Logger
	limiter     *rateLimiter // non-peer sources (shield.rate_limit)
	peerLimiter *rateLimiter // configured peers (shield.peer_rate_limit)
	bans        *banList
	counter     *failCounter

	// Cumulative drop counters by reason, for the admin API's metrics
	// snapshot (Stats). Incremented in Check at each of its three drop
	// points; read via Stats' atomic Load.
	dropsBanned  atomic.Int64
	dropsScanner atomic.Int64
	dropsRate    atomic.Int64

	// cached parse of the rate_limit string (re-parsed only when it changes).
	rlMu   sync.Mutex
	rlStr  string
	rlOpts config.RateLimit

	// cached parse of the peer_rate_limit string (same pattern).
	prlMu   sync.Mutex
	prlStr  string
	prlOpts config.RateLimit

	stop context.CancelFunc
	done chan struct{}
}

// New builds a Shield over store, installs the nftables backend from the
// current config's shield.nftables mode, and starts a background prune loop.
func New(store *config.Store, log *slog.Logger) *Shield {
	return newShield(store, log, true)
}

// NewNoKernel builds a Shield that bans in-process only, with no nftables
// backend. It exists for the edge proxy, whose public listeners are not in
// config.Listeners() — the list the kernel rules are derived from — so a
// second kernel-managing Shield would either write rules for the wrong
// ports or fight the trunk plane's Shield over the same nft table. The
// in-process ban list, rate limiter and scanner detection are identical;
// only the kernel-level enforcement is absent.
func NewNoKernel(store *config.Store, log *slog.Logger) *Shield {
	return newShield(store, log, false)
}

func newShield(store *config.Store, log *slog.Logger, kernel bool) *Shield {
	cfg := store.Current()
	bl := newBanList()
	if kernel {
		bl.nft = newNFTBackend(cfg.Shield.NFTables, cfg.Listeners(), log)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Shield{
		store:       store,
		log:         log,
		limiter:     newRateLimiter(),
		peerLimiter: newRateLimiter(),
		bans:        bl,
		counter:     newFailCounter(),
		stop:        cancel,
		done:        make(chan struct{}),
	}
	go s.pruneLoop(ctx)
	return s
}

// Check is the per-request gate (spec §3): configured peers are exempt from
// the ban/scanner plane but not from rate limiting — a separate, looser
// per-IP limit (shield.peer_rate_limit, T-18/F-19) caps them, since a
// spoofed peer source would otherwise have no rate ceiling at all (a real
// peer's legitimate load stays far below the threshold, so it never sees
// the limiter). For non-peers: a banned source and a rate-limit violation
// Drop; otherwise a scanner UA is dropped AND instantly banned — but only
// AFTER the rate limiter has had its say (T-04, F-03: the UA is a
// client-controlled "ban me" signal, so it must first burn through the
// source's rate budget like any other traffic, never skip the limiter).
// transport is the lowercased request transport ("udp"/"tcp"/"tls"/""): a
// single-packet scanner verdict only syncs to the kernel for
// connection-oriented transports (T-02, F-04 — see kernelSync).
func (s *Shield) Check(src netip.Addr, userAgent string, transport string) Verdict {
	cfg := s.store.Current()
	if isConfiguredPeer(cfg, src) {
		rl := s.peerRateLimit(cfg)
		if !s.peerLimiter.allow(src, rl.Rate, rl.Interval, rl.PerIP) {
			s.log.Debug("shield peer rate-limited", "source", src)
			s.dropsRate.Add(1)
			return Drop
		}
		return Allow
	}
	if s.bans.banned(src) {
		s.dropsBanned.Add(1)
		return Drop
	}
	rl := s.rateLimit(cfg)
	if !s.limiter.allow(src, rl.Rate, rl.Interval, rl.PerIP) {
		s.log.Debug("shield rate-limited", "source", src)
		s.dropsRate.Add(1)
		return Drop
	}
	if isScanner(userAgent) {
		if !s.bans.ban(src, cfg.Shield.AutoBan.Duration.Std(), kernelSync(transport)) {
			s.log.Debug("shield ban table at hard cap; scanner ban refused", "source", src, "ua", userAgent)
		} else {
			s.log.Warn("shield banned scanner", "source", src, "ua", userAgent)
		}
		s.dropsScanner.Add(1)
		return Drop
	}
	return Allow
}

// kernelSync reports whether a single-packet scanner ban from this
// transport may sync to nftables: only connection-oriented transports
// (tcp/tls) qualify. A UDP verdict rests on one forgable datagram, so it
// stays memory-only — a spoofed packet must not be able to kernel-blackhole
// a victim's IP (T-02, F-04). Multi-packet auto-bans (RecordUnidentified)
// sync regardless of transport.
func kernelSync(transport string) bool {
	t := strings.ToLower(transport)
	return t == "tcp" || t == "tls"
}

// Stats is a snapshot of shield activity for metrics.
type Stats struct {
	BannedCurrent int
	// BanAddsRejected counts ban additions refused at the ban table's hard
	// cap (T-03) — an indicator that a source flood is exhausting the table.
	BanAddsRejected int64
	DropsByReason   map[string]int64
}

// Stats returns a snapshot of current bans and cumulative drops by reason.
func (s *Shield) Stats() Stats {
	return Stats{
		BannedCurrent:   s.bans.size(),
		BanAddsRejected: s.bans.overflowed(),
		DropsByReason: map[string]int64{
			"banned":  s.dropsBanned.Load(),
			"scanner": s.dropsScanner.Load(),
			"rate":    s.dropsRate.Load(),
		},
	}
}

// RecordUnidentified counts an unidentified-source request; the Nth within the
// window bans the source (spec §3).
func (s *Shield) RecordUnidentified(src netip.Addr) {
	cfg := s.store.Current()
	if isConfiguredPeer(cfg, src) {
		return // defensive: exempt peers never counted
	}
	n := s.counter.record(src, cfg.Shield.AutoBan.Window.Std())
	if n >= cfg.Shield.AutoBan.Failures {
		// Auto-ban is a multi-packet verdict (N failures within the window),
		// so the kernel sync is allowed on any transport — see kernelSync.
		if !s.bans.ban(src, cfg.Shield.AutoBan.Duration.Std(), true) {
			s.log.Debug("shield ban table at hard cap; auto-ban refused", "source", src, "failures", n)
			return
		}
		s.log.Warn("shield auto-banned source", "source", src, "failures", n, "duration", cfg.Shield.AutoBan.Duration.Std())
	}
}

// Unban removes any ban on ip — from the in-memory table and, best-effort,
// the kernel set — and reports whether a ban existed (T-02, F-04: the admin
// API's DELETE /api/bans/{ip} calls this). The kernel delete runs
// synchronously via nftBackend.unban rather than through the worker queue,
// so an operator unban takes effect even while the queue is saturated.
func (s *Shield) Unban(ip netip.Addr) bool {
	existed := s.bans.unban(ip)
	if s.bans.nft != nil {
		s.bans.nft.unban(ip)
	}
	return existed
}

// Close stops the prune loop and tears down the nftables ruleset.
func (s *Shield) Close() error {
	s.stop()
	<-s.done
	if s.bans.nft != nil {
		return s.bans.nft.close()
	}
	return nil
}

func (s *Shield) rateLimit(cfg *config.Config) config.RateLimit {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	if cfg.Shield.RateLimit != s.rlStr {
		if rl, err := config.ParseRateLimit(cfg.Shield.RateLimit); err == nil {
			s.rlOpts = rl
			s.rlStr = cfg.Shield.RateLimit
		}
	}
	return s.rlOpts
}

// peerRateLimit is rateLimit's counterpart for the peer limiter (T-18).
func (s *Shield) peerRateLimit(cfg *config.Config) config.RateLimit {
	s.prlMu.Lock()
	defer s.prlMu.Unlock()
	if cfg.Shield.PeerRateLimit != s.prlStr {
		if rl, err := config.ParseRateLimit(cfg.Shield.PeerRateLimit); err == nil {
			s.prlOpts = rl
			s.prlStr = cfg.Shield.PeerRateLimit
		}
	}
	return s.prlOpts
}

func (s *Shield) pruneLoop(ctx context.Context) {
	defer close(s.done)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.limiter.prune()
			s.peerLimiter.prune()
			s.bans.prune()
			s.counter.prune(s.store.Current().Shield.AutoBan.Window.Std())
		}
	}
}

// isConfiguredPeer reports whether src matches any peer's allowed_ips.
func isConfiguredPeer(cfg *config.Config, src netip.Addr) bool {
	for _, p := range cfg.Peers {
		if p.AllowsIP(src) {
			return true
		}
	}
	return false
}

// failCounter is a per-IP sliding-window count of unidentified-source hits.
type failCounter struct {
	mu   sync.Mutex
	hits map[netip.Addr][]time.Time
	now  func() time.Time
}

func newFailCounter() *failCounter {
	return &failCounter{hits: make(map[netip.Addr][]time.Time), now: time.Now}
}

// record adds a hit for src and returns the number of hits within window.
func (c *failCounter) record(src netip.Addr, window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	cutoff := now.Add(-window)
	kept := c.hits[src][:0]
	for _, t := range c.hits[src] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	c.hits[src] = kept
	return len(kept)
}

// prune drops IPs whose most recent hit has aged out of the window.
func (c *failCounter) prune(window time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := c.now().Add(-window)
	for ip, hits := range c.hits {
		if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
			delete(c.hits, ip)
		}
	}
}
