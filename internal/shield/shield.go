package shield

import (
	"context"
	"log/slog"
	"net/netip"
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
// the ban/scanner plane but still rate-limited (loosely), and
// every denial is a silent Drop. Params (rate limit, auto_ban) hot-reload from
// the config store per call. Bans live in process memory only.
type Shield struct {
	store       *config.Store
	log         *slog.Logger
	limiter     *rateLimiter // non-peer sources (shield.rate_limit)
	peerLimiter *rateLimiter // configured peers (shield.peer_rate_limit)
	bans        *banList

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

// New builds the trunk plane's Shield over store and starts a background
// prune loop.
func New(store *config.Store, log *slog.Logger) *Shield {
	return newShield(store, log)
}

// NewNoKernel builds the edge plane's Shield. The name predates the removal
// of the nftables backend (every Shield now bans in process memory only);
// it is kept as the edge plane's constructor.
func NewNoKernel(store *config.Store, log *slog.Logger) *Shield {
	return newShield(store, log)
}

func newShield(store *config.Store, log *slog.Logger) *Shield {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Shield{
		store:       store,
		log:         log,
		limiter:     newRateLimiter(),
		peerLimiter: newRateLimiter(),
		bans:        newBanList(),
		stop:        cancel,
		done:        make(chan struct{}),
	}
	go s.pruneLoop(ctx)
	return s
}

// Check is the per-request gate (spec §3): configured peers are exempt from
// the ban/scanner plane but not from rate limiting — a separate, looser
// per-IP limit (shield.peer_rate_limit) caps them, since a
// spoofed peer source would otherwise have no rate ceiling at all (a real
// peer's legitimate load stays far below the threshold, so it never sees
// the limiter). For non-peers: a banned source and a rate-limit violation
// Drop; otherwise a scanner UA is dropped AND instantly banned — but only
// AFTER the rate limiter has had its say (the UA is a
// client-controlled "ban me" signal, so it must first burn through the
// source's rate budget like any other traffic, never skip the limiter).
// transport is the lowercased request transport ("udp"/"tcp"/"tls"/"ws"/
// "wss"/"").
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
		if !s.bans.ban(src, cfg.Shield.AutoBan.Duration.Std()) {
			s.log.Debug("shield ban table at hard cap; scanner ban refused", "source", src, "ua", userAgent)
		} else {
			s.log.Warn("shield banned scanner", "source", src, "ua", userAgent)
		}
		s.dropsScanner.Add(1)
		return Drop
	}
	return Allow
}

// Stats is a snapshot of shield activity for metrics.
type Stats struct {
	BannedCurrent int
	// BanAddsRejected counts ban additions refused at the ban table's hard
	// cap — an indicator that a source flood is exhausting the table.
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

// Unban removes any ban on ip and reports whether a ban existed (the admin
// API's DELETE /api/bans/{ip} calls this).
func (s *Shield) Unban(ip netip.Addr) bool {
	return s.bans.unban(ip)
}

// Close stops the prune loop.
func (s *Shield) Close() error {
	s.stop()
	<-s.done
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

// peerRateLimit is rateLimit's counterpart for the peer limiter.
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
