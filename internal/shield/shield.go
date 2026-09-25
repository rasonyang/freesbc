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
// identification on every inbound request. On the trunk plane configured
// peers are exempt from the ban/scanner plane but still rate-limited
// (loosely); the edge plane has no peers and exempts nobody. Every denial is
// a silent Drop. Params (rate limit, auto_ban) hot-reload from
// the config store per call. Bans live in process memory only.
type Shield struct {
	store       *config.Store
	log         *slog.Logger
	limiter     *rateLimiter             // non-peer sources (shield.rate_limit)
	peerLimiter *rateLimiter             // configured peers (shield.peer_rate_limit)
	bans        *banList[netip.Addr]     // source IPs (connection-oriented verdicts)
	socketBans  *banList[netip.AddrPort] // UDP source sockets (see CheckFrom)

	// exemptPeers is the plane's exemption predicate: true on the trunk
	// plane, whose peers are the config's peers; false on the edge plane,
	// where a source inside a trunk peer's allowed_ips is an ordinary
	// public client (P2-SHD-005).
	exemptPeers bool

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
// prune loop. Configured peers are exempt from its ban and scanner checks.
func New(store *config.Store, log *slog.Logger) *Shield {
	return newShield(store, log, true)
}

// NewNoKernel builds the edge plane's Shield: no source is exempt (the
// edge's trusted private plane bypasses the shield before calling it). The
// name predates the removal of the nftables backend (every Shield now bans
// in process memory only); it is kept as the edge plane's constructor.
func NewNoKernel(store *config.Store, log *slog.Logger) *Shield {
	return newShield(store, log, false)
}

func newShield(store *config.Store, log *slog.Logger, exemptPeers bool) *Shield {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Shield{
		store:       store,
		log:         log,
		limiter:     newRateLimiter(),
		peerLimiter: newRateLimiter(),
		bans:        newBanList(),
		socketBans:  newBanTable[netip.AddrPort](),
		exemptPeers: exemptPeers,
		stop:        cancel,
		done:        make(chan struct{}),
	}
	go s.pruneLoop(ctx)
	return s
}

// Check is the per-request gate (spec §3): on the trunk plane, configured
// peers are exempt from the ban/scanner plane but not from rate limiting — a separate, looser
// per-IP limit (shield.peer_rate_limit) caps them, since a
// spoofed peer source would otherwise have no rate ceiling at all (a real
// peer's legitimate load stays far below the threshold, so it never sees
// the limiter). For non-peers: a banned source and a rate-limit violation
// Drop; otherwise a scanner UA is dropped, and instantly banned when it
// arrived over a connection-oriented transport (see bannableTransport) — but
// only AFTER the rate limiter has had its say (the UA is a
// client-controlled "ban me" signal, so it must first burn through the
// source's rate budget like any other traffic, never skip the limiter).
// transport is the request transport ("udp"/"tcp"/"tls"/"ws"/"wss"/"";
// case-insensitive).
//
// Check knows only the source IP, so a scanner datagram is dropped without
// any ban; CheckFrom, which also knows the source port, bans the socket.
func (s *Shield) Check(src netip.Addr, userAgent string, transport string) Verdict {
	return s.CheckFrom(netip.AddrPortFrom(src, 0), userAgent, transport)
}

// socketBanMax caps how long a UDP scanner verdict bans its source socket.
// The verdict rests on one forgeable datagram, so the ban is kept short: a
// real scanner that keeps sending from the socket re-arms it, while a
// forged datagram naming a victim's socket silences that socket briefly
// and never the rest of its IP.
const socketBanMax = time.Minute

// CheckFrom is Check with the source port. A scanner verdict on UDP bans
// only the exact source socket (IP and port), for at most socketBanMax, in
// a table separate from the IP bans; a port of 0 means unknown and bans
// nothing.
func (s *Shield) CheckFrom(srcAP netip.AddrPort, userAgent string, transport string) Verdict {
	srcAP = netip.AddrPortFrom(srcAP.Addr().Unmap(), srcAP.Port())
	src := srcAP.Addr()
	cfg := s.store.Current()
	if s.exemptPeers && isConfiguredPeer(cfg, src) {
		rl := s.peerRateLimit(cfg)
		if !s.peerLimiter.allow(src, rl.Rate, rl.Interval, rl.PerIP) {
			s.log.Debug("shield peer rate-limited", "source", src)
			s.dropsRate.Add(1)
			return Drop
		}
		return Allow
	}
	if s.BannedFrom(srcAP, transport) {
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
		s.dropsScanner.Add(1)
		if !bannableTransport(transport) {
			// A datagram's source address is forgeable: an IP ban would let
			// one spoofed packet lock a third party out, and a spoofed flood
			// fill the IP table. Ban the socket instead, briefly.
			if isUDP(transport) && srcAP.Port() != 0 {
				s.socketBans.ban(srcAP, min(cfg.Shield.AutoBan.Duration.Std(), socketBanMax))
			}
			s.log.Debug("shield dropped scanner datagram", "source", srcAP, "ua", userAgent)
			return Drop
		}
		if !s.bans.ban(src, cfg.Shield.AutoBan.Duration.Std()) {
			s.log.Debug("shield ban table at hard cap; scanner ban refused", "source", src, "ua", userAgent)
		} else {
			s.log.Warn("shield banned scanner", "source", src, "ua", userAgent)
		}
		return Drop
	}
	return Allow
}

// bannableTransport reports whether a scanner verdict on this transport may
// ban its source. Only connection-oriented transports qualify: their source
// address survived a handshake, so it is not forged. UDP, and an unknown or
// empty transport, get a drop without a ban.
func bannableTransport(transport string) bool {
	switch strings.ToLower(transport) {
	case "tcp", "tls", "ws", "wss":
		return true
	}
	return false
}

func isUDP(transport string) bool { return strings.EqualFold(transport, "udp") }

// BannedFrom reports whether the source is banned: its IP, or on UDP its
// exact socket. Like Banned it counts nothing, so a read filter can call it.
func (s *Shield) BannedFrom(src netip.AddrPort, transport string) bool {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	if s.bans.banned(src.Addr()) {
		return true
	}
	return isUDP(transport) && src.Port() != 0 && s.socketBans.banned(src)
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
		BannedCurrent:   s.bans.size() + s.socketBans.size(),
		BanAddsRejected: s.bans.overflowed() + s.socketBans.overflowed(),
		DropsByReason: map[string]int64{
			"banned":  s.dropsBanned.Load(),
			"scanner": s.dropsScanner.Load(),
			"rate":    s.dropsRate.Load(),
		},
	}
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
			s.socketBans.prune()
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
