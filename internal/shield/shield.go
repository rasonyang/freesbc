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

// Shield is FreeSBC's front-door security plane. It is consulted on every
// inbound request on the public edge listeners; every denial is a silent
// Drop. Params (rate limits, ban) hot-reload from the config store per
// call. Bans live in process memory only.
type Shield struct {
	store      *config.Store
	log        *slog.Logger
	isCarrier  func(netip.Addr) bool    // carrier-source predicate; never nil
	limiter    *rateLimiter             // per-source limit (rate_limit / carrier_rate_limit)
	bans       *banList[netip.Addr]     // source IPs (connection-oriented verdicts)
	socketBans *banList[netip.AddrPort] // UDP source sockets (see CheckFrom)

	// Cumulative drop counters by reason, for the admin API's metrics
	// snapshot (Stats). Incremented in Check at each of its three drop
	// points; read via Stats' atomic Load.
	dropsBanned  atomic.Int64
	dropsScanner atomic.Int64
	dropsRate    atomic.Int64

	// cached parses of the rate limit strings (re-parsed only when they change).
	rlMu    sync.Mutex
	rlStr   string
	rlOpts  config.RateLimit
	carStr  string
	carOpts config.RateLimit

	stop context.CancelFunc
	done chan struct{}
}

// New builds the Shield over store and starts a background prune loop.
// isCarrier reports whether an address is a carrier source: such sources
// are limited by shield.carrier_rate_limit instead of shield.rate_limit
// and are exempt from the scanner ban. nil means no carriers. (The edge's
// trusted private plane bypasses the shield before calling it.)
func New(store *config.Store, log *slog.Logger, isCarrier func(netip.Addr) bool) *Shield {
	if isCarrier == nil {
		isCarrier = func(netip.Addr) bool { return false }
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Shield{
		store:      store,
		log:        log,
		isCarrier:  isCarrier,
		limiter:    newRateLimiter(),
		bans:       newBanList(),
		socketBans: newBanTable[netip.AddrPort](),
		stop:       cancel,
		done:       make(chan struct{}),
	}
	go s.pruneLoop(ctx)
	return s
}

// Check is the per-request gate (spec §3): a banned source and a
// rate-limit violation Drop; otherwise a scanner UA is dropped, and instantly
// banned when it arrived over a connection-oriented transport (see
// bannableTransport) — but only AFTER the rate limiter has had its say (the
// UA is a client-controlled "ban me" signal, so it must first burn through
// the source's rate budget like any other traffic, never skip the limiter).
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
	if s.BannedFrom(srcAP, transport) {
		s.dropsBanned.Add(1)
		return Drop
	}
	if !s.AllowRate(srcAP.Addr()) {
		return Drop
	}
	return s.CheckScanner(srcAP, userAgent, transport)
}

// AllowRate charges one token of src's rate-limit bucket (shield.rate_limit,
// or shield.carrier_rate_limit for a carrier source) and reports whether it
// was available. A refusal is counted as a "rate" drop. It needs no parsed
// message, so the edge read filter calls it once per datagram or frame,
// before the parser; a parsable request is then charged exactly once, there,
// and its guard calls CheckScanner instead of CheckFrom.
func (s *Shield) AllowRate(src netip.Addr) bool {
	src = src.Unmap()
	rl := s.rateLimit(s.store.Current(), s.isCarrier(src))
	if !s.limiter.allow(src, rl.Rate, rl.Interval, rl.PerIP) {
		s.log.Debug("shield rate-limited", "source", src)
		s.dropsRate.Add(1)
		return false
	}
	return true
}

// CheckScanner is CheckFrom without the rate token: the ban re-check and the
// scanner (User-Agent) verdict, which need a parsed message. The caller must
// already have charged the source through AllowRate (the UA is a
// client-controlled "ban me" signal, so it must first burn through the
// source's rate budget like any other traffic, never skip the limiter).
func (s *Shield) CheckScanner(srcAP netip.AddrPort, userAgent string, transport string) Verdict {
	srcAP = netip.AddrPortFrom(srcAP.Addr().Unmap(), srcAP.Port())
	src := srcAP.Addr()
	cfg := s.store.Current()
	if s.BannedFrom(srcAP, transport) {
		s.dropsBanned.Add(1)
		return Drop
	}
	carrier := s.isCarrier(src)
	if !carrier && isScanner(userAgent) {
		s.dropsScanner.Add(1)
		if !bannableTransport(transport) {
			// A datagram's source address is forgeable: an IP ban would let
			// one spoofed packet lock a third party out, and a spoofed flood
			// fill the IP table. Ban the socket instead, briefly.
			if isUDP(transport) && srcAP.Port() != 0 {
				s.socketBans.ban(srcAP, min(cfg.Shield.Ban.Std(), socketBanMax))
			}
			s.log.Debug("shield dropped scanner datagram", "source", srcAP, "ua", userAgent)
			return Drop
		}
		if !s.bans.ban(src, cfg.Shield.Ban.Std()) {
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

func (s *Shield) rateLimit(cfg *config.Config, carrier bool) config.RateLimit {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	str, cached, opts := cfg.Shield.RateLimit, &s.rlStr, &s.rlOpts
	if carrier {
		str, cached, opts = cfg.Shield.CarrierRateLimit, &s.carStr, &s.carOpts
	}
	if str != *cached {
		if rl, err := config.ParseRateLimit(str); err == nil {
			*opts = rl
			*cached = str
		}
	}
	return *opts
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
			s.bans.prune()
			s.socketBans.prune()
		}
	}
}
