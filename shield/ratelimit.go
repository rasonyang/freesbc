package shield

import (
	"math"
	"net/netip"
	"sync"
	"time"
)

// bucket is a token bucket: tokens refill continuously toward capacity.
type bucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a per-source-IP (or single global) token-bucket limiter.
// The rate/interval/perIP parameters are passed per call so a hot-reloaded
// config takes effect without rebuilding the limiter (only the buckets carry
// state). now is injectable for tests.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	global  *bucket
	now     func() time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[netip.Addr]*bucket), now: time.Now}
}

// allow consumes one token for src and reports whether it was available.
// Capacity (burst) = rate; refill = rate tokens per interval.
func (r *rateLimiter) allow(src netip.Addr, rate int, interval time.Duration, perIP bool) bool {
	if rate <= 0 || interval <= 0 {
		return true // misconfigured → don't throttle
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var b *bucket
	if perIP {
		b = r.buckets[src]
		if b == nil {
			b = &bucket{tokens: float64(rate), last: now}
			r.buckets[src] = b
		}
	} else {
		if r.global == nil {
			r.global = &bucket{tokens: float64(rate), last: now}
		}
		b = r.global
	}
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens = math.Min(float64(rate), b.tokens+elapsed*float64(rate)/interval.Seconds())
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// prune drops per-IP buckets that have refilled to (near) full — an idle
// bucket carries no state (a fresh one starts full), so removing it is safe
// and bounds memory under a spoofed-source flood. Call periodically.
func (r *rateLimiter) prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for ip, b := range r.buckets {
		// refill to now, then drop if full.
		// (recomputing here avoids needing a stored rate — a bucket last
		// touched long ago is full regardless of rate.)
		if now.Sub(b.last) >= time.Minute {
			delete(r.buckets, ip)
		}
	}
}
