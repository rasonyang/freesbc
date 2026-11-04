package shield

import (
	"container/list"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// bucketCap is the hard ceiling on per-source buckets, the same bound as
// the ban table (banCap): a flood of distinct sources must not grow the
// map without bound. At the cap the least recently used bucket is evicted.
const bucketCap = banCap

// bucket is a token bucket: tokens refill continuously toward capacity.
// interval is the refill interval the bucket was last used with, so prune
// can tell when it has refilled to full without knowing the config.
type bucket struct {
	key      rateKey
	tokens   float64
	last     time.Time
	interval time.Duration
}

// rateKey names one per-source bucket. A per-IP bucket carries the
// bucketKey address with port 0; a socket floor carries the exact source
// socket and socket=true. stream separates the stream transports (tcp, tls,
// ws, wss) from datagrams, so forged datagrams never touch a stream
// source's buckets.
type rateKey struct {
	src    netip.AddrPort
	stream bool
	socket bool
}

// rateLimiter is a per-source (or single global) token-bucket limiter.
// The rate/interval/perIP parameters are passed per call so a hot-reloaded
// config takes effect without rebuilding the limiter (only the buckets carry
// state). Per-source buckets are keyed by bucketKey (an IPv6 source by its
// /64) and held in an LRU capped at bucketCap. now is injectable for tests.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[rateKey]*list.Element // of *bucket
	lru     *list.List                // front = most recently used
	global  *bucket
	now     func() time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[rateKey]*list.Element), lru: list.New(), now: time.Now}
}

// bucketKey is the per-source bucket key: an IPv4 address (4in6 unmapped)
// as is, an IPv6 address by its /64. One IPv6 host is normally given a
// whole /64, so keying by address would hand one host unlimited buckets.
func bucketKey(src netip.Addr) netip.Addr {
	src = src.Unmap()
	if src.Is6() {
		return netip.PrefixFrom(src.WithZone(""), 64).Masked().Addr()
	}
	return src
}

// allow consumes one token of src's datagram-class per-IP bucket (or of
// the global bucket when perIP is false) and reports whether it was
// available. Capacity (burst) = rate; refill = rate tokens per interval.
func (r *rateLimiter) allow(src netip.Addr, rate int, interval time.Duration, perIP bool) bool {
	return r.take(rateKey{src: netip.AddrPortFrom(bucketKey(src), 0)}, rate, interval, perIP)
}

// take is allow for an explicit bucket key; perIP false ignores key.
func (r *rateLimiter) take(key rateKey, rate int, interval time.Duration, perIP bool) bool {
	if rate <= 0 || interval <= 0 {
		return true // misconfigured → don't throttle
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var b *bucket
	if perIP {
		if e := r.buckets[key]; e != nil {
			r.lru.MoveToFront(e)
			b = e.Value.(*bucket)
		} else {
			if r.lru.Len() >= bucketCap {
				oldest := r.lru.Back()
				r.lru.Remove(oldest)
				delete(r.buckets, oldest.Value.(*bucket).key)
			}
			b = &bucket{key: key, tokens: float64(rate), last: now}
			r.buckets[key] = r.lru.PushFront(b)
		}
	} else {
		if r.global == nil {
			r.global = &bucket{tokens: float64(rate), last: now}
		}
		b = r.global
	}
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.interval = interval
	b.tokens = math.Min(float64(rate), b.tokens+elapsed*float64(rate)/interval.Seconds())
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// prune drops per-source buckets that have been idle for at least their own
// refill interval: such a bucket has refilled to full, and a fresh one
// starts full, so removing it loses no state. A partly drained bucket is
// kept, so an N/h limit is not reset by an idle minute. Call periodically.
func (r *rateLimiter) prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	// A full walk (buckets can carry different intervals), bounded by
	// bucketCap and run once a minute.
	for e := r.lru.Back(); e != nil; {
		prev := e.Prev()
		if b := e.Value.(*bucket); now.Sub(b.last) >= b.interval {
			r.lru.Remove(e)
			delete(r.buckets, b.key)
		}
		e = prev
	}
}

// Limiter is a single global token bucket: Allow consumes one token from a
// bucket of capacity rl.Rate that refills rl.Rate tokens per rl.Interval.
// The limit is passed per call, so a hot-reloaded value applies at once;
// rl.PerIP is ignored (the bucket is always global). Safe for concurrent
// use. The zero value is not usable; call NewLimiter.
type Limiter struct{ rl *rateLimiter }

// NewLimiter returns an empty (full) global limiter.
func NewLimiter() *Limiter { return &Limiter{rl: newRateLimiter()} }

// Allow reports whether a token was available and consumes it. A limit with
// no rate or interval never refuses.
func (l *Limiter) Allow(rl config.RateLimit) bool {
	return l.rl.allow(netip.Addr{}, rl.Rate, rl.Interval, false)
}
