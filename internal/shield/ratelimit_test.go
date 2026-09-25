package shield

import (
	"net/netip"
	"testing"
	"time"
)

func TestRateLimiterBurstThenThrottle(t *testing.T) {
	r := newRateLimiter()
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.7")

	// capacity = rate = 3: first 3 allowed, 4th denied within the same instant.
	for i := 0; i < 3; i++ {
		if !r.allow(ip, 3, time.Second, true) {
			t.Fatalf("token %d should be allowed", i)
		}
	}
	if r.allow(ip, 3, time.Second, true) {
		t.Fatal("4th token in the same instant must be denied")
	}
	// after 1 second, the bucket has fully refilled (3 tokens).
	now = now.Add(time.Second)
	if !r.allow(ip, 3, time.Second, true) {
		t.Fatal("token after full refill should be allowed")
	}
}

func TestRateLimiterPerIPIsolation(t *testing.T) {
	r := newRateLimiter()
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	a := netip.MustParseAddr("203.0.113.1")
	b := netip.MustParseAddr("203.0.113.2")
	// exhaust a
	r.allow(a, 1, time.Second, true)
	if r.allow(a, 1, time.Second, true) {
		t.Fatal("a exhausted")
	}
	// b unaffected
	if !r.allow(b, 1, time.Second, true) {
		t.Fatal("b must have its own bucket")
	}
}

func TestRateLimiterGlobal(t *testing.T) {
	r := newRateLimiter()
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	a := netip.MustParseAddr("203.0.113.1")
	b := netip.MustParseAddr("203.0.113.2")
	// perIP=false → one shared bucket of capacity 1; a consumes it, b denied.
	if !r.allow(a, 1, time.Second, false) {
		t.Fatal("first global token allowed")
	}
	if r.allow(b, 1, time.Second, false) {
		t.Fatal("global bucket shared: b must be denied")
	}
}

func TestRateLimiterPruneDropsIdle(t *testing.T) {
	r := newRateLimiter()
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.7")
	r.allow(ip, 5, time.Second, true) // creates a bucket
	now = now.Add(time.Hour)          // long idle → bucket refills to full
	r.prune()
	if len(r.buckets) != 0 {
		t.Fatalf("prune should drop the idle/full bucket, have %d", len(r.buckets))
	}
}

// audit: P2-SHD-002
// At bucketCap the least recently used bucket is evicted; the map never
// grows past the cap.
func TestRateLimiterLRUCap(t *testing.T) {
	r := newRateLimiter()
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	for i := 0; i <= bucketCap; i++ {
		r.allow(capIP(i), 1, time.Second, true)
	}
	if got := len(r.buckets); got != bucketCap {
		t.Fatalf("buckets = %d, want the cap %d", got, bucketCap)
	}
	if _, ok := r.buckets[capIP(0)]; ok {
		t.Error("the least recently used bucket was not the one evicted")
	}
	if _, ok := r.buckets[capIP(bucketCap)]; !ok {
		t.Error("the newest bucket is missing")
	}
}

// audit: P2-SHD-002
// IPv6 sources share one bucket per /64; IPv4 and 4in6 share per address.
func TestRateLimiterKeysIPv6By64(t *testing.T) {
	r := newRateLimiter()
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	if !r.allow(netip.MustParseAddr("2001:db8:1:2::1"), 1, time.Second, true) {
		t.Fatal("first token refused")
	}
	if r.allow(netip.MustParseAddr("2001:db8:1:2:ffff::9"), 1, time.Second, true) {
		t.Error("another address in the same /64 got its own bucket")
	}
	if !r.allow(netip.MustParseAddr("2001:db8:1:3::1"), 1, time.Second, true) {
		t.Error("a different /64 must have its own bucket")
	}
	r.allow(netip.MustParseAddr("192.0.2.1"), 1, time.Second, true)
	if r.allow(netip.MustParseAddr("::ffff:192.0.2.1"), 1, time.Second, true) {
		t.Error("a 4in6 source must share its IPv4 bucket")
	}
}

// audit: P2-SHD-003
// prune keeps a bucket until it has been idle for its own interval.
func TestRateLimiterPruneHonoursInterval(t *testing.T) {
	r := newRateLimiter()
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	ip := netip.MustParseAddr("203.0.113.8")
	r.allow(ip, 10, time.Hour, true)
	now = now.Add(59 * time.Minute)
	r.prune()
	if len(r.buckets) != 1 {
		t.Fatal("a 10/h bucket was pruned before an hour of idleness")
	}
	now = now.Add(time.Minute)
	r.prune()
	if len(r.buckets) != 0 || r.lru.Len() != 0 {
		t.Fatal("a bucket idle for its whole interval must be pruned")
	}
}
