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
