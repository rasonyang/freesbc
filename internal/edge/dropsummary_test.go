package edge

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The summary names the total, the number of sources and the top one, and
// an interval with no drops yields nothing.
func TestDropSummary(t *testing.T) {
	var d dropSummary
	if msg, ok := d.take(time.Minute); ok {
		t.Fatalf("empty interval produced %q", msg)
	}
	a, b := netip.MustParseAddr("51.15.26.108"), netip.MustParseAddr("198.51.100.4")
	for i := 0; i < 5; i++ {
		d.addAdmission(a)
	}
	d.addAdmission(b)
	d.addAdmission(netip.MustParseAddr("::ffff:198.51.100.4")) // mapped form is the same source
	msg, ok := d.take(time.Minute)
	want := "admission drops: 7 in 1m0s (7 admission, 0 malformed) from 2 sources, top=51.15.26.108 (5 admission, 0 malformed)"
	if !ok || msg != want {
		t.Fatalf("summary = %q, %v; want %q", msg, ok, want)
	}
	if msg, ok := d.take(time.Minute); ok {
		t.Fatalf("interval after take produced %q", msg)
	}
}

// Malformed reads are counted apart from admission drops; a source with both
// shows both, and a malformed-only source appears with its count.
func TestDropSummaryKinds(t *testing.T) {
	var d dropSummary
	a, b := netip.MustParseAddr("51.15.26.108"), netip.MustParseAddr("198.51.100.4")
	d.addAdmission(a)
	d.addAdmission(a)
	d.addAdmission(a)
	for i := 0; i < 4; i++ {
		d.addMalformed(a)
	}
	d.addMalformed(b)
	msg, ok := d.take(time.Minute)
	want := "admission drops: 8 in 1m0s (3 admission, 5 malformed) from 2 sources, top=51.15.26.108 (3 admission, 4 malformed)"
	if !ok || msg != want {
		t.Fatalf("summary = %q, %v; want %q", msg, ok, want)
	}
	d.addMalformed(b)
	msg, ok = d.take(time.Minute)
	want = "admission drops: 1 in 1m0s (0 admission, 1 malformed) from 1 sources, top=198.51.100.4 (0 admission, 1 malformed)"
	if !ok || msg != want {
		t.Fatalf("summary = %q, %v; want %q", msg, ok, want)
	}
}

// Sources past the tally cap still count in the total and never grow the map.
func TestDropSummaryBounded(t *testing.T) {
	var d dropSummary
	n := maxSummarySources + 500
	for i := 0; i < n; i++ {
		d.addAdmission(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	if len(d.bySrc) != maxSummarySources {
		t.Fatalf("tally holds %d sources, want the cap %d", len(d.bySrc), maxSummarySources)
	}
	msg, ok := d.take(time.Minute)
	if !ok || !strings.HasPrefix(msg, fmt.Sprintf("admission drops: %d in", n)) || !strings.Contains(msg, "+ sources") {
		t.Fatalf("summary = %q", msg)
	}
}
