package media

import (
	"net"
	"net/netip"
	"testing"
)

// The latch's per-packet API takes and returns netip.AddrPort (issue
// #173: ReadFromUDPAddrPort allocates no *net.UDPAddr per packet). The
// latch tests were written against *net.UDPAddr and stay that way through
// these adapters, so they keep checking the semantics the relay had
// before: net.IPv4 builds a 16-byte IPv4-mapped IP, which the latch must
// still treat as the plain IPv4 address.

func (l *latch) accept(src *net.UDPAddr) bool { return l.acceptFrom(src.AddrPort()) }

func (l *latch) target() *net.UDPAddr {
	if d := l.dest(); d.IsValid() {
		return net.UDPAddrFromAddrPort(d)
	}
	return nil
}

// TestLatchSourceFormsCompareLikeNetIP pins the comparison the relay made
// with net.IP.Equal on a *net.UDPAddr: a source read as an IPv4-mapped
// IPv6 address (a dual-stack socket) is the same source as its IPv4 form,
// in either order, and an IPv6 zone does not make a source different.
// What is sent to is the unmapped form, which both socket families accept.
func TestLatchSourceFormsCompareLikeNetIP(t *testing.T) {
	v4 := netip.MustParseAddrPort("198.51.100.7:4000")
	mapped := netip.MustParseAddrPort("[::ffff:198.51.100.7]:4000")

	for _, tc := range []struct{ first, again netip.AddrPort }{{v4, mapped}, {mapped, v4}} {
		l := &latch{mode: LatchStrict}
		l.setExpected(netip.MustParseAddr("198.51.100.7"))
		if !l.acceptFrom(tc.first) {
			t.Fatalf("%v: matching source must latch", tc.first)
		}
		if !l.acceptFrom(tc.again) || !l.permitsFrom(tc.again) {
			t.Fatalf("%v after %v: the other form of the latched source must stay accepted", tc.again, tc.first)
		}
		if got := l.dest(); got != v4 {
			t.Fatalf("dest = %v, want the unmapped %v", got, v4)
		}
	}

	l := &latch{mode: LatchLoose}
	l.seed(netip.MustParseAddrPort("[2001:db8::1]:4000"))
	zoned := netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1%eth0"), 4000)
	if !l.acceptFrom(zoned) || l.rank != rankExact {
		t.Fatalf("a zoned source must rank as the exact signalled address (rank %d)", l.rank)
	}
	if !l.acceptFrom(netip.MustParseAddrPort("[2001:db8::1]:4000")) {
		t.Fatal("the unzoned form of the latched source must stay accepted")
	}
	if got := l.dest(); got != zoned {
		t.Fatalf("dest = %v, want the latched source with its zone %v", got, zoned)
	}
	if l.acceptFrom(netip.AddrPort{}) || l.permitsFrom(netip.AddrPort{}) {
		t.Fatal("an invalid source must never be accepted")
	}
}
