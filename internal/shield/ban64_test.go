package shield

import (
	"net/netip"
	"testing"
)

// v6 returns an address inside 2001:db8:1:2::/64 (or the neighbouring
// 2001:db8:1:3::/64 when nb) whose low 32 bits are n.
func v6(nb bool, n uint32) netip.Addr {
	b := netip.MustParseAddr("2001:db8:1:2::").As16()
	if nb {
		b[7] = 3
	}
	b[12], b[13], b[14], b[15] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	return netip.AddrFrom16(b)
}

// One /64 rotating through more than banCap /128 addresses past the
// threshold holds one ban entry and blocks the whole /64, never filling
// the table.
func TestIPv6BanCoversWholePrefix(t *testing.T) {
	for _, tc := range []struct {
		transport, kind string
		udp             bool
	}{
		{"udp", BanKindUDPIP, true},
		{"wss", BanKindIP, false},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			s := admissionShield(t, "1/10m")
			for i := uint32(0); i < banCap+100; i++ {
				s.StrikeOn(v6(false, i), StrikeAdmission, tc.transport)
			}
			st := s.Stats()
			if st.BansByKind[tc.kind] != 1 || st.BanAddsRejected != 0 {
				t.Fatalf("bans by kind %v, rejected %d; want one %s entry", st.BansByKind, st.BanAddsRejected, tc.kind)
			}
			for _, n := range []uint32{0, 5, banCap + 99, 1 << 31} { // the last was never struck
				if !s.BannedFrom(netip.AddrPortFrom(v6(false, n), 5060), tc.transport) {
					t.Errorf("address %d of the /64 not blocked", n)
				}
			}
			if s.BannedFrom(netip.AddrPortFrom(v6(true, 0), 5060), tc.transport) {
				t.Error("neighbouring /64 blocked")
			}
			if !tc.udp {
				if !s.Banned(v6(false, 77)) || s.Banned(v6(true, 0)) {
					t.Error("Banned disagrees with BannedFrom")
				}
			}
		})
	}
}

func TestIPv6StreamScannerBansPrefix(t *testing.T) {
	s := testShield(t, shieldCfg)
	if s.CheckFrom(netip.AddrPortFrom(v6(false, 1), 40000), "sipvicious", "tcp") != Drop {
		t.Fatal("scanner not dropped")
	}
	if !s.BannedFrom(netip.AddrPortFrom(v6(false, 99), 1), "tls") {
		t.Error("scanner ban does not cover the /64")
	}
	if s.BannedFrom(netip.AddrPortFrom(v6(true, 1), 1), "tls") {
		t.Error("neighbouring /64 banned")
	}
}

func TestIPv4BanStaysSingleAddress(t *testing.T) {
	s := admissionShield(t, "1/10m")
	a, b := netip.MustParseAddr("198.51.100.40"), netip.MustParseAddr("198.51.100.41")
	s.StrikeOn(a, StrikeAdmission, "wss")
	s.StrikeOn(a, StrikeAdmission, "wss")
	if !s.Banned(a) || s.Banned(b) {
		t.Errorf("banned(a)=%v banned(b)=%v", s.Banned(a), s.Banned(b))
	}
}

// A carrier address inside a banned /64 is never blocked.
func TestCarrierInsideBannedPrefixNotBlocked(t *testing.T) {
	carrier := v6(false, 0xcafe)
	s, store := strikeShield(t, "100/10m", func(a netip.Addr) bool { return a == carrier })
	next := *store.Current()
	next.Shield.AdmissionBan = "1/10m"
	store.Replace(&next)
	for i := 0; i < 3; i++ {
		s.StrikeOn(v6(false, 1), StrikeAdmission, "wss")
	}
	if !s.Banned(v6(false, 2)) {
		t.Fatal("/64 not banned")
	}
	if s.Banned(carrier) || s.BannedFrom(netip.AddrPortFrom(carrier, 5060), "wss") || s.BannedFrom(netip.AddrPortFrom(carrier, 5060), "udp") {
		t.Error("carrier source blocked by a /64 ban")
	}
}

func TestBansListIPv6AsPrefix(t *testing.T) {
	s := admissionShield(t, "1/10m")
	v4 := netip.MustParseAddr("198.51.100.50")
	for i := 0; i < 2; i++ {
		s.StrikeOn(v6(false, 1), StrikeAdmission, "wss")
		s.StrikeOn(v4, StrikeAdmission, "wss")
	}
	page, total := s.Bans(10, 0)
	got := map[string]bool{}
	for _, b := range page {
		got[b.Source] = true
	}
	if total != 2 || !got["2001:db8:1:2::/64"] || !got["198.51.100.50"] {
		t.Errorf("bans = %+v", page)
	}
}
