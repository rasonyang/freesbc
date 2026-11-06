package shield

import (
	"net/netip"
	"testing"
	"time"
)

// A forged-source flood of admission strikes holds the offender table at
// its cap and the ban table under banCap. The ban table's own hard cap is
// covered by TestBanListCap (banlist_test.go) and the forged-UDP fill in
// audit_shield_test.go.
func TestAdmissionStrikeFloodBounded(t *testing.T) {
	s, store := strikeShield(t, "5/10m", nil)
	next := *store.Current()
	next.Shield.AdmissionBan = "1/10m"
	store.Replace(&next)
	s.offenders.max = 256
	for i := 0; i < 5000; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		s.Strike(ip, StrikeAdmission)
		s.Strike(ip, StrikeAdmission) // over 1/10m: banned
	}
	if n := s.offenders.size(); n > 256 {
		t.Errorf("offender table holds %d, cap 256", n)
	}
	if n := s.bans.size(); n > banCap {
		t.Errorf("ban table holds %d, banCap %d", n, banCap)
	}
}

// A flood of more than banCap distinct sources into one table holds that
// table's live count at the cap and moves only its own refusal counter.
func TestBanTableFloodExportedPerKind(t *testing.T) {
	s, _ := strikeShield(t, "5/10m", nil)
	for i := 0; i < banCap+100; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		s.udpBans.ban(ip, time.Hour, BanReasonAdmission)
	}
	st := s.Stats()
	if got := st.BansByKind[BanKindUDPIP]; got != banCap {
		t.Errorf("udp_ip live = %d, want %d", got, banCap)
	}
	if got := st.BanAddsRejectedByKind[BanKindUDPIP]; got != 100 {
		t.Errorf("udp_ip rejected = %d, want 100", got)
	}
	for _, k := range []string{BanKindIP, BanKindUDPSocket} {
		if st.BansByKind[k] != 0 || st.BanAddsRejectedByKind[k] != 0 {
			t.Errorf("%s: live %d rejected %d, want 0 0", k, st.BansByKind[k], st.BanAddsRejectedByKind[k])
		}
	}
	if st.BanAddsRejected != 100 {
		t.Errorf("BanAddsRejected = %d, want 100", st.BanAddsRejected)
	}
}
