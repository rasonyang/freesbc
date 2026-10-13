package shield

import (
	"net/netip"
	"testing"
)

// Malformed and admission strikes share one admission_ban budget per source
// and scope, while the offender view keeps one row per reason.
func TestMalformedSharesAdmissionBudget(t *testing.T) {
	s := admissionShield(t, "4/10m")
	ip := netip.MustParseAddr("198.51.100.40")
	for i := 0; i < 2; i++ {
		s.StrikeOn(ip, StrikeAdmission, "udp")
		s.StrikeOn(ip, StrikeMalformed, "udp")
	}
	if s.BannedFrom(netip.AddrPortFrom(ip, 5060), "udp") {
		t.Fatal("banned at the shared threshold")
	}
	top, total := s.Offenders(10)
	if total != 2 {
		t.Fatalf("offenders = %+v, want one row per reason", top)
	}
	got := map[string]int{}
	for _, o := range top {
		got[o.Reason] = o.Strikes
	}
	if got[StrikeAdmissionUDP] != 2 || got[StrikeMalformedUDP] != 2 {
		t.Errorf("per-reason counts = %v", got)
	}
	if !s.StrikeOn(ip, StrikeMalformed, "udp") {
		t.Fatal("the malformed strike over the shared budget did not ban")
	}
	page, _ := s.Bans(10, 0)
	if len(page) != 1 || page[0].Kind != BanKindUDPIP || page[0].Reason != BanReasonMalformed {
		t.Errorf("bans = %+v", page)
	}
	for _, tr := range []string{"tcp", "tls", "ws", "wss"} {
		if s.BannedFrom(netip.AddrPortFrom(ip, 5060), tr) {
			t.Errorf("%s banned by a UDP malformed ban", tr)
		}
	}
	if s.Banned(ip) {
		t.Error("the all-transport table holds a UDP-scoped ban")
	}
}

// Malformed alone crosses the threshold, and the admission side keeps the
// "admission" ban reason when it is the one that crosses.
func TestMalformedAloneAndAdmissionReason(t *testing.T) {
	s := admissionShield(t, "2/10m")
	a := netip.MustParseAddr("198.51.100.41")
	s.StrikeOn(a, StrikeMalformed, "udp")
	s.StrikeOn(a, StrikeMalformed, "udp")
	if !s.StrikeOn(a, StrikeMalformed, "UDP") {
		t.Fatal("malformed strikes alone did not ban")
	}
	b := netip.MustParseAddr("198.51.100.42")
	s.StrikeOn(b, StrikeMalformed, "udp")
	s.StrikeOn(b, StrikeMalformed, "udp")
	if !s.StrikeOn(b, StrikeAdmission, "udp") {
		t.Fatal("an admission strike over the shared budget did not ban")
	}
	for _, p := range func() []BanInfo { page, _ := s.Bans(10, 0); return page }() {
		want := BanReasonMalformed
		if p.Source == b.String() {
			want = BanReasonAdmission
		}
		if p.Reason != want {
			t.Errorf("ban %s reason = %s, want %s", p.Source, p.Reason, want)
		}
	}
}

// Stream malformed strikes (ws/wss) keep their own scope and ban every
// transport; UDP and stream budgets do not add up.
func TestMalformedStreamScope(t *testing.T) {
	s := admissionShield(t, "2/10m")
	ip := netip.MustParseAddr("198.51.100.43")
	s.StrikeOn(ip, StrikeMalformed, "udp")
	s.StrikeOn(ip, StrikeMalformed, "udp")
	s.StrikeOn(ip, StrikeMalformed, "wss")
	if s.Banned(ip) {
		t.Fatal("UDP and stream malformed strikes added up")
	}
	s.StrikeOn(ip, StrikeMalformed, "wss")
	if !s.StrikeOn(ip, StrikeMalformed, "ws") || !s.Banned(ip) {
		t.Fatal("stream malformed strikes did not ban every transport")
	}
}

// A 2xx clears the whole admission budget, malformed strikes included.
func TestClearStrikesAdmissionClearsMalformed(t *testing.T) {
	s := admissionShield(t, "2/10m")
	ip := netip.MustParseAddr("198.51.100.44")
	s.StrikeOn(ip, StrikeMalformed, "udp")
	s.StrikeOn(ip, StrikeMalformed, "wss")
	s.ClearStrikes(ip, StrikeAdmission)
	if _, total := s.Offenders(10); total != 0 {
		t.Errorf("offenders after clear = %d", total)
	}
}

func TestMalformedCarrierExempt(t *testing.T) {
	carrier := netip.MustParseAddr("192.0.2.60")
	s, store := strikeShield(t, "100/10m", func(a netip.Addr) bool { return a == carrier })
	next := *store.Current()
	next.Shield.AdmissionBan = "1/10m"
	store.Replace(&next)
	for i := 0; i < 5; i++ {
		if s.StrikeOn(carrier, StrikeMalformed, "udp") {
			t.Fatal("a carrier source was banned")
		}
	}
	if _, total := s.Offenders(10); total != 0 {
		t.Error("a carrier source was counted")
	}
}

// A forged-source malformed flood is bounded by the offender and ban caps.
func TestMalformedFloodBounded(t *testing.T) {
	s := admissionShield(t, "1/10m")
	for i := 0; i < offenderCap+2000; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		s.StrikeOn(ip, StrikeMalformed, "udp")
		s.StrikeOn(ip, StrikeMalformed, "udp")
	}
	if n := s.offenders.size(); n > offenderCap {
		t.Fatalf("offender table = %d, cap %d", n, offenderCap)
	}
	if n := s.udpBans.size(); n > banCap {
		t.Fatalf("ban table = %d, cap %d", n, banCap)
	}
	_, total := s.Offenders(10)
	if total > offenderCap {
		t.Fatalf("offender rows = %d", total)
	}
}
