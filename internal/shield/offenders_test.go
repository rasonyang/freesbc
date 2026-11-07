package shield

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

func strikeShield(t *testing.T, registerBan string, isCarrier func(netip.Addr) bool) (*Shield, *config.Store) {
	t.Helper()
	cfg, err := config.Parse([]byte(shieldCfg + "  register_ban: \"" + registerBan + "\"\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	store := config.NewStore(cfg)
	s := New(store, discard(), isCarrier, nil)
	t.Cleanup(func() { s.Close() })
	return s, store
}

// Up to n strikes in a window are tolerated; the next one bans the IP for
// shield.ban, with reason "register".
func TestStrikeBansOverThreshold(t *testing.T) {
	s, _ := strikeShield(t, "3/10m", nil)
	src := netip.MustParseAddr("198.51.100.9")
	for i := 0; i < 3; i++ {
		if s.Strike(src, StrikeRegister) {
			t.Fatalf("strike %d banned; the threshold is 3", i+1)
		}
	}
	if s.Banned(src) {
		t.Fatal("banned at the threshold")
	}
	if !s.Strike(src, StrikeRegister) || !s.Banned(src) {
		t.Fatal("the strike over the threshold did not ban")
	}
	page, _ := s.Bans(10, 0)
	if len(page) != 1 || page[0].Reason != BanReasonRegister || page[0].Kind != BanKindIP {
		t.Errorf("bans = %+v", page)
	}
	if until := page[0].Until.Sub(page[0].Since); until != time.Hour {
		t.Errorf("ban lasts %s, want shield.ban (1h)", until)
	}
}

// The window is fixed from its first strike: strikes spread over more than
// one window never add up.
func TestStrikeWindowResets(t *testing.T) {
	s, _ := strikeShield(t, "2/1m", nil)
	now := time.Unix(1_700_000_000, 0)
	s.offenders.now = func() time.Time { return now }
	src := netip.MustParseAddr("198.51.100.10")
	for i := 0; i < 10; i++ {
		s.Strike(src, StrikeRegister)
		s.Strike(src, StrikeRegister)
		now = now.Add(time.Minute)
	}
	if s.Banned(src) {
		t.Fatal("two strikes per window banned a 2/1m source")
	}
}

// A success clears the count.
func TestClearStrikes(t *testing.T) {
	s, _ := strikeShield(t, "2/10m", nil)
	src := netip.MustParseAddr("198.51.100.11")
	for i := 0; i < 10; i++ {
		s.Strike(src, StrikeRegister)
		s.Strike(src, StrikeRegister)
		s.ClearStrikes(src, StrikeRegister)
	}
	if s.Banned(src) {
		t.Fatal("cleared strikes still banned")
	}
	if _, total := s.Offenders(10); total != 0 {
		t.Errorf("offenders after clear = %d", total)
	}
}

func TestStrikeCarrierExempt(t *testing.T) {
	carrier := netip.MustParseAddr("192.0.2.50")
	s, _ := strikeShield(t, "1/10m", func(a netip.Addr) bool { return a == carrier })
	for i := 0; i < 10; i++ {
		if s.Strike(carrier, StrikeRegister) {
			t.Fatal("a carrier source was banned")
		}
	}
	if s.Banned(carrier) {
		t.Fatal("a carrier source is banned")
	}
	if _, total := s.Offenders(10); total != 0 {
		t.Error("a carrier source was counted")
	}
}

// "off" counts nothing, and the threshold is read per strike: a reload
// takes effect on the next one.
func TestStrikeOffAndHotThreshold(t *testing.T) {
	s, store := strikeShield(t, "off", nil)
	src := netip.MustParseAddr("198.51.100.12")
	for i := 0; i < 50; i++ {
		if s.Strike(src, StrikeRegister) {
			t.Fatal("register_ban off banned")
		}
	}
	if _, total := s.Offenders(10); total != 0 {
		t.Error("register_ban off counted strikes")
	}
	next := *store.Current()
	next.Shield.RegisterBan = "1/10m"
	store.Replace(&next)
	s.Strike(src, StrikeRegister)
	if !s.Strike(src, StrikeRegister) {
		t.Fatal("the reloaded threshold was not applied")
	}
}

func TestStrikeUnknownReasonIgnored(t *testing.T) {
	s, _ := strikeShield(t, "1/10m", nil)
	src := netip.MustParseAddr("198.51.100.13")
	for i := 0; i < 5; i++ {
		if s.Strike(src, "nope") {
			t.Fatal("an unknown reason banned")
		}
	}
}

// IPv6 sources share one count and one ban per /64: once over the
// threshold the whole /64 is banned, not only the addresses struck.
func TestStrikeIPv6By64(t *testing.T) {
	s, _ := strikeShield(t, "2/10m", nil)
	for i := 1; i <= 3; i++ {
		s.Strike(netip.MustParseAddr(fmt.Sprintf("2001:db8:1:2::%d", i)), StrikeRegister)
	}
	if !s.Banned(netip.MustParseAddr("2001:db8:1:2::3")) {
		t.Fatal("the third address of the /64 was not banned")
	}
	if !s.Banned(netip.MustParseAddr("2001:db8:1:2::1")) {
		t.Error("an address of the banned /64 was not banned")
	}
	if s.Banned(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Error("a neighbouring /64 was banned")
	}
	top, total := s.Offenders(10)
	if total != 1 || top[0].Source != "2001:db8:1:2::/64" || top[0].Strikes != 3 {
		t.Errorf("offenders = %+v (total %d)", top, total)
	}
}

// A flood of distinct sources never grows the table past its cap.
func TestOffenderTableCapped(t *testing.T) {
	s, _ := strikeShield(t, "5/10m", nil)
	s.offenders.max = 64
	for i := 0; i < 1000; i++ {
		s.Strike(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), StrikeRegister)
	}
	if n := s.offenders.size(); n != 64 {
		t.Errorf("offender table holds %d, want the cap 64", n)
	}
	if b := s.bans.size(); b != 0 {
		t.Errorf("single strikes from distinct sources banned %d", b)
	}
}

func TestOffendersOrderAndPrune(t *testing.T) {
	s, _ := strikeShield(t, "100/1m", nil)
	now := time.Unix(1_700_000_000, 0)
	s.offenders.now = func() time.Time { return now }
	a, b := netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("198.51.100.21")
	s.Strike(a, StrikeRegister)
	for i := 0; i < 3; i++ {
		s.Strike(b, StrikeRegister)
	}
	top, total := s.Offenders(1)
	if total != 2 || len(top) != 1 || top[0].Source != b.String() || top[0].Strikes != 3 || top[0].Reason != StrikeRegister {
		t.Fatalf("offenders = %+v (total %d)", top, total)
	}
	if !top[0].Until.Equal(top[0].Since.Add(time.Minute)) {
		t.Errorf("window %s..%s", top[0].Since, top[0].Until)
	}
	now = now.Add(time.Minute)
	if _, total := s.Offenders(10); total != 0 {
		t.Errorf("expired windows listed: %d", total)
	}
	s.offenders.prune()
	if n := s.offenders.size(); n != 0 {
		t.Errorf("prune left %d", n)
	}
}

// Admission strikes have their own threshold (shield.admission_ban) and
// reason, independent of register_ban.
func TestStrikeAdmissionOwnThreshold(t *testing.T) {
	s, store := strikeShield(t, "100/10m", nil)
	next := *store.Current()
	next.Shield.AdmissionBan = "2/10m"
	store.Replace(&next)
	src := netip.MustParseAddr("198.51.100.20")
	s.Strike(src, StrikeAdmission)
	s.Strike(src, StrikeAdmission)
	if s.Banned(src) {
		t.Fatal("banned at the admission threshold")
	}
	if !s.Strike(src, StrikeAdmission) || !s.Banned(src) {
		t.Fatal("the strike over shield.admission_ban did not ban")
	}
	page, _ := s.Bans(10, 0)
	if len(page) != 1 || page[0].Reason != BanReasonAdmission {
		t.Errorf("bans = %+v", page)
	}
	other := netip.MustParseAddr("198.51.100.21")
	for i := 0; i < 5; i++ {
		s.Strike(other, StrikeRegister)
	}
	if s.Banned(other) {
		t.Error("register strikes were counted against the admission threshold")
	}
}
