package shield

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// longRig is a shield with every table on one fake clock.
type longRig struct {
	*Shield
	store *config.Store
	now   time.Time
	logs  *bytes.Buffer
}

func newLongRig(t *testing.T, shieldKeys string) *longRig {
	t.Helper()
	cfg, err := config.Parse([]byte(shieldCfg + shieldKeys))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := &longRig{store: config.NewStore(cfg), now: time.Unix(1_700_000_000, 0), logs: &bytes.Buffer{}}
	r.Shield = New(r.store, slog.New(slog.NewTextHandler(r.logs, nil)), nil, nil)
	t.Cleanup(func() { r.Close() })
	clock := func() time.Time { return r.now }
	r.offenders.now, r.aors.now = clock, clock
	r.bans.now, r.udpBans.now, r.socketBans.now = clock, clock, clock
	return r
}

func (r *longRig) setLimits(mut func(*config.ShieldConfig)) {
	next := *r.store.Current()
	mut(&next.Shield)
	r.store.Replace(&next)
}

// drive strikes every interval for total time and returns the elapsed time
// at which strike reported a ban (0 if never).
func (r *longRig) drive(interval, total time.Duration, strike func() bool) time.Duration {
	for el := time.Duration(0); el < total; el += interval {
		if strike() {
			return el
		}
		r.now = r.now.Add(interval)
	}
	return 0
}

var testSrc = netip.MustParseAddr("198.51.100.77")

func TestAdmissionLongStageCatchesSlowSource(t *testing.T) {
	udpAdmission := func(r *longRig) func() bool {
		return func() bool { return r.StrikeOn(testSrc, StrikeAdmission, "udp") }
	}
	// 8 strikes per 10 minutes stays under 20/10m forever.
	r := newLongRig(t, "  admission_ban: 20/10m\n  admission_ban_long: off\n")
	if at := r.drive(75*time.Second, 2*time.Hour, udpAdmission(r)); at != 0 {
		t.Fatalf("banned at %s with the long stage off", at)
	}
	if page, _ := r.Bans(10, 0); len(page) != 0 {
		t.Fatalf("bans = %+v", page)
	}

	r = newLongRig(t, "  admission_ban: 20/10m\n  admission_ban_long: 30/1h\n")
	grew := false
	strike := udpAdmission(r)
	at := r.drive(75*time.Second, 2*time.Hour, func() bool {
		if top, _ := r.Offenders(10); len(top) == 1 && top[0].LongStrikes > 0 && top[0].LongStrikes < 31 {
			grew = true
			if top[0].Strikes > 20 || top[0].LongUntil.Sub(top[0].LongSince) != time.Hour {
				t.Errorf("view = %+v", top[0])
			}
		}
		return strike()
	})
	if at == 0 || at > time.Hour {
		t.Fatalf("not banned within the long window (at %s)", at)
	}
	if !grew {
		t.Error("the offender view never showed the long count growing")
	}
	page, _ := r.Bans(10, 0)
	if len(page) != 1 || page[0].Reason != BanReasonAdmission || page[0].Kind != BanKindUDPIP {
		t.Fatalf("bans = %+v", page)
	}
	if !strings.Contains(r.logs.String(), "stage=long") {
		t.Errorf("no stage=long WARN: %s", r.logs)
	}

	// 4 per 10 minutes is 24/h: the documented residual floor under 30/1h.
	r = newLongRig(t, "  admission_ban: 20/10m\n  admission_ban_long: 30/1h\n")
	if at := r.drive(150*time.Second, 2*time.Hour, udpAdmission(r)); at != 0 {
		t.Fatalf("a 24/h source was banned at %s", at)
	}
}

func TestRegisterLongStageCatchesSlowSource(t *testing.T) {
	strike := func(r *longRig) func() bool { return func() bool { return r.Strike(testSrc, StrikeRegister) } }
	r := newLongRig(t, "  register_ban: 10/10m\n  register_ban_long: off\n")
	if at := r.drive(75*time.Second, 2*time.Hour, strike(r)); at != 0 {
		t.Fatalf("banned at %s with the long stage off", at)
	}
	r = newLongRig(t, "  register_ban: 10/10m\n  register_ban_long: 20/1h\n")
	if at := r.drive(75*time.Second, 2*time.Hour, strike(r)); at == 0 {
		t.Fatal("slow source not banned")
	}
	page, _ := r.Bans(10, 0)
	if len(page) != 1 || page[0].Reason != BanReasonRegister || page[0].Kind != BanKindIP {
		t.Fatalf("bans = %+v", page)
	}
	if !strings.Contains(r.logs.String(), "stage=long") {
		t.Errorf("no stage=long WARN: %s", r.logs)
	}
	r = newLongRig(t, "  register_ban: 10/10m\n  register_ban_long: 20/1h\n")
	if at := r.drive(200*time.Second, 2*time.Hour, strike(r)); at != 0 {
		t.Fatalf("an 18/h source was banned at %s", at)
	}
}

func TestAORLongStageLocksSlowAttack(t *testing.T) {
	strike := func(r *longRig) func() bool { return func() bool { return r.StrikeAOR("a@x") } }
	r := newLongRig(t, "  register_ban_aor: 10/10m\n  register_ban_aor_long: off\n")
	if at := r.drive(75*time.Second, 2*time.Hour, strike(r)); at != 0 || r.AORLocked("a@x") {
		t.Fatalf("locked at %s with the long stage off", at)
	}
	r = newLongRig(t, "  register_ban_aor: 10/10m\n  register_ban_aor_long: 20/1h\n")
	if at := r.drive(75*time.Second, 2*time.Hour, strike(r)); at == 0 || !r.AORLocked("a@x") {
		t.Fatal("slow attack did not lock the AoR")
	}
	top, _ := r.Offenders(10)
	if len(top) != 1 || top[0].LongStrikes < 21 || !strings.Contains(r.logs.String(), "stage=long") {
		t.Errorf("offenders = %+v logs = %s", top, r.logs)
	}
	r = newLongRig(t, "  register_ban_aor: 10/10m\n  register_ban_aor_long: 20/1h\n")
	if at := r.drive(200*time.Second, 2*time.Hour, strike(r)); at != 0 || r.AORLocked("a@x") {
		t.Fatalf("an 18/h attack locked at %s", at)
	}
}

func TestShortResetKeepsLongCount(t *testing.T) {
	r := newLongRig(t, "  register_ban: 100/1m\n  register_ban_long: 100/1h\n  register_ban_aor: 100/1m\n  register_ban_aor_long: 100/1h\n")
	for i := 0; i < 3; i++ {
		r.Strike(testSrc, StrikeRegister)
		r.StrikeAOR("a@x")
	}
	r.now = r.now.Add(2 * time.Minute)
	r.Strike(testSrc, StrikeRegister)
	r.StrikeAOR("a@x")
	top, total := r.Offenders(10)
	if total != 2 {
		t.Fatalf("offenders = %+v", top)
	}
	for _, o := range top {
		if o.Strikes != 1 || o.LongStrikes != 4 {
			t.Errorf("%s: short %d long %d, want 1 and 4", o.Reason, o.Strikes, o.LongStrikes)
		}
	}
	// Past the short window with no strike, the row keeps only the long stage.
	r.now = r.now.Add(2 * time.Minute)
	top, _ = r.Offenders(10)
	for _, o := range top {
		if o.Strikes != 0 || !o.Since.IsZero() || !o.Until.IsZero() || o.LongStrikes != 4 || o.LongSince.IsZero() {
			t.Errorf("%s: view %+v", o.Reason, o)
		}
	}
}

func TestClearDropsBothStages(t *testing.T) {
	r := newLongRig(t, "  register_ban: 3/1m\n  register_ban_long: 5/1h\n  register_ban_aor: 3/1m\n  register_ban_aor_long: 5/1h\n")
	for i := 0; i < 4; i++ {
		r.Strike(testSrc, StrikeRegister)
		r.StrikeAOR("a@x")
		r.now = r.now.Add(2 * time.Minute) // the short window never fills
	}
	r.ClearStrikes(testSrc, StrikeRegister)
	r.ClearAOR("a@x")
	if _, total := r.Offenders(10); total != 0 {
		t.Fatalf("offenders after clear = %d", total)
	}
	// Without the cleared long count, four more strikes stay under 5.
	for i := 0; i < 4; i++ {
		if r.Strike(testSrc, StrikeRegister) || r.StrikeAOR("a@x") {
			t.Fatal("a cleared long count survived")
		}
		r.now = r.now.Add(2 * time.Minute)
	}
}

func TestShortKeyIsMasterSwitch(t *testing.T) {
	r := newLongRig(t, "  register_ban: off\n  register_ban_long: 2/1h\n  register_ban_aor: off\n  register_ban_aor_long: 2/1h\n  admission_ban: off\n  admission_ban_long: 2/1h\n")
	for i := 0; i < 10; i++ {
		if r.Strike(testSrc, StrikeRegister) || r.StrikeAOR("a@x") || r.StrikeOn(testSrc, StrikeAdmission, "tcp") || r.Strike(testSrc, StrikeMalformed) {
			t.Fatal("a strike counted with the short key off")
		}
	}
	if r.AORLocked("a@x") || r.Banned(testSrc) {
		t.Fatal("locked or banned with the short key off")
	}
	if _, total := r.Offenders(10); total != 0 {
		t.Fatalf("offenders = %d", total)
	}
	// Turning the short key on lets a pending long stage act at once.
	r.setLimits(func(c *config.ShieldConfig) { c.RegisterBan = "10/1m" })
	for i := 0; i < 2; i++ {
		r.Strike(testSrc, StrikeRegister)
	}
	if !r.Strike(testSrc, StrikeRegister) {
		t.Fatal("long stage not enforced once the short key is on")
	}
}

func TestLongKeyHotChange(t *testing.T) {
	r := newLongRig(t, "  register_ban: 100/1m\n  register_ban_long: off\n")
	for i := 0; i < 5; i++ {
		r.Strike(testSrc, StrikeRegister)
		r.now = r.now.Add(2 * time.Minute)
	}
	r.setLimits(func(c *config.ShieldConfig) { c.RegisterBanLong = "3/1h" })
	// The long stage starts counting at the next strike: no history.
	for i := 0; i < 3; i++ {
		if r.Strike(testSrc, StrikeRegister) {
			t.Fatalf("banned at long strike %d of 3", i+1)
		}
	}
	if !r.Strike(testSrc, StrikeRegister) {
		t.Fatal("hot long key not applied")
	}
	// Turning it off again: a stale over long stage no longer bans.
	r.setLimits(func(c *config.ShieldConfig) { c.RegisterBanLong = "off" })
	if r.Strike(testSrc, StrikeRegister) {
		t.Fatal("a disabled long stage still banned")
	}
}

func TestPruneKeepsOpenLongStage(t *testing.T) {
	r := newLongRig(t, "  register_ban: 100/1m\n  register_ban_long: 100/1h\n  register_ban_aor: 100/1m\n  register_ban_aor_long: 100/1h\n")
	r.Strike(testSrc, StrikeRegister)
	r.StrikeAOR("a@x")
	r.now = r.now.Add(30 * time.Minute)
	r.offenders.prune()
	r.aors.prune()
	if r.offenders.size() != 1 || r.aors.size() != 1 {
		t.Fatalf("pruned with the long window open: %d %d", r.offenders.size(), r.aors.size())
	}
	r.now = r.now.Add(31 * time.Minute)
	r.offenders.prune()
	r.aors.prune()
	if r.offenders.size() != 0 || r.aors.size() != 0 {
		t.Fatalf("kept after both windows ended: %d %d", r.offenders.size(), r.aors.size())
	}
}

func TestAdmissionViewRowsAreUnionOfParts(t *testing.T) {
	r := newLongRig(t, "  admission_ban: 100/1m\n  admission_ban_long: 100/1h\n")
	r.Strike(testSrc, StrikeMalformed)
	r.Strike(testSrc, StrikeMalformed)
	r.Strike(testSrc, StrikeAdmission)
	r.now = r.now.Add(2 * time.Minute) // the short stage closes
	r.Strike(testSrc, StrikeAdmission)
	top, total := r.Offenders(10)
	if total != 2 || len(top) != 2 {
		t.Fatalf("offenders = %+v", top)
	}
	got := map[string][2]int{}
	for _, o := range top {
		got[o.Reason] = [2]int{o.Strikes, o.LongStrikes}
	}
	if got[StrikeAdmission] != [2]int{1, 2} || got[StrikeMalformed] != [2]int{0, 2} {
		t.Errorf("rows = %v", got)
	}
	if top[0].Reason != StrikeAdmission {
		t.Errorf("sort: %+v", top)
	}
}

func TestLongStageWarnsOncePerWindow(t *testing.T) {
	r := newLongRig(t, "  register_ban: 100/1m\n  register_ban_long: 2/1h\n")
	for i := 0; i < 6; i++ {
		r.Strike(testSrc, StrikeRegister)
	}
	if n := strings.Count(r.logs.String(), "shield banned source for repeated failures"); n != 1 {
		t.Errorf("WARN count = %d", n)
	}
	if !strings.Contains(r.logs.String(), "stage=long strikes=3 window=1h0m0s") {
		t.Errorf("WARN attrs: %s", r.logs)
	}
}
