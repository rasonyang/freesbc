package shield

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

func aorShield(t *testing.T, lim string) (*Shield, *config.Store) {
	t.Helper()
	cfg, err := config.Parse([]byte(shieldCfg + "  register_ban_aor: \"" + lim + "\"\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	store := config.NewStore(cfg)
	s := New(store, discard(), nil)
	t.Cleanup(func() { s.Close() })
	return s, store
}

func TestAORLockOpensOverThresholdAndExpires(t *testing.T) {
	s, _ := aorShield(t, "3/10m")
	now := time.Unix(1_700_000_000, 0)
	s.aors.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if s.StrikeAOR("a@x") || s.AORLocked("a@x") {
			t.Fatalf("locked at strike %d; threshold is 3", i+1)
		}
	}
	if !s.StrikeAOR("a@x") || !s.AORLocked("a@x") {
		t.Fatal("strike over the threshold did not lock")
	}
	if s.AORLocked("b@x") {
		t.Error("another AoR locked")
	}
	now = now.Add(time.Hour - time.Second)
	if !s.AORLocked("a@x") {
		t.Error("lock ended before shield.ban")
	}
	now = now.Add(2 * time.Second)
	if s.AORLocked("a@x") {
		t.Error("lock outlived shield.ban")
	}
	s.aors.prune()
	if s.aors.size() != 0 {
		t.Error("expired lock not pruned")
	}
}

func TestAORWindowIsFixed(t *testing.T) {
	s, _ := aorShield(t, "2/1m")
	now := time.Unix(1_700_000_000, 0)
	s.aors.now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		s.StrikeAOR("a@x")
		now = now.Add(61 * time.Second)
	}
	if s.AORLocked("a@x") {
		t.Fatal("strikes spread over many windows locked the AoR")
	}
}

func TestAORClearAndOff(t *testing.T) {
	s, store := aorShield(t, "1/10m")
	s.StrikeAOR("a@x")
	s.StrikeAOR("a@x")
	if !s.AORLocked("a@x") {
		t.Fatal("not locked")
	}
	s.ClearAOR("a@x")
	if s.AORLocked("a@x") {
		t.Fatal("ClearAOR kept the lock")
	}
	s.StrikeAOR("a@x")
	s.StrikeAOR("a@x")
	next := *store.Current()
	next.Shield.RegisterBanAOR = "off"
	store.Replace(&next)
	if s.AORLocked("a@x") {
		t.Error("off keeps a lock")
	}
	if s.StrikeAOR("c@x") {
		t.Error("off counted")
	}
}

func TestAORTableCapped(t *testing.T) {
	s, _ := aorShield(t, "10/10m")
	s.aors.max = 64
	for i := 0; i < 5000; i++ {
		s.StrikeAOR(fmt.Sprintf("user%d@example.com", i))
	}
	if n := s.aors.size(); n != 64 {
		t.Errorf("table holds %d AoRs, want the cap 64", n)
	}
	// A very long key is truncated, so its memory is bounded too.
	s.StrikeAOR(strings.Repeat("a", 100000) + "@x")
	for _, e := range s.aors.live() {
		if len(e.key) > aorKeyMax {
			t.Fatalf("key of %d bytes stored", len(e.key))
		}
	}
}

func TestAOROffendersListed(t *testing.T) {
	s, _ := aorShield(t, "5/10m")
	for i := 0; i < 3; i++ {
		s.StrikeAOR("a@x")
	}
	top, total := s.Offenders(10)
	if total != 1 || len(top) != 1 || top[0].Source != "a@x" || top[0].Reason != StrikeRegisterAOR || top[0].Strikes != 3 {
		t.Errorf("offenders = %+v (%d)", top, total)
	}
}
