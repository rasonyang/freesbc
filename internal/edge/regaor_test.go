package edge

import (
	"net/netip"
	"testing"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Tests for the per-AoR REGISTER strike table (issue #187,
// shield.register_ban_aor). Timing-based over real UDP loopback: re-run once
// before treating a flake as failure.

const victimAOR = "victim@example.com"

// setRegisterBanAOR hot-reloads shield.register_ban_aor.
func setRegisterBanAOR(h *harness, v string) {
	next := *h.store.Current()
	next.Shield.RegisterBanAOR = v
	h.store.Replace(&next)
}

// strikeFromSource records one refused credential attempt for aor from the
// distinct public source 198.51.100.<i>, through the same path a relayed
// 401 takes (the nonce was relayed to that source, so it is countable).
func strikeFromSource(h *harness, i int, aor string) {
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 5060)
	h.srv.regGuard.challenged(src.Addr(), "b", []string{"n"})
	h.srv.registerStrike(src, fsip.RegisterHead{AOR: aor, Auth: true, Nonce: "n", Branch: "b",
		CallID: "cid", AuthKey: uint64(i)}, false)
}

func aorLocked(h *harness, aor string) bool { return h.srv.currentShield().AORLocked(aor) }

func aorDrops(h *harness) uint64 {
	return h.srv.metrics.Snapshot().AdmissionDrops["register_aor_locked"]
}

// registerOK registers user@example.com from c with a good credential.
func registerOK(t *testing.T, h *harness, c *client, user string) {
	t.Helper()
	if res := c.do(t, c.buildRegister(user, "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
		t.Fatalf("%s challenge: %d", user, res.StatusCode)
	}
	if res := c.do(t, c.buildRegister(user, "example.com", 600, digest(user, "abc123nonce", "right")), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("%s register: %d", user, res.StatusCode)
	}
}

// 12 refused attempts on one AoR from 12 distinct sources, each far under
// register_ban, open the AoR's limit: a binding-less source then gets no
// answer and the switch sees nothing, while the holder of a live binding of
// the AoR still refreshes and another AoR is untouched.
func TestRegisterAORLimitOpensAcrossSources(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	if v, ok := h.srv.metrics.Snapshot().AdmissionDrops["register_aor_locked"]; !ok || v != 0 {
		t.Fatalf("register_aor_locked not exported from zero: %v %v", v, ok)
	}
	holder := newUDPClient(t)
	registerOK(t, h, holder, "victim")

	for i := 1; i <= 12; i++ {
		strikeFromSource(h, i, victimAOR)
		if i <= 10 && aorLocked(h, victimAOR) {
			t.Fatalf("locked after %d strikes; the threshold is 10", i)
		}
	}
	if !aorLocked(h, victimAOR) {
		t.Fatal("12 refused attempts across 12 sources did not open the AoR limit")
	}
	for i := 1; i <= 12; i++ {
		if h.srv.currentShield().Banned(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})) {
			t.Fatalf("source %d was banned; each is under register_ban", i)
		}
	}
	top, _ := h.srv.Offenders(100)
	found := false
	for _, o := range top {
		if o.Reason == "register_aor" && o.Source == victimAOR && o.Strikes == 12 {
			found = true
		}
	}
	if !found {
		t.Errorf("offenders lack the AoR entry: %+v", top)
	}

	before := len(h.fs.received(sip.REGISTER))
	// The holder refreshes normally: forwarded, challenged.
	if res := holder.do(t, holder.buildRegister("victim", "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
		t.Fatalf("holder refresh: %d, want the switch's 401", res.StatusCode)
	}
	if got := len(h.fs.received(sip.REGISTER)); got != before+1 {
		t.Fatalf("holder refresh reached the switch %d times, want 1", got-before)
	}
	if aorDrops(h) != 0 {
		t.Fatal("the holder's REGISTER was counted as a drop")
	}
	if res := holder.do(t, holder.buildRegister("bystander", "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
		t.Fatalf("another AoR: %d, want 401", res.StatusCode)
	}
}

// A source with no live binding of the locked AoR is dropped silently, with
// nothing sent upstream, and the drop is not an admission strike.
func TestRegisterAORLockedDropsBindinglessSource(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	for i := 1; i <= 12; i++ {
		strikeFromSource(h, i, victimAOR)
	}
	c := newUDPClient(t)
	before := len(h.fs.received(sip.REGISTER))
	for i := 0; i < 3; i++ {
		expectSilence(t, c, c.buildRegister("victim", "example.com", 600, ""), h.publicUDP)
	}
	if got := len(h.fs.received(sip.REGISTER)); got != before {
		t.Fatalf("the switch saw %d REGISTERs for a locked AoR", got-before)
	}
	if n := aorDrops(h); n < 3 { // UDP retransmissions count too
		t.Errorf("register_aor_locked drops = %d, want at least 3", n)
	}
	// Not itself a strike: no source-keyed offender for 127.0.0.1.
	top, _ := h.srv.Offenders(100)
	for _, o := range top {
		if o.Source == guardSrc.String() {
			t.Errorf("the drop struck the source: %+v", o)
		}
	}
	// Another AoR from the same source is served.
	if res := c.do(t, c.buildRegister("bystander", "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
		t.Fatalf("another AoR: %d", res.StatusCode)
	}
}

// End to end: real refused attempts open the limit, with register_ban set
// out of reach so only the per-AoR count can act.
func TestRegisterAORLimitCountsRealAttempts(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setRegisterBan(h, "1000/10m")
	setRegisterBanAOR(h, "3/10m")
	setAuthStatus(h, 401)
	c := newUDPClient(t)
	for i := 0; i < 4; i++ {
		if code := challengeThenGuess(t, h, c, "v", i); code != 401 {
			t.Fatalf("guess %d: %d", i, code)
		}
	}
	if bannedLoopback(h) {
		t.Fatal("register_ban acted")
	}
	if !aorLocked(h, "v@example.com") {
		t.Fatal("4 refused attempts over 3/10m did not open the AoR limit")
	}
	expectSilence(t, c, c.buildRegister("v", "example.com", 600, ""), h.publicUDP)
}

// A 2xx for the AoR clears its count and lifts an open limit.
func TestRegisterAOR2xxClears(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	holder := newUDPClient(t)
	registerOK(t, h, holder, "victim")
	for i := 1; i <= 12; i++ {
		strikeFromSource(h, i, victimAOR)
	}
	if !aorLocked(h, victimAOR) {
		t.Fatal("not locked")
	}
	// The holder's refresh succeeds at the switch.
	if res := holder.do(t, holder.buildRegister("victim", "example.com", 600, digest("victim", "abc123nonce", "right")), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("refresh: %d", res.StatusCode)
	}
	if aorLocked(h, victimAOR) {
		t.Fatal("a 2xx did not lift the lock")
	}
	top, _ := h.srv.Offenders(100)
	for _, o := range top {
		if o.Reason == "register_aor" {
			t.Fatalf("a 2xx left the AoR count: %+v", o)
		}
	}
}

// A carrier source is never limited.
func TestRegisterAORCarrierSourceNeverLimited(t *testing.T) {
	h := startHarness(t, false) // 127.0.0.1 is a carrier source
	for i := 1; i <= 12; i++ {
		strikeFromSource(h, i, victimAOR)
	}
	c := newUDPClient(t)
	if res := c.do(t, c.buildRegister("victim", "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
		t.Fatalf("carrier source: %d, want 401", res.StatusCode)
	}
	if aorDrops(h) != 0 {
		t.Error("a carrier source was dropped")
	}
	// And its own refused attempts never count.
	setAuthStatus(h, 401)
	for i := 0; i < 15; i++ {
		challengeThenGuess(t, h, c, "carrieruser", i)
	}
	if aorLocked(h, "carrieruser@example.com") {
		t.Error("a carrier source opened an AoR limit")
	}
}

// "off" stops counting and dropping; a reload changes the threshold.
func TestRegisterAORHotReloadAndOff(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setRegisterBanAOR(h, "off")
	for i := 1; i <= 20; i++ {
		strikeFromSource(h, i, victimAOR)
	}
	if aorLocked(h, victimAOR) {
		t.Fatal("off locked an AoR")
	}
	top, _ := h.srv.Offenders(100)
	for _, o := range top {
		if o.Reason == "register_aor" {
			t.Fatalf("off counted AoR strikes: %+v", o)
		}
	}
	setRegisterBanAOR(h, "2/10m")
	for i := 21; i <= 23; i++ {
		strikeFromSource(h, i, victimAOR)
	}
	if !aorLocked(h, victimAOR) {
		t.Fatal("the reloaded 2/10m threshold was not applied")
	}
	c := newUDPClient(t)
	expectSilence(t, c, c.buildRegister("victim", "example.com", 600, ""), h.publicUDP)
	setRegisterBanAOR(h, "off")
	if res := c.do(t, c.buildRegister("victim", "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
		t.Fatalf("after off: %d, want 401", res.StatusCode)
	}
}
