package edge

// regbreaker_test.go covers the per-node REGISTER circuit breaker (issue
// #182): a switch node that answered nothing registerBreakerThreshold times
// in a row is no longer dialed for a REGISTER until its window passes.
//
// The unanswered attempts are produced the deterministic way the failover
// tests do (see startHarnessSwitches): a dead node address fails the send
// at once, so no test waits out registerTimeout. The breaker counts that
// exactly like a silent node.

import (
	"fmt"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

func allowed(h *cooldownTable, n string, d time.Duration) bool {
	ok, _ := h.RegisterAllow(n, d)
	return ok
}

// probeAttempt admits a half-open probe (its window already over) and
// reports it failed, returning the breaker's verdict.
func probeAttempt(t *testing.T, h *cooldownTable, n string) (opened bool, window time.Duration) {
	t.Helper()
	h.mu.Lock()
	h.reg[n].openUntil = time.Now().Add(-time.Second)
	h.mu.Unlock()
	ok, probe := h.RegisterAllow(n, time.Minute)
	if !ok || !probe {
		t.Fatalf("half-open breaker: allow=%v probe=%v, want the probe admitted", ok, probe)
	}
	opened, window, _ = h.RegisterUnanswered(n, probe)
	return opened, window
}

func TestRegisterBreakerTable(t *testing.T) {
	h := newCooldownTable()
	const n = "10.0.0.1:5060"

	for i := 1; i < registerBreakerThreshold; i++ {
		opened, _, _ := h.RegisterUnanswered(n, false)
		if opened {
			t.Fatalf("attempt %d opened the breaker below the threshold", i)
		}
		if !allowed(h, n, time.Second) {
			t.Fatalf("attempt %d: node refused below the threshold", i)
		}
	}
	// A response in between resets the run: the failures must be consecutive.
	h.RegisterAnswered(n)
	for i := 1; i < registerBreakerThreshold; i++ {
		if opened, _, _ := h.RegisterUnanswered(n, false); opened {
			t.Fatal("breaker opened although an answer reset the count")
		}
	}

	opened, window, _ := h.RegisterUnanswered(n, false)
	if !opened || window != registerBreakerBackoff[0] {
		t.Fatalf("threshold attempt: opened=%v window=%v, want open for %v", opened, window, registerBreakerBackoff[0])
	}
	if allowed(h, n, time.Second) {
		t.Fatal("open breaker admitted a REGISTER")
	}

	// Window over: exactly one probe is admitted, the rest wait for it.
	h.reg[n].openUntil = time.Now().Add(-time.Second)
	if ok, probe := h.RegisterAllow(n, time.Minute); !ok || !probe {
		t.Fatal("half-open breaker refused the probe")
	}
	if allowed(h, n, time.Minute) {
		t.Fatal("half-open breaker admitted a second concurrent probe")
	}

	// A released probe (never sent) frees the slot at once.
	h.RegisterRelease(n)
	if ok, probe := h.RegisterAllow(n, time.Minute); !ok || !probe {
		t.Fatal("released probe slot was not reusable")
	}

	// The probe fails: re-open with the next, longer window.
	opened, window, _ = h.RegisterUnanswered(n, true)
	if !opened || window != registerBreakerBackoff[1] {
		t.Fatalf("failed probe: opened=%v window=%v, want open for %v", opened, window, registerBreakerBackoff[1])
	}
	for i := 0; i < 5; i++ {
		_, window = probeAttempt(t, h, n)
	}
	if want := registerBreakerBackoff[len(registerBreakerBackoff)-1]; window != want {
		t.Fatalf("backoff cap = %v, want %v", window, want)
	}

	// Any answer closes it at once and resets the backoff.
	h.RegisterAnswered(n)
	if !allowed(h, n, time.Second) {
		t.Fatal("breaker still refusing after an answer")
	}
	for i := 0; i < registerBreakerThreshold; i++ {
		_, window, _ = h.RegisterUnanswered(n, false)
	}
	if window != registerBreakerBackoff[0] {
		t.Fatalf("window after a close = %v, want %v", window, registerBreakerBackoff[0])
	}
}

// Attempts dialed before the breaker opened finish unanswered while it is
// open (a real outage has many REGISTERs in flight). They must not count as
// failed probes: no escalation, no forced WARN. Only a real probe escalates.
func TestRegisterBreakerInFlightAttemptsAreNotProbes(t *testing.T) {
	h := newCooldownTable()
	const n = "10.0.0.2:5060"
	opens := 0
	for i := 0; i < registerBreakerThreshold; i++ {
		if opened, _, _ := h.RegisterUnanswered(n, false); opened {
			opens++
		}
	}
	for i := 0; i < 47; i++ {
		opened, window, _ := h.RegisterUnanswered(n, false)
		if opened {
			opens++
		}
		if window != 0 {
			t.Fatalf("in-flight completion changed the window to %v", window)
		}
	}
	if opens != 1 {
		t.Fatalf("breaker reported opening %d times, want 1", opens)
	}
	if lvl := h.reg[n].level; lvl != 1 {
		t.Fatalf("level = %d after in-flight completions, want 1", lvl)
	}
	if allowed(h, n, time.Second) {
		t.Fatal("breaker stopped being open")
	}
	if opened, window := probeAttempt(t, h, n); !opened || window != registerBreakerBackoff[1] {
		t.Fatalf("failed probe: opened=%v window=%v, want %v", opened, window, registerBreakerBackoff[1])
	}
}

// The unanswered WARN is bounded: one per node per window, plus one each
// time the breaker opens.
func TestRegisterBreakerWarnThrottle(t *testing.T) {
	h := newCooldownTable()
	w1 := 0
	for i := 0; i < registerBreakerThreshold-1; i++ {
		if _, _, w := h.RegisterUnanswered("n", false); w {
			w1++
		}
	}
	if w1 != 1 {
		t.Fatalf("non-opening failures logged %d WARNs in one window, want 1", w1)
	}
}

func TestRegisterBreakerEndToEnd(t *testing.T) {
	const dead = "10.255.255.1:5060"
	h, _ := startHarnessSwitches(t, []string{dead})
	phone := newUDPClient(t)
	register := func(i int) *sip.Response {
		return phone.do(t, phone.buildRegister(fmt.Sprintf("u%d", i), "example.com", 600, ""), h.publicUDP)
	}

	// Below the threshold nothing changes: each attempt is dialed and the
	// phone gets the plain synthesized 503.
	for i := 0; i < registerBreakerThreshold; i++ {
		res := register(i)
		if res.StatusCode != 503 {
			t.Fatalf("attempt %d: got %d, want 503", i, res.StatusCode)
		}
		if i < registerBreakerThreshold-1 && res.GetHeader("Retry-After") != nil {
			t.Fatalf("attempt %d: Retry-After on a dialed attempt", i)
		}
	}
	m := h.srv.metrics.Snapshot()
	if m.RegisterUnanswered != uint64(registerBreakerThreshold) || m.RegisterBreakerRejects != 0 {
		t.Fatalf("after %d dials: unanswered=%d rejects=%d", registerBreakerThreshold, m.RegisterUnanswered, m.RegisterBreakerRejects)
	}

	// Now open: answered locally with a Retry-After, not dialed, and the
	// unanswered count does not grow.
	res := register(100)
	if res.StatusCode != 503 {
		t.Fatalf("open breaker: got %d, want 503", res.StatusCode)
	}
	if ra := res.GetHeader("Retry-After"); ra == nil || ra.Value() != "30" {
		t.Fatalf("open breaker: Retry-After = %v, want 30", ra)
	}
	m = h.srv.metrics.Snapshot()
	if m.RegisterUnanswered != uint64(registerBreakerThreshold) || m.RegisterBreakerRejects != 1 {
		t.Fatalf("after the open reject: unanswered=%d rejects=%d", m.RegisterUnanswered, m.RegisterBreakerRejects)
	}
	nodes := h.srv.SwitchNodes()
	if len(nodes) != 1 || nodes[0].State != NodeCoolingDown {
		t.Fatalf("switch nodes = %+v, want cooling_down", nodes)
	}
}

// With a pool the breaker stops dialing the dead node but not failover, and
// an answer from the node (here a 401) closes it again.
func TestRegisterBreakerPoolFailoverAndRecovery(t *testing.T) {
	addrA := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	addrB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h, switches := startHarnessSwitches(t, []string{addrA, addrB})
	fsA, fsB := switches[addrA], switches[addrB]
	idxA := nodeIndex(t, h.srv.topo, addrA)
	userA := userForNode(t, h.srv.topo, idxA)

	// Open A's breaker as a run of silent attempts would.
	for i := 0; i < registerBreakerThreshold; i++ {
		h.srv.upstreamCooldown.RegisterUnanswered(addrA, false)
	}
	phone := newUDPClient(t)
	res := phone.do(t, phone.buildRegister(userA, "example.com", 600, ""), h.publicUDP)
	if res.StatusCode != 401 {
		t.Fatalf("got %d, want the 401 from the live node", res.StatusCode)
	}
	if got := len(fsB.waitFor(sip.REGISTER, 1, 3*time.Second)); got != 1 {
		t.Fatalf("fs-b saw %d REGISTERs, want 1", got)
	}
	if got := len(fsA.received(sip.REGISTER)); got != 0 {
		t.Fatalf("fs-a saw %d REGISTERs while its breaker was open", got)
	}

	// Window over: the next attempt probes A, whose 401 closes the breaker.
	h.srv.upstreamCooldown.mu.Lock()
	h.srv.upstreamCooldown.reg[addrA].openUntil = time.Now().Add(-time.Second)
	h.srv.upstreamCooldown.mu.Unlock()
	res = phone.do(t, phone.buildRegister(userA, "example.com", 600, ""), h.publicUDP)
	if res.StatusCode != 401 {
		t.Fatalf("probe: got %d, want 401", res.StatusCode)
	}
	if got := len(fsA.waitFor(sip.REGISTER, 1, 3*time.Second)); got != 1 {
		t.Fatalf("fs-a saw %d REGISTERs, want the one probe", got)
	}
	// The server relays the final response first and closes the breaker
	// after, so the phone having the 401 does not mean it is closed yet.
	// Poll the state under the lock; RegisterAllow would take the half-open
	// probe slot.
	var open bool
	var fails int
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		h.srv.upstreamCooldown.mu.Lock()
		b := h.srv.upstreamCooldown.reg[addrA]
		open, fails = b.open, b.fails
		h.srv.upstreamCooldown.mu.Unlock()
		if !open || time.Now().After(deadline) {
			break
		}
	}
	if open || fails != 0 {
		t.Fatalf("a 401 did not close the breaker: open=%v fails=%d", open, fails)
	}
	if !allowed(h.srv.upstreamCooldown, addrA, registerTimeout) {
		t.Fatal("a closed breaker did not allow a REGISTER")
	}
}
