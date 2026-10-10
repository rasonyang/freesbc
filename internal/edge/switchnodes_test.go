package edge

import (
	"testing"
	"time"
)

// SwitchNodes mirrors the passive cooldown: Penalize raises Cooling, a
// Recover or an expired window clears it.
func TestSwitchNodesCooldownRaiseAndClear(t *testing.T) {
	s := &Server{
		topo:             &topology{upstreamNames: []string{"10.0.0.1:5060", "10.0.0.2:5060"}},
		upstreamCooldown: newCooldownTable(),
	}
	cooling := func() map[string]bool {
		m := map[string]bool{}
		for _, n := range s.SwitchNodes() {
			m[n.Addr] = n.Cooling
		}
		return m
	}
	if got := cooling(); len(got) != 2 || got["10.0.0.1:5060"] || got["10.0.0.2:5060"] {
		t.Fatalf("fresh nodes = %v, want both not cooling", got)
	}
	s.upstreamCooldown.Penalize("10.0.0.1:5060", time.Minute)
	if got := cooling(); !got["10.0.0.1:5060"] || got["10.0.0.2:5060"] {
		t.Fatalf("after Penalize = %v, want only the first cooling", got)
	}
	s.upstreamCooldown.Recover("10.0.0.1:5060")
	if got := cooling(); got["10.0.0.1:5060"] {
		t.Fatalf("after Recover = %v, want none cooling", got)
	}
	s.upstreamCooldown.Penalize("10.0.0.2:5060", time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	if got := cooling(); got["10.0.0.2:5060"] {
		t.Fatalf("after expiry = %v, want none cooling", got)
	}
}
