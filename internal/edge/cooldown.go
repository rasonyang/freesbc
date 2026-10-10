package edge

import (
	"sync"
	"time"
)

// cooldownTable tracks per-name cooldowns passively: a target that produced no response at all across a
// whole attempt (a failDial) is Penalized and then skipped in favour of
// alternatives until the cooldown window elapses — lazily, with no
// background sweeper — or a later successful exchange Recovers it. There is
// deliberately no active probing (no OPTIONS): an upstream
// switch receives only the traffic it is answering, and a
// health-check cadence of its own is exactly the sort of unsolicited traffic
// a carrier's edge will drop or penalize.
//
// Keyed by NAME, never by address (a bounded, operator-chosen name set).
// Safe for concurrent use.
type cooldownTable struct {
	mu    sync.Mutex
	until map[string]time.Time // name → cooldown-until
	// lastFail is when each name was last Penalized. Recover clears the
	// cooldown but keeps this, so an operator still sees the last failure.
	lastFail map[string]time.Time
}

func newCooldownTable() *cooldownTable {
	return &cooldownTable{until: make(map[string]time.Time), lastFail: make(map[string]time.Time)}
}

// Available reports whether the target may be used now — true unless it is
// inside an unexpired cooldown window.
func (h *cooldownTable) Available(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.until[name]
	return !ok || !time.Now().Before(t) // now >= t ⇒ expired ⇒ available
}

// Penalize starts (or extends) the target's cooldown window.
func (h *cooldownTable) Penalize(name string, cooldown time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.until[name] = now.Add(cooldown)
	h.lastFail[name] = now
}

// Recover clears any cooldown on the target, making it immediately
// available — a target that just answered is, by construction, healthy.
func (h *cooldownTable) Recover(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.until, name)
}

// Switch node states.
const (
	NodeHealthy     = "healthy"
	NodeCoolingDown = "cooling_down"
)

// SwitchNodeInfo is the operator view of one switch node's passive health.
type SwitchNodeInfo struct {
	Address string // "IP:port", the node's name
	State   string // NodeHealthy or NodeCoolingDown
	// CooldownRemaining and CooldownUntil are zero unless cooling down.
	CooldownRemaining time.Duration
	CooldownUntil     time.Time
	// LastFailure is when the node was last penalized; zero if never.
	LastFailure time.Time
}

// snapshot reports the state of each of names, in the order given, as of
// now. A name the table has never seen is healthy.
func (h *cooldownTable) snapshot(names []string, now time.Time) []SwitchNodeInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]SwitchNodeInfo, 0, len(names))
	for _, n := range names {
		info := SwitchNodeInfo{Address: n, State: NodeHealthy, LastFailure: h.lastFail[n]}
		if until, ok := h.until[n]; ok && now.Before(until) {
			info.State = NodeCoolingDown
			info.CooldownUntil = until
			info.CooldownRemaining = until.Sub(now)
		}
		out = append(out, info)
	}
	return out
}
