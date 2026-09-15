package edge

import (
	"sync"
	"time"
)

// cooldownTable tracks per-name cooldowns passively, mirroring the trunk
// plane's endpointHealth: a target that produced no response at all across a
// whole attempt (a failDial) is Penalized and then skipped in favour of
// alternatives until the cooldown window elapses — lazily, with no
// background sweeper — or a later successful exchange Recovers it. There is
// deliberately no active probing (no OPTIONS): a carrier gateway or an
// upstream switch receives only the traffic it is answering, and a
// health-check cadence of its own is exactly the sort of unsolicited traffic
// a carrier's edge will drop or penalize.
//
// One type, two instances: the PSTN gateway cooldown and the upstream node
// cooldown are the same policy over the same shape (a bounded,
// operator-chosen name set), and duplicating the logic would let the two
// drift apart. Keyed by NAME, never by address. Safe for concurrent use.
type cooldownTable struct {
	mu    sync.Mutex
	until map[string]time.Time // name → cooldown-until
}

func newCooldownTable() *cooldownTable {
	return &cooldownTable{until: make(map[string]time.Time)}
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
	h.until[name] = time.Now().Add(cooldown)
}

// Recover clears any cooldown on the target, making it immediately
// available — a target that just answered is, by construction, healthy.
func (h *cooldownTable) Recover(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.until, name)
}
