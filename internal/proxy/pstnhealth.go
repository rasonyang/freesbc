package proxy

import (
	"sync"
	"time"
)

// pstnHealth tracks per-gateway cooldowns passively, mirroring the trunk
// plane's endpointHealth: a gateway that produced no response at all across
// a whole attempt (a failDial) is Penalized and then skipped in favour of
// alternatives until the cooldown window elapses — lazily, with no
// background sweeper — or a later successful call Recovers it. There is
// deliberately no active probing (no OPTIONS): a carrier gateway receives
// only the calls it is answering, and a health-check cadence of its own is
// exactly the sort of unsolicited traffic a carrier's edge will drop or
// penalize. Keyed by the configured gateway NAME (a bounded, operator-chosen
// set), not by address. Safe for concurrent use.
type pstnHealth struct {
	mu    sync.Mutex
	until map[string]time.Time // gateway name → cooldown-until
	now   func() time.Time     // injectable for tests
}

func newPSTNHealth() *pstnHealth {
	return &pstnHealth{until: make(map[string]time.Time), now: time.Now}
}

// Available reports whether the gateway may be dialed now — true unless it
// is inside an unexpired cooldown window.
func (h *pstnHealth) Available(gateway string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.until[gateway]
	return !ok || !h.now().Before(t) // now >= t ⇒ expired ⇒ available
}

// Penalize starts (or extends) the gateway's cooldown window.
func (h *pstnHealth) Penalize(gateway string, cooldown time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.until[gateway] = h.now().Add(cooldown)
}

// Recover clears any cooldown on the gateway, making it immediately
// available — a gateway that just answered a call is, by construction,
// healthy.
func (h *pstnHealth) Recover(gateway string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.until, gateway)
}
