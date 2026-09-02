package trunk

import (
	"sync"
	"time"
)

// endpointHealth tracks per-endpoint cooldowns passively: a connect failure
// (failDial) Penalizes an endpoint, which then reports unavailable until the
// cooldown window elapses (lazy, no background sweeper) or a subsequent
// successful call Recovers it. Safe for concurrent use.
type endpointHealth struct {
	mu    sync.Mutex
	until map[string]time.Time // endpointKey → cooldown-until
	now   func() time.Time
}

func newEndpointHealth() *endpointHealth {
	return &endpointHealth{until: make(map[string]time.Time), now: time.Now}
}

// Available reports whether ep may be dialed now — true unless it is inside
// an unexpired cooldown window.
func (h *endpointHealth) Available(ep Endpoint) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.until[endpointKey(ep)]
	return !ok || !h.now().Before(t) // now >= t ⇒ expired ⇒ available
}

// Penalize starts (or extends) ep's cooldown window.
func (h *endpointHealth) Penalize(ep Endpoint, cooldown time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.until[endpointKey(ep)] = h.now().Add(cooldown)
}

// Recover clears any cooldown on ep, making it immediately available.
func (h *endpointHealth) Recover(ep Endpoint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.until, endpointKey(ep))
}
