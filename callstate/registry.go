// Package callstate holds the in-memory table of active calls: a query
// surface for metrics now and the admin API later (M7). It stores plain
// call metadata (not the SIP/media objects) so it has no dependency on the
// signaling or media packages.
package callstate

import "sync"

// Call is one active call's metadata.
type Call struct {
	ID            string // A-leg Call-ID
	FromPeer      string
	ToPeer        string
	StartUnixNano int64
}

// Registry is a concurrency-safe table of active calls keyed by Call-ID.
type Registry struct {
	mu    sync.RWMutex
	calls map[string]Call
}

func NewRegistry() *Registry {
	return &Registry{calls: make(map[string]Call)}
}

// Add inserts or overwrites a call.
func (r *Registry) Add(c Call) {
	r.mu.Lock()
	r.calls[c.ID] = c
	r.mu.Unlock()
}

// Remove deletes a call by ID; removing a missing ID is a no-op.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	delete(r.calls, id)
	r.mu.Unlock()
}

// Count returns the number of active calls.
func (r *Registry) Count() int {
	r.mu.RLock()
	n := len(r.calls)
	r.mu.RUnlock()
	return n
}

// Snapshot returns a copy of all active calls, for enumeration.
func (r *Registry) Snapshot() []Call {
	r.mu.RLock()
	out := make([]Call, 0, len(r.calls))
	for _, c := range r.calls {
		out = append(out, c)
	}
	r.mu.RUnlock()
	return out
}
