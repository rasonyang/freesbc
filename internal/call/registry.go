// Package call holds the in-memory table of active calls: the query
// surface behind metrics and the admin API. It stores plain call metadata
// (not the SIP or media objects), which is what keeps it free of any
// dependency on the signaling and media packages — and therefore usable
// from admin without dragging either plane in.
package call

import "sync"

// Record is one active call's metadata — deliberately just metadata:
// the SIP dialog and media objects live in the plane that owns them.
type Record struct {
	ID            string // A-leg Call-ID
	FromPeer      string
	ToPeer        string
	StartUnixNano int64
}

// Registry is a concurrency-safe table of active calls keyed by Call-ID.
type Registry struct {
	mu    sync.RWMutex
	calls map[string]Record
}

func NewRegistry() *Registry {
	return &Registry{calls: make(map[string]Record)}
}

// Add inserts or overwrites a call.
func (r *Registry) Add(c Record) {
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
func (r *Registry) Snapshot() []Record {
	r.mu.RLock()
	out := make([]Record, 0, len(r.calls))
	for _, c := range r.calls {
		out = append(out, c)
	}
	r.mu.RUnlock()
	return out
}
