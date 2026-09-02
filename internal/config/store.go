package config

import (
	"sync"
	"sync/atomic"
)

// Store publishes immutable *Config snapshots. Readers call Current and use
// that snapshot for the lifetime of one call/request (lock-free). The
// hot-reload path calls Replace, which also notifies Subscribe listeners.
type Store struct {
	p atomic.Pointer[Config]

	mu   sync.Mutex
	subs []chan struct{}
}

func NewStore(c *Config) *Store {
	s := &Store{}
	s.p.Store(c)
	return s
}

// Current returns the active config snapshot. Never nil.
func (s *Store) Current() *Config { return s.p.Load() }

// Replace atomically swaps in a new validated config and coalescing-notifies
// every Subscribe listener. In-flight calls keep the snapshot they hold.
func (s *Store) Replace(c *Config) {
	s.p.Store(c)
	s.mu.Lock()
	for _, ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default: // already has a pending signal — coalesce
		}
	}
	s.mu.Unlock()
}

// Subscribe returns a channel that receives a signal on each Replace. The
// channel is buffered(1) and sends are non-blocking, so a slow subscriber
// coalesces bursts and never blocks Replace. Intended for a long-lived
// reconciler (e.g. the registrar); there is no unsubscribe.
func (s *Store) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	return ch
}
