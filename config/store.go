package config

import "sync/atomic"

// Store publishes immutable *Config snapshots. Readers call Current and use
// that snapshot for the lifetime of one call/request; the hot-reload path
// calls Replace. Both are lock-free.
type Store struct {
	p atomic.Pointer[Config]
}

func NewStore(c *Config) *Store {
	s := &Store{}
	s.p.Store(c)
	return s
}

// Current returns the active config snapshot. Never nil.
func (s *Store) Current() *Config { return s.p.Load() }

// Replace atomically swaps in a new validated config. In-flight calls keep
// the snapshot they already hold.
func (s *Store) Replace(c *Config) { s.p.Store(c) }
