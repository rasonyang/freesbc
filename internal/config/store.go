package config

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Store publishes immutable *Config snapshots. Readers call Current and use
// that snapshot for the lifetime of one call/request (lock-free). The
// hot-reload path calls Replace.
type Store struct {
	p atomic.Pointer[Config]

	rmu    sync.Mutex
	reload ReloadStatus
}

// ReloadStatus is what the file watcher last did, kept for the life of the
// process (no persistence) so the admin surface can tell an operator whether
// the running process and the file on disk still agree.
type ReloadStatus struct {
	// LastOK is when the last reload was published; zero until one happens.
	LastOK time.Time
	// RestartRequired is the sorted RestartOnlyChanges(boot, current) after
	// the last successful reload: restart-only keys whose file value the
	// running process does not use yet. Never nil.
	RestartRequired []string
	// LastError and LastErrorAt describe the last reload that failed to load
	// or validate; both are zero after the next successful reload. A failure
	// leaves RestartRequired as it was, since the snapshot did not change.
	LastError   string
	LastErrorAt time.Time
}

// ReloadStatus returns a copy of the watcher's last outcome. Safe for
// concurrent use.
func (s *Store) ReloadStatus() ReloadStatus {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	st := s.reload
	st.RestartRequired = slices.Clone(st.RestartRequired)
	if st.RestartRequired == nil {
		st.RestartRequired = []string{}
	}
	return st
}

// reloadOK records a published reload. Called only by Watch.
func (s *Store) reloadOK(at time.Time, restartRequired []string) {
	s.rmu.Lock()
	s.reload = ReloadStatus{LastOK: at, RestartRequired: slices.Clone(restartRequired)}
	s.rmu.Unlock()
}

// reloadFailed records a rejected reload, keeping the rest. Called only by
// Watch.
func (s *Store) reloadFailed(at time.Time, err error) {
	s.rmu.Lock()
	s.reload.LastError = err.Error()
	s.reload.LastErrorAt = at
	s.rmu.Unlock()
}

func NewStore(c *Config) *Store {
	s := &Store{}
	s.p.Store(c)
	return s
}

// Current returns the active config snapshot. Never nil.
func (s *Store) Current() *Config { return s.p.Load() }

// Replace atomically swaps in a new validated config. In-flight calls keep
// the snapshot they hold.
func (s *Store) Replace(c *Config) { s.p.Store(c) }
