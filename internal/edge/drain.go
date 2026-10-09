package edge

import (
	"sync"
	"sync/atomic"
	"time"
)

// drainState is the edge's drain (maintenance) mode: while on, every new
// out-of-dialog INVITE is refused in beginDialog with 503 + Retry-After
// (rejectDraining), so a restart can wait for the live calls to end.
//
// It is runtime state only. It is not in config, is not persisted, and a
// restart starts not draining. Everything that belongs to a call or
// registration already in place is unchanged: re-INVITE and every other
// in-dialog request, REGISTER, OPTIONS, SUBSCRIBE/NOTIFY/MESSAGE/REFER and
// RTP. The switch is not exempt: a switch-originated INVITE (a transfer
// leg, a call to a client or carrier) is refused like any other.
type drainState struct {
	flag  atomic.Bool // read lock-free on every new INVITE
	mu    sync.Mutex  // serialises set and get; guards since
	since time.Time
}

// on reports whether the edge is draining.
func (d *drainState) on() bool { return d.flag.Load() }

// set enters or leaves drain and reports whether the state changed. Entering
// while already draining keeps the original since time.
func (d *drainState) set(on bool) (changed bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.flag.Load() == on {
		return false
	}
	if on {
		d.since = time.Now()
	} else {
		d.since = time.Time{}
	}
	d.flag.Store(on)
	return true
}

// get returns the state and, while draining, when it was entered.
func (d *drainState) get() (draining bool, since time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flag.Load(), d.since
}
