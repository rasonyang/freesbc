package shield

import (
	"container/list"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// Per-AoR REGISTER strikes (shield.register_ban_aor, issue #187). A
// distributed low-and-slow brute force spreads refused credentials for one
// AoR across many source IPs, each under shield.register_ban, so nothing is
// ever banned by source. The AoR table counts the same refused attempts per
// AoR; over the threshold the AoR's limit is open for shield.ban and the
// edge drops REGISTERs for it from sources that hold no live binding of it.

// StrikeRegisterAOR is the reason AoR entries carry in the offender list.
const StrikeRegisterAOR = "register_aor"

const (
	// aorCap bounds the AoR table. AoRs are attacker-chosen strings, so a
	// flood of distinct ones only evicts the least recently struck, and
	// not a locked one while an unlocked one is near the back.
	aorCap = 16384
	// aorEvictScan is how many entries from the back of the LRU a full
	// table looks through for one that is not locked before it gives up
	// and evicts the back entry.
	aorEvictScan = 64
	// aorKeyMax caps a key's length. A longer AoR (the edge never admits one:
	// fsip.NormalizeAOR allows 128+1+255 bytes at most) is cut to it.
	aorKeyMax = 384
)

// aorEntry is one AoR's strikes in a short and a long fixed window, each
// opening at its first strike, and the end of its lock once either stage's
// threshold was crossed.
type aorEntry struct {
	key         string
	short, long strikeStage
	locked      time.Time // zero, or when the limit closes again
}

type aorTable struct {
	mu      sync.Mutex
	entries map[string]*list.Element // of *aorEntry
	lru     *list.List               // front = most recently struck
	max     int
	now     func() time.Time
}

func newAORTable() *aorTable {
	return &aorTable{entries: map[string]*list.Element{}, lru: list.New(), max: aorCap, now: time.Now}
}

func aorKey(aor string) string {
	if len(aor) > aorKeyMax {
		aor = aor[:aorKeyMax]
	}
	return aor
}

// strike adds one strike to every enabled stage (the short stage under
// short, which the caller has checked is usable, and the long stage under
// long when that is usable). When either crosses its N the AoR is locked
// until now+ban; the lock is not extended. It returns the verdict (over =
// the AoR is locked, crossed = this strike opened the lock).
func (t *aorTable) strike(aor string, short, long config.StrikeLimit, ban time.Duration) strikeVerdict {
	key := aorKey(aor)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var e *aorEntry
	if el, ok := t.entries[key]; ok {
		e = el.Value.(*aorEntry)
		t.lru.MoveToFront(el)
		if !e.locked.IsZero() && !now.Before(e.locked) {
			e.short, e.long, e.locked = strikeStage{}, strikeStage{}, time.Time{}
		}
	} else {
		if t.lru.Len() >= t.max {
			victim := t.evictable(now)
			delete(t.entries, victim.Value.(*aorEntry).key)
			t.lru.Remove(victim)
		}
		e = &aorEntry{key: key}
		t.entries[key] = t.lru.PushFront(e)
	}
	// A stage keeps its window while the lock is open, as it always has.
	keep := !e.locked.IsZero()
	sOver, sCross := e.short.add(now, "", short, keep)
	var lOver, lCross bool
	if usableLimit(long) {
		lOver, lCross = e.long.add(now, "", long, keep)
	}
	v := verdict(&e.short, &e.long, sOver, sCross, lOver, lCross)
	if keep {
		v.over, v.crossed = true, false
		return v
	}
	if v.over {
		e.locked = now.Add(ban)
		v.crossed = true
	}
	return v
}

// evictable picks the entry a full table drops: the least recently struck
// one that is not locked at now among the last aorEvictScan, else the back
// entry, so the cap always holds. A locked AoR is no longer struck, so it
// drifts to the back and would otherwise be the first to go.
func (t *aorTable) evictable(now time.Time) *list.Element {
	el := t.lru.Back()
	for i := 0; el != nil && i < aorEvictScan; i, el = i+1, el.Prev() {
		if e := el.Value.(*aorEntry); e.locked.IsZero() || !now.Before(e.locked) {
			return el
		}
	}
	return t.lru.Back()
}

func (t *aorTable) isLocked(aor string) bool {
	key := aorKey(aor)
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.entries[key]
	if !ok {
		return false
	}
	e := el.Value.(*aorEntry)
	return !e.locked.IsZero() && t.now().Before(e.locked)
}

func (t *aorTable) clear(aor string) {
	key := aorKey(aor)
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.entries[key]; ok {
		delete(t.entries, key)
		t.lru.Remove(el)
	}
}

// expired reports whether e no longer matters at now.
func (e *aorEntry) expired(now time.Time) bool {
	if !e.locked.IsZero() {
		return !now.Before(e.locked)
	}
	return !e.short.open(now) && !e.long.open(now)
}

func (t *aorTable) prune() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, el := range t.entries {
		if el.Value.(*aorEntry).expired(now) {
			delete(t.entries, k)
			t.lru.Remove(el)
		}
	}
}

func (t *aorTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// live copies the entries still counting or locked. A locked entry reports
// its stages as stored (they stop resetting while the lock is open); an
// unlocked one reports only the stages whose window is open.
func (t *aorTable) live() []aorEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out := make([]aorEntry, 0, len(t.entries))
	for _, el := range t.entries {
		e := el.Value.(*aorEntry)
		if e.expired(now) {
			continue
		}
		row := *e
		if e.locked.IsZero() {
			if !row.short.open(now) {
				row.short = strikeStage{}
			}
			if !row.long.open(now) {
				row.long = strikeStage{}
			}
		}
		out = append(out, row)
	}
	return out
}

// StrikeAOR records one refused REGISTER credential attempt against aor
// (a normalised "user@host") and reports whether the AoR's limit is open as
// a result. Over shield.register_ban_aor the limit opens for shield.ban,
// with one WARN naming the AoR. A threshold of "off" counts nothing. The
// caller makes the strike trustworthy and exempts carrier sources and
// refreshes of a live binding, as for Strike.
func (s *Shield) StrikeAOR(aor string) bool {
	if aor == "" {
		return false
	}
	cfg := s.store.Current()
	lim, long := s.strikeLimits(cfg, StrikeRegisterAOR)
	if !usableLimit(lim) {
		return false
	}
	v := s.aors.strike(aor, lim, long, cfg.Shield.Ban.Std())
	if v.crossed {
		s.log.Warn("shield locked AoR for repeated failed REGISTER credentials; REGISTERs for it from sources without a live binding are dropped",
			"aor", aor, "stage", v.stage, "strikes", v.count, "window", v.window.String(), "lock", cfg.Shield.Ban.Std().String())
	}
	return v.over
}

// AORLocked reports whether aor's limit is open: a REGISTER for it from a
// source with no live binding of it is to be dropped. Always false while
// shield.register_ban_aor is "off" (read hot, so a reload that turns it off
// lifts every lock at once).
func (s *Shield) AORLocked(aor string) bool {
	if aor == "" {
		return false
	}
	if lim := s.strikeLimit(s.store.Current(), StrikeRegisterAOR); !usableLimit(lim) {
		return false
	}
	return s.aors.isLocked(aor)
}

// ClearAOR forgets aor's strikes and lifts its lock: a 2xx REGISTER for it
// proved the credentials work.
func (s *Shield) ClearAOR(aor string) { s.aors.clear(aor) }
