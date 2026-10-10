package admin

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"
)

// HealthSeverity is how bad an active condition is. The overall status is
// the worst severity among the active conditions, or "ok" with none.
type HealthSeverity string

const (
	HealthDegraded HealthSeverity = "degraded"
	HealthCritical HealthSeverity = "critical"

	// healthOK is the overall status with no active condition. It is never
	// a condition's severity.
	healthOK = "ok"
)

// rank orders severities; an unknown value counts as degraded so a bad
// closure can neither hide a condition nor invent a worse status.
func (v HealthSeverity) rank() int {
	if v == HealthCritical {
		return 2
	}
	return 1
}

// norm maps an unknown severity to degraded.
func (v HealthSeverity) norm() HealthSeverity {
	if v == HealthCritical {
		return HealthCritical
	}
	return HealthDegraded
}

// HealthCondition is one raw active condition, as Deps.Health reports it:
// derived from live state on each call, with no memory. The tracker adds
// when it first appeared and records the transitions.
type HealthCondition struct {
	// ID is stable for as long as the condition is the same one, for
	// example "switch_cooldown:10.77.0.10:5060".
	ID       string
	Severity HealthSeverity
	Message  string
	// Detail is optional extra text for the operator.
	Detail string
}

// ActiveCondition is a HealthCondition with the time it was first seen
// active; it is the /api/health conditions entry.
type ActiveCondition struct {
	ID       string         `json:"id"`
	Severity HealthSeverity `json:"severity"`
	Message  string         `json:"message"`
	Since    time.Time      `json:"since"`
	Detail   string         `json:"detail,omitempty"`
}

// HealthEventType is what a history entry records.
type HealthEventType string

const (
	HealthRaised  HealthEventType = "raised"
	HealthCleared HealthEventType = "cleared"
	// HealthChanged is a severity change of a condition that stayed active;
	// its Since is kept.
	HealthChanged HealthEventType = "changed"
)

// HealthEvent is one raise, clear or severity change. For a cleared event
// Severity and Message are the condition's last values.
type HealthEvent struct {
	Time     time.Time       `json:"time"`
	ID       string          `json:"id"`
	Event    HealthEventType `json:"event"`
	Severity HealthSeverity  `json:"severity"`
	Message  string          `json:"message"`
}

const (
	// healthRingSize is how many events the in-memory history keeps; the
	// oldest is dropped first. A restart clears it.
	healthRingSize = 200
	// healthInterval is how often the tracker evaluates with nobody polling,
	// so the history and each since are accurate to this granularity.
	healthInterval = 5 * time.Second
)

// healthTracker turns the stateless Deps.Health into active conditions with
// a since time and a bounded transition history. All state sits behind one
// mutex, held across the closure call too, so two concurrent evaluations
// cannot apply their results out of order.
type healthTracker struct {
	src func() []HealthCondition // nil: nothing is ever active
	now func() time.Time         // nil is time.Now

	mu     sync.Mutex
	active map[string]ActiveCondition
	buf    [healthRingSize]HealthEvent
	start  int // index of the oldest event
	n      int // number of events held
}

func (t *healthTracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// push appends an event to the ring. The caller holds mu.
func (t *healthTracker) push(ev HealthEvent) {
	if t.n < healthRingSize {
		t.buf[(t.start+t.n)%healthRingSize] = ev
		t.n++
		return
	}
	t.buf[t.start] = ev
	t.start = (t.start + 1) % healthRingSize
}

// evaluate reads the live conditions, records the transitions since the
// last evaluation and returns the active conditions, worst first then by id.
// Never nil.
func (t *healthTracker) evaluate() []ActiveCondition {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock().UTC()

	var raw []HealthCondition
	if t.src != nil {
		raw = t.src()
	}
	// A duplicate id keeps its worst severity.
	cur := make(map[string]HealthCondition, len(raw))
	for _, c := range raw {
		c.Severity = c.Severity.norm()
		if old, ok := cur[c.ID]; ok && old.Severity.rank() >= c.Severity.rank() {
			continue
		}
		cur[c.ID] = c
	}
	if t.active == nil {
		t.active = make(map[string]ActiveCondition)
	}

	for id, c := range cur {
		prev, was := t.active[id]
		switch {
		case !was:
			t.active[id] = ActiveCondition{ID: id, Severity: c.Severity, Message: c.Message, Since: now, Detail: c.Detail}
			t.push(HealthEvent{Time: now, ID: id, Event: HealthRaised, Severity: c.Severity, Message: c.Message})
		case prev.Severity != c.Severity:
			t.active[id] = ActiveCondition{ID: id, Severity: c.Severity, Message: c.Message, Since: prev.Since, Detail: c.Detail}
			t.push(HealthEvent{Time: now, ID: id, Event: HealthChanged, Severity: c.Severity, Message: c.Message})
		default:
			// Same condition: the text may move (a count, an age) without
			// being a transition.
			prev.Message, prev.Detail = c.Message, c.Detail
			t.active[id] = prev
		}
	}
	// Cleared conditions, in id order so the history is deterministic.
	var gone []string
	for id := range t.active {
		if _, ok := cur[id]; !ok {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	for _, id := range gone {
		prev := t.active[id]
		delete(t.active, id)
		t.push(HealthEvent{Time: now, ID: id, Event: HealthCleared, Severity: prev.Severity, Message: prev.Message})
	}

	out := make([]ActiveCondition, 0, len(t.active))
	for _, c := range t.active {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := out[i].Severity.rank(), out[j].Severity.rank(); ri != rj {
			return ri > rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// history returns the events newest first; never nil.
func (t *healthTracker) history() []HealthEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]HealthEvent, 0, t.n)
	for i := t.n - 1; i >= 0; i-- {
		out = append(out, t.buf[(t.start+i)%healthRingSize])
	}
	return out
}

// healthStatus is the overall status of a set of active conditions: the
// worst severity, or "ok" with none.
func healthStatus(conds []ActiveCondition) string {
	status := healthOK
	for _, c := range conds {
		if c.Severity == HealthCritical {
			return string(HealthCritical)
		}
		status = string(HealthDegraded)
	}
	return status
}

// healthLevel is the freesbc_admin_health_status gauge value: 0 ok,
// 1 degraded, 2 critical.
func healthLevel(status string) float64 {
	switch status {
	case string(HealthCritical):
		return 2
	case string(HealthDegraded):
		return 1
	}
	return 0
}

// run evaluates every interval until ctx ends, so history and since stay
// accurate with nobody polling.
func (t *healthTracker) run(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	t.evaluate()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.evaluate()
		}
	}
}

// handleHealth serves GET /api/health: the overall status and the active
// conditions, always an array.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	conds := s.health.evaluate()
	writeJSON(w, map[string]any{"status": healthStatus(conds), "conditions": conds})
}

// handleHealthHistory serves GET /api/health/history: the raise, clear and
// change events, newest first like /api/audit, always an array. It
// evaluates first so a transition that just happened is in it.
func (s *Server) handleHealthHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.health.evaluate()
	writeJSON(w, map[string]any{"events": s.health.history()})
}
