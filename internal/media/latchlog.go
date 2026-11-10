package media

import (
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// rejectLogInterval is the shortest gap between two "rejected by latch"
// WARNs of one session.
const rejectLogInterval = time.Second

// rejectLogPerPlane is how many of those WARNs one PlanePool lets through
// per second, summed over its sessions: the RTP range is internet-facing,
// and a scanner sweeping it must not make every latched session log.
const rejectLogPerPlane = 10

// planeBudget is a pool's fixed one-second window of rejectLogPerPlane
// lines. At most one line per session per second reaches it, so a mutex is
// cheap enough.
type planeBudget struct {
	now   func() time.Time // nil = time.Now
	mu    sync.Mutex
	start time.Time
	used  int
	held  uint64 // lines refused since the last one let through
}

// allow takes one line from the current window. When it succeeds, held is
// the number of lines the cap refused since the previous line.
func (b *planeBudget) allow() (held uint64, ok bool) {
	now := time.Now
	if b.now != nil {
		now = b.now
	}
	t := now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if t.Sub(b.start) >= time.Second || t.Before(b.start) {
		b.start, b.used = t, 0
	}
	if b.used >= rejectLogPerPlane {
		b.held++
		return 0, false
	}
	b.used++
	held, b.held = b.held, 0
	return held, true
}

func (r latchRank) String() string {
	switch r {
	case rankNone:
		return "none"
	case rankAny:
		return "any"
	case rankSignalled:
		return "signalled"
	case rankExact:
		return "exact"
	}
	return "unknown"
}

// logLimiter lets one event through per interval and counts the ones it
// held back, lock-free: it is shared by all of a session's relay
// goroutines.
type logLimiter struct {
	now        func() time.Time // nil = time.Now
	next       atomic.Int64     // unix nanos before which allow refuses
	suppressed atomic.Uint64    // events since the last one let through
}

// allow counts one event and reports whether to log it now. When it does,
// n is the number of events since the previous logged one, this included.
func (l *logLimiter) allow() (n uint64, ok bool) {
	l.suppressed.Add(1)
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	t := now().UnixNano()
	next := l.next.Load()
	if t < next || !l.next.CompareAndSwap(next, t+int64(rejectLogInterval)) {
		return 0, false
	}
	return l.suppressed.Swap(0), true
}

// latchReporter turns latch verdicts into counters and log lines for one
// session. It is called after the latch mutex is released.
type latchReporter struct {
	log      *slog.Logger
	counters *counters
	planes   [2]string       // per side; the pool's name, or "a"/"b"
	budgets  [2]*planeBudget // per side: its pool's WARN budget; nil = uncapped
	lim      logLimiter
}

func newLatchReporter(log *slog.Logger, c *counters, planes [2]string, budgets [2]*planeBudget) latchReporter {
	if log == nil {
		log = slog.Default()
	}
	for i, d := range [2]string{"a", "b"} {
		if planes[i] == "" {
			planes[i] = d
		}
	}
	return latchReporter{log: log, counters: c, planes: planes, budgets: budgets}
}

// observe reports whether the packet from src on side may be processed.
// The common case (the latched source) returns before touching anything.
func (r *latchReporter) observe(side Side, rtp bool, src netip.AddrPort, v latchVerdict) bool {
	if v.ev == evSame {
		return true
	}
	return r.slow(side, rtp, src, v)
}

func kindName(rtp bool) string {
	if rtp {
		return "rtp"
	}
	return "rtcp"
}

func (r *latchReporter) slow(side Side, rtp bool, src netip.AddrPort, v latchVerdict) bool {
	switch v.ev {
	case evRefused:
		r.counters.recordRejected(side, rtp)
		if v.heldRank == rankNone {
			return false // nothing latched yet: counted, not logged
		}
		if n, ok := r.lim.allow(); ok {
			var held uint64
			if b := r.budgets[side]; b != nil {
				if held, ok = b.allow(); !ok {
					// The plane cap refused: keep the count for this
					// session's next line.
					r.lim.suppressed.Add(n)
					return false
				}
			}
			attrs := []any{
				"plane", r.planes[side], "kind", kindName(rtp), "reason", v.reason(),
				"latched", v.held.String(), "latched_rank", v.heldRank.String(),
				"source", unmapped(src).String(), "source_rank", v.rank.String(),
				"count", n}
			if held > 0 {
				attrs = append(attrs, "lines_suppressed", held)
			}
			r.log.Warn("media packets rejected by latch", attrs...)
		}
		return false
	case evMoved:
		r.log.Info("media latch moved",
			"plane", r.planes[side], "kind", kindName(rtp),
			"from", v.held.String(), "to", unmapped(src).String(),
			"from_rank", v.heldRank.String(), "to_rank", v.rank.String())
	case evSet:
		r.log.Debug("media latch set",
			"plane", r.planes[side], "kind", kindName(rtp),
			"to", unmapped(src).String(), "to_rank", v.rank.String())
	}
	return true
}

// unmapped is src as logged: an IPv4-mapped IPv6 source (a dual-stack
// socket) in its plain IPv4 form, as the latch stores it.
func unmapped(src netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
}
