package shield

import (
	"container/list"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// Strike reasons: what a plane reports through Shield.Strike. Each has its
// own threshold key and is also the reason recorded on the ban it leads
// to.
const (
	// StrikeRegister is a failed REGISTER credential attempt
	// (shield.register_ban).
	StrikeRegister = BanReasonRegister
	// StrikeAdmission is a public request dropped by edge admission
	// (shield.admission_ban).
	StrikeAdmission = BanReasonAdmission
	// StrikeAdmissionUDP is the offender-table reason of admission strikes
	// from UDP, counted apart from stream ones (see StrikeOn).
	StrikeAdmissionUDP = StrikeAdmission + "_udp"
	// StrikeMalformed is a public datagram the read filter's scan found
	// malformed (issue #190). It shares shield.admission_ban with
	// StrikeAdmission: one budget per source and scope, so a source that
	// alternates both kinds is counted once. The offender view keeps the
	// two reasons apart (StrikeMalformed, StrikeMalformedUDP).
	StrikeMalformed = BanReasonMalformed
	// StrikeMalformedUDP is the offender-table reason of malformed strikes
	// from UDP.
	StrikeMalformedUDP = StrikeMalformed + "_udp"
)

// offenderCap bounds the offender table. A flood of distinct sources only
// evicts the least recently struck entries, so memory stays bounded and a
// source that keeps failing stays tracked (it is always the most recent).
const offenderCap = 16384

// offenderKey names one budget: the source and the budget's reason. A
// budget shared by several strike reasons (admission_ban) is keyed by its
// primary reason (StrikeAdmission, with "_udp" for the UDP scope).
type offenderKey struct {
	src    netip.Addr // bucketKey: an IPv4 address, an IPv6 /64
	reason string
}

// offender is one source's strikes of one reason within a fixed window
// that opens at its first strike.
type offender struct {
	key    offenderKey
	start  time.Time
	window time.Duration
	count  int  // all strikes of the budget in this window
	over   bool // the threshold was crossed in this window (WARN once)
	// parts breaks count down by the reason each strike was reported
	// under. It is nil until a strike names a part, so a single-reason
	// budget (register) allocates nothing. At most one entry per reason
	// sharing the budget, so it stays tiny.
	parts map[string]int
}

// offenderTable is an LRU-capped table of per-source strike counters.
type offenderTable struct {
	mu      sync.Mutex
	entries map[offenderKey]*list.Element // of *offender
	lru     *list.List                    // front = most recently struck
	max     int
	now     func() time.Time
}

func newOffenderTable() *offenderTable {
	return &offenderTable{entries: map[offenderKey]*list.Element{}, lru: list.New(), max: offenderCap, now: time.Now}
}

// strike adds one strike under lim and returns the window's count, whether
// it is over lim.N, and whether this strike is the one that crossed it.
//
// part is the reason the strike is tallied under in the offender view when
// it must be told apart from the rest of the budget, else "".
func (t *offenderTable) strike(key offenderKey, part string, lim config.StrikeLimit) (count int, over, crossed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var o *offender
	if el, ok := t.entries[key]; ok {
		o = el.Value.(*offender)
		t.lru.MoveToFront(el)
		if now.Sub(o.start) >= lim.Window {
			o.start, o.count, o.over, o.parts = now, 0, false, nil
		}
	} else {
		if t.lru.Len() >= t.max {
			oldest := t.lru.Back()
			delete(t.entries, oldest.Value.(*offender).key)
			t.lru.Remove(oldest)
		}
		o = &offender{key: key, start: now}
		t.entries[key] = t.lru.PushFront(o)
	}
	o.window = lim.Window
	o.count++
	if part != "" {
		if o.parts == nil {
			o.parts = map[string]int{}
		}
		o.parts[part]++
	}
	if o.count <= lim.N {
		return o.count, false, false
	}
	crossed = !o.over
	o.over = true
	return o.count, true, crossed
}

// clear forgets key's strikes.
func (t *offenderTable) clear(key offenderKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.entries[key]; ok {
		delete(t.entries, key)
		t.lru.Remove(el)
	}
}

// prune drops the entries whose window has ended.
func (t *offenderTable) prune() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, el := range t.entries {
		if o := el.Value.(*offender); now.Sub(o.start) >= o.window {
			delete(t.entries, k)
			t.lru.Remove(el)
		}
	}
}

func (t *offenderTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// live copies the entries whose window is still open, one row per reason a
// budget was struck under (a single-reason budget is one row).
func (t *offenderTable) live() []offender {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out := make([]offender, 0, len(t.entries))
	for _, el := range t.entries {
		o := el.Value.(*offender)
		if now.Sub(o.start) >= o.window {
			continue
		}
		if len(o.parts) == 0 {
			row := *o
			row.parts = nil
			out = append(out, row)
			continue
		}
		for reason, n := range o.parts {
			row := *o
			row.key.reason, row.count, row.parts = reason, n, nil
			out = append(out, row)
		}
	}
	return out
}

// Strike records one strike of reason (StrikeRegister) against src and
// reports whether src is banned as a result. Over the reason's threshold
// (a hot key, e.g. shield.register_ban) every further strike within the
// window bans src's IP for shield.ban with reason as the ban reason; the
// first is logged at WARN. Strikes are counted per source key (an IPv6
// source by its /64, so an attacker rotating addresses inside its /64
// shares one count), while the ban names the struck address.
//
// A carrier source is never struck, and an unknown reason or a threshold
// of "off" counts nothing. The caller is responsible for the strike being
// trustworthy: a forgeable datagram must not be able to strike a victim's
// address (see the edge's REGISTER guard).
func (s *Shield) Strike(src netip.Addr, reason string) bool {
	return s.strike(src, reason, false)
}

// StrikeOn is Strike for a request that arrived on transport. A UDP source
// address can be forged, so strikes from UDP are counted apart from stream
// strikes (offender reason StrikeAdmissionUDP) and ban the IP on UDP only
// (BanKindUDPIP): a forged datagram flood can silence the victim's UDP,
// never its TCP, TLS, WS or WSS. A stream source survived a handshake, so
// its strikes ban the IP on every transport. An unknown transport is
// treated as UDP.
func (s *Shield) StrikeOn(src netip.Addr, reason, transport string) bool {
	return s.strike(src, reason, !bannableTransport(transport))
}

func (s *Shield) strike(src netip.Addr, reason string, udp bool) bool {
	src = src.Unmap()
	if s.isCarrier(src) {
		return false
	}
	cfg := s.store.Current()
	lim := s.strikeLimit(cfg, reason)
	if lim.Off || lim.N <= 0 || lim.Window <= 0 {
		return false
	}
	// A reason that shares another's threshold shares its budget too: the
	// entry is keyed by the budget's reason and the strike is also tallied
	// under its own reason, which is what the offender view lists.
	budget := reason
	if reason == StrikeMalformed {
		budget = StrikeAdmission
	}
	table, key, part := s.bans, offenderKey{bucketKey(src), budget}, ""
	if udp {
		table, key.reason = s.udpBans, budget+"_udp"
	}
	if budget == StrikeAdmission {
		part = reason
		if udp {
			part += "_udp"
		}
	}
	count, over, crossed := s.offenders.strike(key, part, lim)
	if !over {
		return false
	}
	if !table.ban(src, cfg.Shield.Ban.Std(), reason) {
		s.log.Debug("shield ban table at hard cap; strike ban refused", "source", src, "reason", reason)
		return false
	}
	if crossed {
		s.log.Warn("shield banned source for repeated failures", "source", src, "reason", reason,
			"strikes", count, "window", lim.Window.String(), "ban", cfg.Shield.Ban.Std().String())
	} else {
		s.log.Debug("shield extended strike ban", "source", src, "reason", reason, "strikes", count)
	}
	return true
}

// ClearStrikes forgets src's strikes of reason: the plane saw src succeed
// (a 2xx registration), so its earlier failures were not an attack.
// Clearing StrikeAdmission clears the whole admission_ban budget, malformed
// strikes included, in both scopes.
func (s *Shield) ClearStrikes(src netip.Addr, reason string) {
	s.offenders.clear(offenderKey{bucketKey(src), reason})
	if reason == StrikeAdmission {
		s.offenders.clear(offenderKey{bucketKey(src), StrikeAdmissionUDP})
	}
}

// strikeLimit parses reason's threshold from cfg, cached until the string
// changes.
func (s *Shield) strikeLimit(cfg *config.Config, reason string) config.StrikeLimit {
	var str string
	switch reason {
	case StrikeRegister:
		str = cfg.Shield.RegisterBan
	case StrikeAdmission, StrikeMalformed:
		str = cfg.Shield.AdmissionBan
		reason = StrikeAdmission
	default:
		return config.StrikeLimit{Off: true}
	}
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	if s.strikeStr == nil {
		s.strikeStr = map[string]string{}
		s.strikeOpts = map[string]config.StrikeLimit{}
	}
	if s.strikeStr[reason] != str {
		lim, err := config.ParseStrikeLimit(str)
		if err != nil {
			lim = config.StrikeLimit{Off: true}
		}
		s.strikeOpts[reason] = lim
		s.strikeStr[reason] = str
	}
	return s.strikeOpts[reason]
}

// OffenderInfo is one source with strikes in an open window.
type OffenderInfo struct {
	// Source is the struck IPv4 address, or an IPv6 /64 prefix.
	Source string
	// Reason is the strike reason (StrikeRegister, StrikeAdmission,
	// StrikeAdmissionUDP, StrikeMalformed, StrikeMalformedUDP). Strikes is
	// that reason's own count, though reasons sharing a budget (admission
	// and malformed) are banned on their sum.
	Reason string
	// Strikes is the count in the current window, which opened at Since
	// and closes at Until.
	Strikes      int
	Since, Until time.Time
}

// maxOffenders bounds one Offenders list.
const maxOffenders = 1000

// Offenders returns up to limit (clamped to 1..1000) sources with strikes
// in an open window, most strikes first, and the total number of such
// sources. The table is copied under its lock and sorted outside it.
func (s *Shield) Offenders(limit int) (top []OffenderInfo, total int) {
	limit = min(max(limit, 1), maxOffenders)
	live := s.offenders.live()
	sort.Slice(live, func(i, j int) bool {
		if live[i].count != live[j].count {
			return live[i].count > live[j].count
		}
		if !live[i].start.Equal(live[j].start) {
			return live[i].start.Before(live[j].start)
		}
		return live[i].key.src.Less(live[j].key.src)
	})
	total = len(live)
	top = make([]OffenderInfo, 0, min(limit, total))
	for _, o := range live[:min(limit, total)] {
		src := o.key.src.String()
		if o.key.src.Is6() {
			src = netip.PrefixFrom(o.key.src, 64).String()
		}
		top = append(top, OffenderInfo{Source: src, Reason: o.key.reason, Strikes: o.count,
			Since: o.start, Until: o.start.Add(o.window)})
	}
	return top, total
}
