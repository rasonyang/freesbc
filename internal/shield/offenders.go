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

// strikeStage is one fixed window of strikes that opens at its first strike:
// the short stage (shield.*_ban) or the long stage (shield.*_ban_long) of an
// entry. The zero value is a closed stage with no strikes.
type strikeStage struct {
	start  time.Time
	window time.Duration
	count  int
	over   bool // count crossed the stage's N in this window (WARN once)
	// parts breaks count down by the reason each strike was reported
	// under. It is nil until a strike names a part, so a single-reason
	// budget (register) allocates nothing. At most one entry per reason
	// sharing the budget, so it stays tiny.
	parts map[string]int
}

// open reports whether the stage's window is still running at now.
func (g *strikeStage) open(now time.Time) bool {
	return g.window > 0 && now.Sub(g.start) < g.window
}

// end is when the stage's window closes (zero for a stage never used).
func (g *strikeStage) end() time.Time {
	if g.window <= 0 {
		return time.Time{}
	}
	return g.start.Add(g.window)
}

// add counts one strike under lim, first starting a new window if the
// current one ended (or never began). A stage never resets when keep is
// set (an AoR whose lock is open).
func (g *strikeStage) add(now time.Time, part string, lim config.StrikeLimit, keep bool) (over, crossed bool) {
	if g.window <= 0 {
		g.start = now
	} else if !keep && now.Sub(g.start) >= lim.Window {
		*g = strikeStage{start: now}
	}
	g.window = lim.Window
	g.count++
	if part != "" {
		if g.parts == nil {
			g.parts = map[string]int{}
		}
		g.parts[part]++
	}
	if g.count <= lim.N {
		return false, false
	}
	crossed = !g.over
	g.over = true
	return true, crossed
}

// usableLimit reports whether lim counts anything.
func usableLimit(lim config.StrikeLimit) bool {
	return !lim.Off && lim.N > 0 && lim.Window > 0
}

// strikeVerdict is the outcome of one strike across both stages.
type strikeVerdict struct {
	over    bool // either stage is over its N
	crossed bool // this strike made a stage cross its N
	// stage, count and window describe the crossing stage ("short" wins when
	// both cross), else the first stage that is over.
	stage  string
	count  int
	window time.Duration
}

const (
	stageShort = "short"
	stageLong  = "long"
)

// verdict combines the two stages' results of one strike.
func verdict(short, long *strikeStage, sOver, sCross, lOver, lCross bool) strikeVerdict {
	v := strikeVerdict{over: sOver || lOver, crossed: sCross || lCross}
	switch {
	case sCross || (!lCross && sOver):
		v.stage, v.count, v.window = stageShort, short.count, short.window
	case lOver:
		v.stage, v.count, v.window = stageLong, long.count, long.window
	default:
		v.stage, v.count, v.window = stageShort, short.count, short.window
	}
	return v
}

// offender is one source's strikes of one budget: a short and a long stage.
type offender struct {
	key         offenderKey
	short, long strikeStage
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

// strike adds one strike to every enabled stage: the short stage under
// short (which the caller has checked is usable) and the long stage under
// long when that is usable. Each stage resets on its own window.
//
// part is the reason the strike is tallied under in the offender view when
// it must be told apart from the rest of the budget, else "".
func (t *offenderTable) strike(key offenderKey, part string, short, long config.StrikeLimit) strikeVerdict {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var o *offender
	if el, ok := t.entries[key]; ok {
		o = el.Value.(*offender)
		t.lru.MoveToFront(el)
	} else {
		if t.lru.Len() >= t.max {
			oldest := t.lru.Back()
			delete(t.entries, oldest.Value.(*offender).key)
			t.lru.Remove(oldest)
		}
		o = &offender{key: key}
		t.entries[key] = t.lru.PushFront(o)
	}
	sOver, sCross := o.short.add(now, part, short, false)
	var lOver, lCross bool
	if usableLimit(long) {
		lOver, lCross = o.long.add(now, part, long, false)
	}
	return verdict(&o.short, &o.long, sOver, sCross, lOver, lCross)
}

// clear forgets key's strikes (both stages).
func (t *offenderTable) clear(key offenderKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.entries[key]; ok {
		delete(t.entries, key)
		t.lru.Remove(el)
	}
}

// prune drops the entries whose stages have both ended.
func (t *offenderTable) prune() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, el := range t.entries {
		if o := el.Value.(*offender); !o.short.open(now) && !o.long.open(now) {
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

// live copies the entries with an open stage, one row per reason a budget
// was struck under in either open stage (a single-reason budget is one row).
// A row's stages carry that reason's own counts; a closed stage is zero.
func (t *offenderTable) live() []offender {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out := make([]offender, 0, len(t.entries))
	for _, el := range t.entries {
		o := el.Value.(*offender)
		sh, lg := o.short, o.long
		if !sh.open(now) {
			sh = strikeStage{}
		}
		if !lg.open(now) {
			lg = strikeStage{}
		}
		if sh.window == 0 && lg.window == 0 {
			continue
		}
		if len(sh.parts) == 0 && len(lg.parts) == 0 {
			sh.parts, lg.parts = nil, nil
			out = append(out, offender{key: o.key, short: sh, long: lg})
			continue
		}
		reasons := map[string]bool{}
		for r := range sh.parts {
			reasons[r] = true
		}
		for r := range lg.parts {
			reasons[r] = true
		}
		for reason := range reasons {
			row := offender{key: o.key, short: sh, long: lg}
			row.key.reason = reason
			row.short.count, row.short.parts = sh.parts[reason], nil
			row.long.count, row.long.parts = lg.parts[reason], nil
			out = append(out, row)
		}
	}
	return out
}

// Strike records one strike of reason (StrikeRegister) against src and
// reports whether src is banned as a result. Over the reason's threshold
// (a hot key, e.g. shield.register_ban) every further strike within the
// window bans src for shield.ban with reason as the ban reason; the first
// is logged at WARN. Strikes and bans are both keyed by bucketKey: an IPv4
// address, an IPv6 source by its /64, so an attacker rotating addresses
// inside its /64 shares one count and one ban entry.
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
// never its TCP, TLS, WS or WSS. A ban covers the source's bucketKey, so
// for IPv6 the whole /64 (a forged flood naming one address silences its
// /64 on UDP). A stream source survived a handshake, so its strikes ban
// the source on every transport. An unknown transport is
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
	lim, long := s.strikeLimits(cfg, reason)
	if !usableLimit(lim) {
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
	v := s.offenders.strike(key, part, lim, long)
	if !v.over {
		return false
	}
	if !table.ban(key.src, cfg.Shield.Ban.Std(), reason) {
		s.log.Debug("shield ban table at hard cap; strike ban refused", "source", banKeyString(key.src), "address", src, "reason", reason)
		return false
	}
	if v.crossed {
		s.log.Warn("shield banned source for repeated failures", "source", banKeyString(key.src), "address", src, "reason", reason,
			"stage", v.stage, "strikes", v.count, "window", v.window.String(), "ban", cfg.Shield.Ban.Std().String())
	} else {
		s.log.Debug("shield extended strike ban", "source", banKeyString(key.src), "address", src, "reason", reason, "stage", v.stage, "strikes", v.count)
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

// strikeLimit parses reason's short-stage threshold from cfg, cached until
// the string changes.
func (s *Shield) strikeLimit(cfg *config.Config, reason string) config.StrikeLimit {
	short, _ := s.strikeLimits(cfg, reason)
	return short
}

// strikeLimits parses reason's short and long stage thresholds from cfg.
// Each is cached under its own key until its string changes. The long
// limit is returned even while the short one is off; the short key is the
// master switch and the caller checks it first.
func (s *Shield) strikeLimits(cfg *config.Config, reason string) (short, long config.StrikeLimit) {
	var shortStr, longStr string
	switch reason {
	case StrikeRegister:
		shortStr, longStr = cfg.Shield.RegisterBan, cfg.Shield.RegisterBanLong
	case StrikeAdmission, StrikeMalformed:
		shortStr, longStr = cfg.Shield.AdmissionBan, cfg.Shield.AdmissionBanLong
		reason = StrikeAdmission
	case StrikeRegisterAOR:
		shortStr, longStr = cfg.Shield.RegisterBanAOR, cfg.Shield.RegisterBanAORLong
	default:
		return config.StrikeLimit{Off: true}, config.StrikeLimit{Off: true}
	}
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	return s.cachedStrikeLimit(reason, shortStr), s.cachedStrikeLimit(reason+"_long", longStr)
}

// cachedStrikeLimit parses str, cached under key until str changes. The
// caller holds rlMu.
func (s *Shield) cachedStrikeLimit(key, str string) config.StrikeLimit {
	if s.strikeStr == nil {
		s.strikeStr = map[string]string{}
		s.strikeOpts = map[string]config.StrikeLimit{}
	}
	if cur, ok := s.strikeStr[key]; !ok || cur != str {
		lim, err := config.ParseStrikeLimit(str)
		if err != nil {
			lim = config.StrikeLimit{Off: true}
		}
		s.strikeOpts[key] = lim
		s.strikeStr[key] = str
	}
	return s.strikeOpts[key]
}

// OffenderInfo is one source with strikes in an open window.
type OffenderInfo struct {
	// Source is the struck IPv4 address, or an IPv6 /64 prefix; for reason
	// StrikeRegisterAOR it is the AoR.
	Source string
	// Reason is the strike reason (StrikeRegister, StrikeAdmission,
	// StrikeAdmissionUDP, StrikeMalformed, StrikeMalformedUDP,
	// StrikeRegisterAOR). Strikes is that reason's own count, though reasons
	// sharing a budget (admission and malformed) are banned on their sum.
	Reason string
	// Strikes is the count in the short stage's current window, which
	// opened at Since and closes at Until (for an AoR, Until is the lock
	// end while locked). All zero while that window is closed.
	Strikes      int
	Since, Until time.Time
	// LongStrikes, LongSince and LongUntil are the same for the long stage
	// (shield.*_ban_long); zero while its window is closed.
	LongStrikes          int
	LongSince, LongUntil time.Time
}

// maxOffenders bounds one Offenders list.
const maxOffenders = 1000

// Offenders returns up to limit (clamped to 1..1000) sources with strikes
// in an open window, most strikes first, and the total number of such
// sources. The table is copied under its lock and sorted outside it.
func (s *Shield) Offenders(limit int) (top []OffenderInfo, total int) {
	limit = min(max(limit, 1), maxOffenders)
	live := s.offenders.live()
	aors := s.aors.live()
	sort.Slice(live, func(i, j int) bool {
		if live[i].short.count != live[j].short.count {
			return live[i].short.count > live[j].short.count
		}
		if live[i].long.count != live[j].long.count {
			return live[i].long.count > live[j].long.count
		}
		if !live[i].short.start.Equal(live[j].short.start) {
			return live[i].short.start.Before(live[j].short.start)
		}
		return live[i].key.src.Less(live[j].key.src)
	})
	total = len(live) + len(aors)
	top = make([]OffenderInfo, 0, min(limit, total))
	for _, o := range live {
		top = append(top, OffenderInfo{Source: banKeyString(o.key.src), Reason: o.key.reason,
			Strikes: o.short.count, Since: o.short.start, Until: o.short.end(),
			LongStrikes: o.long.count, LongSince: o.long.start, LongUntil: o.long.end()})
	}
	for _, e := range aors {
		info := OffenderInfo{Source: e.key, Reason: StrikeRegisterAOR,
			Strikes: e.short.count, Since: e.short.start, Until: e.short.end(),
			LongStrikes: e.long.count, LongSince: e.long.start, LongUntil: e.long.end()}
		if !e.locked.IsZero() {
			info.Until = e.locked
		}
		top = append(top, info)
	}
	sort.SliceStable(top, func(i, j int) bool {
		if top[i].Strikes != top[j].Strikes {
			return top[i].Strikes > top[j].Strikes
		}
		return top[i].LongStrikes > top[j].LongStrikes
	})
	if len(top) > limit {
		top = top[:limit]
	}
	return top, total
}
