package edge

import (
	"container/list"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/shield"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file is the edge plane's per-request admission policy for public
// requests that would otherwise reach FreeSWITCH unauthenticated (issue
// #86). It runs after parsing, per request type, and never touches
// responses:
//
//   - an out-of-dialog INVITE on a public listener is admitted only from an
//     a carrier source or from a transport address that holds a live
//     registration binding (admitPublicInvite);
//   - a REGISTER is always admitted, except from a source that has had
//     enumMaxAORs distinct AoRs rejected 403/404 by the registrar within
//     enumWindow (enumLimiter);
//   - an out-of-dialog MESSAGE (and SUBSCRIBE) on a public listener is
//     admitted only from a live registration (admitPublicOutOfDialog);
//   - a public BYE or INFO that names no dialog on record is forwarded to
//     the switch only from a live registration or a carrier source
//     (admitDialogless); anyone else is answered 481 and counted.
//
// Drops are silent: no response is sent, so a scanner learns nothing and
// sipgo's Timer G never retransmits a final to a spoofed source. The one
// exception is a dialog-less BYE or INFO, which is counted like a drop but
// answered 481 (as a REFER, MESSAGE or NOTIFY naming no dialog is); a
// non-INVITE final is never retransmitted by Timer G.
//
// A REGISTER for an AoR whose refused-credential count passed
// shield.register_ban_aor, from a source with no live binding of it, is
// dropped the same way (register_aor_locked, regguard.go).
//
// Every drop except register_enumeration and register_aor_locked, the
// dialog-less BYE/INFO one included, is also a strike against its source
// for shield.admission_ban (admissionStrike); the ban scope follows the
// transport of the request: UDP strikes ban the IP on UDP only, stream
// transports ban every one.

// dropReason is why a public request was dropped by admission. The set is
// fixed, so it is a bounded metric label.
type dropReason int

const (
	dropInviteNotAdmitted dropReason = iota
	dropRegisterEnumeration
	dropSubscribeNotAdmitted
	dropMessageNotAdmitted
	dropDialogless
	dropRegisterAORLocked
	numDropReasons
)

// dropReasonLabels are the metric labels of the drop reasons.
var dropReasonLabels = [numDropReasons]string{
	dropInviteNotAdmitted:    "invite_not_admitted",
	dropRegisterEnumeration:  "register_enumeration",
	dropSubscribeNotAdmitted: "subscribe_not_admitted",
	dropMessageNotAdmitted:   "message_not_admitted",
	dropDialogless:           "dialogless_not_admitted",
	dropRegisterAORLocked:    "register_aor_locked",
}

func (r dropReason) String() string { return dropReasonLabels[r] }

// inviteSource is who a public out-of-dialog INVITE is from, which decides
// where admission sends it.
type inviteSource int

const (
	// srcDrop: neither a live registration nor a carrier source.
	srcDrop inviteSource = iota
	// srcClient: the transport address of a live registration.
	srcClient
	// srcCarrier: a carrier source (resolved edge.carriers addresses plus
	// edge.carrier_sources).
	srcCarrier
)

// admitPublicInvite decides whether an out-of-dialog INVITE that arrived
// on a public listener may be relayed to the switch, and by which path.
// FreeSWITCH is not among the admitted sources: it speaks only on the
// private bind, a trusted socket that never reaches this check, so a public
// read from FreeSWITCH's own address is an ordinary public INVITE. The
// source is, in order:
//
//   - exactly the transport address (transport + IP:port) of a live
//     registration binding: a registered phone or browser calling out over
//     the socket it registered from (a WebSocket client's INVITE arrives on
//     the connection that registered, which is the address its binding
//     records). It wins over a carrier source, so a client behind a
//     carrier's address is never sent down the unauthenticated carrier
//     path: srcClient, delivered to the switch's client port;
//   - inside a carrier source (carrierDirectory): srcCarrier, with the
//     carrier's name, delivered to the switch's carrier port. A carrier's
//     own address counts only on that carrier's transport (a tls carrier's
//     IP over UDP is nobody); edge.carrier_sources match on any;
//   - anything else: srcDrop.
//
// The check keys on the transport source only, never on From or any
// identity header, so it cannot be talked past by a spoofed header.
func (s *Server) admitPublicInvite(req *sip.Request, src netip.AddrPort) (inviteSource, string) {
	if s.loc.HasSource(sip.NetworkToLower(req.Transport()), src) {
		return srcClient, ""
	}
	if name, ok := s.carriers.snapshot().carrierFor(src, sip.NetworkToLower(req.Transport())); ok {
		return srcCarrier, name
	}
	return srcDrop, ""
}

// outOfDialogVerdict is what admitPublicOutOfDialog decides.
type outOfDialogVerdict int

const (
	// oodAdmitted: the source holds a live registration; the Binding
	// returned names it.
	oodAdmitted outOfDialogVerdict = iota
	// oodCarrier: a carrier source. The request is not supported from
	// carriers; the handler answers 405.
	oodCarrier
	// oodDropped: nobody. The request was counted and dropped silently
	// (dropSilently); the handler returns without responding.
	oodDropped
)

// admitPublicOutOfDialog is the admission check of an out-of-dialog
// request other than INVITE that arrived on a public listener and that
// only a registered client may send: MESSAGE, and SUBSCRIBE. Like
// admitPublicInvite it keys on the transport source alone and a live
// registration wins over a carrier source. A registered source is
// admitted with its Binding (the one whose user equals the From user,
// else the first live one at that source), a carrier source is answered
// 405, and anything else is dropped silently and counted under reason.
func (s *Server) admitPublicOutOfDialog(req *sip.Request, src netip.AddrPort, reason dropReason) (Binding, outOfDialogVerdict) {
	user := ""
	if f := req.From(); f != nil {
		user = f.Address.User
	}
	if b, ok := s.loc.SourceBinding(sip.NetworkToLower(req.Transport()), src, user); ok {
		return b, oodAdmitted
	}
	if _, ok := s.carriers.snapshot().carrierFor(src, sip.NetworkToLower(req.Transport())); ok {
		return Binding{}, oodCarrier
	}
	s.dropSilently(reason, req, src)
	return Binding{}, oodDropped
}

// admitDialogless is the admission check of a public BYE or INFO that
// matches no dialog on record. directionFor would hash such a request to
// a switch, which is right for a registered client or a carrier whose
// dialog record is gone (restart, early expiry), but would otherwise let
// any public sender make the edge deliver a request to the switch and
// relay its answer. The source must be a live registration (transport +
// IP:port) or a carrier source, as for an INVITE (admitPublicInvite).
// Anyone else is counted under dropDialogless and the handler answers 481,
// the same answer a REFER, MESSAGE or NOTIFY naming no dialog gets.
func (s *Server) admitDialogless(req *sip.Request, src netip.AddrPort) bool {
	if kind, _ := s.admitPublicInvite(req, src); kind != srcDrop {
		return true
	}
	// dropSilently counts, logs and strikes the source (admission_ban,
	// as for any drop but enumeration); the caller sends the 481.
	s.dropSilently(dropDialogless, req, src)
	return false
}

// dropSilently records an admission drop: it counts it by reason and logs
// it, at WARN the first time a source IP is dropped for that reason and at
// Debug afterwards, so a scanner cannot flood the log. Nothing is sent to
// the requester; the handler returns without responding, and sipgo's
// handleRequest then terminates the server transaction unanswered (see
// onInvite).
func (s *Server) dropSilently(reason dropReason, req *sip.Request, src netip.AddrPort, attrs ...any) {
	s.metrics.AdmissionDropped(reason)
	s.dropSummary.addAdmission(src.Addr())
	if reason != dropRegisterEnumeration && reason != dropRegisterAORLocked {
		s.admissionStrike(src.Addr(), sip.NetworkToLower(req.Transport()))
	}
	args := append([]any{
		"reason", reason.String(),
		"method", req.Method.String(),
		"transport", sip.NetworkToLower(req.Transport()),
		"public_remote", src.String(),
		"sip_call_id", fsip.CallID(req),
	}, attrs...)
	if s.dropWarned.first(reason, src.Addr()) {
		s.log.Warn("public request dropped by admission; further drops from this source are logged at debug", args...)
		return
	}
	s.log.Debug("public request dropped by admission", args...)
}

// admissionStrike counts one admission drop against src in the shield
// (shield.admission_ban, issue #180): a source that keeps sending requests
// admission drops, below every rate limit, is eventually banned by IP for
// shield.ban. It never counts a carrier source or an IP that holds a
// registration binding on any port (a phone that re-registers from a new
// port must recover), and the shield counts only after a sustained number
// of drops in a window, never one datagram. The drop itself is already
// silent, so the ban only stops the parsing cost.
func (s *Server) admissionStrike(ip netip.Addr, transport string) {
	sh := s.currentShield()
	if sh == nil {
		return
	}
	ip = ip.Unmap()
	if s.carriers.snapshot().isSource(ip) || s.loc.HasIP(ip) {
		return
	}
	sh.StrikeOn(ip, shield.StrikeAdmission, transport)
}

// malformedStrike counts one malformed public read (a UDP datagram or a
// WS/WSS frame fsip.Malformed flagged) against its source in the shield. It
// shares shield.admission_ban with admissionStrike, so a source alternating
// both kinds hits one budget, and it has the same exemptions (a carrier
// source, an IP holding a registration) and the same ban scope (UDP: that IP
// on UDP only; WS/WSS: every transport). A tcp or tls read never reaches it:
// a chunk of a byte stream is not a message. Each read it strikes is also
// counted, by kind, in the once-a-minute drop summary (dropSummary). The
// read is already past the ban check and the rate token, so the cost is one
// shield call.
func (s *Server) malformedStrike(info sip.TransportReadProps) {
	sh := s.currentShield()
	if sh == nil {
		return
	}
	ap, err := netip.ParseAddrPort(info.RemoteAddr.String())
	if err != nil {
		return
	}
	ip := ap.Addr().Unmap()
	if s.carriers.snapshot().isSource(ip) || s.loc.HasIP(ip) {
		return
	}
	s.dropSummary.addMalformed(ip)
	sh.StrikeOn(ip, shield.StrikeMalformed, info.Transport)
}

// admissionSummaryEvery is the period of the admission-drop summary WARN,
// which covers admission drops and the malformed public reads that strike
// (malformedStrike), kept apart by kind. An interval with neither logs
// nothing.
const admissionSummaryEvery = time.Minute

// maxSummarySources bounds the per-source counts kept for one summary
// interval. Sources past it still count in the totals, only their per-source
// count is lost, so memory is bounded however many sources are dropped.
const maxSummarySources = 1024

// summaryCount is one source's tally for an interval, by kind.
type summaryCount struct{ admission, malformed int }

// dropSummary counts the admission drops and struck malformed reads of one
// interval: a total per kind and a bounded per-source tally, from which the
// WARN names the top source by its combined count.
type dropSummary struct {
	mu        sync.Mutex
	admission int
	malformed int
	bySrc     map[netip.Addr]summaryCount
	overflow  bool // some source was not tracked (cap reached)
}

func (d *dropSummary) addAdmission(ip netip.Addr) { d.add(ip, false) }
func (d *dropSummary) addMalformed(ip netip.Addr) { d.add(ip, true) }

func (d *dropSummary) add(ip netip.Addr, malformed bool) {
	ip = ip.Unmap().WithZone("")
	d.mu.Lock()
	defer d.mu.Unlock()
	if malformed {
		d.malformed++
	} else {
		d.admission++
	}
	if d.bySrc == nil {
		d.bySrc = map[netip.Addr]summaryCount{}
	}
	c, ok := d.bySrc[ip]
	if !ok && len(d.bySrc) >= maxSummarySources {
		d.overflow = true
		return
	}
	if malformed {
		c.malformed++
	} else {
		c.admission++
	}
	d.bySrc[ip] = c
}

// take returns the summary line for the interval just ended and starts a
// new one; ok is false when there was nothing to report.
func (d *dropSummary) take(interval time.Duration) (msg string, ok bool) {
	d.mu.Lock()
	adm, mal, by, overflow := d.admission, d.malformed, d.bySrc, d.overflow
	d.admission, d.malformed, d.bySrc, d.overflow = 0, 0, nil, false
	d.mu.Unlock()
	if adm+mal == 0 {
		return "", false
	}
	var top netip.Addr
	var topC summaryCount
	topN := 0
	for ip, c := range by {
		if n := c.admission + c.malformed; n > topN || (n == topN && ip.Less(top)) {
			top, topC, topN = ip, c, n
		}
	}
	more := ""
	if overflow {
		more = "+"
	}
	return fmt.Sprintf("admission drops: %d in %s (%d admission, %d malformed) from %d%s sources, top=%s (%d admission, %d malformed)",
		adm+mal, interval, adm, mal, len(by), more, top, topC.admission, topC.malformed), true
}

// maxWarnedSources bounds the set of sources already warned about. When
// full, the oldest entry is forgotten, so at worst a source is warned about
// again; memory never grows with the number of scanners.
const maxWarnedSources = 4096

// warnOnce remembers which (reason, source IP) pairs have already been
// logged at WARN, in a fixed-capacity FIFO.
type warnOnce struct {
	mu   sync.Mutex
	seen map[warnKey]struct{}
	ring []warnKey
	next int
	max  int
}

type warnKey struct {
	reason dropReason
	ip     netip.Addr
}

func newWarnOnce(max int) *warnOnce {
	return &warnOnce{seen: map[warnKey]struct{}{}, max: max}
}

// first reports whether this is the first drop remembered for (reason, ip),
// and remembers it.
func (w *warnOnce) first(reason dropReason, ip netip.Addr) bool {
	k := warnKey{reason, ip.Unmap().WithZone("")}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.seen[k]; ok {
		return false
	}
	if len(w.ring) < w.max {
		w.ring = append(w.ring, k)
	} else {
		delete(w.seen, w.ring[w.next])
		w.ring[w.next] = k
		w.next = (w.next + 1) % w.max
	}
	w.seen[k] = struct{}{}
	return true
}

// REGISTER enumeration limit. A scanner enumerating accounts sends
// REGISTERs for thousands of AoRs from one source, and the registrar
// rejects the unknown ones; a real phone, or a NAT full of phones, uses a
// handful of AoRs. So a source is cut off once enumMaxAORs DISTINCT AoRs
// have been rejected 403/404 within one enumWindow. Digest challenges
// (401/407) are the normal first leg of every registration and never count.
// Constants rather than config: the thresholds are far from real usage in
// both directions.
const (
	enumWindow     = 10 * time.Minute
	enumMaxAORs    = 10
	enumMaxSources = 4096
)

// enumLimiter tracks, per source key (IPv4 address; IPv6 /64), the distinct
// AoRs rejected within a fixed window that opens at the first rejection.
// The table is an LRU capped at enumMaxSources: a new source past the cap
// evicts the least recently rejected one, so a flood of sources can never
// stop tracking (it only forgets the oldest). Memory is bounded by
// enumMaxSources × enumMaxAORs AoR strings.
type enumLimiter struct {
	mu      sync.Mutex
	entries map[netip.Addr]*list.Element // of *enumEntry
	lru     *list.List                   // front = most recently rejected
	max     int
	now     func() time.Time
}

type enumEntry struct {
	key   netip.Addr
	start time.Time
	aors  []string
}

func newEnumLimiter() *enumLimiter {
	return &enumLimiter{
		entries: map[netip.Addr]*list.Element{},
		lru:     list.New(),
		max:     enumMaxSources,
		now:     time.Now,
	}
}

// enumKey is the per-source key: an IPv4 address as is, an IPv6 address by
// its /64 (as the shield's rate limiter keys it), since one IPv6 host is
// normally given a whole /64.
func enumKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

// blocked reports whether REGISTERs from ip are currently dropped.
func (l *enumLimiter) blocked(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.entries[enumKey(ip)]
	if !ok {
		return false
	}
	e := el.Value.(*enumEntry)
	return l.now().Sub(e.start) < enumWindow && len(e.aors) >= enumMaxAORs
}

// rejected records that the registrar rejected aor (403/404) for a
// REGISTER from ip. It reports whether this rejection took the source to
// the limit.
func (l *enumLimiter) rejected(ip netip.Addr, aor string) (reached bool) {
	key := enumKey(ip)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var e *enumEntry
	if el, ok := l.entries[key]; ok {
		e = el.Value.(*enumEntry)
		l.lru.MoveToFront(el)
		if now.Sub(e.start) >= enumWindow {
			e.start, e.aors = now, e.aors[:0]
		}
	} else {
		if l.lru.Len() >= l.max {
			oldest := l.lru.Back()
			delete(l.entries, oldest.Value.(*enumEntry).key)
			l.lru.Remove(oldest)
		}
		e = &enumEntry{key: key, start: now}
		l.entries[key] = l.lru.PushFront(e)
	}
	if len(e.aors) >= enumMaxAORs {
		return false // already at the limit
	}
	for _, a := range e.aors {
		if a == aor {
			return false
		}
	}
	e.aors = append(e.aors, aor)
	return len(e.aors) == enumMaxAORs
}

// countsAsEnumeration reports whether a registrar's final response to a
// REGISTER counts toward the enumeration limit: only 403 and 404, the
// answers a registrar gives an unknown or forbidden account.
func countsAsEnumeration(code int) bool { return code == 403 || code == 404 }
