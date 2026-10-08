package edge

import (
	"container/list"
	"net/netip"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

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
//     admitted only from a live registration (admitPublicOutOfDialog).
//
// All drops are silent: no response is sent, so a scanner learns nothing
// and sipgo's Timer G never retransmits a final to a spoofed source.

// dropReason is why a public request was dropped by admission. The set is
// fixed, so it is a bounded metric label.
type dropReason int

const (
	dropInviteNotAdmitted dropReason = iota
	dropRegisterEnumeration
	dropSubscribeNotAdmitted
	dropMessageNotAdmitted
	numDropReasons
)

// dropReasonLabels are the metric labels of the drop reasons.
var dropReasonLabels = [numDropReasons]string{
	dropInviteNotAdmitted:    "invite_not_admitted",
	dropRegisterEnumeration:  "register_enumeration",
	dropSubscribeNotAdmitted: "subscribe_not_admitted",
	dropMessageNotAdmitted:   "message_not_admitted",
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
//     carrier's name, delivered to the switch's carrier port;
//   - anything else: srcDrop.
//
// The check keys on the transport source only, never on From or any
// identity header, so it cannot be talked past by a spoofed header.
func (s *Server) admitPublicInvite(req *sip.Request, src netip.AddrPort) (inviteSource, string) {
	if s.loc.HasSource(sip.NetworkToLower(req.Transport()), src) {
		return srcClient, ""
	}
	if name, ok := s.carriers.snapshot().carrierFor(src); ok {
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
	if _, ok := s.carriers.snapshot().carrierFor(src); ok {
		return Binding{}, oodCarrier
	}
	s.dropSilently(reason, req, src)
	return Binding{}, oodDropped
}

// dropSilently records an admission drop: it counts it by reason and logs
// it, at WARN the first time a source IP is dropped for that reason and at
// Debug afterwards, so a scanner cannot flood the log. Nothing is sent to
// the requester; the handler returns without responding, and sipgo's
// handleRequest then terminates the server transaction unanswered (see
// onInvite).
func (s *Server) dropSilently(reason dropReason, req *sip.Request, src netip.AddrPort, attrs ...any) {
	s.metrics.AdmissionDropped(reason)
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
