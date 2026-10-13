package edge

import (
	"bytes"
	"container/list"
	"hash/fnv"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/shield"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// REGISTER credential guard (issue #181). REGISTER is never admission-
// gated: every one is forwarded to the registrar, which challenges it. A
// source that keeps presenting credentials the registrar refuses is
// brute-forcing or enumerating accounts, and the enumeration limit
// (enumLimiter) never sees it when the registrar answers 401 rather than
// 403/404. So each refused credential attempt is a strike against its
// source in the shield (shield.register_ban), and a source over the
// threshold is banned for shield.ban; the read filter then drops it before
// anything is forwarded.
//
// What counts as a strike: a public REGISTER carrying Authorization (or
// Proxy-Authorization) that the registrar answers 401, 403, 404 or 407,
// unless the new challenge says stale=true (the credential was right, the
// nonce old). Never the first, credential-less REGISTER of a normal
// registration, never a 2xx (which clears the source's count), and never an
// exchange the registrar did not answer: at the edge that looks exactly like
// a switch outage, which must not ban every phone that keeps retrying.
//
// Forgery (#17): a strike counts only if the attempt's nonce is one the
// edge relayed to that same source key in a challenge. A UDP datagram's
// source can be forged, but a forger never sees the challenge sent to the
// address it claims, so it cannot strike a victim's IP, and cannot fill
// the ban table with forged addresses either.
//
// Replays: over UDP, a client that reuses the challenged request's Via
// branch for its Authorization retry is a retransmission to sipgo, which
// answers it from the completed server transaction (the cached 401) and
// never runs onRegister. Scanners do exactly that. The read filter
// therefore counts a REGISTER with credentials whose branch the edge
// challenged moments ago (within regReplayWindow, the life of that
// transaction) as a failed attempt on its own. Reliable transports end the
// server transaction with its final response, so there a reused branch
// reaches onRegister and is judged by the registrar's answer.
//
// Refreshes: an attempt from the source of a live binding with the same
// AoR and Call-ID is the refresh of a registration that already
// succeeded, and never counts.
const (
	// regGuardSources caps the sources whose challenges are remembered; a
	// new source past it evicts the least recently challenged one. Losing a
	// record only makes that source's next attempts uncountable (fail open).
	regGuardSources = 16384
	// regNonceTTL is how long a challenge nonce relayed to a source keeps
	// that source's attempts countable.
	regNonceTTL = 15 * time.Minute
	// regReplayWindow is how long after a challenge the read filter treats
	// an Authorization retry on the challenged branch as a replay sipgo
	// will absorb: sipgo's UDP non-INVITE Timer J (64*T1 = 32 s) plus a
	// margin.
	regReplayWindow = 40 * time.Second

	regNoncesPerSource   = 4
	regBranchesPerSource = 8
	regStruckPerSource   = 16
)

type regStamp struct {
	h  uint64
	at time.Time
}

// regRecord is what the guard remembers about one source key.
type regRecord struct {
	key      netip.Addr
	nonces   [regNoncesPerSource]regStamp
	ni       int
	branches [regBranchesPerSource]regStamp
	bi       int
	// struck are the attempts already counted (branch and attempt key), so
	// a UDP retransmission, or a replay later judged by the registrar too,
	// counts once.
	struck [regStruckPerSource]uint64
	si     int
}

// regGuard is the LRU-capped table of regRecords, keyed like the shield
// (an IPv4 address, an IPv6 /64). Nonces and branches are stored as 64-bit
// hashes, never in clear, and never logged.
type regGuard struct {
	mu      sync.Mutex
	entries map[netip.Addr]*list.Element // of *regRecord
	lru     *list.List                   // front = most recently challenged
	max     int
	now     func() time.Time
}

func newRegGuard() *regGuard {
	return &regGuard{entries: map[netip.Addr]*list.Element{}, lru: list.New(), max: regGuardSources, now: time.Now}
}

func regHash(s string) uint64 {
	f := fnv.New64a()
	_, _ = f.Write([]byte(s))
	return f.Sum64()
}

// challenged records that the edge relayed a challenge carrying nonces to
// src, in answer to the request with Via branch.
func (g *regGuard) challenged(src netip.Addr, branch string, nonces []string) {
	if len(nonces) == 0 {
		return
	}
	key := enumKey(src)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var r *regRecord
	if el, ok := g.entries[key]; ok {
		r = el.Value.(*regRecord)
		g.lru.MoveToFront(el)
	} else {
		if g.lru.Len() >= g.max {
			oldest := g.lru.Back()
			delete(g.entries, oldest.Value.(*regRecord).key)
			g.lru.Remove(oldest)
		}
		r = &regRecord{key: key}
		g.entries[key] = g.lru.PushFront(r)
	}
	for _, n := range nonces {
		r.nonces[r.ni] = regStamp{regHash(n), now}
		r.ni = (r.ni + 1) % len(r.nonces)
	}
	if branch != "" {
		r.branches[r.bi] = regStamp{regHash(branch), now}
		r.bi = (r.bi + 1) % len(r.branches)
	}
}

// countable reports whether an attempt from src (Via branch, nonce, and
// attempt key from fsip.DigestAttempt) is a new strike: its nonce was
// relayed to src's key within regNonceTTL, it has not been counted before,
// and, for a replay, its branch was challenged within regReplayWindow. A
// countable attempt is remembered as counted.
func (g *regGuard) countable(src netip.Addr, branch, nonce string, attempt uint64, replay bool) bool {
	if nonce == "" {
		return false
	}
	nh, bh := regHash(nonce), regHash(branch)
	g.mu.Lock()
	defer g.mu.Unlock()
	el, ok := g.entries[enumKey(src)]
	if !ok {
		return false
	}
	r := el.Value.(*regRecord)
	now := g.now()
	if !recent(r.nonces[:], nh, now, regNonceTTL) {
		return false
	}
	if replay && (branch == "" || !recent(r.branches[:], bh, now, regReplayWindow)) {
		return false
	}
	id := bh ^ (attempt * 0x9e3779b97f4a7c15)
	for _, s := range r.struck {
		if s == id {
			return false
		}
	}
	r.struck[r.si] = id
	r.si = (r.si + 1) % len(r.struck)
	return true
}

func recent(ring []regStamp, h uint64, now time.Time, ttl time.Duration) bool {
	for _, s := range ring {
		if s.h == h && !s.at.IsZero() && now.Sub(s.at) < ttl {
			return true
		}
	}
	return false
}

func (g *regGuard) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.entries)
}

// registerHead describes a public REGISTER for the guard: the same fields
// the read filter scans from raw bytes, taken from the parsed request.
func registerHead(req *sip.Request, aor string) fsip.RegisterHead {
	h := fsip.RegisterHead{AOR: aor, CallID: fsip.CallID(req)}
	if via := req.Via(); via != nil && via.Params != nil {
		h.Branch, _ = via.Params.Get("branch")
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization"} {
		if a := req.GetHeader(name); a != nil {
			h.Auth = true
			h.Nonce, h.AuthKey = fsip.DigestAttempt(a.Value())
			break
		}
	}
	return h
}

var registerLine = []byte("REGISTER ")

// registerReplayRead is the read filter's REGISTER hook, for a public UDP
// datagram that already passed the ban and rate checks. A REGISTER with
// credentials on a branch the edge has just challenged is a replay sipgo
// will answer from its transaction without running onRegister: it is
// counted here, and dropped if its strike bans the source.
func (s *Server) registerReplayRead(info sip.TransportReadProps, data []byte) (drop bool) {
	if !bytes.HasPrefix(data, registerLine) || !strings.EqualFold(info.Transport, "udp") || info.RemoteAddr == nil {
		return false
	}
	head, ok := fsip.ScanRegister(data)
	if !ok || !head.Auth {
		return false
	}
	src, err := netip.ParseAddrPort(info.RemoteAddr.String())
	if err != nil {
		return false
	}
	return s.registerStrike(src, head, true)
}

// registerStrike counts one failed credential attempt from src, if it is
// countable (see regGuard.countable and the exemptions above), and reports
// whether the strike banned src.
func (s *Server) registerStrike(src netip.AddrPort, head fsip.RegisterHead, replay bool) bool {
	sh := s.currentShield()
	if sh == nil || !head.Auth {
		return false
	}
	ip := src.Addr().Unmap()
	if s.carriers.snapshot().isSource(ip) || s.refreshesBinding(ip, head.AOR, head.CallID) {
		return false
	}
	if !s.regGuard.countable(ip, head.Branch, head.Nonce, head.AuthKey, replay) {
		return false
	}
	s.metrics.RegisterAuthFailed()
	// The same refused attempt is also a strike against the AoR, whatever
	// the source (issue #187): a distributed brute force keeps each source
	// under register_ban but not the AoR it all aims at.
	sh.StrikeAOR(head.AOR)
	return sh.Strike(ip, shield.StrikeRegister)
}

// aorLockedFor reports whether a REGISTER for aor from src is to be dropped
// because the AoR's limit is open (shield.register_ban_aor): src is neither
// a carrier source nor the holder of a live binding of aor (matched by
// source key, any port, so a phone that moved ports still refreshes).
func (s *Server) aorLockedFor(src netip.Addr, aor string) bool {
	sh := s.currentShield()
	if sh == nil || !sh.AORLocked(aor) {
		return false
	}
	src = src.Unmap()
	if s.carriers.snapshot().isSource(src) {
		return false
	}
	key := enumKey(src)
	for _, b := range s.loc.ByAOR(aor) {
		if enumKey(b.Source.Addr()) == key {
			return false
		}
	}
	return true
}

// refreshesBinding reports whether ip's source key holds a live binding of
// aor with this Call-ID: the request refreshes a registration that already
// succeeded.
func (s *Server) refreshesBinding(ip netip.Addr, aor, callID string) bool {
	if aor == "" || callID == "" {
		return false
	}
	key := enumKey(ip)
	for _, b := range s.loc.ByAOR(aor) {
		if b.CallID == callID && enumKey(b.Source.Addr()) == key {
			return true
		}
	}
	return false
}

// registerOutcome feeds the registrar's final answer to a public REGISTER
// into the guard, before it is relayed: a 2xx clears the source's strikes;
// a refused credential is a strike; a challenge is remembered, so the
// source's next attempt with its nonce can be counted.
func (s *Server) registerOutcome(in bindingInput, res *sip.Response) {
	code := res.StatusCode
	if code/100 == 2 {
		if sh := s.currentShield(); sh != nil {
			sh.ClearStrikes(in.source.Addr(), shield.StrikeRegister)
			sh.ClearStrikes(in.source.Addr(), shield.StrikeAdmission)
			sh.ClearAOR(in.aor)
		}
		return
	}
	nonces, stale := challengeNonces(res)
	switch code {
	case 401, 403, 404, 407:
		if !stale {
			s.registerStrike(in.source, in.head, false)
		}
	}
	if code == 401 || code == 407 {
		s.regGuard.challenged(in.source.Addr(), in.head.Branch, nonces)
	}
}

// challengeNonces returns the nonces of a response's WWW-Authenticate and
// Proxy-Authenticate challenges, and whether any is marked stale=true.
func challengeNonces(res *sip.Response) (nonces []string, stale bool) {
	for _, name := range []string{"WWW-Authenticate", "Proxy-Authenticate"} {
		for _, h := range res.GetHeaders(name) {
			v := h.Value()
			if n, ok := fsip.DigestParam(v, "nonce"); ok && n != "" {
				nonces = append(nonces, n)
			}
			if st, ok := fsip.DigestParam(v, "stale"); ok && strings.EqualFold(st, "true") {
				stale = true
			}
		}
	}
	return nonces, stale
}
