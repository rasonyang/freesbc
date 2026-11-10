package media

import (
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Side identifies one leg of a relayed call.
type Side int

const (
	SideA Side = 0
	SideB Side = 1
)

// LatchMode controls which inbound packet sources a stream accepts before
// and after it latches.
type LatchMode int

const (
	// LatchStrict (default) requires a packet's source IP to match the
	// address set via SetExpectedRemote (or seeded by SetRemote); the
	// port may differ (NAT). With no expectation set, every packet is
	// rejected: a strict latch fails closed until signaling arms it.
	LatchStrict LatchMode = iota
	// LatchLoose also accepts a source signalling never named (a hard-NAT
	// peer whose SDP carries an unroutable address), but only until a
	// source signalling vouches for is heard: see latchRank.
	LatchLoose
)

// latchRank is how well signalling vouches for a packet source. A latch
// moves UP this ranking at once, sideways or down only onto a vouched
// source (rankSignalled or better) once the latched one has been silent for
// LatchFallback, or through an authorised relatch.
//
//   - rankExact: the exact IP:port the side's SDP signalled.
//   - rankSignalled: the SDP's IP from another port (a NAT that rewrote
//     the port), or the IP the side's SIP came from (SetSignallingSource:
//     a phone behind NAT whose SDP carries its private address sends RTP
//     from the same public IP as its SIP).
//   - rankAny: any other source. LatchLoose only.
//
// This is what closes the first-packet hijack (P2-EDG-001): a source that
// sprays the port range before the real endpoint speaks wins at most a
// rankAny latch, which the endpoint's first packet from a vouched address
// takes back.
type latchRank uint8

const (
	rankNone latchRank = iota // not latched / rejected
	rankAny
	rankSignalled
	rankExact
)

// LearnDelay is how long a latch keeps sending to the SDP-signalled
// address after it latched a below-exact source, when that SDP address is
// plausible: it is the address the side's SIP came from, so there is no
// NAT between them and the endpoint should be sending from it. A packet
// from the exact signalled address latches at once; only after the delay
// does the destination move to the below-exact source. Modelled on
// rtpengine's "delayed" endpoint learning: a symmetric endpoint never
// waits, one whose port was rewritten loses at most this much of its
// inbound audio, and a packet sprayed at the port from the endpoint's own
// IP does not redirect the call's audio to its sender.
const LearnDelay = 3 * time.Second

// LatchFallback is how long a latched source must be silent before a vouched
// source (rankSignalled or better, never rankAny) of no higher rank than the
// latch may take it over. Without it a few stray packets from the exact SDP
// address would replace a live stream from another port of the same IP for
// the rest of the call (#324). A stream that is still flowing is never
// taken over by a same-IP source. Once the latch fell back away from a
// rankExact source, dest sends to the SDP address (the peer proved it
// listens there) so an echoing peer cannot make the two sources alternate.
const LatchFallback = time.Second

// latch tracks the remote endpoint of one UDP stream. An inbound packet
// that latches fixes where the stream's reverse direction is sent; after
// that only a better-vouched source (see latchRank) or an authorised
// relatch moves it (RTP-hijack hardening).
//
// Addresses are netip values, so the per-packet path (ReadFromUDPAddrPort,
// acceptFrom, dest, WriteToUDPAddrPort) allocates nothing. Sources are
// compared as net.IP.Equal compared them: an IPv4-mapped IPv6 address
// equals its IPv4 form and the zone is ignored (hostOf).
type latch struct {
	mu       sync.Mutex
	mode     LatchMode
	expected netip.Addr // zero value = no expectation
	// signalled is the exact media address the side's SDP gave (see
	// seed); zero until seeded.
	signalled netip.AddrPort
	// sigSource is the IP the side's SIP signalling came from, when the
	// signaling plane knows it (setSignallingSource); zero otherwise.
	sigSource netip.Addr
	// dst is the PROVISIONAL send-to address seeded from SDP (invalid when
	// none). It carries the reverse direction until an inbound packet
	// latches — and, while learning is delayed, until LearnDelay has
	// passed since then.
	dst netip.AddrPort
	// remote is the source an ACCEPTED INBOUND packet latched (unmapped,
	// zone kept for sending), rank how well signalling vouched for it
	// (rankNone = not latched), and learnedAt when it latched.
	remote    netip.AddrPort
	rank      latchRank
	learnedAt time.Time
	// lastSeen is when remote last had a packet accepted (the silence
	// fallback). exactLost is set when the latch fell back away from a
	// rankExact remote: dest then sends to dst (the exact signalled
	// address) until relatch or a seed of a different address resets it.
	lastSeen  time.Time
	exactLost bool
	// allowLoopback lets seed install a loopback destination. It comes
	// from the pool the side was allocated from (PlaneParams.AllowLoopback)
	// and is fixed for the latch's lifetime.
	allowLoopback bool
	// policy is the pool's destination class policy (PlaneParams.Dest),
	// fixed for the latch's lifetime. The zero value refuses nothing.
	policy DestPolicy
	// pinSeed makes seed send to sigSource instead of the SDP address (see
	// Session.PinSeedToSignallingSource); changed at runtime, under mu.
	pinSeed bool
	// now is the clock; nil means time.Now. Tests replace it.
	now func() time.Time
}

func (l *latch) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *latch) setExpected(ip netip.Addr) {
	l.mu.Lock()
	l.expected = ip
	l.mu.Unlock()
}

// setSignallingSource records the IP the side's SIP signalling came from
// (see rankSignalled and LearnDelay).
func (l *latch) setSignallingSource(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sigSource = ip.Unmap()
	// A pinned side whose SDP is already known (an earlier fork's phone,
	// or a seed that came before its source) follows the new source until
	// a packet latches.
	if l.pinSeed && l.signalled.IsValid() && l.rank == rankNone {
		l.dst = netip.AddrPort{}
		if l.pinnedOK(l.sigSource) {
			l.dst = netip.AddrPortFrom(l.sigSource.WithZone(""), l.signalled.Port())
		}
	}
}

// setPinSeed turns the signalling-source pin on or off for later seeds.
func (l *latch) setPinSeed(on bool) {
	l.mu.Lock()
	l.pinSeed = on
	l.mu.Unlock()
}

// pinnedOK reports whether ip may be the destination of a pinned side:
// a valid unicast address that passes the loopback rule. Callers hold mu.
func (l *latch) pinnedOK(ip netip.Addr) bool {
	return ip.IsValid() && unicastMediaAddr(ip) && (!ip.IsLoopback() || l.allowLoopback)
}

// setMode changes the latch's strict/loose policy at runtime. Used when the
// peer actually selected for a call (e.g. the winning failover target)
// carries a different media_latch setting than whatever the session was
// allocated with.
func (l *latch) setMode(m LatchMode) {
	l.mu.Lock()
	l.mode = m
	l.mu.Unlock()
}

// relatch re-arms the latch to a new signalled media address: the
// expected source becomes addr's IP, the current remote is forgotten, and
// addr is seeded as the provisional destination — so media keeps flowing
// to the new address before (or without) its first packet, as it must for
// a recvonly peer or an IVR that waits to hear audio. The next packet from
// the new expected IP re-latches as usual. Used only for authorized
// media-address changes (re-INVITE, a new answer); unsolicited packets
// still cannot move a latch.
//
// An addr with no usable port re-arms the source check only; one whose
// IP is invalid (an FQDN the caller did not resolve) clears it.
func (l *latch) relatch(addr netip.AddrPort) {
	l.mu.Lock()
	l.expected = addr.Addr()
	l.signalled = netip.AddrPort{}
	l.dst = netip.AddrPort{}
	l.remote = netip.AddrPort{}
	l.rank = rankNone
	l.exactLost = false
	l.mu.Unlock()
	l.seed(addr)
}

// seed sets the expected source IP, the exact signalled address and a
// PROVISIONAL send-to address, all taken from the far side's SDP, without
// latching.
//
// Without it the relay cannot send anything until the far side has sent
// first: target() would be nil, so an endpoint waiting to hear audio
// before producing any would deadlock against another doing the same. With
// it, media flows to the signalled address immediately, and the first
// packet that latches still overrides the destination — which is exactly
// symmetric RTP, and is what carries the stream through a NAT that
// rewrote the port.
//
// The anti-hijack property is unchanged: a seed never latches, and once a
// real packet has latched, SDP does not move it; only a better-vouched
// source (latchRank) or an authorized re-INVITE does.
//
// Only a unicast address is ever installed as a destination (see
// seedableDestination): the unspecified address (RFC 3264 §8.4 hold),
// multicast, broadcast and link-local addresses are ignored outright, and
// a loopback address only arms the source check unless the pool allows
// loopback — otherwise a public client's SDP could make the SBC's media
// socket send to a service on the SBC host itself.
//
// Two more rules shape the destination IP (the SDP port is always kept).
// A pinned side (PinSeedToSignallingSource: a registered client) sends to
// the IP its signalling came from, whatever its SDP says, and to nothing
// while that IP is unknown; the SDP address still arms the source check.
// On any other side the pool's DestPolicy refuses the classes that can
// never be a peer's media (private, CGNAT, the SBC's own addresses on a
// public plane): the source check is armed but nothing is sent until the
// peer's first packet latches.
func (l *latch) seed(addr netip.AddrPort) {
	if !addr.IsValid() || addr.Port() == 0 {
		return
	}
	ip := addr.Addr().Unmap()
	if !unicastMediaAddr(ip) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expected = ip
	if sig := netip.AddrPortFrom(ip, addr.Port()); sig != l.signalled {
		l.exactLost = false // a refresh of the same address keeps it
		l.signalled = sig
	}
	send := ip
	if l.pinSeed {
		send = l.sigSource
		if !l.pinnedOK(send) {
			return
		}
	} else if l.policy.refuses(ip) {
		return
	}
	if send.IsLoopback() && !l.allowLoopback {
		return // arm the source check, but never send to it
	}
	l.dst = netip.AddrPortFrom(send.WithZone(""), addr.Port())
}

// unicastMediaAddr reports whether ip can be a unicast RTP peer at all:
// not unspecified, multicast, the IPv4 limited broadcast, or link-local.
// Loopback passes here; whether it may be SENT to is the pool's policy.
func unicastMediaAddr(ip netip.Addr) bool {
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), ip.IsMulticast(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
		return false
	case ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return false
	}
	return true
}

// hostOf is src's address as the latch compares it: unmapped and without
// a zone, which is how net.IP.Equal (and netip.AddrFromSlice) saw a
// *net.UDPAddr source before the relay moved to netip.
func hostOf(src netip.AddrPort) netip.Addr {
	return src.Addr().Unmap().WithZone("")
}

// sameSource reports whether src is the latched remote.
func (l *latch) sameSource(src netip.AddrPort) bool {
	return l.rank != rankNone && hostOf(l.remote) == hostOf(src) && l.remote.Port() == src.Port()
}

// rankOf is how well signalling vouches for src under the latch's mode.
func (l *latch) rankOf(src netip.AddrPort) latchRank {
	if !src.Addr().IsValid() {
		return rankNone
	}
	ip := hostOf(src)
	if l.mode == LatchStrict && (!l.expected.IsValid() || ip != l.expected.Unmap()) {
		return rankNone // strict: reject until SetExpectedRemote arms the latch
	}
	switch {
	case l.signalled.IsValid() && ip == l.signalled.Addr() && src.Port() == l.signalled.Port():
		return rankExact
	case l.expected.IsValid() && ip == l.expected.Unmap(),
		l.sigSource.IsValid() && ip == l.sigSource:
		return rankSignalled
	}
	return rankAny
}

// latchEvent is what a latch decision did, for the caller to count and log
// once the latch mutex is released.
type latchEvent uint8

const (
	evSame    latchEvent = iota // accepted without a latch change (or, for permits, would be accepted)
	evSet                       // first latch (from rankNone)
	evMoved                     // replaced a latched source with a better-vouched or live one
	evRefused                   // not accepted
)

// latchVerdict is the value-typed result of a latch decision. held and
// heldRank describe the source latched BEFORE the decision (rankNone when
// none); rank is how well src is vouched for. fallback marks a move that
// was not a rank upgrade: the held source had been silent for LatchFallback.
type latchVerdict struct {
	ev       latchEvent
	held     netip.AddrPort
	heldRank latchRank
	rank     latchRank
	fallback bool
}

func (v latchVerdict) ok() bool { return v.ev != evRefused }

// reason names why a refusal happened: "source" when the mode or the
// armed expectation rejects src outright, "latched" when src is no better
// vouched than the source already held, or the held source is still live.
func (v latchVerdict) reason() string {
	if v.rank == rankNone {
		return "source"
	}
	return "latched"
}

// takes decides whether a packet from src (not the latched remote) may move
// the latch at now, and to which rank. fallback reports a move that is not a
// rank upgrade. Callers hold mu.
func (l *latch) takes(src netip.AddrPort, now time.Time) (r latchRank, ok, fallback bool) {
	r = l.rankOf(src)
	switch {
	case r > l.rank:
		return r, true, false
	case r >= rankSignalled && r <= l.rank && now.Sub(l.lastSeen) >= LatchFallback:
		return r, true, true // the latched source went silent: follow the live one
	}
	return r, false, false
}

// acceptFrom reports whether a packet from src may be processed, latching
// the stream to src when it is the first acceptable source, a better-vouched
// one than the source already latched, or a vouched one while the latched
// source has been silent for LatchFallback.
func (l *latch) acceptFrom(src netip.AddrPort) bool {
	return l.decide(src, l.clock()).ok()
}

// decide is acceptFrom at a clock reading the caller already took (so the
// relay's per-packet path reads the clock once), reporting what happened so
// the caller can count and log it outside the latch mutex. The
// already-latched path allocates nothing and takes the mutex once.
func (l *latch) decide(src netip.AddrPort, now time.Time) latchVerdict {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sameSource(src) {
		l.lastSeen = now
		return latchVerdict{ev: evSame}
	}
	r, ok, fb := l.takes(src, now)
	if !ok {
		// unacceptable, or no better than the live latched source
		return latchVerdict{ev: evRefused, held: l.remote, heldRank: l.rank, rank: r}
	}
	v := latchVerdict{ev: evSet, held: l.remote, heldRank: l.rank, rank: r, fallback: fb}
	if l.rank != rankNone {
		v.ev = evMoved
	}
	if l.rank == rankExact {
		l.exactLost = true
	}
	l.remote = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	l.rank = r
	l.learnedAt = now
	l.lastSeen = now
	return v
}

// permitsFrom reports whether acceptFrom would take a packet from src,
// without latching to it. The SDES path checks it before spending a
// decrypt on a source the latch refuses anyway, and calls acceptFrom only
// once the packet has authenticated, so a forged packet never moves the
// latch.
func (l *latch) permitsFrom(src netip.AddrPort) bool { return l.permit(src, l.clock()).ok() }

// permit is permitsFrom at the caller's clock reading, reporting the
// verdict (never evSet or evMoved).
func (l *latch) permit(src netip.AddrPort, now time.Time) latchVerdict {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sameSource(src) {
		return latchVerdict{ev: evSame}
	}
	r, ok, _ := l.takes(src, now)
	if !ok {
		return latchVerdict{ev: evRefused, held: l.remote, heldRank: l.rank, rank: r}
	}
	return latchVerdict{ev: evSame, rank: r} // would be accepted; nothing latched
}

// learningDelayed reports whether a below-exact latch waits LearnDelay
// before it becomes the destination: the SDP address was installed and is
// the address the side's SIP came from, so it is plausibly where the
// endpoint listens — not a private address behind a NAT.
func (l *latch) learningDelayed() bool {
	return l.dst.IsValid() && l.sigSource.IsValid() && l.signalled.Addr() == l.sigSource
}

// dest returns where the reverse direction is sent: the latched remote,
// the SDP-seeded destination before latching (or while learning is
// delayed), or an invalid AddrPort when there is neither.
func (l *latch) dest() netip.AddrPort {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rank == rankNone {
		return l.dst
	}
	if l.exactLost && l.dst.IsValid() && l.dst == l.signalled {
		return l.dst
	}
	if l.rank < rankExact && l.learningDelayed() && l.clock().Sub(l.learnedAt) < LearnDelay {
		return l.dst
	}
	return l.remote
}

// CloseCause is why a session closed. It describes the media plane only; a
// caller maps it onto whatever its own signaling needs.
type CloseCause int32

const (
	// CloseNone: the session has not closed.
	CloseNone CloseCause = iota
	// CloseRequested: its owner called Close.
	CloseRequested
	// CloseSilence: the silence watchdog fired.
	CloseSilence
	// CloseLegFailed: a WebRTC leg failed to establish or to verify its peer
	// (ICE, DTLS or fingerprint).
	CloseLegFailed
	// CloseFault: a relay goroutine panicked.
	CloseFault
)

// SessionConfig configures one relayed call.
type SessionConfig struct {
	// Latch is the per-side latching mode (zero value = strict).
	Latch [2]LatchMode
	// Timeout tears the session down after this much silence; zero means
	// the Timeout of side A's pool PlaneParams (see AllocateAcross).
	Timeout time.Duration
	// Log receives the latch logs (a refused-packet WARN, a latch move);
	// nil uses the default logger. Each side is named in them by its
	// pool's name (NewPlanePool), "a" or "b" when that is empty.
	Log *slog.Logger
}

// Session is the media half of one call: two port pairs relaying RTP and
// RTCP between side A and side B. Lifecycle: AllocateAcross → SetExpectedRemote
// (from SDP) → Start → Close, or automatic teardown on RTP silence,
// observable via Done. Safe for concurrent use.
type Session struct {
	// pools[side] is the pool that side's pair came from. Two entries
	// rather than one shared pool because the edge proxy allocates side A
	// from the PUBLIC plane and side B from the PRIVATE one (see
	// AllocateAcross).
	pools   [2]*PlanePool
	pairs   [2]*portPair
	rtp     [2]*latch
	rtcp    [2]*latch
	timeout time.Duration

	// sdes[side] is non-nil once the side is an SDES-SRTP side (sdes.go).
	sdes [2]atomic.Pointer[sdesLeg]

	lastRx   [2]atomic.Int64 // per sending side: unix nanos of its last genuine packet
	counters counters
	// rep counts and logs what the latches decide (latchlog.go).
	rep  latchReporter
	done chan struct{}
	// cause is why the session closed, stored by the Close that won, before
	// done is closed (see CloseCause).
	cause atomic.Int32

	// state is the session's lifecycle, made explicit rather than inferred
	// from a sync.Once plus "are the goroutines running": every transition
	// is one atomic step, so Start and Close are each idempotent and can
	// race each other without a half-started relay or a double release.
	state atomic.Int32
}

// Session and WebRTCSession lifecycle states. Transitions only ever move
// forward: allocated → running → closed, or allocated → closed.
const (
	sessAllocated int32 = iota
	sessRunning
	sessClosed
)

// Stats returns the session's packet counters, per side.
func (s *Session) Stats() Stats { return s.counters.snapshot() }

// AllocateAcross binds side A from poolA and side B from poolB. This is
// the edge proxy's shape: the public side's socket lives in the public
// plane's range and binds the public address, the private side's in the
// private plane's — so neither leg can ever be told to send media to the
// other plane's address.
//
// On failure the already-bound pair is closed and released, so a partial
// allocation never leaks a socket or a port reservation.
//
// Each pool's parameters are read once, so one allocation never mixes two
// config snapshots (audit P2-MED-009).
func AllocateAcross(poolA, poolB *PlanePool, cfg SessionConfig) (*Session, error) {
	parA := poolA.params()
	parB := parA
	if poolB != poolA {
		parB = poolB.params()
	}
	return allocateAcross(poolA, parA, poolB, parB, cfg)
}

func allocateAcross(poolA *PlanePool, parA PlaneParams, poolB *PlanePool, parB PlaneParams, cfg SessionConfig) (*Session, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = parA.Timeout
	}
	a, err := poolA.allocatePairWith(parA)
	if err != nil {
		return nil, err
	}
	b, err := poolB.allocatePairWith(parB)
	if err != nil {
		a.Close()
		poolA.release(a.RTPPort())
		return nil, err
	}
	s := &Session{
		pools:   [2]*PlanePool{poolA, poolB},
		pairs:   [2]*portPair{a, b},
		timeout: cfg.Timeout,
		done:    make(chan struct{}),
	}
	s.rep = newLatchReporter(cfg.Log, &s.counters, [2]string{poolA.name, poolB.name}, [2]*planeBudget{&poolA.rejectBudget, &poolB.rejectBudget})
	pars := [2]PlaneParams{parA, parB}
	for side := range s.pairs {
		s.rtp[side] = &latch{mode: cfg.Latch[side], allowLoopback: pars[side].AllowLoopback, policy: pars[side].Dest}
		s.rtcp[side] = &latch{mode: cfg.Latch[side], allowLoopback: pars[side].AllowLoopback, policy: pars[side].Dest}
	}
	return s, nil
}

// RTPPort returns the local RTP port of one side (RTCP is RTP+1); the
// signaling plane writes these into rewritten SDP.
func (s *Session) RTPPort(side Side) int { return s.pairs[side].RTPPort() }

// SetExpectedRemote records the SDP-signaled media source IP for one side;
// strict latching checks the first packet against it.
func (s *Session) SetExpectedRemote(side Side, ip netip.Addr) {
	s.rtp[side].setExpected(ip)
	s.rtcp[side].setExpected(ip)
}

// SetSignallingSource records the IP one side's SIP signalling came from.
// A loose latch ranks a packet from it above an unknown source, and, when
// the side's SDP address is that same IP, delays learning any other
// source by LearnDelay (see latchRank). Survives Relatch.
func (s *Session) SetSignallingSource(side Side, ip netip.Addr) {
	s.rtp[side].setSignallingSource(ip)
	s.rtcp[side].setSignallingSource(ip)
}

// PinSeedToSignallingSource makes later seeds of one side (SetRemote,
// SetRTCPRemote, Relatch) send to the IP set by SetSignallingSource with
// the SDP's port, instead of the SDP's own address: a registered client's
// SDP cannot steer the SBC's media socket to another host. Call it before
// SetRemote; SetSignallingSource must also be set, or the side sends
// nothing until its first packet latches. The pin survives Relatch and a
// packet from the real source still latches as usual.
func (s *Session) PinSeedToSignallingSource(side Side, on bool) {
	s.rtp[side].setPinSeed(on)
	s.rtcp[side].setPinSeed(on)
}

// SetRemote seeds one side's send-to address AND its expected source IP
// from that side's SDP, so media can flow to it before its first packet
// arrives. The first accepted inbound packet still overrides the
// destination (symmetric RTP) — see latch.seed.
func (s *Session) SetRemote(side Side, addr netip.AddrPort) {
	seedPair(s.rtp[side], s.rtcp[side], addr)
}

// seedPair seeds an RTP/RTCP latch pair from one signalled media address:
// RTP to addr, RTCP to addr's port+1 (left unseeded when that port does not
// exist). It is the one seeding rule for Session and WebRTCSession.
func seedPair(rtp, rtcp *latch, addr netip.AddrPort) {
	rtp.seed(addr)
	if r, ok := rtcpAddr(addr); ok {
		rtcp.seed(r)
	}
}

// relatchPair re-arms an RTP/RTCP latch pair to a newly signalled address.
// When addr has no RTCP port+1 the RTCP source check is still re-armed, with
// port 0, so a re-INVITE cannot leave the old RTCP latch open to a hijack.
// It is the one re-latch rule for Session and WebRTCSession; keep them
// from drifting apart.
func relatchPair(rtp, rtcp *latch, addr netip.AddrPort) {
	rtp.relatch(addr)
	r, ok := rtcpAddr(addr)
	if !ok {
		r = netip.AddrPortFrom(addr.Addr(), 0) // re-arm the source check only
	}
	rtcp.relatch(r)
}

// rtcpAddr is the conventional RTCP address for a media address: the RTP
// port plus one (RFC 3550 §11). ok is false when that port does not exist.
// An explicit a=rtcp is handled by the caller passing the port it parsed.
func rtcpAddr(addr netip.AddrPort) (netip.AddrPort, bool) {
	if addr.Port() < 65535 {
		return netip.AddrPortFrom(addr.Addr(), addr.Port()+1), true
	}
	return netip.AddrPort{}, false
}

// SetRTCPRemote overrides just the RTCP send-to address of one side, for a
// peer whose a=rtcp names a port other than RTP+1.
func (s *Session) SetRTCPRemote(side Side, addr netip.AddrPort) {
	s.rtcp[side].seed(addr)
}

// Relatch re-arms both the RTP and RTCP latches of one side to the newly
// signalled media address, for an authorized change (a re-INVITE, or an
// answer from another fork or failover target). It re-seeds the send-to
// addresses too — RTP to addr, RTCP to addr's port+1 — so the side keeps
// receiving media even if it never sends first; follow it with
// SetRTCPRemote for an explicit a=rtcp port.
func (s *Session) Relatch(side Side, addr netip.AddrPort) {
	relatchPair(s.rtp[side], s.rtcp[side], addr)
}

// SendTarget is where one side's RTP is sent right now: the latched
// remote, the seeded destination before a latch, or the zero value when
// the side has neither (nothing is sent until its first packet latches).
func (s *Session) SendTarget(side Side) netip.AddrPort { return s.rtp[side].dest() }

// Done is closed when the session ends (Close or silence timeout).
func (s *Session) Done() <-chan struct{} { return s.done }

// Cause says why the session closed; CloseNone until Done is closed.
func (s *Session) Cause() CloseCause { return CloseCause(s.cause.Load()) }

// Close tears the session down and returns its ports to the pool.
// Idempotent and safe to call from any goroutine.
func (s *Session) Close() error { return s.closeWith(CloseRequested) }

// closeWith is Close recording why. Only the call that wins the close
// records a cause, and it does so before Done fires.
func (s *Session) closeWith(c CloseCause) error {
	if s.state.Swap(sessClosed) == sessClosed {
		return nil
	}
	s.cause.Store(int32(c))
	for _, pp := range s.pairs {
		pp.Close()
	}
	s.pools[SideA].release(s.pairs[SideA].RTPPort())
	s.pools[SideB].release(s.pairs[SideB].RTPPort())
	close(s.done)
	return nil
}
