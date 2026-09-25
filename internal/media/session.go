package media

import (
	"net"
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
// and after it latches (spec §3 decision 5).
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
// only ever moves UP this ranking (or through an authorised relatch), and
// a latch at rankExact is final.
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

// latch tracks the remote endpoint of one UDP stream. An inbound packet
// that latches fixes where the stream's reverse direction is sent; after
// that only a better-vouched source (see latchRank) or an authorised
// relatch moves it (RTP-hijack hardening).
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
	// dst is the PROVISIONAL send-to address seeded from SDP. It carries
	// the reverse direction until an inbound packet latches — and, while
	// learning is delayed, until LearnDelay has passed since then.
	dst *net.UDPAddr
	// remote is the source an ACCEPTED INBOUND packet latched, rank how
	// well signalling vouched for it (rankNone = not latched), and
	// learnedAt when it latched.
	remote    *net.UDPAddr
	rank      latchRank
	learnedAt time.Time
	// allowLoopback lets seed install a loopback destination. It comes
	// from the pool the side was allocated from (PlaneParams.AllowLoopback)
	// and is fixed for the latch's lifetime.
	allowLoopback bool
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
	l.sigSource = ip.Unmap()
	l.mu.Unlock()
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
	l.dst = nil
	l.remote = nil
	l.rank = rankNone
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
	l.signalled = netip.AddrPortFrom(ip, addr.Port())
	if ip.IsLoopback() && !l.allowLoopback {
		return // arm the source check, but never send to it
	}
	l.dst = &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(addr.Port())}
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

// rankOf is how well signalling vouches for src under the latch's mode.
func (l *latch) rankOf(src *net.UDPAddr) latchRank {
	ip, ok := netip.AddrFromSlice(src.IP)
	if !ok {
		return rankNone
	}
	ip = ip.Unmap()
	if l.mode == LatchStrict && (!l.expected.IsValid() || ip != l.expected.Unmap()) {
		return rankNone // strict: reject until SetExpectedRemote arms the latch
	}
	switch {
	case l.signalled.IsValid() && ip == l.signalled.Addr() && src.Port == int(l.signalled.Port()):
		return rankExact
	case l.expected.IsValid() && ip == l.expected.Unmap(),
		l.sigSource.IsValid() && ip == l.sigSource:
		return rankSignalled
	}
	return rankAny
}

// accept reports whether a packet from src may be processed, latching the
// stream to src when it is the first acceptable source or a better-vouched
// one than the source already latched.
func (l *latch) accept(src *net.UDPAddr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rank != rankNone && l.remote.IP.Equal(src.IP) && l.remote.Port == src.Port {
		return true
	}
	r := l.rankOf(src)
	if r <= l.rank {
		return false // unacceptable, or no better than the latched source
	}
	l.remote = &net.UDPAddr{
		IP:   append(net.IP(nil), src.IP...),
		Port: src.Port,
		Zone: src.Zone,
	}
	l.rank = r
	l.learnedAt = l.clock()
	return true
}

// learningDelayed reports whether a below-exact latch waits LearnDelay
// before it becomes the destination: the SDP address was installed and is
// the address the side's SIP came from, so it is plausibly where the
// endpoint listens — not a private address behind a NAT.
func (l *latch) learningDelayed() bool {
	return l.dst != nil && l.sigSource.IsValid() && l.signalled.Addr() == l.sigSource
}

// target returns where the reverse direction is sent: the latched remote,
// the SDP-seeded destination before latching (or while learning is
// delayed), or nil when there is neither.
func (l *latch) target() *net.UDPAddr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rank == rankNone {
		return l.dst
	}
	if l.rank < rankExact && l.learningDelayed() && l.clock().Sub(l.learnedAt) < LearnDelay {
		return l.dst
	}
	return l.remote
}

// SessionConfig configures one relayed call.
type SessionConfig struct {
	// Latch is the per-side latching mode (zero value = strict).
	Latch [2]LatchMode
	// Timeout tears the session down after this much silence; zero means
	// the pool's PlaneParams.Timeout (listen.media.rtp_timeout), read with
	// the rest of the allocation's parameters.
	Timeout time.Duration
}

// Session is the media half of one call: two port pairs relaying RTP and
// RTCP between side A and side B. Lifecycle: Allocate → SetExpectedRemote
// (from SDP) → Start → Close, or automatic teardown on RTP silence,
// observable via Done. Safe for concurrent use.
type Session struct {
	// pools[side] is the pool that side's pair came from. Two entries
	// rather than one shared pool because the edge proxy allocates side A
	// from the PUBLIC plane and side B from the PRIVATE one (see
	// AllocateAcross); the trunk B2BUA plane simply passes the same pool
	// twice.
	pools   [2]*PlanePool
	pairs   [2]*portPair
	rtp     [2]*latch
	rtcp    [2]*latch
	timeout time.Duration

	// srtpIn/srtpOut are atomic.Pointer, not plain fields: the relay's forward
	// loops (media/relay.go) read them per-packet from already-running
	// goroutines, and SetSRTP can legitimately be called again after Start —
	// e.g. a failover target's answer replacing an earlier target's early-media
	// contexts (see processAnswerSDP in sig/b2bua.go). Plain fields would be a
	// data race under -race and, worse, could tear under concurrent
	// read/write. atomic.Pointer makes every Store/Load a single atomic op, so
	// SetSRTP is safe to call at any point in the session's lifecycle.
	srtpIn  [2]atomic.Pointer[SRTPContext] // decrypt packets received FROM this side (nil = plaintext)
	srtpOut [2]atomic.Pointer[SRTPContext] // encrypt packets sent TO this side (nil = plaintext)

	lastRx   [2]atomic.Int64 // per sending side: unix nanos of its last genuine packet
	counters counters
	done     chan struct{}

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

// Allocate binds two port pairs (side A and side B) for one call from
// this single pool — the trunk B2BUA plane's shape. The caller must Close
// the session — or rely on silence teardown — to return the ports.
// Returns ErrPortsExhausted when the range is full.
func (p *PlanePool) Allocate(cfg SessionConfig) (*Session, error) {
	return p.AllocateWith(p.params(), cfg)
}

// AllocateWith is Allocate with the pool's parameters supplied by the
// caller, for a signalling plane that takes one config snapshot per call
// and must not let the pool read a second, newer one (audit P2-TRK-005).
func (p *PlanePool) AllocateWith(par PlaneParams, cfg SessionConfig) (*Session, error) {
	return allocateAcross(p, par, p, par, cfg)
}

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
	allowLoopback := [2]bool{parA.AllowLoopback, parB.AllowLoopback}
	for side := range s.pairs {
		s.rtp[side] = &latch{mode: cfg.Latch[side], allowLoopback: allowLoopback[side]}
		s.rtcp[side] = &latch{mode: cfg.Latch[side], allowLoopback: allowLoopback[side]}
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

// SetRemote seeds one side's send-to address AND its expected source IP
// from that side's SDP, so media can flow to it before its first packet
// arrives. The first accepted inbound packet still overrides the
// destination (symmetric RTP) — see latch.seed.
func (s *Session) SetRemote(side Side, addr netip.AddrPort) {
	s.rtp[side].seed(addr)
	if rtcp, ok := rtcpAddr(addr); ok {
		s.rtcp[side].seed(rtcp)
	}
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
	s.rtp[side].relatch(addr)
	rtcp, ok := rtcpAddr(addr)
	if !ok {
		rtcp = netip.AddrPortFrom(addr.Addr(), 0) // re-arm the source check only
	}
	s.rtcp[side].relatch(rtcp)
}

// SetLatchMode changes both the RTP and RTCP latch policy of one side at
// runtime, to align it with the peer actually selected for the call — e.g.
// a failover winner whose media_latch differs from the target the session
// was originally Allocated against. Safe to call at any point in the
// session's lifecycle, including after packets have already latched (it
// only changes how a not-yet-latched or future latch decides acceptance;
// see latch.accept).
func (s *Session) SetLatchMode(side Side, mode LatchMode) {
	s.rtp[side].setMode(mode)
	s.rtcp[side].setMode(mode)
}

// ParseLatchMode maps a peer's media_latch config string to a LatchMode.
// Anything other than "loose" is strict (the safe default).
func ParseLatchMode(s string) LatchMode {
	if s == "loose" {
		return LatchLoose
	}
	return LatchStrict
}

// SetSRTP installs the SRTP contexts for one side: inbound decrypts what we
// receive from that side, outbound encrypts what we send to it. A nil context
// means that direction is plaintext. Safe to call at any point in the
// session's lifecycle, including after Start and more than once for the same
// side (srtpIn/srtpOut are atomic.Pointer) — e.g. a B-leg failover target's
// answer must be able to replace (or clear) the contexts an earlier target's
// early media already installed, without racing the relay's forward loops.
func (s *Session) SetSRTP(side Side, inbound, outbound *SRTPContext) {
	if s.state.Load() == sessClosed {
		return // the relay is gone; installing keys on it would be a lie
	}
	s.srtpIn[side].Store(inbound)
	s.srtpOut[side].Store(outbound)
}

// Done is closed when the session ends (Close or silence timeout).
func (s *Session) Done() <-chan struct{} { return s.done }

// Close tears the session down and returns its ports to the pool.
// Idempotent and safe to call from any goroutine.
func (s *Session) Close() error {
	if s.state.Swap(sessClosed) == sessClosed {
		return nil
	}
	for _, pp := range s.pairs {
		pp.Close()
	}
	s.pools[SideA].release(s.pairs[SideA].RTPPort())
	s.pools[SideB].release(s.pairs[SideB].RTPPort())
	close(s.done)
	return nil
}
