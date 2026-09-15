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

// LatchMode controls how the first inbound packet of a stream is matched
// against the SDP-signaled source address (spec §3 decision 5).
type LatchMode int

const (
	// LatchStrict (default) requires the first packet's source IP to match
	// the address set via SetExpectedRemote; the port may differ (NAT).
	// With no expectation set, the first packet is accepted from anywhere.
	LatchStrict LatchMode = iota
	// LatchLoose accepts the first packet from any source (hard-NAT peers).
	LatchLoose
)

// latch tracks the remote endpoint of one UDP stream. The first accepted
// packet fixes the remote address; the latch never moves afterwards
// (RTP-hijack hardening).
type latch struct {
	mu       sync.Mutex
	mode     LatchMode
	expected netip.Addr // zero value = no expectation
	remote   *net.UDPAddr
	// latched records whether remote was fixed by an ACCEPTED INBOUND
	// packet, as opposed to merely seeded from SDP (see seed). Only a
	// latched remote is treated as final; a seeded one is still open to
	// being corrected by the first genuine packet, which is what makes
	// symmetric RTP work through NAT.
	latched bool
}

func (l *latch) setExpected(ip netip.Addr) {
	l.mu.Lock()
	l.expected = ip
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

// relatch re-arms the latch to a new expected IP and forgets the current
// remote, so the next packet from the new expected address re-latches. Used
// only for authorized media-address changes (re-INVITE); unsolicited packets
// still cannot move a latch.
func (l *latch) relatch(ip netip.Addr) {
	l.mu.Lock()
	l.expected = ip
	l.remote = nil
	l.latched = false
	l.mu.Unlock()
}

// seed sets both the expected source IP and a PROVISIONAL send-to address
// taken from the far side's SDP, without latching.
//
// Without it the relay cannot send anything until the far side has sent
// first: target() would be nil, so an endpoint waiting to hear audio
// before producing any would deadlock against another doing the same. With
// it, media flows to the signalled address immediately, and the first
// packet that passes the strict-mode source check still overrides the
// destination — which is exactly symmetric RTP, and is what carries the
// stream through a NAT that rewrote the port.
//
// The anti-hijack property is unchanged: a seeded (not yet latched) remote
// accepts inbound packets only from the expected IP, and once a real
// packet has latched it, nothing moves it again short of an authorized
// re-INVITE.
func (l *latch) seed(addr netip.AddrPort) {
	if !addr.IsValid() || addr.Port() == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expected = addr.Addr()
	if l.latched {
		return // a real packet already fixed this; SDP does not override it
	}
	l.remote = &net.UDPAddr{IP: net.IP(addr.Addr().AsSlice()), Port: int(addr.Port())}
}

// accept reports whether a packet from src may be processed, latching the
// stream to src on the first acceptance.
func (l *latch) accept(src *net.UDPAddr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.latched {
		return l.remote.IP.Equal(src.IP) && l.remote.Port == src.Port
	}
	if l.mode == LatchStrict {
		if !l.expected.IsValid() {
			return false // strict: reject until SetExpectedRemote arms the latch
		}
		ip, ok := netip.AddrFromSlice(src.IP)
		if !ok || ip.Unmap() != l.expected.Unmap() {
			return false
		}
	}
	l.remote = &net.UDPAddr{
		IP:   append(net.IP(nil), src.IP...),
		Port: src.Port,
		Zone: src.Zone,
	}
	l.latched = true
	return true
}

// target returns the latched remote, or nil before latching.
func (l *latch) target() *net.UDPAddr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.remote
}

// SessionConfig configures one relayed call.
type SessionConfig struct {
	// Latch is the per-side latching mode (zero value = strict).
	Latch [2]LatchMode
	// Timeout tears the session down after this much silence; zero means
	// use listen.media.rtp_timeout from the current config snapshot.
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

	lastRx   atomic.Int64 // unix nanos of the last accepted packet
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

// Stats returns the session's packet counters (side A reported as
// "public", side B as "private").
func (s *Session) Stats() Stats { return s.counters.snapshot() }

// Allocate binds two port pairs (side A and side B) for one call from
// this single pool — the trunk B2BUA plane's shape. The caller must Close
// the session — or rely on silence teardown — to return the ports.
// Returns ErrPortsExhausted when the range is full.
func (p *PlanePool) Allocate(cfg SessionConfig) (*Session, error) {
	return AllocateAcross(p, p, cfg)
}

// AllocateAcross binds side A from poolA and side B from poolB. This is
// the edge proxy's shape: the public side's socket lives in the public
// plane's range and binds the public address, the private side's in the
// private plane's — so neither leg can ever be told to send media to the
// other plane's address.
//
// On failure the already-bound pair is closed and released, so a partial
// allocation never leaks a socket or a port reservation.
func AllocateAcross(poolA, poolB *PlanePool, cfg SessionConfig) (*Session, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = poolA.timeout()
	}
	a, err := poolA.allocatePair()
	if err != nil {
		return nil, err
	}
	b, err := poolB.allocatePair()
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
	for side := range s.pairs {
		s.rtp[side] = &latch{mode: cfg.Latch[side]}
		s.rtcp[side] = &latch{mode: cfg.Latch[side]}
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

// Relatch re-arms both the RTP and RTCP latches of one side to ip, for an
// authorized media-address change signalled by a re-INVITE.
func (s *Session) Relatch(side Side, ip netip.Addr) {
	s.rtp[side].relatch(ip)
	s.rtcp[side].relatch(ip)
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
