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
	l.mu.Unlock()
}

// accept reports whether a packet from src may be processed, latching the
// stream to src on the first acceptance.
func (l *latch) accept(src *net.UDPAddr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.remote != nil {
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
	pool    *Pool
	pairs   [2]*PortPair
	rtp     [2]*latch
	rtcp    [2]*latch
	timeout time.Duration

	srtpIn  [2]*SRTPContext // decrypt packets received FROM this side (nil = plaintext)
	srtpOut [2]*SRTPContext // encrypt packets sent TO this side (nil = plaintext)

	lastRx    atomic.Int64 // unix nanos of the last accepted packet
	done      chan struct{}
	closeOnce sync.Once
}

// Allocate binds two port pairs (side A and side B) for one call. The
// caller must Close the session — or rely on silence teardown — to return
// the ports. Returns ErrPortsExhausted when the range is full.
func (p *Pool) Allocate(cfg SessionConfig) (*Session, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = p.store.Current().Listen.Media.RTPTimeout.Std()
	}
	a, err := p.allocatePair()
	if err != nil {
		return nil, err
	}
	b, err := p.allocatePair()
	if err != nil {
		a.Close()
		p.release(a.RTPPort())
		return nil, err
	}
	s := &Session{
		pool:    p,
		pairs:   [2]*PortPair{a, b},
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
// means that direction is plaintext. Call before Start (the forward loops read
// these once running; setting after Start races the relay goroutines).
func (s *Session) SetSRTP(side Side, inbound, outbound *SRTPContext) {
	s.srtpIn[side] = inbound
	s.srtpOut[side] = outbound
}

// Done is closed when the session ends (Close or silence timeout).
func (s *Session) Done() <-chan struct{} { return s.done }

// Close tears the session down and returns its ports to the pool.
// Idempotent and safe to call from any goroutine.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		for _, pp := range s.pairs {
			pp.Close()
		}
		s.pool.release(s.pairs[SideA].RTPPort())
		s.pool.release(s.pairs[SideB].RTPPort())
		close(s.done)
	})
	return nil
}
