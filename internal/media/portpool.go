// Package media implements the RTP/RTCP relay plane: port allocation,
// hardened first-packet latching, payload-agnostic UDP forwarding between
// the two legs of a call, and (for the edge proxy) the browser-facing
// ICE-Lite/DTLS-SRTP media leg. It knows nothing about SIP — the
// signaling plane drives it via a pool, Session and WebRTCSession.
package media

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ErrPortsExhausted is returned when no free port pair is left in the
// configured range; the signaling plane maps it to 503 (spec §7).
var ErrPortsExhausted = errors.New("media: RTP port range exhausted")

// portPair is one bound socket pair: RTP on an even port, RTCP on RTP+1.
type portPair struct {
	RTP  *net.UDPConn
	RTCP *net.UDPConn
}

// RTPPort returns the bound RTP port (the RTCP port is RTPPort()+1).
func (pp *portPair) RTPPort() int {
	return pp.RTP.LocalAddr().(*net.UDPAddr).Port
}

// Close closes both sockets.
func (pp *portPair) Close() {
	_ = pp.RTP.Close()
	_ = pp.RTCP.Close()
}

// PlaneParams is one pool's live configuration, re-read on every
// allocation so a hot-reloaded range or bind address applies to new
// sessions without disturbing established ones.
type PlaneParams struct {
	// MinPort and MaxPort bound the RTP/RTCP ports this pool hands out.
	MinPort, MaxPort uint16
	// BindIP is the local address sockets bind to; the zero Addr binds
	// every interface.
	BindIP netip.Addr
	// Timeout is the default media-silence teardown for sessions built
	// from this pool.
	Timeout time.Duration
	// AllowLoopback lets a session side allocated from this pool send to
	// a loopback address learned from SDP (SetRemote, Relatch). Off, a
	// loopback c= only arms the source check. It is meant for a plane
	// that is itself on loopback (an all-on-one-host lab, the test
	// suites); a pool facing real clients must leave it off, or a
	// client's SDP could point the SBC's media socket at a local service.
	// Unspecified, multicast, broadcast and link-local destinations are
	// refused regardless.
	AllowLoopback bool
}

// PlanePool allocates RTP/RTCP port pairs from one network plane's range.
// The edge proxy runs two of them — a public pool facing phones and
// browsers, a private pool facing FreeSWITCH — so the two planes can bind
// different addresses and draw from disjoint ranges. The trunk B2BUA
// plane runs a single pool and allocates both sides of a call from it
// (Allocate).
//
// Safe for concurrent use; allocation is O(range) in the worst case. A
// candidate port is RESERVED under the mutex (so no two callers can ever
// pick the same one) and bound with the mutex released, so a sweep past
// ports other processes hold never blocks Stats, release or another
// caller's allocation.
type PlanePool struct {
	name   string
	params func() PlaneParams

	mu     sync.Mutex
	inUse  map[int]struct{} // RTP (even) ports currently allocated
	cursor int              // next candidate RTP port
}

// NewPlanePool builds a pool whose range and bind address come from params
// on every allocation. name appears in exhaustion errors and metrics.
func NewPlanePool(name string, params func() PlaneParams) *PlanePool {
	return &PlanePool{name: name, params: params, inUse: make(map[int]struct{})}
}

// allocatePair binds the next free RTP/RTCP pair. Ports occupied by other
// processes are skipped; a full sweep with no free pair returns an
// ErrPortsExhausted error naming the configured range. The cursor walks
// only even ports inside [lo, hi] and wraps before hi, so a pair (port,
// port+1) can never be bound outside the configured range — even when hi
// is odd or lo is odd.
func (p *PlanePool) allocatePair() (*portPair, error) {
	par := p.params()
	pair, err := sweep(p, par, func(port int) (*portPair, error) { return bindPair(port, par.BindIP) })
	if err != nil {
		return nil, fmt.Errorf("%w: no free pair in %s range %d-%d", ErrPortsExhausted, p.name, par.MinPort, par.MaxPort)
	}
	return pair, nil
}

// allocateSingle binds ONE socket on an even port and reserves the
// odd port above it without binding, so a muxed (rtcp-mux) session still
// consumes a full pair's worth of the range and can never collide with a
// non-muxed neighbour. Used by the WebRTC leg, where ICE, DTLS, SRTP and
// SRTCP all share a single socket.
func (p *PlanePool) allocateSingle() (*net.UDPConn, error) {
	par := p.params()
	conn, err := sweep(p, par, func(port int) (*net.UDPConn, error) {
		return listenUDP("udp", udpAddr(port, par.BindIP))
	})
	if err != nil {
		return nil, fmt.Errorf("%w: no free port in %s range %d-%d", ErrPortsExhausted, p.name, par.MinPort, par.MaxPort)
	}
	return conn, nil
}

// errSweepExhausted ends a sweep that tried every pair in the range.
var errSweepExhausted = errors.New("media: sweep exhausted")

// sweep walks the range from the cursor, one even port per candidate.
// Each candidate is reserved in inUse under mu, then bound with mu
// released; a bind that fails (another process holds the port) drops the
// reservation and moves on. At most one full lap is tried.
func sweep[T any](p *PlanePool, par PlaneParams, bind func(port int) (T, error)) (T, error) {
	lo, hi := int(par.MinPort), int(par.MaxPort)
	if lo%2 != 0 {
		lo++ // RTP ports are even by convention
	}
	pairs := (hi - lo + 1) / 2
	var zero T
	for tried := 0; tried < pairs; tried++ {
		port, ok := p.reserveNext(lo, hi)
		if !ok {
			continue // this candidate is already in use
		}
		v, err := bind(port)
		if err != nil {
			p.release(port) // occupied by another process
			continue
		}
		return v, nil
	}
	return zero, errSweepExhausted
}

// reserveNext takes the next candidate port from the cursor and, when it
// is free in this pool, reserves it. ok=false means the candidate was
// already reserved; the cursor has still moved on.
func (p *PlanePool) reserveNext(lo, hi int) (port int, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cursor < lo || p.cursor+1 > hi {
		p.cursor = lo
	}
	port = p.cursor
	p.cursor += 2
	if p.cursor+1 > hi {
		p.cursor = lo
	}
	if _, used := p.inUse[port]; used {
		return port, false
	}
	p.inUse[port] = struct{}{}
	return port, true
}

// Stats returns the number of RTP port pairs currently allocated and the
// total number of pairs the configured range can hold.
func (p *PlanePool) Stats() (inUse, total int) {
	par := p.params()
	lo, hi := int(par.MinPort), int(par.MaxPort)
	if lo%2 != 0 {
		lo++
	}
	total = (hi - lo + 1) / 2
	// listen.media.port_range is not validated for max > min, so an
	// inverted range is reachable and would report a negative capacity.
	if total < 0 {
		total = 0
	}
	// Only reservations inside the CURRENT range count. After a reload
	// that moves or shrinks the range, live calls keep their old ports
	// until they end; counting those against the new capacity would
	// report more in use than the range can hold (P2-MED-011).
	p.mu.Lock()
	for port := range p.inUse {
		if port >= lo && port+1 <= hi {
			inUse++
		}
	}
	p.mu.Unlock()
	return inUse, total
}

// release returns an RTP port to the pool. The caller closes the sockets.
func (p *PlanePool) release(rtpPort int) {
	p.mu.Lock()
	delete(p.inUse, rtpPort)
	p.mu.Unlock()
}

// timeout is the pool's default silence teardown.
func (p *PlanePool) timeout() time.Duration { return p.params().Timeout }

// allowLoopback is the pool's loopback-destination policy, read once per
// session at allocation.
func (p *PlanePool) allowLoopback() bool { return p.params().AllowLoopback }

// listenUDP is net.ListenUDP; a variable only so a test can observe what
// the pool holds while a bind is in progress.
var listenUDP = net.ListenUDP

func bindPair(port int, bind netip.Addr) (*portPair, error) {
	rtp, err := listenUDP("udp", udpAddr(port, bind))
	if err != nil {
		return nil, err
	}
	rtcp, err := listenUDP("udp", udpAddr(port+1, bind))
	if err != nil {
		_ = rtp.Close()
		return nil, err
	}
	return &portPair{RTP: rtp, RTCP: rtcp}, nil
}

// udpAddr builds the local address for one socket: port with bind when it
// is valid, else the wildcard address.
func udpAddr(port int, bind netip.Addr) *net.UDPAddr {
	a := &net.UDPAddr{Port: port}
	if bind.IsValid() {
		a.IP = net.IP(bind.AsSlice())
	}
	return a
}
