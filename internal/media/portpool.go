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
}

// PlanePool allocates RTP/RTCP port pairs from one network plane's range.
// The edge proxy runs two of them — a public pool facing phones and
// browsers, a private pool facing FreeSWITCH — so the two planes can bind
// different addresses and draw from disjoint ranges. The trunk B2BUA
// plane runs a single pool and allocates both sides of a call from it
// (Allocate).
//
// Safe for concurrent use; allocation is O(range) in the worst case and
// holds one mutex for the whole sweep, which is what makes "no duplicate
// allocation" true even under a burst of simultaneous calls.
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
	lo, hi := int(par.MinPort), int(par.MaxPort)
	if lo%2 != 0 {
		lo++ // RTP ports are even by convention
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cursor < lo || p.cursor+1 > hi {
		p.cursor = lo
	}
	pairs := (hi - lo + 1) / 2
	for tried := 0; tried < pairs; tried++ {
		port := p.cursor
		p.cursor += 2
		if p.cursor+1 > hi {
			p.cursor = lo
		}
		if _, used := p.inUse[port]; used {
			continue
		}
		pair, err := bindPair(port, par.BindIP)
		if err != nil {
			continue // occupied by another process
		}
		p.inUse[port] = struct{}{}
		return pair, nil
	}
	return nil, fmt.Errorf("%w: no free pair in %s range %d-%d", ErrPortsExhausted, p.name, par.MinPort, par.MaxPort)
}

// allocateSingle binds ONE socket on an even port and reserves the
// odd port above it without binding, so a muxed (rtcp-mux) session still
// consumes a full pair's worth of the range and can never collide with a
// non-muxed neighbour. Used by the WebRTC leg, where ICE, DTLS, SRTP and
// SRTCP all share a single socket.
func (p *PlanePool) allocateSingle() (*net.UDPConn, error) {
	par := p.params()
	lo, hi := int(par.MinPort), int(par.MaxPort)
	if lo%2 != 0 {
		lo++
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cursor < lo || p.cursor+1 > hi {
		p.cursor = lo
	}
	pairs := (hi - lo + 1) / 2
	for tried := 0; tried < pairs; tried++ {
		port := p.cursor
		p.cursor += 2
		if p.cursor+1 > hi {
			p.cursor = lo
		}
		if _, used := p.inUse[port]; used {
			continue
		}
		conn, err := net.ListenUDP("udp", udpAddr(port, par.BindIP))
		if err != nil {
			continue
		}
		p.inUse[port] = struct{}{}
		return conn, nil
	}
	return nil, fmt.Errorf("%w: no free port in %s range %d-%d", ErrPortsExhausted, p.name, par.MinPort, par.MaxPort)
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
	p.mu.Lock()
	inUse = len(p.inUse)
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

func bindPair(port int, bind netip.Addr) (*portPair, error) {
	rtp, err := net.ListenUDP("udp", udpAddr(port, bind))
	if err != nil {
		return nil, err
	}
	rtcp, err := net.ListenUDP("udp", udpAddr(port+1, bind))
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
