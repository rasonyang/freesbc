// Package media implements the RTP/RTCP relay plane: port allocation,
// hardened first-packet latching, and payload-agnostic UDP forwarding
// between the two legs of a call. It knows nothing about SIP or SDP —
// the signaling plane drives it via Pool.Allocate and Session.
package media

import (
	"errors"
	"net"
	"sync"

	"github.com/freesbc/freesbc/config"
)

// ErrPortsExhausted is returned when no free port pair is left in the
// configured range; the signaling plane maps it to 503 (spec §7).
var ErrPortsExhausted = errors.New("media: RTP port range exhausted")

// PortPair is one bound socket pair: RTP on an even port, RTCP on RTP+1.
type PortPair struct {
	RTP  *net.UDPConn
	RTCP *net.UDPConn
}

// RTPPort returns the bound RTP port (the RTCP port is RTPPort()+1).
func (pp *PortPair) RTPPort() int {
	return pp.RTP.LocalAddr().(*net.UDPAddr).Port
}

// Close closes both sockets.
func (pp *PortPair) Close() {
	_ = pp.RTP.Close()
	_ = pp.RTCP.Close()
}

// Pool allocates port pairs from listen.media.port_range. The range is
// read from the config store on every allocation, so a hot-reloaded range
// applies to new calls without disturbing established ones.
type Pool struct {
	store *config.Store

	mu     sync.Mutex
	inUse  map[int]struct{} // RTP (even) ports currently allocated
	cursor int              // next candidate RTP port
}

func NewPool(store *config.Store) *Pool {
	return &Pool{store: store, inUse: make(map[int]struct{})}
}

// allocatePair binds the next free RTP/RTCP pair. Ports occupied by other
// processes are skipped; a full sweep with no free pair returns
// ErrPortsExhausted.
func (p *Pool) allocatePair() (*PortPair, error) {
	media := p.store.Current().Listen.Media
	lo, hi := int(media.PortRange.Min), int(media.PortRange.Max)
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
		pair, err := bindPair(port)
		if err != nil {
			continue // occupied by another process
		}
		p.inUse[port] = struct{}{}
		return pair, nil
	}
	return nil, ErrPortsExhausted
}

// release returns an RTP port to the pool. The caller closes the sockets.
func (p *Pool) release(rtpPort int) {
	p.mu.Lock()
	delete(p.inUse, rtpPort)
	p.mu.Unlock()
}

func bindPair(port int) (*PortPair, error) {
	rtp, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	rtcp, err := net.ListenUDP("udp", &net.UDPAddr{Port: port + 1})
	if err != nil {
		_ = rtp.Close()
		return nil, err
	}
	return &PortPair{RTP: rtp, RTCP: rtcp}, nil
}
