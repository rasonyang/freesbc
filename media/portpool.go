// Package media implements the RTP/RTCP relay plane: port allocation,
// hardened first-packet latching, and payload-agnostic UDP forwarding
// between the two legs of a call. It knows nothing about SIP or SDP —
// the signaling plane drives it via Pool.Allocate and Session.
package media

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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

// Pool allocates port pairs from the configured range
// (rtp.port_min/port_max, else listen.media.port_range — see
// Config.RTPPortRange). The range and the rtp.bind_ip the sockets bind to
// are read from the config store on every allocation, so a hot-reloaded
// range or bind address applies to new calls without disturbing
// established ones.
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
// processes are skipped; a full sweep with no free pair returns an
// ErrPortsExhausted error naming the configured range. The cursor walks
// only even ports inside [lo, hi] and wraps before hi, so a pair (port,
// port+1) can never be bound outside the configured range — even when hi
// is odd or lo is odd.
func (p *Pool) allocatePair() (*PortPair, error) {
	pr := p.store.Current().RTPPortRange()
	lo, hi := int(pr.Min), int(pr.Max)
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
		pair, err := bindPair(port, p.bindIP())
		if err != nil {
			continue // occupied by another process
		}
		p.inUse[port] = struct{}{}
		return pair, nil
	}
	return nil, fmt.Errorf("%w: no free pair in %d-%d", ErrPortsExhausted, pr.Min, pr.Max)
}

// Stats returns the number of RTP port pairs currently allocated and the
// total number of pairs the configured range can hold.
func (p *Pool) Stats() (inUse, total int) {
	pr := p.store.Current().RTPPortRange()
	lo, hi := int(pr.Min), int(pr.Max)
	if lo%2 != 0 {
		lo++
	}
	total = (hi - lo + 1) / 2
	if total < 0 {
		total = 0
	}
	p.mu.Lock()
	inUse = len(p.inUse)
	p.mu.Unlock()
	return inUse, total
}

// release returns an RTP port to the pool. The caller closes the sockets.
func (p *Pool) release(rtpPort int) {
	p.mu.Lock()
	delete(p.inUse, rtpPort)
	p.mu.Unlock()
}

// bindIP returns the rtp.bind_ip the pool's sockets bind to, or the zero
// Addr (every interface) when unset. Only the bind plane — the advertised
// SDP address lives on the signaling side (Server.mediaIP); the two stay
// independent so NAT/VPN deployments can bind privately and advertise
// publicly.
func (p *Pool) bindIP() netip.Addr {
	if b := p.store.Current().RTP.BindIP; b != "" {
		if ip, err := netip.ParseAddr(b); err == nil {
			return ip
		}
	}
	return netip.Addr{}
}

func bindPair(port int, bind netip.Addr) (*PortPair, error) {
	rtp, err := net.ListenUDP("udp", udpAddr(port, bind))
	if err != nil {
		return nil, err
	}
	rtcp, err := net.ListenUDP("udp", udpAddr(port+1, bind))
	if err != nil {
		_ = rtp.Close()
		return nil, err
	}
	return &PortPair{RTP: rtp, RTCP: rtcp}, nil
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
