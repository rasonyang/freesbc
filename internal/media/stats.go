package media

import "sync/atomic"

// Stats is one media session's packet counters (spec §12/§17). Counters
// are per DIRECTION of the relay, named from the SBC's point of view:
// "rx" is what the SBC received from that side, "tx" what it sent to it.
//
// Deliberately not a full RTCP analytics engine: these are the numbers an
// operator needs to answer "is media flowing, and which way isn't it",
// nothing more.
type Stats struct {
	PublicRTPPacketsRx  uint64
	PublicRTPPacketsTx  uint64
	PublicRTPBytesRx    uint64
	PublicRTPBytesTx    uint64
	PublicRTCPPacketsRx uint64
	PublicRTCPPacketsTx uint64

	PrivateRTPPacketsRx  uint64
	PrivateRTPPacketsTx  uint64
	PrivateRTPBytesRx    uint64
	PrivateRTPBytesTx    uint64
	PrivateRTCPPacketsRx uint64
	PrivateRTCPPacketsTx uint64

	// LastActivityUnixNano is when the session last accepted a packet that
	// passed every check (latch, and SRTP authentication where it
	// applies). Unauthenticated bytes never move it — see the note in
	// relay.go.
	LastActivityUnixNano int64
}

// counters is the atomic backing store for Stats. One instance per
// session; every field is touched from the relay goroutines.
type counters struct {
	rtpPacketsRx  [2]atomic.Uint64
	rtpPacketsTx  [2]atomic.Uint64
	rtpBytesRx    [2]atomic.Uint64
	rtpBytesTx    [2]atomic.Uint64
	rtcpPacketsRx [2]atomic.Uint64
	rtcpPacketsTx [2]atomic.Uint64
}

func (c *counters) recordRx(side Side, rtp bool, n int) {
	if rtp {
		c.rtpPacketsRx[side].Add(1)
		c.rtpBytesRx[side].Add(uint64(n))
		return
	}
	c.rtcpPacketsRx[side].Add(1)
}

func (c *counters) recordTx(side Side, rtp bool, n int) {
	if rtp {
		c.rtpPacketsTx[side].Add(1)
		c.rtpBytesTx[side].Add(uint64(n))
		return
	}
	c.rtcpPacketsTx[side].Add(1)
}

// snapshot renders the counters, mapping side A to "public" and side B to
// "private" — the orientation both the edge proxy and the trunk B2BUA use
// (A is the leg the call arrived on).
func (c *counters) snapshot(lastRx int64) Stats {
	return Stats{
		PublicRTPPacketsRx:   c.rtpPacketsRx[SideA].Load(),
		PublicRTPPacketsTx:   c.rtpPacketsTx[SideA].Load(),
		PublicRTPBytesRx:     c.rtpBytesRx[SideA].Load(),
		PublicRTPBytesTx:     c.rtpBytesTx[SideA].Load(),
		PublicRTCPPacketsRx:  c.rtcpPacketsRx[SideA].Load(),
		PublicRTCPPacketsTx:  c.rtcpPacketsTx[SideA].Load(),
		PrivateRTPPacketsRx:  c.rtpPacketsRx[SideB].Load(),
		PrivateRTPPacketsTx:  c.rtpPacketsTx[SideB].Load(),
		PrivateRTPBytesRx:    c.rtpBytesRx[SideB].Load(),
		PrivateRTPBytesTx:    c.rtpBytesTx[SideB].Load(),
		PrivateRTCPPacketsRx: c.rtcpPacketsRx[SideB].Load(),
		PrivateRTCPPacketsTx: c.rtcpPacketsTx[SideB].Load(),
		LastActivityUnixNano: lastRx,
	}
}

// isRTCP reports whether a packet on an RTP/RTCP-multiplexed flow is RTCP,
// per RFC 5761 §4: the RTP payload-type field (the low 7 bits of the
// second byte) overlaps the RTCP packet-type field, and the range 64-95 is
// reserved so the two can be told apart unambiguously.
func isRTCP(pkt []byte) bool {
	if len(pkt) < 2 {
		return false
	}
	pt := pkt[1] & 0x7f
	return pt >= 64 && pt <= 95
}
