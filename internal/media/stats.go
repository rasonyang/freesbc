package media

import "sync/atomic"

// Stats is one media session's packet counters (spec §12/§17), per side
// of the relay. Counters are named from the SBC's point of view: "rx" is
// what the SBC received from that side, "tx" what it sent to it.
//
// The sides are SideA and SideB, not "public" and "private": that is only
// the edge proxy's orientation. On the edge, A is the client-facing
// (public) leg and B the FreeSWITCH-facing (private) one — the browser
// and FreeSWITCH on a WebRTCSession. On the trunk B2BUA, A is the leg the
// call arrived on and B the one it was placed on, and neither is public
// or private.
//
// Deliberately not a full RTCP analytics engine: these are the numbers an
// operator needs to answer "is media flowing, and which way isn't it",
// nothing more.
type Stats struct {
	A, B LegStats
}

// LegStats is one side's RTP counters. RTCP is relayed but not counted.
type LegStats struct {
	RTPPacketsRx uint64
	RTPPacketsTx uint64
	RTPBytesRx   uint64
	RTPBytesTx   uint64
}

// Side returns one side's counters.
func (s Stats) Side(side Side) LegStats {
	if side == SideB {
		return s.B
	}
	return s.A
}

// Total sums both sides, for process-wide counters.
func (s Stats) Total() LegStats {
	return LegStats{
		RTPPacketsRx: s.A.RTPPacketsRx + s.B.RTPPacketsRx,
		RTPPacketsTx: s.A.RTPPacketsTx + s.B.RTPPacketsTx,
		RTPBytesRx:   s.A.RTPBytesRx + s.B.RTPBytesRx,
		RTPBytesTx:   s.A.RTPBytesTx + s.B.RTPBytesTx,
	}
}

// counters is the atomic backing store for Stats. One instance per
// session; every field is touched from the relay goroutines.
type counters struct {
	rtpPacketsRx [2]atomic.Uint64
	rtpPacketsTx [2]atomic.Uint64
	rtpBytesRx   [2]atomic.Uint64
	rtpBytesTx   [2]atomic.Uint64
}

// recordRx and recordTx count RTP only; RTCP is relayed but not counted,
// since nothing reads an RTCP counter.
func (c *counters) recordRx(side Side, rtp bool, n int) {
	if !rtp {
		return
	}
	c.rtpPacketsRx[side].Add(1)
	c.rtpBytesRx[side].Add(uint64(n))
}

func (c *counters) recordTx(side Side, rtp bool, n int) {
	if !rtp {
		return
	}
	c.rtpPacketsTx[side].Add(1)
	c.rtpBytesTx[side].Add(uint64(n))
}

// snapshot renders the counters.
func (c *counters) snapshot() Stats {
	leg := func(side Side) LegStats {
		return LegStats{
			RTPPacketsRx: c.rtpPacketsRx[side].Load(),
			RTPPacketsTx: c.rtpPacketsTx[side].Load(),
			RTPBytesRx:   c.rtpBytesRx[side].Load(),
			RTPBytesTx:   c.rtpBytesTx[side].Load(),
		}
	}
	return Stats{A: leg(SideA), B: leg(SideB)}
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
