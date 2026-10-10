package media

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/srtp/v3"
)

// Micro-benchmarks for the media plane (issue #109). They run only under
// -bench; plain `go test` never executes them. Fixed ports come from
// 20200-20999, a range no test in this package uses (the test band is
// 20000-24999, with 20102-20999 unclaimed).

// g711Packet builds a 172-byte RTP packet (12-byte header + 160 bytes of
// G.711 payload, 20 ms) with the given sequence number.
func g711Packet(seq uint16) []byte {
	p := make([]byte, 172)
	p[0] = 0x80
	p[2], p[3] = byte(seq>>8), byte(seq)
	p[10], p[11] = 0x12, 0x34
	for i := 12; i < len(p); i++ {
		p[i] = byte(i)
	}
	return p
}

// latchProbe latches dst's side, then sends probes from src until dst
// receives one, which proves both sides are latched.
func latchProbe(src, dst *net.UDPConn) bool {
	_, _ = dst.Write(g711Packet(0)) // latch dst's own side first
	buf := make([]byte, 2048)
	for try := 0; try < 60; try++ {
		_, _ = src.Write(g711Packet(0))
		_ = dst.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := dst.Read(buf); err == nil {
			return true
		}
	}
	return false
}

func dialSideConn(s *Session, side Side) (*net.UDPConn, error) {
	return net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(side)})
}

// BenchmarkSessionForward measures one packet through Session.forward:
// A sends, the relay reads, applies the latch and writes, B receives. The
// figure is the full loopback round trip (one send and one receive by the
// endpoints, one read and one write by the relay), so it includes the
// syscall floor.
func BenchmarkSessionForward(b *testing.B) {
	p := testPool(20200, 20215)
	s, err := AllocateAcross(p, p, SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchLoose}, Timeout: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	s.Start()
	ea, err := dialSideConn(s, SideA)
	if err != nil {
		b.Fatal(err)
	}
	defer ea.Close()
	eb, err := dialSideConn(s, SideB)
	if err != nil {
		b.Fatal(err)
	}
	defer eb.Close()
	if !latchProbe(ea, eb) || !latchProbe(eb, ea) {
		b.Fatal("latch probe never forwarded")
	}
	pkt := g711Packet(1)
	buf := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ea.Write(pkt); err != nil {
			b.Fatal(err)
		}
		_ = eb.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := eb.Read(buf); err != nil {
			b.Fatalf("packet %d lost: %v", i, err)
		}
	}
}

// BenchmarkSessionForwardParallel runs one independent session per
// RunParallel worker, to show how the relay scales across calls. Run with
// -cpu to vary the worker count (at most 64).
func BenchmarkSessionForwardParallel(b *testing.B) {
	const maxSessions = 64
	p := testPool(20300, 20300+maxSessions*4*2-1)
	var started atomic.Int64
	b.ReportAllocs()
	b.SetBytes(172)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		if started.Add(1) > maxSessions {
			b.Error("more parallel workers than sessions")
			return
		}
		s, err := AllocateAcross(p, p, SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchLoose}, Timeout: time.Hour})
		if err != nil {
			b.Error(err)
			return
		}
		defer s.Close()
		s.Start()
		ea, err := dialSideConn(s, SideA)
		if err != nil {
			b.Error(err)
			return
		}
		defer ea.Close()
		eb, err := dialSideConn(s, SideB)
		if err != nil {
			b.Error(err)
			return
		}
		defer eb.Close()
		if !latchProbe(ea, eb) || !latchProbe(eb, ea) {
			b.Error("latch probe never forwarded")
			return
		}
		pkt := g711Packet(1)
		buf := make([]byte, 2048)
		for pb.Next() {
			if _, err := ea.Write(pkt); err != nil {
				b.Error(err)
				return
			}
			_ = eb.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := eb.Read(buf); err != nil {
				b.Errorf("packet lost: %v", err)
				return
			}
		}
	})
}

var benchProfiles = []struct {
	name    string
	profile srtp.ProtectionProfile
	saltLen int
}{
	{"cm80", srtp.ProtectionProfileAes128CmHmacSha1_80, 14},
	{"gcm", srtp.ProtectionProfileAeadAes128Gcm, 12},
}

func benchSRTPCtx(b *testing.B, profile srtp.ProtectionProfile, saltLen int) *SRTPContext {
	b.Helper()
	key := make([]byte, 16)
	salt := make([]byte, saltLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range salt {
		salt[i] = byte(i + 101)
	}
	c, err := newSRTPContextFromKeys(profile, key, salt)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

// BenchmarkSRTPProtectRTP encrypts a 172-byte G.711 packet into a buffer
// with the relay's spare capacity, as Session.forward does.
func BenchmarkSRTPProtectRTP(b *testing.B) {
	for _, pr := range benchProfiles {
		b.Run(pr.name, func(b *testing.B) {
			ctx := benchSRTPCtx(b, pr.profile, pr.saltLen)
			plain := g711Packet(0)
			buf := make([]byte, 0, relayBufSize)
			b.ReportAllocs()
			b.SetBytes(int64(len(plain)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				plain[2], plain[3] = byte(i>>8), byte(i)
				buf = append(buf[:0], plain...)
				if _, ok := ctx.protectRTPInto(buf, buf); !ok {
					b.Fatal("protect failed")
				}
			}
		})
	}
}

// BenchmarkSRTPUnprotectRTP authenticates and decrypts a 172-byte packet.
// The replay window rejects a repeated index, so packets are protected
// ahead of time in batches (timer stopped) and fed in order to a fresh
// receiver.
func BenchmarkSRTPUnprotectRTP(b *testing.B) {
	const batch = 4096
	for _, pr := range benchProfiles {
		b.Run(pr.name, func(b *testing.B) {
			wire := make([][]byte, batch)
			work := make([]byte, 0, relayBufSize)
			b.ReportAllocs()
			b.SetBytes(172)
			for done := 0; done < b.N; {
				b.StopTimer()
				tx := benchSRTPCtx(b, pr.profile, pr.saltLen)
				rx := benchSRTPCtx(b, pr.profile, pr.saltLen)
				n := min(batch, b.N-done)
				for i := 0; i < n; i++ {
					buf := append(make([]byte, 0, relayBufSize), g711Packet(uint16(i))...)
					out, ok := tx.protectRTPInto(buf, buf)
					if !ok {
						b.Fatal("protect failed")
					}
					wire[i] = out
				}
				b.StartTimer()
				for i := 0; i < n; i++ {
					work = append(work[:0], wire[i]...)
					if _, ok := rx.unprotectRTPInto(work, work); !ok {
						b.Fatal("unprotect failed")
					}
				}
				done += n
			}
		})
	}
}

// BenchmarkSRTPProtectRTCP covers the RTCP path with a minimal receiver
// report.
func BenchmarkSRTPProtectRTCP(b *testing.B) {
	ctx := benchSRTPCtx(b, srtp.ProtectionProfileAes128CmHmacSha1_80, 14)
	rr := testRTCPPacket()
	buf := make([]byte, 0, relayBufSize)
	b.ReportAllocs()
	b.SetBytes(int64(len(rr)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = append(buf[:0], rr...)
		if _, ok := ctx.protectRTCPInto(buf, buf); !ok {
			b.Fatal("protect failed")
		}
	}
}

// BenchmarkMuxClassify is the pure RFC 7983 first-byte classifier over the
// packet kinds a WebRTC socket carries (RTP, STUN, DTLS, RTCP).
func BenchmarkMuxClassify(b *testing.B) {
	stun := make([]byte, 20) // first byte 0: STUN binding request
	stun[1] = 0x01
	stun[4], stun[5], stun[6], stun[7] = 0x21, 0x12, 0xa4, 0x42
	dtls := make([]byte, 60) // 22: DTLS handshake
	dtls[0] = 22
	rtcp := make([]byte, 28) // RTCP sender report
	rtcp[0], rtcp[1] = 0x80, 200
	pkts := [][]byte{g711Packet(1), stun, dtls, rtcp, g711Packet(2)}
	b.ReportAllocs()
	b.ResetTimer()
	var sink muxKind
	for i := 0; i < b.N; i++ {
		sink += classify(pkts[i%len(pkts)])
	}
	_ = sink
}

// BenchmarkDemuxRTP drives the demux read loop end to end: a UDP datagram
// in, classified, queued on the SRTP endpoint, read out.
func BenchmarkDemuxRTP(b *testing.B) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20250})
	if err != nil {
		b.Fatal(err)
	}
	defer peer.Close()
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20252}, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatal(err)
	}
	d := newDemux(conn) // closes conn
	defer d.Close()
	pkt := g711Packet(1)
	buf := make([]byte, 2048)
	dst := conn.LocalAddr().(*net.UDPAddr)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := peer.WriteToUDP(pkt, dst); err != nil {
			b.Fatal(err)
		}
		if _, err := d.srtp.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPoolAllocateRelease allocates and releases one pair at several
// occupancies of a 250-pair range. At 99% the sweep has to skip held
// reservations.
func BenchmarkPoolAllocateRelease(b *testing.B) {
	const lo, pairs = 20500, 250
	for _, occ := range []int{0, 50, 99} {
		b.Run(fmt.Sprintf("occ%d", occ), func(b *testing.B) {
			p := testPool(lo, lo+pairs*2-1)
			hold := pairs * occ / 100
			var held []*portPair
			for i := 0; i < hold; i++ {
				pp, err := p.allocatePair()
				if err != nil {
					b.Fatal(err)
				}
				held = append(held, pp)
			}
			defer func() {
				for _, pp := range held {
					port := pp.RTPPort()
					pp.Close()
					p.release(port)
				}
			}()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pp, err := p.allocatePair()
				if err != nil {
					b.Fatal(err)
				}
				port := pp.RTPPort()
				pp.Close()
				p.release(port)
			}
		})
	}
}

// BenchmarkPoolExhausted is the worst case of sweep: every pair is held, so
// one allocation walks the whole range and fails.
func BenchmarkPoolExhausted(b *testing.B) {
	const lo, pairs = 20500, 250
	p := testPool(lo, lo+pairs*2-1)
	var held []*portPair
	for i := 0; i < pairs; i++ {
		pp, err := p.allocatePair()
		if err != nil {
			b.Fatal(err)
		}
		held = append(held, pp)
	}
	defer func() {
		for _, pp := range held {
			port := pp.RTPPort()
			pp.Close()
			p.release(port)
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.allocatePair(); err == nil {
			b.Fatal("expected exhaustion")
		}
	}
}
