package media

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// BenchmarkUDPSendPath compares the ways the relay could send one G.711
// packet on Linux (issue #172), per packet, from one sender to a loopback
// sink another goroutine drains:
//
//   - sendto: WriteToUDP with a *net.UDPAddr, what relayPlain does;
//   - sendto-addrport: WriteToUDPAddrPort, which skips the net.IP path;
//   - send-connected: Write on a connected socket (no route lookup), which
//     the relay cannot use as is: its sockets must keep receiving from any
//     source until the latch decides;
//   - sendmmsg/N: N packets per sendmmsg, what relayBatched does when N
//     packets are queued.
//
// It measures the sender's syscall path, not a relay: see
// BenchmarkRelayLoad for that. Ports are kernel-assigned.
func BenchmarkUDPSendPath(b *testing.B) {
	sinkConn := func(b *testing.B) (*net.UDPConn, func()) {
		sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			b.Fatal(err)
		}
		_ = sink.SetReadBuffer(4 << 20)
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 2048)
			for {
				if _, _, err := sink.ReadFromUDP(buf); errors.Is(err, net.ErrClosed) {
					return
				}
			}
		}()
		return sink, func() { _ = sink.Close(); <-done }
	}
	sender := func(b *testing.B) *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			b.Fatal(err)
		}
		return c
	}
	pkt := g711Packet(1)

	b.Run("sendto", func(b *testing.B) {
		sink, stop := sinkConn(b)
		defer stop()
		c := sender(b)
		defer c.Close()
		dst := sink.LocalAddr().(*net.UDPAddr)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = c.WriteToUDP(pkt, dst)
		}
	})
	b.Run("sendto-addrport", func(b *testing.B) {
		sink, stop := sinkConn(b)
		defer stop()
		c := sender(b)
		defer c.Close()
		dst := sink.LocalAddr().(*net.UDPAddr).AddrPort()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = c.WriteToUDPAddrPort(pkt, dst)
		}
	})
	b.Run("send-connected", func(b *testing.B) {
		sink, stop := sinkConn(b)
		defer stop()
		c, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = c.Write(pkt)
		}
	})
	for _, n := range []int{1, 4, relayBatchSize} {
		b.Run(fmt.Sprintf("sendmmsg/%d", n), func(b *testing.B) {
			sink, stop := sinkConn(b)
			defer stop()
			c := sender(b)
			defer c.Close()
			wr, err := newMmsgSocket(c)
			if err != nil {
				b.Fatal(err)
			}
			dst := sink.LocalAddr().(*net.UDPAddr)
			sent := func(int) {}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i += n {
				k := min(n, b.N-i)
				for j := 0; j < k; j++ {
					wr.queue(j, pkt, dst)
				}
				wr.flush(k, sent)
			}
		})
	}
}

// BenchmarkSessionForwardBurst sends `burst` packets back to back through
// a session and reads them all, per packet, with the plain and the batched
// relay: the queue depth at which batching starts to pay on loopback. The
// endpoints run in this process, so their syscalls are included. Ports
// 20900-20915 (the micro-benchmark range).
func BenchmarkSessionForwardBurst(b *testing.B) {
	for _, mode := range []string{"plain", "batch"} {
		for _, burst := range []int{1, 4, 16} {
			b.Run(fmt.Sprintf("%s/burst=%d", mode, burst), func(b *testing.B) {
				old := batchRelay.Load()
				batchRelay.Store(mode == "batch")
				defer batchRelay.Store(old)
				p := testPool(20900, 20915)
				s, err := AllocateAcross(p, p, SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchLoose}, Timeout: 0})
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
				_ = eb.SetReadBuffer(1 << 20)
				if !latchProbe(ea, eb) || !latchProbe(eb, ea) {
					b.Fatal("latch probe never forwarded")
				}
				pkt := g711Packet(1)
				buf := make([]byte, 2048)
				b.ReportAllocs()
				b.SetBytes(int64(len(pkt)))
				b.ResetTimer()
				for i := 0; i < b.N; i += burst {
					k := min(burst, b.N-i)
					for j := 0; j < k; j++ {
						if _, err := ea.Write(pkt); err != nil {
							b.Fatal(err)
						}
					}
					_ = eb.SetReadDeadline(time.Now().Add(2 * time.Second))
					for j := 0; j < k; j++ {
						if _, err := eb.Read(buf); err != nil {
							b.Fatalf("packet lost: %v", err)
						}
					}
				}
			})
		}
	}
}
