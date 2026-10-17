package media

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Tests for the batched RTP relay (relay_batch_linux.go, issue #172). It
// is off by default, so the rest of the suite covers relayPlain; these run
// the relay tests again with it on, and test what only the batch path
// does. Fixed ports: 21500-21599.

// withBatchRelay turns the batched relay on for the sessions the test
// starts. The media suite runs its tests sequentially, so flipping the
// package variable is safe.
func withBatchRelay(t *testing.T) {
	t.Helper()
	old := batchRelay.Load()
	batchRelay.Store(true)
	t.Cleanup(func() { batchRelay.Store(old) })
}

// TestBatchRelayRunsRelaySuite runs the Session relay, latching and SDES
// tests through the batched loop.
func TestBatchRelayRunsRelaySuite(t *testing.T) {
	withBatchRelay(t)
	for _, tc := range []struct {
		name string
		fn   func(*testing.T)
	}{
		{"RelayForwardsBothDirections", TestRelayForwardsBothDirections},
		{"RelayDropsHijackPackets", TestRelayDropsHijackPackets},
		{"RelaySilenceTimeoutReleasesPorts", TestRelaySilenceTimeoutReleasesPorts},
		{"RelayActivityDefersTimeout", TestRelayActivityDefersTimeout},
		{"SessionCloseCause", TestSessionCloseCause},
		{"SDESRoundTripRTP", TestSDESRoundTripRTP},
		{"SDESRoundTripRTCP", TestSDESRoundTripRTCP},
		{"SDESBadAuthDroppedAndDoesNotLatch", TestSDESBadAuthDroppedAndDoesNotLatch},
		{"SDESNoKeyFailsClosed", TestSDESNoKeyFailsClosed},
		{"SDESRekeyMidStream", TestSDESRekeyMidStream},
		{"SDESSameKeyKeepsState", TestSDESSameKeyKeepsState},
		{"SDESRekeyUnderTraffic", TestSDESRekeyUnderTraffic},
		{"SDESForgeriesDoNotRefreshWatchdog", TestSDESForgeriesDoNotRefreshWatchdog},
		{"AuditMED012StartIsOneShot", TestAuditMED012StartIsOneShot},
		{"AuditMED005RelatchKeepsSendingToNewAddress", TestAuditMED005RelatchKeepsSendingToNewAddress},
		{"AuditP1012RelayBufferMatchesMaxPacketSize", TestAuditP1012RelayBufferMatchesMaxPacketSize},
		{"AuditMED013StatsAreSideNeutral", TestAuditMED013StatsAreSideNeutral},
	} {
		t.Run(tc.name, tc.fn)
	}
}

// TestBatchRelayQueuedBurstInOrder queues more packets than one batch
// holds before the relay starts, so the first reads return full batches,
// and checks every packet arrives once, in order, and is counted.
func TestBatchRelayQueuedBurstInOrder(t *testing.T) {
	withBatchRelay(t)
	for _, bind := range []string{"127.0.0.1", ""} { // AF_INET, and the dual-stack wildcard
		t.Run(fmt.Sprintf("bind=%q", bind), func(t *testing.T) {
			pool := NewPlanePool("batch", func() PlaneParams {
				par := PlaneParams{MinPort: 21500, MaxPort: 21519, Timeout: time.Minute, AllowLoopback: true}
				if bind != "" {
					par.BindIP = netip.MustParseAddr(bind)
				}
				return par
			})
			s, err := AllocateAcross(pool, pool, SessionConfig{Latch: [2]LatchMode{LatchLoose, LatchLoose}})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			a := auditUDP(t, "127.0.0.1")
			b := auditUDP(t, "127.0.0.1")
			s.SetRemote(SideB, auditAddrPort(b))
			const burst = 3*relayBatchSize + 3
			pubA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideA)}
			for i := 0; i < burst; i++ {
				if _, err := a.WriteToUDP(g711Packet(uint16(i)), pubA); err != nil {
					t.Fatal(err)
				}
			}
			s.Start()
			buf := make([]byte, 2048)
			for i := 0; i < burst; i++ {
				_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _, err := b.ReadFromUDP(buf)
				if err != nil {
					t.Fatalf("packet %d of %d not relayed: %v", i, burst, err)
				}
				if n != 172 {
					t.Fatalf("packet %d: %d bytes, want 172", i, n)
				}
				if seq := int(buf[2])<<8 | int(buf[3]); seq != i {
					t.Fatalf("packet %d arrived as sequence %d: order not kept", i, seq)
				}
			}
			st := s.Stats()
			if st.A.RTPPacketsRx != burst || st.B.RTPPacketsTx != burst || st.B.RTPBytesTx != burst*172 {
				t.Errorf("counters: A rx %d, B tx %d packets %d bytes; want %d, %d, %d",
					st.A.RTPPacketsRx, st.B.RTPPacketsTx, st.B.RTPBytesTx, burst, burst, burst*172)
			}
			// The reverse direction latched nothing yet; the latch on side
			// A learned a's source, so b's packets go back to a.
			pubB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.RTPPort(SideB)}
			if _, err := b.WriteToUDP(g711Packet(7), pubB); err != nil {
				t.Fatal(err)
			}
			_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, _, err := a.ReadFromUDP(buf); err != nil {
				t.Fatalf("reverse direction: %v", err)
			}
		})
	}
}

// TestBatchFlushDropsOnlyTheFailingDatagram checks the sendmmsg error
// path: a datagram the kernel refuses (port 0) is dropped and not
// counted, and the datagrams around it still go, as with one WriteToUDP
// per packet.
func TestBatchFlushDropsOnlyTheFailingDatagram(t *testing.T) {
	out := auditUDP(t, "127.0.0.1")
	sink := auditUDP(t, "127.0.0.1")
	wr, err := newMmsgSocket(out)
	if err != nil {
		t.Fatal(err)
	}
	good := sink.LocalAddr().(*net.UDPAddr)
	bad := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	pkts := [][]byte{[]byte("one"), []byte("two-x"), []byte("three"), []byte("four-x"), []byte("five")}
	dsts := []*net.UDPAddr{good, bad, good, bad, good}
	for i := range pkts {
		if !wr.queue(i, pkts[i], dsts[i]) {
			t.Fatalf("queue %d refused", i)
		}
	}
	var sent []int
	wr.flush(len(pkts), func(n int) { sent = append(sent, n) })
	if fmt.Sprint(sent) != "[3 5 4]" {
		t.Errorf("sent byte counts %v, want [3 5 4]", sent)
	}
	buf := make([]byte, 64)
	for _, want := range []string{"one", "three", "five"} {
		_ = sink.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := sink.ReadFromUDP(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("got %q (%v), want %q", buf[:n], err, want)
		}
	}
	// A zoned or unreachable-family destination is left to WriteToUDP.
	if wr.queue(0, pkts[0], &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 9, Zone: "lo"}) {
		t.Error("a zoned destination must not be batched")
	}
	if wr.queue(0, pkts[0], &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9}) {
		t.Error("an IPv6 destination on an AF_INET socket must not be batched")
	}
}
