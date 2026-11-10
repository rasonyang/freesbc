package media

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// arrivals records when packets reached a fake endpoint.
type arrivals struct {
	mu sync.Mutex
	at []time.Time
}

func (a *arrivals) add() {
	a.mu.Lock()
	a.at = append(a.at, time.Now())
	a.mu.Unlock()
}

// gaps returns the inter-arrival gaps above min, plus the time from the
// last arrival to end.
func (a *arrivals) gaps(start, end time.Time, min time.Duration) (big []time.Duration, n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := start
	for _, t := range a.at {
		if d := t.Sub(prev); d > min {
			big = append(big, d)
		}
		prev = t
	}
	if d := end.Sub(prev); d > min {
		big = append(big, d)
	}
	return big, len(a.at)
}

// echoPeerCall runs a call where the peer advertises 127.0.0.1:P, sends its
// media from P-2 and echoes from P whatever it receives on P-2 (#324), and
// the switch sends at 20 ms. Both directions must keep flowing.
func echoPeerCall(t *testing.T, pubIP, privIP string, lo, hi int, delayed bool, dur time.Duration) {
	pub := newAuditPool("public", lo, hi, pubIP)
	priv := newAuditPool("private", lo, hi, privIP)
	pub.loopback.Store(true)
	priv.loopback.Store(true)
	s, err := AllocateAcross(pub.PlanePool, priv.PlanePool, SessionConfig{Latch: [2]LatchMode{LatchStrict, LatchStrict}, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// The peer: E is the advertised socket on P, S the socket it sends from.
	var adv, src *net.UDPConn
	for i := 0; i < 50 && src == nil; i++ {
		e, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		p := e.LocalAddr().(*net.UDPAddr).Port
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p - 2})
		if err != nil {
			_ = e.Close()
			continue
		}
		adv, src = e, c
	}
	if src == nil {
		t.Skip("no free port pair P, P-2 on 127.0.0.1")
	}
	defer adv.Close()
	defer src.Close()
	sw := auditUDP(t, privIP)

	s.SetRemote(SideA, auditAddrPort(adv))
	if delayed { // learning delayed by LearnDelay; otherwise dest moves at once
		s.SetSignallingSource(SideA, netip.MustParseAddr("127.0.0.1"))
	}
	s.SetRemote(SideB, auditAddrPort(sw))
	s.Start()
	pubDst := &net.UDPAddr{IP: net.ParseIP(pubIP), Port: s.RTPPort(SideA)}
	privDst := &net.UDPAddr{IP: net.ParseIP(privIP), Port: s.RTPPort(SideB)}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var swGot, peerGot arrivals // swGot: the peer's own packets at the switch
	var sent atomic.Int64

	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	// Peer sender (from P-2).
	run(func() {
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				_, _ = src.WriteToUDP([]byte("S"), pubDst)
			}
		}
	})
	// Switch sender.
	run(func() {
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				_, _ = sw.WriteToUDP([]byte("W"), privDst)
				sent.Add(1)
			}
		}
	})
	// Peer receivers: S echoes from P what it gets; E only counts.
	run(func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := src.ReadFromUDP(buf); err != nil {
				return
			}
			peerGot.add()
			_, _ = adv.WriteToUDP([]byte("E"), pubDst)
		}
	})
	run(func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := adv.ReadFromUDP(buf); err != nil {
				return
			}
			peerGot.add()
		}
	})
	// Switch receiver.
	run(func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := sw.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n == 1 && buf[0] == 'S' {
				swGot.add()
			}
		}
	})

	start := time.Now()
	time.Sleep(dur)
	end := time.Now()
	close(stop)
	time.Sleep(300 * time.Millisecond) // let in-flight packets land
	st := s.Stats()
	_ = adv.Close()
	_ = src.Close()
	_ = sw.Close()
	wg.Wait()

	// Peer to switch: at most one gap, about LatchFallback, then none.
	big, n := swGot.gaps(start, end, 250*time.Millisecond)
	if n < 100 {
		t.Fatalf("switch got only %d of the peer's packets", n)
	}
	if len(big) > 1 {
		t.Errorf("peer->switch gaps %v, want at most one", big)
	}
	for _, g := range big {
		if g > LatchFallback+500*time.Millisecond {
			t.Errorf("peer->switch gap %v exceeds the fallback bound", g)
		}
	}
	// Switch to peer never stalls (the SDP address and the learned port both
	// reach the peer).
	if big, _ := peerGot.gaps(start, end, 250*time.Millisecond); len(big) > 0 {
		t.Errorf("switch->peer gaps %v, want none", big)
	}
	if st.A.RTPPacketsRx != st.B.RTPPacketsTx || st.B.RTPPacketsRx != st.A.RTPPacketsTx {
		t.Errorf("rx/tx mismatch: A rx %d tx %d, B rx %d tx %d", st.A.RTPPacketsRx, st.A.RTPPacketsTx, st.B.RTPPacketsRx, st.B.RTPPacketsTx)
	}
	if st.B.RTPPacketsRx < uint64(sent.Load())-5 {
		t.Errorf("switch packets lost at the relay: sent %d, relayed %d", sent.Load(), st.B.RTPPacketsRx)
	}
}

// Delayed learning needs LearnDelay (3 s) + LatchFallback (1 s) + margin;
// without it the echo starts at once, so a second cycle would show within
// ~3 s and 4 s covers one gap plus two fallback windows.
func TestEchoPeerSingleIP(t *testing.T) {
	echoPeerCall(t, "127.0.0.1", "127.0.0.1", 22600, 22699, true, 6*time.Second)
}

func TestEchoPeerSingleIPImmediate(t *testing.T) {
	echoPeerCall(t, "127.0.0.1", "127.0.0.1", 22800, 22899, false, 4*time.Second)
}

func TestEchoPeerTwoAddresses(t *testing.T) {
	auditUDP(t, "127.0.0.2") // skips when the alias is missing
	echoPeerCall(t, "127.0.0.1", "127.0.0.2", 22700, 22799, true, 6*time.Second)
}

func TestEchoPeerTwoAddressesImmediate(t *testing.T) {
	auditUDP(t, "127.0.0.2")
	echoPeerCall(t, "127.0.0.1", "127.0.0.2", 22900, 22999, false, 4*time.Second)
}
