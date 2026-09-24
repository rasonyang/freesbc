package media

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPool builds a pool over [minPort, maxPort] bound to every interface.
func testPool(minPort, maxPort int) *PlanePool {
	return NewPlanePool("test", func() PlaneParams {
		return PlaneParams{MinPort: uint16(minPort), MaxPort: uint16(maxPort), Timeout: 5 * time.Minute}
	})
}

func TestPoolAllocateReleaseCycle(t *testing.T) {
	p := testPool(22000, 22007) // room for 4 pairs
	var pairs []*portPair
	for i := 0; i < 4; i++ {
		pair, err := p.allocatePair()
		if err != nil {
			t.Fatalf("pair %d: %v", i, err)
		}
		if pair.RTPPort()%2 != 0 {
			t.Errorf("RTP port %d not even", pair.RTPPort())
		}
		pairs = append(pairs, pair)
	}
	if _, err := p.allocatePair(); !errors.Is(err, ErrPortsExhausted) {
		t.Fatalf("want ErrPortsExhausted, got %v", err)
	}
	pairs[0].Close()
	p.release(pairs[0].RTPPort())
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("re-allocate after release: %v", err)
	}
	pair.Close()
	for _, pp := range pairs[1:] {
		pp.Close()
	}
}

func TestPoolSkipsForeignBoundPort(t *testing.T) {
	// Occupy the first RTP port outside the pool; allocation must skip it.
	held, err := net.ListenUDP("udp", &net.UDPAddr{Port: 22100})
	if err != nil {
		t.Skipf("cannot bind fixture port: %v", err)
	}
	defer held.Close()
	p := testPool(22100, 22103)
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer pair.Close()
	if got := pair.RTPPort(); got != 22102 {
		t.Errorf("got port %d, want 22102 (22100 is occupied)", got)
	}
}

func TestPoolStats(t *testing.T) {
	p := testPool(23000, 23007) // 8 ports → 4 pairs
	inUse, total := p.Stats()
	if inUse != 0 || total != 4 {
		t.Fatalf("empty pool: inUse=%d total=%d, want 0/4", inUse, total)
	}
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer pair.Close()
	inUse, total = p.Stats()
	if inUse != 1 || total != 4 {
		t.Fatalf("after 1 alloc: inUse=%d total=%d, want 1/4", inUse, total)
	}
}

func TestPoolConcurrentAllocate(t *testing.T) {
	p := testPool(22200, 22263) // 32 pairs
	var wg sync.WaitGroup
	got := make(chan *portPair, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if pair, err := p.allocatePair(); err == nil {
				got <- pair
			}
		}()
	}
	wg.Wait()
	close(got)
	seen := map[int]bool{}
	n := 0
	for pair := range got {
		n++
		if seen[pair.RTPPort()] {
			t.Errorf("port %d allocated twice", pair.RTPPort())
		}
		seen[pair.RTPPort()] = true
		pair.Close()
	}
	if n != 32 {
		t.Errorf("allocated %d pairs, want 32", n)
	}
}

// TestPoolBindsRTPBindIP proves the media sockets bind to rtp.bind_ip, not
// the wildcard: a NAT/VPN deployment binds media privately (e.g. the VPN
// address) while the SDP advertises the public rtp.advertised_ip — the
// signaling side handles that split (Server.mediaIP); the pool only owns
// the bind plane.
func TestPoolBindsRTPBindIP(t *testing.T) {
	bind := netip.MustParseAddr("127.0.0.1")
	p := NewPlanePool("test", func() PlaneParams {
		return PlaneParams{MinPort: 22300, MaxPort: 22303, BindIP: bind, Timeout: 5 * time.Minute}
	})
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer pair.Close()
	for name, c := range map[string]*net.UDPConn{"RTP": pair.RTP, "RTCP": pair.RTCP} {
		ip := c.LocalAddr().(*net.UDPAddr).IP
		if ip == nil || !ip.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("%s socket bound to %v, want 127.0.0.1 (rtp.bind_ip)", name, ip)
		}
	}

	// A hot-reloaded empty bind address applies to the NEXT allocation:
	// bind all interfaces again (wildcard), without disturbing the
	// established pair.
	bind = netip.Addr{}
	next, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate after reload: %v", err)
	}
	defer next.Close()
	if ip := next.RTP.LocalAddr().(*net.UDPAddr).IP; ip != nil && !ip.IsUnspecified() {
		t.Errorf("after reload, RTP socket bound to %v, want wildcard (unspecified)", ip)
	}
}

// TestPoolRangeBounds proves the configured range drives the pool: every
// allocated pair lands inside it (RTP even, RTCP = RTP+1, never past
// MaxPort), the pool exhausts exactly at the range's pair capacity with an
// error naming the range, and a released port is reused by the next
// allocation.
func TestPoolRangeBounds(t *testing.T) {
	p := testPool(20000, 20100)

	// 101 ports → 50 usable even-RTP pairs (20000..20098; 20100 has no
	// room for its RTCP at 20101).
	const wantPairs = 50
	seen := map[int]bool{}
	var pairs []*portPair
	for i := 0; i < wantPairs; i++ {
		pair, err := p.allocatePair()
		if err != nil {
			t.Fatalf("pair %d: %v", i, err)
		}
		port := pair.RTPPort()
		if port < 20000 || port > 20100 || port%2 != 0 {
			t.Errorf("RTP port %d outside/odd for range 20000-20100", port)
		}
		if rtcp := pair.RTCP.LocalAddr().(*net.UDPAddr).Port; rtcp != port+1 || rtcp > 20100 {
			t.Errorf("RTCP port %d, want RTP+1=%d and <= 20100", rtcp, port+1)
		}
		if seen[port] {
			t.Errorf("port %d allocated twice", port)
		}
		seen[port] = true
		pairs = append(pairs, pair)
	}

	// Exhaustion: the error must be errors.Is-compatible (sig maps it to
	// 503) and name the configured range.
	_, err := p.allocatePair()
	if !errors.Is(err, ErrPortsExhausted) {
		t.Fatalf("want ErrPortsExhausted, got %v", err)
	}
	if !strings.Contains(err.Error(), "20000-20100") {
		t.Errorf("exhaustion error %q does not name the configured range", err)
	}

	// Release one pair → its port is the one reused by the next allocation.
	released := pairs[0].RTPPort()
	pairs[0].Close()
	p.release(released)
	again, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate after release: %v", err)
	}
	defer again.Close()
	if got := again.RTPPort(); got != released {
		t.Errorf("reused port %d, want released port %d", got, released)
	}
	for _, pp := range pairs[1:] {
		pp.Close()
	}
}

// TestPoolStatsOddCapacity proves Stats totals the pairs a range can hold.
func TestPoolStatsOddCapacity(t *testing.T) {
	p := testPool(21000, 21003) // 4 ports → 2 pairs
	if inUse, total := p.Stats(); inUse != 0 || total != 2 {
		t.Fatalf("empty pool: inUse=%d total=%d, want 0/2", inUse, total)
	}
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer pair.Close()
	if inUse, total := p.Stats(); inUse != 1 || total != 2 {
		t.Errorf("after 1 alloc: inUse=%d total=%d, want 1/2", inUse, total)
	}
}
