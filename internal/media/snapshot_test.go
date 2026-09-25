package media

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// countingPool is a pool whose params function counts its calls.
func countingPool(name string, lo, hi uint16, n *atomic.Int32) *PlanePool {
	return NewPlanePool(name, func() PlaneParams {
		n.Add(1)
		return PlaneParams{MinPort: lo, MaxPort: hi, BindIP: netip.MustParseAddr("127.0.0.1"), Timeout: time.Minute}
	})
}

// audit: P2-MED-009
// One allocation reads each pool's configuration once: a reload landing
// between two reads must never give one session a range from one snapshot
// and a timeout or loopback policy from another.
func TestAllocationReadsParamsOncePerPool(t *testing.T) {
	var n, na, nb atomic.Int32

	p := countingPool("trunk", 23840, 23847, &n)
	s, err := p.Allocate(SessionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got := n.Load(); got != 1 {
		t.Errorf("Allocate read the pool's params %d times, want 1", got)
	}

	a := countingPool("public", 23848, 23851, &na)
	b := countingPool("private", 23852, 23859, &nb)
	s, err = AllocateAcross(a, b, SessionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if na.Load() != 1 || nb.Load() != 1 {
		t.Errorf("AllocateAcross read params %d (public) and %d (private) times, want 1 each", na.Load(), nb.Load())
	}

	nb.Store(0)
	ws, err := NewWebRTCSession(nil, b, WebRTCSessionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	b.release(ws.PrivateRTPPort())
	ws.priv.Close()
	if got := nb.Load(); got != 1 {
		t.Errorf("NewWebRTCSession read the private pool's params %d times, want 1", got)
	}
}
