package media

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/config"
)

// testStore builds a config store with the given media port range. Config
// fields are exported, so tests construct the snapshot directly.
func testStore(minPort, maxPort int) *config.Store {
	cfg := &config.Config{
		Listen: config.ListenConfig{
			Media: config.MediaConfig{
				PortRange:  config.PortRange{Min: uint16(minPort), Max: uint16(maxPort)},
				PublicIP:   "auto",
				RTPTimeout: config.Duration(5 * time.Minute),
			},
		},
	}
	return config.NewStore(cfg)
}

func TestPoolAllocateReleaseCycle(t *testing.T) {
	p := NewPool(testStore(40000, 40007)) // room for 4 pairs
	var pairs []*PortPair
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
	held, err := net.ListenUDP("udp", &net.UDPAddr{Port: 40100})
	if err != nil {
		t.Skipf("cannot bind fixture port: %v", err)
	}
	defer held.Close()
	p := NewPool(testStore(40100, 40103))
	pair, err := p.allocatePair()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer pair.Close()
	if got := pair.RTPPort(); got != 40102 {
		t.Errorf("got port %d, want 40102 (40100 is occupied)", got)
	}
}

func TestPoolConcurrentAllocate(t *testing.T) {
	p := NewPool(testStore(40200, 40263)) // 32 pairs
	var wg sync.WaitGroup
	got := make(chan *PortPair, 32)
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
