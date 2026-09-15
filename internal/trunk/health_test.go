package trunk

import (
	"sync"
	"testing"
	"time"
)

func TestEndpointHealthPenalizeAndExpire(t *testing.T) {
	h := newEndpointHealth()
	ep := Endpoint{Host: "1.2.3.4", Port: 5060, Transport: "udp"}

	if !h.Available(ep) {
		t.Fatal("fresh endpoint must be available")
	}
	// A long cooldown is still in force immediately after Penalize.
	h.Penalize(ep, time.Hour)
	if h.Available(ep) {
		t.Fatal("penalized endpoint must be unavailable within the window")
	}
	// A short cooldown expires on its own (lazy, no sweeper).
	h.Penalize(ep, 20*time.Millisecond)
	if h.Available(ep) {
		t.Fatal("still within the 20ms cooldown")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !h.Available(ep) {
		if time.Now().After(deadline) {
			t.Fatal("cooldown never expired")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEndpointHealthRecoverClearsImmediately(t *testing.T) {
	h := newEndpointHealth()
	ep := Endpoint{Host: "5.6.7.8", Port: 5060, Transport: "tcp"}
	h.Penalize(ep, time.Hour)
	if h.Available(ep) {
		t.Fatal("penalized for an hour → unavailable")
	}
	h.Recover(ep)
	if !h.Available(ep) {
		t.Fatal("Recover must clear the cooldown immediately")
	}
}

func TestEndpointHealthConcurrent(t *testing.T) {
	h := newEndpointHealth()
	ep := Endpoint{Host: "9.9.9.9", Port: 5060, Transport: "udp"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Penalize(ep, time.Second)
			_ = h.Available(ep)
			h.Recover(ep)
		}()
	}
	wg.Wait() // -race is the assertion
}
