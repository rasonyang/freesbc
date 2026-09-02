package trunk

import (
	"sync"
	"testing"
	"time"
)

func TestEndpointHealthPenalizeAndExpire(t *testing.T) {
	h := newEndpointHealth()
	fakeNow := time.Unix(2000, 0)
	h.now = func() time.Time { return fakeNow }
	ep := Endpoint{Host: "1.2.3.4", Port: 5060, Transport: "udp"}

	if !h.Available(ep) {
		t.Fatal("fresh endpoint must be available")
	}
	h.Penalize(ep, 30*time.Second)
	if h.Available(ep) {
		t.Fatal("penalized endpoint must be unavailable within the window")
	}
	fakeNow = fakeNow.Add(29 * time.Second)
	if h.Available(ep) {
		t.Fatal("still within cooldown at 29s")
	}
	fakeNow = fakeNow.Add(2 * time.Second) // now 31s > 30s window
	if !h.Available(ep) {
		t.Fatal("cooldown expired → available again")
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
