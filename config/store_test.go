package config

import (
	"sync"
	"testing"
	"time"
)

func TestStoreCurrentAndReplace(t *testing.T) {
	c1 := validConfig()
	s := NewStore(c1)
	if s.Current() != c1 {
		t.Fatal("Current should return the initial config")
	}
	c2 := validConfig()
	s.Replace(c2)
	if s.Current() != c2 {
		t.Fatal("Current should return the replaced config")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore(validConfig())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				s.Replace(validConfig())
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if s.Current() == nil {
					t.Error("Current returned nil")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestStoreSubscribeNotifiesOnReplace(t *testing.T) {
	s := NewStore(validConfig())
	ch := s.Subscribe()
	select {
	case <-ch:
		t.Fatal("should not fire before any Replace")
	default:
	}
	s.Replace(validConfig())
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("Subscribe did not fire on Replace")
	}
}

func TestStoreSubscribeCoalesces(t *testing.T) {
	s := NewStore(validConfig())
	ch := s.Subscribe()
	for i := 0; i < 5; i++ {
		s.Replace(validConfig())
	}
	// Buffered(1) + non-blocking send: at least one signal, never a block.
	got := 0
	for {
		select {
		case <-ch:
			got++
		default:
			if got < 1 {
				t.Fatal("expected at least one coalesced signal")
			}
			return
		}
	}
}

func TestStoreReplaceNeverBlocksWithSlowSubscriber(t *testing.T) {
	s := NewStore(validConfig())
	_ = s.Subscribe() // never drained
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			s.Replace(validConfig())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Replace blocked on an undrained subscriber")
	}
}
