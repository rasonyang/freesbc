package config

import (
	"sync"
	"testing"
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
