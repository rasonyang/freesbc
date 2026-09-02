package call

import (
	"sync"
	"testing"
)

func TestRegistryAddRemoveCount(t *testing.T) {
	r := NewRegistry()
	if r.Count() != 0 {
		t.Fatal("new registry must be empty")
	}
	r.Add(Record{ID: "a", FromPeer: "pbx", ToPeer: "carrier", StartUnixNano: 1})
	r.Add(Record{ID: "b", FromPeer: "pbx", ToPeer: "carrier", StartUnixNano: 2})
	if r.Count() != 2 {
		t.Fatalf("count = %d, want 2", r.Count())
	}
	r.Remove("a")
	if r.Count() != 1 {
		t.Fatalf("count after remove = %d, want 1", r.Count())
	}
	r.Remove("missing") // no-op, must not panic
	snap := r.Snapshot()
	if len(snap) != 1 || snap[0].ID != "b" {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestRegistryReAddOverwrites(t *testing.T) {
	r := NewRegistry()
	r.Add(Record{ID: "a", ToPeer: "carrier-a"})
	r.Add(Record{ID: "a", ToPeer: "carrier-b"})
	if r.Count() != 1 {
		t.Fatalf("re-add same id must not duplicate: count=%d", r.Count())
	}
	if r.Snapshot()[0].ToPeer != "carrier-b" {
		t.Error("re-add must overwrite")
	}
}

func TestRegistryConcurrent(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := string(rune('A' + n%26))
			r.Add(Record{ID: id})
			_ = r.Count()
			r.Snapshot()
			r.Remove(id)
		}(i)
	}
	wg.Wait()
}
