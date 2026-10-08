package edge

import (
	fsip "github.com/freesbc/freesbc/internal/sip"
	"net/netip"
	"testing"
	"time"
)

func binding(aor, callID string, src string, ttl time.Duration) Binding {
	return Binding{
		AOR: aor, User: aor[:len(aor)-len("@example.com")],
		CallID: callID, Transport: "udp",
		Source:    netip.MustParseAddrPort(src),
		ExpiresAt: time.Now().Add(ttl),
	}
}

func TestLocationPutAndLookup(t *testing.T) {
	l := NewLocation()
	b, err := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:5060", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if b.Token == "" {
		t.Fatal("no token assigned")
	}
	got, ok := l.ByToken(b.Token)
	if !ok || got.AOR != "1001@example.com" {
		t.Fatalf("ByToken = %+v %v", got, ok)
	}
	if bs := l.ByAOR("1001@example.com"); len(bs) != 1 {
		t.Fatalf("ByAOR = %d bindings", len(bs))
	}
	if l.Count() != 1 {
		t.Errorf("Count = %d", l.Count())
	}
}

// A refresh must keep the SAME token: FreeSWITCH stored that contact and
// will use it as the Request-URI of every inbound call, so a new token
// would strand the registration.
func TestLocationRefreshKeepsToken(t *testing.T) {
	l := NewLocation()
	first, _ := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:5060", time.Hour))
	second, err := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:6000", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Token != first.Token {
		t.Fatalf("token changed on refresh: %q → %q", first.Token, second.Token)
	}
	if l.Count() != 1 {
		t.Errorf("refresh created a second binding: %d", l.Count())
	}
	// ...but the source address must follow the client's new port.
	got, _ := l.ByToken(first.Token)
	if got.Source.Port() != 6000 {
		t.Errorf("source not updated: %v", got.Source)
	}
}

// Two devices for one user are two bindings with two tokens.
func TestLocationMultipleDevices(t *testing.T) {
	l := NewLocation()
	a, _ := l.Put(binding("1001@example.com", "desk-phone", "198.51.100.5:5060", time.Hour))
	b, _ := l.Put(binding("1001@example.com", "browser", "203.0.113.9:41000", time.Hour))
	if a.Token == b.Token {
		t.Fatal("two devices share a token")
	}
	if got := len(l.ByAOR("1001@example.com")); got != 2 {
		t.Fatalf("ByAOR = %d, want 2", got)
	}
}

func TestLocationRemove(t *testing.T) {
	l := NewLocation()
	b, _ := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:5060", time.Hour))
	if l.Remove("1001@example.com", "call-a") == nil {
		t.Fatal("Remove reported nothing removed")
	}
	if _, ok := l.ByToken(b.Token); ok {
		t.Error("binding still resolvable after Remove")
	}
	if l.Count() != 0 {
		t.Errorf("Count = %d after Remove", l.Count())
	}
	if l.Remove("1001@example.com", "call-a") != nil {
		t.Error("second Remove reported a removal")
	}
}

func TestLocationExpiry(t *testing.T) {
	l := NewLocation()
	b, _ := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:5060", -time.Second))
	if _, ok := l.ByToken(b.Token); ok {
		t.Error("expired binding resolvable")
	}
	if got := l.ByAOR("1001@example.com"); len(got) != 0 {
		t.Error("expired binding listed")
	}
	if n := l.Prune(); n != 1 {
		t.Errorf("Prune removed %d, want 1", n)
	}
	if l.Count() != 0 {
		t.Errorf("Count = %d after Prune", l.Count())
	}
}

// A WebSocket that closes takes its bindings with it: keeping them would
// make FreeSBC accept inbound calls it cannot deliver.
func TestLocationRemoveBySource(t *testing.T) {
	l := NewLocation()
	l.Put(binding("1001@example.com", "ws-a", "203.0.113.9:41000", time.Hour))
	l.Put(binding("1002@example.com", "ws-b", "203.0.113.9:41000", time.Hour))
	l.Put(binding("1003@example.com", "udp", "198.51.100.5:5060", time.Hour))
	if n := l.RemoveBySource(netip.MustParseAddrPort("203.0.113.9:41000")); n != 2 {
		t.Fatalf("removed %d, want 2", n)
	}
	if l.Count() != 1 {
		t.Errorf("Count = %d, want 1", l.Count())
	}
}

func TestLocationBounds(t *testing.T) {
	l := NewLocation()
	l.maxPerAOR = 2
	for i, id := range []string{"a", "b"} {
		if _, err := l.Put(binding("1001@example.com", id, "198.51.100.5:5060", time.Hour)); err != nil {
			t.Fatalf("device %d rejected: %v", i, err)
		}
	}
	if _, err := l.Put(binding("1001@example.com", "c", "198.51.100.5:5060", time.Hour)); err == nil {
		t.Fatal("per-AoR cap not enforced")
	}

	l2 := NewLocation()
	l2.maxTotal = 2
	l2.Put(binding("1001@example.com", "a", "198.51.100.5:5060", time.Hour))
	l2.Put(binding("1002@example.com", "b", "198.51.100.5:5060", time.Hour))
	if _, err := l2.Put(binding("1003@example.com", "c", "198.51.100.5:5060", time.Hour)); err == nil {
		t.Fatal("total cap not enforced")
	}
}

func TestTokensAreUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok := fsip.NewToken()
		if len(tok) < 16 {
			t.Fatalf("token %q too short to resist guessing", tok)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}

// checkSourceIndex fails the test unless the source index holds exactly the
// bindings the token index holds, each under its own Source.
func checkSourceIndex(t *testing.T, l *Location) {
	t.Helper()
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := 0
	for src, list := range l.bySource {
		if len(list) == 0 {
			t.Errorf("source index keeps an empty list for %v", src)
		}
		for _, b := range list {
			n++
			if b.Source != src {
				t.Errorf("binding %s indexed under %v, its source is %v", b.Token, src, b.Source)
			}
			if l.byToken[b.Token] != b {
				t.Errorf("source index holds binding %s the token index does not", b.Token)
			}
		}
	}
	if n != len(l.byToken) {
		t.Errorf("source index holds %d bindings, token index %d", n, len(l.byToken))
	}
}

// The source index (HasSource, RemoveBySource) must stay consistent with the
// other two indexes through every way a binding enters or leaves the table.
func TestLocationSourceIndexConsistency(t *testing.T) {
	l := NewLocation()
	srcA := netip.MustParseAddrPort("198.51.100.5:5060")
	srcB := netip.MustParseAddrPort("198.51.100.5:6000")

	// add: two AoRs over one socket share a source.
	if _, err := l.Put(binding("1001@example.com", "call-a", srcA.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(binding("1002@example.com", "call-b", srcA.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	checkSourceIndex(t, l)
	if !l.HasSource("udp", srcA) || !l.HasSource("UDP", srcA) {
		t.Fatal("HasSource misses a registered udp source")
	}
	if l.HasSource("ws", srcA) {
		t.Error("HasSource matched the wrong transport")
	}
	if l.HasSource("udp", srcB) {
		t.Error("HasSource matched a different port of the same IP")
	}

	// refresh from a new source: re-indexed, the old source keeps only the
	// other AoR.
	if _, err := l.Put(binding("1001@example.com", "call-a", srcB.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	checkSourceIndex(t, l)
	if !l.HasSource("udp", srcB) || !l.HasSource("udp", srcA) {
		t.Fatal("refresh lost a source")
	}

	// remove (un-REGISTER): srcA's last binding goes, and so does srcA.
	if l.Remove("1002@example.com", "call-b") == nil {
		t.Fatal("Remove found nothing")
	}
	checkSourceIndex(t, l)
	if l.HasSource("udp", srcA) {
		t.Error("source still admitted after its only binding was removed")
	}

	// RemoveBySource: every binding from the source, and nothing else.
	if _, err := l.Put(binding("1003@example.com", "call-c", srcB.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(binding("1004@example.com", "call-d", srcA.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := l.RemoveBySource(srcB); n != 2 {
		t.Fatalf("RemoveBySource removed %d, want 2", n)
	}
	checkSourceIndex(t, l)
	if l.HasSource("udp", srcB) || !l.HasSource("udp", srcA) || l.Count() != 1 {
		t.Fatalf("RemoveBySource: srcB=%v srcA=%v count=%d",
			l.HasSource("udp", srcB), l.HasSource("udp", srcA), l.Count())
	}

	// expiry: an expired binding is not a live source even before Prune,
	// and Prune takes it out of the index.
	if _, err := l.Put(binding("1005@example.com", "call-e", "198.51.100.9:5060", -time.Second)); err != nil {
		t.Fatal(err)
	}
	if l.HasSource("udp", netip.MustParseAddrPort("198.51.100.9:5060")) {
		t.Error("an expired binding admits its source")
	}
	if n := l.Prune(); n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	checkSourceIndex(t, l)

	// The per-AoR sweep in Put removes an expired binding from the index
	// too.
	if _, err := l.Put(binding("1004@example.com", "call-x", srcB.String(), -time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(binding("1004@example.com", "call-y", srcB.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	checkSourceIndex(t, l)

	// A refused Put (per-AoR cap) must leave no trace in the index.
	for i := 0; i < defaultMaxPerAOR+2; i++ {
		_, _ = l.Put(binding("1006@example.com", "cap-"+string(rune('a'+i)), "198.51.100.10:5060", time.Hour))
	}
	checkSourceIndex(t, l)
	if got := len(l.ByAOR("1006@example.com")); got != defaultMaxPerAOR {
		t.Fatalf("per-AoR cap: %d bindings, want %d", got, defaultMaxPerAOR)
	}
}

// The removal hook (used to end subscription records) hears about every way
// a binding leaves the table, after the table's lock is released, and not
// about a refresh in place.
func TestLocationRemoveHook(t *testing.T) {
	newTable := func() (*Location, *[]string) {
		l := NewLocation()
		var got []string
		l.SetOnRemove(func(tokens []string) {
			// The hook runs outside the lock: it may call back in.
			_ = l.Count()
			got = append(got, tokens...)
		})
		return l, &got
	}
	mustPut := func(t *testing.T, l *Location, b Binding) *Binding {
		t.Helper()
		p, err := l.Put(b)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("Remove", func(t *testing.T) {
		l, got := newTable()
		b := mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", time.Hour))
		l.Remove("1001@example.com", "c1")
		if len(*got) != 1 || (*got)[0] != b.Token {
			t.Errorf("hook tokens = %v, want [%s]", *got, b.Token)
		}
	})
	t.Run("RemoveBySource", func(t *testing.T) {
		l, got := newTable()
		a := mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", time.Hour))
		b := mustPut(t, l, binding("1002@example.com", "c2", "198.51.100.5:5060", time.Hour))
		mustPut(t, l, binding("1003@example.com", "c3", "198.51.100.6:5060", time.Hour))
		l.RemoveBySource(netip.MustParseAddrPort("198.51.100.5:5060"))
		if len(*got) != 2 {
			t.Fatalf("hook tokens = %v, want the two bindings of that source", *got)
		}
		seen := map[string]bool{(*got)[0]: true, (*got)[1]: true}
		if !seen[a.Token] || !seen[b.Token] {
			t.Errorf("hook tokens = %v", *got)
		}
	})
	t.Run("Prune", func(t *testing.T) {
		l, got := newTable()
		old := mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", -time.Second))
		mustPut(t, l, binding("1002@example.com", "c2", "198.51.100.6:5060", time.Hour))
		if n := l.Prune(); n != 1 {
			t.Fatalf("Prune = %d", n)
		}
		if len(*got) != 1 || (*got)[0] != old.Token {
			t.Errorf("hook tokens = %v, want [%s]", *got, old.Token)
		}
	})
	t.Run("sweep inside Put", func(t *testing.T) {
		l, got := newTable()
		old := mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", -time.Second))
		mustPut(t, l, binding("1001@example.com", "c2", "198.51.100.5:5062", time.Hour))
		if len(*got) != 1 || (*got)[0] != old.Token {
			t.Errorf("hook tokens = %v, want the lapsed binding [%s]", *got, old.Token)
		}
	})
	t.Run("refresh in place is not a removal", func(t *testing.T) {
		l, got := newTable()
		mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", time.Hour))
		mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:6000", time.Hour))
		if len(*got) != 0 {
			t.Errorf("hook tokens = %v, want none", *got)
		}
	})
}
