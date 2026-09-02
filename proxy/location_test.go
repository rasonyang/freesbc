package proxy

import (
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
		tok := newToken()
		if len(tok) < 16 {
			t.Fatalf("token %q too short to resist guessing", tok)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}
