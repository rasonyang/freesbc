package edge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
)

func TestLocationRegistrationsSearchAndPaging(t *testing.T) {
	l := NewLocation()
	if page, total := l.Registrations("", 10, 0); page == nil || len(page) != 0 || total != 0 {
		t.Fatalf("empty table: %v %d, want non-nil empty", page, total)
	}
	for i, u := range []string{"1001", "1002", "2001", "1001x"} {
		if _, err := l.Put(binding(u+"@example.com", "c"+u, fmt.Sprintf("198.51.100.%d:5060", i+1), time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	// A second device for 1001, and an expired binding that must not list.
	b := binding("1001@example.com", "c-second", "198.51.100.9:5060", time.Hour)
	b.Transport = "wss"
	if _, err := l.Put(b); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(binding("9999@example.com", "c-dead", "198.51.100.10:5060", -time.Second)); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		user          string
		limit, offset int
		wantLen       int
		wantTotal     int
		first         string
	}{
		{"all", "", 100, 0, 5, 5, "1001@example.com"},
		{"user substring", "1001", 100, 0, 3, 3, "1001@example.com"},
		{"user case-insensitive", " 2001 ", 100, 0, 1, 1, "2001@example.com"},
		{"no match", "nobody", 100, 0, 0, 0, ""},
		{"page 1", "", 2, 0, 2, 5, "1001@example.com"},
		{"page 3", "", 2, 4, 1, 5, "2001@example.com"},
		{"past end", "", 2, 50, 0, 5, ""},
		{"negative offset and zero limit", "", 0, -4, 1, 5, "1001@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page, total := l.Registrations(tc.user, tc.limit, tc.offset)
			if page == nil || len(page) != tc.wantLen || total != tc.wantTotal {
				t.Fatalf("len %d total %d (page %v), want %d / %d", len(page), total, page, tc.wantLen, tc.wantTotal)
			}
			if tc.first != "" && page[0].AOR != tc.first {
				t.Errorf("first AoR = %s, want %s", page[0].AOR, tc.first)
			}
		})
	}
	page, _ := l.Registrations("1001", 100, 0)
	if page[0].Source != "198.51.100.1:5060" || page[0].Transport != "udp" || page[1].Transport != "wss" || page[0].ExpiresAt.IsZero() {
		t.Errorf("fields = %+v", page)
	}
}

func TestLocationRegistrationsBoundedPageOf10kBindings(t *testing.T) {
	l := NewLocation()
	l.maxTotal, l.maxPerAOR = 10000, 10
	for i := 0; i < 10000; i++ {
		if _, err := l.Put(binding(fmt.Sprintf("u%05d@example.com", i), fmt.Sprintf("c%d", i),
			fmt.Sprintf("10.%d.%d.1:5060", i>>8, i&0xff), time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	page, total := l.Registrations("", 1_000_000, 0)
	if total != 10000 || len(page) != maxRegistrationPage {
		t.Fatalf("len %d total %d, want %d of 10000", len(page), total, maxRegistrationPage)
	}
	if page[0].AOR != "u00000@example.com" || page[len(page)-1].AOR != "u00999@example.com" {
		t.Errorf("page bounds %s .. %s", page[0].AOR, page[len(page)-1].AOR)
	}
	last, _ := l.Registrations("", 50, 9990)
	if len(last) != 10 || last[9].AOR != "u09999@example.com" {
		t.Errorf("last page = %d", len(last))
	}
	if page, total := l.Registrations("u0123", 100, 0); total != 10 || len(page) != 10 {
		t.Errorf("search u0123: %d / %d, want 10", len(page), total)
	}
}

func TestCarrierRegTableSnapshot(t *testing.T) {
	tab := newCarrierRegTable()
	if got := tab.snapshot(); got == nil || len(got) != 0 {
		t.Fatalf("empty snapshot = %v, want non-nil empty", got)
	}
	exp := time.Now().Add(time.Minute)
	tab.put(carrierBinding{token: "t2", carrier: "b", node: "10.0.0.2:5060", contact: sip.Uri{User: "gw", Host: "10.0.0.2"}, expires: exp})
	tab.put(carrierBinding{token: "t1", carrier: "a", node: "10.0.0.1:5060", contact: sip.Uri{User: "gw", Host: "10.0.0.1"}, expires: exp})
	tab.put(carrierBinding{token: "dead", carrier: "a", expires: time.Now().Add(-time.Second)})
	got := tab.snapshot()
	if len(got) != 2 {
		t.Fatalf("snapshot = %+v, want 2 live", got)
	}
	if got[0] != (CarrierRegistrationInfo{Carrier: "a", User: "gw", Token: "t1", Node: "10.0.0.1:5060", Expires: exp}) || got[1].Carrier != "b" {
		t.Errorf("snapshot = %+v", got)
	}
	tab.remove("t1")
	if got := tab.snapshot(); len(got) != 1 || got[0].Token != "t2" {
		t.Errorf("after remove = %+v", got)
	}
}

func TestCooldownTableSnapshot(t *testing.T) {
	h := newCooldownTable()
	names := []string{"10.0.0.1:5060", "10.0.0.2:5060"}
	now := time.Now()

	got := h.snapshot(names, now)
	if len(got) != 2 || got[0].State != NodeHealthy || !got[0].LastFailure.IsZero() || got[0].CooldownRemaining != 0 {
		t.Fatalf("fresh = %+v", got)
	}

	h.Penalize(names[1], time.Minute)
	got = h.snapshot(names, time.Now())
	n := got[1]
	if got[0].State != NodeHealthy || n.State != NodeCoolingDown || n.LastFailure.IsZero() ||
		n.CooldownRemaining <= 0 || n.CooldownRemaining > time.Minute || !n.CooldownUntil.After(n.LastFailure) {
		t.Fatalf("penalized = %+v", got)
	}

	// The window lapses lazily: healthy again, last failure remembered.
	got = h.snapshot(names, n.CooldownUntil.Add(time.Second))
	if got[1].State != NodeHealthy || got[1].LastFailure.IsZero() || got[1].CooldownRemaining != 0 {
		t.Errorf("lapsed = %+v", got[1])
	}

	h.Penalize(names[1], time.Minute)
	h.Recover(names[1])
	got = h.snapshot(names, time.Now())
	if got[1].State != NodeHealthy || got[1].LastFailure.IsZero() {
		t.Errorf("recovered = %+v", got[1])
	}
}

func TestCarrierDirectoryInfoDNSFailureAndRecovery(t *testing.T) {
	stub := &dnsStub{
		srv: map[string][]*net.SRV{"sip.carrier.example": {
			{Target: "n1.carrier.example.", Port: 5070, Priority: 1},
			{Target: "n2.carrier.example.", Port: 5070, Priority: 2},
		}},
		ips: map[string][]string{
			"n1.carrier.example": {"192.0.2.1"}, "n2.carrier.example": {"192.0.2.2"},
			"plain.example": {"192.0.2.7"},
		},
	}
	clk := &fakeClock{t: time.Unix(1000, 0)}
	d := newTestDirectory(stub, clk, nil,
		config.Carrier{Name: "srv", Host: "sip.carrier.example", Port: 5060, Transport: config.CarrierTCP},
		config.Carrier{Name: "a", Host: "plain.example", Port: 5080, ExplicitPort: true},
		config.Carrier{Name: "lit", Host: "198.51.100.4", Port: 5060, Addr: netip.MustParseAddr("198.51.100.4")},
		config.Carrier{Name: "unresolved", Host: "none.example", Port: 5060})

	byName := func() map[string]CarrierInfo {
		m := map[string]CarrierInfo{}
		for _, c := range d.snapshotInfo() {
			m[c.Name] = c
		}
		return m
	}
	d.refresh(context.Background())
	got := byName()
	if len(got) != 4 {
		t.Fatalf("infos = %+v", got)
	}
	if c := got["srv"]; c.Mode != carrierModeSRV || c.Transport != "tcp" || c.Failing || c.LastError != "" ||
		len(c.Addresses) != 2 || !c.Addresses[0].InUse || c.Addresses[1].InUse ||
		c.Addresses[0].Address != "192.0.2.1:5070" || !c.ResolvedAt.Equal(clk.t) || !c.ExpiresAt.Equal(clk.t.Add(carrierDNSTTL)) {
		t.Errorf("srv = %+v", c)
	}
	if c := got["a"]; c.Mode != carrierModeA || c.Host != "plain.example:5080" || c.Transport != "udp" || c.Addresses[0].Address != "192.0.2.7:5080" {
		t.Errorf("a = %+v", c)
	}
	if c := got["lit"]; c.Mode != carrierModeLiteral || len(c.Addresses) != 1 || !c.Addresses[0].InUse || c.Failing {
		t.Errorf("lit = %+v", c)
	}
	// "none.example" resolves to nothing (A fallback after a not-found SRV).
	if c := got["unresolved"]; !c.Failing || c.LastError == "" || c.Addresses == nil || len(c.Addresses) != 0 {
		t.Errorf("unresolved = %+v", c)
	}

	// A resolver outage keeps the last good addresses and shows the error.
	stub.mu.Lock()
	stub.srvErr = errors.New("resolver down")
	stub.mu.Unlock()
	failedAt := clk.t.Add(carrierDNSTTL + time.Second)
	clk.t = failedAt
	d.refresh(context.Background())
	c := byName()["srv"]
	if !c.Failing || c.LastError == "" || len(c.Addresses) != 2 || c.Mode != carrierModeSRV ||
		!c.ExpiresAt.Equal(failedAt.Add(carrierDNSNegTTL)) || c.ResolvedAt.Equal(failedAt) {
		t.Errorf("failing srv = %+v", c)
	}

	// Recovery clears the error and moves the resolution time.
	stub.mu.Lock()
	stub.srvErr = nil
	stub.mu.Unlock()
	clk.advance(carrierDNSNegTTL + time.Second)
	d.refresh(context.Background())
	c = byName()["srv"]
	if c.Failing || c.LastError != "" || !c.ResolvedAt.Equal(clk.t) {
		t.Errorf("recovered srv = %+v", c)
	}
}
