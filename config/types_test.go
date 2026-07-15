package config

import (
	"testing"
	"time"
)

func TestDurationUnmarshalYAML(t *testing.T) {
	var d Duration
	if err := d.UnmarshalYAML([]byte("90s")); err != nil {
		t.Fatalf("unmarshal 90s: %v", err)
	}
	if d.Std() != 90*time.Second {
		t.Errorf("got %v, want 90s", d.Std())
	}
	if err := d.UnmarshalYAML([]byte("not-a-duration")); err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestPortRangeUnmarshalYAML(t *testing.T) {
	var p PortRange
	if err := p.UnmarshalYAML([]byte("16384-32768")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Min != 16384 || p.Max != 32768 {
		t.Errorf("got %d-%d, want 16384-32768", p.Min, p.Max)
	}
	for _, bad := range []string{"16384", "32768-16384", "0-70000", "0-100", "a-b"} {
		if err := p.UnmarshalYAML([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestSIPListenUnmarshalYAML(t *testing.T) {
	var s SIPListen
	if err := s.UnmarshalYAML([]byte("udp://0.0.0.0:5060")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Transport != "udp" || s.Host != "0.0.0.0" || s.Port != 5060 {
		t.Errorf("got %+v", s)
	}
	if err := s.UnmarshalYAML([]byte("tls://0.0.0.0:5061")); err != nil {
		t.Fatalf("tls listener: %v", err)
	}
	for _, bad := range []string{"sctp://0.0.0.0:5060", "udp://nohost", "5060"} {
		if err := s.UnmarshalYAML([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestParseRateLimit(t *testing.T) {
	rl, err := ParseRateLimit("20/s per_ip")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rl.Rate != 20 || rl.Interval != time.Second || !rl.PerIP {
		t.Errorf("got %+v", rl)
	}
	rl, err = ParseRateLimit("100/m")
	if err != nil {
		t.Fatalf("parse global: %v", err)
	}
	if rl.Rate != 100 || rl.Interval != time.Minute || rl.PerIP {
		t.Errorf("got %+v", rl)
	}
	for _, bad := range []string{"", "20", "0/s", "20/d", "20/s per_call"} {
		if _, err := ParseRateLimit(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
