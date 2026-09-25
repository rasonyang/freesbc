package config

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// audit: P2-CFG-007
// A reload that edits only hot settings reports no restart-only change; one
// that edits the listener set, the edge topology or the plane set names
// each changed key.
func TestRestartOnlyChanges(t *testing.T) {
	parse := func(src string) *Config {
		t.Helper()
		c, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return c
	}
	trunk := parse(minimalYAML)
	edge := parse(proxyYAML)
	withPstn := parse(withPSTN(proxyYAML, "  pstn:\n    address: 198.51.100.9:5060\n    match: 203.0.113.7:16060\n"))

	cases := []struct {
		name          string
		running, next *Config
		want          []string
	}{
		{"identical", trunk, parse(minimalYAML), nil},
		{"hot only: peer address", trunk, parse(strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.99:5060", 1)), nil},
		{"hot only: pstn budget", withPstn,
			parse(withPSTN(proxyYAML, "  pstn:\n    address: 198.51.100.9:5060\n    match: 203.0.113.7:16060\n    attempt_timeout: 5s\n")), nil},
		{"trunk listener", trunk, parse(strings.Replace(minimalYAML, "0.0.0.0:5060", "0.0.0.0:5070", 1)),
			[]string{"listen.sip / sip.bind_ip / sip.bind_port / sip.transport"}},
		{"edge rtp range", edge, parse(strings.Replace(proxyYAML, "port_max: 39999", "port_max: 38999", 1)),
			[]string{"rtp.public / rtp.private"}},
		{"pstn removed", withPstn, edge,
			[]string{"sip.pstn (address, transport, match, gateways, routes)"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RestartOnlyChanges(tc.running, tc.next); !slices.Equal(got, tc.want) {
				t.Errorf("RestartOnlyChanges = %q, want %q", got, tc.want)
			}
		})
	}
}

// audit: P2-APP-003
// app.Run decides once which planes run. A reload that adds or removes a
// plane is a restart-only change and must be reported as one.
func TestRestartOnlyChangesPlaneSet(t *testing.T) {
	trunk, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	edge, err := Parse([]byte(proxyYAML))
	if err != nil {
		t.Fatal(err)
	}
	got := RestartOnlyChanges(trunk, edge)
	for _, key := range []string{
		"peers (trunk plane on/off)",
		"sip.upstream / sip.upstreams.nodes (edge plane on/off)",
	} {
		if !slices.Contains(got, key) {
			t.Errorf("trunk-only → edge-only reload: %q missing from %q", key, got)
		}
	}
}

// syncBuffer is a bytes.Buffer safe to write from the watcher goroutine and
// read from the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// audit: P2-CFG-007
// Watch publishes a reload that edits a restart-only setting (its hot
// settings apply) but warns, naming the setting, instead of accepting it
// silently.
func TestWatchWarnsOnRestartOnlyChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	var logs syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Watch(ctx, path, store, slog.New(slog.NewTextHandler(&logs, nil))) }()
	time.Sleep(100 * time.Millisecond) // let the watcher attach

	updated := strings.Replace(minimalYAML, "0.0.0.0:5060", "0.0.0.0:5070", 1)
	updated = strings.Replace(updated, "10.0.0.10:5060", "10.0.0.99:5060", 1)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.99:5060"
	})
	out := logs.String()
	if !strings.Contains(out, "restart-only") || !strings.Contains(out, "listen.sip") {
		t.Errorf("reload changing listen.sip logged no restart-only warning naming it:\n%s", out)
	}
}
