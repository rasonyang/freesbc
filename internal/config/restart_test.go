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

	"golang.org/x/crypto/bcrypt"
)

// A reload that edits only hot settings (shield) reports no restart-only
// change; every other section names its changed key.
func TestRestartOnlyChanges(t *testing.T) {
	base := minimalYAML + "tls: { cert: a, key: b }\n"
	cases := []struct {
		name string
		next string
		want []string
	}{
		{"identical", base, nil},
		{"hot only: shield", base + "shield: { ban: 2h, rate_limit: 1/s per_ip, carrier_rate_limit: 1/s per_ip }\n", nil},
		{"public", strings.Replace(base, "203.0.113.7", "203.0.113.8", 1), []string{"public"}},
		{"private", strings.Replace(base, "10.77.0.2", "10.77.0.3", 1), []string{"private"}},
		{"rtp", base + "rtp: 30000-30999\n", []string{"rtp"}},
		{"tls", strings.Replace(base, "cert: a", "cert: c", 1), []string{"tls"}},
		{"switch", strings.Replace(base, "10.77.0.10:5060", "10.77.0.11:5060", 1), []string{"edge.switch"}},
		{"switch_carrier_port", strings.Replace(base, "edge:\n", "edge:\n  switch_carrier_port: 5080\n", 1), []string{"edge.switch_carrier_port"}},
		{"listen", strings.Replace(base, "udp: 5060", "udp: 5070", 1), []string{"edge.listen"}},
		{"carriers", strings.Replace(base, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carriers: { a: 1.2.3.4 }", 1), []string{"edge.carriers"}},
		{"carrier_sources", strings.Replace(base, "listen: { udp: 5060 }", "listen: { udp: 5060 }\n  carrier_sources: [1.2.3.4]", 1), []string{"edge.carrier_sources"}},
		{"admin", base + "admin: { listen: 127.0.0.1:8080, password_hash: \"" + testHash + "\" }\n", []string{"admin"}},
		{"admin allowed_hosts", base + "admin: { listen: 127.0.0.1:8080, password_hash: \"" + testHash + "\", allowed_hosts: [a.example] }\n", []string{"admin"}},
	}
	running := mustParse(t, base)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RestartOnlyChanges(running, mustParse(t, tc.next)); !slices.Equal(got, tc.want) {
				t.Errorf("RestartOnlyChanges = %q, want %q", got, tc.want)
			}
		})
	}
}

// testHash is a bcrypt cost-10 hash of "pw".
var testHash = func() string {
	h, err := bcrypt.GenerateFromPassword([]byte("pw"), 10)
	if err != nil {
		panic(err)
	}
	return string(h)
}()

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
	path := filepath.Join(t.TempDir(), "freesbc.yaml")
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

	updated := strings.Replace(minimalYAML, "203.0.113.7", "203.0.113.8", 1) + "shield: { ban: 99m }\n"
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Shield.Ban.Std() == 99*time.Minute
	})
	out := logs.String()
	if !strings.Contains(out, "restart-only") || !strings.Contains(out, "public") {
		t.Errorf("reload changing public logged no restart-only warning naming it:\n%s", out)
	}
}
