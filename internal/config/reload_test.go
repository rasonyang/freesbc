package config

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func startWatch(t *testing.T, path string, store *Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	go func() { _ = Watch(ctx, path, store, log) }()
	time.Sleep(100 * time.Millisecond) // let the watcher attach
}

func TestWatchReloadsValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	updated := strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.99:5060", 1)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.99:5060"
	})
}

func TestWatchKeepsOldConfigOnBadReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	if err := os.WriteFile(path, []byte("listen: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	// Give the watcher time to (wrongly) swap; then assert it did not.
	time.Sleep(600 * time.Millisecond)
	if store.Current() != initial {
		t.Fatal("bad config must not replace the running config")
	}

	// And a subsequent good write still lands.
	updated := strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.42:5060", 1)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.42:5060"
	})
}

func TestWatchSurvivesAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	// Editors and `mv` replace the file via rename; the watcher must survive.
	tmp := filepath.Join(dir, ".sbc.yaml.tmp")
	updated := strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.77:5060", 1)
	if err := os.WriteFile(tmp, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.77:5060"
	})
}
