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

// audit: P2-CFG-011
// A Kubernetes ConfigMap volume exposes sbc.yaml as a symlink to
// ..data/sbc.yaml, and ..data as a symlink to a timestamped directory. An
// update writes a new directory and renames a new ..data link over the old
// one: the only event in the watched directory is for "..data", never for
// sbc.yaml itself. The reload must still happen.
func TestWatchFollowsConfigMapSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	writeVersion := func(name, body string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "sbc.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeVersion("..2026_09_25_v1", minimalYAML)
	if err := os.Symlink("..2026_09_25_v1", filepath.Join(dir, "..data")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	path := filepath.Join(dir, "sbc.yaml")
	if err := os.Symlink(filepath.Join("..data", "sbc.yaml"), path); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	// The kubelet's atomic update: new directory, new ..data_tmp link,
	// rename it over ..data, drop the old directory.
	writeVersion("..2026_09_25_v2", strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.99:5060", 1))
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink("..2026_09_25_v2", tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "..2026_09_25_v1")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.99:5060"
	})
}

// audit: P2-CFG-011
// A config path that is a symlink into another directory reloads when the
// target file is edited in place there.
func TestWatchFollowsSymlinkTargetInOtherDir(t *testing.T) {
	linkDir, targetDir := t.TempDir(), t.TempDir()
	target := filepath.Join(targetDir, "real.yaml")
	if err := os.WriteFile(target, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(linkDir, "sbc.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink: %v", err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	updated := strings.Replace(minimalYAML, "10.0.0.10:5060", "10.0.0.99:5060", 1)
	if err := os.WriteFile(target, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Peers["pbx"].Address == "10.0.0.99:5060"
	})
}
