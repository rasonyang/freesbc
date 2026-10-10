package config

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
	path := filepath.Join(t.TempDir(), "freesbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	updated := minimalYAML + "shield: { ban: 99m }\n"
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Shield.Ban.Std() == 99*time.Minute
	})
}

func TestWatchKeepsOldConfigOnBadReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freesbc.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	if err := os.WriteFile(path, []byte("public: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	// Give the watcher time to (wrongly) swap; then assert it did not.
	time.Sleep(600 * time.Millisecond)
	if store.Current() != initial {
		t.Fatal("bad config must not replace the running config")
	}

	// And a subsequent good write still lands.
	updated := minimalYAML + "shield: { ban: 42m }\n"
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Shield.Ban.Std() == 42*time.Minute
	})
}

func TestWatchSurvivesAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "freesbc.yaml")
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
	tmp := filepath.Join(dir, ".freesbc.yaml.tmp")
	updated := minimalYAML + "shield: { ban: 77m }\n"
	if err := os.WriteFile(tmp, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Shield.Ban.Std() == 77*time.Minute
	})
}

// audit: P2-CFG-011
// A Kubernetes ConfigMap volume exposes freesbc.yaml as a symlink to
// ..data/freesbc.yaml, and ..data as a symlink to a timestamped directory. An
// update writes a new directory and renames a new ..data link over the old
// one: the only event in the watched directory is for "..data", never for
// freesbc.yaml itself. The reload must still happen.
func TestWatchFollowsConfigMapSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	writeVersion := func(name, body string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "freesbc.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeVersion("..2026_09_25_v1", minimalYAML)
	if err := os.Symlink("..2026_09_25_v1", filepath.Join(dir, "..data")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	path := filepath.Join(dir, "freesbc.yaml")
	if err := os.Symlink(filepath.Join("..data", "freesbc.yaml"), path); err != nil {
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
	writeVersion("..2026_09_25_v2", minimalYAML+"shield: { ban: 99m }\n")
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
		return store.Current().Shield.Ban.Std() == 99*time.Minute
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
	path := filepath.Join(linkDir, "freesbc.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink: %v", err)
	}
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	updated := minimalYAML + "shield: { ban: 99m }\n"
	if err := os.WriteFile(target, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		return store.Current().Shield.Ban.Std() == 99*time.Minute
	})
}

func TestWatchRecordsReloadStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freesbc.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(minimalYAML)
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial)
	startWatch(t, path, store)

	st := store.ReloadStatus()
	if !st.LastOK.IsZero() || st.LastError != "" || st.RestartRequired == nil || len(st.RestartRequired) != 0 {
		t.Fatalf("initial status = %+v, want zero times and an empty non-nil list", st)
	}

	// A restart-only edit is published and named.
	write(minimalYAML + "rtp: 30000-30099\n")
	waitFor(t, 3*time.Second, func() bool { return !store.ReloadStatus().LastOK.IsZero() })
	st = store.ReloadStatus()
	if len(st.RestartRequired) != 1 || st.RestartRequired[0] != "rtp" {
		t.Fatalf("restart_required = %v, want [rtp]", st.RestartRequired)
	}
	firstOK := st.LastOK

	// A bad file records the error, keeps the snapshot and the list.
	published := store.Current()
	write("public: [")
	waitFor(t, 3*time.Second, func() bool { return store.ReloadStatus().LastError != "" })
	st = store.ReloadStatus()
	if st.LastErrorAt.IsZero() || !st.LastOK.Equal(firstOK) {
		t.Fatalf("failed status = %+v, want LastErrorAt set and LastOK unchanged", st)
	}
	if len(st.RestartRequired) != 1 || st.RestartRequired[0] != "rtp" {
		t.Fatalf("restart_required after failure = %v, want [rtp]", st.RestartRequired)
	}
	if store.Current() != published {
		t.Fatal("failed reload replaced the snapshot")
	}

	// Editing back to the boot values empties the list and clears the error.
	write(minimalYAML)
	waitFor(t, 3*time.Second, func() bool { return store.ReloadStatus().LastError == "" })
	st = store.ReloadStatus()
	if len(st.RestartRequired) != 0 || st.LastErrorAt != (time.Time{}) || !st.LastOK.After(firstOK) {
		t.Fatalf("recovered status = %+v, want empty list, cleared error, newer LastOK", st)
	}

	// The returned slice is a copy.
	st.RestartRequired = append(st.RestartRequired, "x")
	if len(store.ReloadStatus().RestartRequired) != 0 {
		t.Fatal("ReloadStatus leaked its slice")
	}
}
