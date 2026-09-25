package config

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// reloadDebounce coalesces editor write bursts into one reload.
const reloadDebounce = 200 * time.Millisecond

// Watch monitors the config file and hot-swaps validated configs into store.
// It watches the parent directory (not the file) so atomic-rename saves keep
// working. When the path is a symlink it also follows the link: a swap of
// any link on the way to the file (a Kubernetes ConfigMap renames a new
// "..data" link into place and never touches the visible file) and an
// in-place edit of the target in another directory both reload. An invalid
// config is logged and the previous one stays active — the process never
// dies from a bad reload. Blocks until ctx is cancelled.
func Watch(ctx context.Context, path string, store *Store, log *slog.Logger) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	if err := w.Add(filepath.Dir(abs)); err != nil {
		return err
	}
	links := newLinkTracker(abs, w, log)

	fire := make(chan struct{}, 1)
	var timer *time.Timer
	schedule := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(reloadDebounce, func() {
			select {
			case fire <- struct{}{}:
			default:
			}
		})
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 && links.affects(ev.Name) {
				schedule()
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			log.Error("config watcher error", "err", err)
		case <-fire:
			cfg, err := loadNoPanic(abs)
			if err != nil {
				log.Error("config reload failed, keeping previous config", "err", err)
				continue
			}
			store.Replace(cfg)
			log.Info("config reloaded", "path", abs)
		}
	}
}

// linkTracker decides whether a directory event can have changed the config
// file's content. It remembers where the path currently resolves to, so a
// symlink swap anywhere on the way is noticed by the change of target, and
// it watches the target's directory when that is not the path's own.
type linkTracker struct {
	abs    string // the configured path, absolute
	dir    string // its directory, symlinks resolved
	target string // what abs resolves to now; "" when it does not resolve
	w      *fsnotify.Watcher
	log    *slog.Logger
}

func newLinkTracker(abs string, w *fsnotify.Watcher, log *slog.Logger) *linkTracker {
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		dir = filepath.Dir(abs)
	}
	t := &linkTracker{abs: abs, dir: dir, w: w, log: log}
	t.follow()
	return t
}

// follow re-resolves the path and watches the target's directory. It
// reports whether the target changed.
func (t *linkTracker) follow() bool {
	target, err := filepath.EvalSymlinks(t.abs)
	if err != nil {
		target = "" // mid-swap or removed; the next event retries
	}
	if target == t.target {
		return false
	}
	t.target = target
	if target != "" && filepath.Dir(target) != t.dir {
		// Add is idempotent. A directory left behind by an earlier
		// target stays watched; its events no longer match and are
		// ignored.
		if err := t.w.Add(filepath.Dir(target)); err != nil {
			t.log.Warn("config watcher: cannot watch the symlink target's directory; in-place edits there will not reload",
				"target", target, "err", err)
		}
	}
	return true
}

// affects reports whether an event on name may have changed the config.
func (t *linkTracker) affects(name string) bool {
	if name == t.abs || (t.target != "" && name == t.target) {
		t.follow()
		return true
	}
	// Any other entry: only a change of where the path resolves counts
	// (e.g. a ConfigMap's "..data" link renamed over).
	return t.follow()
}

// loadNoPanic is Load with a last-resort recover. Parse is written never to
// panic, but the reload goroutine is the one place where a panic would kill
// the whole process on an operator's save, so a missed case still leaves the
// previous snapshot in place and is logged as a failed reload.
func loadNoPanic(path string) (cfg *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			cfg, err = nil, fmt.Errorf("config parser panicked (this is a bug): %v", r)
		}
	}()
	return Load(path)
}
