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
// working. An invalid config is logged and the previous one stays active —
// the process never dies from a bad reload. Blocks until ctx is cancelled.
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

	base := filepath.Base(abs)
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
			if filepath.Base(ev.Name) != base {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			schedule()
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
