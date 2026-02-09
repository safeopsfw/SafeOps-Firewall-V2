// Package hotreload provides file-system watching and config reload orchestration.
// It uses fsnotify to detect changes to TOML config files and domains.txt,
// then validates and applies the new configuration atomically.
package hotreload

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"firewall_engine/internal/logging"
)

// FileChangeHandler is called when a watched file changes.
// The handler receives the absolute path of the changed file.
type FileChangeHandler func(path string)

// Watcher monitors config files for changes using fsnotify.
// It debounces rapid edits (e.g., editor save-then-rename) so the handler
// fires at most once per debounce window per file.
type Watcher struct {
	fsWatcher *fsnotify.Watcher
	logger    logging.Logger
	handlers  map[string]FileChangeHandler // basename → handler
	mu        sync.RWMutex

	debounce time.Duration
	timers   map[string]*time.Timer // basename → pending debounce timer
	timerMu  sync.Mutex

	reloads atomic.Int64
	errors  atomic.Int64
	running atomic.Bool
}

// NewWatcher creates a file watcher with the given debounce interval.
// Typical debounce: 500ms (editors write temp → rename → delete in <100ms).
func NewWatcher(logger logging.Logger, debounce time.Duration) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Watcher{
		fsWatcher: fsw,
		logger:    logger,
		handlers:  make(map[string]FileChangeHandler),
		debounce:  debounce,
		timers:    make(map[string]*time.Timer),
	}, nil
}

// Watch registers a handler for a specific file path.
// The file's parent directory is watched (fsnotify watches directories, not files).
func (w *Watcher) Watch(filePath string, handler FileChangeHandler) error {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}

	base := filepath.Base(absPath)
	dir := filepath.Dir(absPath)

	w.mu.Lock()
	w.handlers[base] = handler
	w.mu.Unlock()

	// Watch the directory (fsnotify doesn't watch individual files reliably on all OS)
	return w.fsWatcher.Add(dir)
}

// Start begins listening for file changes. Blocks until ctx is cancelled.
func (w *Watcher) Start(ctx context.Context) {
	w.running.Store(true)
	defer w.running.Store(false)

	w.logger.Info().Msg("Hot-reload watcher started")

	for {
		select {
		case <-ctx.Done():
			w.logger.Info().Msg("Hot-reload watcher stopping")
			return

		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			// Only care about writes and creates (editors may create new file + rename)
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}

			base := filepath.Base(event.Name)
			w.mu.RLock()
			handler, exists := w.handlers[base]
			w.mu.RUnlock()

			if !exists {
				continue
			}

			// Debounce: reset timer each time the same file fires
			w.timerMu.Lock()
			if t, ok := w.timers[base]; ok {
				t.Stop()
			}
			absPath, _ := filepath.Abs(event.Name)
			h := handler // capture for closure
			w.timers[base] = time.AfterFunc(w.debounce, func() {
				w.reloads.Add(1)
				w.logger.Info().Str("file", base).Msg("Config file changed, reloading")
				h(absPath)
			})
			w.timerMu.Unlock()

		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			w.errors.Add(1)
			w.logger.Error().Err(err).Msg("File watcher error")
		}
	}
}

// Close stops the underlying fsnotify watcher.
func (w *Watcher) Close() error {
	w.timerMu.Lock()
	for _, t := range w.timers {
		t.Stop()
	}
	w.timerMu.Unlock()
	return w.fsWatcher.Close()
}

// Stats returns watcher statistics.
func (w *Watcher) Stats() WatcherStats {
	w.mu.RLock()
	fileCount := len(w.handlers)
	w.mu.RUnlock()

	return WatcherStats{
		FilesWatched: fileCount,
		TotalReloads: w.reloads.Load(),
		TotalErrors:  w.errors.Load(),
		Running:      w.running.Load(),
	}
}

// WatcherStats holds watcher statistics.
type WatcherStats struct {
	FilesWatched int   `json:"files_watched"`
	TotalReloads int64 `json:"total_reloads"`
	TotalErrors  int64 `json:"total_errors"`
	Running      bool  `json:"running"`
}
