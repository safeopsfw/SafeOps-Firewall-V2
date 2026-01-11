// Package config provides configuration file watching functionality.
package config

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// WatchCallback is called when the config file changes
type WatchCallback func(cfg *Config, err error)

// Watcher watches a configuration file for changes
type Watcher struct {
	path        string
	callback    WatchCallback
	interval    time.Duration
	lastModTime time.Time
	lastSize    int64
	debounce    time.Duration

	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
}

// WatcherOption configures the watcher
type WatcherOption func(*Watcher)

// WithInterval sets the polling interval
func WithInterval(d time.Duration) WatcherOption {
	return func(w *Watcher) {
		w.interval = d
	}
}

// WithDebounce sets the debounce duration
func WithDebounce(d time.Duration) WatcherOption {
	return func(w *Watcher) {
		w.debounce = d
	}
}

// NewWatcher creates a new configuration watcher
func NewWatcher(path string, callback WatchCallback, opts ...WatcherOption) *Watcher {
	w := &Watcher{
		path:     path,
		callback: callback,
		interval: 5 * time.Second,
		debounce: 500 * time.Millisecond,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// Start starts watching the configuration file
func (w *Watcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return nil
	}

	// Get initial file info
	info, err := os.Stat(w.path)
	if err != nil {
		return err
	}

	w.lastModTime = info.ModTime()
	w.lastSize = info.Size()

	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.running = true

	go w.watch()

	return nil
}

// Stop stops watching
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return
	}

	w.cancel()
	w.running = false
}

// IsRunning returns whether the watcher is running
func (w *Watcher) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

// watch is the main watch loop
func (w *Watcher) watch() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	var debounceTimer *time.Timer
	var pendingReload bool

	for {
		select {
		case <-w.ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case <-ticker.C:
			if w.hasChanged() {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				pendingReload = true
				debounceTimer = time.AfterFunc(w.debounce, func() {
					w.mu.Lock()
					if pendingReload {
						pendingReload = false
						w.mu.Unlock()
						w.reload()
					} else {
						w.mu.Unlock()
					}
				})
			}
		}
	}
}

// hasChanged checks if the file has changed
func (w *Watcher) hasChanged() bool {
	info, err := os.Stat(w.path)
	if err != nil {
		return false
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if info.ModTime() != w.lastModTime || info.Size() != w.lastSize {
		w.lastModTime = info.ModTime()
		w.lastSize = info.Size()
		return true
	}

	return false
}

// reload reloads the configuration
func (w *Watcher) reload() {
	cfg, err := Load(w.path)
	w.callback(cfg, err)
}

// Watch creates a watcher and starts it
func Watch(path string, callback WatchCallback, opts ...WatcherOption) (*Watcher, error) {
	w := NewWatcher(path, callback, opts...)
	if err := w.Start(); err != nil {
		return nil, err
	}
	return w, nil
}

// WatchWithReload watches config and updates the provided config pointer
func WatchWithReload(cfg *Config, onChange func(*Config)) (*Watcher, error) {
	if cfg.filePath == "" {
		return nil, fmt.Errorf("config has no file path")
	}

	return Watch(cfg.filePath, func(newCfg *Config, err error) {
		if err != nil {
			return
		}

		cfg.mu.Lock()
		// Copy fields
		cfg.App = newCfg.App
		cfg.Logging = newCfg.Logging
		cfg.Server = newCfg.Server
		cfg.Database = newCfg.Database
		cfg.Redis = newCfg.Redis
		cfg.GRPC = newCfg.GRPC
		cfg.Metrics = newCfg.Metrics
		cfg.Custom = newCfg.Custom
		cfg.mu.Unlock()

		if onChange != nil {
			onChange(cfg)
		}
	})
}

// MultiWatcher watches multiple configuration files
type MultiWatcher struct {
	watchers []*Watcher
	mu       sync.Mutex
}

// NewMultiWatcher creates a new multi-file watcher
func NewMultiWatcher() *MultiWatcher {
	return &MultiWatcher{
		watchers: make([]*Watcher, 0),
	}
}

// Add adds a file to watch
func (m *MultiWatcher) Add(path string, callback WatchCallback, opts ...WatcherOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	watcher := NewWatcher(path, callback, opts...)
	if err := watcher.Start(); err != nil {
		return err
	}

	m.watchers = append(m.watchers, watcher)
	return nil
}

// Stop stops all watchers
func (m *MultiWatcher) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, w := range m.watchers {
		w.Stop()
	}
}

// ConfigReloader provides hot-reload functionality with validation
type ConfigReloader struct {
	watcher   *Watcher
	validator func(*Config) error
	onReload  func(*Config)
	onError   func(error)
	current   *Config
	mu        sync.RWMutex
}

// ReloaderOption configures the reloader
type ReloaderOption func(*ConfigReloader)

// WithValidator sets a custom validator
func WithValidator(v func(*Config) error) ReloaderOption {
	return func(r *ConfigReloader) {
		r.validator = v
	}
}

// WithOnReload sets the reload callback
func WithOnReload(f func(*Config)) ReloaderOption {
	return func(r *ConfigReloader) {
		r.onReload = f
	}
}

// WithOnError sets the error callback
func WithOnError(f func(error)) ReloaderOption {
	return func(r *ConfigReloader) {
		r.onError = f
	}
}

// NewConfigReloader creates a new config reloader
func NewConfigReloader(cfg *Config, opts ...ReloaderOption) (*ConfigReloader, error) {
	r := &ConfigReloader{
		current:   cfg,
		validator: Validate,
	}

	for _, opt := range opts {
		opt(r)
	}

	watcher, err := Watch(cfg.filePath, r.handleChange)
	if err != nil {
		return nil, err
	}

	r.watcher = watcher
	return r, nil
}

// handleChange handles config file changes
func (r *ConfigReloader) handleChange(cfg *Config, err error) {
	if err != nil {
		if r.onError != nil {
			r.onError(err)
		}
		return
	}

	// Validate new config
	if r.validator != nil {
		if err := r.validator(cfg); err != nil {
			if r.onError != nil {
				r.onError(err)
			}
			return
		}
	}

	// Update current config
	r.mu.Lock()
	r.current = cfg
	r.mu.Unlock()

	// Notify
	if r.onReload != nil {
		r.onReload(cfg)
	}
}

// Get returns the current config
func (r *ConfigReloader) Get() *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// Stop stops the reloader
func (r *ConfigReloader) Stop() {
	r.watcher.Stop()
}
