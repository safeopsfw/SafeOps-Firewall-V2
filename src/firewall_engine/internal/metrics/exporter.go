// Package metrics provides Prometheus metrics collection for the firewall engine.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ============================================================================
// Exporter Configuration
// ============================================================================

// ExporterConfig configures the metrics HTTP exporter.
type ExporterConfig struct {
	// Address is the listen address (e.g., ":9090" or "127.0.0.1:9090").
	Address string `json:"address" toml:"address"`

	// Path is the metrics endpoint path (e.g., "/metrics").
	Path string `json:"path" toml:"path"`

	// ReadTimeout is the HTTP read timeout.
	ReadTimeout time.Duration `json:"read_timeout" toml:"read_timeout"`

	// WriteTimeout is the HTTP write timeout.
	WriteTimeout time.Duration `json:"write_timeout" toml:"write_timeout"`

	// IdleTimeout is the HTTP idle timeout.
	IdleTimeout time.Duration `json:"idle_timeout" toml:"idle_timeout"`

	// EnableHealthEndpoint adds a /health endpoint.
	EnableHealthEndpoint bool `json:"enable_health_endpoint" toml:"enable_health_endpoint"`

	// EnableReadyEndpoint adds a /ready endpoint.
	EnableReadyEndpoint bool `json:"enable_ready_endpoint" toml:"enable_ready_endpoint"`
}

// DefaultExporterConfig returns a config with sensible defaults.
func DefaultExporterConfig() ExporterConfig {
	return ExporterConfig{
		Address:              ":9090",
		Path:                 "/metrics",
		ReadTimeout:          10 * time.Second,
		WriteTimeout:         10 * time.Second,
		IdleTimeout:          60 * time.Second,
		EnableHealthEndpoint: true,
		EnableReadyEndpoint:  true,
	}
}

// Validate checks the config for errors.
func (c *ExporterConfig) Validate() error {
	if c.Address == "" {
		return errors.New("address is required")
	}
	if c.Path == "" {
		c.Path = "/metrics"
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 10 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 10 * time.Second
	}
	return nil
}

// ============================================================================
// Metrics Exporter
// ============================================================================

// Exporter exports metrics via HTTP for Prometheus scraping.
type Exporter struct {
	config   ExporterConfig
	registry *Registry
	server   *http.Server
	mux      *http.ServeMux

	mu        sync.Mutex
	isRunning bool
	ready     bool
}

// NewExporter creates a new metrics exporter.
func NewExporter(config ExporterConfig, registry *Registry) (*Exporter, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if registry == nil {
		registry = DefaultRegistry()
	}

	e := &Exporter{
		config:   config,
		registry: registry,
		mux:      http.NewServeMux(),
		ready:    true,
	}

	// Setup routes
	e.setupRoutes()

	// Create HTTP server
	e.server = &http.Server{
		Addr:         config.Address,
		Handler:      e.mux,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
	}

	return e, nil
}

// setupRoutes configures HTTP routes.
func (e *Exporter) setupRoutes() {
	// Main metrics endpoint
	if e.registry.promRegistry != nil {
		// Use custom registry
		e.mux.Handle(e.config.Path, promhttp.HandlerFor(
			e.registry.promRegistry,
			promhttp.HandlerOpts{
				EnableOpenMetrics: true,
			},
		))
	} else {
		// Use default registry
		e.mux.Handle(e.config.Path, promhttp.Handler())
	}

	// Health endpoint
	if e.config.EnableHealthEndpoint {
		e.mux.HandleFunc("/health", e.handleHealth)
	}

	// Ready endpoint
	if e.config.EnableReadyEndpoint {
		e.mux.HandleFunc("/ready", e.handleReady)
	}

	// Root endpoint (redirect to metrics)
	e.mux.HandleFunc("/", e.handleRoot)
}

// handleHealth handles the /health endpoint.
func (e *Exporter) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

// handleReady handles the /ready endpoint.
func (e *Exporter) handleReady(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	ready := e.ready
	e.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if ready {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "READY")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "NOT READY")
	}
}

// handleRoot handles the root endpoint.
func (e *Exporter) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SafeOps Firewall Metrics</title></head>
<body>
<h1>SafeOps Firewall Metrics</h1>
<p><a href="%s">Metrics</a></p>
<p><a href="/health">Health</a></p>
<p><a href="/ready">Ready</a></p>
</body>
</html>`, e.config.Path)
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start starts the HTTP server.
func (e *Exporter) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.isRunning {
		e.mu.Unlock()
		return errors.New("exporter already running")
	}
	e.isRunning = true
	e.mu.Unlock()

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := e.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return e.Stop()
	case err := <-errCh:
		return err
	}
}

// StartAsync starts the server without blocking.
func (e *Exporter) StartAsync() error {
	e.mu.Lock()
	if e.isRunning {
		e.mu.Unlock()
		return errors.New("exporter already running")
	}
	e.isRunning = true
	e.mu.Unlock()

	go func() {
		if err := e.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Log error but don't crash
			// In production, use structured logging
		}
	}()

	return nil
}

// Stop stops the HTTP server gracefully.
func (e *Exporter) Stop() error {
	e.mu.Lock()
	if !e.isRunning {
		e.mu.Unlock()
		return nil
	}
	e.isRunning = false
	e.mu.Unlock()

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := e.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	return nil
}

// SetReady sets the readiness status.
func (e *Exporter) SetReady(ready bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ready = ready
}

// IsRunning returns true if the exporter is running.
func (e *Exporter) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isRunning
}

// GetAddress returns the listen address.
func (e *Exporter) GetAddress() string {
	return e.config.Address
}

// ============================================================================
// Quick Start Function
// ============================================================================

// StartMetricsServer starts a metrics server with default config.
// Returns the exporter for shutdown.
func StartMetricsServer(registry *Registry) (*Exporter, error) {
	config := DefaultExporterConfig()
	exporter, err := NewExporter(config, registry)
	if err != nil {
		return nil, err
	}

	if err := exporter.StartAsync(); err != nil {
		return nil, err
	}

	return exporter, nil
}

// StartMetricsServerOnPort starts a metrics server on a specific port.
func StartMetricsServerOnPort(registry *Registry, port int) (*Exporter, error) {
	config := DefaultExporterConfig()
	config.Address = fmt.Sprintf(":%d", port)

	exporter, err := NewExporter(config, registry)
	if err != nil {
		return nil, err
	}

	if err := exporter.StartAsync(); err != nil {
		return nil, err
	}

	return exporter, nil
}

// ============================================================================
// Prometheus Gatherer for Custom Registry
// ============================================================================

// GathererFunc returns a gatherer for the registry.
func (r *Registry) GathererFunc() prometheus.Gatherer {
	if r.promRegistry != nil {
		return r.promRegistry
	}
	return prometheus.DefaultGatherer
}
