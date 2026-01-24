// Package health provides health monitoring for the firewall engine.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ============================================================================
// HTTP Server Configuration
// ============================================================================

// HTTPConfig configures the health HTTP server.
type HTTPConfig struct {
	// Address is the listen address (e.g., ":8080").
	Address string `json:"address" toml:"address"`

	// ReadTimeout is the HTTP read timeout.
	ReadTimeout time.Duration `json:"read_timeout" toml:"read_timeout"`

	// WriteTimeout is the HTTP write timeout.
	WriteTimeout time.Duration `json:"write_timeout" toml:"write_timeout"`

	// CheckTimeout is the timeout for health checks.
	CheckTimeout time.Duration `json:"check_timeout" toml:"check_timeout"`
}

// DefaultHTTPConfig returns a config with sensible defaults.
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Address:      ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		CheckTimeout: 5 * time.Second,
	}
}

// Validate checks the config for errors.
func (c *HTTPConfig) Validate() error {
	if c.Address == "" {
		return errors.New("address is required")
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 10 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 10 * time.Second
	}
	if c.CheckTimeout <= 0 {
		c.CheckTimeout = 5 * time.Second
	}
	return nil
}

// ============================================================================
// Health HTTP Server
// ============================================================================

// Server is an HTTP server for health endpoints.
type Server struct {
	config     HTTPConfig
	aggregator *Aggregator
	server     *http.Server
	mux        *http.ServeMux

	mu        sync.Mutex
	isRunning bool
	ready     bool
	started   bool
}

// NewServer creates a new health HTTP server.
func NewServer(config HTTPConfig, aggregator *Aggregator) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if aggregator == nil {
		aggregator = DefaultAggregator()
	}

	s := &Server{
		config:     config,
		aggregator: aggregator,
		mux:        http.NewServeMux(),
		ready:      true,
		started:    false,
	}

	// Setup routes
	s.setupRoutes()

	// Create HTTP server
	s.server = &http.Server{
		Addr:         config.Address,
		Handler:      s.mux,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	}

	return s, nil
}

// setupRoutes configures HTTP routes.
func (s *Server) setupRoutes() {
	// Health endpoint - main health check
	s.mux.HandleFunc("/health", s.handleHealth)

	// Ready endpoint - is system ready to serve?
	s.mux.HandleFunc("/ready", s.handleReady)

	// Startup endpoint - has startup completed?
	s.mux.HandleFunc("/startup", s.handleStartup)

	// Alive endpoint - simple ping (always returns 200)
	s.mux.HandleFunc("/alive", s.handleAlive)

	// Status endpoint - detailed status with all components
	s.mux.HandleFunc("/status", s.handleStatus)

	// Root endpoint
	s.mux.HandleFunc("/", s.handleRoot)
}

// ============================================================================
// HTTP Handlers
// ============================================================================

// handleHealth handles the /health endpoint.
// Returns 200 if healthy/degraded, 503 if unhealthy.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.CheckTimeout)
	defer cancel()

	result := s.aggregator.CheckWithOptions(ctx, CheckOptions{
		Timeout:  s.config.CheckTimeout,
		Parallel: true,
	})

	s.writeJSONResponse(w, result)
}

// handleReady handles the /ready endpoint.
// Returns 200 if ready to serve, 503 if not ready.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	ready := s.ready
	s.mu.Unlock()

	if !ready {
		s.writeSimpleResponse(w, http.StatusServiceUnavailable, "NOT READY", "System not ready")
		return
	}

	// Also check health
	ctx, cancel := context.WithTimeout(r.Context(), s.config.CheckTimeout)
	defer cancel()

	result := s.aggregator.CheckWithOptions(ctx, CheckOptions{
		Timeout:  s.config.CheckTimeout,
		Parallel: true,
	})

	if !result.IsOK() {
		s.writeSimpleResponse(w, http.StatusServiceUnavailable, "NOT READY", "Health check failed")
		return
	}

	s.writeSimpleResponse(w, http.StatusOK, "READY", "System ready to serve")
}

// handleStartup handles the /startup endpoint.
// Returns 200 if startup complete, 503 if still starting.
func (s *Server) handleStartup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	started := s.started
	s.mu.Unlock()

	if !started {
		s.writeSimpleResponse(w, http.StatusServiceUnavailable, "STARTING", "System still starting up")
		return
	}

	s.writeSimpleResponse(w, http.StatusOK, "STARTED", "Startup complete")
}

// handleAlive handles the /alive endpoint.
// Always returns 200 if the server is responding.
func (s *Server) handleAlive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.writeSimpleResponse(w, http.StatusOK, "ALIVE", "Server is alive")
}

// handleStatus handles the /status endpoint.
// Returns detailed status with all component information.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.CheckTimeout)
	defer cancel()

	result := s.aggregator.CheckWithOptions(ctx, CheckOptions{
		Timeout:        s.config.CheckTimeout,
		Parallel:       true,
		IncludeDetails: true,
	})

	// Always return 200 for status (informational)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// handleRoot handles the root endpoint.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>SafeOps Firewall Health</title></head>
<body>
<h1>SafeOps Firewall Health</h1>
<ul>
<li><a href="/health">Health</a> - Overall health check</li>
<li><a href="/ready">Ready</a> - Readiness check</li>
<li><a href="/startup">Startup</a> - Startup status</li>
<li><a href="/alive">Alive</a> - Simple ping</li>
<li><a href="/status">Status</a> - Detailed status</li>
</ul>
</body>
</html>`)
}

// ============================================================================
// Response Helpers
// ============================================================================

// writeJSONResponse writes an aggregated result as JSON.
func (s *Server) writeJSONResponse(w http.ResponseWriter, result AggregatedResult) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.HTTPStatusCode())
	json.NewEncoder(w).Encode(result)
}

// simpleResponse is a simple status response.
type simpleResponse struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// writeSimpleResponse writes a simple status response.
func (s *Server) writeSimpleResponse(w http.ResponseWriter, statusCode int, status, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(simpleResponse{
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
	})
}

// ============================================================================
// Lifecycle
// ============================================================================

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.isRunning = true
	s.mu.Unlock()

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return s.Stop()
	case err := <-errCh:
		return err
	}
}

// StartAsync starts the server without blocking.
func (s *Server) StartAsync() error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.isRunning = true
	s.mu.Unlock()

	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Log error but don't crash
		}
	}()

	return nil
}

// Stop stops the HTTP server gracefully.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.isRunning {
		s.mu.Unlock()
		return nil
	}
	s.isRunning = false
	s.mu.Unlock()

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	return nil
}

// SetReady sets the readiness status.
func (s *Server) SetReady(ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = ready
}

// SetStarted marks startup as complete.
func (s *Server) SetStarted(started bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = started
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isRunning
}

// GetAddress returns the listen address.
func (s *Server) GetAddress() string {
	return s.config.Address
}

// ============================================================================
// Quick Start Functions
// ============================================================================

// StartHealthServer starts a health server with default config.
func StartHealthServer(aggregator *Aggregator) (*Server, error) {
	config := DefaultHTTPConfig()
	server, err := NewServer(config, aggregator)
	if err != nil {
		return nil, err
	}

	if err := server.StartAsync(); err != nil {
		return nil, err
	}

	server.SetStarted(true)
	return server, nil
}

// StartHealthServerOnPort starts a health server on a specific port.
func StartHealthServerOnPort(aggregator *Aggregator, port int) (*Server, error) {
	config := DefaultHTTPConfig()
	config.Address = fmt.Sprintf(":%d", port)

	server, err := NewServer(config, aggregator)
	if err != nil {
		return nil, err
	}

	if err := server.StartAsync(); err != nil {
		return nil, err
	}

	server.SetStarted(true)
	return server, nil
}
