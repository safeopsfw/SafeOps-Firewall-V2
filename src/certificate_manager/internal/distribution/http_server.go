package distribution

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ============================================================================
// Server Configuration
// ============================================================================

// HTTPServerConfig contains configuration for the HTTP distribution server.
type HTTPServerConfig struct {
	ListenAddress   string        // Network address to listen on (e.g., "192.168.1.1:80")
	ReadTimeout     time.Duration // Maximum duration for reading entire request
	WriteTimeout    time.Duration // Maximum duration for writing entire response
	IdleTimeout     time.Duration // Maximum time to wait for next request on keep-alive
	MaxHeaderBytes  int           // Maximum size of request headers
	ShutdownTimeout time.Duration // Maximum time to wait for graceful shutdown
	EnableAccessLog bool          // Enable HTTP access logging
	EnableMetrics   bool          // Enable Prometheus metrics
	CACertPath      string        // Path to CA certificate PEM file
	BaseURL         string        // Base URL for scripts/profiles (e.g., "http://192.168.1.1")
	Organization    string        // Organization name
	CACommonName    string        // CA common name
	SupportEmail    string        // Support email (optional)
}

// DefaultHTTPServerConfig returns default configuration.
func DefaultHTTPServerConfig() *HTTPServerConfig {
	return &HTTPServerConfig{
		ListenAddress:   ":80",
		ReadTimeout:     15 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     60 * time.Second,
		MaxHeaderBytes:  1 << 20, // 1 MB
		ShutdownTimeout: 30 * time.Second,
		EnableAccessLog: true,
		EnableMetrics:   true,
		CACertPath:      "/etc/safeops/ca/root-cert.pem",
		BaseURL:         "http://192.168.1.1",
		Organization:    "SafeOps",
		CACommonName:    "SafeOps Root CA",
	}
}

// ============================================================================
// HTTP Server
// ============================================================================

// HTTPServer represents the CA certificate distribution HTTP server.
type HTTPServer struct {
	config   *HTTPServerConfig
	server   *http.Server
	handlers *Handlers
	mux      *http.ServeMux

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewHTTPServer creates a new HTTP distribution server.
func NewHTTPServer(config *HTTPServerConfig) (*HTTPServer, error) {
	if config == nil {
		config = DefaultHTTPServerConfig()
	}

	// Create handlers configuration
	handlersConfig := &HandlersConfig{
		CACertPath:     config.CACertPath,
		BaseURL:        config.BaseURL,
		CacheMaxAge:    24 * time.Hour,
		Organization:   config.Organization,
		CACommonName:   config.CACommonName,
		SupportEmail:   config.SupportEmail,
		EnableTracking: true,
	}

	// Create handlers
	handlers := NewHandlers(handlersConfig)

	// Create mux
	mux := http.NewServeMux()

	// Register routes
	handlers.RegisterRoutes(mux)

	// Create server
	s := &HTTPServer{
		config:   config,
		handlers: handlers,
		mux:      mux,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}

	// Create HTTP server with middleware
	var handler http.Handler = mux
	if config.EnableAccessLog {
		handler = s.accessLogMiddleware(handler)
	}
	handler = s.recoveryMiddleware(handler)
	handler = s.securityHeadersMiddleware(handler)

	s.server = &http.Server{
		Addr:           config.ListenAddress,
		Handler:        handler,
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		IdleTimeout:    config.IdleTimeout,
		MaxHeaderBytes: config.MaxHeaderBytes,
	}

	return s, nil
}

// ============================================================================
// Server Lifecycle
// ============================================================================

// Start starts the HTTP server.
func (s *HTTPServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Validate CA certificate exists
	if _, err := os.Stat(s.config.CACertPath); err != nil {
		if os.IsNotExist(err) {
			log.Printf("[WARN] CA certificate not found at %s, server will start but certificates won't be served", s.config.CACertPath)
		}
	}

	// Start server in goroutine
	go func() {
		defer close(s.doneCh)

		log.Printf("[INFO] HTTP distribution server starting on %s", s.config.ListenAddress)
		log.Printf("[INFO] Base URL: %s", s.config.BaseURL)
		log.Printf("[INFO] Organization: %s", s.config.Organization)

		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] HTTP server error: %v", err)
		}

		log.Printf("[INFO] HTTP distribution server stopped")
	}()

	return nil
}

// StartAndBlock starts the server and blocks until shutdown.
func (s *HTTPServer) StartAndBlock() error {
	if err := s.Start(); err != nil {
		return err
	}
	<-s.doneCh
	return nil
}

// Stop gracefully stops the HTTP server.
func (s *HTTPServer) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return errors.New("server not running")
	}
	s.running = false
	s.mu.Unlock()

	log.Printf("[INFO] Initiating graceful shutdown...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
	defer cancel()

	// Stop handlers (flushes download tracker)
	s.handlers.Stop()

	// Shutdown server
	if err := s.server.Shutdown(ctx); err != nil {
		log.Printf("[ERROR] Shutdown error: %v", err)
		return err
	}

	log.Printf("[INFO] Graceful shutdown complete")
	return nil
}

// IsRunning returns whether the server is running.
func (s *HTTPServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// ============================================================================
// Signal Handling
// ============================================================================

// WaitForShutdown blocks until a shutdown signal is received.
func (s *HTTPServer) WaitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("[INFO] Received signal: %v", sig)
		s.Stop()
	case <-s.stopCh:
		// Manual stop requested
	}
}

// RunWithSignalHandler starts the server and handles shutdown signals.
func (s *HTTPServer) RunWithSignalHandler() error {
	if err := s.Start(); err != nil {
		return err
	}

	s.WaitForShutdown()
	return nil
}

// ============================================================================
// Middleware
// ============================================================================

// accessLogMiddleware logs all HTTP requests.
func (s *HTTPServer) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Handle request
		next.ServeHTTP(wrapped, r)

		// Log request
		duration := time.Since(start)
		log.Printf("[HTTP] %s | %s | %s %s | %d | %v | %d bytes",
			time.Now().Format("2006-01-02 15:04:05"),
			getClientIP(r),
			r.Method,
			r.URL.Path,
			wrapped.statusCode,
			duration,
			wrapped.bytesWritten,
		)
	})
}

// recoveryMiddleware catches panics and returns HTTP 500.
func (s *HTTPServer) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[ERROR] Panic recovered: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds security headers to all responses.
func (s *HTTPServer) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Server", "SafeOps-CA/1.0")
		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code and bytes.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Parse RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ============================================================================
// Server Information
// ============================================================================

// ServerInfo contains server runtime information.
type ServerInfo struct {
	Address      string    `json:"address"`
	BaseURL      string    `json:"base_url"`
	Organization string    `json:"organization"`
	CACommonName string    `json:"ca_common_name"`
	Running      bool      `json:"running"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	Fingerprint  string    `json:"fingerprint,omitempty"`
}

// GetInfo returns server runtime information.
func (s *HTTPServer) GetInfo() ServerInfo {
	return ServerInfo{
		Address:      s.config.ListenAddress,
		BaseURL:      s.config.BaseURL,
		Organization: s.config.Organization,
		CACommonName: s.config.CACommonName,
		Running:      s.IsRunning(),
		Fingerprint:  s.handlers.GetFingerprint(),
	}
}

// GetHandlers returns the handlers instance.
func (s *HTTPServer) GetHandlers() *Handlers {
	return s.handlers
}

// GetTracker returns the download tracker.
func (s *HTTPServer) GetTracker() *DownloadTracker {
	return s.handlers.GetTracker()
}

// ============================================================================
// Static File Serving (Optional)
// ============================================================================

// AddStaticFileHandler adds a handler for serving static files.
func (s *HTTPServer) AddStaticFileHandler(urlPath string, fsPath string) error {
	if _, err := os.Stat(fsPath); os.IsNotExist(err) {
		return fmt.Errorf("static files path does not exist: %s", fsPath)
	}

	fs := http.FileServer(http.Dir(fsPath))
	s.mux.Handle(urlPath, http.StripPrefix(urlPath, fs))

	log.Printf("[INFO] Added static file handler: %s -> %s", urlPath, fsPath)
	return nil
}

// ============================================================================
// Custom Handler Registration
// ============================================================================

// HandleFunc registers a custom handler function.
func (s *HTTPServer) HandleFunc(pattern string, handler http.HandlerFunc) {
	s.mux.HandleFunc(pattern, handler)
}

// Handle registers a custom handler.
func (s *HTTPServer) Handle(pattern string, handler http.Handler) {
	s.mux.Handle(pattern, handler)
}

// ============================================================================
// Configuration Helpers
// ============================================================================

// SetBaseURL updates the base URL configuration.
func (s *HTTPServer) SetBaseURL(baseURL string) {
	s.config.BaseURL = baseURL
}

// ReloadCertificate reloads the CA certificate from disk.
func (s *HTTPServer) ReloadCertificate() error {
	return s.handlers.ReloadCertificate()
}

// ============================================================================
// Convenience Functions
// ============================================================================

// ListenAndServe is a convenience function that creates and starts a server.
func ListenAndServe(address string, caCertPath string, baseURL string) error {
	config := DefaultHTTPServerConfig()
	config.ListenAddress = address
	config.CACertPath = caCertPath
	config.BaseURL = baseURL

	server, err := NewHTTPServer(config)
	if err != nil {
		return err
	}

	return server.RunWithSignalHandler()
}

// NewDefaultServer creates a server with default configuration.
func NewDefaultServer() (*HTTPServer, error) {
	return NewHTTPServer(DefaultHTTPServerConfig())
}

// ============================================================================
// Health and Status
// ============================================================================

// HealthStatus represents the server health status.
type HealthStatus struct {
	Healthy       bool      `json:"healthy"`
	CAAvailable   bool      `json:"ca_available"`
	Uptime        string    `json:"uptime"`
	TotalRequests int64     `json:"total_requests"`
	UniqueDevices int       `json:"unique_devices"`
	LastRequest   time.Time `json:"last_request,omitempty"`
}

// GetHealthStatus returns the current health status.
func (s *HTTPServer) GetHealthStatus() HealthStatus {
	status := HealthStatus{
		Healthy:     s.IsRunning(),
		CAAvailable: s.handlers.GetFingerprint() != "",
	}

	if tracker := s.GetTracker(); tracker != nil {
		metrics := tracker.GetMetrics()
		status.TotalRequests = metrics.TotalDownloads
		status.UniqueDevices = metrics.UniqueIPs
		status.LastRequest = metrics.LastDownload
	}

	return status
}
