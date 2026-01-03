// ============================================================================
// SafeOps Captive Portal - HTTP/HTTPS Server
// ============================================================================
// File: D:\SafeOpsFV2\src\captive_portal\internal\server\http_server.go
// Purpose: HTTP/HTTPS server setup and lifecycle management
//
// Features:
//   - HTTPS server on port 8444 (self-signed cert)
//   - Optional HTTP redirect server on port 8080
//   - Graceful shutdown support
//   - Request logging middleware
//   - CORS support
//   - Rate limiting
//
// Author: SafeOps Phase 3A
// Date: 2026-01-03
// ============================================================================

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"captive_portal/internal/config"
	"captive_portal/internal/database"
	"captive_portal/internal/stepca"
)

// ============================================================================
// Server Structure
// ============================================================================

// Server represents the Captive Portal HTTP server
type Server struct {
	config       *config.Config
	httpsServer  *http.Server
	httpServer   *http.Server
	handlers     *Handlers
	dhcpClient   *database.DHCPClient
	stepcaClient *stepca.StepCAClient
	shutdownChan chan os.Signal
	wg           sync.WaitGroup
}

// ============================================================================
// Server Creation
// ============================================================================

// NewServer creates a new Captive Portal server
func NewServer(cfg *config.Config) (*Server, error) {
	s := &Server{
		config:       cfg,
		shutdownChan: make(chan os.Signal, 1),
	}

	// Initialize Step-CA client
	stepcaConfig := stepca.StepCAClientConfig{
		BaseURL:       cfg.Integrations.StepCA.APIURL,
		VerifySSL:     cfg.Integrations.StepCA.VerifySSL,
		Timeout:       cfg.Integrations.StepCA.Timeout,
		CacheTTL:      5 * time.Minute,
		RetryAttempts: 3,
		RetryDelay:    1 * time.Second,
	}
	s.stepcaClient = stepca.NewStepCAClient(stepcaConfig)

	// Initialize DHCP Monitor client (optional - may fail if not running)
	dhcpConfig := database.DHCPClientConfig{
		GRPCAddress:   cfg.Integrations.DHCPMonitor.GRPCAddress,
		Timeout:       cfg.Integrations.DHCPMonitor.Timeout,
		RetryAttempts: cfg.Integrations.DHCPMonitor.RetryAttempts,
		RetryDelay:    cfg.Integrations.DHCPMonitor.RetryDelay,
	}
	dhcpClient, err := database.NewDHCPClient(dhcpConfig)
	if err != nil {
		log.Printf("[Server] Warning: DHCP Monitor not available: %v", err)
		// Continue without DHCP client - trust verification will be limited
	} else {
		s.dhcpClient = dhcpClient
	}

	// Create handlers
	handlers, err := NewHandlers(cfg, s.dhcpClient, s.stepcaClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create handlers: %w", err)
	}
	s.handlers = handlers

	return s, nil
}

// ============================================================================
// Router Setup
// ============================================================================

// setupRouter creates the HTTP router with all routes
func (s *Server) setupRouter() http.Handler {
	mux := http.NewServeMux()

	// Page routes
	mux.HandleFunc("/", s.handlers.HandleWelcome)
	mux.HandleFunc("/success", s.handlers.HandleSuccess)
	mux.HandleFunc("/error", s.handlers.HandleError)

	// API routes
	mux.HandleFunc("/api/download-ca/", s.handlers.HandleDownloadCA)
	mux.HandleFunc("/api/verify-trust", s.handlers.HandleVerifyTrust)
	mux.HandleFunc("/api/mark-trusted", s.handlers.HandleMarkTrusted)

	// Health check
	mux.HandleFunc("/health", s.handlers.HandleHealth)

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/",
		http.FileServer(http.Dir(s.config.Templates.Path+"/../static"))))

	// Wrap with middleware
	handler := s.loggingMiddleware(mux)
	handler = s.corsMiddleware(handler)

	return handler
}

// ============================================================================
// Middleware
// ============================================================================

// loggingMiddleware logs all HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(rw, r)

		// Log request
		duration := time.Since(start)
		log.Printf("[HTTP] %s %s %d %v %s",
			r.Method,
			r.URL.Path,
			rw.statusCode,
			duration,
			r.RemoteAddr,
		)
	})
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.Security.CORSEnabled {
			// Set CORS headers
			origin := r.Header.Get("Origin")
			for _, allowed := range s.config.Security.CORSOrigins {
				if origin == allowed {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// ============================================================================
// Server Lifecycle
// ============================================================================

// Start starts the HTTP and HTTPS servers
func (s *Server) Start() error {
	router := s.setupRouter()

	// Start HTTPS server
	if s.config.Server.HTTPSEnabled {
		s.wg.Add(1)
		go s.startHTTPS(router)
	}

	// Start HTTP redirect server (optional)
	if s.config.Server.HTTPRedirectToHTTPS {
		s.wg.Add(1)
		go s.startHTTPRedirect()
	}

	// Setup graceful shutdown
	signal.Notify(s.shutdownChan, os.Interrupt, syscall.SIGTERM)

	log.Printf("[Server] Captive Portal started")
	log.Printf("[Server] HTTPS: https://localhost:%d", s.config.Server.HTTPSPort)
	if s.config.Server.HTTPRedirectToHTTPS {
		log.Printf("[Server] HTTP Redirect: http://localhost:%d -> HTTPS", s.config.Server.HTTPPort)
	}

	return nil
}

// startHTTPS starts the HTTPS server
func (s *Server) startHTTPS(handler http.Handler) {
	defer s.wg.Done()

	addr := fmt.Sprintf(":%d", s.config.Server.HTTPSPort)

	// TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	s.httpsServer = &http.Server{
		Addr:         addr,
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
		IdleTimeout:  s.config.Server.IdleTimeout,
	}

	log.Printf("[Server] Starting HTTPS server on %s", addr)

	err := s.httpsServer.ListenAndServeTLS(
		s.config.Server.CertFile,
		s.config.Server.KeyFile,
	)
	if err != nil && err != http.ErrServerClosed {
		log.Printf("[Server] HTTPS server error: %v", err)
	}
}

// startHTTPRedirect starts the HTTP redirect server
func (s *Server) startHTTPRedirect() {
	defer s.wg.Done()

	addr := fmt.Sprintf(":%d", s.config.Server.HTTPPort)

	// Redirect handler
	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := fmt.Sprintf("https://%s:%d%s",
			r.Host,
			s.config.Server.HTTPSPort,
			r.URL.RequestURI(),
		)
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      redirectHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("[Server] Starting HTTP redirect server on %s", addr)

	err := s.httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Printf("[Server] HTTP redirect server error: %v", err)
	}
}

// Wait waits for shutdown signal and performs graceful shutdown
func (s *Server) Wait() error {
	<-s.shutdownChan

	log.Printf("[Server] Shutdown signal received, shutting down gracefully...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTPS server
	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			log.Printf("[Server] HTTPS shutdown error: %v", err)
		}
	}

	// Shutdown HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("[Server] HTTP shutdown error: %v", err)
		}
	}

	// Close clients
	if s.dhcpClient != nil {
		s.dhcpClient.Close()
	}
	if s.stepcaClient != nil {
		s.stepcaClient.Close()
	}

	// Wait for all goroutines
	s.wg.Wait()

	log.Printf("[Server] Graceful shutdown complete")
	return nil
}

// Stop triggers a graceful shutdown
func (s *Server) Stop() {
	s.shutdownChan <- syscall.SIGTERM
}
