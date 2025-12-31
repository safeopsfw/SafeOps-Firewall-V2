// Package main is the entry point for the Certificate Manager service.
// This is a Step-CA only version that focuses on CA distribution.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"certificate_manager/config"
	"certificate_manager/internal/stepca"
	"certificate_manager/internal/storage"
	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	ServiceName     = "certificate-manager"
	ServiceVersion  = "2.0.0" // Step-CA only version
	DefaultHTTPPort = 8082    // CA distribution (no admin required)
	ShutdownTimeout = 30 * time.Second
)

// ============================================================================
// Application Structure
// ============================================================================

// Application holds all service components
type Application struct {
	config       *types.Config
	dbStorage    *storage.Database
	fsStorage    *storage.FilesystemStorage
	stepCAClient *stepca.Client
	httpServer   *http.Server

	// Lifecycle
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	shutdownCh chan struct{}
}

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	// Panic recovery
	defer recoverPanic()

	// Create application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create application
	app := &Application{
		ctx:        ctx,
		cancel:     cancel,
		shutdownCh: make(chan struct{}),
	}

	// Initialize and run
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %v\n", err)
		os.Exit(1)
	}
}

// Run executes the application lifecycle
func (app *Application) Run() error {
	// Setup signal handling
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	// Initialize components
	if err := app.initialize(); err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}

	// Start services
	if err := app.start(); err != nil {
		return fmt.Errorf("service startup failed: %w", err)
	}

	logInfo("Certificate Manager (Step-CA Mode) started successfully")
	logInfo("HTTP server listening on port %d", app.getHTTPPort())

	// Wait for shutdown signal
	select {
	case sig := <-signalCh:
		logInfo("Received signal: %v, initiating shutdown", sig)
	case <-app.ctx.Done():
		logInfo("Context cancelled, initiating shutdown")
	}

	// Graceful shutdown
	return app.shutdown()
}

// ============================================================================
// Initialization
// ============================================================================

// initialize sets up all application components
func (app *Application) initialize() error {
	var err error

	// Load configuration
	logInfo("Loading configuration...")
	app.config, err = loadConfiguration()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize storage
	logInfo("Initializing storage...")
	if err := app.initStorage(); err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize step-ca client
	logInfo("Initializing Step-CA client...")
	if err := app.initStepCA(); err != nil {
		logWarn("Step-CA client initialization failed: %v (continuing without Step-CA)", err)
	}

	// Initialize HTTP server
	logInfo("Initializing HTTP server...")
	if err := app.initHTTPServer(); err != nil {
		return fmt.Errorf("failed to initialize HTTP server: %w", err)
	}

	logInfo("Initialization complete")
	return nil
}

// initStorage initializes database and filesystem storage
func (app *Application) initStorage() error {
	var err error

	// Database storage
	app.dbStorage, err = storage.NewDatabase(app.config.Database)
	if err != nil {
		logWarn("Database connection failed: %v (continuing without database)", err)
	}

	// Filesystem storage
	app.fsStorage, err = storage.NewFilesystemStorage(app.config.Storage)
	if err != nil {
		return fmt.Errorf("filesystem storage failed: %w", err)
	}

	return nil
}

// initStepCA initializes the Step-CA client
func (app *Application) initStepCA() error {
	var err error

	// Create Step-CA client
	stepCAConfig := &stepca.ClientConfig{
		BaseURL:    "https://localhost:9000",
		RootCAPath: "D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt",
		Timeout:    30 * time.Second,
	}

	app.stepCAClient, err = stepca.NewClient(stepCAConfig)
	if err != nil {
		return fmt.Errorf("Step-CA client creation failed: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(app.ctx, 5*time.Second)
	defer cancel()

	if err := app.stepCAClient.Health(ctx); err != nil {
		return fmt.Errorf("Step-CA health check failed: %w", err)
	}

	logInfo("Step-CA connected successfully at %s", stepCAConfig.BaseURL)
	return nil
}

// initHTTPServer initializes the HTTP server for health and CA distribution
func (app *Application) initHTTPServer() error {
	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("/health", app.healthHandler)
	mux.HandleFunc("/ready", app.readyHandler)
	mux.HandleFunc("/metrics", app.metricsHandler)
	mux.HandleFunc("/api/stats", app.statsHandler)

	// CA certificate download endpoints
	mux.HandleFunc("/ca/root.crt", app.serveCACertificate)
	mux.HandleFunc("/ca/root.pem", app.serveCACertificate)
	mux.HandleFunc("/download/ca", app.serveCACertificate)

	// CORS middleware
	corsHandler := corsMiddleware(mux)

	app.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", app.getHTTPPort()),
		Handler: corsHandler,
	}

	return nil
}

// corsMiddleware adds CORS headers for frontend access
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// Service Startup
// ============================================================================

// start launches all services
func (app *Application) start() error {
	// Start HTTP server
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		logInfo("HTTP server listening on port %d", app.getHTTPPort())
		if err := app.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logError("HTTP server error: %v", err)
		}
	}()

	return nil
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

// shutdown performs graceful shutdown
func (app *Application) shutdown() error {
	logInfo("Starting graceful shutdown...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()

	app.cancel()

	// Stop HTTP server
	if app.httpServer != nil {
		logInfo("Stopping HTTP server...")
		if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
			logWarn("HTTP shutdown error: %v", err)
		}
	}

	// Close Step-CA client
	if app.stepCAClient != nil {
		logInfo("Closing Step-CA client...")
		if err := app.stepCAClient.Close(); err != nil {
			logWarn("Step-CA client close error: %v", err)
		}
	}

	// Close database connection
	if app.dbStorage != nil {
		logInfo("Closing database connection...")
		if err := app.dbStorage.Close(); err != nil {
			logWarn("Database close error: %v", err)
		}
	}

	// Wait for all goroutines
	done := make(chan struct{})
	go func() {
		app.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logInfo("Graceful shutdown complete")
	case <-shutdownCtx.Done():
		logWarn("Shutdown timeout exceeded, forcing exit")
	}

	return nil
}

// ============================================================================
// HTTP Handlers
// ============================================================================

// healthHandler responds to health probes
func (app *Application) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":    "healthy",
		"service":   ServiceName,
		"version":   ServiceVersion,
		"mode":      "step-ca",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// readyHandler responds to readiness probes
func (app *Application) readyHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

// metricsHandler exposes Prometheus metrics
func (app *Application) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	fmt.Fprintln(w, "# HELP certificate_manager_up Certificate Manager is running")
	fmt.Fprintln(w, "# TYPE certificate_manager_up gauge")
	fmt.Fprintln(w, "certificate_manager_up 1")

	fmt.Fprintln(w, "# HELP certificate_manager_mode Current operation mode")
	fmt.Fprintln(w, "# TYPE certificate_manager_mode gauge")
	fmt.Fprintln(w, "certificate_manager_mode{mode=\"step-ca\"} 1")
}

// statsHandler returns JSON stats for the dashboard
func (app *Application) statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := map[string]interface{}{
		"ca": map[string]interface{}{
			"status":        "active",
			"mode":          "step-ca",
			"organization":  "SafeOps",
			"commonName":    "SafeOps Root CA (Step-CA)",
			"validityYears": 10,
		},
		"stepCA": map[string]interface{}{
			"connected": app.stepCAClient != nil,
			"url":       "https://localhost:9000",
		},
	}

	json.NewEncoder(w).Encode(stats)
}

// serveCACertificate serves the Step-CA root certificate
func (app *Application) serveCACertificate(w http.ResponseWriter, r *http.Request) {
	caCertPath := "D:/SafeOpsFV2/certs/step-ca/ca/certs/root_ca.crt"

	// Check if file exists
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		http.Error(w, "CA certificate not found", http.StatusNotFound)
		return
	}

	// Serve the file
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=\"safeops-root-ca.crt\"")
	http.ServeFile(w, r, caCertPath)
}

// ============================================================================
// Helpers
// ============================================================================

func (app *Application) getHTTPPort() int {
	return DefaultHTTPPort
}

func (app *Application) getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func loadConfiguration() (*types.Config, error) {
	return config.Load("")
}

func recoverPanic() {
	if r := recover(); r != nil {
		fmt.Fprintf(os.Stderr, "PANIC: %v\n", r)
		os.Exit(1)
	}
}

func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func logWarn(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func logError(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}
