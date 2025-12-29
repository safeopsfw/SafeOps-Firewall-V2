// Package main is the entry point for the Certificate Manager service.
// It orchestrates component initialization, service startup, and graceful shutdown.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"certificate_manager/config"
	"certificate_manager/internal/acme"
	"certificate_manager/internal/ca"
	"certificate_manager/internal/distribution"
	"certificate_manager/internal/monitoring"
	"certificate_manager/internal/storage"
	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	ServiceName        = "certificate-manager"
	ServiceVersion     = "1.0.0"
	DefaultGRPCPort    = 50060 // Updated per documentation
	DefaultHTTPPort    = 8082  // CA distribution (no admin required)
	DefaultOCSPPort    = 8888  // OCSP responder
	DefaultMetricsPort = 9160  // Prometheus metrics
	ShutdownTimeout    = 30 * time.Second
)

// ============================================================================
// Application Structure
// ============================================================================

// Application holds all service components
type Application struct {
	config           *types.Config
	dbStorage        *storage.Database
	fsStorage        *storage.FilesystemStorage
	acmeClient       *acme.Client
	certManager      *ca.CertificateManager
	renewalScheduler *ca.RenewalScheduler
	distributor      *distribution.Distributor
	watcher          *distribution.CertificateWatcher
	grpcServer       *distribution.CertificateManagerServer
	httpServer       *http.Server
	metricsServer    *http.Server

	// Monitoring components
	healthChecker    *monitoring.HealthChecker
	statsCollector   *monitoring.StatsCollector
	metricsCollector *monitoring.MetricsCollector

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

	logInfo("Certificate Manager started successfully")
	logInfo("gRPC server listening on port %d", app.getGRPCPort())

	// Request initial certificates for configured domains
	go app.requestInitialCertificates()

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

	// Initialize ACME client
	logInfo("Initializing ACME client...")
	if err := app.initACME(); err != nil {
		return fmt.Errorf("failed to initialize ACME client: %w", err)
	}

	// Initialize certificate authority
	logInfo("Initializing certificate manager...")
	if err := app.initCertificateManager(); err != nil {
		return fmt.Errorf("failed to initialize certificate manager: %w", err)
	}

	// Initialize distribution
	logInfo("Initializing distribution services...")
	if err := app.initDistribution(); err != nil {
		return fmt.Errorf("failed to initialize distribution: %w", err)
	}

	// Initialize monitoring
	logInfo("Initializing monitoring services...")
	if err := app.initMonitoring(); err != nil {
		logWarn("Monitoring initialization failed: %v (continuing without full monitoring)", err)
	}

	// Initialize servers
	logInfo("Initializing servers...")
	if err := app.initServers(); err != nil {
		return fmt.Errorf("failed to initialize servers: %w", err)
	}

	logInfo("Initialization complete")
	return nil
}

// initStorage initializes database and filesystem storage
func (app *Application) initStorage() error {
	var err error

	// Database storage - uses types.DatabaseConfig directly
	app.dbStorage, err = storage.NewDatabase(app.config.Database)
	if err != nil {
		logWarn("Database connection failed: %v (continuing without database)", err)
		// Don't fail - we might operate without database
	}

	// Database migrations would be run via external migration tool
	// or schema initialization scripts

	// Filesystem storage - uses types.StorageConfig directly
	app.fsStorage, err = storage.NewFilesystemStorage(app.config.Storage)
	if err != nil {
		return fmt.Errorf("filesystem storage failed: %w", err)
	}

	return nil
}

// initACME initializes the ACME client
func (app *Application) initACME() error {
	// Create account manager with correct argument order: (config, db)
	accountManager := acme.NewAccountManager(app.config.ACME, app.dbStorage)

	// Create ACME client - validator will be set up later during certificate issuance
	// The client can work without validator for initialization
	app.acmeClient = acme.NewClient(app.config.ACME, accountManager, nil)

	// Initialize ACME account
	if err := app.acmeClient.Initialize(app.ctx); err != nil {
		logWarn("ACME initialization failed: %v (will retry on first certificate request)", err)
	}

	return nil
}

// initCertificateManager initializes certificate operations
func (app *Application) initCertificateManager() error {
	var err error

	// Create certificate manager with ManagerConfig
	managerCfg := ca.ManagerConfig{
		ACMEClient:     app.acmeClient,
		DBStorage:      app.dbStorage,
		FSStorage:      app.fsStorage,
		ACMEConfig:     app.config.ACME,
		DefaultKeyType: app.config.ACME.KeyType,
	}
	app.certManager, err = ca.NewCertificateManager(managerCfg)
	if err != nil {
		return fmt.Errorf("certificate manager creation failed: %w", err)
	}

	// Create renewal scheduler (takes 2 args: certManager and config)
	renewalConfig := ca.RenewalConfig{
		CheckInterval:        app.config.Renewal.CheckInterval,
		RenewalThresholdDays: app.config.Renewal.RenewBeforeDays,
		ConcurrentRenewals:   app.config.Renewal.MaxConcurrentRenewals,
		RetryBackoff:         app.config.Renewal.RetryInterval,
		EnableAutoRenewal:    app.config.Renewal.Enabled,
	}

	app.renewalScheduler, err = ca.NewRenewalScheduler(app.certManager, renewalConfig)
	if err != nil {
		return fmt.Errorf("renewal scheduler creation failed: %w", err)
	}

	return nil
}

// initDistribution initializes distribution services
func (app *Application) initDistribution() error {
	var err error

	// Create distributor
	distributorConfig := distribution.DistributorConfig{
		Timeout:         30 * time.Second,
		MaxConcurrent:   10,
		RetryAttempts:   app.config.Distribution.MaxRetryAttempts,
		RetryBackoff:    app.config.Distribution.RetryInterval,
		VerifyAfterPush: true,
	}

	app.distributor, err = distribution.NewDistributor(
		app.certManager,
		app.fsStorage,
		distributorConfig,
	)
	if err != nil {
		return fmt.Errorf("distributor creation failed: %w", err)
	}

	// Create certificate watcher
	watcherConfig := distribution.WatcherConfig{
		DebounceWindow:        time.Second,
		CertPath:              app.config.Storage.CertPath,
		KeyPath:               app.config.Storage.KeyPath,
		EnableFilesystemWatch: true,
		EnableDatabaseWatch:   app.dbStorage != nil,
	}

	app.watcher, err = distribution.NewCertificateWatcher(
		app.dbStorage,
		app.fsStorage,
		app.distributor,
		watcherConfig,
	)
	if err != nil {
		return fmt.Errorf("watcher creation failed: %w", err)
	}

	return nil
}

// initMonitoring initializes monitoring components
func (app *Application) initMonitoring() error {
	// Create stats collector (can work without database)
	app.statsCollector = monitoring.NewStatsCollector(nil)

	// Create health checker
	healthConfig := monitoring.DefaultHealthConfig()
	app.healthChecker = monitoring.NewHealthChecker(healthConfig, nil)

	// Create metrics collector
	app.metricsCollector = monitoring.NewMetricsCollector(app.statsCollector)

	// Set global metrics instance for use by other packages
	monitoring.SetGlobalMetrics(app.metricsCollector)

	return nil
}

// initServers initializes gRPC and HTTP servers
func (app *Application) initServers() error {
	var err error

	// Create gRPC server
	serverConfig := distribution.ServerConfig{
		Port:                    app.getGRPCPort(),
		GracefulShutdownTimeout: ShutdownTimeout,
	}

	app.grpcServer, err = distribution.NewCertificateManagerServer(
		app.certManager,
		app.renewalScheduler,
		app.distributor,
		app.watcher,
		serverConfig,
	)
	if err != nil {
		return fmt.Errorf("gRPC server creation failed: %w", err)
	}

	// Create HTTP server for health checks and metrics
	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.healthHandler)
	mux.HandleFunc("/ready", app.readyHandler)
	mux.HandleFunc("/metrics", app.metricsHandler)

	app.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", app.getHTTPPort()),
		Handler: mux,
	}

	return nil
}

// ============================================================================
// Service Startup
// ============================================================================

// start launches all services
func (app *Application) start() error {
	// Start gRPC server
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		if err := app.grpcServer.Serve(); err != nil {
			logError("gRPC server error: %v", err)
		}
	}()

	// Start HTTP server
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		logInfo("HTTP server listening on port %d", app.getHTTPPort())
		if err := app.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logError("HTTP server error: %v", err)
		}
	}()

	// Start renewal scheduler
	if app.config.Renewal.Enabled {
		app.wg.Add(1)
		go func() {
			defer app.wg.Done()
			logInfo("Starting renewal scheduler...")
			if err := app.renewalScheduler.Start(app.ctx); err != nil {
				logError("Renewal scheduler error: %v", err)
			}
		}()
	}

	// Start certificate watcher
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		logInfo("Starting certificate watcher...")
		if err := app.watcher.Start(app.ctx); err != nil {
			logError("Certificate watcher error: %v", err)
		}
	}()

	// Start distributor
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		if err := app.distributor.Start(app.ctx); err != nil {
			logError("Distributor error: %v", err)
		}
	}()

	return nil
}

// ============================================================================
// Initial Certificate Request
// ============================================================================

// requestInitialCertificates checks for and requests missing certificates
func (app *Application) requestInitialCertificates() {
	// Get enabled domains from config
	var enabledDomains []string
	for _, d := range app.config.Domains {
		if d.Enabled {
			enabledDomains = append(enabledDomains, d.CommonName)
		}
	}

	if len(enabledDomains) == 0 {
		logInfo("No domains configured for initial certificate request")
		return
	}

	logInfo("Checking initial certificates for %d domains", len(enabledDomains))

	for _, domain := range enabledDomains {
		// Check if certificate exists
		_, err := app.certManager.GetCertificate(app.ctx, domain)
		if err == nil {
			logInfo("Certificate already exists for %s", domain)
			continue
		}

		// Request new certificate
		logInfo("Requesting certificate for %s", domain)
		_, err = app.certManager.IssueCertificate(app.ctx, []string{domain})
		if err != nil {
			logError("Failed to issue certificate for %s: %v", domain, err)
			continue
		}

		logInfo("Successfully issued certificate for %s", domain)
	}
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

// shutdown performs graceful shutdown
func (app *Application) shutdown() error {
	logInfo("Starting graceful shutdown...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()

	// Stop accepting new requests
	app.cancel()

	// Stop gRPC server
	if app.grpcServer != nil {
		logInfo("Stopping gRPC server...")
		if err := app.grpcServer.GracefulShutdown(); err != nil {
			logWarn("gRPC shutdown error: %v", err)
		}
	}

	// Stop HTTP server
	if app.httpServer != nil {
		logInfo("Stopping HTTP server...")
		if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
			logWarn("HTTP shutdown error: %v", err)
		}
	}

	// Stop renewal scheduler
	if app.renewalScheduler != nil {
		logInfo("Stopping renewal scheduler...")
		if err := app.renewalScheduler.Stop(); err != nil {
			logWarn("Renewal scheduler stop error: %v", err)
		}
	}

	// Stop watcher
	if app.watcher != nil {
		logInfo("Stopping certificate watcher...")
		if err := app.watcher.Stop(); err != nil {
			logWarn("Watcher stop error: %v", err)
		}
	}

	// Stop distributor
	if app.distributor != nil {
		logInfo("Stopping distributor...")
		if err := app.distributor.Stop(); err != nil {
			logWarn("Distributor stop error: %v", err)
		}
	}

	// Close database connection
	if app.dbStorage != nil {
		logInfo("Closing database connection...")
		if err := app.dbStorage.Close(); err != nil {
			logWarn("Database close error: %v", err)
		}
	}

	// Wait for all goroutines with timeout
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
// Health Check Handlers
// ============================================================================

// healthHandler responds to health probes
func (app *Application) healthHandler(w http.ResponseWriter, _ *http.Request) {
	status := app.checkHealth()

	if status.Healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"%s","components":%s}`,
		boolToStatus(status.Healthy),
		componentsToJSON(status.Components))
}

// readyHandler responds to readiness probes
func (app *Application) readyHandler(w http.ResponseWriter, _ *http.Request) {
	// Check if all services are running
	ready := app.grpcServer != nil && app.grpcServer.IsRunning()

	if ready {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not_ready"}`))
	}
}

// metricsHandler exposes Prometheus metrics
func (app *Application) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	// Basic metrics
	fmt.Fprintln(w, "# HELP certificate_manager_up Certificate Manager is running")
	fmt.Fprintln(w, "# TYPE certificate_manager_up gauge")
	fmt.Fprintln(w, "certificate_manager_up 1")

	// Renewal metrics
	if app.renewalScheduler != nil {
		status, _ := app.renewalScheduler.GetRenewalStatus(context.Background())
		if status != nil {
			fmt.Fprintf(w, "certificate_renewals_total{status=\"success\"} %d\n", status.Metrics.RenewalsSucceeded)
			fmt.Fprintf(w, "certificate_renewals_total{status=\"failed\"} %d\n", status.Metrics.RenewalsFailed)
			fmt.Fprintf(w, "certificates_managed_total %d\n", status.Metrics.TotalManaged)
		}
	}

	// Distribution metrics
	if app.distributor != nil {
		metrics := app.distributor.GetMetrics()
		if metrics != nil {
			fmt.Fprintf(w, "certificate_distributions_total %d\n", metrics.TotalDistributions)
			fmt.Fprintf(w, "certificate_distribution_success_total %d\n", metrics.SuccessCount)
			fmt.Fprintf(w, "certificate_distribution_failure_total %d\n", metrics.FailureCount)
		}
	}
}

// HealthStatus represents overall health
type HealthStatus struct {
	Healthy    bool
	Components map[string]bool
}

// checkHealth performs health checks on all components
func (app *Application) checkHealth() HealthStatus {
	status := HealthStatus{
		Healthy:    true,
		Components: make(map[string]bool),
	}

	// Check database
	if app.dbStorage != nil {
		if err := app.dbStorage.Ping(context.Background()); err == nil {
			status.Components["database"] = true
		} else {
			status.Components["database"] = false
			status.Healthy = false
		}
	}

	// Check gRPC server
	if app.grpcServer != nil && app.grpcServer.IsRunning() {
		status.Components["grpc_server"] = true
	} else {
		status.Components["grpc_server"] = false
	}

	// Check renewal scheduler
	if app.renewalScheduler != nil && app.renewalScheduler.IsRunning() {
		status.Components["renewal_scheduler"] = true
	} else {
		status.Components["renewal_scheduler"] = false
	}

	// Check watcher
	if app.watcher != nil && app.watcher.IsRunning() {
		status.Components["watcher"] = true
	} else {
		status.Components["watcher"] = false
	}

	return status
}

// ============================================================================
// Configuration
// ============================================================================

// loadConfiguration loads the application configuration
func loadConfiguration() (*types.Config, error) {
	// Try to load from environment or default path
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "" // Let config.Load use its default
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		logWarn("Failed to load config file: %v, using defaults", err)
		// Return minimal default config
		cfg = defaultConfig()
	}

	// Apply environment overrides
	applyEnvOverrides(cfg)

	return cfg, nil
}

// defaultConfig creates a minimal default configuration
func defaultConfig() *types.Config {
	return &types.Config{
		Service: types.ServiceConfig{
			Name:    ServiceName,
			Version: ServiceVersion,
		},
		GRPC: types.GRPCConfig{
			Enabled: true,
			Port:    DefaultGRPCPort,
			Host:    "0.0.0.0",
		},
		ACME: types.AcmeConfig{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			TermsAgreed:  true,
		},
		Database: types.DatabaseConfig{
			Enabled: false, // Disabled by default
			Host:    "localhost",
			Port:    5432,
			Name:    "safeops_db",
			SSLMode: "disable",
		},
		Renewal: types.RenewalConfig{
			Enabled:         true,
			CheckInterval:   24 * time.Hour,
			RenewBeforeDays: 30,
		},
		Storage: types.StorageConfig{
			CertPath: "./certs",
			KeyPath:  "./keys",
		},
		Health: types.HealthConfig{
			Enabled: true,
			Port:    DefaultHTTPPort,
		},
	}
}

// applyEnvOverrides applies environment variable overrides
func applyEnvOverrides(cfg *types.Config) {
	if val := os.Getenv("ACME_EMAIL"); val != "" {
		cfg.ACME.Email = val
	}
	if val := os.Getenv("ACME_DIRECTORY_URL"); val != "" {
		cfg.ACME.DirectoryURL = val
	}
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		cfg.Service.LogLevel = val
	}
	if val := os.Getenv("GRPC_PORT"); val != "" {
		cfg.GRPC.Port = parsePort(val, DefaultGRPCPort)
	}
	if val := os.Getenv("CERT_STORAGE_PATH"); val != "" {
		cfg.Storage.CertPath = val
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

// getGRPCPort returns the configured gRPC port
func (app *Application) getGRPCPort() int {
	if app.config != nil && app.config.GRPC.Port > 0 {
		return app.config.GRPC.Port
	}
	return DefaultGRPCPort
}

// getHTTPPort returns the configured HTTP port
func (app *Application) getHTTPPort() int {
	if app.config != nil && app.config.Health.Port > 0 {
		return app.config.Health.Port
	}
	return DefaultHTTPPort
}

// parsePort parses port string with default fallback
func parsePort(s string, defaultVal int) int {
	var port int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			port = port*10 + int(c-'0')
		}
	}
	if port <= 0 || port > 65535 {
		return defaultVal
	}
	return port
}

// recoverPanic handles unexpected panics
func recoverPanic() {
	if r := recover(); r != nil {
		logError("PANIC RECOVERED: %v", r)
		os.Exit(1)
	}
}

// boolToStatus converts bool to status string
func boolToStatus(b bool) string {
	if b {
		return "healthy"
	}
	return "unhealthy"
}

// componentsToJSON converts component map to JSON
func componentsToJSON(components map[string]bool) string {
	result := "{"
	first := true
	for k, v := range components {
		if !first {
			result += ","
		}
		result += fmt.Sprintf(`"%s":%t`, k, v)
		first = false
	}
	result += "}"
	return result
}

// isPortAvailable checks if a port is available
func isPortAvailable(port int) bool {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// ============================================================================
// Logging (Simple implementation - would use shared/go/logging in production)
// ============================================================================

func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func logWarn(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}
