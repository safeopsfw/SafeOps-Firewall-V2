// DHCP Monitor Service - Main Entry Point
// Phase 2: Real-time device detection and trust management
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dhcp_monitor/internal/config"
	"dhcp_monitor/internal/database"
	grpcserver "dhcp_monitor/internal/grpc"
	"dhcp_monitor/internal/manager"
	"dhcp_monitor/internal/platform"
	"dhcp_monitor/internal/watcher"
)

// =============================================================================
// VERSION INFORMATION
// =============================================================================

var (
	Version   = "2.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// =============================================================================
// COMMAND LINE FLAGS
// =============================================================================

var (
	configPath  = flag.String("config", "config/dhcp_monitor.yaml", "Path to configuration file")
	validateCfg = flag.Bool("validate", false, "Validate configuration and exit")
	showVersion = flag.Bool("version", false, "Show version information and exit")
	migrateOnly = flag.Bool("migrate-only", false, "Run database migrations and exit")
)

// =============================================================================
// MAIN FUNCTION
// =============================================================================

func main() {
	flag.Parse()

	// Handle --version flag
	if *showVersion {
		printVersion()
		return
	}

	// Run with panic recovery
	if err := runWithPanicRecovery(run); err != nil {
		log.Printf("[MAIN] Fatal error: %v", err)
		os.Exit(1)
	}
}

// run is the main execution function wrapped by panic recovery
func run() error {
	log.Println("╔════════════════════════════════════════╗")
	log.Println("║     DHCP Monitor Service v2.0.0        ║")
	log.Println("╚════════════════════════════════════════╝")

	// Load configuration
	cfg, err := loadConfiguration(*configPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	// Handle --validate flag
	if *validateCfg {
		log.Println("[MAIN] Configuration is valid")
		return nil
	}

	log.Printf("[MAIN] Configuration loaded: %s", cfg.String())

	// Initialize database
	db, err := initializeDatabase(cfg)
	if err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer db.Close()

	// Run migrations if enabled
	if err := runMigrations(db, cfg); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	// Handle --migrate-only flag
	if *migrateOnly {
		log.Println("[MAIN] Migrations complete, exiting")
		return nil
	}

	// Create event channel for watcher -> manager communication
	eventChannel := createEventChannel(1000)

	// Initialize device manager
	deviceMgr, err := initializeDeviceManager(db, eventChannel, cfg)
	if err != nil {
		return fmt.Errorf("initialize device manager: %w", err)
	}

	// Initialize watchers
	arpMonitor, dhcpEnricher, err := initializeWatchers(eventChannel, cfg)
	if err != nil {
		// Stop device manager on watcher init failure
		deviceMgr.Stop()
		return fmt.Errorf("initialize watchers: %w", err)
	}

	// Start mDNS Responder (for safeops-portal.local)
	// Bind to All Interfaces - dynamic IP selection
	mdnsResp, err := platform.NewMDNSResponder("safeops-portal.local")
	if err != nil {
		log.Printf("[MAIN] Warning: Failed to create mDNS responder: %v", err)
	} else {
		// Run in background
		err = mdnsResp.Start(context.Background())
		if err != nil {
			log.Printf("[MAIN] Warning: Failed to start mDNS responder: %v", err)
		}
	}

	// Initialize gRPC server
	server := grpcserver.NewServer(db)

	// Setup signal handler
	sigChan := setupSignalHandler()

	// Start gRPC server in goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		log.Printf("[MAIN] Starting gRPC server on %s:%d", cfg.GRPC.Host, cfg.GRPC.Port)
		if err := server.Start(cfg.GRPC.Host, cfg.GRPC.Port); err != nil {
			serverErrChan <- err
		}
	}()

	// Wait for gRPC server to start with retries
	var startupErr error
	for attempt := 1; attempt <= 5; attempt++ {
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		startupErr = validateStartup(db, server)
		if startupErr == nil {
			break
		}
		log.Printf("[MAIN] Startup validation attempt %d failed: %v", attempt, startupErr)
	}

	// Validate startup
	if startupErr != nil {
		shutdown(server, arpMonitor, dhcpEnricher, deviceMgr, db)
		return fmt.Errorf("startup validation: %w", startupErr)
	}

	log.Println("[MAIN] ═══════════════════════════════════════")
	log.Println("[MAIN] DHCP Monitor started successfully")
	log.Printf("[MAIN] Version: %s", Version)
	log.Printf("[MAIN] gRPC: %s:%d", cfg.GRPC.Host, cfg.GRPC.Port)
	log.Printf("[MAIN] Database: %s:%d/%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.Name)
	log.Println("[MAIN] ═══════════════════════════════════════")

	// Wait for shutdown signal or server error
	select {
	case sig := <-sigChan:
		log.Printf("[MAIN] Received shutdown signal: %v", sig)
	case err := <-serverErrChan:
		log.Printf("[MAIN] Server error: %v", err)
	}

	// Perform graceful shutdown
	shutdown(server, arpMonitor, dhcpEnricher, deviceMgr, db)

	log.Println("[MAIN] DHCP Monitor stopped successfully")
	return nil
}

// =============================================================================
// INITIALIZATION FUNCTIONS
// =============================================================================

// loadConfiguration loads and validates the configuration file
func loadConfiguration(path string) (*config.Config, error) {
	log.Printf("[MAIN] Loading configuration from %s", path)

	// Check if config file exists - use hardcoded defaults if not
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("[MAIN] Config file not found at %s, using hardcoded defaults", path)
		return createDefaultConfig(), nil
	}

	cfg, err := config.LoadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// createDefaultConfig creates hardcoded default configuration
// This allows the binary to run without external config files
func createDefaultConfig() *config.Config {
	return &config.Config{
		Database: config.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			Name:     "safeops",
			User:     "safeops",
			Password: "safeops123",
			SSLMode:  "disable",
			Pool: config.PoolConfig{
				MinConnections:    2,
				MaxConnections:    10,
				ConnectionTimeout: 30 * time.Second,
				IdleTimeout:       5 * time.Minute,
				MaxLifetime:       1 * time.Hour,
			},
			Migration: config.MigrationConfig{
				AutoMigrate:    true,
				ValidateSchema: true,
			},
		},
		GRPC: config.GRPCConfig{
			Host:           "0.0.0.0",
			Port:           50055,
			MaxMessageSize: 4 * 1024 * 1024, // 4MB
			ConnTimeout:    10 * time.Second,
			Keepalive: config.KeepaliveConfig{
				Time:    30 * time.Second,
				Timeout: 10 * time.Second,
				MinTime: 10 * time.Second,
			},
		},
		Monitoring: config.MonitoringConfig{
			ARPTable: config.ARPTableConfig{
				RefreshInterval: 30 * time.Second,
				PollInterval:    30 * time.Second,
				CacheDuration:   5 * time.Minute,
			},
			Detection: config.DetectionConfig{
				PrimaryMethod:      "arp",
				SecondaryMethod:    "dhcp_event_log",
				DedupCacheDuration: 5 * time.Minute,
				DedupCacheMaxSize:  1000,
			},
		},
		DHCPEventLog: config.DHCPEventLogConfig{
			Enabled:      true,
			PollInterval: 30 * time.Second,
		},
		DeviceManagement: config.DeviceManagementConfig{
			Status: config.StatusConfig{
				InactiveTimeout: 10 * time.Minute,
				ExpiredTimeout:  24 * time.Hour,
			},
			Cleanup: config.CleanupConfig{
				Enabled:           true,
				Interval:          1 * time.Hour,
				PurgeExpiredAfter: 30 * 24 * time.Hour, // 30 days
			},
			UnknownDevices: config.UnknownDevicesConfig{
				AutoCreate:         true,
				DefaultTrustStatus: "UNTRUSTED",
				DefaultDeviceType:  "unknown",
			},
		},
		Logging: config.LoggingConfig{
			Level:  "INFO",
			Format: "json",
		},
		Service: config.ServiceConfig{
			Name: "dhcp_monitor",
			Shutdown: config.ShutdownConfig{
				Timeout:          30 * time.Second,
				DrainConnections: true,
			},
		},
	}
}

// initializeDatabase creates and tests the database connection
func initializeDatabase(cfg *config.Config) (*database.DatabaseClient, error) {
	log.Printf("[MAIN] Connecting to database %s:%d/%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.Name)

	dbConfig := &database.DatabaseConfig{
		Host:              cfg.Database.Host,
		Port:              cfg.Database.Port,
		Name:              cfg.Database.Name,
		User:              cfg.Database.User,
		Password:          cfg.Database.Password,
		SSLMode:           cfg.Database.SSLMode,
		MinConnections:    cfg.Database.Pool.MinConnections,
		MaxConnections:    cfg.Database.Pool.MaxConnections,
		ConnectionTimeout: cfg.Database.Pool.ConnectionTimeout,
		IdleTimeout:       cfg.Database.Pool.IdleTimeout,
		MaxLifetime:       cfg.Database.Pool.MaxLifetime,
	}

	// Retry connection with backoff
	var db *database.DatabaseClient
	var err error
	maxRetries := 3
	retryDelay := 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		db, err = database.NewDatabaseClient(dbConfig)
		if err == nil {
			break
		}

		log.Printf("[MAIN] Database connection failed (attempt %d/%d): %v",
			attempt, maxRetries, err)

		if attempt < maxRetries {
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
		}
	}

	if err != nil {
		return nil, fmt.Errorf("connect after %d attempts: %w", maxRetries, err)
	}

	log.Println("[MAIN] Database connection established")
	return db, nil
}

// runMigrations executes database migrations if enabled
func runMigrations(db *database.DatabaseClient, cfg *config.Config) error {
	if !cfg.Database.Migration.AutoMigrate {
		log.Println("[MAIN] Auto-migrate disabled, skipping migrations")
		return nil
	}

	log.Println("[MAIN] Running database migrations...")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := db.RunMigrations(ctx, "database/schemas"); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	log.Println("[MAIN] Database migrations complete")
	return nil
}

// createEventChannel creates the buffered event channel
func createEventChannel(bufferSize int) watcher.EventChannel {
	log.Printf("[MAIN] Creating event channel (buffer=%d)", bufferSize)
	return watcher.NewEventChannel(bufferSize)
}

// initializeDeviceManager creates and starts the device manager
func initializeDeviceManager(db *database.DatabaseClient, eventChan watcher.EventChannel, cfg *config.Config) (*manager.DeviceManager, error) {
	cleanupInterval := cfg.GetCleanupInterval()
	inactiveTimeout := cfg.GetInactiveTimeout()

	log.Printf("[MAIN] Starting device manager (cleanup=%v, inactive=%v)",
		cleanupInterval, inactiveTimeout)

	deviceMgr, err := manager.NewDeviceManager(db, eventChan, cleanupInterval, inactiveTimeout)
	if err != nil {
		return nil, fmt.Errorf("create device manager: %w", err)
	}

	if err := deviceMgr.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("start device manager: %w", err)
	}

	log.Println("[MAIN] Device manager started")
	return deviceMgr, nil
}

// initializeWatchers creates and starts the network watchers
func initializeWatchers(eventChan watcher.EventChannel, cfg *config.Config) (*watcher.ARPMonitor, *watcher.DHCPEnricher, error) {
	// Initialize ARP Monitor
	log.Println("[MAIN] Starting ARP monitor...")

	pollInterval := cfg.Monitoring.ARPTable.PollInterval
	if pollInterval == 0 {
		pollInterval = 30 * time.Second
	}
	cacheExpiry := cfg.Monitoring.Detection.DedupCacheDuration
	if cacheExpiry == 0 {
		cacheExpiry = 5 * time.Minute
	}
	interfaceFilter := ""
	if len(cfg.Monitoring.Interfaces.IncludePatterns) > 0 {
		interfaceFilter = cfg.Monitoring.Interfaces.IncludePatterns[0]
	}

	arpMonitor, err := watcher.NewARPMonitor(eventChan, pollInterval, cacheExpiry, interfaceFilter)
	if err != nil {
		return nil, nil, fmt.Errorf("create ARP monitor: %w", err)
	}

	if err := arpMonitor.Start(context.Background()); err != nil {
		return nil, nil, fmt.Errorf("start ARP monitor: %w", err)
	}

	log.Println("[MAIN] ARP monitor started")

	// Initialize DHCP Enricher (if enabled)
	var dhcpEnricher *watcher.DHCPEnricher
	if cfg.DHCPEventLog.Enabled {
		log.Println("[MAIN] Starting DHCP enricher...")

		enricherPollInterval := cfg.DHCPEventLog.PollInterval
		if enricherPollInterval == 0 {
			enricherPollInterval = 30 * time.Second
		}

		dhcpEnricher, err = watcher.NewDHCPEnricher(eventChan, enricherPollInterval)
		if err != nil {
			arpMonitor.Stop()
			return nil, nil, fmt.Errorf("create DHCP enricher: %w", err)
		}

		if err := dhcpEnricher.Start(context.Background()); err != nil {
			arpMonitor.Stop()
			return nil, nil, fmt.Errorf("start DHCP enricher: %w", err)
		}

		log.Println("[MAIN] DHCP enricher started")
	} else {
		log.Println("[MAIN] DHCP enricher disabled")
	}

	return arpMonitor, dhcpEnricher, nil
}

// =============================================================================
// SIGNAL HANDLING
// =============================================================================

// setupSignalHandler creates a channel for OS signals
func setupSignalHandler() <-chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	return sigChan
}

// =============================================================================
// SHUTDOWN
// =============================================================================

// shutdown gracefully stops all components in reverse order
func shutdown(server *grpcserver.Server, arpMonitor *watcher.ARPMonitor, dhcpEnricher *watcher.DHCPEnricher, deviceMgr *manager.DeviceManager, db *database.DatabaseClient) {
	startTime := time.Now()
	log.Println("[MAIN] Shutting down DHCP Monitor...")

	// Stop gRPC server first (stop accepting new requests)
	log.Println("[MAIN] Stopping gRPC server...")
	server.Stop()
	log.Println("[MAIN] gRPC server stopped")

	// Stop watchers (stop detection)
	log.Println("[MAIN] Stopping watchers...")
	if arpMonitor != nil {
		arpMonitor.Stop()
		log.Println("[MAIN] ARP monitor stopped")
	}
	if dhcpEnricher != nil {
		dhcpEnricher.Stop()
		log.Println("[MAIN] DHCP enricher stopped")
	}

	// Stop device manager (finish processing events)
	log.Println("[MAIN] Stopping device manager...")
	if deviceMgr != nil {
		deviceMgr.Stop()
		log.Println("[MAIN] Device manager stopped")
	}

	// Close database connections last
	log.Println("[MAIN] Closing database connections...")
	if db != nil {
		db.Close()
		log.Println("[MAIN] Database connections closed")
	}

	log.Printf("[MAIN] Shutdown complete (duration: %v)", time.Since(startTime))
}

// =============================================================================
// VALIDATION
// =============================================================================

// validateStartup performs post-initialization health checks
func validateStartup(db *database.DatabaseClient, server *grpcserver.Server) error {
	log.Println("[MAIN] Performing startup validation...")

	// Check database connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.Ping(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Check server is running
	if !server.IsRunning() {
		return fmt.Errorf("gRPC server not running")
	}

	log.Println("[MAIN] Startup validation passed")
	return nil
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// printVersion displays version information
func printVersion() {
	fmt.Printf("DHCP Monitor v%s\n", Version)
	fmt.Printf("Build Time: %s\n", BuildTime)
	fmt.Printf("Git Commit: %s\n", GitCommit)
}

// runWithPanicRecovery wraps execution with panic recovery
func runWithPanicRecovery(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered: %v", r)
			log.Printf("[MAIN] PANIC: %v", r)
		}
	}()
	return fn()
}
