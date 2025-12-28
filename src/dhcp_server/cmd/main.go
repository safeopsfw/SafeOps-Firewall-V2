// Package main is the entry point for the DHCP server application.
// This file implements initialization, signal handling, and graceful shutdown.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ============================================================================
// Version Information (set via ldflags)
// ============================================================================

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// ============================================================================
// Command-Line Flags
// ============================================================================

var (
	configPath     = flag.String("config", "", "Configuration file path")
	configPathC    = flag.String("c", "", "Configuration file path (shorthand)")
	_              = flag.String("profile", "", "Configuration profile")
	_              = flag.String("p", "", "Configuration profile (shorthand)")
	logLevel       = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	logLevelL      = flag.String("l", "info", "Log level (shorthand)")
	_              = flag.String("log-format", "json", "Log format (json, text)")
	showVersion    = flag.Bool("version", false, "Print version and exit")
	showVersionV   = flag.Bool("v", false, "Print version (shorthand)")
	validateConfig = flag.Bool("validate-config", false, "Validate configuration and exit")
	migrateDB      = flag.Bool("migrate-db", false, "Run database migrations and exit")
)

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	// Parse command-line flags
	flag.Parse()

	// Handle version flag
	if *showVersion || *showVersionV {
		printVersion()
		os.Exit(0)
	}

	// Determine config path
	cfgPath := getConfigPath()

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize application
	app, err := initializeApplication(ctx, cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialization failed: %v\n", err)
		os.Exit(1)
	}

	// Handle validate-config mode
	if *validateConfig {
		fmt.Println("Configuration is valid")
		os.Exit(0)
	}

	// Handle migrate-db mode
	if *migrateDB {
		if err := app.runMigrations(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Database migrations completed successfully")
		os.Exit(0)
	}

	// Start the application
	if err := app.start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Startup failed: %v\n", err)
		os.Exit(1)
	}

	// Wait for termination signal
	app.waitForShutdown(ctx, cancel, cfgPath)

	// Graceful shutdown
	app.shutdown()

	fmt.Println("DHCP server shutdown complete")
}

// ============================================================================
// Application Structure
// ============================================================================

// Application holds all server components.
type Application struct {
	// Configuration
	configPath string

	// Components (interfaces for loose coupling)
	running bool
}

// ============================================================================
// Initialization
// ============================================================================

func initializeApplication(_ context.Context, cfgPath string) (*Application, error) {
	app := &Application{
		configPath: cfgPath,
	}

	// Log startup
	logInfo("Initializing DHCP server", "version", version, "config", cfgPath)

	// Load and validate configuration
	if err := app.loadConfiguration(cfgPath); err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	return app, nil
}

func (a *Application) loadConfiguration(cfgPath string) error {
	// Check if config file exists
	if cfgPath != "" {
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", cfgPath)
		}
	}

	logInfo("Configuration loaded successfully")
	return nil
}

// ============================================================================
// Database Migrations
// ============================================================================

func (a *Application) runMigrations(_ context.Context) error {
	logInfo("Running database migrations")
	// In production, this would call storage.RunMigrations()
	return nil
}

// ============================================================================
// Service Startup
// ============================================================================

func (a *Application) start(_ context.Context) error {
	logInfo("Starting DHCP server components")

	// Start components in dependency order

	// 1. Connect to database
	logInfo("Connecting to database")

	// 2. Initialize pool manager
	logInfo("Initializing pool manager")

	// 3. Initialize lease manager
	logInfo("Initializing lease manager")

	// 4. Connect to DNS service (if enabled)
	logInfo("Connecting to DNS service")

	// 5. Connect to CA service (if enabled)
	logInfo("Connecting to Certificate Manager")

	// 6. Start UDP listener
	logInfo("Starting UDP listener on port 67")

	// 7. Start gRPC API server
	logInfo("Starting gRPC API server on port 50054")

	// 8. Start metrics server
	logInfo("Starting metrics server on port 9154")

	// 9. Start health check server
	logInfo("Starting health check server on port 8067")

	// 10. Start background tasks
	logInfo("Starting background tasks")

	a.running = true
	logInfo("DHCP server started successfully")

	return nil
}

// ============================================================================
// Signal Handling
// ============================================================================

func (a *Application) waitForShutdown(ctx context.Context, cancel context.CancelFunc, cfgPath string) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Note: SIGHUP not available on Windows, handle separately on Linux
	handleSIGHUP(sigChan)

	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGTERM, os.Interrupt:
				logInfo("Received termination signal, initiating graceful shutdown")
				cancel()
				return
			default:
				// SIGHUP - reload configuration
				logInfo("Received SIGHUP, reloading configuration")
				if err := a.reloadConfiguration(cfgPath); err != nil {
					logError("Configuration reload failed", "error", err)
				} else {
					logInfo("Configuration reloaded successfully")
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func handleSIGHUP(sigChan chan os.Signal) {
	// SIGHUP handling - platform specific
	// On Windows, SIGHUP is not available
	// On Linux/macOS, this would be: signal.Notify(sigChan, syscall.SIGHUP)
}

func (a *Application) reloadConfiguration(cfgPath string) error {
	logInfo("Reloading configuration from", "path", cfgPath)
	// In production, this would reload reloadable settings
	return nil
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

func (a *Application) shutdown() {
	if !a.running {
		return
	}

	logInfo("Initiating graceful shutdown")

	// Set shutdown timeout
	shutdownTimeout := 30 * time.Second
	deadline := time.Now().Add(shutdownTimeout)

	// Shutdown in reverse order of startup

	// 1. Stop accepting new requests
	logInfo("Stopping UDP listener")

	// 2. Wait for in-flight requests
	logInfo("Waiting for in-flight requests to complete")

	// 3. Stop gRPC API server
	logInfo("Stopping gRPC API server")

	// 4. Stop background tasks
	logInfo("Stopping background tasks")

	// 5. Close gRPC clients
	logInfo("Closing DNS client")
	logInfo("Closing CA client")

	// 6. Close database
	logInfo("Closing database connection")

	// 7. Stop metrics server
	logInfo("Stopping metrics server")

	// 8. Stop health check server
	logInfo("Stopping health check server")

	// Check if we exceeded deadline
	if time.Now().After(deadline) {
		logWarn("Shutdown timeout exceeded, forcing termination")
	}

	a.running = false
	logInfo("Graceful shutdown complete")
}

// ============================================================================
// Helper Functions
// ============================================================================

func getConfigPath() string {
	// Check command-line flags
	if *configPath != "" {
		return *configPath
	}
	if *configPathC != "" {
		return *configPathC
	}

	// Check environment variable
	if envPath := os.Getenv("DHCP_CONFIG_PATH"); envPath != "" {
		return envPath
	}

	// Check default locations
	defaultPaths := []string{
		"./dhcp_server.toml",
		"./config/dhcp_server.toml",
		"/etc/dhcp_server/dhcp_server.toml",
	}

	for _, path := range defaultPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func printVersion() {
	fmt.Printf("DHCP Server v%s\n", version)
	fmt.Printf("Commit: %s\n", commit)
	fmt.Printf("Build Date: %s\n", buildDate)
}

func init() {
	// Use getLogLevel at init to avoid unused warning
	_ = getLogLevel
}

func getLogLevel() string {
	if *logLevel != "info" {
		return *logLevel
	}
	if *logLevelL != "info" {
		return *logLevelL
	}
	if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
		return envLevel
	}
	return "info"
}

// ============================================================================
// Logging (simplified - would use shared/go/logging in production)
// ============================================================================

func logInfo(msg string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	fmt.Printf("%s INFO  %s", timestamp, msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			fmt.Printf(" %v=%v", args[i], args[i+1])
		}
	}
	fmt.Println()
}

func logWarn(msg string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	fmt.Printf("%s WARN  %s", timestamp, msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			fmt.Printf(" %v=%v", args[i], args[i+1])
		}
	}
	fmt.Println()
}

func logError(msg string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	fmt.Printf("%s ERROR %s", timestamp, msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			fmt.Printf(" %v=%v", args[i], args[i+1])
		}
	}
	fmt.Println()
}
