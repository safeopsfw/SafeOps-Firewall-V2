// Package main provides the unified entry point for NIC Management service.
// This combines both the gRPC service and REST API into a single executable.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"safeops/nic_management/api"
	"safeops/nic_management/config"
	"safeops/nic_management/internal/discovery"
	"safeops/nic_management/internal/failover"
	internalgrpc "safeops/nic_management/internal/grpc"
	"safeops/nic_management/internal/nat"
	"safeops/nic_management/internal/subprocess"
)

// =============================================================================
// Build Information
// =============================================================================

var (
	// Version is set at build time.
	Version = "1.0.0"
	// GitCommit is set at build time.
	GitCommit = "unknown"
	// BuildDate is set at build time.
	BuildDate = "unknown"
)

// =============================================================================
// Command-Line Flags
// =============================================================================

var (
	configPath     = flag.String("config", "/etc/safeops/nic_management.yaml", "Path to config file")
	showVersion    = flag.Bool("version", false, "Show version information")
	installService = flag.Bool("install-service", false, "Install as Windows service")
	apiPort        = flag.Int("api-port", 8081, "REST API port")
	grpcPort       = flag.Int("grpc-port", 50056, "gRPC server port")
)

// =============================================================================
// Service Components
// =============================================================================

// ServiceComponents holds all initialized service components.
type ServiceComponents struct {
	// Configuration.
	config *config.Config

	// Discovery layer.
	enumerator *discovery.Enumerator
	classifier *discovery.Classifier
	monitor    *discovery.Monitor

	// NAT layer.
	portAllocator  *nat.PortAllocator
	mappingTable   *nat.MappingTable
	sessionTracker *nat.SessionTracker
	cleanupManager *nat.CleanupManager

	// Failover layer.
	failoverHandler *failover.FailoverHandler

	// gRPC layer.
	handlers       *internalgrpc.Handlers
	streamHandlers *internalgrpc.StreamHandlers
	grpcServer     *internalgrpc.GrpcServer

	// REST API layer.
	apiServer *api.NICAPIServer

	// Packet Engine subprocess.
	packetEngine *subprocess.PacketEngineManager
}

// =============================================================================
// Main Entry Point
// =============================================================================

func main() {
	// Parse command-line flags.
	flag.Parse()

	// Handle version flag.
	if *showVersion {
		printVersion()
		return
	}

	// Handle service installation.
	if *installService {
		runServiceInstall()
		return
	}

	// Initialize logger.
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.Printf("Starting Unified NIC Management Service v%s (commit: %s, built: %s)", Version, GitCommit, BuildDate)
	log.Printf("Platform: %s/%s, Go version: %s", runtime.GOOS, runtime.GOARCH, runtime.Version())

	// Load configuration.
	cfg, err := loadConfiguration(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Printf("Configuration loaded from %s", *configPath)

	// Create context for service lifecycle.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize all components.
	components, err := initializeComponents(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize components: %v", err)
	}
	log.Println("All components initialized successfully")

	// Start all workers.
	var wg sync.WaitGroup
	if err := startAllWorkers(ctx, components, &wg); err != nil {
		log.Fatalf("Failed to start workers: %v", err)
	}

	log.Printf("NIC Management gRPC service ready on port %d", *grpcPort)
	log.Printf("NIC Management REST API ready on port %d", *apiPort)

	// Set up signal handlers.
	sigChan := setupSignalHandlers()

	// Wait for shutdown signal.
	sig := <-sigChan
	log.Printf("Received signal %v, initiating graceful shutdown...", sig)

	// Cancel context to notify all workers.
	cancel()

	// Perform graceful shutdown.
	shutdownService(components)

	// Wait for all goroutines to finish.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All services stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("Shutdown timeout exceeded, forcing exit")
	}

	log.Println("Unified NIC Management service stopped")
}

// =============================================================================
// Configuration Loading
// =============================================================================

// loadConfiguration loads and validates service configuration.
func loadConfiguration(configPath string) (*config.Config, error) {
	// Check if config file exists.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Use default configuration if file doesn't exist.
		log.Printf("Config file not found at %s, using defaults", configPath)
		return createDefaultConfig(), nil
	}

	// Load configuration from file.
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	// Apply environment variable overrides.
	applyEnvironmentOverrides(cfg)

	return cfg, nil
}

// createDefaultConfig creates default configuration.
func createDefaultConfig() *config.Config {
	cfg := &config.Config{
		Service: config.ServiceConfig{
			Name:     "nic_management",
			LogLevel: "info",
		},
		GRPC: config.GRPCConfig{
			ListenAddress: fmt.Sprintf("0.0.0.0:%d", *grpcPort),
		},
		Failover: config.FailoverConfig{
			Enabled: true,
		},
		NAT: config.NATConfig{
			Enabled: true,
		},
		Monitoring: config.MonitoringConfig{
			Enabled: true,
		},
	}

	// Add default WAN interface.
	cfg.WANInterfaces = []config.WANInterfaceConfig{
		{
			Name:     "eth0",
			Priority: 1,
			Weight:   100,
			Enabled:  true,
		},
	}

	return cfg
}

// applyEnvironmentOverrides applies environment variable overrides.
func applyEnvironmentOverrides(cfg *config.Config) {
	if port := os.Getenv("NIC_MGMT_PORT"); port != "" {
		var p int
		if _, err := fmt.Sscanf(port, "%d", &p); err == nil && p > 0 && p < 65536 {
			cfg.GRPC.ListenAddress = fmt.Sprintf("0.0.0.0:%d", p)
		}
	}

	if logLevel := os.Getenv("NIC_MGMT_LOG_LEVEL"); logLevel != "" {
		cfg.Service.LogLevel = logLevel
	}

	if tlsCert := os.Getenv("NIC_MGMT_TLS_CERT"); tlsCert != "" {
		if cfg.GRPC.TLS == nil {
			cfg.GRPC.TLS = &config.TLSConfig{}
		}
		cfg.GRPC.TLS.CertFile = tlsCert
		cfg.GRPC.TLS.Enabled = true
	}

	if tlsKey := os.Getenv("NIC_MGMT_TLS_KEY"); tlsKey != "" {
		if cfg.GRPC.TLS == nil {
			cfg.GRPC.TLS = &config.TLSConfig{}
		}
		cfg.GRPC.TLS.KeyFile = tlsKey
	}
}

// =============================================================================
// Component Initialization
// =============================================================================

// initializeComponents creates and wires all service components.
func initializeComponents(ctx context.Context, cfg *config.Config) (*ServiceComponents, error) {
	_ = ctx // Used in production for initialization context.

	components := &ServiceComponents{
		config: cfg,
	}

	var err error

	// Initialize Discovery Layer.
	enumeratorConfig := discovery.DefaultEnumeratorConfig()
	components.enumerator, err = discovery.NewEnumerator(enumeratorConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create enumerator: %w", err)
	}

	classifierConfig := discovery.DefaultClassifierConfig()
	components.classifier = discovery.NewClassifier(classifierConfig)

	monitorConfig := discovery.DefaultMonitorConfig()
	components.monitor, err = discovery.NewMonitor(components.enumerator, components.classifier, monitorConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor: %w", err)
	}

	// Initialize NAT Layer (with nil DB for now).
	portAllocatorConfig := nat.DefaultPortAllocatorConfig()
	if cfg.NAT.PortAllocation != nil {
		portAllocatorConfig.PortRangeStart = uint16(cfg.NAT.PortAllocation.Start)
		portAllocatorConfig.PortRangeEnd = uint16(cfg.NAT.PortAllocation.End)
	}
	components.portAllocator, _ = nat.NewPortAllocator(nil, portAllocatorConfig)

	mappingTableConfig := nat.DefaultMappingTableConfig()
	components.mappingTable, _ = nat.NewMappingTable(nil, mappingTableConfig)

	sessionTrackerConfig := nat.DefaultSessionTrackerConfig()
	components.sessionTracker = nat.NewSessionTracker(sessionTrackerConfig)

	cleanupConfig := nat.DefaultCleanupConfig()
	components.cleanupManager = nat.NewCleanupManager(
		components.mappingTable,
		components.sessionTracker,
		components.portAllocator,
		cleanupConfig,
	)

	// Initialize Failover Layer.
	failoverHandlerConfig := failover.DefaultFailoverConfig()
	components.failoverHandler = failover.NewFailoverHandler(
		nil, // Traffic distributor interface.
		nil, // NAT translator interface.
		nil, // Routing engine interface.
		nil, // WAN selector interface.
		nil, // Database interface.
		nil, // Event publisher interface.
		failoverHandlerConfig,
	)

	// Initialize gRPC Layer.
	handlersConfig := internalgrpc.DefaultHandlersConfig()
	components.handlers = internalgrpc.NewHandlers(
		components.monitor,
		nil, // Metrics aggregator.
		components.failoverHandler,
		nil, // Interface configurator.
		nil, // Firewall hooks.
		nil, // IDS hooks.
		nil, // Logger hooks.
		handlersConfig,
	)

	streamConfig := internalgrpc.DefaultStreamHandlersConfig()
	components.streamHandlers = internalgrpc.NewStreamHandlers(
		nil, // Metrics aggregator.
		streamConfig,
	)

	// Create gRPC server with configured port.
	serverConfig := internalgrpc.DefaultServerConfig()
	serverConfig.Port = *grpcPort
	if cfg.GRPC.TLS != nil && cfg.GRPC.TLS.Enabled {
		serverConfig.TLSEnabled = true
		serverConfig.TLSCertPath = cfg.GRPC.TLS.CertFile
		serverConfig.TLSKeyPath = cfg.GRPC.TLS.KeyFile
	}
	components.grpcServer, err = internalgrpc.NewGrpcServer(
		components.handlers,
		components.streamHandlers,
		serverConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC server: %w", err)
	}

	// Initialize REST API Server.
	components.apiServer = api.NewNICAPIServer(*apiPort, *configPath)

	// Initialize Packet Engine Manager.
	components.packetEngine = subprocess.NewPacketEngineManager()
	log.Println("Packet Engine manager initialized")

	return components, nil
}

// =============================================================================
// Worker Management
// =============================================================================

// startAllWorkers starts all background workers.
func startAllWorkers(ctx context.Context, c *ServiceComponents, wg *sync.WaitGroup) error {
	// Start discovery monitor.
	if c.monitor != nil {
		if err := c.monitor.Start(ctx); err != nil {
			log.Printf("Warning: discovery monitor start failed: %v", err)
		}
	}

	// Start NAT cleanup.
	if c.cleanupManager != nil {
		if err := c.cleanupManager.Start(ctx); err != nil {
			log.Printf("Warning: NAT cleanup start failed: %v", err)
		}
	}

	// Start failover handler.
	if c.failoverHandler != nil {
		if err := c.failoverHandler.Start(ctx); err != nil {
			log.Printf("Warning: failover handler start failed: %v", err)
		}
	}

	// Start gRPC server.
	if c.grpcServer != nil {
		if err := c.grpcServer.Start(ctx); err != nil {
			return fmt.Errorf("gRPC server start failed: %w", err)
		}
	}

	// Start REST API server in goroutine.
	if c.apiServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("Starting REST API server on port %d", *apiPort)
			if err := c.apiServer.Start(); err != nil {
				log.Printf("REST API server error: %v", err)
			}
		}()
	}

	// NOTE: Packet Engine runs separately with Admin privileges
	// Uncomment below to auto-start packet_engine as subprocess
	/*
		if c.packetEngine != nil {
			if err := c.packetEngine.Start(); err != nil {
				log.Printf("Warning: Packet Engine start failed: %v", err)
				log.Printf("Packet Engine requires Administrator privileges and WinDivert files")
			} else {
				log.Println("Packet Engine started successfully")
			}
		}
	*/

	return nil
}

// =============================================================================
// Graceful Shutdown
// =============================================================================

// shutdownService performs graceful shutdown of all components.
func shutdownService(c *ServiceComponents) {
	log.Println("Initiating graceful shutdown...")

	// Set shutdown timeout.
	shutdownTimeout := 30 * time.Second
	deadline := time.Now().Add(shutdownTimeout)

	// Phase 1: Stop accepting new work.
	log.Println("Phase 1: Stopping new connections...")
	if c.grpcServer != nil {
		_ = c.grpcServer.Stop()
	}
	if c.apiServer != nil {
		_ = c.apiServer.Stop()
	}
	if c.packetEngine != nil {
		_ = c.packetEngine.Stop()
		log.Println("Packet Engine stopped")
	}

	// Phase 2: Stop background workers.
	log.Println("Phase 2: Stopping background workers...")

	if c.monitor != nil {
		_ = c.monitor.Stop()
	}

	if c.cleanupManager != nil {
		_ = c.cleanupManager.Stop()
	}

	if c.failoverHandler != nil {
		_ = c.failoverHandler.Stop()
	}

	// Phase 3: Final cleanup.
	log.Println("Phase 3: Final cleanup...")

	if c.sessionTracker != nil {
		_ = c.sessionTracker.Stop()
	}

	if c.mappingTable != nil {
		_ = c.mappingTable.Stop()
	}

	// Check if we exceeded deadline.
	if time.Now().After(deadline) {
		log.Println("Warning: Shutdown exceeded timeout, some resources may not be cleaned up")
	}

	log.Println("Shutdown complete")
}

// =============================================================================
// Signal Handling
// =============================================================================

// setupSignalHandlers registers OS signal handlers.
func setupSignalHandlers() chan os.Signal {
	sigChan := make(chan os.Signal, 1)

	// Register signal handlers based on platform.
	if runtime.GOOS == "windows" {
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	} else {
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	}

	return sigChan
}

// =============================================================================
// Version Information
// =============================================================================

// printVersion prints service version information.
func printVersion() {
	fmt.Println("Unified NIC Management Service")
	fmt.Printf("  Version:    %s\n", Version)
	fmt.Printf("  Git Commit: %s\n", GitCommit)
	fmt.Printf("  Build Date: %s\n", BuildDate)
	fmt.Printf("  Go Version: %s\n", runtime.Version())
	fmt.Printf("  Platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

// =============================================================================
// Service Installation
// =============================================================================

// runServiceInstall runs the service installation process.
// Uses functions from installer.go
func runServiceInstall() {
	// TODO: Implement service installation
	log.Println("Service installation not yet implemented")
	// config := DefaultServiceConfig()
	// if err := InstallService(config); err != nil {
	// 	log.Fatalf("Installation failed: %v", err)
	// }
}
