// Package main is the DNS Server application entry point.
package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dns_server/internal/dns"
	"dns_server/internal/recursive"
)

// =============================================================================
// CONFIGURATION DEFAULTS
// =============================================================================

const (
	defaultBindAddress     = ":53"
	defaultCacheSize       = 50000
	defaultCacheTTL        = 300
	defaultUpstreamServers = "8.8.8.8:53,1.1.1.1:53"
	defaultUpstreamTimeout = "3s"
	defaultServerName      = "ns1.safeops.local"
	defaultEnableEDNS      = true
)

// Config holds DNS Server configuration.
type Config struct {
	BindAddress     string
	CacheSize       int
	CacheTTL        uint32
	UpstreamServers []string
	UpstreamTimeout time.Duration
	ServerName      string
	EnableEDNS      bool
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

func main() {
	// Setup logging
	setupLogging()

	log.Println("Starting DNS Server...")

	// Load configuration
	cfg := loadConfiguration()
	logConfiguration(cfg)

	// Initialize all components
	server, err := initializeComponents(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize DNS Server: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the UDP server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			errChan <- err
		}
	}()

	log.Printf("DNS Server running on %s", cfg.BindAddress)
	log.Println("Press Ctrl+C to stop")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v", sig)
	case err := <-errChan:
		log.Printf("Server error: %v", err)
	}

	log.Println("Initiating graceful shutdown...")

	// Shutdown server
	if err := server.Shutdown(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("DNS Server stopped")
}

// =============================================================================
// CONFIGURATION
// =============================================================================

// loadConfiguration reads configuration from environment variables with defaults.
func loadConfiguration() *Config {
	cfg := &Config{
		BindAddress:     getEnvOrDefault("DNS_BIND_ADDRESS", defaultBindAddress),
		CacheSize:       getEnvIntOrDefault("DNS_CACHE_SIZE", defaultCacheSize),
		CacheTTL:        uint32(getEnvIntOrDefault("DNS_DEFAULT_TTL", defaultCacheTTL)),
		UpstreamServers: getEnvSliceOrDefault("DNS_UPSTREAM_SERVERS", defaultUpstreamServers),
		UpstreamTimeout: getEnvDurationOrDefault("DNS_UPSTREAM_TIMEOUT", defaultUpstreamTimeout),
		ServerName:      getEnvOrDefault("DNS_SERVER_NAME", defaultServerName),
		EnableEDNS:      getEnvBoolOrDefault("DNS_ENABLE_EDNS", defaultEnableEDNS),
	}

	// Validate configuration
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = defaultCacheSize
	}
	if len(cfg.UpstreamServers) == 0 {
		cfg.UpstreamServers = strings.Split(defaultUpstreamServers, ",")
	}
	if cfg.UpstreamTimeout <= 0 {
		cfg.UpstreamTimeout = 3 * time.Second
	}

	return cfg
}

// logConfiguration logs loaded configuration values.
func logConfiguration(cfg *Config) {
	log.Println("Configuration loaded:")
	log.Printf("  Bind Address:     %s", cfg.BindAddress)
	log.Printf("  Cache Size:       %d entries", cfg.CacheSize)
	log.Printf("  Default TTL:      %d seconds", cfg.CacheTTL)
	log.Printf("  Upstream Servers: %v", cfg.UpstreamServers)
	log.Printf("  Upstream Timeout: %v", cfg.UpstreamTimeout)
	log.Printf("  Server Name:      %s", cfg.ServerName)
	log.Printf("  EDNS Enabled:     %v", cfg.EnableEDNS)
}

// =============================================================================
// COMPONENT INITIALIZATION
// =============================================================================

// initializeComponents creates and wires all DNS Server components.
func initializeComponents(cfg *Config) (*dns.UDPServer, error) {
	// Create cache (50,000 entries)
	cache := dns.NewDNSCache(cfg.CacheSize)
	log.Printf("Initialized DNS cache (max %d entries)", cfg.CacheSize)

	// Create zone resolver (Phase 1: stub that always returns false)
	zoneResolver := dns.NewZoneResolver()
	log.Println("Initialized zone resolver (Phase 1: recursive-only mode)")

	// Create upstream resolver
	upstreamResolver := recursive.NewUpstreamResolver(cfg.UpstreamServers, cfg.UpstreamTimeout)
	log.Printf("Initialized upstream resolver (%v)", cfg.UpstreamServers)

	// Create response builder
	responseBuilder := dns.NewResponseBuilder(cfg.ServerName, cfg.CacheTTL, cfg.EnableEDNS)
	log.Println("Initialized response builder")

	// Create UDP server with all dependencies
	server := dns.NewUDPServer(
		cfg.BindAddress,
		cache,
		zoneResolver,
		upstreamResolver,
		responseBuilder,
	)
	log.Println("Initialized UDP server")

	log.Println("All components initialized successfully")
	return server, nil
}

// =============================================================================
// LOGGING SETUP
// =============================================================================

// setupLogging configures log output format.
func setupLogging() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stdout)
}

// =============================================================================
// ENVIRONMENT VARIABLE HELPERS
// =============================================================================

// getEnvOrDefault returns environment variable value or default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvIntOrDefault returns parsed int environment variable or default.
func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getEnvSliceOrDefault returns comma-separated environment variable as slice.
func getEnvSliceOrDefault(key, defaultValue string) []string {
	value := getEnvOrDefault(key, defaultValue)
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// getEnvDurationOrDefault returns parsed duration environment variable or default.
func getEnvDurationOrDefault(key, defaultValue string) time.Duration {
	value := getEnvOrDefault(key, defaultValue)
	if parsed, err := time.ParseDuration(value); err == nil {
		return parsed
	}
	if defaultParsed, err := time.ParseDuration(defaultValue); err == nil {
		return defaultParsed
	}
	return 3 * time.Second
}

// getEnvBoolOrDefault returns parsed bool environment variable or default.
func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		lower := strings.ToLower(value)
		return lower == "true" || lower == "1" || lower == "yes"
	}
	return defaultValue
}
