// Package main is the DNS Server application entry point.
// Phase 3A: Includes TLS Proxy integration for DNS decision handling.
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
	defaultBindAddress      = ":53"
	defaultCacheSize        = 50000
	defaultCacheTTL         = 300
	defaultUpstreamServers  = "8.8.8.8:53,1.1.1.1:53"
	defaultUpstreamTimeout  = "3s"
	defaultServerName       = "ns1.safeops.local"
	defaultEnableEDNS       = true
	// Phase 3A: TLS Proxy integration
	defaultTLSProxyAddress  = "localhost:50052"
	defaultTLSProxyTimeout  = "2s"
	defaultTLSProxyEnabled  = true
)

// Config holds DNS Server configuration.
type Config struct {
	BindAddress      string
	CacheSize        int
	CacheTTL         uint32
	UpstreamServers  []string
	UpstreamTimeout  time.Duration
	ServerName       string
	EnableEDNS       bool
	// Phase 3A: TLS Proxy settings
	TLSProxyAddress  string
	TLSProxyTimeout  time.Duration
	TLSProxyEnabled  bool
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

func main() {
	setupLogging()

	log.Println("Starting DNS Server (Phase 3A with TLS Proxy integration)...")

	cfg := loadConfiguration()
	logConfiguration(cfg)

	server, tlsProxyResolver, err := initializeComponents(cfg)
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
	if cfg.TLSProxyEnabled && tlsProxyResolver != nil && tlsProxyResolver.IsEnabled() {
		log.Printf("TLS Proxy integration: ENABLED (%s)", cfg.TLSProxyAddress)
	} else {
		log.Println("TLS Proxy integration: DISABLED")
	}
	log.Println("Press Ctrl+C to stop")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v", sig)
	case err := <-errChan:
		log.Printf("Server error: %v", err)
	}

	log.Println("Initiating graceful shutdown...")

	// Shutdown components
	if tlsProxyResolver != nil {
		tlsProxyResolver.Close()
	}
	if err := server.Shutdown(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("DNS Server stopped")
}

// =============================================================================
// CONFIGURATION
// =============================================================================

func loadConfiguration() *Config {
	cfg := &Config{
		BindAddress:      getEnvOrDefault("DNS_BIND_ADDRESS", defaultBindAddress),
		CacheSize:        getEnvIntOrDefault("DNS_CACHE_SIZE", defaultCacheSize),
		CacheTTL:         uint32(getEnvIntOrDefault("DNS_DEFAULT_TTL", defaultCacheTTL)),
		UpstreamServers:  getEnvSliceOrDefault("DNS_UPSTREAM_SERVERS", defaultUpstreamServers),
		UpstreamTimeout:  getEnvDurationOrDefault("DNS_UPSTREAM_TIMEOUT", defaultUpstreamTimeout),
		ServerName:       getEnvOrDefault("DNS_SERVER_NAME", defaultServerName),
		EnableEDNS:       getEnvBoolOrDefault("DNS_ENABLE_EDNS", defaultEnableEDNS),
		// Phase 3A
		TLSProxyAddress:  getEnvOrDefault("DNS_TLS_PROXY_ADDRESS", defaultTLSProxyAddress),
		TLSProxyTimeout:  getEnvDurationOrDefault("DNS_TLS_PROXY_TIMEOUT", defaultTLSProxyTimeout),
		TLSProxyEnabled:  getEnvBoolOrDefault("DNS_TLS_PROXY_ENABLED", defaultTLSProxyEnabled),
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
	if cfg.TLSProxyTimeout <= 0 {
		cfg.TLSProxyTimeout = 2 * time.Second
	}

	return cfg
}

func logConfiguration(cfg *Config) {
	log.Println("Configuration loaded:")
	log.Printf("  Bind Address:      %s", cfg.BindAddress)
	log.Printf("  Cache Size:        %d entries", cfg.CacheSize)
	log.Printf("  Default TTL:       %d seconds", cfg.CacheTTL)
	log.Printf("  Upstream Servers:  %v", cfg.UpstreamServers)
	log.Printf("  Upstream Timeout:  %v", cfg.UpstreamTimeout)
	log.Printf("  Server Name:       %s", cfg.ServerName)
	log.Printf("  EDNS Enabled:      %v", cfg.EnableEDNS)
	log.Printf("  TLS Proxy Enabled: %v", cfg.TLSProxyEnabled)
	if cfg.TLSProxyEnabled {
		log.Printf("  TLS Proxy Address: %s", cfg.TLSProxyAddress)
		log.Printf("  TLS Proxy Timeout: %v", cfg.TLSProxyTimeout)
	}
}

// =============================================================================
// COMPONENT INITIALIZATION
// =============================================================================

func initializeComponents(cfg *Config) (interface{ Start() error; Shutdown() error }, *dns.TLSProxyResolver, error) {
	// Phase 3A: Create TLS Proxy resolver (optional)
	var tlsProxyResolver *dns.TLSProxyResolver
	var err error

	if cfg.TLSProxyEnabled {
		tlsProxyResolver, err = dns.NewTLSProxyResolver(cfg.TLSProxyAddress, cfg.TLSProxyTimeout)
		if err != nil {
			log.Printf("WARNING: TLS Proxy connection failed: %v", err)
			log.Println("Continuing without TLS Proxy integration")
			tlsProxyResolver = nil
		}
	} else {
		log.Println("TLS Proxy integration disabled (DNS_TLS_PROXY_ENABLED=false)")
	}

	// Create cache
	cache := dns.NewDNSCache(cfg.CacheSize)
	log.Printf("Initialized DNS cache (max %d entries)", cfg.CacheSize)

	// Create zone resolver (Phase 1: stub that always returns false)
	zoneResolver := dns.NewZoneResolver()
	log.Println("Initialized zone resolver (recursive-only mode)")

	// Create upstream resolver
	upstreamResolver := recursive.NewUpstreamResolver(cfg.UpstreamServers, cfg.UpstreamTimeout)
	log.Printf("Initialized upstream resolver (%v)", cfg.UpstreamServers)

	// Create response builder
	responseBuilder := dns.NewResponseBuilder(cfg.ServerName, cfg.CacheTTL, cfg.EnableEDNS)
	log.Println("Initialized response builder")

	// Create base UDP server with all dependencies
	baseServer := dns.NewUDPServer(
		cfg.BindAddress,
		cache,
		zoneResolver,
		upstreamResolver,
		responseBuilder,
	)

	// Phase 3A: Wrap with TLS Proxy integration if enabled
	var server interface{ Start() error; Shutdown() error }
	if tlsProxyResolver != nil && tlsProxyResolver.IsEnabled() {
		server = dns.NewUDPServerWithTLSProxy(baseServer, tlsProxyResolver)
		log.Println("Initialized UDP server WITH TLS Proxy integration")
	} else {
		server = baseServer
		log.Println("Initialized UDP server (standard mode)")
	}

	log.Println("All components initialized successfully")
	return server, tlsProxyResolver, nil
}

// =============================================================================
// LOGGING SETUP
// =============================================================================

func setupLogging() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stdout)
}

// =============================================================================
// ENVIRONMENT VARIABLE HELPERS
// =============================================================================

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

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

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		lower := strings.ToLower(value)
		return lower == "true" || lower == "1" || lower == "yes"
	}
	return defaultValue
}
