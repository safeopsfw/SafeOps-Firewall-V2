// Package config provides configuration loading and validation for DHCP server.
// This file implements comprehensive DHCP server configuration management.
package config

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

// ============================================================================
// Configuration Structures
// ============================================================================

// Config is the root configuration structure.
type Config struct {
	Service        ServiceConfig        `toml:"service"`
	Pools          []PoolConfig         `toml:"pools"`
	Reservations   []ReservationConfig  `toml:"reservations"`
	DNSIntegration DNSIntegrationConfig `toml:"dns_integration"`
	CAIntegration  CAIntegrationConfig  `toml:"ca_integration"`
	Monitoring     MonitoringConfig     `toml:"monitoring"`
	API            APIConfig            `toml:"api"`
	Database       DatabaseConfig       `toml:"database"`
}

// ServiceConfig contains general service settings.
type ServiceConfig struct {
	Name          string   `toml:"name"`
	Interfaces    []string `toml:"interfaces"`
	ListenAddress string   `toml:"listen_address"`
	ListenPort    int      `toml:"listen_port"`
	EnableIPv6    bool     `toml:"enable_ipv6"`
}

// PoolConfig contains DHCP pool settings.
type PoolConfig struct {
	Name        string        `toml:"name"`
	Subnet      string        `toml:"subnet"`
	RangeStart  string        `toml:"range_start"`
	RangeEnd    string        `toml:"range_end"`
	Gateway     string        `toml:"gateway"`
	DNSServers  []string      `toml:"dns_servers"`
	DomainName  string        `toml:"domain_name"`
	LeaseTime   time.Duration `toml:"lease_time"`
	ExcludedIPs []string      `toml:"excluded_ips"`
}

// ReservationConfig contains static reservation settings.
type ReservationConfig struct {
	MACAddress string `toml:"mac_address"`
	IPAddress  string `toml:"ip_address"`
	Hostname   string `toml:"hostname"`
	Pool       string `toml:"pool"`
}

// DNSIntegrationConfig contains DNS integration settings.
type DNSIntegrationConfig struct {
	Enabled       bool          `toml:"enabled"`
	GRPCAddress   string        `toml:"grpc_address"`
	Timeout       time.Duration `toml:"timeout"`
	RetryAttempts int           `toml:"retry_attempts"`
}

// CAIntegrationConfig contains CA integration settings.
type CAIntegrationConfig struct {
	Enabled     bool          `toml:"enabled"`
	GRPCAddress string        `toml:"grpc_address"`
	CacheTTL    time.Duration `toml:"cache_ttl"`
	Timeout     time.Duration `toml:"timeout"`
}

// MonitoringConfig contains monitoring settings.
type MonitoringConfig struct {
	MetricsPort     int    `toml:"metrics_port"`
	MetricsPath     string `toml:"metrics_path"`
	HealthPort      int    `toml:"health_port"`
	EnableProfiling bool   `toml:"enable_profiling"`
}

// APIConfig contains gRPC API settings.
type APIConfig struct {
	GRPCPort         int    `toml:"grpc_port"`
	EnableTLS        bool   `toml:"enable_tls"`
	TLSCertPath      string `toml:"tls_cert_path"`
	TLSKeyPath       string `toml:"tls_key_path"`
	TLSCAPath        string `toml:"tls_ca_path"`
	EnableReflection bool   `toml:"enable_reflection"`
}

// DatabaseConfig contains database settings.
type DatabaseConfig struct {
	Host           string `toml:"host"`
	Port           int    `toml:"port"`
	Database       string `toml:"database"`
	User           string `toml:"user"`
	Password       string `toml:"password"`
	SSLMode        string `toml:"ssl_mode"`
	MaxConnections int    `toml:"max_connections"`
}

// ============================================================================
// Default Configuration
// ============================================================================

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Service: ServiceConfig{
			Name:          "dhcp_server",
			ListenAddress: "0.0.0.0",
			ListenPort:    67,
			EnableIPv6:    false,
		},
		Pools:        make([]PoolConfig, 0),
		Reservations: make([]ReservationConfig, 0),
		DNSIntegration: DNSIntegrationConfig{
			Enabled:       true,
			GRPCAddress:   "localhost:50053",
			Timeout:       5 * time.Second,
			RetryAttempts: 3,
		},
		CAIntegration: CAIntegrationConfig{
			Enabled:     true,
			GRPCAddress: "localhost:50056",
			CacheTTL:    time.Hour,
			Timeout:     5 * time.Second,
		},
		Monitoring: MonitoringConfig{
			MetricsPort:     9154,
			MetricsPath:     "/metrics",
			HealthPort:      8067,
			EnableProfiling: false,
		},
		API: APIConfig{
			GRPCPort:         50054,
			EnableTLS:        false,
			EnableReflection: false,
		},
		Database: DatabaseConfig{
			Host:           "localhost",
			Port:           5432,
			Database:       "dhcp_server",
			User:           "dhcp_user",
			SSLMode:        "require",
			MaxConnections: 25,
		},
	}
}

// ============================================================================
// Configuration Loading
// ============================================================================

// LoadConfig loads configuration from a file path.
func LoadConfig(configPath string) (*Config, error) {
	// Start with defaults
	config := DefaultConfig()

	// Read file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// Parse TOML (simplified - in production use go-toml)
	if err := parseConfigData(data, config); err != nil {
		return nil, err
	}

	// Expand environment variables
	config.expandEnvVars()

	// Apply defaults for missing values
	config.ApplyDefaults()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// parseConfigData parses config from bytes (simplified TOML parsing)
func parseConfigData(data []byte, _ *Config) error {
	// In production, use github.com/pelletier/go-toml
	// This is a placeholder that just validates the data exists
	if len(data) == 0 {
		return ErrEmptyConfig
	}
	return nil
}

// ============================================================================
// Environment Variable Expansion
// ============================================================================

func (c *Config) expandEnvVars() {
	// Expand database password
	c.Database.Password = expandEnvVar(c.Database.Password)

	// Expand TLS paths
	c.API.TLSCertPath = expandEnvVar(c.API.TLSCertPath)
	c.API.TLSKeyPath = expandEnvVar(c.API.TLSKeyPath)
	c.API.TLSCAPath = expandEnvVar(c.API.TLSCAPath)
}

func expandEnvVar(value string) string {
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		varName := value[2 : len(value)-1]
		return os.Getenv(varName)
	}
	return value
}

// ============================================================================
// Default Value Application
// ============================================================================

// ApplyDefaults fills in missing configuration with defaults.
func (c *Config) ApplyDefaults() {
	defaults := DefaultConfig()

	// Service defaults
	if c.Service.Name == "" {
		c.Service.Name = defaults.Service.Name
	}
	if c.Service.ListenAddress == "" {
		c.Service.ListenAddress = defaults.Service.ListenAddress
	}
	if c.Service.ListenPort == 0 {
		c.Service.ListenPort = defaults.Service.ListenPort
	}

	// DNS integration defaults
	if c.DNSIntegration.Timeout == 0 {
		c.DNSIntegration.Timeout = defaults.DNSIntegration.Timeout
	}
	if c.DNSIntegration.RetryAttempts == 0 {
		c.DNSIntegration.RetryAttempts = defaults.DNSIntegration.RetryAttempts
	}

	// CA integration defaults
	if c.CAIntegration.CacheTTL == 0 {
		c.CAIntegration.CacheTTL = defaults.CAIntegration.CacheTTL
	}
	if c.CAIntegration.Timeout == 0 {
		c.CAIntegration.Timeout = defaults.CAIntegration.Timeout
	}

	// Monitoring defaults
	if c.Monitoring.MetricsPort == 0 {
		c.Monitoring.MetricsPort = defaults.Monitoring.MetricsPort
	}
	if c.Monitoring.MetricsPath == "" {
		c.Monitoring.MetricsPath = defaults.Monitoring.MetricsPath
	}
	if c.Monitoring.HealthPort == 0 {
		c.Monitoring.HealthPort = defaults.Monitoring.HealthPort
	}

	// API defaults
	if c.API.GRPCPort == 0 {
		c.API.GRPCPort = defaults.API.GRPCPort
	}

	// Database defaults
	if c.Database.Port == 0 {
		c.Database.Port = defaults.Database.Port
	}
	if c.Database.SSLMode == "" {
		c.Database.SSLMode = defaults.Database.SSLMode
	}
	if c.Database.MaxConnections == 0 {
		c.Database.MaxConnections = defaults.Database.MaxConnections
	}

	// Pool defaults
	for i := range c.Pools {
		if c.Pools[i].LeaseTime == 0 {
			c.Pools[i].LeaseTime = 24 * time.Hour
		}
	}
}

// ============================================================================
// Configuration Validation
// ============================================================================

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate pools
	if err := c.validatePools(); err != nil {
		return err
	}

	// Validate reservations
	if err := c.validateReservations(); err != nil {
		return err
	}

	// Validate DNS integration
	if c.DNSIntegration.Enabled {
		if err := c.validateDNSIntegration(); err != nil {
			return err
		}
	}

	// Validate CA integration
	if c.CAIntegration.Enabled {
		if err := c.validateCAIntegration(); err != nil {
			return err
		}
	}

	// Validate API
	if err := c.validateAPI(); err != nil {
		return err
	}

	// Validate database
	if err := c.validateDatabase(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validatePools() error {
	if len(c.Pools) == 0 {
		return ErrNoPoolsConfigured
	}

	poolNames := make(map[string]bool)
	for _, pool := range c.Pools {
		// Check for duplicate pool names
		if poolNames[pool.Name] {
			return ErrDuplicatePoolName
		}
		poolNames[pool.Name] = true

		// Validate pool name
		if pool.Name == "" {
			return ErrInvalidPoolName
		}

		// Validate subnet CIDR
		_, _, err := net.ParseCIDR(pool.Subnet)
		if err != nil {
			return ErrInvalidSubnet
		}

		// Validate range start/end
		rangeStart := net.ParseIP(pool.RangeStart)
		rangeEnd := net.ParseIP(pool.RangeEnd)
		if rangeStart == nil || rangeEnd == nil {
			return ErrInvalidIPRange
		}

		// Validate gateway
		if net.ParseIP(pool.Gateway) == nil {
			return ErrInvalidGateway
		}

		// Validate DNS servers
		for _, dns := range pool.DNSServers {
			if net.ParseIP(dns) == nil {
				return ErrInvalidDNSServer
			}
		}

		// Validate lease time
		if pool.LeaseTime < 5*time.Minute {
			return ErrInvalidLeaseTime
		}
	}

	return nil
}

func (c *Config) validateReservations() error {
	macs := make(map[string]bool)
	ips := make(map[string]bool)

	for _, res := range c.Reservations {
		// Validate MAC
		if _, err := net.ParseMAC(res.MACAddress); err != nil {
			return ErrInvalidMACAddress
		}

		// Check for duplicate MAC
		if macs[res.MACAddress] {
			return ErrDuplicateMAC
		}
		macs[res.MACAddress] = true

		// Validate IP
		if net.ParseIP(res.IPAddress) == nil {
			return ErrInvalidIPAddress
		}

		// Check for duplicate IP
		if ips[res.IPAddress] {
			return ErrDuplicateIP
		}
		ips[res.IPAddress] = true
	}

	return nil
}

func (c *Config) validateDNSIntegration() error {
	if c.DNSIntegration.GRPCAddress == "" {
		return ErrInvalidGRPCAddress
	}
	if c.DNSIntegration.Timeout <= 0 {
		return ErrInvalidTimeout
	}
	return nil
}

func (c *Config) validateCAIntegration() error {
	if c.CAIntegration.GRPCAddress == "" {
		return ErrInvalidGRPCAddress
	}
	if c.CAIntegration.CacheTTL <= 0 {
		return ErrInvalidCacheTTL
	}
	return nil
}

func (c *Config) validateAPI() error {
	if c.API.GRPCPort < 1 || c.API.GRPCPort > 65535 {
		return ErrInvalidPort
	}

	if c.API.EnableTLS {
		if c.API.TLSCertPath == "" || c.API.TLSKeyPath == "" {
			return ErrMissingTLSConfig
		}
	}

	return nil
}

func (c *Config) validateDatabase() error {
	if c.Database.Host == "" {
		return ErrInvalidDBHost
	}
	if c.Database.Port < 1 || c.Database.Port > 65535 {
		return ErrInvalidPort
	}
	if c.Database.Database == "" {
		return ErrInvalidDBName
	}
	if c.Database.MaxConnections < 1 {
		return ErrInvalidMaxConnections
	}
	return nil
}

// ============================================================================
// Configuration Reload
// ============================================================================

// Reload reloads configuration from a file.
func (c *Config) Reload(configPath string) error {
	newConfig, err := LoadConfig(configPath)
	if err != nil {
		return err
	}

	// Update reloadable settings
	c.Pools = newConfig.Pools
	c.Reservations = newConfig.Reservations
	c.DNSIntegration = newConfig.DNSIntegration
	c.CAIntegration = newConfig.CAIntegration

	return nil
}

// ============================================================================
// Configuration Accessors
// ============================================================================

// GetPool returns a pool by name.
func (c *Config) GetPool(name string) *PoolConfig {
	for i := range c.Pools {
		if c.Pools[i].Name == name {
			return &c.Pools[i]
		}
	}
	return nil
}

// GetPoolNames returns all pool names.
func (c *Config) GetPoolNames() []string {
	names := make([]string, len(c.Pools))
	for i, pool := range c.Pools {
		names[i] = pool.Name
	}
	return names
}

// GetReservationByMAC returns a reservation by MAC address.
func (c *Config) GetReservationByMAC(mac string) *ReservationConfig {
	for i := range c.Reservations {
		if c.Reservations[i].MACAddress == mac {
			return &c.Reservations[i]
		}
	}
	return nil
}

// GetDatabaseConnectionString returns a PostgreSQL connection string.
func (c *Config) GetDatabaseConnectionString() string {
	return "host=" + c.Database.Host +
		" port=" + string(rune(c.Database.Port)) +
		" user=" + c.Database.User +
		" password=" + c.Database.Password +
		" dbname=" + c.Database.Database +
		" sslmode=" + c.Database.SSLMode
}

// ============================================================================
// Errors
// ============================================================================

var (
	// General errors
	ErrEmptyConfig    = errors.New("configuration file is empty")
	ErrConfigNotFound = errors.New("configuration file not found")

	// Pool errors
	ErrNoPoolsConfigured = errors.New("at least one pool must be configured")
	ErrDuplicatePoolName = errors.New("duplicate pool name")
	ErrInvalidPoolName   = errors.New("invalid or empty pool name")
	ErrInvalidSubnet     = errors.New("invalid subnet CIDR notation")
	ErrInvalidIPRange    = errors.New("invalid IP range start or end")
	ErrInvalidGateway    = errors.New("invalid gateway IP address")
	ErrInvalidDNSServer  = errors.New("invalid DNS server IP address")
	ErrInvalidLeaseTime  = errors.New("lease time must be at least 5 minutes")
	ErrOverlappingPools  = errors.New("pools have overlapping IP ranges")

	// Reservation errors
	ErrInvalidMACAddress = errors.New("invalid MAC address format")
	ErrInvalidIPAddress  = errors.New("invalid IP address format")
	ErrDuplicateMAC      = errors.New("duplicate MAC address in reservations")
	ErrDuplicateIP       = errors.New("duplicate IP address in reservations")

	// Integration errors
	ErrInvalidGRPCAddress = errors.New("invalid gRPC address")
	ErrInvalidTimeout     = errors.New("timeout must be greater than zero")
	ErrInvalidCacheTTL    = errors.New("cache TTL must be greater than zero")

	// API errors
	ErrInvalidPort      = errors.New("invalid port number")
	ErrMissingTLSConfig = errors.New("TLS enabled but cert/key paths missing")

	// Database errors
	ErrInvalidDBHost         = errors.New("database host cannot be empty")
	ErrInvalidDBName         = errors.New("database name cannot be empty")
	ErrInvalidMaxConnections = errors.New("max connections must be at least 1")
)
