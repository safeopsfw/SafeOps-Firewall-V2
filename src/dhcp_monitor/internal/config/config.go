// Package config provides YAML configuration loading for DHCP Monitor
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete DHCP Monitor configuration
type Config struct {
	Database         DatabaseConfig         `yaml:"database"`
	GRPC             GRPCConfig             `yaml:"grpc"`
	Monitoring       MonitoringConfig       `yaml:"monitoring"`
	DHCPEventLog     DHCPEventLogConfig     `yaml:"dhcp_event_log"`
	DeviceManagement DeviceManagementConfig `yaml:"device_management"`
	Logging          LoggingConfig          `yaml:"logging"`
	Service          ServiceConfig          `yaml:"service"`
}

// DatabaseConfig holds PostgreSQL connection settings
type DatabaseConfig struct {
	Host      string          `yaml:"host"`
	Port      int             `yaml:"port"`
	Name      string          `yaml:"name"`
	User      string          `yaml:"user"`
	Password  string          `yaml:"password"`
	SSLMode   string          `yaml:"sslmode"`
	Pool      PoolConfig      `yaml:"pool"`
	Migration MigrationConfig `yaml:"migration"`
}

// PoolConfig holds connection pool settings
type PoolConfig struct {
	MinConnections    int           `yaml:"min_connections"`
	MaxConnections    int           `yaml:"max_connections"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	MaxLifetime       time.Duration `yaml:"max_lifetime"`
}

// MigrationConfig holds migration behavior settings
type MigrationConfig struct {
	AutoMigrate    bool `yaml:"auto_migrate"`
	ValidateSchema bool `yaml:"validate_schema"`
}

// GRPCConfig holds gRPC server settings
type GRPCConfig struct {
	Host           string          `yaml:"host"`
	Port           int             `yaml:"port"`
	MaxMessageSize int             `yaml:"max_message_size"`
	ConnTimeout    time.Duration   `yaml:"connection_timeout"`
	Keepalive      KeepaliveConfig `yaml:"keepalive"`
	TLS            TLSConfig       `yaml:"tls"`
}

// KeepaliveConfig holds gRPC keepalive settings
type KeepaliveConfig struct {
	Time    time.Duration `yaml:"time"`
	Timeout time.Duration `yaml:"timeout"`
	MinTime time.Duration `yaml:"min_time"`
}

// TLSConfig holds TLS certificate settings
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// MonitoringConfig holds network monitoring settings
type MonitoringConfig struct {
	IPHelper   IPHelperConfig  `yaml:"ip_helper"`
	ARPTable   ARPTableConfig  `yaml:"arp_table"`
	Interfaces InterfaceConfig `yaml:"interfaces"`
	Detection  DetectionConfig `yaml:"detection"`
}

// IPHelperConfig holds Windows IP Helper API settings
type IPHelperConfig struct {
	Enabled         bool          `yaml:"enabled"`
	CallbackTimeout time.Duration `yaml:"callback_timeout"`
}

// ARPTableConfig holds ARP monitoring settings
type ARPTableConfig struct {
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	PollInterval    time.Duration `yaml:"poll_interval"`
	CacheDuration   time.Duration `yaml:"cache_duration"`
}

// InterfaceConfig holds interface filtering settings
type InterfaceConfig struct {
	IncludePatterns []string `yaml:"include_patterns"`
	ExcludePatterns []string `yaml:"exclude_patterns"`
}

// DetectionConfig holds detection method settings
type DetectionConfig struct {
	PrimaryMethod      string        `yaml:"primary_method"`
	SecondaryMethod    string        `yaml:"secondary_method"`
	DedupCacheDuration time.Duration `yaml:"dedup_cache_duration"`
	DedupCacheMaxSize  int           `yaml:"dedup_cache_max_size"`
}

// DHCPEventLogConfig holds DHCP Event Log monitoring settings
type DHCPEventLogConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Channel      string        `yaml:"channel"`
	PollInterval time.Duration `yaml:"poll_interval"`
	EventIDs     []int         `yaml:"event_ids"`
}

// DeviceManagementConfig holds device management settings
type DeviceManagementConfig struct {
	Status         StatusConfig         `yaml:"status"`
	Cleanup        CleanupConfig        `yaml:"cleanup"`
	IPHistory      IPHistoryConfig      `yaml:"ip_history"`
	UnknownDevices UnknownDevicesConfig `yaml:"unknown_devices"`
}

// StatusConfig holds device status settings
type StatusConfig struct {
	InactiveTimeout time.Duration `yaml:"inactive_timeout"`
	ExpiredTimeout  time.Duration `yaml:"expired_timeout"`
}

// CleanupConfig holds cleanup policy settings
type CleanupConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Interval          time.Duration `yaml:"interval"`
	PurgeExpiredAfter time.Duration `yaml:"purge_expired_after"`
}

// IPHistoryConfig holds IP history retention settings
type IPHistoryConfig struct {
	RetentionDays       int `yaml:"retention_days"`
	MaxEntriesPerDevice int `yaml:"max_entries_per_device"`
}

// UnknownDevicesConfig holds unknown device handling settings
type UnknownDevicesConfig struct {
	AutoCreate         bool   `yaml:"auto_create"`
	DefaultTrustStatus string `yaml:"default_trust_status"`
	DefaultDeviceType  string `yaml:"default_device_type"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level      string            `yaml:"level"`
	Output     OutputConfig      `yaml:"output"`
	Format     string            `yaml:"format"`
	Components map[string]string `yaml:"components"`
}

// OutputConfig holds log output settings
type OutputConfig struct {
	Stdout bool       `yaml:"stdout"`
	File   FileConfig `yaml:"file"`
}

// FileConfig holds log file settings
type FileConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Path     string         `yaml:"path"`
	Rotation RotationConfig `yaml:"rotation"`
}

// RotationConfig holds log rotation settings
type RotationConfig struct {
	MaxSizeMB  int  `yaml:"max_size_mb"`
	MaxAgeDays int  `yaml:"max_age_days"`
	MaxBackups int  `yaml:"max_backups"`
	Compress   bool `yaml:"compress"`
}

// ServiceConfig holds service behavior settings
type ServiceConfig struct {
	Name     string         `yaml:"name"`
	Version  string         `yaml:"version"`
	Startup  StartupConfig  `yaml:"startup"`
	Shutdown ShutdownConfig `yaml:"shutdown"`
	Health   HealthConfig   `yaml:"health"`
	Metrics  MetricsConfig  `yaml:"metrics"`
}

// StartupConfig holds startup behavior settings
type StartupConfig struct {
	ValidateDatabase   bool `yaml:"validate_database"`
	ValidateInterfaces bool `yaml:"validate_interfaces"`
	FailFast           bool `yaml:"fail_fast"`
}

// ShutdownConfig holds shutdown behavior settings
type ShutdownConfig struct {
	Timeout          time.Duration `yaml:"timeout"`
	DrainConnections bool          `yaml:"drain_connections"`
}

// HealthConfig holds health check settings
type HealthConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

// MetricsConfig holds Prometheus metrics settings
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// LoadConfig reads and parses the YAML configuration file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Substitute environment variables
	content := substituteEnvVars(string(data))

	config := &Config{}
	if err := yaml.Unmarshal([]byte(content), config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Apply defaults
	applyDefaults(config)

	return config, nil
}

// substituteEnvVars replaces ${VAR} and ${VAR:-default} with environment values
func substituteEnvVars(content string) string {
	// Pattern: ${VAR:-default} or ${VAR}
	re := regexp.MustCompile(`\$\{([^}:]+)(?::-([^}]*))?\}`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}

		varName := parts[1]
		defaultVal := ""
		if len(parts) >= 3 {
			defaultVal = parts[2]
		}

		if val := os.Getenv(varName); val != "" {
			return val
		}
		return defaultVal
	})
}

// applyDefaults sets default values for unset configuration options
func applyDefaults(c *Config) {
	// Database defaults
	if c.Database.Host == "" {
		c.Database.Host = "localhost"
	}
	if c.Database.Port == 0 {
		c.Database.Port = 5432
	}
	if c.Database.Name == "" {
		c.Database.Name = "safeops_network"
	}
	if c.Database.SSLMode == "" {
		c.Database.SSLMode = "disable"
	}
	if c.Database.Pool.MaxConnections == 0 {
		c.Database.Pool.MaxConnections = 25
	}
	if c.Database.Pool.MinConnections == 0 {
		c.Database.Pool.MinConnections = 5
	}
	if c.Database.Pool.ConnectionTimeout == 0 {
		c.Database.Pool.ConnectionTimeout = 10 * time.Second
	}

	// gRPC defaults
	if c.GRPC.Port == 0 {
		c.GRPC.Port = 50055
	}
	if c.GRPC.Host == "" {
		c.GRPC.Host = "0.0.0.0"
	}

	// Logging defaults
	if c.Logging.Level == "" {
		c.Logging.Level = "INFO"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}

	// Service defaults
	if c.Service.Name == "" {
		c.Service.Name = "dhcp_monitor"
	}
	if c.Service.Shutdown.Timeout == 0 {
		c.Service.Shutdown.Timeout = 30 * time.Second
	}
}

// Validate checks configuration for required values and validity
func (c *Config) Validate() error {
	var errs []string

	// Database validation
	if c.Database.User == "" {
		errs = append(errs, "database.user is required")
	}
	if c.Database.Password == "" {
		errs = append(errs, "database.password is required (set via DB_PASSWORD env var)")
	}
	if c.Database.Port < 1 || c.Database.Port > 65535 {
		errs = append(errs, "database.port must be between 1 and 65535")
	}
	if c.Database.Pool.MaxConnections < c.Database.Pool.MinConnections {
		errs = append(errs, "database.pool.max_connections must be >= min_connections")
	}

	// gRPC validation
	if c.GRPC.Port < 1 || c.GRPC.Port > 65535 {
		errs = append(errs, "grpc.port must be between 1 and 65535")
	}
	if c.GRPC.TLS.Enabled {
		if c.GRPC.TLS.CertFile == "" {
			errs = append(errs, "grpc.tls.cert_file is required when TLS is enabled")
		}
		if c.GRPC.TLS.KeyFile == "" {
			errs = append(errs, "grpc.tls.key_file is required when TLS is enabled")
		}
	}

	// Device management validation
	if c.DeviceManagement.Cleanup.Enabled {
		if c.DeviceManagement.Cleanup.Interval <= 0 {
			errs = append(errs, "device_management.cleanup.interval must be > 0")
		}
	}

	// Logging validation
	level := strings.ToUpper(c.Logging.Level)
	if level != "DEBUG" && level != "INFO" && level != "WARN" && level != "ERROR" {
		errs = append(errs, "logging.level must be DEBUG, INFO, WARN, or ERROR")
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

// GetDatabaseDSN returns the PostgreSQL connection string
func (c *Config) GetDatabaseDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
		c.Database.SSLMode,
	)
}

// GetGRPCAddress returns the gRPC server bind address
func (c *Config) GetGRPCAddress() string {
	return fmt.Sprintf("%s:%d", c.GRPC.Host, c.GRPC.Port)
}

// String returns a sanitized string representation of the config
func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{Database: %s:%d/%s, GRPC: %s:%d, Logging: %s}",
		c.Database.Host, c.Database.Port, c.Database.Name,
		c.GRPC.Host, c.GRPC.Port,
		c.Logging.Level,
	)
}

// GetCleanupInterval returns the cleanup interval duration
func (c *Config) GetCleanupInterval() time.Duration {
	if c.DeviceManagement.Cleanup.Interval > 0 {
		return c.DeviceManagement.Cleanup.Interval
	}
	return 5 * time.Minute
}

// GetInactiveTimeout returns the inactive timeout duration
func (c *Config) GetInactiveTimeout() time.Duration {
	if c.DeviceManagement.Status.InactiveTimeout > 0 {
		return c.DeviceManagement.Status.InactiveTimeout
	}
	return 10 * time.Minute
}

// GetShutdownTimeout returns the shutdown timeout duration
func (c *Config) GetShutdownTimeout() time.Duration {
	if c.Service.Shutdown.Timeout > 0 {
		return c.Service.Shutdown.Timeout
	}
	return 30 * time.Second
}

// IsAutoMigrate returns whether auto migration is enabled
func (c *Config) IsAutoMigrate() bool {
	return c.Database.Migration.AutoMigrate
}
