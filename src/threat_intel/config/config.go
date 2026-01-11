package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ==========================================================================
// Main Configuration Structures
// ==========================================================================

// Config holds all application configuration
type Config struct {
	Database    DatabaseConfig    `yaml:"database"`
	API         APIConfig         `yaml:"api"`
	Worker      WorkerConfig      `yaml:"worker"`
	Storage     StorageConfig     `yaml:"storage"`
	Logging     LogConfig         `yaml:"logging"`
	Performance PerformanceConfig `yaml:"performance"`
	Monitoring  MonitoringConfig  `yaml:"monitoring"`
}

// DatabaseConfig holds PostgreSQL connection settings
type DatabaseConfig struct {
	Host               string `yaml:"host"`
	Port               int    `yaml:"port"`
	Database           string `yaml:"database"`
	User               string `yaml:"user"`
	Password           string `yaml:"password"`
	SSLMode            string `yaml:"sslmode"`
	MaxConnections     int    `yaml:"max_connections"`
	MaxIdleConnections int    `yaml:"max_idle_connections"`
	ConnectionLifetime int    `yaml:"connection_lifetime"` // minutes
}

// APIConfig holds API server settings
type APIConfig struct {
	Host         string   `yaml:"host"`
	Port         int      `yaml:"port"`
	EnableCORS   bool     `yaml:"enable_cors"`
	CORSOrigins  []string `yaml:"cors_origins"`
	RateLimit    int      `yaml:"rate_limit"`
	EnableAuth   bool     `yaml:"enable_auth"`
	AuthType     string   `yaml:"auth_type"`
	AuthSecret   string   `yaml:"auth_secret"`
	ReadTimeout  int      `yaml:"read_timeout"`
	WriteTimeout int      `yaml:"write_timeout"`
	IdleTimeout  int      `yaml:"idle_timeout"`
}

// WorkerConfig holds background worker settings
type WorkerConfig struct {
	Enabled         bool `yaml:"enabled"`
	ConcurrentJobs  int  `yaml:"concurrent_jobs"`
	RetryAttempts   int  `yaml:"retry_attempts"`
	RetryDelay      int  `yaml:"retry_delay"`      // seconds
	JobTimeout      int  `yaml:"job_timeout"`      // seconds
	CleanupInterval int  `yaml:"cleanup_interval"` // hours
	CleanupAgeDays  int  `yaml:"cleanup_age_days"`
}

// StorageConfig holds file storage settings
type StorageConfig struct {
	BasePath      string `yaml:"base_path"`
	CreateSubdirs bool   `yaml:"create_subdirs"`
	MaxFileSize   int    `yaml:"max_file_size"` // MB
	Compression   bool   `yaml:"compression"`
	RetentionDays int    `yaml:"retention_days"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	FilePath   string `yaml:"file_path"`
	MaxSize    int    `yaml:"max_size"` // MB
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"` // days
	Compress   bool   `yaml:"compress"`
}

// PerformanceConfig holds performance tuning settings
type PerformanceConfig struct {
	BatchSize       int  `yaml:"batch_size"`
	BufferSize      int  `yaml:"buffer_size"` // MB
	ParallelParsers int  `yaml:"parallel_parsers"`
	EnableCaching   bool `yaml:"enable_caching"`
	CacheTTL        int  `yaml:"cache_ttl"` // seconds
}

// MonitoringConfig holds metrics and health check settings
type MonitoringConfig struct {
	EnableMetrics       bool `yaml:"enable_metrics"`
	MetricsPort         int  `yaml:"metrics_port"`
	HealthCheckInterval int  `yaml:"health_check_interval"` // seconds
}

// ==========================================================================
// Feed Source Structures
// ==========================================================================

// FeedSource represents a threat intelligence feed
type FeedSource struct {
	Name            string                 `yaml:"name"`
	Category        string                 `yaml:"category"`
	URL             string                 `yaml:"url"`
	Format          string                 `yaml:"format"`
	Enabled         bool                   `yaml:"enabled"`
	UpdateFrequency int                    `yaml:"update_frequency"` // seconds
	Description     string                 `yaml:"description"`
	AuthRequired    bool                   `yaml:"auth_required"`
	AuthType        string                 `yaml:"auth_type"`
	ParserConfig    map[string]interface{} `yaml:"parser_config,omitempty"`
}

// FeedsConfig holds all feed sources
type FeedsConfig struct {
	Feeds []FeedSource `yaml:"feeds"`
}

// ==========================================================================
// Configuration Loading Functions
// ==========================================================================

// LoadConfig loads and validates the main configuration file
func LoadConfig(configPath string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	// Read file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	// Apply defaults
	applyDefaults(&cfg)

	// Override with environment variables
	applyEnvOverrides(&cfg)

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// LoadSources loads threat intelligence feed definitions
func LoadSources(sourcesPath string) ([]FeedSource, error) {
	// Check if file exists
	if _, err := os.Stat(sourcesPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("sources file not found: %s", sourcesPath)
	}

	// Read file
	data, err := os.ReadFile(sourcesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read sources file: %w", err)
	}

	// Parse YAML
	var feedsConfig FeedsConfig
	if err := yaml.Unmarshal(data, &feedsConfig); err != nil {
		return nil, fmt.Errorf("failed to parse sources YAML: %w", err)
	}

	// Validate each feed
	for i, feed := range feedsConfig.Feeds {
		if err := validateFeedSource(&feed); err != nil {
			return nil, fmt.Errorf("invalid feed source at index %d (%s): %w", i, feed.Name, err)
		}
	}

	return feedsConfig.Feeds, nil
}

// LoadEnabledSources loads only enabled feed sources
func LoadEnabledSources(sourcesPath string) ([]FeedSource, error) {
	allSources, err := LoadSources(sourcesPath)
	if err != nil {
		return nil, err
	}

	var enabled []FeedSource
	for _, source := range allSources {
		if source.Enabled {
			enabled = append(enabled, source)
		}
	}

	return enabled, nil
}

// ==========================================================================
// Default Value Application
// ==========================================================================

func applyDefaults(cfg *Config) {
	// Database defaults
	if cfg.Database.Port == 0 {
		cfg.Database.Port = 5432
	}
	if cfg.Database.MaxConnections == 0 {
		cfg.Database.MaxConnections = 25
	}
	if cfg.Database.MaxIdleConnections == 0 {
		cfg.Database.MaxIdleConnections = 5
	}
	if cfg.Database.ConnectionLifetime == 0 {
		cfg.Database.ConnectionLifetime = 30
	}
	if cfg.Database.SSLMode == "" {
		cfg.Database.SSLMode = "disable"
	}

	// API defaults
	if cfg.API.Port == 0 {
		cfg.API.Port = 8080
	}
	if cfg.API.Host == "" {
		cfg.API.Host = "0.0.0.0"
	}
	if cfg.API.RateLimit == 0 {
		cfg.API.RateLimit = 100
	}
	if cfg.API.ReadTimeout == 0 {
		cfg.API.ReadTimeout = 30
	}
	if cfg.API.WriteTimeout == 0 {
		cfg.API.WriteTimeout = 30
	}
	if cfg.API.IdleTimeout == 0 {
		cfg.API.IdleTimeout = 60
	}

	// Worker defaults
	if cfg.Worker.ConcurrentJobs == 0 {
		cfg.Worker.ConcurrentJobs = 5
	}
	if cfg.Worker.RetryAttempts == 0 {
		cfg.Worker.RetryAttempts = 3
	}
	if cfg.Worker.RetryDelay == 0 {
		cfg.Worker.RetryDelay = 60
	}
	if cfg.Worker.JobTimeout == 0 {
		cfg.Worker.JobTimeout = 300
	}
	if cfg.Worker.CleanupInterval == 0 {
		cfg.Worker.CleanupInterval = 24
	}
	if cfg.Worker.CleanupAgeDays == 0 {
		cfg.Worker.CleanupAgeDays = 7
	}

	// Storage defaults
	if cfg.Storage.BasePath == "" {
		cfg.Storage.BasePath = "./feeds/"
	}
	if cfg.Storage.MaxFileSize == 0 {
		cfg.Storage.MaxFileSize = 500
	}
	if cfg.Storage.RetentionDays == 0 {
		cfg.Storage.RetentionDays = 7
	}

	// Logging defaults
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
	if cfg.Logging.MaxSize == 0 {
		cfg.Logging.MaxSize = 100
	}
	if cfg.Logging.MaxBackups == 0 {
		cfg.Logging.MaxBackups = 5
	}
	if cfg.Logging.MaxAge == 0 {
		cfg.Logging.MaxAge = 30
	}

	// Performance defaults
	if cfg.Performance.BatchSize == 0 {
		cfg.Performance.BatchSize = 1000
	}
	if cfg.Performance.BufferSize == 0 {
		cfg.Performance.BufferSize = 10
	}
	if cfg.Performance.CacheTTL == 0 {
		cfg.Performance.CacheTTL = 300
	}

	// Monitoring defaults
	if cfg.Monitoring.MetricsPort == 0 {
		cfg.Monitoring.MetricsPort = 9090
	}
	if cfg.Monitoring.HealthCheckInterval == 0 {
		cfg.Monitoring.HealthCheckInterval = 30
	}
}

// ==========================================================================
// Environment Variable Overrides
// ==========================================================================

func applyEnvOverrides(cfg *Config) {
	// Database overrides
	if v := os.Getenv("DB_HOST"); v != "" {
		cfg.Database.Host = v
	}
	if v := os.Getenv("DB_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Database.Port = port
		}
	}
	if v := os.Getenv("DB_USER"); v != "" {
		cfg.Database.User = v
	}
	if v := os.Getenv("DB_PASSWORD"); v != "" {
		cfg.Database.Password = v
	}
	if v := os.Getenv("DB_NAME"); v != "" {
		cfg.Database.Database = v
	}

	// API overrides
	if v := os.Getenv("API_HOST"); v != "" {
		cfg.API.Host = v
	}
	if v := os.Getenv("API_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.API.Port = port
		}
	}

	// Worker overrides
	if v := os.Getenv("WORKER_ENABLED"); v != "" {
		cfg.Worker.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("WORKER_CONCURRENT_JOBS"); v != "" {
		if jobs, err := strconv.Atoi(v); err == nil {
			cfg.Worker.ConcurrentJobs = jobs
		}
	}

	// Logging overrides
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("LOG_OUTPUT"); v != "" {
		cfg.Logging.Output = v
	}

	// Storage overrides
	if v := os.Getenv("STORAGE_PATH"); v != "" {
		cfg.Storage.BasePath = v
	}
}

// ==========================================================================
// Validation Functions
// ==========================================================================

func validateConfig(cfg *Config) error {
	if err := validateDatabaseConfig(&cfg.Database); err != nil {
		return fmt.Errorf("database config: %w", err)
	}
	if err := validateAPIConfig(&cfg.API); err != nil {
		return fmt.Errorf("api config: %w", err)
	}
	if err := validateWorkerConfig(&cfg.Worker); err != nil {
		return fmt.Errorf("worker config: %w", err)
	}
	if err := validateStorageConfig(&cfg.Storage); err != nil {
		return fmt.Errorf("storage config: %w", err)
	}
	if err := validateLogConfig(&cfg.Logging); err != nil {
		return fmt.Errorf("logging config: %w", err)
	}
	return nil
}

func validateDatabaseConfig(cfg *DatabaseConfig) error {
	if cfg.Host == "" {
		return fmt.Errorf("host is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if cfg.Database == "" {
		return fmt.Errorf("database name is required")
	}
	if cfg.User == "" {
		return fmt.Errorf("user is required")
	}
	if cfg.MaxConnections < 1 {
		return fmt.Errorf("max_connections must be at least 1")
	}
	if cfg.MaxIdleConnections < 0 {
		return fmt.Errorf("max_idle_connections must be non-negative")
	}
	return nil
}

func validateAPIConfig(cfg *APIConfig) error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if cfg.RateLimit < 0 {
		return fmt.Errorf("rate_limit must be non-negative")
	}
	if cfg.ReadTimeout < 0 {
		return fmt.Errorf("read_timeout must be non-negative")
	}
	if cfg.WriteTimeout < 0 {
		return fmt.Errorf("write_timeout must be non-negative")
	}
	return nil
}

func validateWorkerConfig(cfg *WorkerConfig) error {
	if cfg.ConcurrentJobs < 1 {
		return fmt.Errorf("concurrent_jobs must be at least 1")
	}
	if cfg.RetryAttempts < 0 {
		return fmt.Errorf("retry_attempts must be non-negative")
	}
	if cfg.JobTimeout < 1 {
		return fmt.Errorf("job_timeout must be at least 1 second")
	}
	return nil
}

func validateStorageConfig(cfg *StorageConfig) error {
	if cfg.BasePath == "" {
		return fmt.Errorf("base_path is required")
	}

	// Ensure directory exists or can be created
	if err := os.MkdirAll(cfg.BasePath, 0755); err != nil {
		return fmt.Errorf("cannot create storage directory: %w", err)
	}

	if cfg.MaxFileSize < 1 {
		return fmt.Errorf("max_file_size must be at least 1 MB")
	}
	return nil
}

func validateLogConfig(cfg *LogConfig) error {
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[cfg.Level] {
		return fmt.Errorf("invalid log level: %s (must be debug, info, warn, or error)", cfg.Level)
	}

	validFormats := map[string]bool{"json": true, "text": true, "logfmt": true}
	if !validFormats[cfg.Format] {
		return fmt.Errorf("invalid log format: %s (must be json, text, or logfmt)", cfg.Format)
	}

	validOutputs := map[string]bool{"stdout": true, "file": true, "both": true}
	if !validOutputs[cfg.Output] {
		return fmt.Errorf("invalid log output: %s (must be stdout, file, or both)", cfg.Output)
	}

	if (cfg.Output == "file" || cfg.Output == "both") && cfg.FilePath == "" {
		return fmt.Errorf("file_path required when output is file or both")
	}

	return nil
}

func validateFeedSource(feed *FeedSource) error {
	if feed.Name == "" {
		return fmt.Errorf("name is required")
	}
	if feed.Category == "" {
		return fmt.Errorf("category is required")
	}
	if feed.URL == "" {
		return fmt.Errorf("url is required")
	}
	if feed.Format == "" {
		return fmt.Errorf("format is required")
	}
	if feed.UpdateFrequency < 1 {
		return fmt.Errorf("update_frequency must be at least 1 second")
	}

	// Validate category
	validCategories := map[string]bool{
		"ip_geo": true, "ip_blacklist": true, "ip_anonymization": true,
		"domain": true, "hash": true, "ioc": true, "asn": true,
	}
	if !validCategories[feed.Category] {
		return fmt.Errorf("invalid category: %s", feed.Category)
	}

	// Validate format
	validFormats := map[string]bool{
		"csv": true, "json": true, "txt": true, "mmdb": true,
		"xml": true, "tsv": true, "rss": true,
	}
	if !validFormats[feed.Format] {
		return fmt.Errorf("invalid format: %s", feed.Format)
	}

	return nil
}

// ==========================================================================
// Helper Functions
// ==========================================================================

// GetDefaultConfigPath returns the default configuration file path
func GetDefaultConfigPath() string {
	return filepath.Join("config", "config.yaml")
}

// GetDefaultSourcesPath returns the default sources file path
func GetDefaultSourcesPath() string {
	return filepath.Join("config", "sources.yaml")
}
