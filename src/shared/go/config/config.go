// Package config provides configuration loading, validation, and hot-reload
// functionality for SafeOps services.
package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config holds the main application configuration
type Config struct {
	// App configuration
	App AppConfig `mapstructure:"app" yaml:"app"`

	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging" yaml:"logging"`

	// Server configuration
	Server ServerConfig `mapstructure:"server" yaml:"server"`

	// Database configuration
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`

	// Redis configuration
	Redis RedisConfig `mapstructure:"redis" yaml:"redis"`

	// gRPC configuration
	GRPC GRPCConfig `mapstructure:"grpc" yaml:"grpc"`

	// Metrics configuration
	Metrics MetricsConfig `mapstructure:"metrics" yaml:"metrics"`

	// Custom sections
	Custom map[string]interface{} `mapstructure:"custom" yaml:"custom"`

	// Internal
	mu       sync.RWMutex
	filePath string
}

// AppConfig holds application-level settings
type AppConfig struct {
	Name        string `mapstructure:"name" yaml:"name"`
	Version     string `mapstructure:"version" yaml:"version"`
	Environment string `mapstructure:"environment" yaml:"environment"` // dev, staging, production
	Debug       bool   `mapstructure:"debug" yaml:"debug"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level      string `mapstructure:"level" yaml:"level"`   // debug, info, warn, error
	Format     string `mapstructure:"format" yaml:"format"` // json, text
	Output     string `mapstructure:"output" yaml:"output"` // stdout, file path
	MaxSizeMB  int    `mapstructure:"max_size_mb" yaml:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups" yaml:"max_backups"`
	MaxAgeDays int    `mapstructure:"max_age_days" yaml:"max_age_days"`
}

// ServerConfig holds HTTP server settings
type ServerConfig struct {
	Host            string        `mapstructure:"host" yaml:"host"`
	Port            int           `mapstructure:"port" yaml:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout" yaml:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout" yaml:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout" yaml:"shutdown_timeout"`
	TLS             TLSConfig     `mapstructure:"tls" yaml:"tls"`
}

// TLSConfig holds TLS settings
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file"`
	CAFile   string `mapstructure:"ca_file" yaml:"ca_file"`
}

// DatabaseConfig holds database settings
type DatabaseConfig struct {
	Host            string        `mapstructure:"host" yaml:"host"`
	Port            int           `mapstructure:"port" yaml:"port"`
	User            string        `mapstructure:"user" yaml:"user"`
	Password        string        `mapstructure:"password" yaml:"password"`
	Database        string        `mapstructure:"database" yaml:"database"`
	SSLMode         string        `mapstructure:"ssl_mode" yaml:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns" yaml:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime" yaml:"conn_max_lifetime"`
}

// RedisConfig holds Redis settings
type RedisConfig struct {
	Addresses   []string      `mapstructure:"addresses" yaml:"addresses"`
	Password    string        `mapstructure:"password" yaml:"password"`
	Database    int           `mapstructure:"database" yaml:"database"`
	PoolSize    int           `mapstructure:"pool_size" yaml:"pool_size"`
	MinIdleConn int           `mapstructure:"min_idle_conn" yaml:"min_idle_conn"`
	MaxRetries  int           `mapstructure:"max_retries" yaml:"max_retries"`
	DialTimeout time.Duration `mapstructure:"dial_timeout" yaml:"dial_timeout"`
}

// GRPCConfig holds gRPC settings
type GRPCConfig struct {
	Host           string        `mapstructure:"host" yaml:"host"`
	Port           int           `mapstructure:"port" yaml:"port"`
	MaxRecvMsgSize int           `mapstructure:"max_recv_msg_size" yaml:"max_recv_msg_size"`
	MaxSendMsgSize int           `mapstructure:"max_send_msg_size" yaml:"max_send_msg_size"`
	KeepAlive      time.Duration `mapstructure:"keep_alive" yaml:"keep_alive"`
	TLS            TLSConfig     `mapstructure:"tls" yaml:"tls"`
}

// MetricsConfig holds metrics settings
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled" yaml:"enabled"`
	Port    int    `mapstructure:"port" yaml:"port"`
	Path    string `mapstructure:"path" yaml:"path"`
}

// Loader handles configuration loading
type Loader struct {
	v *viper.Viper
}

// NewLoader creates a new configuration loader
func NewLoader() *Loader {
	return &Loader{
		v: viper.New(),
	}
}

// Load loads configuration from file
func Load(path string) (*Config, error) {
	loader := NewLoader()
	return loader.LoadFromFile(path)
}

// LoadFromFile loads configuration from a file
func (l *Loader) LoadFromFile(path string) (*Config, error) {
	// Set config file
	l.v.SetConfigFile(path)

	// Set config type based on extension
	ext := filepath.Ext(path)
	if ext != "" {
		l.v.SetConfigType(strings.TrimPrefix(ext, "."))
	}

	// Read config
	if err := l.v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal
	var cfg Config
	if err := l.v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	cfg.filePath = path
	return &cfg, nil
}

// LoadFromBytes loads configuration from bytes
func (l *Loader) LoadFromBytes(data []byte, configType string) (*Config, error) {
	l.v.SetConfigType(configType)

	if err := l.v.ReadConfig(strings.NewReader(string(data))); err != nil {
		return nil, fmt.Errorf("failed to read config data: %w", err)
	}

	var cfg Config
	if err := l.v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// LoadWithDefaults loads config with default values
func LoadWithDefaults(path string, defaults *Config) (*Config, error) {
	loader := NewLoader()

	// Set defaults
	if defaults != nil {
		if err := setDefaults(loader.v, defaults); err != nil {
			return nil, fmt.Errorf("failed to set defaults: %w", err)
		}
	}

	return loader.LoadFromFile(path)
}

// setDefaults sets default values from a struct
func setDefaults(v *viper.Viper, defaults *Config) error {
	defaultMap := make(map[string]interface{})
	data, err := yaml.Marshal(defaults)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, &defaultMap); err != nil {
		return err
	}

	for key, value := range defaultMap {
		v.SetDefault(key, value)
	}

	return nil
}

// Get returns a value from the config
func (c *Config) Get(key string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Custom == nil {
		return nil
	}
	return c.Custom[key]
}

// GetString returns a string value from custom config
func (c *Config) GetString(key string) string {
	v := c.Get(key)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// GetInt returns an int value from custom config
func (c *Config) GetInt(key string) int {
	v := c.Get(key)
	switch i := v.(type) {
	case int:
		return i
	case int64:
		return int(i)
	case float64:
		return int(i)
	}
	return 0
}

// GetBool returns a bool value from custom config
func (c *Config) GetBool(key string) bool {
	v := c.Get(key)
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// Set sets a custom config value
func (c *Config) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Custom == nil {
		c.Custom = make(map[string]interface{})
	}
	c.Custom[key] = value
}

// Clone creates a deep copy of the config
func (c *Config) Clone() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create new config with field copies (cannot copy mutex)
	clone := &Config{
		App:      c.App,
		Logging:  c.Logging,
		Server:   c.Server,
		Database: c.Database,
		Redis:    c.Redis,
		GRPC:     c.GRPC,
		Metrics:  c.Metrics,
		filePath: c.filePath,
	}

	if c.Custom != nil {
		clone.Custom = make(map[string]interface{})
		for k, v := range c.Custom {
			clone.Custom[k] = v
		}
	}
	return clone
}

// Reload reloads the configuration from file
func (c *Config) Reload() error {
	if c.filePath == "" {
		return fmt.Errorf("no file path set")
	}

	newCfg, err := Load(c.filePath)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Copy fields individually (cannot copy mutex)
	c.App = newCfg.App
	c.Logging = newCfg.Logging
	c.Server = newCfg.Server
	c.Database = newCfg.Database
	c.Redis = newCfg.Redis
	c.GRPC = newCfg.GRPC
	c.Metrics = newCfg.Metrics
	c.Custom = newCfg.Custom
	// Keep original filePath and mu (mutex cannot be copied)

	return nil
}

// FilePath returns the config file path
func (c *Config) FilePath() string {
	return c.filePath
}

// DSN returns the database DSN string
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// Address returns the server address
func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Address returns the gRPC address
func (c *GRPCConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		App: AppConfig{
			Name:        "safeops-service",
			Version:     "1.0.0",
			Environment: "development",
			Debug:       false,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSizeMB:  100,
			MaxBackups: 3,
			MaxAgeDays: 7,
		},
		Server: ServerConfig{
			Host:            "0.0.0.0",
			Port:            8080,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 10 * time.Second,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            5432,
			User:            "postgres",
			Database:        "safeops",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Redis: RedisConfig{
			Addresses:   []string{"localhost:6379"},
			Database:    0,
			PoolSize:    10,
			MinIdleConn: 2,
			MaxRetries:  3,
			DialTimeout: 5 * time.Second,
		},
		GRPC: GRPCConfig{
			Host:           "0.0.0.0",
			Port:           9090,
			MaxRecvMsgSize: 4 * 1024 * 1024,
			MaxSendMsgSize: 4 * 1024 * 1024,
			KeepAlive:      30 * time.Second,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9100,
			Path:    "/metrics",
		},
	}
}

// IsProduction returns true if running in production
func (c *Config) IsProduction() bool {
	return c.App.Environment == "production"
}

// IsDevelopment returns true if running in development
func (c *Config) IsDevelopment() bool {
	return c.App.Environment == "development" || c.App.Environment == "dev"
}

// MustLoad loads config and panics on error
func MustLoad(path string) *Config {
	cfg, err := Load(path)
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	return cfg
}
