// Package config handles threat intelligence service configuration
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main application configuration
type Config struct {
	Database DatabaseConfig `yaml:"database"`
	Fetcher  FetcherConfig  `yaml:"fetcher"`
	WebUI    WebUIConfig    `yaml:"webui"`
	Logging  LoggingConfig  `yaml:"logging"`
	Metrics  MetricsConfig  `yaml:"metrics"`
}

// DatabaseConfig holds database connection settings
type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"ssl_mode"`
}

// FetcherConfig holds feed fetcher settings
type FetcherConfig struct {
	UpdateInterval time.Duration `yaml:"update_interval"`
	Concurrency    int           `yaml:"concurrency"`
	Timeout        time.Duration `yaml:"timeout"`
	RetryAttempts  int           `yaml:"retry_attempts"`
	SourcesDir     string        `yaml:"sources_dir"`
}

// WebUIConfig holds web interface settings
type WebUIConfig struct {
	Address      string `yaml:"address"`
	Port         int    `yaml:"port"`
	TemplatesDir string `yaml:"templates_dir"`
	StaticDir    string `yaml:"static_dir"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// MetricsConfig holds Prometheus metrics settings
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// LoadConfig loads configuration from YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Apply defaults
	applyDefaults(&cfg)

	return &cfg, nil
}

// applyDefaults sets default values for unspecified config options
func applyDefaults(cfg *Config) {
	if cfg.Database.Port == 0 {
		cfg.Database.Port = 5432
	}
	if cfg.Database.SSLMode == "" {
		cfg.Database.SSLMode = "require"
	}
	if cfg.Fetcher.UpdateInterval == 0 {
		cfg.Fetcher.UpdateInterval = 1 * time.Hour
	}
	if cfg.Fetcher.Concurrency == 0 {
		cfg.Fetcher.Concurrency = 10
	}
	if cfg.Fetcher.Timeout == 0 {
		cfg.Fetcher.Timeout = 30 * time.Second
	}
	if cfg.WebUI.Port == 0 {
		cfg.WebUI.Port = 8080
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}
}
