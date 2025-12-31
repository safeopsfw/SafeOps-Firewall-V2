// Package config handles configuration loading and management
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the complete application configuration
type Config struct {
	Service      ServiceConfig      `yaml:"service"`
	WindowsDHCP  WindowsDHCPConfig  `yaml:"windows_dhcp"`
	DNS          DNSConfig          `yaml:"dns"`
	Portal       PortalConfig       `yaml:"portal"`
	StepCA       StepCAConfig       `yaml:"stepca"`
	Database     DatabaseConfig     `yaml:"database"`
	Monitoring   MonitoringConfig   `yaml:"monitoring"`
	Logging      LoggingConfig      `yaml:"logging"`
}

type ServiceConfig struct {
	Name     string `yaml:"name"`
	LogLevel string `yaml:"log_level"`
}

type WindowsDHCPConfig struct {
	Method         string        `yaml:"method"`           // wmi, powershell, netsh
	PollInterval   time.Duration `yaml:"poll_interval"`
	Server         string        `yaml:"server"`
	AutoConfigure  bool          `yaml:"auto_configure"`
}

type DNSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Port       int    `yaml:"port"`
	Upstream   string `yaml:"upstream"`
	HijackTTL  uint32 `yaml:"hijack_ttl"`
}

type PortalConfig struct {
	IP             string        `yaml:"ip"`
	HTTPPort       int           `yaml:"http_port"`
	HTTPSPort      int           `yaml:"https_port"`
	HTTPSEnabled   bool          `yaml:"https_enabled"`
	CertPath       string        `yaml:"cert_path"`
	KeyPath        string        `yaml:"key_path"`
	SessionTimeout time.Duration `yaml:"session_timeout"`
}

type StepCAConfig struct {
	APIURL       string `yaml:"api_url"`
	RootCertPath string `yaml:"root_cert_path"`
	VerifyClientCerts bool `yaml:"verify_client_certs"`
}

type DatabaseConfig struct {
	Path          string `yaml:"path"`
	RetentionDays int    `yaml:"retention_days"`
}

type MonitoringConfig struct {
	MetricsPort int  `yaml:"metrics_port"`
	HealthPort  int  `yaml:"health_port"`
	Profiling   bool `yaml:"profiling"`
}

type LoggingConfig struct {
	Level    string `yaml:"level"`
	Format   string `yaml:"format"`
	Output   string `yaml:"output"`
	FilePath string `yaml:"file_path"`
}

// Load loads configuration from file
func Load(path string) (*Config, error) {
	// Use default path if not specified
	if path == "" {
		path = "config/config.yaml"
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Apply defaults
	applyDefaults(&cfg)

	// Validate
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// applyDefaults applies default values to missing config fields
func applyDefaults(cfg *Config) {
	if cfg.Service.Name == "" {
		cfg.Service.Name = "dhcp_monitor"
	}
	if cfg.Service.LogLevel == "" {
		cfg.Service.LogLevel = "info"
	}

	if cfg.WindowsDHCP.Method == "" {
		cfg.WindowsDHCP.Method = "powershell"
	}
	if cfg.WindowsDHCP.PollInterval == 0 {
		cfg.WindowsDHCP.PollInterval = 30 * time.Second
	}
	if cfg.WindowsDHCP.Server == "" {
		cfg.WindowsDHCP.Server = "localhost"
	}

	if cfg.DNS.Port == 0 {
		cfg.DNS.Port = 53
	}
	if cfg.DNS.Upstream == "" {
		cfg.DNS.Upstream = "8.8.8.8"
	}

	if cfg.Portal.HTTPPort == 0 {
		cfg.Portal.HTTPPort = 80
	}
	if cfg.Portal.HTTPSPort == 0 {
		cfg.Portal.HTTPSPort = 443
	}
	if cfg.Portal.SessionTimeout == 0 {
		cfg.Portal.SessionTimeout = 10 * time.Minute
	}

	if cfg.Database.Path == "" {
		cfg.Database.Path = "./devices.db"
	}
	if cfg.Database.RetentionDays == 0 {
		cfg.Database.RetentionDays = 90
	}

	if cfg.Monitoring.MetricsPort == 0 {
		cfg.Monitoring.MetricsPort = 9155
	}
	if cfg.Monitoring.HealthPort == 0 {
		cfg.Monitoring.HealthPort = 8068
	}

	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "text"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
}

// validate validates the configuration
func validate(cfg *Config) error {
	// Validate DHCP method
	validMethods := map[string]bool{"powershell": true, "wmi": true, "netsh": true}
	if !validMethods[cfg.WindowsDHCP.Method] {
		return fmt.Errorf("invalid DHCP monitoring method: %s", cfg.WindowsDHCP.Method)
	}

	// Validate ports
	if cfg.DNS.Port < 1 || cfg.DNS.Port > 65535 {
		return fmt.Errorf("invalid DNS port: %d", cfg.DNS.Port)
	}
	if cfg.Portal.HTTPPort < 1 || cfg.Portal.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", cfg.Portal.HTTPPort)
	}
	if cfg.Portal.HTTPSPort < 1 || cfg.Portal.HTTPSPort > 65535 {
		return fmt.Errorf("invalid HTTPS port: %d", cfg.Portal.HTTPSPort)
	}

	// Validate HTTPS config
	if cfg.Portal.HTTPSEnabled {
		if cfg.Portal.CertPath == "" || cfg.Portal.KeyPath == "" {
			return fmt.Errorf("HTTPS enabled but cert/key paths not specified")
		}
	}

	// Validate Step-CA config
	if cfg.StepCA.RootCertPath == "" {
		return fmt.Errorf("Step-CA root certificate path not specified")
	}
	if _, err := os.Stat(cfg.StepCA.RootCertPath); err != nil {
		return fmt.Errorf("Step-CA root certificate not found: %w", err)
	}

	return nil
}
