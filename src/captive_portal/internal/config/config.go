package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// GlobalConfig holds the loaded configuration
var GlobalConfig *Config

// LoadConfig loads configuration from YAML file
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	GlobalConfig = &cfg
	return &cfg, nil
}

// validateConfig validates required configuration fields
func validateConfig(cfg *Config) error {
	// Server validation
	if cfg.Server.HTTPSEnabled {
		if cfg.Server.CertFile == "" {
			return fmt.Errorf("cert_file is required when HTTPS is enabled")
		}
		if cfg.Server.KeyFile == "" {
			return fmt.Errorf("key_file is required when HTTPS is enabled")
		}
		if cfg.Server.HTTPSPort == 0 {
			return fmt.Errorf("https_port must be specified")
		}
	}

	// Step-CA validation
	if cfg.Integrations.StepCA.APIURL == "" {
		return fmt.Errorf("step_ca.api_url is required")
	}

	// Templates validation
	if cfg.Templates.Path == "" {
		return fmt.Errorf("templates.path is required")
	}

	return nil
}

// GetConfig returns the global configuration
func GetConfig() *Config {
	return GlobalConfig
}

// MustLoadConfig loads config or panics
func MustLoadConfig(configPath string) *Config {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	return cfg
}
