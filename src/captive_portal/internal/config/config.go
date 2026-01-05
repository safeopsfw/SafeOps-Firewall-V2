package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// GlobalConfig holds the loaded configuration
var GlobalConfig *Config

// LoadConfig loads configuration from YAML file
func LoadConfig(configPath string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("[Config] File not found at %s, using hardcoded defaults\n", configPath)
		return DefaultConfig(), nil
	}

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

// DefaultConfig returns the hardcoded default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPSPort:           8444,
			HTTPSEnabled:        true,
			CertFile:            "internal/certs/server.crt",
			KeyFile:             "internal/certs/server.key",
			HTTPPort:            8080,
			HTTPEnabled:         true,  // Serve content on HTTP (for CA cert download)
			HTTPRedirectToHTTPS: false, // Disabled - devices need HTTP access to download CA cert
			ReadTimeout:         10 * time.Second,
			WriteTimeout:        10 * time.Second,
			IdleTimeout:         120 * time.Second,
		},
		Portal: PortalConfig{
			Title:                 "SafeOps Captive Portal",
			WelcomeMessage:        "Welcome to SafeOps Network",
			CACertName:            "SafeOps Root CA",
			CACertDescription:     "Install this certificate to access the secure network",
			AutoVerifyEnabled:     true,
			VerifyIntervalSeconds: 5,
			VerifyTimeoutSeconds:  300,
		},
		Integrations: IntegrationsConfig{
			DHCPMonitor: DHCPMonitorConfig{
				GRPCAddress:   "localhost:50055",
				Timeout:       5 * time.Second,
				RetryAttempts: 3,
				RetryDelay:    2 * time.Second,
			},
			StepCA: StepCAConfig{
				APIURL:         "https://localhost:9000",
				VerifySSL:      false,
				RootCAEndpoint: "/roots.pem",
				Timeout:        10 * time.Second,
			},
			Database: DatabaseConfig{
				Enabled: false,
			},
		},
		Templates: TemplatesConfig{
			Path:           "internal/templates",
			ReloadOnChange: false,
		},
		Static: StaticConfig{
			CSSPath: "internal/static/css",
			JSPath:  "internal/static/js",
		},
		Logging: LoggingConfig{
			Level:  "INFO",
			Format: "json",
			Output: "stdout",
		},
		Security: SecurityConfig{
			CORSEnabled:       true,
			RateLimitEnabled:  true,
			RateLimitRequests: 100,
			RateLimitWindow:   "1m",
			SessionTimeout:    "30m",
		},
	}
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
