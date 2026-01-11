package config

import "time"

// Config represents the captive portal configuration
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Portal       PortalConfig       `yaml:"portal"`
	Integrations IntegrationsConfig `yaml:"integrations"`
	Static       StaticConfig       `yaml:"static"`
	Templates    TemplatesConfig    `yaml:"templates"`
	Logging      LoggingConfig      `yaml:"logging"`
	Security     SecurityConfig     `yaml:"security"`
}

// ServerConfig contains HTTPS server settings
type ServerConfig struct {
	HTTPSPort           int           `yaml:"https_port"`
	HTTPSEnabled        bool          `yaml:"https_enabled"`
	CertFile            string        `yaml:"cert_file"`
	KeyFile             string        `yaml:"key_file"`
	HTTPPort            int           `yaml:"http_port"`
	HTTPEnabled         bool          `yaml:"http_enabled"` // NEW: Serve content on HTTP (for CA cert download)
	HTTPRedirectToHTTPS bool          `yaml:"http_redirect_to_https"`
	ReadTimeout         time.Duration `yaml:"read_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout"`
	IdleTimeout         time.Duration `yaml:"idle_timeout"`
}

// PortalConfig contains portal branding and auto-verify settings
type PortalConfig struct {
	Title                 string `yaml:"title"`
	WelcomeMessage        string `yaml:"welcome_message"`
	CACertName            string `yaml:"ca_cert_name"`
	CACertDescription     string `yaml:"ca_cert_description"`
	AutoVerifyEnabled     bool   `yaml:"auto_verify_enabled"`
	VerifyIntervalSeconds int    `yaml:"verify_interval_seconds"`
	VerifyTimeoutSeconds  int    `yaml:"verify_timeout_seconds"`
}

// IntegrationsConfig contains external service configurations
type IntegrationsConfig struct {
	DHCPMonitor DHCPMonitorConfig `yaml:"dhcp_monitor"`
	StepCA      StepCAConfig      `yaml:"step_ca"`
	Database    DatabaseConfig    `yaml:"database"`
}

// DHCPMonitorConfig for gRPC client
type DHCPMonitorConfig struct {
	GRPCAddress   string        `yaml:"grpc_address"`
	Timeout       time.Duration `yaml:"timeout"`
	RetryAttempts int           `yaml:"retry_attempts"`
	RetryDelay    time.Duration `yaml:"retry_delay"`
}

// StepCAConfig for Step-CA HTTP client
type StepCAConfig struct {
	APIURL         string        `yaml:"api_url"`
	VerifySSL      bool          `yaml:"verify_ssl"`
	RootCAEndpoint string        `yaml:"root_ca_endpoint"`
	Timeout        time.Duration `yaml:"timeout"`
}

// DatabaseConfig for PostgreSQL fallback connection
type DatabaseConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"sslmode"`
}

// StaticConfig contains static file paths
type StaticConfig struct {
	CSSPath string `yaml:"css_path"`
	JSPath  string `yaml:"js_path"`
}

// TemplatesConfig for HTML template settings
type TemplatesConfig struct {
	Path           string `yaml:"path"`
	ReloadOnChange bool   `yaml:"reload_on_change"`
}

// LoggingConfig for structured logging
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
	Compress   bool   `yaml:"compress"`
}

// SecurityConfig for CORS, rate limiting, sessions
type SecurityConfig struct {
	CORSEnabled       bool     `yaml:"cors_enabled"`
	CORSOrigins       []string `yaml:"cors_origins"`
	RateLimitEnabled  bool     `yaml:"rate_limit_enabled"`
	RateLimitRequests int      `yaml:"rate_limit_requests"`
	RateLimitWindow   string   `yaml:"rate_limit_window"`
	SessionTimeout    string   `yaml:"session_timeout"`
	SessionSecret     string   `yaml:"session_secret"`
}
