// Package config provides configuration validation functionality.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
	Value   interface{}
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []*ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}

	var msgs []string
	for _, err := range e {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// HasErrors returns true if there are any errors
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// Validator validates configuration
type Validator struct {
	errors ValidationErrors
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		errors: make(ValidationErrors, 0),
	}
}

// Validate validates a configuration
func Validate(cfg *Config) error {
	v := NewValidator()
	return v.ValidateConfig(cfg)
}

// ValidateConfig validates the entire configuration
func (v *Validator) ValidateConfig(cfg *Config) error {
	v.validateApp(&cfg.App)
	v.validateLogging(&cfg.Logging)
	v.validateServer(&cfg.Server)
	v.validateDatabase(&cfg.Database)
	v.validateRedis(&cfg.Redis)
	v.validateGRPC(&cfg.GRPC)
	v.validateMetrics(&cfg.Metrics)

	if v.errors.HasErrors() {
		return v.errors
	}
	return nil
}

// validateApp validates app configuration
func (v *Validator) validateApp(cfg *AppConfig) {
	v.Required("app.name", cfg.Name)
	v.Required("app.version", cfg.Version)
	v.OneOf("app.environment", cfg.Environment, []string{"development", "dev", "staging", "production", "prod"})
}

// validateLogging validates logging configuration
func (v *Validator) validateLogging(cfg *LoggingConfig) {
	v.OneOf("logging.level", cfg.Level, []string{"debug", "info", "warn", "warning", "error", "fatal"})
	v.OneOf("logging.format", cfg.Format, []string{"json", "text", "console"})

	if cfg.Output != "stdout" && cfg.Output != "stderr" && cfg.Output != "" {
		v.WritableFile("logging.output", cfg.Output)
	}

	v.PositiveOrZero("logging.max_size_mb", cfg.MaxSizeMB)
	v.PositiveOrZero("logging.max_backups", cfg.MaxBackups)
	v.PositiveOrZero("logging.max_age_days", cfg.MaxAgeDays)
}

// validateServer validates server configuration
func (v *Validator) validateServer(cfg *ServerConfig) {
	v.Port("server.port", cfg.Port)
	v.Positive("server.read_timeout", int(cfg.ReadTimeout))
	v.Positive("server.write_timeout", int(cfg.WriteTimeout))

	if cfg.TLS.Enabled {
		v.FileExists("server.tls.cert_file", cfg.TLS.CertFile)
		v.FileExists("server.tls.key_file", cfg.TLS.KeyFile)
	}
}

// validateDatabase validates database configuration
func (v *Validator) validateDatabase(cfg *DatabaseConfig) {
	if cfg.Host == "" && cfg.Port == 0 {
		return // Database not configured
	}

	v.Required("database.host", cfg.Host)
	v.Port("database.port", cfg.Port)
	v.Required("database.user", cfg.User)
	v.Required("database.database", cfg.Database)
	v.OneOf("database.ssl_mode", cfg.SSLMode, []string{"disable", "require", "verify-ca", "verify-full", ""})
	v.PositiveOrZero("database.max_open_conns", cfg.MaxOpenConns)
	v.PositiveOrZero("database.max_idle_conns", cfg.MaxIdleConns)
}

// validateRedis validates Redis configuration
func (v *Validator) validateRedis(cfg *RedisConfig) {
	if len(cfg.Addresses) == 0 {
		return // Redis not configured
	}

	for i, addr := range cfg.Addresses {
		v.HostPort(fmt.Sprintf("redis.addresses[%d]", i), addr)
	}

	v.Range("redis.database", cfg.Database, 0, 15)
	v.PositiveOrZero("redis.pool_size", cfg.PoolSize)
}

// validateGRPC validates gRPC configuration
func (v *Validator) validateGRPC(cfg *GRPCConfig) {
	if cfg.Port == 0 {
		return // gRPC not configured
	}

	v.Port("grpc.port", cfg.Port)
	v.PositiveOrZero("grpc.max_recv_msg_size", cfg.MaxRecvMsgSize)
	v.PositiveOrZero("grpc.max_send_msg_size", cfg.MaxSendMsgSize)

	if cfg.TLS.Enabled {
		v.FileExists("grpc.tls.cert_file", cfg.TLS.CertFile)
		v.FileExists("grpc.tls.key_file", cfg.TLS.KeyFile)
	}
}

// validateMetrics validates metrics configuration
func (v *Validator) validateMetrics(cfg *MetricsConfig) {
	if !cfg.Enabled {
		return
	}

	v.Port("metrics.port", cfg.Port)
	if cfg.Path != "" && !strings.HasPrefix(cfg.Path, "/") {
		v.addError("metrics.path", "must start with /", cfg.Path)
	}
}

// Validation helper methods

// Required checks that a value is not empty
func (v *Validator) Required(field string, value string) bool {
	if strings.TrimSpace(value) == "" {
		v.addError(field, "is required", value)
		return false
	}
	return true
}

// Positive checks that a value is positive
func (v *Validator) Positive(field string, value int) bool {
	if value <= 0 {
		v.addError(field, "must be positive", value)
		return false
	}
	return true
}

// PositiveOrZero checks that a value is non-negative
func (v *Validator) PositiveOrZero(field string, value int) bool {
	if value < 0 {
		v.addError(field, "must be non-negative", value)
		return false
	}
	return true
}

// Range checks that a value is within a range
func (v *Validator) Range(field string, value, min, max int) bool {
	if value < min || value > max {
		v.addError(field, fmt.Sprintf("must be between %d and %d", min, max), value)
		return false
	}
	return true
}

// Port checks that a value is a valid port number
func (v *Validator) Port(field string, value int) bool {
	if value < 1 || value > 65535 {
		v.addError(field, "must be a valid port (1-65535)", value)
		return false
	}
	return true
}

// OneOf checks that a value is one of the allowed values
func (v *Validator) OneOf(field string, value string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(value, a) {
			return true
		}
	}
	v.addError(field, fmt.Sprintf("must be one of: %s", strings.Join(allowed, ", ")), value)
	return false
}

// FileExists checks that a file exists
func (v *Validator) FileExists(field string, path string) bool {
	if path == "" {
		v.addError(field, "is required", path)
		return false
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		v.addError(field, "file does not exist", path)
		return false
	}
	return true
}

// WritableFile checks that a file path is writable
func (v *Validator) WritableFile(field string, path string) bool {
	dir := path
	if idx := strings.LastIndex(path, string(os.PathSeparator)); idx >= 0 {
		dir = path[:idx]
	}

	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		v.addError(field, "directory does not exist or is not writable", path)
		return false
	}
	return true
}

// HostPort checks that a value is a valid host:port
func (v *Validator) HostPort(field string, value string) bool {
	_, _, err := net.SplitHostPort(value)
	if err != nil {
		v.addError(field, "must be a valid host:port", value)
		return false
	}
	return true
}

// URL checks that a value is a valid URL
func (v *Validator) URL(field string, value string) bool {
	_, err := url.Parse(value)
	if err != nil {
		v.addError(field, "must be a valid URL", value)
		return false
	}
	return true
}

// Email checks that a value is a valid email
func (v *Validator) Email(field string, value string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, value)
	if !matched {
		v.addError(field, "must be a valid email address", value)
		return false
	}
	return true
}

// Regex checks that a value matches a pattern
func (v *Validator) Regex(field string, value string, pattern string) bool {
	matched, err := regexp.MatchString(pattern, value)
	if err != nil || !matched {
		v.addError(field, fmt.Sprintf("must match pattern: %s", pattern), value)
		return false
	}
	return true
}

// MinLength checks minimum string length
func (v *Validator) MinLength(field string, value string, min int) bool {
	if len(value) < min {
		v.addError(field, fmt.Sprintf("must be at least %d characters", min), value)
		return false
	}
	return true
}

// MaxLength checks maximum string length
func (v *Validator) MaxLength(field string, value string, max int) bool {
	if len(value) > max {
		v.addError(field, fmt.Sprintf("must be at most %d characters", max), value)
		return false
	}
	return true
}

// addError adds a validation error
func (v *Validator) addError(field, message string, value interface{}) {
	v.errors = append(v.errors, &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// Errors returns all validation errors
func (v *Validator) Errors() ValidationErrors {
	return v.errors
}

// Custom allows custom validation logic
func (v *Validator) Custom(field string, valid bool, message string, value interface{}) bool {
	if !valid {
		v.addError(field, message, value)
		return false
	}
	return true
}
