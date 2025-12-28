// Package types provides core, reusable type definitions and data structures
// shared across all NIC Management service components. It serves as the single
// source of truth for configuration structures, service metadata, health status,
// error types, and common enumerations.
package types

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// =============================================================================
// Service Configuration Types
// =============================================================================

// ServiceConfig represents the top-level service configuration loaded from YAML.
type ServiceConfig struct {
	ServiceName string `yaml:"name" json:"service_name"`
	Version     string `yaml:"version" json:"version"`
	Description string `yaml:"description" json:"description"`
	LogLevel    string `yaml:"log_level" json:"log_level"`
	LogFormat   string `yaml:"log_format" json:"log_format"`
	LogOutput   string `yaml:"log_output" json:"log_output"`
	LogFile     string `yaml:"log_file" json:"log_file"`
	Environment string `yaml:"environment" json:"environment"`
}

// DatabaseConfig represents PostgreSQL connection settings.
type DatabaseConfig struct {
	Host              string        `yaml:"host" json:"host"`
	Port              int           `yaml:"port" json:"port"`
	Database          string        `yaml:"database" json:"database"`
	Username          string        `yaml:"username" json:"username"`
	Password          string        `yaml:"password" json:"-"` // Excluded from JSON serialization
	MaxConnections    int           `yaml:"max_connections" json:"max_connections"`
	MinConnections    int           `yaml:"min_connections" json:"min_connections"`
	MaxIdleTime       time.Duration `yaml:"max_idle_time" json:"max_idle_time"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout" json:"connection_timeout"`
	HealthCheckPeriod time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	SSLEnabled        bool          `yaml:"ssl_enabled" json:"ssl_enabled"`
	SSLMode           string        `yaml:"ssl_mode" json:"ssl_mode"`
}

// GRPCConfig represents gRPC server configuration.
type GRPCConfig struct {
	ListenAddress        string        `yaml:"listen_address" json:"listen_address"`
	MaxConcurrentStreams int           `yaml:"max_concurrent_streams" json:"max_concurrent_streams"`
	MaxConnectionIdle    time.Duration `yaml:"max_connection_idle" json:"max_connection_idle"`
	MaxConnectionAge     time.Duration `yaml:"max_connection_age" json:"max_connection_age"`
	MaxRecvMsgSize       int           `yaml:"max_recv_msg_size" json:"max_recv_msg_size"`
	MaxSendMsgSize       int           `yaml:"max_send_msg_size" json:"max_send_msg_size"`
	EnableTLS            bool          `yaml:"enable_tls" json:"enable_tls"`
	TLSCertFile          string        `yaml:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile           string        `yaml:"tls_key_file" json:"tls_key_file"`
	TLSCAFile            string        `yaml:"tls_ca_file" json:"tls_ca_file"`
	ClientAuth           string        `yaml:"client_auth" json:"client_auth"`
	KeepaliveTime        time.Duration `yaml:"keepalive_time" json:"keepalive_time"`
	KeepaliveTimeout     time.Duration `yaml:"keepalive_timeout" json:"keepalive_timeout"`
}

// MonitoringConfig represents metrics and monitoring configuration.
type MonitoringConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`
	StatisticsInterval time.Duration `yaml:"statistics_interval" json:"statistics_interval"`
	PrometheusPort     int           `yaml:"prometheus_port" json:"prometheus_port"`
	PrometheusPath     string        `yaml:"prometheus_path" json:"prometheus_path"`
	StreamingEnabled   bool          `yaml:"streaming_enabled" json:"streaming_enabled"`
	RetentionDays      int           `yaml:"retention_days" json:"retention_days"`
}

// IntegrationEndpoint represents a connection to another SafeOps service.
type IntegrationEndpoint struct {
	Endpoint      string        `yaml:"endpoint" json:"endpoint"`
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	Timeout       time.Duration `yaml:"timeout" json:"timeout"`
	RetryAttempts int           `yaml:"retry_attempts" json:"retry_attempts"`
}

// IntegrationsConfig holds all service integration endpoints.
type IntegrationsConfig struct {
	FirewallEngine IntegrationEndpoint `yaml:"firewall_engine" json:"firewall_engine"`
	DHCPServer     IntegrationEndpoint `yaml:"dhcp_server" json:"dhcp_server"`
	DNSServer      IntegrationEndpoint `yaml:"dns_server" json:"dns_server"`
	NetworkLogger  IntegrationEndpoint `yaml:"network_logger" json:"network_logger"`
	IDSIPS         IntegrationEndpoint `yaml:"ids_ips" json:"ids_ips"`
	ThreatIntel    IntegrationEndpoint `yaml:"threat_intel" json:"threat_intel"`
}

// =============================================================================
// Health and Status Types
// =============================================================================

// HealthStatus represents the overall service health state.
type HealthStatus string

const (
	// HealthStatusHealthy indicates all components are functioning normally.
	HealthStatusHealthy HealthStatus = "HEALTHY"
	// HealthStatusDegraded indicates some components have issues but service is operational.
	HealthStatusDegraded HealthStatus = "DEGRADED"
	// HealthStatusDown indicates the service is not operational.
	HealthStatusDown HealthStatus = "DOWN"
	// HealthStatusUnknown indicates the health status cannot be determined.
	HealthStatusUnknown HealthStatus = "UNKNOWN"
	// HealthStatusStarting indicates the service is in startup phase.
	HealthStatusStarting HealthStatus = "STARTING"
	// HealthStatusStopping indicates the service is shutting down.
	HealthStatusStopping HealthStatus = "STOPPING"
)

// IsHealthy returns true if the status indicates a healthy service.
func (h HealthStatus) IsHealthy() bool {
	return h == HealthStatusHealthy
}

// String returns the string representation of HealthStatus.
func (h HealthStatus) String() string {
	return string(h)
}

// ServiceStatus represents the runtime status of the service.
type ServiceStatus struct {
	Status            HealthStatus      `json:"status"`
	Uptime            time.Duration     `json:"uptime"`
	UptimeHuman       string            `json:"uptime_human"`
	StartTime         time.Time         `json:"start_time"`
	Version           string            `json:"version"`
	BuildInfo         string            `json:"build_info,omitempty"`
	Message           string            `json:"message,omitempty"`
	ComponentStatuses map[string]string `json:"component_statuses,omitempty"`
}

// ComponentHealth represents the health of an individual service component.
type ComponentHealth struct {
	Name        string            `json:"name"`
	Status      HealthStatus      `json:"status"`
	Message     string            `json:"message,omitempty"`
	LastChecked time.Time         `json:"last_checked"`
	Details     map[string]string `json:"details,omitempty"`
}

// =============================================================================
// Error Types
// =============================================================================

// Sentinel errors for common error conditions.
var (
	// ErrNotFound indicates the requested resource was not found.
	ErrNotFound = errors.New("resource not found")

	// ErrAlreadyExists indicates the resource already exists.
	ErrAlreadyExists = errors.New("resource already exists")

	// ErrInvalidConfiguration indicates configuration validation failed.
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrDatabaseConnection indicates database connectivity issues.
	ErrDatabaseConnection = errors.New("database connection failed")

	// ErrInterfaceNotFound indicates the network interface doesn't exist.
	ErrInterfaceNotFound = errors.New("network interface not found")

	// ErrInvalidState indicates an invalid state transition.
	ErrInvalidState = errors.New("invalid state transition")

	// ErrOperationTimeout indicates the operation timed out.
	ErrOperationTimeout = errors.New("operation timed out")

	// ErrPermissionDenied indicates insufficient permissions.
	ErrPermissionDenied = errors.New("permission denied")

	// ErrServiceUnavailable indicates the service is not available.
	ErrServiceUnavailable = errors.New("service unavailable")

	// ErrInvalidInput indicates invalid input parameters.
	ErrInvalidInput = errors.New("invalid input parameters")

	// ErrRustLibraryNotLoaded indicates the Rust FFI library failed to load.
	ErrRustLibraryNotLoaded = errors.New("rust library not loaded")
)

// InterfaceError represents an error related to a specific network interface.
type InterfaceError struct {
	InterfaceName string
	Operation     string
	Err           error
}

func (e *InterfaceError) Error() string {
	return fmt.Sprintf("interface %s: %s failed: %v", e.InterfaceName, e.Operation, e.Err)
}

func (e *InterfaceError) Unwrap() error {
	return e.Err
}

// NewInterfaceError creates a new InterfaceError.
func NewInterfaceError(interfaceName, operation string, err error) *InterfaceError {
	return &InterfaceError{
		InterfaceName: interfaceName,
		Operation:     operation,
		Err:           err,
	}
}

// ConfigurationError represents a configuration-related error.
type ConfigurationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ConfigurationError) Error() string {
	return fmt.Sprintf("configuration error for field '%s': %s (value: %v)", e.Field, e.Message, e.Value)
}

// NewConfigurationError creates a new ConfigurationError.
func NewConfigurationError(field string, value interface{}, message string) *ConfigurationError {
	return &ConfigurationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}

// ValidationError represents a validation failure.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	return fmt.Sprintf("%d validation errors: %v", len(e), []ValidationError(e))
}

// HasErrors returns true if there are any validation errors.
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// =============================================================================
// Common Enumerations
// =============================================================================

// LogLevel represents logging verbosity levels.
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// IsValid returns true if the log level is valid.
func (l LogLevel) IsValid() bool {
	switch l {
	case LogLevelTrace, LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, LogLevelFatal:
		return true
	default:
		return false
	}
}

// Environment represents deployment environment types.
type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentStaging     Environment = "staging"
	EnvironmentProduction  Environment = "production"
)

// IsProduction returns true if the environment is production.
func (e Environment) IsProduction() bool {
	return e == EnvironmentProduction
}

// Protocol represents network protocols.
type Protocol string

const (
	ProtocolTCP    Protocol = "TCP"
	ProtocolUDP    Protocol = "UDP"
	ProtocolICMP   Protocol = "ICMP"
	ProtocolICMPv6 Protocol = "ICMPv6"
	ProtocolSCTP   Protocol = "SCTP"
	ProtocolGRE    Protocol = "GRE"
	ProtocolAny    Protocol = "ANY"
)

// IsValid returns true if the protocol is valid.
func (p Protocol) IsValid() bool {
	switch p {
	case ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolICMPv6, ProtocolSCTP, ProtocolGRE, ProtocolAny:
		return true
	default:
		return false
	}
}

// IPVersion represents IP address versions.
type IPVersion string

const (
	IPVersionV4      IPVersion = "IPv4"
	IPVersionV6      IPVersion = "IPv6"
	IPVersionUnknown IPVersion = "Unknown"
)

// =============================================================================
// Utility Types
// =============================================================================

// Pagination represents request pagination parameters.
type Pagination struct {
	Page       int `json:"page" yaml:"page"`
	PageSize   int `json:"page_size" yaml:"page_size"`
	TotalCount int `json:"total_count" yaml:"total_count"`
	TotalPages int `json:"total_pages" yaml:"total_pages"`
}

// NewPagination creates a new Pagination with defaults.
func NewPagination(page, pageSize int) *Pagination {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	return &Pagination{
		Page:     page,
		PageSize: pageSize,
	}
}

// Offset returns the SQL OFFSET value for this pagination.
func (p *Pagination) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// SetTotalCount sets the total count and calculates total pages.
func (p *Pagination) SetTotalCount(count int) {
	p.TotalCount = count
	if p.PageSize > 0 {
		p.TotalPages = (count + p.PageSize - 1) / p.PageSize
	}
}

// HasNextPage returns true if there is a next page.
func (p *Pagination) HasNextPage() bool {
	return p.Page < p.TotalPages
}

// HasPreviousPage returns true if there is a previous page.
func (p *Pagination) HasPreviousPage() bool {
	return p.Page > 1
}

// TimeRange represents a time-based query filter.
type TimeRange struct {
	StartTime time.Time `json:"start_time" yaml:"start_time"`
	EndTime   time.Time `json:"end_time" yaml:"end_time"`
}

// IsValid returns true if the time range is valid (start before end).
func (t *TimeRange) IsValid() bool {
	return t.StartTime.Before(t.EndTime)
}

// Duration returns the duration of the time range.
func (t *TimeRange) Duration() time.Duration {
	return t.EndTime.Sub(t.StartTime)
}

// Contains returns true if the given time is within the range.
func (t *TimeRange) Contains(tm time.Time) bool {
	return (tm.Equal(t.StartTime) || tm.After(t.StartTime)) &&
		(tm.Equal(t.EndTime) || tm.Before(t.EndTime))
}

// NewTimeRangeLast creates a TimeRange for the last N duration.
func NewTimeRangeLast(d time.Duration) *TimeRange {
	now := time.Now()
	return &TimeRange{
		StartTime: now.Add(-d),
		EndTime:   now,
	}
}

// =============================================================================
// Network Types
// =============================================================================

// IPAddressInfo represents an IP address with metadata.
type IPAddressInfo struct {
	Address   string    `json:"address" yaml:"address"`
	Version   IPVersion `json:"version" yaml:"version"`
	Prefix    int       `json:"prefix" yaml:"prefix"`
	Gateway   string    `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	IsPrimary bool      `json:"is_primary" yaml:"is_primary"`
}

// ParseIPAddressInfo parses an IP address string into IPAddressInfo.
func ParseIPAddressInfo(addr string) (*IPAddressInfo, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", addr)
	}

	version := IPVersionV4
	if ip.To4() == nil {
		version = IPVersionV6
	}

	return &IPAddressInfo{
		Address: addr,
		Version: version,
	}, nil
}

// MACAddressInfo represents a MAC address.
type MACAddressInfo struct {
	Address string `json:"address" yaml:"address"`
}

// ParseMACAddress validates and normalizes a MAC address.
func ParseMACAddress(addr string) (*MACAddressInfo, error) {
	hw, err := net.ParseMAC(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address: %s: %w", addr, err)
	}
	return &MACAddressInfo{
		Address: hw.String(),
	}, nil
}

// =============================================================================
// Statistics Types
// =============================================================================

// CounterStats represents basic counter statistics.
type CounterStats struct {
	Total   int64     `json:"total"`
	Current int64     `json:"current"`
	Peak    int64     `json:"peak"`
	PeakAt  time.Time `json:"peak_at,omitempty"`
}

// Update updates the counter and tracks peak values.
func (c *CounterStats) Update(value int64) {
	c.Current = value
	c.Total += value
	if value > c.Peak {
		c.Peak = value
		c.PeakAt = time.Now()
	}
}

// RateStats represents rate-based statistics.
type RateStats struct {
	CurrentRate float64   `json:"current_rate"`
	AverageRate float64   `json:"average_rate"`
	PeakRate    float64   `json:"peak_rate"`
	PeakAt      time.Time `json:"peak_at,omitempty"`
	Unit        string    `json:"unit"` // e.g., "pps", "bps", "rps"
}

// ByteStats represents byte-based statistics with human-readable formatting.
type ByteStats struct {
	Bytes       int64  `json:"bytes"`
	HumanFormat string `json:"human_format"`
}

// NewByteStats creates ByteStats with human-readable format.
func NewByteStats(bytes int64) ByteStats {
	return ByteStats{
		Bytes:       bytes,
		HumanFormat: FormatBytes(bytes),
	}
}

// FormatBytes formats bytes into a human-readable string.
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats a duration into a human-readable string.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

// =============================================================================
// Callback Types
// =============================================================================

// EventCallback is a generic callback function for events.
type EventCallback func(event interface{})

// ErrorCallback is a callback function for error handling.
type ErrorCallback func(err error)

// =============================================================================
// Context Values
// =============================================================================

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// ContextKeyRequestID is the context key for request IDs.
	ContextKeyRequestID ContextKey = "request_id"
	// ContextKeyUserID is the context key for user IDs.
	ContextKeyUserID ContextKey = "user_id"
	// ContextKeyTraceID is the context key for trace IDs.
	ContextKeyTraceID ContextKey = "trace_id"
	// ContextKeySpanID is the context key for span IDs.
	ContextKeySpanID ContextKey = "span_id"
)
