// Package config handles configuration loading and validation for Certificate Manager.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"certificate_manager/pkg/types"

	"github.com/BurntSushi/toml"
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultConfigPath      = "config/templates/certificate_manager.toml"
	DefaultGRPCPort        = 50053
	DefaultRenewBeforeDays = 30
	DefaultCheckInterval   = 24 * time.Hour
	MinRenewBeforeDays     = 7
	MaxRenewBeforeDays     = 89
	MinCheckInterval       = 1 * time.Hour
	MaxCheckInterval       = 168 * time.Hour // 1 week
)

// Let's Encrypt URLs
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Environment variable for config path
const ConfigPathEnvVar = "CERTMGR_CONFIG_PATH"

// ============================================================================
// Configuration Structure
// ============================================================================

// RawConfig mirrors the TOML file structure for parsing
type RawConfig struct {
	Service       RawServiceConfig       `toml:"service"`
	GRPC          RawGRPCConfig          `toml:"grpc"`
	ACME          RawACMEConfig          `toml:"acme"`
	Domains       []RawDomainConfig      `toml:"domains"`
	Storage       RawStorageConfig       `toml:"storage"`
	Database      RawDatabaseConfig      `toml:"database"`
	Renewal       RawRenewalConfig       `toml:"renewal"`
	Distribution  RawDistributionConfig  `toml:"distribution"`
	HTTPChallenge RawHTTPChallengeConfig `toml:"http_challenge"`
	DNSChallenge  RawDNSChallengeConfig  `toml:"dns_challenge"`
	Metrics       RawMetricsConfig       `toml:"metrics"`
	Health        RawHealthConfig        `toml:"health"`
	// SafeOps Internal CA Sections
	CA         RawCAConfig         `toml:"ca"`
	CRL        RawCRLConfig        `toml:"crl"`
	OCSP       RawOCSPConfig       `toml:"ocsp"`
	Security   RawSecurityConfig   `toml:"security"`
	Backup     RawBackupConfig     `toml:"backup"`
	HTTPServer RawHTTPServerConfig `toml:"http_server"`
}

type RawServiceConfig struct {
	Name             string `toml:"name"`
	Version          string `toml:"version"`
	Environment      string `toml:"environment"`
	LogLevel         string `toml:"log_level"`
	LogFormat        string `toml:"log_format"`
	LogFile          string `toml:"log_file"`
	PIDFile          string `toml:"pid_file"`
	WorkingDirectory string `toml:"working_directory"`
}

type RawGRPCConfig struct {
	Enabled              bool   `toml:"enabled"`
	Host                 string `toml:"host"`
	Port                 string `toml:"port"`
	MaxConcurrentStreams int    `toml:"max_concurrent_streams"`
	MaxConnectionIdle    string `toml:"max_connection_idle"`
	MaxConnectionAge     string `toml:"max_connection_age"`
	KeepaliveTime        string `toml:"keepalive_time"`
	KeepaliveTimeout     string `toml:"keepalive_timeout"`
	ReflectionEnabled    bool   `toml:"reflection_enabled"`
}

type RawACMEConfig struct {
	DirectoryURL       string `toml:"directory_url"`
	Email              string `toml:"email"`
	TermsAgreed        bool   `toml:"terms_agreed"`
	PreferredChallenge string `toml:"preferred_challenge"`
	KeyType            string `toml:"key_type"`
	Timeout            string `toml:"timeout"`
	RetryAttempts      int    `toml:"retry_attempts"`
	RetryDelay         string `toml:"retry_delay"`
	RateLimitBuffer    int    `toml:"rate_limit_buffer"`
}

type RawDomainConfig struct {
	CommonName        string   `toml:"common_name"`
	SubjectAltNames   []string `toml:"subject_alt_names"`
	Wildcard          bool     `toml:"wildcard"`
	ChallengeType     string   `toml:"challenge_type"`
	Enabled           bool     `toml:"enabled"`
	AutoRenew         bool     `toml:"auto_renew"`
	RenewBeforeDays   int      `toml:"renew_before_days"`
	DNSProvider       string   `toml:"dns_provider"`
	HTTPChallengePort int      `toml:"http_challenge_port"`
}

type RawStorageConfig struct {
	Type              string `toml:"type"`
	CertPath          string `toml:"cert_path"`
	KeyPath           string `toml:"key_path"`
	ChainPath         string `toml:"chain_path"`
	BackupPath        string `toml:"backup_path"`
	FilePermissions   string `toml:"file_permissions"`
	DirPermissions    string `toml:"directory_permissions"`
	EncryptKeys       bool   `toml:"encrypt_keys"`
	EncryptionKeyFile string `toml:"encryption_key_file"`
}

type RawDatabaseConfig struct {
	Enabled            bool   `toml:"enabled"`
	Host               string `toml:"host"`
	Port               string `toml:"port"`
	Name               string `toml:"name"`
	User               string `toml:"user"`
	Password           string `toml:"password"`
	SSLMode            string `toml:"sslmode"`
	MaxConnections     int    `toml:"max_connections"`
	IdleConnections    int    `toml:"idle_connections"`
	ConnectionLifetime string `toml:"connection_lifetime"`
	ConnectionTimeout  string `toml:"connection_timeout"`
}

type RawRenewalConfig struct {
	Enabled               bool     `toml:"enabled"`
	CheckInterval         string   `toml:"check_interval"`
	RenewBeforeDays       int      `toml:"renew_before_days"`
	MaxConcurrentRenewals int      `toml:"max_concurrent_renewals"`
	RetryFailedRenewals   bool     `toml:"retry_failed_renewals"`
	RetryInterval         string   `toml:"retry_interval"`
	MaxRetryAttempts      int      `toml:"max_retry_attempts"`
	NotificationEnabled   bool     `toml:"notification_enabled"`
	NotificationChannels  []string `toml:"notification_channels"`
}

type RawDistributionConfig struct {
	Enabled               bool     `toml:"enabled"`
	Method                string   `toml:"method"`
	TargetServices        []string `toml:"target_services"`
	RetryFailed           bool     `toml:"retry_failed"`
	RetryInterval         string   `toml:"retry_interval"`
	MaxRetryAttempts      int      `toml:"max_retry_attempts"`
	NotificationOnFailure bool     `toml:"notification_on_failure"`
}

type RawHTTPChallengeConfig struct {
	Enabled       bool   `toml:"enabled"`
	Port          int    `toml:"port"`
	BindAddress   string `toml:"bind_address"`
	Timeout       string `toml:"timeout"`
	WellKnownPath string `toml:"well_known_path"`
	AllowExternal bool   `toml:"allow_external"`
}

type RawDNSChallengeConfig struct {
	Enabled            bool   `toml:"enabled"`
	Provider           string `toml:"provider"`
	APIToken           string `toml:"api_token"`
	APIKey             string `toml:"api_key"`
	APISecret          string `toml:"api_secret"`
	PropagationTimeout string `toml:"propagation_timeout"`
	PollingInterval    string `toml:"polling_interval"`
	TTL                int    `toml:"ttl"`
}

type RawMetricsConfig struct {
	Enabled              bool   `toml:"enabled"`
	Port                 int    `toml:"port"`
	Path                 string `toml:"path"`
	IncludeSystemMetrics bool   `toml:"include_system_metrics"`
}

type RawHealthConfig struct {
	Enabled               bool   `toml:"enabled"`
	Port                  int    `toml:"port"`
	Path                  string `toml:"path"`
	CheckDatabase         bool   `toml:"check_database"`
	CheckACMEConnectivity bool   `toml:"check_acme_connectivity"`
}

// ============================================================================
// SafeOps Internal CA Configuration Structures
// ============================================================================

// RawCAConfig for internal SafeOps CA
type RawCAConfig struct {
	Organization       string `toml:"organization"`
	OrganizationalUnit string `toml:"organizational_unit"`
	Country            string `toml:"country"`
	Province           string `toml:"province"`
	Locality           string `toml:"locality"`
	ValidityYears      int    `toml:"validity_years"`
	KeySize            int    `toml:"key_size"`
	KeyType            string `toml:"key_type"`
	SignatureHash      string `toml:"signature_hash"`
	SerialNumberBits   int    `toml:"serial_number_bits"`
	CAKeyPath          string `toml:"ca_key_path"`
	CACertPath         string `toml:"ca_cert_path"`
	CAChainPath        string `toml:"ca_chain_path"`
	PassphraseFile     string `toml:"passphrase_file"`
	EncryptPrivateKey  bool   `toml:"encrypt_private_key"`
	HSMEnabled         bool   `toml:"hsm_enabled"`
	HSMSlotID          int    `toml:"hsm_slot_id"`
	AutoGenerate       bool   `toml:"auto_generate"`
}

// RawCRLConfig for CRL generation
type RawCRLConfig struct {
	Enabled          bool   `toml:"enabled"`
	UpdateInterval   string `toml:"update_interval"`
	NextUpdateOffset string `toml:"next_update_offset"`
	CRLPath          string `toml:"crl_path"`
	CRLURL           string `toml:"crl_url"`
	CRLDERPath       string `toml:"crl_der_path"`
	MaxCRLSize       int    `toml:"max_crl_size"`
	SignatureHash    string `toml:"signature_hash"`
	ServeHTTP        bool   `toml:"serve_http"`
	HTTPPort         int    `toml:"http_port"`
}

// RawOCSPConfig for OCSP responder
type RawOCSPConfig struct {
	Enabled               bool   `toml:"enabled"`
	BindAddress           string `toml:"bind_address"`
	Port                  int    `toml:"port"`
	OCSPURL               string `toml:"ocsp_url"`
	SignerCertPath        string `toml:"signer_cert_path"`
	SignerKeyPath         string `toml:"signer_key_path"`
	SignerCertValidity    string `toml:"signer_cert_validity"`
	ResponseValidity      string `toml:"response_validity"`
	CacheEnabled          bool   `toml:"cache_enabled"`
	CacheTTL              string `toml:"cache_ttl"`
	MaxConcurrentRequests int    `toml:"max_concurrent_requests"`
	Timeout               string `toml:"timeout"`
}

// RawSecurityConfig for audit and rate limiting
type RawSecurityConfig struct {
	AuditLoggingEnabled   bool     `toml:"audit_logging_enabled"`
	AuditLogPath          string   `toml:"audit_log_path"`
	AuditLogMaxSize       int      `toml:"audit_log_max_size"`
	AuditLogMaxBackups    int      `toml:"audit_log_max_backups"`
	RateLimitEnabled      bool     `toml:"rate_limit_enabled"`
	MaxCertsPerHour       int      `toml:"max_certs_per_hour"`
	MaxCertsPerDay        int      `toml:"max_certs_per_day"`
	MaxRevocationsPerDay  int      `toml:"max_revocations_per_day"`
	RequireAuthentication bool     `toml:"require_authentication"`
	AllowedIPs            []string `toml:"allowed_ips"`
	AllowedSubnets        []string `toml:"allowed_subnets"`
	KeyRotationEnabled    bool     `toml:"key_rotation_enabled"`
	KeyRotationInterval   string   `toml:"key_rotation_interval"`
}

// RawBackupConfig for CA backup settings
type RawBackupConfig struct {
	Enabled           bool   `toml:"enabled"`
	BackupInterval    string `toml:"backup_interval"`
	BackupPath        string `toml:"backup_path"`
	RetentionDays     int    `toml:"retention_days"`
	MaxBackups        int    `toml:"max_backups"`
	IncludePrivateKey bool   `toml:"include_private_key"`
	EncryptBackup     bool   `toml:"encrypt_backup"`
	CompressBackup    bool   `toml:"compress_backup"`
}

// RawHTTPServerConfig for CA distribution HTTP server
type RawHTTPServerConfig struct {
	Enabled        bool   `toml:"enabled"`
	BindAddress    string `toml:"bind_address"`
	Port           int    `toml:"port"`
	TLSEnabled     bool   `toml:"tls_enabled"`
	TLSCertPath    string `toml:"tls_cert_path"`
	TLSKeyPath     string `toml:"tls_key_path"`
	BasePath       string `toml:"base_path"`
	MaxRequestSize int64  `toml:"max_request_size"`
	RateLimit      int    `toml:"rate_limit"`
}

// ============================================================================
// Configuration Loader
// ============================================================================

// Load reads and validates the configuration file
func Load(path string) (*types.Config, error) {
	// Determine config path
	configPath := path
	if configPath == "" {
		configPath = os.Getenv(ConfigPathEnvVar)
	}
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	// Read file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Expand environment variables
	expandedData := expandEnvVars(string(data))

	// Parse TOML
	var raw RawConfig
	if _, err := toml.Decode(expandedData, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Convert to typed config
	config, err := convertConfig(&raw)
	if err != nil {
		return nil, fmt.Errorf("config conversion failed: %w", err)
	}

	// Apply defaults
	applyDefaults(config)

	// Validate
	if err := Validate(config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return config, nil
}

// LoadFromString parses config from string (for testing)
func LoadFromString(data string) (*types.Config, error) {
	expandedData := expandEnvVars(data)

	var raw RawConfig
	if _, err := toml.Decode(expandedData, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	config, err := convertConfig(&raw)
	if err != nil {
		return nil, err
	}

	applyDefaults(config)
	return config, Validate(config)
}

// ============================================================================
// Environment Variable Expansion
// ============================================================================

var envVarRegex = regexp.MustCompile(`\$\{([^}:]+)(?::-([^}]*))?\}`)

// expandEnvVars replaces ${VAR} and ${VAR:-default} patterns
func expandEnvVars(s string) string {
	return envVarRegex.ReplaceAllStringFunc(s, func(match string) string {
		submatches := envVarRegex.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		varName := submatches[1]
		defaultValue := ""
		if len(submatches) >= 3 {
			defaultValue = submatches[2]
		}

		value := os.Getenv(varName)
		if value == "" {
			return defaultValue
		}
		return value
	})
}

// ============================================================================
// Configuration Converter
// ============================================================================

func convertConfig(raw *RawConfig) (*types.Config, error) {
	config := &types.Config{}

	// Service
	config.Service = types.ServiceConfig{
		Name:             raw.Service.Name,
		Version:          raw.Service.Version,
		Environment:      raw.Service.Environment,
		LogLevel:         raw.Service.LogLevel,
		LogFormat:        raw.Service.LogFormat,
		LogFile:          raw.Service.LogFile,
		PIDFile:          raw.Service.PIDFile,
		WorkingDirectory: raw.Service.WorkingDirectory,
	}

	// GRPC
	grpcPort := parseIntOrDefault(raw.GRPC.Port, DefaultGRPCPort)
	config.GRPC = types.GRPCConfig{
		Enabled:              raw.GRPC.Enabled,
		Host:                 raw.GRPC.Host,
		Port:                 grpcPort,
		MaxConcurrentStreams: raw.GRPC.MaxConcurrentStreams,
		MaxConnectionIdle:    parseDuration(raw.GRPC.MaxConnectionIdle, 5*time.Minute),
		MaxConnectionAge:     parseDuration(raw.GRPC.MaxConnectionAge, 30*time.Minute),
		KeepaliveTime:        parseDuration(raw.GRPC.KeepaliveTime, 30*time.Second),
		KeepaliveTimeout:     parseDuration(raw.GRPC.KeepaliveTimeout, 10*time.Second),
		ReflectionEnabled:    raw.GRPC.ReflectionEnabled,
	}

	// ACME
	challengeType, _ := types.ParseChallengeType(raw.ACME.PreferredChallenge)
	keyType, _ := types.ParseKeyType(raw.ACME.KeyType)
	config.ACME = types.AcmeConfig{
		DirectoryURL:       raw.ACME.DirectoryURL,
		Email:              raw.ACME.Email,
		TermsAgreed:        raw.ACME.TermsAgreed,
		PreferredChallenge: challengeType,
		KeyType:            keyType,
		Timeout:            parseDuration(raw.ACME.Timeout, 60*time.Second),
		RetryAttempts:      raw.ACME.RetryAttempts,
		RetryDelay:         parseDuration(raw.ACME.RetryDelay, 10*time.Second),
		RateLimitBuffer:    raw.ACME.RateLimitBuffer,
	}

	// Domains
	for _, d := range raw.Domains {
		ct, _ := types.ParseChallengeType(d.ChallengeType)
		config.Domains = append(config.Domains, types.DomainConfig{
			CommonName:        d.CommonName,
			SubjectAltNames:   d.SubjectAltNames,
			Wildcard:          d.Wildcard,
			ChallengeType:     ct,
			Enabled:           d.Enabled,
			AutoRenew:         d.AutoRenew,
			RenewBeforeDays:   d.RenewBeforeDays,
			DNSProvider:       d.DNSProvider,
			HTTPChallengePort: d.HTTPChallengePort,
		})
	}

	// Storage
	storageType := types.StorageBoth
	switch strings.ToLower(raw.Storage.Type) {
	case "filesystem":
		storageType = types.StorageFilesystem
	case "database":
		storageType = types.StorageDatabase
	}
	config.Storage = types.StorageConfig{
		Type:              storageType,
		CertPath:          raw.Storage.CertPath,
		KeyPath:           raw.Storage.KeyPath,
		ChainPath:         raw.Storage.ChainPath,
		BackupPath:        raw.Storage.BackupPath,
		FilePermissions:   parseFilePermissions(raw.Storage.FilePermissions, 0600),
		EncryptKeys:       raw.Storage.EncryptKeys,
		EncryptionKeyFile: raw.Storage.EncryptionKeyFile,
	}

	// Database
	dbPort := parseIntOrDefault(raw.Database.Port, 5432)
	config.Database = types.DatabaseConfig{
		Enabled:            raw.Database.Enabled,
		Host:               raw.Database.Host,
		Port:               dbPort,
		Name:               raw.Database.Name,
		User:               raw.Database.User,
		Password:           raw.Database.Password,
		SSLMode:            raw.Database.SSLMode,
		MaxConnections:     raw.Database.MaxConnections,
		IdleConnections:    raw.Database.IdleConnections,
		ConnectionLifetime: parseDuration(raw.Database.ConnectionLifetime, 30*time.Minute),
		ConnectionTimeout:  parseDuration(raw.Database.ConnectionTimeout, 10*time.Second),
	}

	// Renewal
	config.Renewal = types.RenewalConfig{
		Enabled:               raw.Renewal.Enabled,
		CheckInterval:         parseDuration(raw.Renewal.CheckInterval, DefaultCheckInterval),
		RenewBeforeDays:       raw.Renewal.RenewBeforeDays,
		MaxConcurrentRenewals: raw.Renewal.MaxConcurrentRenewals,
		RetryFailedRenewals:   raw.Renewal.RetryFailedRenewals,
		RetryInterval:         parseDuration(raw.Renewal.RetryInterval, 6*time.Hour),
		MaxRetryAttempts:      raw.Renewal.MaxRetryAttempts,
		NotificationEnabled:   raw.Renewal.NotificationEnabled,
		NotificationChannels:  raw.Renewal.NotificationChannels,
	}

	// Distribution
	distMethod := types.DistMethodGRPCPush
	switch strings.ToLower(raw.Distribution.Method) {
	case "file_copy":
		distMethod = types.DistMethodFileCopy
	case "api_call":
		distMethod = types.DistMethodAPICall
	}
	config.Distribution = types.DistributionConfig{
		Enabled:               raw.Distribution.Enabled,
		Method:                distMethod,
		TargetServices:        raw.Distribution.TargetServices,
		RetryFailed:           raw.Distribution.RetryFailed,
		RetryInterval:         parseDuration(raw.Distribution.RetryInterval, 5*time.Minute),
		MaxRetryAttempts:      raw.Distribution.MaxRetryAttempts,
		NotificationOnFailure: raw.Distribution.NotificationOnFailure,
	}

	// HTTP Challenge
	config.HTTPChallenge = types.HTTPChallengeConfig{
		Enabled:       raw.HTTPChallenge.Enabled,
		Port:          raw.HTTPChallenge.Port,
		BindAddress:   raw.HTTPChallenge.BindAddress,
		WellKnownPath: raw.HTTPChallenge.WellKnownPath,
		Timeout:       parseDuration(raw.HTTPChallenge.Timeout, 30*time.Second),
		AllowExternal: raw.HTTPChallenge.AllowExternal,
	}

	// DNS Challenge
	config.DNSChallenge = types.DNSChallengeConfig{
		Enabled:            raw.DNSChallenge.Enabled,
		Provider:           raw.DNSChallenge.Provider,
		APIToken:           raw.DNSChallenge.APIToken,
		APIKey:             raw.DNSChallenge.APIKey,
		APISecret:          raw.DNSChallenge.APISecret,
		PropagationTimeout: parseDuration(raw.DNSChallenge.PropagationTimeout, 120*time.Second),
		PollingInterval:    parseDuration(raw.DNSChallenge.PollingInterval, 10*time.Second),
		TTL:                raw.DNSChallenge.TTL,
	}

	// Metrics
	config.Metrics = types.MetricsConfig{
		Enabled:              raw.Metrics.Enabled,
		Port:                 raw.Metrics.Port,
		Path:                 raw.Metrics.Path,
		IncludeSystemMetrics: raw.Metrics.IncludeSystemMetrics,
	}

	// Health
	config.Health = types.HealthConfig{
		Enabled:               raw.Health.Enabled,
		Port:                  raw.Health.Port,
		Path:                  raw.Health.Path,
		CheckDatabase:         raw.Health.CheckDatabase,
		CheckACMEConnectivity: raw.Health.CheckACMEConnectivity,
	}

	// SafeOps Internal CA Configuration
	caKeyType, _ := types.ParseKeyType(raw.CA.KeyType)
	config.CA = &types.CAConfig{
		Organization:       raw.CA.Organization,
		OrganizationalUnit: raw.CA.OrganizationalUnit,
		Country:            raw.CA.Country,
		Province:           raw.CA.Province,
		Locality:           raw.CA.Locality,
		ValidityYears:      raw.CA.ValidityYears,
		KeySize:            raw.CA.KeySize,
		KeyType:            caKeyType,
		SignatureHash:      raw.CA.SignatureHash,
		SerialNumberBits:   raw.CA.SerialNumberBits,
		CAKeyPath:          raw.CA.CAKeyPath,
		CACertPath:         raw.CA.CACertPath,
		CAChainPath:        raw.CA.CAChainPath,
		PassphraseFile:     raw.CA.PassphraseFile,
		EncryptPrivateKey:  raw.CA.EncryptPrivateKey,
		HSMEnabled:         raw.CA.HSMEnabled,
		HSMSlotID:          raw.CA.HSMSlotID,
		AutoGenerate:       raw.CA.AutoGenerate,
	}

	// CRL Configuration
	config.CRL = &types.CRLConfig{
		Enabled:          raw.CRL.Enabled,
		UpdateInterval:   parseDuration(raw.CRL.UpdateInterval, 24*time.Hour),
		NextUpdateOffset: parseDuration(raw.CRL.NextUpdateOffset, 7*24*time.Hour),
		CRLPath:          raw.CRL.CRLPath,
		CRLURL:           raw.CRL.CRLURL,
		CRLDERPath:       raw.CRL.CRLDERPath,
		MaxCRLSize:       raw.CRL.MaxCRLSize,
		SignatureHash:    raw.CRL.SignatureHash,
		ServeHTTP:        raw.CRL.ServeHTTP,
		HTTPPort:         raw.CRL.HTTPPort,
	}

	// OCSP Configuration
	config.OCSP = &types.OCSPConfig{
		Enabled:               raw.OCSP.Enabled,
		BindAddress:           raw.OCSP.BindAddress,
		Port:                  raw.OCSP.Port,
		OCSPURL:               raw.OCSP.OCSPURL,
		SignerCertPath:        raw.OCSP.SignerCertPath,
		SignerKeyPath:         raw.OCSP.SignerKeyPath,
		SignerCertValidity:    parseDuration(raw.OCSP.SignerCertValidity, 30*24*time.Hour),
		ResponseValidity:      parseDuration(raw.OCSP.ResponseValidity, 1*time.Hour),
		CacheEnabled:          raw.OCSP.CacheEnabled,
		CacheTTL:              parseDuration(raw.OCSP.CacheTTL, 5*time.Minute),
		MaxConcurrentRequests: raw.OCSP.MaxConcurrentRequests,
		Timeout:               parseDuration(raw.OCSP.Timeout, 10*time.Second),
	}

	// Security Configuration
	config.Security = &types.SecurityConfig{
		AuditLoggingEnabled:   raw.Security.AuditLoggingEnabled,
		AuditLogPath:          raw.Security.AuditLogPath,
		AuditLogMaxSize:       raw.Security.AuditLogMaxSize,
		AuditLogMaxBackups:    raw.Security.AuditLogMaxBackups,
		RateLimitEnabled:      raw.Security.RateLimitEnabled,
		MaxCertsPerHour:       raw.Security.MaxCertsPerHour,
		MaxCertsPerDay:        raw.Security.MaxCertsPerDay,
		MaxRevocationsPerDay:  raw.Security.MaxRevocationsPerDay,
		RequireAuthentication: raw.Security.RequireAuthentication,
		AllowedIPs:            raw.Security.AllowedIPs,
		AllowedSubnets:        raw.Security.AllowedSubnets,
		KeyRotationEnabled:    raw.Security.KeyRotationEnabled,
		KeyRotationInterval:   parseDuration(raw.Security.KeyRotationInterval, 0),
	}

	// Backup Configuration
	config.Backup = &types.BackupConfig{
		Enabled:           raw.Backup.Enabled,
		BackupInterval:    parseDuration(raw.Backup.BackupInterval, 24*time.Hour),
		BackupPath:        raw.Backup.BackupPath,
		RetentionDays:     raw.Backup.RetentionDays,
		MaxBackups:        raw.Backup.MaxBackups,
		IncludePrivateKey: raw.Backup.IncludePrivateKey,
		EncryptBackup:     raw.Backup.EncryptBackup,
		CompressBackup:    raw.Backup.CompressBackup,
	}

	// HTTP Server Configuration
	config.HTTPServer = &types.HTTPServerConfig{
		Enabled:        raw.HTTPServer.Enabled,
		BindAddress:    raw.HTTPServer.BindAddress,
		Port:           raw.HTTPServer.Port,
		TLSEnabled:     raw.HTTPServer.TLSEnabled,
		TLSCertPath:    raw.HTTPServer.TLSCertPath,
		TLSKeyPath:     raw.HTTPServer.TLSKeyPath,
		BasePath:       raw.HTTPServer.BasePath,
		MaxRequestSize: raw.HTTPServer.MaxRequestSize,
		RateLimit:      raw.HTTPServer.RateLimit,
	}

	return config, nil
}

// ============================================================================
// Default Values
// ============================================================================

func applyDefaults(config *types.Config) {
	// Service defaults
	if config.Service.Name == "" {
		config.Service.Name = "certificate_manager"
	}
	if config.Service.Version == "" {
		config.Service.Version = "2.0.0"
	}
	if config.Service.LogLevel == "" {
		config.Service.LogLevel = "info"
	}

	// GRPC defaults
	if config.GRPC.Port == 0 {
		config.GRPC.Port = DefaultGRPCPort
	}
	if config.GRPC.Host == "" {
		config.GRPC.Host = "0.0.0.0"
	}

	// ACME defaults
	if config.ACME.DirectoryURL == "" {
		config.ACME.DirectoryURL = LetsEncryptProduction
	}
	if config.ACME.PreferredChallenge == "" {
		config.ACME.PreferredChallenge = types.ChallengeHTTP01
	}
	if config.ACME.KeyType == "" {
		config.ACME.KeyType = types.KeyECDSAP256
	}
	if config.ACME.RetryAttempts == 0 {
		config.ACME.RetryAttempts = 3
	}

	// Renewal defaults
	if config.Renewal.RenewBeforeDays == 0 {
		config.Renewal.RenewBeforeDays = DefaultRenewBeforeDays
	}
	if config.Renewal.MaxConcurrentRenewals == 0 {
		config.Renewal.MaxConcurrentRenewals = 2
	}
	if config.Renewal.MaxRetryAttempts == 0 {
		config.Renewal.MaxRetryAttempts = 5
	}

	// Database defaults
	if config.Database.Host == "" {
		config.Database.Host = "localhost"
	}
	if config.Database.Port == 0 {
		config.Database.Port = 5432
	}
	if config.Database.Name == "" {
		config.Database.Name = "safeops_db"
	}
	if config.Database.SSLMode == "" {
		config.Database.SSLMode = "disable"
	}
	if config.Database.MaxConnections == 0 {
		config.Database.MaxConnections = 10
	}

	// HTTP Challenge defaults
	if config.HTTPChallenge.Port == 0 {
		config.HTTPChallenge.Port = 80
	}
	if config.HTTPChallenge.WellKnownPath == "" {
		config.HTTPChallenge.WellKnownPath = "/.well-known/acme-challenge"
	}

	// Metrics defaults
	if config.Metrics.Port == 0 {
		config.Metrics.Port = 9093
	}
	if config.Metrics.Path == "" {
		config.Metrics.Path = "/metrics"
	}

	// Health defaults
	if config.Health.Port == 0 {
		config.Health.Port = 8093
	}
	if config.Health.Path == "" {
		config.Health.Path = "/health"
	}
}

// ============================================================================
// Validation Functions
// ============================================================================

// Validate performs comprehensive config validation
func Validate(config *types.Config) error {
	var errs []string

	if err := ValidateACME(&config.ACME); err != nil {
		errs = append(errs, fmt.Sprintf("ACME: %v", err))
	}

	if err := ValidateDomains(config.Domains); err != nil {
		errs = append(errs, fmt.Sprintf("Domains: %v", err))
	}

	if err := ValidateRenewal(&config.Renewal); err != nil {
		errs = append(errs, fmt.Sprintf("Renewal: %v", err))
	}

	if config.Database.Enabled {
		if err := ValidateDatabase(&config.Database); err != nil {
			errs = append(errs, fmt.Sprintf("Database: %v", err))
		}
	}

	if config.GRPC.Enabled {
		if err := ValidateGRPC(&config.GRPC); err != nil {
			errs = append(errs, fmt.Sprintf("GRPC: %v", err))
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// ValidateACME validates ACME configuration
func ValidateACME(cfg *types.AcmeConfig) error {
	if cfg.Email == "" {
		return errors.New("email is required")
	}

	if err := types.ValidateEmail(cfg.Email); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	if cfg.DirectoryURL != "" {
		u, err := url.Parse(cfg.DirectoryURL)
		if err != nil {
			return fmt.Errorf("invalid directory URL: %w", err)
		}
		if u.Scheme != "https" {
			return errors.New("ACME directory URL must use HTTPS")
		}
	}

	if !cfg.TermsAgreed {
		return errors.New("terms_agreed must be true to use Let's Encrypt")
	}

	return nil
}

// ValidateDomains validates domain configurations
func ValidateDomains(domains []types.DomainConfig) error {
	if len(domains) == 0 {
		return nil // Domains are optional at startup
	}

	enabledCount := 0
	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		enabledCount++

		if err := d.Validate(); err != nil {
			return fmt.Errorf("domain %s: %w", d.CommonName, err)
		}
	}

	return nil
}

// ValidateRenewal validates renewal configuration
func ValidateRenewal(cfg *types.RenewalConfig) error {
	if !cfg.Enabled {
		return nil
	}

	if cfg.CheckInterval < MinCheckInterval {
		return fmt.Errorf("check_interval must be at least %v", MinCheckInterval)
	}

	if cfg.CheckInterval > MaxCheckInterval {
		return fmt.Errorf("check_interval must not exceed %v", MaxCheckInterval)
	}

	if cfg.RenewBeforeDays < MinRenewBeforeDays {
		return fmt.Errorf("renew_before_days must be at least %d", MinRenewBeforeDays)
	}

	if cfg.RenewBeforeDays > MaxRenewBeforeDays {
		return fmt.Errorf("renew_before_days must not exceed %d", MaxRenewBeforeDays)
	}

	return nil
}

// ValidateDatabase validates database configuration
func ValidateDatabase(cfg *types.DatabaseConfig) error {
	if cfg.Host == "" {
		return errors.New("host is required")
	}

	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be 1-65535, got %d", cfg.Port)
	}

	if cfg.Name == "" {
		return errors.New("database name is required")
	}

	if cfg.User == "" {
		return errors.New("user is required")
	}

	return nil
}

// ValidateGRPC validates gRPC configuration
func ValidateGRPC(cfg *types.GRPCConfig) error {
	if cfg.Port < 1024 || cfg.Port > 65535 {
		return fmt.Errorf("port must be 1024-65535, got %d", cfg.Port)
	}

	return nil
}

// ValidateStorage validates storage paths
func ValidateStorage(cfg *types.StorageConfig) error {
	paths := []string{cfg.CertPath, cfg.KeyPath, cfg.ChainPath}

	for _, path := range paths {
		if path == "" {
			continue
		}

		dir := filepath.Dir(path)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("cannot create directory %s: %w", dir, err)
			}
		}
	}

	return nil
}

// ============================================================================
// Debug/Display Functions
// ============================================================================

// String returns a human-readable config summary
func String(config *types.Config) string {
	var sb strings.Builder

	sb.WriteString("Certificate Manager Configuration:\n")
	sb.WriteString(fmt.Sprintf("  Service: %s v%s (%s)\n",
		config.Service.Name, config.Service.Version, config.Service.Environment))
	sb.WriteString(fmt.Sprintf("  ACME: %s (email: %s)\n",
		config.ACME.DirectoryURL, config.ACME.Email))
	sb.WriteString(fmt.Sprintf("  gRPC: %s:%d (enabled: %v)\n",
		config.GRPC.Host, config.GRPC.Port, config.GRPC.Enabled))
	sb.WriteString(fmt.Sprintf("  Domains: %d configured\n", len(config.Domains)))
	sb.WriteString(fmt.Sprintf("  Renewal: every %v, %d days before expiry\n",
		config.Renewal.CheckInterval, config.Renewal.RenewBeforeDays))
	sb.WriteString(fmt.Sprintf("  Database: %s@%s:%d/%s (enabled: %v)\n",
		config.Database.User, config.Database.Host, config.Database.Port,
		config.Database.Name, config.Database.Enabled))

	return sb.String()
}

// Redact creates a copy with secrets masked
func Redact(config *types.Config) *types.Config {
	copy := *config
	copy.Database.Password = "***REDACTED***"
	copy.DNSChallenge.APIToken = "***REDACTED***"
	copy.DNSChallenge.APIKey = "***REDACTED***"
	copy.DNSChallenge.APISecret = "***REDACTED***"
	return &copy
}

// ============================================================================
// Helper Functions
// ============================================================================

func parseDuration(s string, defaultVal time.Duration) time.Duration {
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultVal
	}
	return d
}

func parseIntOrDefault(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	var val int
	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		return defaultVal
	}
	return val
}

func parseFilePermissions(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	var val int
	_, err := fmt.Sscanf(s, "%o", &val)
	if err != nil {
		return defaultVal
	}
	return val
}
