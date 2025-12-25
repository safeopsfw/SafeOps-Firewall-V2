// Package types defines core data structures for the Certificate Manager service.
// This package has no external dependencies and can be imported by any other package.
package types

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// Section 11: Constants
// ============================================================================

// Default Values
const (
	DefaultGRPCPort          = 50053
	DefaultRenewBeforeDays   = 30
	DefaultCheckInterval     = 24 * time.Hour
	DefaultMaxRetries        = 3
	DefaultHTTPChallengePort = 80
	DefaultRetryDelay        = 5 * time.Minute
	DefaultDistributionRetry = 10 * time.Minute
)

// Let's Encrypt URLs
const (
	LetsEncryptProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingURL    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Certificate Validity
const (
	MinCertificateValidityDays = 1
	MaxCertificateValidityDays = 90 // Let's Encrypt maximum
)

// File Permissions
const (
	DefaultCertFilePermissions = 0644
	DefaultKeyFilePermissions  = 0600
	DefaultDirPermissions      = 0755
)

// ============================================================================
// Section 2: Certificate Types
// ============================================================================

// CertificateStatus represents the lifecycle state of a certificate
type CertificateStatus string

const (
	CertStatusPending        CertificateStatus = "pending"
	CertStatusActive         CertificateStatus = "active"
	CertStatusExpired        CertificateStatus = "expired"
	CertStatusRevoked        CertificateStatus = "revoked"
	CertStatusRenewalPending CertificateStatus = "renewal_pending"
	CertStatusFailed         CertificateStatus = "failed"
)

func (cs CertificateStatus) String() string { return string(cs) }

// Certificate represents an SSL/TLS certificate with its private key
type Certificate struct {
	ID              int64             `json:"id"`
	CommonName      string            `json:"common_name"`
	SubjectAltNames []string          `json:"subject_alt_names"`
	IsWildcard      bool              `json:"is_wildcard"`
	CertificatePEM  string            `json:"certificate_pem"`
	PrivateKeyPEM   string            `json:"-"` // Never serialize private key
	ChainPEM        string            `json:"chain_pem"`
	SerialNumber    string            `json:"serial_number"`
	Issuer          string            `json:"issuer"`
	NotBefore       time.Time         `json:"not_before"`
	NotAfter        time.Time         `json:"not_after"`
	Status          CertificateStatus `json:"status"`
	AcmeAccountID   int64             `json:"acme_account_id"`
	ChallengeType   ChallengeType     `json:"challenge_type"`
	AcmeOrderURL    string            `json:"acme_order_url"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// CertificateRequest for requesting a new certificate
type CertificateRequest struct {
	CommonName      string        `json:"common_name"`
	SubjectAltNames []string      `json:"subject_alt_names"`
	ChallengeType   ChallengeType `json:"challenge_type"`
	KeyType         KeyType       `json:"key_type"`
	Wildcard        bool          `json:"wildcard"`
}

// CertificateMetadata contains certificate details
type CertificateMetadata struct {
	Fingerprint        string `json:"fingerprint"`
	KeySize            int    `json:"key_size"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Version            int    `json:"version"`
}

// ============================================================================
// Section 3: ACME Account Types
// ============================================================================

// AccountStatus represents ACME account state
type AccountStatus string

const (
	AccountStatusActive      AccountStatus = "active"
	AccountStatusDeactivated AccountStatus = "deactivated"
	AccountStatusRevoked     AccountStatus = "revoked"
)

func (as AccountStatus) String() string { return string(as) }

// AcmeAccount represents a Let's Encrypt account
type AcmeAccount struct {
	ID              int64         `json:"id"`
	Email           string        `json:"email"`
	PrivateKeyPEM   string        `json:"-"`
	DirectoryURL    string        `json:"directory_url"`
	RegistrationURL string        `json:"registration_url"`
	Status          AccountStatus `json:"status"`
	TermsAgreed     bool          `json:"terms_agreed"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// AcmeAccountRequest for creating a new account
type AcmeAccountRequest struct {
	Email        string `json:"email"`
	DirectoryURL string `json:"directory_url"`
	AcceptTerms  bool   `json:"accept_terms"`
}

// ============================================================================
// Section 4: ACME Challenge Types
// ============================================================================

// ChallengeType represents ACME challenge methods
type ChallengeType string

const (
	ChallengeHTTP01    ChallengeType = "http-01"
	ChallengeDNS01     ChallengeType = "dns-01"
	ChallengeTLSALPN01 ChallengeType = "tls-alpn-01"
)

func (ct ChallengeType) String() string { return string(ct) }

// ChallengeStatus represents challenge validation state
type ChallengeStatus string

const (
	ChallengeStatusPending    ChallengeStatus = "pending"
	ChallengeStatusProcessing ChallengeStatus = "processing"
	ChallengeStatusValid      ChallengeStatus = "valid"
	ChallengeStatusInvalid    ChallengeStatus = "invalid"
	ChallengeStatusExpired    ChallengeStatus = "expired"
)

func (cs ChallengeStatus) String() string { return string(cs) }

// Challenge represents an ACME domain validation challenge
type Challenge struct {
	ID               int64           `json:"id"`
	CertificateID    int64           `json:"certificate_id"`
	Domain           string          `json:"domain"`
	Type             ChallengeType   `json:"type"`
	Token            string          `json:"token"`
	KeyAuthorization string          `json:"key_authorization"`
	ValidationURL    string          `json:"validation_url"`
	Status           ChallengeStatus `json:"status"`
	AttemptCount     int             `json:"attempt_count"`
	CreatedAt        time.Time       `json:"created_at"`
	ValidatedAt      time.Time       `json:"validated_at"`
	Error            string          `json:"error,omitempty"`
}

// HTTP01Challenge for HTTP-01 validation
type HTTP01Challenge struct {
	Challenge
	FilePath    string `json:"file_path"`
	FileContent string `json:"file_content"`
	Port        int    `json:"port"`
}

// DNS01Challenge for DNS-01 validation
type DNS01Challenge struct {
	Challenge
	RecordName  string `json:"record_name"`
	RecordValue string `json:"record_value"`
	TTL         int    `json:"ttl"`
	Provider    string `json:"provider"`
}

// ============================================================================
// Section 5: Renewal Schedule Types
// ============================================================================

// RenewalResult represents outcome of a renewal attempt
type RenewalResult string

const (
	RenewalResultSuccess RenewalResult = "success"
	RenewalResultFailed  RenewalResult = "failed"
	RenewalResultSkipped RenewalResult = "skipped"
	RenewalResultPending RenewalResult = "pending"
)

func (rr RenewalResult) String() string { return string(rr) }

// RenewalSchedule tracks automatic renewal
type RenewalSchedule struct {
	ID                 int64           `json:"id"`
	CertificateID      int64           `json:"certificate_id"`
	NextCheckTime      time.Time       `json:"next_check_time"`
	RenewalAttempts    int             `json:"renewal_attempts"`
	LastAttemptTime    time.Time       `json:"last_attempt_time"`
	LastResult         RenewalResult   `json:"last_result"`
	RenewalWindowStart time.Time       `json:"renewal_window_start"`
	AutoRenewEnabled   bool            `json:"auto_renew_enabled"`
	NotificationsSent  map[string]bool `json:"notifications_sent"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// RenewalPolicy defines renewal behavior
type RenewalPolicy struct {
	RenewBeforeDays int           `json:"renew_before_days"`
	MaxRetries      int           `json:"max_retries"`
	RetryInterval   time.Duration `json:"retry_interval"`
	NotifyOnFailure bool          `json:"notify_on_failure"`
}

// ============================================================================
// Section 6: Storage Types
// ============================================================================

// StorageType represents storage backend
type StorageType string

const (
	StorageFilesystem StorageType = "filesystem"
	StorageDatabase   StorageType = "database"
	StorageBoth       StorageType = "both"
)

func (st StorageType) String() string { return string(st) }

// StorageConfig for certificate storage
type StorageConfig struct {
	Type              StorageType `json:"type"`
	CertPath          string      `json:"cert_path"`
	KeyPath           string      `json:"key_path"`
	ChainPath         string      `json:"chain_path"`
	BackupPath        string      `json:"backup_path"`
	FilePermissions   int         `json:"file_permissions"`
	EncryptKeys       bool        `json:"encrypt_keys"`
	EncryptionKeyFile string      `json:"encryption_key_file"`
}

// CertificateFile represents a stored certificate file
type CertificateFile struct {
	Path        string `json:"path"`
	Content     []byte `json:"-"`
	Permissions int    `json:"permissions"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
}

// ============================================================================
// Section 7: Distribution Types
// ============================================================================

// DistributionMethod represents how certs are distributed
type DistributionMethod string

const (
	DistMethodGRPCPush DistributionMethod = "grpc_push"
	DistMethodFileCopy DistributionMethod = "file_copy"
	DistMethodAPICall  DistributionMethod = "api_call"
)

func (dm DistributionMethod) String() string { return string(dm) }

// DistributionStatus represents distribution state
type DistributionStatus string

const (
	DistStatusPending  DistributionStatus = "pending"
	DistStatusSuccess  DistributionStatus = "success"
	DistStatusFailed   DistributionStatus = "failed"
	DistStatusRetrying DistributionStatus = "retrying"
)

func (ds DistributionStatus) String() string { return string(ds) }

// Distribution tracks certificate deployment
type Distribution struct {
	ID             int64              `json:"id"`
	CertificateID  int64              `json:"certificate_id"`
	TargetService  string             `json:"target_service"`
	Timestamp      time.Time          `json:"timestamp"`
	Method         DistributionMethod `json:"method"`
	Status         DistributionStatus `json:"status"`
	ServiceAckTime time.Time          `json:"service_ack_time"`
	ServiceVersion string             `json:"service_version"`
	RetryCount     int                `json:"retry_count"`
	NextRetryTime  time.Time          `json:"next_retry_time"`
	Error          string             `json:"error,omitempty"`
}

// DistributionTarget represents a service to distribute to
type DistributionTarget struct {
	ServiceName  string `json:"service_name"`
	GRPCEndpoint string `json:"grpc_endpoint"`
	FilePath     string `json:"file_path"`
	Enabled      bool   `json:"enabled"`
}

// ============================================================================
// Section 8: Key Generation Types
// ============================================================================

// KeyType represents private key algorithm
type KeyType string

const (
	KeyRSA2048   KeyType = "RSA-2048"
	KeyRSA4096   KeyType = "RSA-4096"
	KeyECDSAP256 KeyType = "ECDSA-P256"
	KeyECDSAP384 KeyType = "ECDSA-P384"
)

func (kt KeyType) String() string { return string(kt) }

// BitSize returns the key size in bits
func (kt KeyType) BitSize() int {
	switch kt {
	case KeyRSA2048:
		return 2048
	case KeyRSA4096:
		return 4096
	case KeyECDSAP256:
		return 256
	case KeyECDSAP384:
		return 384
	default:
		return 0
	}
}

// PrivateKeyInfo holds generated key information
type PrivateKeyInfo struct {
	Type KeyType     `json:"type"`
	Key  interface{} `json:"-"` // *rsa.PrivateKey or *ecdsa.PrivateKey
	PEM  string      `json:"-"`
	Bits int         `json:"bits"`
}

// GetRSAKey returns the RSA key if applicable
func (pk *PrivateKeyInfo) GetRSAKey() (*rsa.PrivateKey, bool) {
	key, ok := pk.Key.(*rsa.PrivateKey)
	return key, ok
}

// GetECDSAKey returns the ECDSA key if applicable
func (pk *PrivateKeyInfo) GetECDSAKey() (*ecdsa.PrivateKey, bool) {
	key, ok := pk.Key.(*ecdsa.PrivateKey)
	return key, ok
}

// CSRRequest for Certificate Signing Request generation
type CSRRequest struct {
	CommonName         string   `json:"common_name"`
	SubjectAltNames    []string `json:"subject_alt_names"`
	Country            string   `json:"country"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	Locality           string   `json:"locality"`
	Province           string   `json:"province"`
	KeyType            KeyType  `json:"key_type"`
}

// ============================================================================
// Section 9: Configuration Types
// ============================================================================

// Config is the root configuration structure
type Config struct {
	Service       ServiceConfig       `json:"service"`
	GRPC          GRPCConfig          `json:"grpc"`
	ACME          AcmeConfig          `json:"acme"`
	Domains       []DomainConfig      `json:"domains"`
	Storage       StorageConfig       `json:"storage"`
	Database      DatabaseConfig      `json:"database"`
	Renewal       RenewalConfig       `json:"renewal"`
	Distribution  DistributionConfig  `json:"distribution"`
	HTTPChallenge HTTPChallengeConfig `json:"http_challenge"`
	DNSChallenge  DNSChallengeConfig  `json:"dns_challenge"`
	Metrics       MetricsConfig       `json:"metrics"`
	Health        HealthConfig        `json:"health"`
}

// ServiceConfig for service identity
type ServiceConfig struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Environment      string `json:"environment"`
	LogLevel         string `json:"log_level"`
	LogFormat        string `json:"log_format"`
	LogFile          string `json:"log_file"`
	PIDFile          string `json:"pid_file"`
	WorkingDirectory string `json:"working_directory"`
}

// GRPCConfig for gRPC server
type GRPCConfig struct {
	Enabled              bool          `json:"enabled"`
	Host                 string        `json:"host"`
	Port                 int           `json:"port"`
	MaxConcurrentStreams int           `json:"max_concurrent_streams"`
	MaxConnectionIdle    time.Duration `json:"max_connection_idle"`
	MaxConnectionAge     time.Duration `json:"max_connection_age"`
	KeepaliveTime        time.Duration `json:"keepalive_time"`
	KeepaliveTimeout     time.Duration `json:"keepalive_timeout"`
	ReflectionEnabled    bool          `json:"reflection_enabled"`
}

// AcmeConfig for Let's Encrypt
type AcmeConfig struct {
	DirectoryURL       string        `json:"directory_url"`
	Email              string        `json:"email"`
	TermsAgreed        bool          `json:"terms_agreed"`
	PreferredChallenge ChallengeType `json:"preferred_challenge"`
	KeyType            KeyType       `json:"key_type"`
	Timeout            time.Duration `json:"timeout"`
	RetryAttempts      int           `json:"retry_attempts"`
	RetryDelay         time.Duration `json:"retry_delay"`
	RateLimitBuffer    int           `json:"rate_limit_buffer"`
	// External Account Binding (enterprise ACME)
	EABKeyID  string `json:"eab_key_id,omitempty"`
	EABMACKey string `json:"-"` // Sensitive - never serialize
}

// DomainConfig for managed domains
type DomainConfig struct {
	CommonName        string        `json:"common_name"`
	SubjectAltNames   []string      `json:"subject_alt_names"`
	Wildcard          bool          `json:"wildcard"`
	ChallengeType     ChallengeType `json:"challenge_type"`
	Enabled           bool          `json:"enabled"`
	AutoRenew         bool          `json:"auto_renew"`
	RenewBeforeDays   int           `json:"renew_before_days"`
	DNSProvider       string        `json:"dns_provider"`
	HTTPChallengePort int           `json:"http_challenge_port"`
}

// DatabaseConfig for PostgreSQL
type DatabaseConfig struct {
	Enabled            bool          `json:"enabled"`
	Host               string        `json:"host"`
	Port               int           `json:"port"`
	Name               string        `json:"name"`
	User               string        `json:"user"`
	Password           string        `json:"-"`
	SSLMode            string        `json:"sslmode"`
	MaxConnections     int           `json:"max_connections"`
	IdleConnections    int           `json:"idle_connections"`
	ConnectionLifetime time.Duration `json:"connection_lifetime"`
	ConnectionTimeout  time.Duration `json:"connection_timeout"`
}

// RenewalConfig for auto-renewal
type RenewalConfig struct {
	Enabled               bool          `json:"enabled"`
	CheckInterval         time.Duration `json:"check_interval"`
	RenewBeforeDays       int           `json:"renew_before_days"`
	MaxConcurrentRenewals int           `json:"max_concurrent_renewals"`
	RetryFailedRenewals   bool          `json:"retry_failed_renewals"`
	RetryInterval         time.Duration `json:"retry_interval"`
	MaxRetryAttempts      int           `json:"max_retry_attempts"`
	NotificationEnabled   bool          `json:"notification_enabled"`
	NotificationChannels  []string      `json:"notification_channels"`
}

// DistributionConfig for cert distribution
type DistributionConfig struct {
	Enabled               bool               `json:"enabled"`
	Method                DistributionMethod `json:"method"`
	TargetServices        []string           `json:"target_services"`
	RetryFailed           bool               `json:"retry_failed"`
	RetryInterval         time.Duration      `json:"retry_interval"`
	MaxRetryAttempts      int                `json:"max_retry_attempts"`
	NotificationOnFailure bool               `json:"notification_on_failure"`
}

// HTTPChallengeConfig for HTTP-01
type HTTPChallengeConfig struct {
	Enabled       bool          `json:"enabled"`
	Port          int           `json:"port"`
	BindAddress   string        `json:"bind_address"`
	WellKnownPath string        `json:"well_known_path"`
	Timeout       time.Duration `json:"timeout"`
	AllowExternal bool          `json:"allow_external"`
}

// DNSChallengeConfig for DNS-01
type DNSChallengeConfig struct {
	Enabled            bool          `json:"enabled"`
	Provider           string        `json:"provider"`
	APIToken           string        `json:"-"`
	APIKey             string        `json:"-"`
	APISecret          string        `json:"-"`
	PropagationTimeout time.Duration `json:"propagation_timeout"`
	PollingInterval    time.Duration `json:"polling_interval"`
	TTL                int           `json:"ttl"`
}

// MetricsConfig for Prometheus
type MetricsConfig struct {
	Enabled              bool   `json:"enabled"`
	Port                 int    `json:"port"`
	Path                 string `json:"path"`
	IncludeSystemMetrics bool   `json:"include_system_metrics"`
}

// HealthConfig for health checks
type HealthConfig struct {
	Enabled               bool   `json:"enabled"`
	Port                  int    `json:"port"`
	Path                  string `json:"path"`
	CheckDatabase         bool   `json:"check_database"`
	CheckACMEConnectivity bool   `json:"check_acme_connectivity"`
}

// ============================================================================
// Section 10: Error Types
// ============================================================================

// ErrorCode for certificate errors
type ErrorCode string

const (
	ErrInvalidDomain             ErrorCode = "INVALID_DOMAIN"
	ErrACMEAccountNotFound       ErrorCode = "ACME_ACCOUNT_NOT_FOUND"
	ErrChallengeValidationFailed ErrorCode = "CHALLENGE_VALIDATION_FAILED"
	ErrCertificateExpired        ErrorCode = "CERTIFICATE_EXPIRED"
	ErrStorageFailed             ErrorCode = "STORAGE_FAILED"
	ErrDistributionFailed        ErrorCode = "DISTRIBUTION_FAILED"
	ErrRenewalFailed             ErrorCode = "RENEWAL_FAILED"
	ErrInvalidConfiguration      ErrorCode = "INVALID_CONFIGURATION"
	ErrDatabaseConnection        ErrorCode = "DATABASE_CONNECTION"
	ErrACMECommunication         ErrorCode = "ACME_COMMUNICATION"
)

// CertificateError is a custom error type
type CertificateError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	Domain    string    `json:"domain,omitempty"`
	CertID    int64     `json:"cert_id,omitempty"`
	Cause     error     `json:"-"`
	Timestamp time.Time `json:"timestamp"`
}

func (e *CertificateError) Error() string {
	if e.Domain != "" {
		return fmt.Sprintf("[%s] %s (domain: %s)", e.Code, e.Message, e.Domain)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *CertificateError) Unwrap() error {
	return e.Cause
}

// WithDomain adds domain context
func (e *CertificateError) WithDomain(domain string) *CertificateError {
	e.Domain = domain
	return e
}

// WithCertID adds certificate ID context
func (e *CertificateError) WithCertID(id int64) *CertificateError {
	e.CertID = id
	return e
}

// NewCertificateError creates a new error
func NewCertificateError(code ErrorCode, message string) *CertificateError {
	return &CertificateError{
		Code:      code,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// ============================================================================
// Section 12: Helper Methods
// ============================================================================

// IsExpiring checks if certificate expires within days
func (c *Certificate) IsExpiring(days int) bool {
	return time.Until(c.NotAfter) <= time.Duration(days)*24*time.Hour
}

// IsValid checks if certificate is currently valid
func (c *Certificate) IsValid() bool {
	now := time.Now()
	return c.Status == CertStatusActive && now.After(c.NotBefore) && now.Before(c.NotAfter)
}

// DaysUntilExpiry returns days until certificate expires
func (c *Certificate) DaysUntilExpiry() int {
	return int(time.Until(c.NotAfter).Hours() / 24)
}

// GetDomains returns all domains (CN + SANs)
func (c *Certificate) GetDomains() []string {
	domains := []string{c.CommonName}
	return append(domains, c.SubjectAltNames...)
}

// ParseKeyType parses string to KeyType
func ParseKeyType(s string) (KeyType, error) {
	switch strings.ToUpper(s) {
	case "RSA-2048", "RSA2048":
		return KeyRSA2048, nil
	case "RSA-4096", "RSA4096":
		return KeyRSA4096, nil
	case "ECDSA-P256", "ECDSAP256", "EC256":
		return KeyECDSAP256, nil
	case "ECDSA-P384", "ECDSAP384", "EC384":
		return KeyECDSAP384, nil
	default:
		return "", fmt.Errorf("unknown key type: %s", s)
	}
}

// ParseChallengeType parses string to ChallengeType
func ParseChallengeType(s string) (ChallengeType, error) {
	switch strings.ToLower(s) {
	case "http-01", "http01":
		return ChallengeHTTP01, nil
	case "dns-01", "dns01":
		return ChallengeDNS01, nil
	case "tls-alpn-01", "tlsalpn01":
		return ChallengeTLSALPN01, nil
	default:
		return "", fmt.Errorf("unknown challenge type: %s", s)
	}
}

// ============================================================================
// Section 13: Validation Methods
// ============================================================================

var domainRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateDomain validates a domain name
func ValidateDomain(domain string) error {
	if len(domain) == 0 {
		return errors.New("domain cannot be empty")
	}
	if len(domain) > 253 {
		return errors.New("domain exceeds maximum length of 253 characters")
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}
	return nil
}

// ValidateEmail validates an email address
func ValidateEmail(email string) error {
	if len(email) == 0 {
		return errors.New("email cannot be empty")
	}
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format: %s", email)
	}
	return nil
}

// ValidateKeyType ensures valid key type
func ValidateKeyType(kt KeyType) error {
	switch kt {
	case KeyRSA2048, KeyRSA4096, KeyECDSAP256, KeyECDSAP384:
		return nil
	default:
		return fmt.Errorf("unsupported key type: %s", kt)
	}
}

// ValidateChallengeType ensures valid challenge type
func ValidateChallengeType(ct ChallengeType) error {
	switch ct {
	case ChallengeHTTP01, ChallengeDNS01, ChallengeTLSALPN01:
		return nil
	default:
		return fmt.Errorf("unsupported challenge type: %s", ct)
	}
}

// Validate performs comprehensive config validation
func (cfg *Config) Validate() error {
	if cfg.Service.Name == "" {
		return errors.New("service name is required")
	}
	if cfg.GRPC.Enabled && cfg.GRPC.Port <= 0 {
		return errors.New("invalid gRPC port")
	}
	if err := ValidateEmail(cfg.ACME.Email); err != nil {
		return fmt.Errorf("ACME email: %w", err)
	}
	for _, domain := range cfg.Domains {
		if err := domain.Validate(); err != nil {
			return fmt.Errorf("domain config: %w", err)
		}
	}
	return nil
}

// Validate validates domain configuration
func (dc *DomainConfig) Validate() error {
	if err := ValidateDomain(dc.CommonName); err != nil {
		return err
	}
	if dc.Wildcard && dc.ChallengeType != ChallengeDNS01 {
		return errors.New("wildcard certificates require DNS-01 challenge")
	}
	if dc.RenewBeforeDays < 1 {
		return errors.New("renew_before_days must be at least 1")
	}
	return nil
}

// ValidateIP checks if string is valid IP address
func ValidateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}
