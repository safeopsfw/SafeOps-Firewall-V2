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
	// SafeOps Internal CA Configuration
	CA         *CAConfig         `json:"ca,omitempty"`
	CRL        *CRLConfig        `json:"crl,omitempty"`
	OCSP       *OCSPConfig       `json:"ocsp,omitempty"`
	Security   *SecurityConfig   `json:"security,omitempty"`
	Backup     *BackupConfig     `json:"backup,omitempty"`
	HTTPServer *HTTPServerConfig `json:"http_server,omitempty"`
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

// ============================================================================
// Section 14: SafeOps Internal CA Types
// ============================================================================

// CAConfig defines internal SafeOps Certificate Authority settings
type CAConfig struct {
	// Organization details
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	Province           string `json:"province"`
	Locality           string `json:"locality"`

	// CA Certificate settings
	ValidityYears    int     `json:"validity_years"`     // CA certificate validity (default: 10)
	KeySize          int     `json:"key_size"`           // RSA key size (2048, 4096)
	KeyType          KeyType `json:"key_type"`           // Key algorithm
	SignatureHash    string  `json:"signature_hash"`     // SHA256, SHA384, SHA512
	SerialNumberBits int     `json:"serial_number_bits"` // Serial number size (default: 128)

	// Storage paths
	CAKeyPath   string `json:"ca_key_path"`   // Path to CA private key
	CACertPath  string `json:"ca_cert_path"`  // Path to CA certificate
	CAChainPath string `json:"ca_chain_path"` // Path to CA chain

	// Key protection
	PassphraseFile    string `json:"passphrase_file"`     // File containing key passphrase
	EncryptPrivateKey bool   `json:"encrypt_private_key"` // Encrypt at rest
	HSMEnabled        bool   `json:"hsm_enabled"`         // Use HSM for key storage
	HSMSlotID         int    `json:"hsm_slot_id"`         // HSM slot identifier

	// Auto-generation
	AutoGenerate bool `json:"auto_generate"` // Generate CA on first start if missing
}

// DefaultCAConfig returns sensible CA defaults
func DefaultCAConfig() *CAConfig {
	return &CAConfig{
		Organization:      "SafeOps",
		Country:           "US",
		ValidityYears:     10,
		KeySize:           4096,
		KeyType:           KeyRSA4096,
		SignatureHash:     "SHA256",
		SerialNumberBits:  128,
		CAKeyPath:         "/opt/safeops/ca/private/ca.key",
		CACertPath:        "/opt/safeops/ca/certs/ca.crt",
		CAChainPath:       "/opt/safeops/ca/certs/ca-chain.crt",
		EncryptPrivateKey: true,
		AutoGenerate:      true,
	}
}

// CAMetadata contains CA certificate information
type CAMetadata struct {
	SerialNumber      string    `json:"serial_number"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	KeyType           KeyType   `json:"key_type"`
	KeySize           int       `json:"key_size"`
	Fingerprint       string    `json:"fingerprint"`      // SHA-256 fingerprint
	FingerprintSHA1   string    `json:"fingerprint_sha1"` // SHA-1 for legacy
	Version           int       `json:"version"`
	IsCA              bool      `json:"is_ca"`
	PathLenConstraint int       `json:"path_len_constraint"`
}

// DaysUntilExpiry returns days until CA expires
func (ca *CAMetadata) DaysUntilExpiry() int {
	return int(time.Until(ca.NotAfter).Hours() / 24)
}

// IsExpiring checks if CA expires within days
func (ca *CAMetadata) IsExpiring(days int) bool {
	return time.Until(ca.NotAfter) <= time.Duration(days)*24*time.Hour
}

// ============================================================================
// Section 15: Revocation Types
// ============================================================================

// RevocationReason as per RFC 5280
type RevocationReason int

const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonCACompromise         RevocationReason = 2
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
	ReasonCertificateHold      RevocationReason = 6
	ReasonRemoveFromCRL        RevocationReason = 8
	ReasonPrivilegeWithdrawn   RevocationReason = 9
	ReasonAACompromise         RevocationReason = 10
)

// String returns human-readable revocation reason
func (r RevocationReason) String() string {
	switch r {
	case ReasonUnspecified:
		return "unspecified"
	case ReasonKeyCompromise:
		return "key_compromise"
	case ReasonCACompromise:
		return "ca_compromise"
	case ReasonAffiliationChanged:
		return "affiliation_changed"
	case ReasonSuperseded:
		return "superseded"
	case ReasonCessationOfOperation:
		return "cessation_of_operation"
	case ReasonCertificateHold:
		return "certificate_hold"
	case ReasonRemoveFromCRL:
		return "remove_from_crl"
	case ReasonPrivilegeWithdrawn:
		return "privilege_withdrawn"
	case ReasonAACompromise:
		return "aa_compromise"
	default:
		return "unknown"
	}
}

// RevocationInfo contains certificate revocation details
type RevocationInfo struct {
	ID             int64            `json:"id"`
	CertificateID  int64            `json:"certificate_id"`
	SerialNumber   string           `json:"serial_number"`
	CommonName     string           `json:"common_name"`
	Reason         RevocationReason `json:"reason"`
	ReasonText     string           `json:"reason_text"`
	RevokedAt      time.Time        `json:"revoked_at"`
	RevokedBy      string           `json:"revoked_by"` // User/system that revoked
	InvalidityDate time.Time        `json:"invalidity_date,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
}

// RevocationRequest for revoking a certificate
type RevocationRequest struct {
	CertificateID  int64            `json:"certificate_id"`
	SerialNumber   string           `json:"serial_number"`
	Reason         RevocationReason `json:"reason"`
	ReasonText     string           `json:"reason_text,omitempty"`
	InvalidityDate *time.Time       `json:"invalidity_date,omitempty"`
}

// CRLEntry represents a single entry in a CRL
type CRLEntry struct {
	SerialNumber   string           `json:"serial_number"`
	RevocationDate time.Time        `json:"revocation_date"`
	Reason         RevocationReason `json:"reason"`
}

// ============================================================================
// Section 16: CRL and OCSP Configuration
// ============================================================================

// CRLConfig for Certificate Revocation List generation
type CRLConfig struct {
	Enabled          bool          `json:"enabled"`
	UpdateInterval   time.Duration `json:"update_interval"`    // How often to regenerate CRL
	NextUpdateOffset time.Duration `json:"next_update_offset"` // NextUpdate = Now + offset
	CRLPath          string        `json:"crl_path"`           // File path for CRL
	CRLURL           string        `json:"crl_url"`            // Distribution point URL
	CRLDERPath       string        `json:"crl_der_path"`       // DER format path
	MaxCRLSize       int           `json:"max_crl_size"`       // Maximum entries
	SignatureHash    string        `json:"signature_hash"`     // SHA256, SHA384
	ServeHTTP        bool          `json:"serve_http"`         // Serve CRL over HTTP
	HTTPPort         int           `json:"http_port"`          // HTTP port for CRL
}

// DefaultCRLConfig returns sensible CRL defaults
func DefaultCRLConfig() *CRLConfig {
	return &CRLConfig{
		Enabled:          true,
		UpdateInterval:   24 * time.Hour,
		NextUpdateOffset: 7 * 24 * time.Hour,
		CRLPath:          "/opt/safeops/ca/crl/ca.crl.pem",
		CRLDERPath:       "/opt/safeops/ca/crl/ca.crl",
		MaxCRLSize:       100000,
		SignatureHash:    "SHA256",
		ServeHTTP:        true,
		HTTPPort:         8080,
	}
}

// OCSPConfig for Online Certificate Status Protocol responder
type OCSPConfig struct {
	Enabled               bool          `json:"enabled"`
	BindAddress           string        `json:"bind_address"`
	Port                  int           `json:"port"`
	OCSPURL               string        `json:"ocsp_url"`                // OCSP responder URL
	SignerCertPath        string        `json:"signer_cert_path"`        // OCSP signing cert
	SignerKeyPath         string        `json:"signer_key_path"`         // OCSP signing key
	SignerCertValidity    time.Duration `json:"signer_cert_validity"`    // OCSP cert validity
	ResponseValidity      time.Duration `json:"response_validity"`       // Response cache time
	CacheEnabled          bool          `json:"cache_enabled"`           // Cache OCSP responses
	CacheTTL              time.Duration `json:"cache_ttl"`               // Cache TTL
	MaxConcurrentRequests int           `json:"max_concurrent_requests"` // Request limit
	Timeout               time.Duration `json:"timeout"`                 // Request timeout
}

// DefaultOCSPConfig returns sensible OCSP defaults
func DefaultOCSPConfig() *OCSPConfig {
	return &OCSPConfig{
		Enabled:               true,
		BindAddress:           "0.0.0.0",
		Port:                  8081,
		SignerCertValidity:    30 * 24 * time.Hour,
		ResponseValidity:      1 * time.Hour,
		CacheEnabled:          true,
		CacheTTL:              5 * time.Minute,
		MaxConcurrentRequests: 100,
		Timeout:               10 * time.Second,
	}
}

// OCSPStatus represents OCSP response status
type OCSPStatus string

const (
	OCSPStatusGood    OCSPStatus = "good"
	OCSPStatusRevoked OCSPStatus = "revoked"
	OCSPStatusUnknown OCSPStatus = "unknown"
)

func (os OCSPStatus) String() string { return string(os) }

// OCSPResponse represents an OCSP query response
type OCSPResponse struct {
	SerialNumber   string           `json:"serial_number"`
	Status         OCSPStatus       `json:"status"`
	RevocationTime time.Time        `json:"revocation_time,omitempty"`
	Reason         RevocationReason `json:"reason,omitempty"`
	ThisUpdate     time.Time        `json:"this_update"`
	NextUpdate     time.Time        `json:"next_update"`
	ProducedAt     time.Time        `json:"produced_at"`
}

// ============================================================================
// Section 17: Security and Audit Types
// ============================================================================

// SecurityConfig for audit and rate limiting
type SecurityConfig struct {
	// Audit logging
	AuditLoggingEnabled bool   `json:"audit_logging_enabled"`
	AuditLogPath        string `json:"audit_log_path"`
	AuditLogMaxSize     int    `json:"audit_log_max_size"` // MB
	AuditLogMaxBackups  int    `json:"audit_log_max_backups"`

	// Rate limiting
	RateLimitEnabled     bool `json:"rate_limit_enabled"`
	MaxCertsPerHour      int  `json:"max_certs_per_hour"`
	MaxCertsPerDay       int  `json:"max_certs_per_day"`
	MaxRevocationsPerDay int  `json:"max_revocations_per_day"`

	// Access control
	RequireAuthentication bool     `json:"require_authentication"`
	AllowedIPs            []string `json:"allowed_ips"`
	AllowedSubnets        []string `json:"allowed_subnets"`

	// Key security
	KeyRotationEnabled  bool          `json:"key_rotation_enabled"`
	KeyRotationInterval time.Duration `json:"key_rotation_interval"`
}

// DefaultSecurityConfig returns sensible security defaults
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		AuditLoggingEnabled:   true,
		AuditLogPath:          "/var/log/safeops/ca-audit.log",
		AuditLogMaxSize:       100,
		AuditLogMaxBackups:    10,
		RateLimitEnabled:      true,
		MaxCertsPerHour:       50,
		MaxCertsPerDay:        500,
		MaxRevocationsPerDay:  100,
		RequireAuthentication: true,
	}
}

// AuditAction represents audited actions
type AuditAction string

const (
	AuditActionCertIssued     AuditAction = "cert_issued"
	AuditActionCertRenewed    AuditAction = "cert_renewed"
	AuditActionCertRevoked    AuditAction = "cert_revoked"
	AuditActionCertDownloaded AuditAction = "cert_downloaded"
	AuditActionCAGenerated    AuditAction = "ca_generated"
	AuditActionCRLGenerated   AuditAction = "crl_generated"
	AuditActionConfigChanged  AuditAction = "config_changed"
	AuditActionAuthSuccess    AuditAction = "auth_success"
	AuditActionAuthFailed     AuditAction = "auth_failed"
	AuditActionBackupCreated  AuditAction = "backup_created"
	AuditActionBackupRestored AuditAction = "backup_restored"
)

func (aa AuditAction) String() string { return string(aa) }

// AuditLogEntry represents an audit log record
type AuditLogEntry struct {
	ID           int64       `json:"id"`
	Timestamp    time.Time   `json:"timestamp"`
	Action       AuditAction `json:"action"`
	Actor        string      `json:"actor"`         // User or system
	ActorIP      string      `json:"actor_ip"`      // Source IP
	ResourceType string      `json:"resource_type"` // certificate, ca, config
	ResourceID   string      `json:"resource_id"`   // Certificate ID, etc.
	Details      string      `json:"details"`       // Additional detail
	Success      bool        `json:"success"`
	ErrorMessage string      `json:"error_message,omitempty"`
}

// ============================================================================
// Section 18: Backup and Recovery Types
// ============================================================================

// BackupConfig for CA backup settings
type BackupConfig struct {
	Enabled           bool          `json:"enabled"`
	BackupInterval    time.Duration `json:"backup_interval"`
	BackupPath        string        `json:"backup_path"`
	RetentionDays     int           `json:"retention_days"`
	MaxBackups        int           `json:"max_backups"`
	IncludePrivateKey bool          `json:"include_private_key"`
	EncryptBackup     bool          `json:"encrypt_backup"`
	EncryptionKey     string        `json:"-"` // Never serialize
	CompressBackup    bool          `json:"compress_backup"`
}

// DefaultBackupConfig returns sensible backup defaults
func DefaultBackupConfig() *BackupConfig {
	return &BackupConfig{
		Enabled:           true,
		BackupInterval:    24 * time.Hour,
		BackupPath:        "/opt/safeops/backups/ca",
		RetentionDays:     90,
		MaxBackups:        30,
		IncludePrivateKey: true,
		EncryptBackup:     true,
		CompressBackup:    true,
	}
}

// BackupMetadata describes a backup archive
type BackupMetadata struct {
	ID               string    `json:"id"` // Backup UUID
	Timestamp        time.Time `json:"timestamp"`
	Size             int64     `json:"size"`     // Bytes
	Checksum         string    `json:"checksum"` // SHA-256
	Path             string    `json:"path"`
	Encrypted        bool      `json:"encrypted"`
	Compressed       bool      `json:"compressed"`
	IncludesKey      bool      `json:"includes_key"`
	CertificateCount int       `json:"certificate_count"`
	CASerialNumber   string    `json:"ca_serial_number"`
	CreatedBy        string    `json:"created_by"`
}

// RestoreRequest for restoring from backup
type RestoreRequest struct {
	BackupID          string `json:"backup_id"`
	BackupPath        string `json:"backup_path"`
	DecryptionKey     string `json:"-"`
	Force             bool   `json:"force"`         // Overwrite existing
	ValidateOnly      bool   `json:"validate_only"` // Dry run
	RestorePrivateKey bool   `json:"restore_private_key"`
}

// RestoreResult contains restore operation results
type RestoreResult struct {
	Success             bool      `json:"success"`
	Timestamp           time.Time `json:"timestamp"`
	RestoredCerts       int       `json:"restored_certs"`
	RestoredRevocations int       `json:"restored_revocations"`
	RestoredCA          bool      `json:"restored_ca"`
	Warnings            []string  `json:"warnings,omitempty"`
	Error               string    `json:"error,omitempty"`
}

// ============================================================================
// Section 19: HTTP Distribution Server Types
// ============================================================================

// HTTPServerConfig for CA certificate distribution server
type HTTPServerConfig struct {
	Enabled        bool   `json:"enabled"`
	BindAddress    string `json:"bind_address"`
	Port           int    `json:"port"`
	TLSEnabled     bool   `json:"tls_enabled"`
	TLSCertPath    string `json:"tls_cert_path"`
	TLSKeyPath     string `json:"tls_key_path"`
	BasePath       string `json:"base_path"`        // URL base path
	MaxRequestSize int64  `json:"max_request_size"` // Bytes
	RateLimit      int    `json:"rate_limit"`       // Requests per second
}

// DefaultHTTPServerConfig returns sensible HTTP server defaults
func DefaultHTTPServerConfig() *HTTPServerConfig {
	return &HTTPServerConfig{
		Enabled:        true,
		BindAddress:    "0.0.0.0",
		Port:           8443,
		TLSEnabled:     true,
		BasePath:       "/ca",
		MaxRequestSize: 1024 * 1024, // 1MB
		RateLimit:      100,
	}
}

// QRCodeConfig for QR code generation
type QRCodeConfig struct {
	Enabled    bool          `json:"enabled"`
	Size       int           `json:"size"`        // Pixels
	ErrorLevel string        `json:"error_level"` // L, M, Q, H
	CachePath  string        `json:"cache_path"`
	CacheTTL   time.Duration `json:"cache_ttl"`
	IncludeURL string        `json:"include_url"` // URL to encode
}

// DefaultQRCodeConfig returns sensible QR code defaults
func DefaultQRCodeConfig() *QRCodeConfig {
	return &QRCodeConfig{
		Enabled:    true,
		Size:       256,
		ErrorLevel: "M",
		CachePath:  "/tmp/safeops/qr",
		CacheTTL:   24 * time.Hour,
	}
}

// ============================================================================
// Section 20: TLS Proxy Integration Types
// ============================================================================

// ProxyCertRequest for TLS proxy certificate signing
type ProxyCertRequest struct {
	CommonName      string      `json:"common_name"`
	SubjectAltNames []string    `json:"subject_alt_names"`
	IPAddresses     []net.IP    `json:"ip_addresses"`
	ValidityHours   int         `json:"validity_hours"`
	KeyType         KeyType     `json:"key_type"`
	Purpose         CertPurpose `json:"purpose"`
}

// CertPurpose indicates certificate use case
type CertPurpose string

const (
	PurposeServerAuth  CertPurpose = "server_auth"  // TLS server certificate
	PurposeClientAuth  CertPurpose = "client_auth"  // TLS client certificate
	PurposeCodeSigning CertPurpose = "code_signing" // Code signing
	PurposeEmailSign   CertPurpose = "email_sign"   // S/MIME email
)

func (cp CertPurpose) String() string { return string(cp) }

// ProxyCertResponse contains signed certificate for TLS proxy
type ProxyCertResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	PrivateKeyPEM  string    `json:"-"`
	ChainPEM       string    `json:"chain_pem"`
	SerialNumber   string    `json:"serial_number"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	Fingerprint    string    `json:"fingerprint"`
}

// SigningStats tracks certificate signing metrics
type SigningStats struct {
	TotalSigned          int64     `json:"total_signed"`
	SignedLast24Hours    int64     `json:"signed_last_24_hours"`
	SignedLast7Days      int64     `json:"signed_last_7_days"`
	AverageSigningTimeMs int64     `json:"average_signing_time_ms"`
	CacheHitRate         float64   `json:"cache_hit_rate"`
	LastSignedAt         time.Time `json:"last_signed_at"`
}
