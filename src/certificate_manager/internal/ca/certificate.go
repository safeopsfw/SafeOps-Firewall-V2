// Package ca orchestrates the complete certificate lifecycle.
package ca

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"certificate_manager/internal/acme"
	"certificate_manager/internal/generation"
	"certificate_manager/internal/storage"
	"certificate_manager/pkg/types"
)

// ============================================================================
// Constants
// ============================================================================

const (
	DefaultKeyType      = types.KeyRSA4096
	RenewalWarningDays  = 30
	CertificateCacheTTL = 5 * time.Minute
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrCertificateNotFound  = errors.New("certificate not found")
	ErrCertExpiredStatus    = errors.New("certificate has expired")
	ErrIssuanceFailed       = errors.New("certificate issuance failed")
	ErrStorageFailed        = errors.New("certificate storage failed")
	ErrValidationFailed     = errors.New("certificate validation failed")
	ErrDuplicateCertificate = errors.New("valid certificate already exists")
	ErrMissingDependency    = errors.New("required dependency not provided")
)

// ============================================================================
// Certificate Manager Structure
// ============================================================================

// CertificateManager orchestrates certificate lifecycle operations
type CertificateManager struct {
	acmeClient   *acme.Client
	orderManager *acme.OrderManager
	dbStorage    *storage.Database
	fsStorage    *storage.FilesystemStorage
	validator    *CertValidator
	config       types.AcmeConfig
	keyType      types.KeyType
}

// ManagerConfig holds CertificateManager configuration
type ManagerConfig struct {
	ACMEClient     *acme.Client
	OrderManager   *acme.OrderManager
	DBStorage      *storage.Database
	FSStorage      *storage.FilesystemStorage
	Validator      *CertValidator
	ACMEConfig     types.AcmeConfig
	DefaultKeyType types.KeyType
}

// ============================================================================
// Constructor
// ============================================================================

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(cfg ManagerConfig) (*CertificateManager, error) {
	// Validate required dependencies
	if cfg.ACMEClient == nil {
		return nil, fmt.Errorf("%w: ACME client", ErrMissingDependency)
	}

	if cfg.DBStorage == nil && cfg.FSStorage == nil {
		return nil, fmt.Errorf("%w: at least one storage backend required", ErrMissingDependency)
	}

	keyType := cfg.DefaultKeyType
	if keyType == "" {
		keyType = DefaultKeyType
	}

	// Create validator if not provided
	validator := cfg.Validator
	if validator == nil {
		validator = NewCertValidator()
	}

	return &CertificateManager{
		acmeClient:   cfg.ACMEClient,
		orderManager: cfg.OrderManager,
		dbStorage:    cfg.DBStorage,
		fsStorage:    cfg.FSStorage,
		validator:    validator,
		config:       cfg.ACMEConfig,
		keyType:      keyType,
	}, nil
}

// ============================================================================
// IssueCertificate - Primary Certificate Acquisition
// ============================================================================

// IssueCertificate requests and stores a new certificate for the given domains
func (cm *CertificateManager) IssueCertificate(ctx context.Context, domains []string) (*types.Certificate, error) {
	if len(domains) == 0 {
		return nil, errors.New("no domains specified")
	}

	primaryDomain := domains[0]

	// Check for existing valid certificate
	existing, err := cm.GetCertificate(ctx, primaryDomain)
	if err == nil && existing != nil {
		if existing.IsValid() && !existing.IsExpiring(RenewalWarningDays) {
			return existing, nil // Return existing valid certificate
		}
	}

	// Generate private key
	keyInfo, err := generation.GeneratePrivateKey(cm.keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate CSR
	csrRequest := &types.CSRRequest{
		CommonName:      primaryDomain,
		SubjectAltNames: domains[1:],
		KeyType:         cm.keyType,
	}
	csrPEM, err := generation.GenerateCSR(keyInfo, csrRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Parse CSR to get DER bytes
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("failed to decode CSR PEM")
	}

	// Request certificate from ACME
	var certBundle *acme.CertificateBundle

	if cm.orderManager != nil {
		// Use order manager for full workflow
		result, err := cm.orderManager.CompleteOrder(ctx, domains, cm.keyType)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrIssuanceFailed, err)
		}
		certBundle = &acme.CertificateBundle{
			Certificate: result.CertificatePEM,
			FullChain:   result.FullChainPEM,
		}
	} else {
		// Use ACME client directly
		certBundle, err = cm.acmeClient.IssueCertificate(ctx, domains, block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrIssuanceFailed, err)
		}
	}

	// Validate certificate chain
	validationResult, err := cm.validator.ValidateChain(certBundle.FullChain)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValidationFailed, err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("%w: certificate validation failed", ErrValidationFailed)
	}

	// Create certificate object
	cert := &types.Certificate{
		CommonName:      primaryDomain,
		SubjectAltNames: domains[1:],
		CertificatePEM:  certBundle.Certificate,
		PrivateKeyPEM:   keyInfo.PEM,
		ChainPEM:        certBundle.FullChain,
		SerialNumber:    validationResult.SerialNumber,
		Issuer:          validationResult.Issuer,
		NotBefore:       validationResult.NotBefore,
		NotAfter:        validationResult.NotAfter,
		Status:          types.CertStatusActive,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Store certificate
	if err := cm.storeCertificate(ctx, cert); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageFailed, err)
	}

	return cert, nil
}

// ============================================================================
// GetCertificate - Certificate Retrieval
// ============================================================================

// GetCertificate retrieves a certificate by domain name
func (cm *CertificateManager) GetCertificate(ctx context.Context, domain string) (*types.Certificate, error) {
	// Try database first
	if cm.dbStorage != nil {
		cert, err := cm.dbStorage.GetCertificate(ctx, domain)
		if err == nil && cert != nil {
			// Check expiration
			if cert.NotAfter.Before(time.Now()) {
				cert.Status = types.CertStatusExpired
			} else if cert.IsExpiring(RenewalWarningDays) {
				// Log warning but still return
			}
			return cert, nil
		}
	}

	// Fallback to filesystem
	if cm.fsStorage != nil {
		certPEM, err := cm.fsStorage.GetCertificate(domain)
		if err == nil {
			keyPEM, keyErr := cm.fsStorage.GetPrivateKey(domain)
			if keyErr == nil {
				cert, err := cm.parseCertificateFromPEM(domain, string(certPEM), string(keyPEM))
				if err == nil {
					return cert, nil
				}
			}
		}
	}

	return nil, ErrCertificateNotFound
}

// GetCertificateByID retrieves a certificate by its ID
func (cm *CertificateManager) GetCertificateByID(ctx context.Context, id int64) (*types.Certificate, error) {
	if cm.dbStorage == nil {
		return nil, errors.New("database storage not available")
	}

	return cm.dbStorage.GetCertificateByID(ctx, id)
}

// ============================================================================
// ListCertificates - Certificate Inventory
// ============================================================================

// CertificateListOptions for filtering certificate lists
type CertificateListOptions struct {
	Domain     string
	Status     types.CertificateStatus
	ExpiringIn int // Days
	Limit      int
	Offset     int
	OrderBy    string
	OrderDesc  bool
}

// CertificateSummary contains certificate metadata without full content
type CertificateSummary struct {
	ID            int64                   `json:"id"`
	CommonName    string                  `json:"common_name"`
	SANs          []string                `json:"sans"`
	Status        types.CertificateStatus `json:"status"`
	Issuer        string                  `json:"issuer"`
	NotBefore     time.Time               `json:"not_before"`
	NotAfter      time.Time               `json:"not_after"`
	DaysRemaining int                     `json:"days_remaining"`
	Fingerprint   string                  `json:"fingerprint"`
}

// ListCertificates returns certificate inventory
func (cm *CertificateManager) ListCertificates(ctx context.Context, opts CertificateListOptions) ([]CertificateSummary, error) {
	if cm.dbStorage == nil {
		return nil, errors.New("database storage not available")
	}

	certs, err := cm.dbStorage.ListCertificates(ctx, string(opts.Status))
	if err != nil {
		return nil, err
	}

	summaries := make([]CertificateSummary, 0, len(certs))
	now := time.Now()

	for _, cert := range certs {
		// Apply filters
		if opts.Domain != "" && cert.CommonName != opts.Domain {
			continue
		}
		if opts.Status != "" && cert.Status != opts.Status {
			continue
		}

		daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)

		if opts.ExpiringIn > 0 && daysRemaining > opts.ExpiringIn {
			continue
		}

		summaries = append(summaries, CertificateSummary{
			ID:            cert.ID,
			CommonName:    cert.CommonName,
			SANs:          cert.SubjectAltNames,
			Status:        cert.Status,
			Issuer:        cert.Issuer,
			NotBefore:     cert.NotBefore,
			NotAfter:      cert.NotAfter,
			DaysRemaining: daysRemaining,
			Fingerprint:   cm.calculateFingerprint(cert.CertificatePEM),
		})
	}

	return summaries, nil
}

// ============================================================================
// DeleteCertificate - Safe Removal
// ============================================================================

// DeleteCertificate removes a certificate from all storage locations
func (cm *CertificateManager) DeleteCertificate(ctx context.Context, id int64, domain string) error {
	var dbErr, fsErr error

	// Delete from database
	if cm.dbStorage != nil {
		dbErr = cm.dbStorage.DeleteCertificate(ctx, id)
	}

	// Delete from filesystem
	if cm.fsStorage != nil {
		fsErr = cm.fsStorage.DeleteCertificateFiles(domain)
	}

	// Return first error encountered
	if dbErr != nil {
		return fmt.Errorf("database deletion failed: %w", dbErr)
	}
	if fsErr != nil {
		return fmt.Errorf("filesystem deletion failed: %w", fsErr)
	}

	return nil
}

// ============================================================================
// Storage Coordination
// ============================================================================

// storeCertificate saves certificate to all configured storage backends
func (cm *CertificateManager) storeCertificate(ctx context.Context, cert *types.Certificate) error {
	// Store in database
	if cm.dbStorage != nil {
		id, err := cm.dbStorage.StoreCertificate(ctx, cert)
		if err != nil {
			return fmt.Errorf("database storage failed: %w", err)
		}
		cert.ID = id
	}

	// Store in filesystem
	if cm.fsStorage != nil {
		// Store certificate
		if err := cm.fsStorage.StoreCertificate(cert.CommonName, []byte(cert.CertificatePEM)); err != nil {
			if cm.dbStorage != nil && cert.ID > 0 {
				cm.dbStorage.DeleteCertificate(ctx, cert.ID)
			}
			return fmt.Errorf("filesystem certificate storage failed: %w", err)
		}
		// Store private key
		if err := cm.fsStorage.StorePrivateKey(cert.CommonName, []byte(cert.PrivateKeyPEM)); err != nil {
			if cm.dbStorage != nil && cert.ID > 0 {
				cm.dbStorage.DeleteCertificate(ctx, cert.ID)
			}
			return fmt.Errorf("filesystem key storage failed: %w", err)
		}
		// Store chain if present
		if cert.ChainPEM != "" {
			cm.fsStorage.StoreCertificateChain(cert.CommonName, []byte(cert.ChainPEM))
		}
	}

	return nil
}

// ============================================================================
// Certificate Chain Validation
// ============================================================================

// ValidateCertificateChain verifies certificate chain integrity
func (cm *CertificateManager) ValidateCertificateChain(chainPEM string) (*CertValidationResult, error) {
	return cm.validator.ValidateChain(chainPEM)
}

// ValidateCertificateForDomains ensures certificate covers specified domains
func (cm *CertificateManager) ValidateCertificateForDomains(certPEM string, domains []string) error {
	result, err := cm.validator.ValidateForDomains(certPEM, domains)
	if err != nil {
		return err
	}
	if !result.Valid {
		return ErrValidationFailed
	}
	return nil
}

// ============================================================================
// Certificate Format Conversion
// ============================================================================

// BuildTLSCertificate creates a tls.Certificate for direct use
func (cm *CertificateManager) BuildTLSCertificate(cert *types.Certificate) (tls.Certificate, error) {
	return tls.X509KeyPair(
		[]byte(cert.CertificatePEM+cert.ChainPEM),
		[]byte(cert.PrivateKeyPEM),
	)
}

// GetFullChain returns leaf certificate concatenated with chain
func (cm *CertificateManager) GetFullChain(cert *types.Certificate) string {
	return cert.CertificatePEM + cert.ChainPEM
}

// ParseX509Certificate parses PEM to x509.Certificate
func (cm *CertificateManager) ParseX509Certificate(certPEM string) (*x509.Certificate, error) {
	return cm.validator.ParseCertificate(certPEM)
}

// ============================================================================
// Helper Methods
// ============================================================================

// parseCertificateFromPEM creates a Certificate object from PEM data
func (cm *CertificateManager) parseCertificateFromPEM(domain, certPEM, keyPEM string) (*types.Certificate, error) {
	x509Cert, err := cm.validator.ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	return &types.Certificate{
		CommonName:      domain,
		SubjectAltNames: x509Cert.DNSNames,
		CertificatePEM:  certPEM,
		PrivateKeyPEM:   keyPEM,
		SerialNumber:    x509Cert.SerialNumber.String(),
		Issuer:          x509Cert.Issuer.CommonName,
		NotBefore:       x509Cert.NotBefore,
		NotAfter:        x509Cert.NotAfter,
		Status:          types.CertStatusActive,
	}, nil
}

// calculateFingerprint computes SHA-256 fingerprint of certificate
func (cm *CertificateManager) calculateFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:])
}

// ============================================================================
// Expiration Checking
// ============================================================================

// GetExpiringCertificates returns certificates expiring within days
func (cm *CertificateManager) GetExpiringCertificates(ctx context.Context, days int) ([]*types.Certificate, error) {
	if cm.dbStorage == nil {
		return nil, errors.New("database storage not available")
	}

	return cm.dbStorage.GetCertificatesDueForRenewal(ctx, days)
}

// CheckCertificateExpiry returns expiration status for a domain
func (cm *CertificateManager) CheckCertificateExpiry(ctx context.Context, domain string) (int, error) {
	cert, err := cm.GetCertificate(ctx, domain)
	if err != nil {
		return 0, err
	}

	return cert.DaysUntilExpiry(), nil
}

// ============================================================================
// Certificate Status Management
// ============================================================================

// UpdateCertificateStatus changes the status of a certificate
func (cm *CertificateManager) UpdateCertificateStatus(ctx context.Context, id int64, status types.CertificateStatus) error {
	if cm.dbStorage == nil {
		return errors.New("database storage not available")
	}

	return cm.dbStorage.UpdateCertificateStatus(ctx, id, status)
}

// RevokeCertificate marks a certificate as revoked
func (cm *CertificateManager) RevokeCertificate(ctx context.Context, id int64, reason string) error {
	// Update status in database
	if err := cm.UpdateCertificateStatus(ctx, id, types.CertStatusRevoked); err != nil {
		return err
	}

	// Optionally revoke with ACME server
	// This would require loading the certificate and sending revocation request

	return nil
}
