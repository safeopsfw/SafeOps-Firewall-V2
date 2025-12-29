// Package storage provides the certificate repository for issued certificates.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrCertificateNotFound    = errors.New("certificate not found")
	ErrCertificateExists      = errors.New("certificate already exists")
	ErrInvalidCertificateData = errors.New("invalid certificate data")
)

// ============================================================================
// Certificate Model
// ============================================================================

// IssuedCertificate represents a certificate signed by our CA.
type IssuedCertificate struct {
	ID                int64      `json:"id"`
	SerialNumber      string     `json:"serial_number"`
	CommonName        string     `json:"common_name"`
	SubjectDN         string     `json:"subject_dn"`
	IssuerDN          string     `json:"issuer_dn"`
	SubjectAltNames   []string   `json:"subject_alt_names"`
	NotBefore         time.Time  `json:"not_before"`
	NotAfter          time.Time  `json:"not_after"`
	SignatureAlgo     string     `json:"signature_algorithm"`
	KeyType           string     `json:"key_type"`
	KeySize           int        `json:"key_size"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	FingerprintSHA1   string     `json:"fingerprint_sha1"`
	CertificatePEM    string     `json:"certificate_pem"`
	CertificateType   string     `json:"certificate_type"`
	IssuedToDeviceIP  string     `json:"issued_to_device_ip,omitempty"`
	IssuedToMAC       string     `json:"issued_to_mac,omitempty"`
	IssuedBy          string     `json:"issued_by"`
	Status            string     `json:"status"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

// ============================================================================
// Repository Interface
// ============================================================================

// CertificateRepository defines the contract for certificate data access.
type CertificateRepository interface {
	// SaveCertificate inserts a new issued certificate record
	SaveCertificate(ctx context.Context, cert *IssuedCertificate) error

	// GetCertificate retrieves a certificate by serial number
	GetCertificate(ctx context.Context, serialNumber string) (*IssuedCertificate, error)

	// GetCertificateByCommonName retrieves all certificates for a given domain
	GetCertificateByCommonName(ctx context.Context, commonName string) ([]*IssuedCertificate, error)

	// ListCertificates returns paginated list of all issued certificates
	ListCertificates(ctx context.Context, limit int, offset int) ([]*IssuedCertificate, error)

	// GetExpiringCertificates finds certificates expiring within specified days
	GetExpiringCertificates(ctx context.Context, withinDays int) ([]*IssuedCertificate, error)

	// CountCertificates returns total count of issued certificates
	CountCertificates(ctx context.Context) (int, error)

	// CountActiveCertificates returns count of non-expired certificates
	CountActiveCertificates(ctx context.Context) (int, error)

	// DeleteCertificate removes a certificate record (for cleanup, not revocation)
	DeleteCertificate(ctx context.Context, serialNumber string) error

	// SearchCertificates performs full-text search on certificates
	SearchCertificates(ctx context.Context, query string) ([]*IssuedCertificate, error)

	// GetCertificatesByType retrieves all certificates of specific type
	GetCertificatesByType(ctx context.Context, certType string) ([]*IssuedCertificate, error)

	// BulkSaveCertificates inserts multiple certificates in a transaction
	BulkSaveCertificates(ctx context.Context, certs []*IssuedCertificate) error

	// UpdateCertificateStatus updates the status of a certificate
	UpdateCertificateStatus(ctx context.Context, serialNumber string, status string) error
}

// ============================================================================
// Repository Implementation
// ============================================================================

// certificateRepository is the concrete implementation of CertificateRepository.
type certificateRepository struct {
	db *Database
}

// NewCertificateRepository creates a new certificate repository instance.
func NewCertificateRepository(db *Database) CertificateRepository {
	return &certificateRepository{
		db: db,
	}
}

// ============================================================================
// Save Certificate
// ============================================================================

// SaveCertificate inserts a new issued certificate record into the database.
func (r *certificateRepository) SaveCertificate(ctx context.Context, cert *IssuedCertificate) error {
	if cert == nil {
		return ErrInvalidCertificateData
	}

	// Validate required fields
	if cert.SerialNumber == "" {
		return fmt.Errorf("%w: serial number is required", ErrInvalidCertificateData)
	}
	if cert.CommonName == "" {
		return fmt.Errorf("%w: common name is required", ErrInvalidCertificateData)
	}

	query := `
		INSERT INTO issued_certificates (
			serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			issued_to_device_ip, issued_to_mac,
			issued_by, status, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING id`

	// Set defaults
	if cert.Status == "" {
		cert.Status = "active"
	}
	if cert.IssuedBy == "" {
		cert.IssuedBy = "system"
	}
	if cert.CreatedAt.IsZero() {
		cert.CreatedAt = time.Now()
	}

	// Convert device IP and MAC to nullable
	var deviceIP, deviceMAC interface{}
	if cert.IssuedToDeviceIP != "" {
		deviceIP = cert.IssuedToDeviceIP
	}
	if cert.IssuedToMAC != "" {
		deviceMAC = cert.IssuedToMAC
	}

	err := r.db.db.QueryRowContext(ctx, query,
		cert.SerialNumber,
		cert.CommonName,
		cert.SubjectDN,
		cert.IssuerDN,
		pq.Array(cert.SubjectAltNames),
		cert.NotBefore,
		cert.NotAfter,
		cert.SignatureAlgo,
		cert.KeyType,
		cert.KeySize,
		cert.FingerprintSHA256,
		cert.FingerprintSHA1,
		cert.CertificatePEM,
		cert.CertificateType,
		deviceIP,
		deviceMAC,
		cert.IssuedBy,
		cert.Status,
		cert.CreatedAt,
	).Scan(&cert.ID)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return fmt.Errorf("%w: serial number %s", ErrCertificateExists, cert.SerialNumber)
		}
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	return nil
}

// ============================================================================
// Get Certificate by Serial Number
// ============================================================================

// GetCertificate retrieves a certificate by its serial number.
func (r *certificateRepository) GetCertificate(ctx context.Context, serialNumber string) (*IssuedCertificate, error) {
	query := `
		SELECT id, serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			COALESCE(issued_to_device_ip::text, ''), COALESCE(issued_to_mac::text, ''),
			issued_by, status, revoked_at, created_at
		FROM issued_certificates
		WHERE serial_number = $1`

	cert := &IssuedCertificate{}
	var revokedAt sql.NullTime

	err := r.db.db.QueryRowContext(ctx, query, serialNumber).Scan(
		&cert.ID,
		&cert.SerialNumber,
		&cert.CommonName,
		&cert.SubjectDN,
		&cert.IssuerDN,
		pq.Array(&cert.SubjectAltNames),
		&cert.NotBefore,
		&cert.NotAfter,
		&cert.SignatureAlgo,
		&cert.KeyType,
		&cert.KeySize,
		&cert.FingerprintSHA256,
		&cert.FingerprintSHA1,
		&cert.CertificatePEM,
		&cert.CertificateType,
		&cert.IssuedToDeviceIP,
		&cert.IssuedToMAC,
		&cert.IssuedBy,
		&cert.Status,
		&revokedAt,
		&cert.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrCertificateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}

	return cert, nil
}

// ============================================================================
// Get Certificates by Common Name
// ============================================================================

// GetCertificateByCommonName retrieves all certificates for a given domain.
func (r *certificateRepository) GetCertificateByCommonName(ctx context.Context, commonName string) ([]*IssuedCertificate, error) {
	query := `
		SELECT id, serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			COALESCE(issued_to_device_ip::text, ''), COALESCE(issued_to_mac::text, ''),
			issued_by, status, revoked_at, created_at
		FROM issued_certificates
		WHERE common_name = $1
		ORDER BY created_at DESC`

	rows, err := r.db.db.QueryContext(ctx, query, commonName)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificates: %w", err)
	}
	defer rows.Close()

	return r.scanCertificates(rows)
}

// ============================================================================
// List Certificates (Paginated)
// ============================================================================

// ListCertificates returns a paginated list of all issued certificates.
func (r *certificateRepository) ListCertificates(ctx context.Context, limit int, offset int) ([]*IssuedCertificate, error) {
	// Apply defaults
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000 // Maximum limit
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			COALESCE(issued_to_device_ip::text, ''), COALESCE(issued_to_mac::text, ''),
			issued_by, status, revoked_at, created_at
		FROM issued_certificates
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.db.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	defer rows.Close()

	return r.scanCertificates(rows)
}

// ============================================================================
// Get Expiring Certificates
// ============================================================================

// GetExpiringCertificates finds certificates expiring within specified days.
func (r *certificateRepository) GetExpiringCertificates(ctx context.Context, withinDays int) ([]*IssuedCertificate, error) {
	query := `
		SELECT id, serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			COALESCE(issued_to_device_ip::text, ''), COALESCE(issued_to_mac::text, ''),
			issued_by, status, revoked_at, created_at
		FROM issued_certificates
		WHERE not_after <= NOW() + INTERVAL '1 day' * $1
			AND not_after > NOW()
			AND status = 'active'
		ORDER BY not_after ASC`

	rows, err := r.db.db.QueryContext(ctx, query, withinDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get expiring certificates: %w", err)
	}
	defer rows.Close()

	return r.scanCertificates(rows)
}

// ============================================================================
// Count Certificates
// ============================================================================

// CountCertificates returns total count of issued certificates.
func (r *certificateRepository) CountCertificates(ctx context.Context) (int, error) {
	var count int
	err := r.db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM issued_certificates").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count certificates: %w", err)
	}
	return count, nil
}

// CountActiveCertificates returns count of non-expired certificates.
func (r *certificateRepository) CountActiveCertificates(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM issued_certificates WHERE not_after > NOW() AND status = 'active'`
	var count int
	err := r.db.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active certificates: %w", err)
	}
	return count, nil
}

// ============================================================================
// Delete Certificate
// ============================================================================

// DeleteCertificate removes a certificate record from the database.
// WARNING: This is for cleanup only, not revocation. Use RevokeCertificate for that.
func (r *certificateRepository) DeleteCertificate(ctx context.Context, serialNumber string) error {
	result, err := r.db.db.ExecContext(ctx,
		"DELETE FROM issued_certificates WHERE serial_number = $1",
		serialNumber,
	)
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

// ============================================================================
// Search Certificates
// ============================================================================

// SearchCertificates performs full-text search on certificates.
func (r *certificateRepository) SearchCertificates(ctx context.Context, query string) ([]*IssuedCertificate, error) {
	// Prepare search pattern
	searchPattern := "%" + strings.ToLower(query) + "%"

	sqlQuery := `
		SELECT id, serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			COALESCE(issued_to_device_ip::text, ''), COALESCE(issued_to_mac::text, ''),
			issued_by, status, revoked_at, created_at
		FROM issued_certificates
		WHERE LOWER(common_name) LIKE $1
			OR LOWER(serial_number) LIKE $1
			OR $2 = ANY(subject_alt_names)
		ORDER BY created_at DESC
		LIMIT 100`

	rows, err := r.db.db.QueryContext(ctx, sqlQuery, searchPattern, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search certificates: %w", err)
	}
	defer rows.Close()

	return r.scanCertificates(rows)
}

// ============================================================================
// Get Certificates by Type
// ============================================================================

// GetCertificatesByType retrieves all certificates of specific type.
func (r *certificateRepository) GetCertificatesByType(ctx context.Context, certType string) ([]*IssuedCertificate, error) {
	query := `
		SELECT id, serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			COALESCE(issued_to_device_ip::text, ''), COALESCE(issued_to_mac::text, ''),
			issued_by, status, revoked_at, created_at
		FROM issued_certificates
		WHERE certificate_type = $1
		ORDER BY created_at DESC`

	rows, err := r.db.db.QueryContext(ctx, query, certType)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificates by type: %w", err)
	}
	defer rows.Close()

	return r.scanCertificates(rows)
}

// ============================================================================
// Bulk Save Certificates
// ============================================================================

// BulkSaveCertificates inserts multiple certificates in a single transaction.
func (r *certificateRepository) BulkSaveCertificates(ctx context.Context, certs []*IssuedCertificate) error {
	if len(certs) == 0 {
		return nil
	}

	tx, err := r.db.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Prepare the insert statement
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO issued_certificates (
			serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			issued_to_device_ip, issued_to_mac,
			issued_by, status, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING id`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	// Insert each certificate
	for _, cert := range certs {
		// Set defaults
		if cert.Status == "" {
			cert.Status = "active"
		}
		if cert.IssuedBy == "" {
			cert.IssuedBy = "system"
		}
		if cert.CreatedAt.IsZero() {
			cert.CreatedAt = time.Now()
		}

		// Convert device IP and MAC to nullable
		var deviceIP, deviceMAC interface{}
		if cert.IssuedToDeviceIP != "" {
			deviceIP = cert.IssuedToDeviceIP
		}
		if cert.IssuedToMAC != "" {
			deviceMAC = cert.IssuedToMAC
		}

		err = stmt.QueryRowContext(ctx,
			cert.SerialNumber,
			cert.CommonName,
			cert.SubjectDN,
			cert.IssuerDN,
			pq.Array(cert.SubjectAltNames),
			cert.NotBefore,
			cert.NotAfter,
			cert.SignatureAlgo,
			cert.KeyType,
			cert.KeySize,
			cert.FingerprintSHA256,
			cert.FingerprintSHA1,
			cert.CertificatePEM,
			cert.CertificateType,
			deviceIP,
			deviceMAC,
			cert.IssuedBy,
			cert.Status,
			cert.CreatedAt,
		).Scan(&cert.ID)

		if err != nil {
			return fmt.Errorf("failed to insert certificate %s: %w", cert.SerialNumber, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ============================================================================
// Update Certificate Status
// ============================================================================

// UpdateCertificateStatus updates the status of a certificate.
func (r *certificateRepository) UpdateCertificateStatus(ctx context.Context, serialNumber string, status string) error {
	var result sql.Result
	var err error

	if status == "revoked" {
		result, err = r.db.db.ExecContext(ctx,
			"UPDATE issued_certificates SET status = $1, revoked_at = NOW() WHERE serial_number = $2",
			status, serialNumber,
		)
	} else {
		result, err = r.db.db.ExecContext(ctx,
			"UPDATE issued_certificates SET status = $1 WHERE serial_number = $2",
			status, serialNumber,
		)
	}

	if err != nil {
		return fmt.Errorf("failed to update certificate status: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// scanCertificates scans multiple certificate rows into a slice.
func (r *certificateRepository) scanCertificates(rows *sql.Rows) ([]*IssuedCertificate, error) {
	var certs []*IssuedCertificate

	for rows.Next() {
		cert := &IssuedCertificate{}
		var revokedAt sql.NullTime

		err := rows.Scan(
			&cert.ID,
			&cert.SerialNumber,
			&cert.CommonName,
			&cert.SubjectDN,
			&cert.IssuerDN,
			pq.Array(&cert.SubjectAltNames),
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.SignatureAlgo,
			&cert.KeyType,
			&cert.KeySize,
			&cert.FingerprintSHA256,
			&cert.FingerprintSHA1,
			&cert.CertificatePEM,
			&cert.CertificateType,
			&cert.IssuedToDeviceIP,
			&cert.IssuedToMAC,
			&cert.IssuedBy,
			&cert.Status,
			&revokedAt,
			&cert.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate row: %w", err)
		}

		if revokedAt.Valid {
			cert.RevokedAt = &revokedAt.Time
		}

		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificate rows: %w", err)
	}

	return certs, nil
}

// ============================================================================
// Additional Query Functions
// ============================================================================

// GetCertificateByFingerprint retrieves a certificate by its SHA-256 fingerprint.
func (r *certificateRepository) GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*IssuedCertificate, error) {
	query := `
		SELECT id, serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			COALESCE(issued_to_device_ip::text, ''), COALESCE(issued_to_mac::text, ''),
			issued_by, status, revoked_at, created_at
		FROM issued_certificates
		WHERE fingerprint_sha256 = $1`

	cert := &IssuedCertificate{}
	var revokedAt sql.NullTime

	err := r.db.db.QueryRowContext(ctx, query, fingerprint).Scan(
		&cert.ID,
		&cert.SerialNumber,
		&cert.CommonName,
		&cert.SubjectDN,
		&cert.IssuerDN,
		pq.Array(&cert.SubjectAltNames),
		&cert.NotBefore,
		&cert.NotAfter,
		&cert.SignatureAlgo,
		&cert.KeyType,
		&cert.KeySize,
		&cert.FingerprintSHA256,
		&cert.FingerprintSHA1,
		&cert.CertificatePEM,
		&cert.CertificateType,
		&cert.IssuedToDeviceIP,
		&cert.IssuedToMAC,
		&cert.IssuedBy,
		&cert.Status,
		&revokedAt,
		&cert.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrCertificateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate by fingerprint: %w", err)
	}

	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}

	return cert, nil
}

// GetCertificatesIssuedToDevice retrieves all certificates issued to a specific device.
func (r *certificateRepository) GetCertificatesIssuedToDevice(ctx context.Context, deviceIP string, macAddress string) ([]*IssuedCertificate, error) {
	query := `
		SELECT id, serial_number, common_name, subject_dn, issuer_dn,
			subject_alt_names, not_before, not_after,
			signature_algorithm, key_type, key_size,
			fingerprint_sha256, fingerprint_sha1,
			certificate_pem, certificate_type,
			COALESCE(issued_to_device_ip::text, ''), COALESCE(issued_to_mac::text, ''),
			issued_by, status, revoked_at, created_at
		FROM issued_certificates
		WHERE (issued_to_device_ip = $1::inet OR issued_to_mac = $2::macaddr)
		ORDER BY created_at DESC`

	rows, err := r.db.db.QueryContext(ctx, query, deviceIP, macAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificates for device: %w", err)
	}
	defer rows.Close()

	return r.scanCertificates(rows)
}

// GetCertificateStatistics returns statistics about issued certificates.
func (r *certificateRepository) GetCertificateStatistics(ctx context.Context) (map[string]int, error) {
	stats := make(map[string]int)

	// Total certificates
	var total int
	if err := r.db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM issued_certificates").Scan(&total); err != nil {
		return nil, err
	}
	stats["total"] = total

	// Active certificates
	var active int
	if err := r.db.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates WHERE status = 'active' AND not_after > NOW()").Scan(&active); err != nil {
		return nil, err
	}
	stats["active"] = active

	// Expired certificates
	var expired int
	if err := r.db.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates WHERE not_after <= NOW()").Scan(&expired); err != nil {
		return nil, err
	}
	stats["expired"] = expired

	// Revoked certificates
	var revoked int
	if err := r.db.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates WHERE status = 'revoked'").Scan(&revoked); err != nil {
		return nil, err
	}
	stats["revoked"] = revoked

	// Expiring soon (within 30 days)
	var expiringSoon int
	if err := r.db.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM issued_certificates WHERE not_after <= NOW() + INTERVAL '30 days' AND not_after > NOW() AND status = 'active'").Scan(&expiringSoon); err != nil {
		return nil, err
	}
	stats["expiring_30_days"] = expiringSoon

	return stats, nil
}
