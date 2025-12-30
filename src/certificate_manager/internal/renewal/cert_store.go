// Package renewal provides certificate storage for renewal operations.
package renewal

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"
)

// ============================================================================
// Database-Backed Certificate Store
// ============================================================================

// DBCertificateStore stores certificates in PostgreSQL database.
type DBCertificateStore struct {
	db *sql.DB
}

// NewDBCertificateStore creates a new database-backed certificate store.
func NewDBCertificateStore(db *sql.DB) *DBCertificateStore {
	return &DBCertificateStore{
		db: db,
	}
}

// ============================================================================
// CertificateStore Implementation
// ============================================================================

// GetCurrentCA retrieves the current active CA certificate.
func (s *DBCertificateStore) GetCurrentCA(ctx context.Context) (*x509.Certificate, error) {
	query := `
		SELECT certificate_pem, created_at, expires_at
		FROM ca_certificates
		WHERE status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`

	var certPEM string
	var createdAt, expiresAt time.Time

	err := s.db.QueryRowContext(ctx, query).Scan(&certPEM, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no active CA certificate found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query CA certificate: %w", err)
	}

	// Parse PEM
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return cert, nil
}

// StorePendingCA stores a new CA certificate as "pending" for grace period.
func (s *DBCertificateStore) StorePendingCA(ctx context.Context, cert *x509.Certificate, key []byte) error {
	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Encode key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: key,
	})

	// Calculate fingerprint
	fingerprint := fmt.Sprintf("%X", cert.Raw[:32])

	query := `
		INSERT INTO ca_certificates (
			certificate_pem,
			private_key_pem,
			fingerprint,
			status,
			created_at,
			expires_at,
			subject,
			issuer
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := s.db.ExecContext(
		ctx,
		query,
		string(certPEM),
		string(keyPEM),
		fingerprint,
		"pending",
		time.Now(),
		cert.NotAfter,
		cert.Subject.String(),
		cert.Issuer.String(),
	)

	if err != nil {
		return fmt.Errorf("failed to store pending CA: %w", err)
	}

	return nil
}

// PromotePendingToActive promotes the pending CA to active status.
func (s *DBCertificateStore) PromotePendingToActive(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Step 1: Mark current active CA as "archived"
	_, err = tx.ExecContext(ctx, `
		UPDATE ca_certificates
		SET status = 'archived', archived_at = $1
		WHERE status = 'active'
	`, time.Now())
	if err != nil {
		return fmt.Errorf("failed to archive current CA: %w", err)
	}

	// Step 2: Promote pending CA to active
	result, err := tx.ExecContext(ctx, `
		UPDATE ca_certificates
		SET status = 'active', activated_at = $1
		WHERE status = 'pending'
	`, time.Now())
	if err != nil {
		return fmt.Errorf("failed to promote pending CA: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("no pending CA found to promote")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit promotion: %w", err)
	}

	return nil
}

// ArchiveOldCA archives an old CA certificate after grace period.
func (s *DBCertificateStore) ArchiveOldCA(ctx context.Context, cert *x509.Certificate) error {
	fingerprint := fmt.Sprintf("%X", cert.Raw[:32])

	query := `
		UPDATE ca_certificates
		SET status = 'archived', archived_at = $1
		WHERE fingerprint = $2 AND status != 'archived'
	`

	_, err := s.db.ExecContext(ctx, query, time.Now(), fingerprint)
	if err != nil {
		return fmt.Errorf("failed to archive old CA: %w", err)
	}

	return nil
}

// ============================================================================
// Additional Helper Methods
// ============================================================================

// GetPendingCA retrieves the pending CA certificate if one exists.
func (s *DBCertificateStore) GetPendingCA(ctx context.Context) (*x509.Certificate, error) {
	query := `
		SELECT certificate_pem
		FROM ca_certificates
		WHERE status = 'pending'
		ORDER BY created_at DESC
		LIMIT 1
	`

	var certPEM string
	err := s.db.QueryRowContext(ctx, query).Scan(&certPEM)
	if err == sql.ErrNoRows {
		return nil, nil // No pending CA is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query pending CA: %w", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode pending CA PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pending CA: %w", err)
	}

	return cert, nil
}

// GetArchivedCAs retrieves all archived CA certificates.
func (s *DBCertificateStore) GetArchivedCAs(ctx context.Context) ([]*x509.Certificate, error) {
	query := `
		SELECT certificate_pem
		FROM ca_certificates
		WHERE status = 'archived'
		ORDER BY archived_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query archived CAs: %w", err)
	}
	defer rows.Close()

	var certs []*x509.Certificate
	for rows.Next() {
		var certPEM string
		if err := rows.Scan(&certPEM); err != nil {
			return nil, fmt.Errorf("failed to scan archived CA: %w", err)
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			continue // Skip invalid PEM
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // Skip invalid certificates
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// GetCAHistory returns all CA certificates (active, pending, archived).
func (s *DBCertificateStore) GetCAHistory(ctx context.Context) ([]CARecord, error) {
	query := `
		SELECT
			fingerprint,
			status,
			subject,
			created_at,
			expires_at,
			activated_at,
			archived_at
		FROM ca_certificates
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query CA history: %w", err)
	}
	defer rows.Close()

	var records []CARecord
	for rows.Next() {
		var record CARecord
		var activatedAt, archivedAt sql.NullTime

		err := rows.Scan(
			&record.Fingerprint,
			&record.Status,
			&record.Subject,
			&record.CreatedAt,
			&record.ExpiresAt,
			&activatedAt,
			&archivedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan CA record: %w", err)
		}

		if activatedAt.Valid {
			record.ActivatedAt = &activatedAt.Time
		}
		if archivedAt.Valid {
			record.ArchivedAt = &archivedAt.Time
		}

		records = append(records, record)
	}

	return records, nil
}

// CARecord represents a CA certificate record in the database.
type CARecord struct {
	Fingerprint string
	Status      string // active, pending, archived
	Subject     string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ActivatedAt *time.Time
	ArchivedAt  *time.Time
}

// ============================================================================
// Database Schema (for reference)
// ============================================================================

/*
CREATE TABLE IF NOT EXISTS ca_certificates (
    id SERIAL PRIMARY KEY,
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    fingerprint VARCHAR(128) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'pending', 'archived')),
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    activated_at TIMESTAMP,
    archived_at TIMESTAMP,

    INDEX idx_status (status),
    INDEX idx_fingerprint (fingerprint),
    INDEX idx_expires_at (expires_at)
);

-- Ensure only one active CA at a time
CREATE UNIQUE INDEX idx_one_active_ca ON ca_certificates (status) WHERE status = 'active';
*/
