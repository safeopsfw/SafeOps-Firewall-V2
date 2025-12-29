package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// Revocation Reason Constants (RFC 5280)
// ============================================================================

const (
	// ReasonUnspecified - default, no specific reason given
	ReasonUnspecified = "unspecified"
	// ReasonKeyCompromise - private key was compromised
	ReasonKeyCompromise = "key_compromise"
	// ReasonCACompromise - CA's private key was compromised
	ReasonCACompromise = "ca_compromise"
	// ReasonAffiliationChanged - subject's organization changed
	ReasonAffiliationChanged = "affiliation_changed"
	// ReasonSuperseded - new certificate issued to replace this one
	ReasonSuperseded = "superseded"
	// ReasonCessationOfOperation - subject no longer operates
	ReasonCessationOfOperation = "cessation_of_operation"
	// ReasonCertificateHold - temporary suspension (can be unrevoked)
	ReasonCertificateHold = "certificate_hold"
	// ReasonPrivilegeWithdrawn - subject's authorization removed
	ReasonPrivilegeWithdrawn = "privilege_withdrawn"
)

// validRevocationReasons contains all valid RFC 5280 revocation reasons.
var validRevocationReasons = map[string]bool{
	ReasonUnspecified:          true,
	ReasonKeyCompromise:        true,
	ReasonCACompromise:         true,
	ReasonAffiliationChanged:   true,
	ReasonSuperseded:           true,
	ReasonCessationOfOperation: true,
	ReasonCertificateHold:      true,
	ReasonPrivilegeWithdrawn:   true,
}

// ============================================================================
// Revoked Certificate Model
// ============================================================================

// RevokedCertificate represents a revoked certificate record from the database.
// Maps to the revoked_certificates table.
type RevokedCertificate struct {
	ID                    int       `json:"id"`
	SerialNumber          string    `json:"serial_number"`
	RevokedAt             time.Time `json:"revoked_at"`
	RevocationReason      string    `json:"revocation_reason"`
	CertificateCommonName string    `json:"certificate_common_name,omitempty"`
	RevokedBy             string    `json:"revoked_by"`
}

// RevocationStats contains statistics about certificate revocations.
type RevocationStats struct {
	TotalRevocations    int            `json:"total_revocations"`
	ReasonCounts        map[string]int `json:"reason_counts"`
	LastRevocation      time.Time      `json:"last_revocation"`
	RevocationsToday    int            `json:"revocations_today"`
	RevocationsThisWeek int            `json:"revocations_this_week"`
}

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrCertificateAlreadyRevoked = errors.New("certificate already revoked")
	ErrCertificateNotRevoked     = errors.New("certificate not revoked")
	ErrInvalidRevocationReason   = errors.New("invalid revocation reason")
	ErrCannotUnrevoke            = errors.New("only certificates with 'certificate_hold' reason can be unrevoked")
)

// ============================================================================
// Revocation Repository Interface
// ============================================================================

// RevocationRepository defines the contract for revocation data access.
type RevocationRepository interface {
	// Core Operations
	RevokeCertificate(ctx context.Context, revocation *RevokedCertificate) error
	CheckRevocation(ctx context.Context, serialNumber string) (*RevokedCertificate, error)
	IsRevoked(ctx context.Context, serialNumber string) (bool, error)
	GetRevocationInfo(ctx context.Context, serialNumber string) (*RevokedCertificate, error)

	// List Operations
	ListRevokedCertificates(ctx context.Context, limit int, offset int) ([]*RevokedCertificate, error)
	GetRevocationsSince(ctx context.Context, since time.Time) ([]*RevokedCertificate, error)
	GetRevocationsByReason(ctx context.Context, reason string) ([]*RevokedCertificate, error)
	GetRevocationsByAdministrator(ctx context.Context, revokedBy string) ([]*RevokedCertificate, error)

	// Counting and Statistics
	CountRevokedCertificates(ctx context.Context) (int, error)
	GetRevocationStats(ctx context.Context) (*RevocationStats, error)

	// Unrevocation (Certificate Hold Only)
	UnrevokeCertificate(ctx context.Context, serialNumber string) error

	// Bulk Operations
	BulkRevokeCertificates(ctx context.Context, revocations []*RevokedCertificate) error
}

// ============================================================================
// Revocation Repository Implementation
// ============================================================================

// revocationRepository is the concrete implementation of RevocationRepository.
type revocationRepository struct {
	db *Database
}

// NewRevocationRepository creates a new revocation repository instance.
func NewRevocationRepository(db *Database) RevocationRepository {
	return &revocationRepository{
		db: db,
	}
}

// ============================================================================
// Validation Helpers
// ============================================================================

// ValidateRevocationReason validates that the reason is RFC 5280 compliant.
func ValidateRevocationReason(reason string) error {
	normalized := strings.ToLower(reason)
	if !validRevocationReasons[normalized] {
		validReasons := make([]string, 0, len(validRevocationReasons))
		for r := range validRevocationReasons {
			validReasons = append(validReasons, r)
		}
		return fmt.Errorf("%w: %s (valid: %s)", ErrInvalidRevocationReason, reason, strings.Join(validReasons, ", "))
	}
	return nil
}

// normalizeRevocationReason normalizes the reason to lowercase.
func normalizeRevocationReason(reason string) string {
	return strings.ToLower(reason)
}

// validateSerialNumber validates that the serial number is not empty.
func validateSerialNumber(serialNumber string) error {
	if strings.TrimSpace(serialNumber) == "" {
		return errors.New("serial number cannot be empty")
	}
	return nil
}

// ============================================================================
// Core Operations
// ============================================================================

// RevokeCertificate inserts a new revocation record into the database.
func (r *revocationRepository) RevokeCertificate(ctx context.Context, revocation *RevokedCertificate) error {
	if revocation == nil {
		return errors.New("revocation record cannot be nil")
	}

	// Validate serial number
	if err := validateSerialNumber(revocation.SerialNumber); err != nil {
		return fmt.Errorf("RevokeCertificate: %w", err)
	}

	// Validate and normalize revocation reason
	if err := ValidateRevocationReason(revocation.RevocationReason); err != nil {
		return fmt.Errorf("RevokeCertificate: %w", err)
	}
	normalizedReason := normalizeRevocationReason(revocation.RevocationReason)

	// Set revoked_at to now if not provided
	revokedAt := revocation.RevokedAt
	if revokedAt.IsZero() {
		revokedAt = time.Now()
	}

	// Check if already revoked
	isRevoked, err := r.IsRevoked(ctx, revocation.SerialNumber)
	if err != nil {
		return fmt.Errorf("RevokeCertificate: check existing: %w", err)
	}
	if isRevoked {
		return fmt.Errorf("RevokeCertificate: %w: %s", ErrCertificateAlreadyRevoked, revocation.SerialNumber)
	}

	query := `
		INSERT INTO revoked_certificates (
			serial_number,
			revoked_at,
			revocation_reason,
			certificate_common_name,
			revoked_by
		) VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`

	err = r.db.db.QueryRowContext(ctx, query,
		revocation.SerialNumber,
		revokedAt,
		normalizedReason,
		revocation.CertificateCommonName,
		revocation.RevokedBy,
	).Scan(&revocation.ID)

	if err != nil {
		return fmt.Errorf("RevokeCertificate: %w", err)
	}

	return nil
}

// CheckRevocation retrieves the revocation record for a serial number.
// Returns the full revocation details or error if not revoked.
func (r *revocationRepository) CheckRevocation(ctx context.Context, serialNumber string) (*RevokedCertificate, error) {
	if err := validateSerialNumber(serialNumber); err != nil {
		return nil, fmt.Errorf("CheckRevocation: %w", err)
	}

	query := `
		SELECT id, serial_number, revoked_at, revocation_reason, 
		       COALESCE(certificate_common_name, ''), revoked_by
		FROM revoked_certificates
		WHERE serial_number = $1
	`

	revocation := &RevokedCertificate{}
	err := r.db.db.QueryRowContext(ctx, query, serialNumber).Scan(
		&revocation.ID,
		&revocation.SerialNumber,
		&revocation.RevokedAt,
		&revocation.RevocationReason,
		&revocation.CertificateCommonName,
		&revocation.RevokedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCertificateNotRevoked
		}
		return nil, fmt.Errorf("CheckRevocation: %w", err)
	}

	return revocation, nil
}

// IsRevoked performs a fast boolean check if a certificate is revoked.
// Uses EXISTS query for optimal performance in high-frequency checks.
func (r *revocationRepository) IsRevoked(ctx context.Context, serialNumber string) (bool, error) {
	if err := validateSerialNumber(serialNumber); err != nil {
		return false, fmt.Errorf("IsRevoked: %w", err)
	}

	query := `SELECT EXISTS(SELECT 1 FROM revoked_certificates WHERE serial_number = $1)`

	var exists bool
	err := r.db.db.QueryRowContext(ctx, query, serialNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("IsRevoked: %w", err)
	}

	return exists, nil
}

// GetRevocationInfo is an alias for CheckRevocation with semantic naming.
func (r *revocationRepository) GetRevocationInfo(ctx context.Context, serialNumber string) (*RevokedCertificate, error) {
	return r.CheckRevocation(ctx, serialNumber)
}

// ============================================================================
// List Operations
// ============================================================================

// ListRevokedCertificates returns a paginated list of all revoked certificates.
// Returns newest revocations first.
func (r *revocationRepository) ListRevokedCertificates(ctx context.Context, limit int, offset int) ([]*RevokedCertificate, error) {
	// Enforce reasonable limits
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, serial_number, revoked_at, revocation_reason, 
		       COALESCE(certificate_common_name, ''), revoked_by
		FROM revoked_certificates
		ORDER BY revoked_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("ListRevokedCertificates: %w", err)
	}
	defer rows.Close()

	return r.scanRevocations(rows)
}

// GetRevocationsSince returns certificates revoked after the specified timestamp.
// Used for incremental CRL updates (delta CRLs).
func (r *revocationRepository) GetRevocationsSince(ctx context.Context, since time.Time) ([]*RevokedCertificate, error) {
	query := `
		SELECT id, serial_number, revoked_at, revocation_reason, 
		       COALESCE(certificate_common_name, ''), revoked_by
		FROM revoked_certificates
		WHERE revoked_at > $1
		ORDER BY revoked_at ASC
	`

	rows, err := r.db.db.QueryContext(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("GetRevocationsSince: %w", err)
	}
	defer rows.Close()

	return r.scanRevocations(rows)
}

// GetRevocationsByReason returns all revocations with a specific reason.
func (r *revocationRepository) GetRevocationsByReason(ctx context.Context, reason string) ([]*RevokedCertificate, error) {
	if err := ValidateRevocationReason(reason); err != nil {
		return nil, fmt.Errorf("GetRevocationsByReason: %w", err)
	}

	normalizedReason := normalizeRevocationReason(reason)

	query := `
		SELECT id, serial_number, revoked_at, revocation_reason, 
		       COALESCE(certificate_common_name, ''), revoked_by
		FROM revoked_certificates
		WHERE revocation_reason = $1
		ORDER BY revoked_at DESC
	`

	rows, err := r.db.db.QueryContext(ctx, query, normalizedReason)
	if err != nil {
		return nil, fmt.Errorf("GetRevocationsByReason: %w", err)
	}
	defer rows.Close()

	return r.scanRevocations(rows)
}

// GetRevocationsByAdministrator returns all revocations performed by a specific admin.
func (r *revocationRepository) GetRevocationsByAdministrator(ctx context.Context, revokedBy string) ([]*RevokedCertificate, error) {
	if strings.TrimSpace(revokedBy) == "" {
		return nil, errors.New("GetRevocationsByAdministrator: administrator name cannot be empty")
	}

	query := `
		SELECT id, serial_number, revoked_at, revocation_reason, 
		       COALESCE(certificate_common_name, ''), revoked_by
		FROM revoked_certificates
		WHERE revoked_by = $1
		ORDER BY revoked_at DESC
	`

	rows, err := r.db.db.QueryContext(ctx, query, revokedBy)
	if err != nil {
		return nil, fmt.Errorf("GetRevocationsByAdministrator: %w", err)
	}
	defer rows.Close()

	return r.scanRevocations(rows)
}

// ============================================================================
// Counting and Statistics
// ============================================================================

// CountRevokedCertificates returns the total count of revoked certificates.
func (r *revocationRepository) CountRevokedCertificates(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM revoked_certificates`

	err := r.db.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountRevokedCertificates: %w", err)
	}

	return count, nil
}

// GetRevocationStats returns comprehensive revocation statistics.
func (r *revocationRepository) GetRevocationStats(ctx context.Context) (*RevocationStats, error) {
	stats := &RevocationStats{
		ReasonCounts: make(map[string]int),
	}

	// Get total count, last revocation, and time-based counts
	summaryQuery := `
		SELECT
			COUNT(*) AS total,
			COALESCE(MAX(revoked_at), '1970-01-01'::timestamp) AS last_revocation,
			SUM(CASE WHEN revoked_at >= CURRENT_DATE THEN 1 ELSE 0 END) AS today,
			SUM(CASE WHEN revoked_at >= NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END) AS this_week
		FROM revoked_certificates
	`

	err := r.db.db.QueryRowContext(ctx, summaryQuery).Scan(
		&stats.TotalRevocations,
		&stats.LastRevocation,
		&stats.RevocationsToday,
		&stats.RevocationsThisWeek,
	)
	if err != nil {
		return nil, fmt.Errorf("GetRevocationStats: summary query: %w", err)
	}

	// Get reason distribution
	reasonQuery := `
		SELECT revocation_reason, COUNT(*) AS count
		FROM revoked_certificates
		GROUP BY revocation_reason
		ORDER BY count DESC
	`

	rows, err := r.db.db.QueryContext(ctx, reasonQuery)
	if err != nil {
		return nil, fmt.Errorf("GetRevocationStats: reason query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var reason string
		var count int
		if err := rows.Scan(&reason, &count); err != nil {
			return nil, fmt.Errorf("GetRevocationStats: scan reason: %w", err)
		}
		stats.ReasonCounts[reason] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRevocationStats: rows error: %w", err)
	}

	return stats, nil
}

// ============================================================================
// Unrevocation (Certificate Hold Only)
// ============================================================================

// UnrevokeCertificate removes a certificate from the revocation list.
// WARNING: Only valid for revocation_reason = "certificate_hold".
// All other revocations are permanent per PKI security requirements.
func (r *revocationRepository) UnrevokeCertificate(ctx context.Context, serialNumber string) error {
	if err := validateSerialNumber(serialNumber); err != nil {
		return fmt.Errorf("UnrevokeCertificate: %w", err)
	}

	// First check if the certificate is revoked and get the reason
	revocation, err := r.CheckRevocation(ctx, serialNumber)
	if err != nil {
		if errors.Is(err, ErrCertificateNotRevoked) {
			return fmt.Errorf("UnrevokeCertificate: %w: %s", ErrCertificateNotRevoked, serialNumber)
		}
		return fmt.Errorf("UnrevokeCertificate: %w", err)
	}

	// Only certificate_hold can be unrevoked
	if revocation.RevocationReason != ReasonCertificateHold {
		return fmt.Errorf("UnrevokeCertificate: %w: reason is '%s', not '%s'",
			ErrCannotUnrevoke, revocation.RevocationReason, ReasonCertificateHold)
	}

	// Delete the revocation record
	query := `
		DELETE FROM revoked_certificates
		WHERE serial_number = $1
		  AND revocation_reason = $2
	`

	result, err := r.db.db.ExecContext(ctx, query, serialNumber, ReasonCertificateHold)
	if err != nil {
		return fmt.Errorf("UnrevokeCertificate: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("UnrevokeCertificate: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("UnrevokeCertificate: no matching revocation found")
	}

	return nil
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkRevokeCertificates revokes multiple certificates in a single transaction.
// Used for mass revocation events like CA compromise.
func (r *revocationRepository) BulkRevokeCertificates(ctx context.Context, revocations []*RevokedCertificate) error {
	if len(revocations) == 0 {
		return nil
	}

	// Validate all revocations first
	for i, revocation := range revocations {
		if revocation == nil {
			return fmt.Errorf("BulkRevokeCertificates: revocation at index %d is nil", i)
		}
		if err := validateSerialNumber(revocation.SerialNumber); err != nil {
			return fmt.Errorf("BulkRevokeCertificates: revocation %d: %w", i, err)
		}
		if err := ValidateRevocationReason(revocation.RevocationReason); err != nil {
			return fmt.Errorf("BulkRevokeCertificates: revocation %d: %w", i, err)
		}
	}

	// Begin transaction
	tx, err := r.db.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("BulkRevokeCertificates: begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Prepare the insert statement
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO revoked_certificates (
			serial_number,
			revoked_at,
			revocation_reason,
			certificate_common_name,
			revoked_by
		) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (serial_number) DO NOTHING
		RETURNING id
	`)
	if err != nil {
		return fmt.Errorf("BulkRevokeCertificates: prepare statement: %w", err)
	}
	defer stmt.Close()

	// Execute for each revocation
	revokedCount := 0
	for _, revocation := range revocations {
		normalizedReason := normalizeRevocationReason(revocation.RevocationReason)
		revokedAt := revocation.RevokedAt
		if revokedAt.IsZero() {
			revokedAt = time.Now()
		}

		var id sql.NullInt64
		err := stmt.QueryRowContext(ctx,
			revocation.SerialNumber,
			revokedAt,
			normalizedReason,
			revocation.CertificateCommonName,
			revocation.RevokedBy,
		).Scan(&id)

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Certificate already revoked, skip (ON CONFLICT DO NOTHING)
				continue
			}
			return fmt.Errorf("BulkRevokeCertificates: insert %s: %w", revocation.SerialNumber, err)
		}

		if id.Valid {
			revocation.ID = int(id.Int64)
			revokedCount++
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("BulkRevokeCertificates: commit: %w", err)
	}

	return nil
}

// ============================================================================
// Additional Query Methods
// ============================================================================

// GetAllRevokedSerialNumbers returns all revoked serial numbers.
// Optimized for CRL generation where only serial numbers are needed.
func (r *revocationRepository) GetAllRevokedSerialNumbers(ctx context.Context) ([]string, error) {
	query := `SELECT serial_number FROM revoked_certificates ORDER BY revoked_at ASC`

	rows, err := r.db.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("GetAllRevokedSerialNumbers: %w", err)
	}
	defer rows.Close()

	var serials []string
	for rows.Next() {
		var serial string
		if err := rows.Scan(&serial); err != nil {
			return nil, fmt.Errorf("GetAllRevokedSerialNumbers: scan: %w", err)
		}
		serials = append(serials, serial)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAllRevokedSerialNumbers: rows error: %w", err)
	}

	return serials, nil
}

// GetRecentRevocations returns the N most recent revocations.
func (r *revocationRepository) GetRecentRevocations(ctx context.Context, count int) ([]*RevokedCertificate, error) {
	if count <= 0 {
		count = 10
	}
	if count > 100 {
		count = 100
	}

	query := `
		SELECT id, serial_number, revoked_at, revocation_reason, 
		       COALESCE(certificate_common_name, ''), revoked_by
		FROM revoked_certificates
		ORDER BY revoked_at DESC
		LIMIT $1
	`

	rows, err := r.db.db.QueryContext(ctx, query, count)
	if err != nil {
		return nil, fmt.Errorf("GetRecentRevocations: %w", err)
	}
	defer rows.Close()

	return r.scanRevocations(rows)
}

// SearchRevocations searches for revocations by certificate common name.
func (r *revocationRepository) SearchRevocations(ctx context.Context, commonNamePattern string) ([]*RevokedCertificate, error) {
	if strings.TrimSpace(commonNamePattern) == "" {
		return nil, errors.New("SearchRevocations: search pattern cannot be empty")
	}

	// Use ILIKE for case-insensitive pattern matching
	query := `
		SELECT id, serial_number, revoked_at, revocation_reason, 
		       COALESCE(certificate_common_name, ''), revoked_by
		FROM revoked_certificates
		WHERE certificate_common_name ILIKE $1
		ORDER BY revoked_at DESC
	`

	// Wrap pattern with wildcards for partial matching
	pattern := "%" + commonNamePattern + "%"

	rows, err := r.db.db.QueryContext(ctx, query, pattern)
	if err != nil {
		return nil, fmt.Errorf("SearchRevocations: %w", err)
	}
	defer rows.Close()

	return r.scanRevocations(rows)
}

// ============================================================================
// Helper Methods
// ============================================================================

// scanRevocations scans rows into a slice of RevokedCertificate.
func (r *revocationRepository) scanRevocations(rows *sql.Rows) ([]*RevokedCertificate, error) {
	revocations := make([]*RevokedCertificate, 0)

	for rows.Next() {
		revocation := &RevokedCertificate{}
		err := rows.Scan(
			&revocation.ID,
			&revocation.SerialNumber,
			&revocation.RevokedAt,
			&revocation.RevocationReason,
			&revocation.CertificateCommonName,
			&revocation.RevokedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		revocations = append(revocations, revocation)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return revocations, nil
}
