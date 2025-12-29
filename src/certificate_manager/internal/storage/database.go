// Package storage provides database and filesystem storage for certificates.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"certificate_manager/pkg/types"

	_ "github.com/lib/pq"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrNotFound          = errors.New("record not found")
	ErrDuplicateKey      = errors.New("duplicate key violation")
	ErrConnectionFailed  = errors.New("database connection failed")
	ErrQueryFailed       = errors.New("query execution failed")
	ErrTransactionFailed = errors.New("transaction failed")
)

// ============================================================================
// Database Structure
// ============================================================================

// Database wraps the PostgreSQL connection pool
type Database struct {
	db     *sql.DB
	config types.DatabaseConfig
}

// ============================================================================
// Database Initialization
// ============================================================================

// NewDatabase creates a new database storage instance
func NewDatabase(config types.DatabaseConfig) (*Database, error) {
	if !config.Enabled {
		return nil, errors.New("database storage is disabled in config")
	}

	connStr := buildConnectionString(config)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxConnections)
	db.SetMaxIdleConns(config.IdleConnections)
	db.SetConnMaxLifetime(config.ConnectionLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectionTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("%w: ping failed: %v", ErrConnectionFailed, err)
	}

	return &Database{
		db:     db,
		config: config,
	}, nil
}

// buildConnectionString creates PostgreSQL connection string
func buildConnectionString(config types.DatabaseConfig) string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		config.Host,
		config.Port,
		config.Name,
		config.User,
		config.Password,
		config.SSLMode,
	)
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// Ping tests database connectivity
func (d *Database) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

// ============================================================================
// Certificate Storage Operations
// ============================================================================

// StoreCertificate inserts a new certificate record
func (d *Database) StoreCertificate(ctx context.Context, cert *types.Certificate) (int64, error) {
	query := `
		INSERT INTO certificates (
			common_name, subject_alt_names, is_wildcard,
			certificate_pem, private_key_pem, chain_pem,
			serial_number, issuer, not_before, not_after,
			status, acme_account_id, acme_order_url, challenge_type,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id`

	var id int64
	err := d.db.QueryRowContext(ctx, query,
		cert.CommonName,
		pqArray(cert.SubjectAltNames),
		cert.IsWildcard,
		cert.CertificatePEM,
		cert.PrivateKeyPEM,
		cert.ChainPEM,
		cert.SerialNumber,
		cert.Issuer,
		cert.NotBefore,
		cert.NotAfter,
		string(cert.Status),
		cert.AcmeAccountID,
		cert.AcmeOrderURL,
		string(cert.ChallengeType),
		time.Now(),
		time.Now(),
	).Scan(&id)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return 0, ErrDuplicateKey
		}
		return 0, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	return id, nil
}

// UpdateCertificate updates an existing certificate
func (d *Database) UpdateCertificate(ctx context.Context, cert *types.Certificate) error {
	query := `
		UPDATE certificates SET
			certificate_pem = $1,
			private_key_pem = $2,
			chain_pem = $3,
			serial_number = $4,
			not_before = $5,
			not_after = $6,
			status = $7,
			updated_at = $8
		WHERE id = $9`

	result, err := d.db.ExecContext(ctx, query,
		cert.CertificatePEM,
		cert.PrivateKeyPEM,
		cert.ChainPEM,
		cert.SerialNumber,
		cert.NotBefore,
		cert.NotAfter,
		string(cert.Status),
		time.Now(),
		cert.ID,
	)

	if err != nil {
		return fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// GetCertificate retrieves a certificate by domain name
func (d *Database) GetCertificate(ctx context.Context, domain string) (*types.Certificate, error) {
	query := `
		SELECT id, common_name, subject_alt_names, is_wildcard,
			certificate_pem, private_key_pem, chain_pem,
			serial_number, issuer, not_before, not_after,
			status, acme_account_id, acme_order_url, challenge_type,
			created_at, updated_at
		FROM certificates
		WHERE (common_name = $1 OR $1 = ANY(subject_alt_names))
			AND status = 'active'
		ORDER BY not_after DESC
		LIMIT 1`

	cert := &types.Certificate{}
	var sans []string
	var status, challengeType string

	err := d.db.QueryRowContext(ctx, query, domain).Scan(
		&cert.ID,
		&cert.CommonName,
		pqArrayScan(&sans),
		&cert.IsWildcard,
		&cert.CertificatePEM,
		&cert.PrivateKeyPEM,
		&cert.ChainPEM,
		&cert.SerialNumber,
		&cert.Issuer,
		&cert.NotBefore,
		&cert.NotAfter,
		&status,
		&cert.AcmeAccountID,
		&cert.AcmeOrderURL,
		&challengeType,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	cert.SubjectAltNames = sans
	cert.Status = types.CertificateStatus(status)
	cert.ChallengeType = types.ChallengeType(challengeType)

	return cert, nil
}

// GetCertificateByID retrieves a certificate by ID
func (d *Database) GetCertificateByID(ctx context.Context, id int64) (*types.Certificate, error) {
	query := `
		SELECT id, common_name, subject_alt_names, is_wildcard,
			certificate_pem, private_key_pem, chain_pem,
			serial_number, issuer, not_before, not_after,
			status, acme_account_id, acme_order_url, challenge_type,
			created_at, updated_at
		FROM certificates
		WHERE id = $1`

	cert := &types.Certificate{}
	var sans []string
	var status, challengeType string

	err := d.db.QueryRowContext(ctx, query, id).Scan(
		&cert.ID,
		&cert.CommonName,
		pqArrayScan(&sans),
		&cert.IsWildcard,
		&cert.CertificatePEM,
		&cert.PrivateKeyPEM,
		&cert.ChainPEM,
		&cert.SerialNumber,
		&cert.Issuer,
		&cert.NotBefore,
		&cert.NotAfter,
		&status,
		&cert.AcmeAccountID,
		&cert.AcmeOrderURL,
		&challengeType,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	cert.SubjectAltNames = sans
	cert.Status = types.CertificateStatus(status)
	cert.ChallengeType = types.ChallengeType(challengeType)

	return cert, nil
}

// ListCertificates returns all certificates, optionally filtered by status
func (d *Database) ListCertificates(ctx context.Context, status string) ([]*types.Certificate, error) {
	var query string
	var args []interface{}

	if status != "" {
		query = `
			SELECT id, common_name, subject_alt_names, is_wildcard,
				certificate_pem, private_key_pem, chain_pem,
				serial_number, issuer, not_before, not_after,
				status, acme_account_id, acme_order_url, challenge_type,
				created_at, updated_at
			FROM certificates
			WHERE status = $1
			ORDER BY not_after DESC`
		args = []interface{}{status}
	} else {
		query = `
			SELECT id, common_name, subject_alt_names, is_wildcard,
				certificate_pem, private_key_pem, chain_pem,
				serial_number, issuer, not_before, not_after,
				status, acme_account_id, acme_order_url, challenge_type,
				created_at, updated_at
			FROM certificates
			ORDER BY not_after DESC`
	}

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}
	defer rows.Close()

	var certs []*types.Certificate
	for rows.Next() {
		cert := &types.Certificate{}
		var sans []string
		var statusStr, challengeType string

		err := rows.Scan(
			&cert.ID,
			&cert.CommonName,
			pqArrayScan(&sans),
			&cert.IsWildcard,
			&cert.CertificatePEM,
			&cert.PrivateKeyPEM,
			&cert.ChainPEM,
			&cert.SerialNumber,
			&cert.Issuer,
			&cert.NotBefore,
			&cert.NotAfter,
			&statusStr,
			&cert.AcmeAccountID,
			&cert.AcmeOrderURL,
			&challengeType,
			&cert.CreatedAt,
			&cert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: scan failed: %v", ErrQueryFailed, err)
		}

		cert.SubjectAltNames = sans
		cert.Status = types.CertificateStatus(statusStr)
		cert.ChallengeType = types.ChallengeType(challengeType)
		certs = append(certs, cert)
	}

	return certs, nil
}

// DeleteCertificate soft-deletes a certificate by marking status as revoked
func (d *Database) DeleteCertificate(ctx context.Context, id int64) error {
	query := `UPDATE certificates SET status = 'revoked', updated_at = $1 WHERE id = $2`

	result, err := d.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ============================================================================
// ACME Account Management
// ============================================================================

// StoreACMEAccount saves account registration data
func (d *Database) StoreACMEAccount(ctx context.Context, account *types.AcmeAccount) (int64, error) {
	query := `
		INSERT INTO acme_accounts (
			email, private_key_pem, directory_url, registration_url,
			status, tos_agreed_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`

	var id int64
	tosAgreedAt := time.Now()
	if !account.TermsAgreed {
		tosAgreedAt = time.Time{}
	}

	err := d.db.QueryRowContext(ctx, query,
		account.Email,
		account.PrivateKeyPEM,
		account.DirectoryURL,
		account.RegistrationURL,
		string(account.Status),
		tosAgreedAt,
		time.Now(),
		time.Now(),
	).Scan(&id)

	if err != nil {
		if IsDuplicateKeyError(err) {
			return 0, ErrDuplicateKey
		}
		return 0, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	return id, nil
}

// GetACMEAccount retrieves account info by email
func (d *Database) GetACMEAccount(ctx context.Context, email string) (*types.AcmeAccount, error) {
	query := `
		SELECT id, email, private_key_pem, directory_url, registration_url,
			status, tos_agreed_at, created_at, updated_at
		FROM acme_accounts
		WHERE email = $1 AND status = 'active'
		LIMIT 1`

	account := &types.AcmeAccount{}
	var status string
	var tosAgreedAt sql.NullTime

	err := d.db.QueryRowContext(ctx, query, email).Scan(
		&account.ID,
		&account.Email,
		&account.PrivateKeyPEM,
		&account.DirectoryURL,
		&account.RegistrationURL,
		&status,
		&tosAgreedAt,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	account.Status = types.AccountStatus(status)
	account.TermsAgreed = tosAgreedAt.Valid

	return account, nil
}

// GetACMEAccountByID retrieves account info by ID
func (d *Database) GetACMEAccountByID(ctx context.Context, id int64) (*types.AcmeAccount, error) {
	query := `
		SELECT id, email, private_key_pem, directory_url, registration_url,
			status, tos_agreed_at, created_at, updated_at
		FROM acme_accounts
		WHERE id = $1`

	account := &types.AcmeAccount{}
	var status string
	var tosAgreedAt sql.NullTime

	err := d.db.QueryRowContext(ctx, query, id).Scan(
		&account.ID,
		&account.Email,
		&account.PrivateKeyPEM,
		&account.DirectoryURL,
		&account.RegistrationURL,
		&status,
		&tosAgreedAt,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	account.Status = types.AccountStatus(status)
	account.TermsAgreed = tosAgreedAt.Valid

	return account, nil
}

// ListACMEAccounts returns all ACME accounts
func (d *Database) ListACMEAccounts(ctx context.Context) ([]*types.AcmeAccount, error) {
	query := `
		SELECT id, email, private_key_pem, directory_url, registration_url,
			status, tos_agreed_at, created_at, updated_at
		FROM acme_accounts
		ORDER BY created_at DESC`

	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}
	defer rows.Close()

	var accounts []*types.AcmeAccount
	for rows.Next() {
		account := &types.AcmeAccount{}
		var status string
		var tosAgreedAt sql.NullTime

		err := rows.Scan(
			&account.ID,
			&account.Email,
			&account.PrivateKeyPEM,
			&account.DirectoryURL,
			&account.RegistrationURL,
			&status,
			&tosAgreedAt,
			&account.CreatedAt,
			&account.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: scan failed: %v", ErrQueryFailed, err)
		}

		account.Status = types.AccountStatus(status)
		account.TermsAgreed = tosAgreedAt.Valid
		accounts = append(accounts, account)
	}

	return accounts, nil
}

// ============================================================================
// Renewal Tracking Operations
// ============================================================================

// GetCertificatesDueForRenewal returns certificates expiring within threshold
func (d *Database) GetCertificatesDueForRenewal(ctx context.Context, daysThreshold int) ([]*types.Certificate, error) {
	query := `
		SELECT id, common_name, subject_alt_names, is_wildcard,
			certificate_pem, private_key_pem, chain_pem,
			serial_number, issuer, not_before, not_after,
			status, acme_account_id, acme_order_url, challenge_type,
			created_at, updated_at
		FROM certificates
		WHERE status = 'active'
			AND not_after <= NOW() + INTERVAL '1 day' * $1
		ORDER BY not_after ASC`

	rows, err := d.db.QueryContext(ctx, query, daysThreshold)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}
	defer rows.Close()

	var certs []*types.Certificate
	for rows.Next() {
		cert := &types.Certificate{}
		var sans []string
		var status, challengeType string

		err := rows.Scan(
			&cert.ID,
			&cert.CommonName,
			pqArrayScan(&sans),
			&cert.IsWildcard,
			&cert.CertificatePEM,
			&cert.PrivateKeyPEM,
			&cert.ChainPEM,
			&cert.SerialNumber,
			&cert.Issuer,
			&cert.NotBefore,
			&cert.NotAfter,
			&status,
			&cert.AcmeAccountID,
			&cert.AcmeOrderURL,
			&challengeType,
			&cert.CreatedAt,
			&cert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: scan failed: %v", ErrQueryFailed, err)
		}

		cert.SubjectAltNames = sans
		cert.Status = types.CertificateStatus(status)
		cert.ChallengeType = types.ChallengeType(challengeType)
		certs = append(certs, cert)
	}

	return certs, nil
}

// RecordCertificateHistory logs a certificate lifecycle event
func (d *Database) RecordCertificateHistory(ctx context.Context, certID int64, eventType string, success bool, errorMsg string) error {
	query := `
		INSERT INTO certificate_history (
			certificate_id, event_type, success, error_message, event_timestamp
		) VALUES ($1, $2, $3, $4, $5)`

	_, err := d.db.ExecContext(ctx, query, certID, eventType, success, errorMsg, time.Now())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	return nil
}

// UpdateCertificateStatus updates the status of a certificate
func (d *Database) UpdateCertificateStatus(ctx context.Context, id int64, status types.CertificateStatus) error {
	query := `UPDATE certificates SET status = $1, updated_at = $2 WHERE id = $3`

	result, err := d.db.ExecContext(ctx, query, string(status), time.Now(), id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ============================================================================
// Transaction Support
// ============================================================================

// Tx wraps sql.Tx for transactions
type Tx struct {
	tx *sql.Tx
}

// BeginTx starts a database transaction
func (d *Database) BeginTx(ctx context.Context) (*Tx, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransactionFailed, err)
	}
	return &Tx{tx: tx}, nil
}

// Commit commits the transaction
func (t *Tx) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction
func (t *Tx) Rollback() error {
	return t.tx.Rollback()
}

// ============================================================================
// Distribution Logging
// ============================================================================

// RecordDistribution logs a certificate distribution event
func (d *Database) RecordDistribution(ctx context.Context, dist *types.Distribution) (int64, error) {
	query := `
		INSERT INTO distribution_log (
			certificate_id, target_service, distribution_timestamp,
			distribution_method, status, retry_count
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`

	var id int64
	err := d.db.QueryRowContext(ctx, query,
		dist.CertificateID,
		dist.TargetService,
		time.Now(),
		string(dist.Method),
		string(dist.Status),
		dist.RetryCount,
	).Scan(&id)

	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	return id, nil
}

// UpdateDistributionStatus updates a distribution record
func (d *Database) UpdateDistributionStatus(ctx context.Context, id int64, status types.DistributionStatus, errorMsg string) error {
	query := `
		UPDATE distribution_log SET
			status = $1,
			error_message = $2,
			service_ack_timestamp = CASE WHEN $1 = 'success' THEN NOW() ELSE NULL END
		WHERE id = $3`

	_, err := d.db.ExecContext(ctx, query, string(status), errorMsg, id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	return nil
}

// ============================================================================
// Challenge Storage
// ============================================================================

// StoreChallenge saves an ACME challenge
func (d *Database) StoreChallenge(ctx context.Context, challenge *types.Challenge) (int64, error) {
	query := `
		INSERT INTO domain_challenges (
			certificate_id, domain, challenge_type, token,
			key_authorization, validation_url, status, attempt_count,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`

	var id int64
	err := d.db.QueryRowContext(ctx, query,
		challenge.CertificateID,
		challenge.Domain,
		string(challenge.Type),
		challenge.Token,
		challenge.KeyAuthorization,
		challenge.ValidationURL,
		string(challenge.Status),
		challenge.AttemptCount,
		time.Now(),
	).Scan(&id)

	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	return id, nil
}

// UpdateChallengeStatus updates challenge status
func (d *Database) UpdateChallengeStatus(ctx context.Context, id int64, status types.ChallengeStatus, errorMsg string) error {
	query := `
		UPDATE domain_challenges SET
			status = $1,
			error_message = $2,
			attempt_count = attempt_count + 1,
			validated_at = CASE WHEN $1 = 'valid' THEN NOW() ELSE NULL END
		WHERE id = $3`

	_, err := d.db.ExecContext(ctx, query, string(status), errorMsg, id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	return nil
}

// ============================================================================
// Error Handling Helpers
// ============================================================================

// IsDuplicateKeyError checks if error is a unique constraint violation
func IsDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "unique constraint")
}

// IsConnectionError checks if error is a connection failure
func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "no connection") ||
		strings.Contains(err.Error(), "connection reset")
}

// ============================================================================
// PostgreSQL Array Helpers
// ============================================================================

// pqArray converts []string to PostgreSQL array format
func pqArray(arr []string) string {
	if len(arr) == 0 {
		return "{}"
	}
	return "{" + strings.Join(arr, ",") + "}"
}

// pqArrayScan returns a scanner for PostgreSQL arrays
func pqArrayScan(dest *[]string) interface{} {
	return &pgStringArray{dest}
}

type pgStringArray struct {
	arr *[]string
}

func (p *pgStringArray) Scan(src interface{}) error {
	if src == nil {
		*p.arr = nil
		return nil
	}

	switch v := src.(type) {
	case []byte:
		return p.parseArray(string(v))
	case string:
		return p.parseArray(v)
	default:
		return fmt.Errorf("cannot scan type %T into string array", src)
	}
}

func (p *pgStringArray) parseArray(s string) error {
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")

	if s == "" {
		*p.arr = []string{}
		return nil
	}

	*p.arr = strings.Split(s, ",")
	return nil
}

// ============================================================================
// Statistics and Metrics
// ============================================================================

// GetCertificateStats returns certificate statistics
func (d *Database) GetCertificateStats(ctx context.Context) (map[string]int64, error) {
	query := `
		SELECT status, COUNT(*) as count
		FROM certificates
		GROUP BY status`

	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}
	defer rows.Close()

	stats := make(map[string]int64)
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		stats[status] = count
	}

	return stats, nil
}

// GetTotalCertificates returns total certificate count
func (d *Database) GetTotalCertificates(ctx context.Context) (int64, error) {
	var count int64
	err := d.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}
	return count, nil
}

// ============================================================================
// Health Check and Connection Pool Monitoring
// ============================================================================

// HealthCheckResult contains detailed health check results
type HealthCheckResult struct {
	Healthy       bool          `json:"healthy"`
	PingOK        bool          `json:"ping_ok"`
	QueryOK       bool          `json:"query_ok"`
	QueryDuration time.Duration `json:"query_duration"`
	PoolStats     sql.DBStats   `json:"pool_stats"`
	PoolSaturated bool          `json:"pool_saturated"`
	SchemaOK      bool          `json:"schema_ok"`
	Errors        []string      `json:"errors,omitempty"`
	Warnings      []string      `json:"warnings,omitempty"`
	CheckedAt     time.Time     `json:"checked_at"`
}

// HealthCheck performs comprehensive database health validation
func (d *Database) HealthCheck(ctx context.Context) (*HealthCheckResult, error) {
	result := &HealthCheckResult{
		Healthy:   true,
		CheckedAt: time.Now(),
		Errors:    []string{},
		Warnings:  []string{},
	}

	// Check 1: Ping database
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pingCancel()

	if err := d.db.PingContext(pingCtx); err != nil {
		result.PingOK = false
		result.Healthy = false
		result.Errors = append(result.Errors, fmt.Sprintf("ping failed: %v", err))
	} else {
		result.PingOK = true
	}

	// Check 2: Execute test query and measure duration
	queryStart := time.Now()
	queryCtx, queryCancel := context.WithTimeout(ctx, 10*time.Second)
	defer queryCancel()

	var testResult int
	err := d.db.QueryRowContext(queryCtx, "SELECT 1").Scan(&testResult)
	result.QueryDuration = time.Since(queryStart)

	if err != nil {
		result.QueryOK = false
		result.Healthy = false
		result.Errors = append(result.Errors, fmt.Sprintf("query failed: %v", err))
	} else {
		result.QueryOK = true
		// Warn if query slow (> 100ms)
		if result.QueryDuration > 100*time.Millisecond {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("query slow: %v", result.QueryDuration))
		}
	}

	// Check 3: Connection pool statistics
	result.PoolStats = d.db.Stats()

	// Check for pool saturation
	if result.PoolStats.OpenConnections >= result.PoolStats.MaxOpenConnections {
		result.PoolSaturated = true
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("connection pool saturated: %d/%d connections in use",
				result.PoolStats.OpenConnections, result.PoolStats.MaxOpenConnections))
	}

	// Warn if too few idle connections
	if result.PoolStats.Idle < 2 && result.PoolStats.OpenConnections > 5 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("low idle connections: %d idle", result.PoolStats.Idle))
	}

	// Check 4: Verify schema_migrations table exists
	var tableExists bool
	schemaQuery := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = 'schema_migrations'
		)`
	if err := d.db.QueryRowContext(ctx, schemaQuery).Scan(&tableExists); err != nil {
		result.SchemaOK = false
		result.Errors = append(result.Errors, fmt.Sprintf("schema check failed: %v", err))
	} else {
		result.SchemaOK = tableExists
		if !tableExists {
			result.Warnings = append(result.Warnings, "schema_migrations table not found")
		}
	}

	return result, nil
}

// GetStats returns current connection pool statistics
func (d *Database) GetStats() sql.DBStats {
	return d.db.Stats()
}

// TestQuery executes a simple test query to verify database accessibility
func (d *Database) TestQuery(ctx context.Context) error {
	var version string
	err := d.db.QueryRowContext(ctx, "SELECT version()").Scan(&version)
	if err != nil {
		return fmt.Errorf("test query failed: %w", err)
	}
	return nil
}

// ============================================================================
// Query Execution with Timeout
// ============================================================================

// DefaultQueryTimeout is the default timeout for queries
const DefaultQueryTimeout = 30 * time.Second

// QueryWithTimeout executes a SELECT query with timeout
func (d *Database) QueryWithTimeout(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	// Apply timeout if context doesn't have one
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultQueryTimeout)
		defer cancel()
	}

	return d.db.QueryContext(ctx, query, args...)
}

// QueryRowWithTimeout executes a query expected to return single row with timeout
func (d *Database) QueryRowWithTimeout(ctx context.Context, query string, args ...interface{}) *sql.Row {
	// Apply timeout if context doesn't have one
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultQueryTimeout)
		_ = cancel // Will be called when Row is scanned
	}

	return d.db.QueryRowContext(ctx, query, args...)
}

// ExecWithTimeout executes INSERT/UPDATE/DELETE with timeout
func (d *Database) ExecWithTimeout(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	// Apply timeout if context doesn't have one
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultQueryTimeout)
		defer cancel()
	}

	return d.db.ExecContext(ctx, query, args...)
}

// ============================================================================
// Retry Logic for Transient Failures
// ============================================================================

// RetryConfig holds retry behavior configuration
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	BackoffFactor  float64
}

// DefaultRetryConfig returns sensible retry defaults
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
		BackoffFactor:  2.0,
	}
}

// RetryQuery retries query execution on transient failures with exponential backoff
func (d *Database) RetryQuery(ctx context.Context, config *RetryConfig, query string, args ...interface{}) (*sql.Rows, error) {
	if config == nil {
		config = DefaultRetryConfig()
	}

	var lastErr error
	backoff := config.InitialBackoff

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		rows, err := d.db.QueryContext(ctx, query, args...)
		if err == nil {
			return rows, nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err) {
			return nil, err
		}

		// Check if context is done
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Wait before retry
		if attempt < config.MaxRetries {
			time.Sleep(backoff)

			// Calculate next backoff (exponential)
			backoff = time.Duration(float64(backoff) * config.BackoffFactor)
			if backoff > config.MaxBackoff {
				backoff = config.MaxBackoff
			}
		}
	}

	return nil, fmt.Errorf("query failed after %d retries: %w", config.MaxRetries+1, lastErr)
}

// RetryExec retries exec on transient failures with exponential backoff
func (d *Database) RetryExec(ctx context.Context, config *RetryConfig, query string, args ...interface{}) (sql.Result, error) {
	if config == nil {
		config = DefaultRetryConfig()
	}

	var lastErr error
	backoff := config.InitialBackoff

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		result, err := d.db.ExecContext(ctx, query, args...)
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err) {
			return nil, err
		}

		// Check if context is done
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Wait before retry
		if attempt < config.MaxRetries {
			time.Sleep(backoff)

			// Calculate next backoff (exponential)
			backoff = time.Duration(float64(backoff) * config.BackoffFactor)
			if backoff > config.MaxBackoff {
				backoff = config.MaxBackoff
			}
		}
	}

	return nil, fmt.Errorf("exec failed after %d retries: %w", config.MaxRetries+1, lastErr)
}

// isRetryableError determines if an error is transient and can be retried
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Connection errors (retryable)
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection timeout") ||
		strings.Contains(errStr, "no connection") ||
		strings.Contains(errStr, "too many connections") ||
		strings.Contains(errStr, "deadlock detected") ||
		strings.Contains(errStr, "lock timeout") ||
		strings.Contains(errStr, "serialization failure") {
		return true
	}

	// Driver-specific errors
	if strings.Contains(errStr, "pq: could not obtain") ||
		strings.Contains(errStr, "pq: canceling statement") {
		return true
	}

	return false
}

// ============================================================================
// Prepared Statement Cache
// ============================================================================

// PreparedStatementCache caches prepared statements for repeated execution
type PreparedStatementCache struct {
	db         *sql.DB
	statements map[string]*sql.Stmt
	mu         sync.RWMutex
}

// NewPreparedStatementCache creates a new statement cache
func (d *Database) NewPreparedStatementCache() *PreparedStatementCache {
	return &PreparedStatementCache{
		db:         d.db,
		statements: make(map[string]*sql.Stmt),
	}
}

// Prepare prepares and caches a SQL statement
func (c *PreparedStatementCache) Prepare(query string) (*sql.Stmt, error) {
	// Check cache first (read lock)
	c.mu.RLock()
	if stmt, ok := c.statements[query]; ok {
		c.mu.RUnlock()
		return stmt, nil
	}
	c.mu.RUnlock()

	// Prepare statement (write lock)
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if stmt, ok := c.statements[query]; ok {
		return stmt, nil
	}

	// Prepare new statement
	stmt, err := c.db.Prepare(query)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}

	c.statements[query] = stmt
	return stmt, nil
}

// Close closes all cached prepared statements
func (c *PreparedStatementCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []string
	for query, stmt := range c.statements {
		if err := stmt.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("failed to close statement: %v", err))
		}
		delete(c.statements, query)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing statements: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Size returns the number of cached statements
func (c *PreparedStatementCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.statements)
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

// GracefulShutdownTimeout is the maximum time to wait for in-flight queries
const GracefulShutdownTimeout = 30 * time.Second

// CloseGracefully waits for in-flight queries before closing
func (d *Database) CloseGracefully(ctx context.Context) error {
	// Get initial stats
	stats := d.db.Stats()
	inUse := stats.InUse

	if inUse > 0 {
		// Wait for in-flight queries
		deadline := time.Now().Add(GracefulShutdownTimeout)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

	WaitLoop:
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				// Context cancelled, force close
				break WaitLoop
			case <-ticker.C:
				stats = d.db.Stats()
				if stats.InUse == 0 {
					// All queries completed
					break WaitLoop
				}
			}
		}
	}

	return d.db.Close()
}
