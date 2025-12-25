// Package storage provides database migration management for Certificate Manager.
package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// Embedded SQL Files
// ============================================================================

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ============================================================================
// Migration Metadata Structure
// ============================================================================

// Migration represents a single schema migration
type Migration struct {
	Version     string    `json:"version"`
	Name        string    `json:"name"`
	SQL         string    `json:"-"`
	Checksum    string    `json:"checksum"`
	AppliedAt   time.Time `json:"applied_at"`
	Status      string    `json:"status"` // pending, applied, failed
	ExecutionMs int64     `json:"execution_ms"`
	ErrorMsg    string    `json:"error_msg,omitempty"`
}

// MigrationStatus constants
const (
	StatusPending = "pending"
	StatusApplied = "applied"
	StatusFailed  = "failed"
)

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrMigrationFailed   = errors.New("migration failed")
	ErrChecksumMismatch  = errors.New("migration checksum mismatch")
	ErrMigrationGap      = errors.New("migration sequence has gaps")
	ErrAlreadyApplied    = errors.New("migration already applied")
	ErrNoMigrationsFound = errors.New("no migrations found")
)

// ============================================================================
// Migrator Structure
// ============================================================================

// Migrator manages database schema migrations
type Migrator struct {
	db         *sql.DB
	migrations []Migration
}

// NewMigrator creates a new migrator instance
func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{
		db:         db,
		migrations: []Migration{},
	}
}

// ============================================================================
// Schema Version Tracking Table
// ============================================================================

const createMigrationsTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version VARCHAR(50) PRIMARY KEY,
	name VARCHAR(255) NOT NULL,
	checksum VARCHAR(64) NOT NULL,
	applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	execution_ms BIGINT DEFAULT 0,
	status VARCHAR(20) DEFAULT 'applied',
	error_msg TEXT
);

CREATE INDEX IF NOT EXISTS idx_schema_migrations_status ON schema_migrations(status);
`

// InitializeMigrationTable creates the schema_migrations tracking table
func (m *Migrator) InitializeMigrationTable(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, createMigrationsTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}
	return nil
}

// ============================================================================
// Migration Execution Engine
// ============================================================================

// RunMigrations applies all pending migrations in order
func (m *Migrator) RunMigrations(ctx context.Context) error {
	// Initialize migration tracking table first
	if err := m.InitializeMigrationTable(ctx); err != nil {
		return err
	}

	// Load available migrations
	if err := m.loadMigrations(); err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	// Get pending migrations
	pending, err := m.GetPendingMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get pending migrations: %w", err)
	}

	if len(pending) == 0 {
		return nil // No migrations to apply
	}

	// Validate migration sequence
	if err := m.ValidateMigrationSequence(pending); err != nil {
		return err
	}

	// Apply each migration in order
	for _, migration := range pending {
		if err := m.applyMigration(ctx, &migration); err != nil {
			return fmt.Errorf("migration %s failed: %w", migration.Version, err)
		}
	}

	return nil
}

// applyMigration executes a single migration within a transaction
func (m *Migrator) applyMigration(ctx context.Context, migration *Migration) error {
	start := time.Now()

	// Begin transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Execute migration SQL
	_, err = tx.ExecContext(ctx, migration.SQL)
	if err != nil {
		// Record failure
		m.recordMigrationResult(ctx, migration, StatusFailed, time.Since(start).Milliseconds(), err.Error())
		return fmt.Errorf("SQL execution failed: %w", err)
	}

	// Record success in tracking table
	recordSQL := `
		INSERT INTO schema_migrations (version, name, checksum, status, execution_ms, applied_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (version) DO UPDATE SET
			status = EXCLUDED.status,
			execution_ms = EXCLUDED.execution_ms,
			applied_at = EXCLUDED.applied_at`

	_, err = tx.ExecContext(ctx, recordSQL,
		migration.Version,
		migration.Name,
		migration.Checksum,
		StatusApplied,
		time.Since(start).Milliseconds(),
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ============================================================================
// Migration Loading and Ordering
// ============================================================================

// loadMigrations loads SQL migrations from embedded files
func (m *Migrator) loadMigrations() error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		// No embedded migrations directory, use initial schema
		m.migrations = []Migration{
			{
				Version: "010",
				Name:    "certificate_manager_initial",
				SQL:     initialSchemaSQL,
			},
		}
		m.migrations[0].Checksum = calculateChecksum(m.migrations[0].SQL)
		return nil
	}

	m.migrations = make([]Migration, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		content, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", entry.Name(), err)
		}

		// Parse version and name from filename (e.g., "010_certificate_manager.sql")
		parts := strings.SplitN(strings.TrimSuffix(entry.Name(), ".sql"), "_", 2)
		version := parts[0]
		name := "migration"
		if len(parts) > 1 {
			name = parts[1]
		}

		migration := Migration{
			Version:  version,
			Name:     name,
			SQL:      string(content),
			Checksum: calculateChecksum(string(content)),
			Status:   StatusPending,
		}

		m.migrations = append(m.migrations, migration)
	}

	// Sort by version
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})

	return nil
}

// GetPendingMigrations returns migrations not yet applied
func (m *Migrator) GetPendingMigrations(ctx context.Context) ([]Migration, error) {
	// Get already applied migrations
	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	appliedMap := make(map[string]Migration)
	for _, mig := range applied {
		appliedMap[mig.Version] = mig
	}

	// Filter to pending only
	var pending []Migration
	for _, migration := range m.migrations {
		if existing, ok := appliedMap[migration.Version]; ok {
			// Check checksum
			if existing.Checksum != migration.Checksum {
				return nil, fmt.Errorf("%w: version %s was modified after being applied",
					ErrChecksumMismatch, migration.Version)
			}
			continue // Already applied
		}
		pending = append(pending, migration)
	}

	return pending, nil
}

// GetAppliedMigrations returns all applied migrations from database
func (m *Migrator) GetAppliedMigrations(ctx context.Context) ([]Migration, error) {
	query := `
		SELECT version, name, checksum, applied_at, execution_ms, status, COALESCE(error_msg, '')
		FROM schema_migrations
		WHERE status = 'applied'
		ORDER BY version ASC`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	var migrations []Migration
	for rows.Next() {
		var mig Migration
		err := rows.Scan(
			&mig.Version,
			&mig.Name,
			&mig.Checksum,
			&mig.AppliedAt,
			&mig.ExecutionMs,
			&mig.Status,
			&mig.ErrorMsg,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan migration row: %w", err)
		}
		migrations = append(migrations, mig)
	}

	return migrations, nil
}

// ValidateMigrationSequence ensures no gaps in version numbers
func (m *Migrator) ValidateMigrationSequence(migrations []Migration) error {
	if len(migrations) == 0 {
		return nil
	}

	// For now, just ensure they're sorted
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version < migrations[i-1].Version {
			return fmt.Errorf("%w: versions out of order", ErrMigrationGap)
		}
	}

	return nil
}

// ============================================================================
// Idempotency Handling
// ============================================================================

// IsAlreadyApplied checks if migration version exists in tracking table
func (m *Migrator) IsAlreadyApplied(ctx context.Context, version string) (bool, error) {
	var count int
	err := m.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM schema_migrations WHERE version = $1 AND status = 'applied'",
		version,
	).Scan(&count)

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// ============================================================================
// Schema Version Reporting
// ============================================================================

// GetCurrentVersion returns the latest applied migration version
func (m *Migrator) GetCurrentVersion(ctx context.Context) (string, error) {
	var version sql.NullString
	err := m.db.QueryRowContext(ctx,
		"SELECT MAX(version) FROM schema_migrations WHERE status = 'applied'",
	).Scan(&version)

	if err != nil {
		return "", err
	}

	if !version.Valid {
		return "", nil // No migrations applied
	}

	return version.String, nil
}

// GetMigrationHistory returns full list of applied migrations
func (m *Migrator) GetMigrationHistory(ctx context.Context) ([]Migration, error) {
	query := `
		SELECT version, name, checksum, applied_at, execution_ms, status, COALESCE(error_msg, '')
		FROM schema_migrations
		ORDER BY version ASC`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []Migration
	for rows.Next() {
		var mig Migration
		err := rows.Scan(
			&mig.Version,
			&mig.Name,
			&mig.Checksum,
			&mig.AppliedAt,
			&mig.ExecutionMs,
			&mig.Status,
			&mig.ErrorMsg,
		)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, mig)
	}

	return migrations, nil
}

// MigrationReport contains migration status summary
type MigrationReport struct {
	CurrentVersion    string      `json:"current_version"`
	TotalApplied      int         `json:"total_applied"`
	TotalPending      int         `json:"total_pending"`
	TotalFailed       int         `json:"total_failed"`
	LastAppliedAt     time.Time   `json:"last_applied_at"`
	AppliedMigrations []Migration `json:"applied_migrations"`
	PendingMigrations []Migration `json:"pending_migrations"`
}

// GenerateMigrationReport creates summary of schema state
func (m *Migrator) GenerateMigrationReport(ctx context.Context) (*MigrationReport, error) {
	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	pending, err := m.GetPendingMigrations(ctx)
	if err != nil {
		return nil, err
	}

	// Count failed
	var failedCount int
	err = m.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM schema_migrations WHERE status = 'failed'",
	).Scan(&failedCount)
	if err != nil {
		failedCount = 0
	}

	currentVersion, _ := m.GetCurrentVersion(ctx)

	var lastApplied time.Time
	if len(applied) > 0 {
		lastApplied = applied[len(applied)-1].AppliedAt
	}

	return &MigrationReport{
		CurrentVersion:    currentVersion,
		TotalApplied:      len(applied),
		TotalPending:      len(pending),
		TotalFailed:       failedCount,
		LastAppliedAt:     lastApplied,
		AppliedMigrations: applied,
		PendingMigrations: pending,
	}, nil
}

// ============================================================================
// Error Handling and Recovery
// ============================================================================

// recordMigrationResult records migration execution result
func (m *Migrator) recordMigrationResult(ctx context.Context, migration *Migration, status string, execMs int64, errorMsg string) {
	query := `
		INSERT INTO schema_migrations (version, name, checksum, status, execution_ms, error_msg, applied_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (version) DO UPDATE SET
			status = EXCLUDED.status,
			execution_ms = EXCLUDED.execution_ms,
			error_msg = EXCLUDED.error_msg,
			applied_at = EXCLUDED.applied_at`

	m.db.ExecContext(ctx, query,
		migration.Version,
		migration.Name,
		migration.Checksum,
		status,
		execMs,
		errorMsg,
		time.Now(),
	)
}

// GetFailedMigrations returns list of failed migrations
func (m *Migrator) GetFailedMigrations(ctx context.Context) ([]Migration, error) {
	query := `
		SELECT version, name, checksum, applied_at, execution_ms, status, COALESCE(error_msg, '')
		FROM schema_migrations
		WHERE status = 'failed'
		ORDER BY applied_at DESC`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []Migration
	for rows.Next() {
		var mig Migration
		err := rows.Scan(
			&mig.Version,
			&mig.Name,
			&mig.Checksum,
			&mig.AppliedAt,
			&mig.ExecutionMs,
			&mig.Status,
			&mig.ErrorMsg,
		)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, mig)
	}

	return migrations, nil
}

// ResetFailedMigration allows retry after fixing issue
func (m *Migrator) ResetFailedMigration(ctx context.Context, version string) error {
	result, err := m.db.ExecContext(ctx,
		"DELETE FROM schema_migrations WHERE version = $1 AND status = 'failed'",
		version,
	)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no failed migration found with version %s", version)
	}

	return nil
}

// ============================================================================
// Manual Migration Support
// ============================================================================

// ApplySpecificMigration runs a single migration by version
func (m *Migrator) ApplySpecificMigration(ctx context.Context, version string) error {
	// Find migration by version
	var migration *Migration
	for i := range m.migrations {
		if m.migrations[i].Version == version {
			migration = &m.migrations[i]
			break
		}
	}

	if migration == nil {
		return fmt.Errorf("migration version %s not found", version)
	}

	// Check if already applied
	applied, err := m.IsAlreadyApplied(ctx, version)
	if err != nil {
		return err
	}
	if applied {
		return ErrAlreadyApplied
	}

	return m.applyMigration(ctx, migration)
}

// MarkAsApplied manually records migration as applied without running SQL
func (m *Migrator) MarkAsApplied(ctx context.Context, version, name, checksum string) error {
	query := `
		INSERT INTO schema_migrations (version, name, checksum, status, applied_at)
		VALUES ($1, $2, $3, 'applied', $4)
		ON CONFLICT (version) DO UPDATE SET status = 'applied'`

	_, err := m.db.ExecContext(ctx, query, version, name, checksum, time.Now())
	return err
}

// ============================================================================
// Helper Functions
// ============================================================================

// calculateChecksum computes SHA256 hash of SQL content
func calculateChecksum(sql string) string {
	hash := sha256.Sum256([]byte(sql))
	return fmt.Sprintf("%x", hash)
}

// ============================================================================
// Initial Schema (Embedded Fallback)
// ============================================================================

// initialSchemaSQL is the fallback schema if no migration files are embedded
const initialSchemaSQL = `
-- Certificate Manager Initial Schema
-- Version: 010

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS acme_accounts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    private_key_pem TEXT NOT NULL,
    directory_url VARCHAR(500) NOT NULL,
    registration_url VARCHAR(500),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    tos_agreed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    common_name VARCHAR(253) NOT NULL,
    subject_alt_names TEXT[] DEFAULT '{}',
    is_wildcard BOOLEAN DEFAULT FALSE,
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    chain_pem TEXT,
    serial_number VARCHAR(255) UNIQUE,
    issuer VARCHAR(255),
    not_before TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    acme_order_url VARCHAR(500),
    challenge_type VARCHAR(20),
    acme_account_id INTEGER REFERENCES acme_accounts(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificate_history (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    event_type VARCHAR(30) NOT NULL,
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    previous_serial VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    triggered_by VARCHAR(100) DEFAULT 'system',
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS renewal_schedule (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE UNIQUE,
    next_renewal_check TIMESTAMP WITH TIME ZONE NOT NULL,
    renewal_attempt_count INTEGER DEFAULT 0,
    last_renewal_attempt TIMESTAMP WITH TIME ZONE,
    last_renewal_result VARCHAR(20),
    renewal_window_start TIMESTAMP WITH TIME ZONE,
    auto_renewal_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domain_challenges (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    domain VARCHAR(253) NOT NULL,
    challenge_type VARCHAR(20) NOT NULL,
    token VARCHAR(500) NOT NULL,
    key_authorization TEXT NOT NULL,
    validation_url VARCHAR(500),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempt_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    validated_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS distribution_log (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    target_service VARCHAR(100) NOT NULL,
    distribution_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    distribution_method VARCHAR(30),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    service_ack_timestamp TIMESTAMP WITH TIME ZONE,
    service_version VARCHAR(50),
    retry_count INTEGER DEFAULT 0,
    next_retry_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cert_common_name ON certificates(common_name);
CREATE INDEX IF NOT EXISTS idx_cert_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_cert_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_renewal_next_check ON renewal_schedule(next_renewal_check);
CREATE INDEX IF NOT EXISTS idx_challenges_domain_status ON domain_challenges(domain, status);
`
