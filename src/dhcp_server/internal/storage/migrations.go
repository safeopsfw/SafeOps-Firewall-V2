// Package storage provides database operations for the DHCP server.
// This file implements database schema migrations with version tracking.
package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Migration Types and Enums
// ============================================================================

// MigrationDirection specifies UP (apply) or DOWN (rollback).
type MigrationDirection int

const (
	MigrationUp MigrationDirection = iota
	MigrationDown
)

// MigrationStatus indicates migration state.
type MigrationStatus string

const (
	StatusPending    MigrationStatus = "PENDING"
	StatusApplied    MigrationStatus = "APPLIED"
	StatusFailed     MigrationStatus = "FAILED"
	StatusRolledBack MigrationStatus = "ROLLED_BACK"
)

// ============================================================================
// Migration Data Structures
// ============================================================================

// Migration represents a single database migration.
type Migration struct {
	Version     string `json:"version"`
	Description string `json:"description"`
	UpSQL       string `json:"-"`
	DownSQL     string `json:"-"`
	Checksum    string `json:"checksum"`
}

// MigrationHistory tracks applied migrations.
type MigrationHistory struct {
	Version     string          `json:"version"`
	Description string          `json:"description"`
	AppliedAt   time.Time       `json:"applied_at"`
	Checksum    string          `json:"checksum"`
	Status      MigrationStatus `json:"status"`
	Duration    time.Duration   `json:"duration"`
}

// MigrationManager orchestrates migration execution.
type MigrationManager struct {
	mu         sync.Mutex
	db         *sql.DB
	migrations []*Migration
	tableName  string
	lockID     int64
}

// MigrationConfig holds configuration settings.
type MigrationConfig struct {
	TableName        string
	LockTimeout      time.Duration
	DryRun           bool
	ValidateChecksum bool
	AutoRun          bool
}

// DefaultMigrationConfig returns sensible defaults.
func DefaultMigrationConfig() MigrationConfig {
	return MigrationConfig{
		TableName:        "dhcp_migration_history",
		LockTimeout:      15 * time.Minute,
		DryRun:           false,
		ValidateChecksum: true,
		AutoRun:          false,
	}
}

// ============================================================================
// Migration Definitions
// ============================================================================

// GetMigrations returns all defined migrations in order.
func GetMigrations() []*Migration {
	return []*Migration{
		migrationV1_0_0(),
		migrationV1_1_0(),
		migrationV1_2_0(),
	}
}

// migrationV1_0_0 creates the initial schema.
func migrationV1_0_0() *Migration {
	return &Migration{
		Version:     "1.0.0",
		Description: "Initial DHCP server schema",
		UpSQL: `
-- Migration history table
CREATE TABLE IF NOT EXISTS dhcp_migration_history (
    id SERIAL PRIMARY KEY,
    version VARCHAR(20) NOT NULL UNIQUE,
    description TEXT,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    checksum VARCHAR(64),
    status VARCHAR(20) DEFAULT 'APPLIED',
    duration_ms INTEGER
);

-- DHCP Pools table
CREATE TABLE IF NOT EXISTS dhcp_pools (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    subnet_cidr CIDR NOT NULL,
    gateway INET,
    dns_servers INET[],
    domain_name VARCHAR(255),
    ntp_servers INET[],
    default_lease_time INTEGER DEFAULT 86400,
    min_lease_time INTEGER DEFAULT 300,
    max_lease_time INTEGER DEFAULT 604800,
    vlan_id INTEGER,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- DHCP Ranges table
CREATE TABLE IF NOT EXISTS dhcp_ranges (
    id SERIAL PRIMARY KEY,
    pool_id INTEGER NOT NULL REFERENCES dhcp_pools(id) ON DELETE CASCADE,
    start_ip INET NOT NULL,
    end_ip INET NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_range CHECK (start_ip <= end_ip)
);

-- DHCP Leases table
CREATE TABLE IF NOT EXISTS dhcp_leases (
    id SERIAL PRIMARY KEY,
    pool_id INTEGER NOT NULL REFERENCES dhcp_pools(id) ON DELETE CASCADE,
    ip_address INET NOT NULL UNIQUE,
    mac_address MACADDR NOT NULL,
    hostname VARCHAR(255),
    client_id VARCHAR(255),
    state VARCHAR(20) DEFAULT 'ACTIVE',
    lease_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    lease_end TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE,
    transaction_id INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- DHCP Reservations table
CREATE TABLE IF NOT EXISTS dhcp_reservations (
    id SERIAL PRIMARY KEY,
    pool_id INTEGER NOT NULL REFERENCES dhcp_pools(id) ON DELETE CASCADE,
    mac_address MACADDR NOT NULL UNIQUE,
    ip_address INET NOT NULL UNIQUE,
    hostname VARCHAR(255),
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- DHCP Options table
CREATE TABLE IF NOT EXISTS dhcp_options (
    id SERIAL PRIMARY KEY,
    pool_id INTEGER REFERENCES dhcp_pools(id) ON DELETE CASCADE,
    option_code INTEGER NOT NULL,
    option_name VARCHAR(100),
    option_value BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_leases_mac ON dhcp_leases(mac_address);
CREATE INDEX IF NOT EXISTS idx_leases_ip ON dhcp_leases(ip_address);
CREATE INDEX IF NOT EXISTS idx_leases_state ON dhcp_leases(state);
CREATE INDEX IF NOT EXISTS idx_leases_end ON dhcp_leases(lease_end);
CREATE INDEX IF NOT EXISTS idx_reservations_mac ON dhcp_reservations(mac_address);
CREATE INDEX IF NOT EXISTS idx_reservations_ip ON dhcp_reservations(ip_address);
CREATE INDEX IF NOT EXISTS idx_ranges_pool ON dhcp_ranges(pool_id);
CREATE INDEX IF NOT EXISTS idx_options_pool ON dhcp_options(pool_id);
`,
		DownSQL: `
DROP TABLE IF EXISTS dhcp_options;
DROP TABLE IF EXISTS dhcp_reservations;
DROP TABLE IF EXISTS dhcp_leases;
DROP TABLE IF EXISTS dhcp_ranges;
DROP TABLE IF EXISTS dhcp_pools;
DROP TABLE IF EXISTS dhcp_migration_history;
`,
	}
}

// migrationV1_1_0 adds lease state machine columns.
func migrationV1_1_0() *Migration {
	return &Migration{
		Version:     "1.1.0",
		Description: "Add lease state machine and audit columns",
		UpSQL: `
-- Add lease event tracking
CREATE TABLE IF NOT EXISTS dhcp_lease_events (
    id SERIAL PRIMARY KEY,
    lease_id INTEGER REFERENCES dhcp_leases(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    old_state VARCHAR(20),
    new_state VARCHAR(20),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add renewal tracking to leases
ALTER TABLE dhcp_leases ADD COLUMN IF NOT EXISTS renewal_count INTEGER DEFAULT 0;
ALTER TABLE dhcp_leases ADD COLUMN IF NOT EXISTS last_renewed TIMESTAMP WITH TIME ZONE;

-- Index for lease events
CREATE INDEX IF NOT EXISTS idx_lease_events_lease ON dhcp_lease_events(lease_id);
CREATE INDEX IF NOT EXISTS idx_lease_events_type ON dhcp_lease_events(event_type);
`,
		DownSQL: `
ALTER TABLE dhcp_leases DROP COLUMN IF EXISTS renewal_count;
ALTER TABLE dhcp_leases DROP COLUMN IF EXISTS last_renewed;
DROP TABLE IF EXISTS dhcp_lease_events;
`,
	}
}

// migrationV1_2_0 adds pool statistics tracking.
func migrationV1_2_0() *Migration {
	return &Migration{
		Version:     "1.2.0",
		Description: "Add pool statistics and utilization tracking",
		UpSQL: `
-- Pool statistics table
CREATE TABLE IF NOT EXISTS dhcp_pool_statistics (
    id SERIAL PRIMARY KEY,
    pool_id INTEGER NOT NULL REFERENCES dhcp_pools(id) ON DELETE CASCADE,
    total_ips INTEGER NOT NULL,
    allocated_ips INTEGER DEFAULT 0,
    reserved_ips INTEGER DEFAULT 0,
    utilization_percent DECIMAL(5,2),
    peak_utilization DECIMAL(5,2),
    peak_time TIMESTAMP WITH TIME ZONE,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Active leases view
CREATE OR REPLACE VIEW v_active_leases AS
SELECT 
    l.*,
    p.name as pool_name,
    p.subnet_cidr
FROM dhcp_leases l
JOIN dhcp_pools p ON l.pool_id = p.id
WHERE l.state = 'ACTIVE' AND l.lease_end > CURRENT_TIMESTAMP;

-- Pool utilization view
CREATE OR REPLACE VIEW v_pool_utilization AS
SELECT 
    p.id as pool_id,
    p.name as pool_name,
    p.subnet_cidr,
    COUNT(l.id) as active_leases,
    COUNT(DISTINCT r.id) as reservations
FROM dhcp_pools p
LEFT JOIN dhcp_leases l ON p.id = l.pool_id AND l.state = 'ACTIVE'
LEFT JOIN dhcp_reservations r ON p.id = r.pool_id
GROUP BY p.id, p.name, p.subnet_cidr;

-- Index for statistics
CREATE INDEX IF NOT EXISTS idx_pool_stats_pool ON dhcp_pool_statistics(pool_id);
CREATE INDEX IF NOT EXISTS idx_pool_stats_time ON dhcp_pool_statistics(recorded_at);
`,
		DownSQL: `
DROP VIEW IF EXISTS v_pool_utilization;
DROP VIEW IF EXISTS v_active_leases;
DROP TABLE IF EXISTS dhcp_pool_statistics;
`,
	}
}

// ============================================================================
// Migration Manager
// ============================================================================

// NewMigrationManager creates a new migration manager.
func NewMigrationManager(db *sql.DB, config MigrationConfig) *MigrationManager {
	migrations := GetMigrations()

	// Calculate checksums
	for _, m := range migrations {
		m.Checksum = calculateChecksum(m.UpSQL)
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return compareVersions(migrations[i].Version, migrations[j].Version) < 0
	})

	return &MigrationManager{
		db:         db,
		migrations: migrations,
		tableName:  config.TableName,
		lockID:     12345, // Advisory lock ID
	}
}

// ============================================================================
// Migration Execution
// ============================================================================

// ApplyAllPending applies all pending migrations.
func (m *MigrationManager) ApplyAllPending(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Acquire lock
	if err := m.acquireLock(ctx); err != nil {
		return fmt.Errorf("failed to acquire migration lock: %w", err)
	}
	defer m.releaseLock(ctx)

	// Ensure history table exists
	if err := m.ensureHistoryTable(ctx); err != nil {
		return fmt.Errorf("failed to create history table: %w", err)
	}

	// Get applied versions
	applied, err := m.getAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied versions: %w", err)
	}

	// Apply pending
	for _, migration := range m.migrations {
		if _, ok := applied[migration.Version]; ok {
			continue // Already applied
		}

		if err := m.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}
	}

	return nil
}

// applyMigration applies a single migration.
func (m *MigrationManager) applyMigration(ctx context.Context, migration *Migration) error {
	start := time.Now()

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute UP SQL
	statements := splitStatements(migration.UpSQL)
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute statement: %w\nSQL: %s", err, stmt)
		}
	}

	// Record in history
	duration := time.Since(start)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO dhcp_migration_history (version, description, checksum, status, duration_ms)
		VALUES ($1, $2, $3, $4, $5)
	`, migration.Version, migration.Description, migration.Checksum, StatusApplied, duration.Milliseconds())
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	return tx.Commit()
}

// RollbackMigration rolls back a specific migration.
func (m *MigrationManager) RollbackMigration(ctx context.Context, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find migration
	var migration *Migration
	for _, mig := range m.migrations {
		if mig.Version == version {
			migration = mig
			break
		}
	}
	if migration == nil {
		return fmt.Errorf("migration %s not found", version)
	}

	// Acquire lock
	if err := m.acquireLock(ctx); err != nil {
		return err
	}
	defer m.releaseLock(ctx)

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Execute DOWN SQL
	statements := splitStatements(migration.DownSQL)
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("rollback failed: %w", err)
		}
	}

	// Update history
	_, err = tx.ExecContext(ctx, `
		UPDATE dhcp_migration_history SET status = $1 WHERE version = $2
	`, StatusRolledBack, version)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// ============================================================================
// Status and Reporting
// ============================================================================

// GetCurrentVersion returns the latest applied version.
func (m *MigrationManager) GetCurrentVersion(ctx context.Context) (string, error) {
	var version sql.NullString
	err := m.db.QueryRowContext(ctx, `
		SELECT version FROM dhcp_migration_history 
		WHERE status = $1 
		ORDER BY applied_at DESC LIMIT 1
	`, StatusApplied).Scan(&version)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return version.String, nil
}

// GetPendingMigrations returns migrations not yet applied.
func (m *MigrationManager) GetPendingMigrations(ctx context.Context) ([]*Migration, error) {
	applied, err := m.getAppliedVersions(ctx)
	if err != nil {
		return nil, err
	}

	pending := make([]*Migration, 0)
	for _, mig := range m.migrations {
		if _, ok := applied[mig.Version]; !ok {
			pending = append(pending, mig)
		}
	}
	return pending, nil
}

// GetHistory returns the migration history.
func (m *MigrationManager) GetHistory(ctx context.Context) ([]*MigrationHistory, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT version, description, applied_at, checksum, status, duration_ms
		FROM dhcp_migration_history
		ORDER BY applied_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	history := make([]*MigrationHistory, 0)
	for rows.Next() {
		h := &MigrationHistory{}
		var durationMs int64
		if err := rows.Scan(&h.Version, &h.Description, &h.AppliedAt, &h.Checksum, &h.Status, &durationMs); err != nil {
			return nil, err
		}
		h.Duration = time.Duration(durationMs) * time.Millisecond
		history = append(history, h)
	}
	return history, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func (m *MigrationManager) ensureHistoryTable(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS dhcp_migration_history (
			id SERIAL PRIMARY KEY,
			version VARCHAR(20) NOT NULL UNIQUE,
			description TEXT,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			checksum VARCHAR(64),
			status VARCHAR(20) DEFAULT 'APPLIED',
			duration_ms INTEGER
		)
	`)
	return err
}

func (m *MigrationManager) getAppliedVersions(ctx context.Context) (map[string]bool, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT version FROM dhcp_migration_history WHERE status = $1
	`, StatusApplied)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, nil
}

func (m *MigrationManager) acquireLock(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", m.lockID)
	return err
}

func (m *MigrationManager) releaseLock(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", m.lockID)
	return err
}

func calculateChecksum(sql string) string {
	hash := sha256.Sum256([]byte(sql))
	return hex.EncodeToString(hash[:])
}

func compareVersions(v1, v2 string) int {
	return strings.Compare(v1, v2)
}

func splitStatements(sql string) []string {
	// Split on semicolons but preserve quoted strings
	statements := make([]string, 0)
	current := strings.Builder{}
	inString := false
	inComment := false

	for i := 0; i < len(sql); i++ {
		c := sql[i]

		// Handle comments
		if !inString && i+1 < len(sql) && sql[i:i+2] == "--" {
			inComment = true
		}
		if inComment && c == '\n' {
			inComment = false
			current.WriteByte(c)
			continue
		}
		if inComment {
			current.WriteByte(c)
			continue
		}

		// Handle strings
		if c == '\'' {
			inString = !inString
		}

		if c == ';' && !inString {
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}

	// Add last statement if any
	stmt := strings.TrimSpace(current.String())
	if stmt != "" {
		statements = append(statements, stmt)
	}

	return statements
}

// ============================================================================
// Errors
// ============================================================================

var (
	ErrMigrationLocked   = errors.New("migration is locked by another process")
	ErrMigrationNotFound = errors.New("migration not found")
	ErrChecksumMismatch  = errors.New("migration checksum mismatch")
	ErrMigrationFailed   = errors.New("migration failed")
)
