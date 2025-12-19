// Package postgres provides comprehensive database migration management.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safeops/shared/go/errors"
)

// ============================================================================
// Migration Structure
// ============================================================================

// Migration represents a database schema migration
type Migration struct {
	Version         int64     // Timestamp version (YYYYMMDDHHmmss)
	Name            string    // Human-readable name
	Up              string    // SQL to apply migration
	Down            string    // SQL to rollback migration
	Checksum        string    // SHA256 hash of Up SQL
	Applied         bool      // Whether migration has been applied
	AppliedAt       time.Time // When migration was applied
	ExecutionTimeMs int64     // Execution time in milliseconds
}

// ============================================================================
// Migrator
// ============================================================================

// Migrator handles database migrations with filesystem discovery and safety features
type Migrator struct {
	client        *Client
	tableName     string
	migrationsDir string
	migrations    []Migration
	dryRun        bool
	lockID        int64
}

// NewMigrator creates a new migrator that discovers migrations from filesystem
func NewMigrator(client *Client, migrationsDir string) *Migrator {
	return &Migrator{
		client:        client,
		tableName:     "schema_migrations",
		migrationsDir: migrationsDir,
		migrations:    make([]Migration, 0),
		dryRun:        false,
		lockID:        hashString(migrationsDir), // Unique lock per migrations directory
	}
}

// WithTableName sets a custom migrations tracking table name
func (m *Migrator) WithTableName(name string) *Migrator {
	m.tableName = name
	return m
}

// WithDryRun enables dry-run mode (preview without executing)
func (m *Migrator) WithDryRun(enabled bool) *Migrator {
	m.dryRun = enabled
	return m
}

// ============================================================================
// Migration Discovery
// ============================================================================

// LoadMigrations discovers and loads migration files from the filesystem
// Files must follow naming convention: YYYYMMDDHHmmss_description.sql
func (m *Migrator) LoadMigrations(ctx context.Context) error {
	// Check if migrations directory exists
	if _, err := os.Stat(m.migrationsDir); os.IsNotExist(err) {
		return errors.New("POSTGRES_MIGRATIONS_DIR_NOT_FOUND", "Migrations directory not found").
			WithField("dir", m.migrationsDir)
	}

	// Find all .sql files
	files, err := filepath.Glob(filepath.Join(m.migrationsDir, "*.sql"))
	if err != nil {
		return errors.Wrap(err, "POSTGRES_MIGRATIONS_GLOB_FAILED", "Failed to search for migration files")
	}

	if len(files) == 0 {
		if m.client.logger != nil {
			m.client.logger.Warn("No migration files found", "dir", m.migrationsDir)
		}
		return nil
	}

	// Parse each migration file
	migrations := make([]Migration, 0, len(files))
	for _, file := range files {
		migration, err := m.parseMigrationFile(file)
		if err != nil {
			return errors.Wrap(err, "POSTGRES_MIGRATION_PARSE_FAILED", "Failed to parse migration file").
				WithField("file", file)
		}
		migrations = append(migrations, migration)
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	// Validate no version gaps or duplicates
	if err := m.validateMigrationSequence(migrations); err != nil {
		return err
	}

	m.migrations = migrations

	if m.client.logger != nil {
		m.client.logger.Info("Loaded migrations from filesystem",
			"count", len(migrations),
			"dir", m.migrationsDir,
		)
	}

	return nil
}

// parseMigrationFile parses a single migration file
// Expected format:
// -- +migrate Up
// CREATE TABLE...
// -- +migrate Down
// DROP TABLE...
func (m *Migrator) parseMigrationFile(filePath string) (Migration, error) {
	// Extract version and name from filename
	filename := filepath.Base(filePath)
	version, name, err := parseMigrationFilename(filename)
	if err != nil {
		return Migration{}, err
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return Migration{}, err
	}

	// Parse Up and Down SQL sections
	upSQL, downSQL, err := parseMigrationContent(string(content))
	if err != nil {
		return Migration{}, err
	}

	// Calculate checksum
	checksum := calculateChecksum(upSQL)

	return Migration{
		Version:  version,
		Name:     name,
		Up:       upSQL,
		Down:     downSQL,
		Checksum: checksum,
	}, nil
}

// parseMigrationFilename extracts version and name from filename
// Expected format: YYYYMMDDHHmmss_description.sql
func parseMigrationFilename(filename string) (int64, string, error) {
	// Remove .sql extension
	filename = strings.TrimSuffix(filename, ".sql")

	// Split on first underscore
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid filename format: expected YYYYMMDDHHmmss_description.sql, got %s", filename)
	}

	// Parse version
	version, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid version number in filename: %s", parts[0])
	}

	// Validate version format (should be 14 digits: YYYYMMDDHHmmss)
	if len(parts[0]) != 14 {
		return 0, "", fmt.Errorf("version must be 14 digits (YYYYMMDDHHmmss), got %s", parts[0])
	}

	name := parts[1]
	return version, name, nil
}

// parseMigrationContent extracts Up and Down SQL from file content
func parseMigrationContent(content string) (string, string, error) {
	// Find Up marker
	upMarker := "-- +migrate Up"
	downMarker := "-- +migrate Down"

	upIndex := strings.Index(content, upMarker)
	downIndex := strings.Index(content, downMarker)

	if upIndex == -1 {
		return "", "", fmt.Errorf("missing '-- +migrate Up' marker")
	}
	if downIndex == -1 {
		return "", "", fmt.Errorf("missing '-- +migrate Down' marker")
	}
	if upIndex >= downIndex {
		return "", "", fmt.Errorf("'-- +migrate Up' must come before '-- +migrate Down'")
	}

	// Extract SQL sections
	upSQL := content[upIndex+len(upMarker) : downIndex]
	downSQL := content[downIndex+len(downMarker):]

	// Trim whitespace
	upSQL = strings.TrimSpace(upSQL)
	downSQL = strings.TrimSpace(downSQL)

	if upSQL == "" {
		return "", "", fmt.Errorf("Up SQL section is empty")
	}
	if downSQL == "" {
		return "", "", fmt.Errorf("Down SQL section is empty")
	}

	return upSQL, downSQL, nil
}

// calculateChecksum calculates SHA256 hash of SQL content
func calculateChecksum(sql string) string {
	hash := sha256.Sum256([]byte(sql))
	return hex.EncodeToString(hash[:])
}

// hashString converts a string to int64 for advisory lock ID
func hashString(s string) int64 {
	hash := sha256.Sum256([]byte(s))
	// Use first 8 bytes as int64
	var id int64
	for i := 0; i < 8 && i < len(hash); i++ {
		id = (id << 8) | int64(hash[i])
	}
	return id
}

// validateMigrationSequence checks for version gaps or duplicates
func (m *Migrator) validateMigrationSequence(migrations []Migration) error {
	if len(migrations) == 0 {
		return nil
	}

	versionsSeen := make(map[int64]bool)
	for _, migration := range migrations {
		if versionsSeen[migration.Version] {
			return errors.New("POSTGRES_DUPLICATE_MIGRATION_VERSION", "Duplicate migration version detected").
				WithField("version", migration.Version).
				WithField("name", migration.Name)
		}
		versionsSeen[migration.Version] = true
	}

	return nil
}

// ============================================================================
// Schema Tracking Table
// ============================================================================

// Initialize creates the migrations tracking table with enhanced schema
func (m *Migrator) Initialize(ctx context.Context) error {
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version BIGINT PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			checksum VARCHAR(64) NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			execution_time_ms INTEGER NOT NULL,
			applied_by VARCHAR(255) DEFAULT CURRENT_USER
		)
	`, m.tableName)

	_, err := m.client.pool.Exec(ctx, query)
	if err != nil {
		return errors.Wrap(err, "POSTGRES_MIGRATIONS_TABLE_CREATE_FAILED", "Failed to create migrations tracking table")
	}

	// Create index on applied_at for chronological queries
	indexQuery := fmt.Sprintf(`
		CREATE INDEX IF NOT EXISTS %s_applied_at_idx ON %s (applied_at)
	`, m.tableName, m.tableName)

	_, err = m.client.pool.Exec(ctx, indexQuery)
	return err
}

// CurrentVersion returns the highest applied migration version
func (m *Migrator) CurrentVersion(ctx context.Context) (int64, error) {
	var version int64
	query := fmt.Sprintf("SELECT COALESCE(MAX(version), 0) FROM %s", m.tableName)
	err := m.client.pool.QueryRow(ctx, query).Scan(&version)
	if err != nil {
		// Table might not exist yet
		if strings.Contains(err.Error(), "does not exist") {
			return 0, nil
		}
		return 0, err
	}
	return version, nil
}

// getAppliedMigrations returns map of applied migrations with metadata
func (m *Migrator) getAppliedMigrations(ctx context.Context) (map[int64]Migration, error) {
	query := fmt.Sprintf(`
		SELECT version, name, checksum, applied_at, execution_time_ms
		FROM %s
		ORDER BY version
	`, m.tableName)

	rows, err := m.client.pool.Query(ctx, query)
	if err != nil {
		// Table might not exist yet
		if strings.Contains(err.Error(), "does not exist") {
			return make(map[int64]Migration), nil
		}
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int64]Migration)
	for rows.Next() {
		var m Migration
		err := rows.Scan(&m.Version, &m.Name, &m.Checksum, &m.AppliedAt, &m.ExecutionTimeMs)
		if err != nil {
			return nil, err
		}
		m.Applied = true
		applied[m.Version] = m
	}

	return applied, rows.Err()
}

// ============================================================================
// Advisory Locks (Concurrent Protection)
// ============================================================================

// acquireLock acquires PostgreSQL advisory lock to prevent concurrent migrations
func (m *Migrator) acquireLock(ctx context.Context) error {
	query := "SELECT pg_try_advisory_lock($1)"
	var acquired bool
	err := m.client.pool.QueryRow(ctx, query, m.lockID).Scan(&acquired)
	if err != nil {
		return errors.Wrap(err, "POSTGRES_LOCK_FAILED", "Failed to acquire migration lock")
	}

	if !acquired {
		return errors.New("POSTGRES_LOCK_BUSY", "Another migration is already running").
			WithField("lock_id", m.lockID)
	}

	if m.client.logger != nil {
		m.client.logger.Debug("Acquired migration lock", "lock_id", m.lockID)
	}

	return nil
}

// releaseLock releases the PostgreSQL advisory lock
func (m *Migrator) releaseLock(ctx context.Context) error {
	query := "SELECT pg_advisory_unlock($1)"
	var released bool
	err := m.client.pool.QueryRow(ctx, query, m.lockID).Scan(&released)
	if err != nil {
		return err
	}

	if m.client.logger != nil {
		m.client.logger.Debug("Released migration lock", "lock_id", m.lockID)
	}

	return nil
}

// ============================================================================
// Migration Execution
// ============================================================================

// Up runs all pending migrations
func (m *Migrator) Up(ctx context.Context) error {
	// Load migrations from filesystem
	if err := m.LoadMigrations(ctx); err != nil {
		return err
	}

	// Acquire lock
	if err := m.acquireLock(ctx); err != nil {
		return err
	}
	defer m.releaseLock(ctx)

	// Initialize tracking table
	if err := m.Initialize(ctx); err != nil {
		return err
	}

	// Get applied migrations
	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	// Find pending migrations
	pending := make([]Migration, 0)
	for _, migration := range m.migrations {
		if appliedMig, exists := applied[migration.Version]; exists {
			// Verify checksum
			if appliedMig.Checksum != migration.Checksum {
				if m.client.logger != nil {
					m.client.logger.Warn("Migration checksum mismatch",
						"version", migration.Version,
						"name", migration.Name,
						"expected", migration.Checksum,
						"actual", appliedMig.Checksum,
					)
				}
			}
		} else {
			pending = append(pending, migration)
		}
	}

	if len(pending) == 0 {
		if m.client.logger != nil {
			m.client.logger.Info("No pending migrations")
		}
		return nil
	}

	// Execute pending migrations
	if m.client.logger != nil {
		m.client.logger.Info("Running pending migrations", "count", len(pending))
	}

	for i, migration := range pending {
		if m.dryRun {
			if m.client.logger != nil {
				m.client.logger.Info("[DRY RUN] Would apply migration",
					"version", migration.Version,
					"name", migration.Name,
					"progress", fmt.Sprintf("%d/%d", i+1, len(pending)),
				)
			}
			continue
		}

		if err := m.runMigration(ctx, migration, true); err != nil {
			return errors.Wrap(err, "POSTGRES_MIGRATION_FAILED", "Migration failed").
				WithField("version", migration.Version).
				WithField("name", migration.Name)
		}

		if m.client.logger != nil {
			m.client.logger.Info("Applied migration",
				"version", migration.Version,
				"name", migration.Name,
				"execution_time_ms", migration.ExecutionTimeMs,
				"progress", fmt.Sprintf("%d/%d", i+1, len(pending)),
			)
		}
	}

	return nil
}

// Rollback rolls back the specified number of migrations
func (m *Migrator) Rollback(ctx context.Context, steps int) error {
	if steps <= 0 {
		return nil
	}

	// Load migrations
	if err := m.LoadMigrations(ctx); err != nil {
		return err
	}

	// Acquire lock
	if err := m.acquireLock(ctx); err != nil {
		return err
	}
	defer m.releaseLock(ctx)

	// Get applied migrations
	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	// Find migrations to rollback (newest first)
	toRollback := make([]Migration, 0)
	for i := len(m.migrations) - 1; i >= 0 && len(toRollback) < steps; i-- {
		migration := m.migrations[i]
		if _, exists := applied[migration.Version]; exists {
			toRollback = append(toRollback, migration)
		}
	}

	if len(toRollback) == 0 {
		if m.client.logger != nil {
			m.client.logger.Info("No migrations to rollback")
		}
		return nil
	}

	// Execute rollbacks
	for i, migration := range toRollback {
		if m.dryRun {
			if m.client.logger != nil {
				m.client.logger.Info("[DRY RUN] Would rollback migration",
					"version", migration.Version,
					"name", migration.Name,
					"progress", fmt.Sprintf("%d/%d", i+1, len(toRollback)),
				)
			}
			continue
		}

		if err := m.runMigration(ctx, migration, false); err != nil {
			return errors.Wrap(err, "POSTGRES_ROLLBACK_FAILED", "Rollback failed").
				WithField("version", migration.Version).
				WithField("name", migration.Name)
		}

		if m.client.logger != nil {
			m.client.logger.Info("Rolled back migration",
				"version", migration.Version,
				"name", migration.Name,
				"progress", fmt.Sprintf("%d/%d", i+1, len(toRollback)),
			)
		}
	}

	return nil
}

// runMigration executes a single migration in a transaction
func (m *Migrator) runMigration(ctx context.Context, migration Migration, up bool) error {
	startTime := time.Now()

	err := m.client.BeginFunc(ctx, func(tx *Tx) error {
		// Execute SQL
		sql := migration.Up
		if !up {
			sql = migration.Down
		}

		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}

		// Update tracking table
		if up {
			executionTimeMs := time.Since(startTime).Milliseconds()
			_, err := tx.Exec(ctx, fmt.Sprintf(`
				INSERT INTO %s (version, name, checksum, execution_time_ms)
				VALUES ($1, $2, $3, $4)
			`, m.tableName), migration.Version, migration.Name, migration.Checksum, executionTimeMs)
			migration.ExecutionTimeMs = executionTimeMs
			return err
		} else {
			_, err := tx.Exec(ctx, fmt.Sprintf(`
				DELETE FROM %s WHERE version = $1
			`, m.tableName), migration.Version)
			return err
		}
	})

	return err
}

// ============================================================================
// Utility Methods
// ============================================================================

// Status returns the status of all migrations
func (m *Migrator) Status(ctx context.Context) ([]Migration, error) {
	if err := m.LoadMigrations(ctx); err != nil {
		return nil, err
	}

	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	// Populate Applied status
	for i := range m.migrations {
		if appliedMig, exists := applied[m.migrations[i].Version]; exists {
			m.migrations[i].Applied = true
			m.migrations[i].AppliedAt = appliedMig.AppliedAt
			m.migrations[i].ExecutionTimeMs = appliedMig.ExecutionTimeMs
		}
	}

	return m.migrations, nil
}
