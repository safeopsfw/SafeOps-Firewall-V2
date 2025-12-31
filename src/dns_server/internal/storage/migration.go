// Package storage provides database migration for the DNS server.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ============================================================================
// Migration Constants
// ============================================================================

const (
	MigrationVersion  = 15
	ComponentName     = "dns_server"
	DefaultSchemaFile = "database/schemas/015_dns_server.sql"
)

// ============================================================================
// Migration Type
// ============================================================================

// Migration handles database schema migrations
type Migration struct {
	db         *Database
	schemaPath string
	version    int
}

// NewMigration creates a new migration handler
func NewMigration(db *Database) *Migration {
	return &Migration{
		db:         db,
		schemaPath: resolveSchemaPath(),
		version:    MigrationVersion,
	}
}

// ============================================================================
// Public API
// ============================================================================

// RunMigrations executes migrations if needed
func RunMigrations(ctx context.Context, db *Database) error {
	m := NewMigration(db)
	return m.Run(ctx)
}

// Run executes the migration
func (m *Migration) Run(ctx context.Context) error {
	log.Printf("Starting database migration check for %s", ComponentName)

	// Ensure migrations table exists
	if err := m.createMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Check current version
	currentVersion, err := m.getCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Already up to date
	if currentVersion == m.version {
		log.Printf("Schema is up to date (version %d)", currentVersion)
		return nil
	}

	// Prevent downgrades
	if currentVersion > m.version {
		return fmt.Errorf("downgrade not supported: current=%d, target=%d", currentVersion, m.version)
	}

	log.Printf("Migrating schema from version %d to %d", currentVersion, m.version)

	// Check if schema already exists (tables present but not tracked)
	exists, err := m.schemaExists(ctx)
	if err != nil {
		return err
	}

	if exists && currentVersion == 0 {
		// Tables exist but not tracked - just update version
		log.Printf("Schema already exists, updating version tracking")
		return m.updateVersionDirect(ctx, m.version)
	}

	// Read and execute schema file
	sqlContent, err := m.readSchemaFile()
	if err != nil {
		return fmt.Errorf("failed to read schema file: %w", err)
	}

	// Parse into statements
	statements := m.parseStatements(sqlContent)
	log.Printf("Parsed %d SQL statements from schema file", len(statements))

	// Execute in transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute each statement
	for i, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute statement %d: %w\nStatement: %s", i+1, err, truncate(stmt, 200))
		}
	}

	// Update version
	if err := m.updateVersion(ctx, tx, m.version); err != nil {
		return fmt.Errorf("failed to update version: %w", err)
	}

	// Commit
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	log.Printf("Migration complete: version %d applied successfully", m.version)
	return nil
}

// ============================================================================
// Version Management
// ============================================================================

func (m *Migration) getCurrentVersion(ctx context.Context) (int, error) {
	var version int
	err := m.db.QueryRow(ctx,
		`SELECT version FROM schema_migrations WHERE component = $1`,
		ComponentName,
	).Scan(&version)

	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return version, nil
}

func (m *Migration) createMigrationsTable(ctx context.Context) error {
	_, err := m.db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			component VARCHAR(100) PRIMARY KEY,
			version INTEGER NOT NULL,
			applied_at TIMESTAMPTZ DEFAULT NOW()
		)
	`)
	return err
}

func (m *Migration) updateVersion(ctx context.Context, tx *sql.Tx, version int) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO schema_migrations (component, version, applied_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (component) DO UPDATE SET version = $2, applied_at = NOW()
	`, ComponentName, version)
	return err
}

func (m *Migration) updateVersionDirect(ctx context.Context, version int) error {
	_, err := m.db.Exec(ctx, `
		INSERT INTO schema_migrations (component, version, applied_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (component) DO UPDATE SET version = $2, applied_at = NOW()
	`, ComponentName, version)
	return err
}

// ============================================================================
// Schema Existence Check
// ============================================================================

func (m *Migration) schemaExists(ctx context.Context) (bool, error) {
	var exists bool
	err := m.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' AND table_name = 'dns_zones'
		)
	`).Scan(&exists)
	return exists, err
}

// ============================================================================
// Schema File Operations
// ============================================================================

func (m *Migration) readSchemaFile() (string, error) {
	content, err := os.ReadFile(m.schemaPath)
	if err != nil {
		return "", fmt.Errorf("cannot read schema file %s: %w", m.schemaPath, err)
	}
	return string(content), nil
}

func (m *Migration) parseStatements(sqlContent string) []string {
	// Remove single-line comments
	lines := strings.Split(sqlContent, "\n")
	var cleanLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "--") {
			cleanLines = append(cleanLines, line)
		}
	}
	sqlContent = strings.Join(cleanLines, "\n")

	// Split on semicolons
	parts := strings.Split(sqlContent, ";")

	var statements []string
	for _, part := range parts {
		stmt := strings.TrimSpace(part)
		if stmt != "" && !strings.HasPrefix(stmt, "--") {
			statements = append(statements, stmt)
		}
	}
	return statements
}

// ============================================================================
// Path Resolution
// ============================================================================

func resolveSchemaPath() string {
	// Try relative to current directory
	if _, err := os.Stat(DefaultSchemaFile); err == nil {
		abs, _ := filepath.Abs(DefaultSchemaFile)
		return abs
	}

	// Try relative to executable
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		path := filepath.Join(exeDir, DefaultSchemaFile)
		if _, err := os.Stat(path); err == nil {
			return path
		}
		path = filepath.Join(exeDir, "..", DefaultSchemaFile)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Check environment variable
	if envPath := os.Getenv("SCHEMA_PATH"); envPath != "" {
		return envPath
	}

	return DefaultSchemaFile
}

// ============================================================================
// Helpers
// ============================================================================

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
