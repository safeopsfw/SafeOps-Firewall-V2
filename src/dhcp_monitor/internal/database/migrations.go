// Package database provides automatic schema migrations
package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Migration represents a single database migration
type Migration struct {
	Version     int
	Description string
	SQL         string
	Checksum    string
}

// createMigrationsTable ensures the schema_migrations table exists
func (c *DatabaseClient) createMigrationsTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			description TEXT,
			checksum VARCHAR(64)
		)`

	_, err := c.DB.ExecContext(ctx, query)
	return err
}

// GetAppliedMigrations returns map of applied migration versions
func (c *DatabaseClient) GetAppliedMigrations(ctx context.Context) (map[int]bool, error) {
	if err := c.createMigrationsTable(ctx); err != nil {
		return nil, fmt.Errorf("create migrations table: %w", err)
	}

	query := `SELECT version FROM schema_migrations ORDER BY version`
	rows, err := c.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}

	return applied, nil
}

// loadMigrationsFromDir reads SQL files from a directory
func loadMigrationsFromDir(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	var migrations []Migration

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		// Parse version from filename (e.g., "020_dhcp_monitor.sql" -> 20)
		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) < 2 {
			continue
		}

		version, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		// Read SQL content
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		// Calculate checksum
		hash := sha256.Sum256(content)
		checksum := hex.EncodeToString(hash[:])

		migrations = append(migrations, Migration{
			Version:     version,
			Description: strings.TrimSuffix(parts[1], ".sql"),
			SQL:         string(content),
			Checksum:    checksum,
		})
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// ApplyMigration executes a single migration in a transaction
func (c *DatabaseClient) ApplyMigration(ctx context.Context, m Migration) error {
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute migration SQL
	_, err = tx.ExecContext(ctx, m.SQL)
	if err != nil {
		return fmt.Errorf("execute migration %d: %w", m.Version, err)
	}

	// Record migration
	recordQuery := `
		INSERT INTO schema_migrations (version, description, checksum)
		VALUES ($1, $2, $3)
		ON CONFLICT (version) DO NOTHING`

	_, err = tx.ExecContext(ctx, recordQuery, m.Version, m.Description, m.Checksum)
	if err != nil {
		return fmt.Errorf("record migration %d: %w", m.Version, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", m.Version, err)
	}

	return nil
}

// RunMigrations applies all pending migrations from a directory
func (c *DatabaseClient) RunMigrations(ctx context.Context, migrationsDir string) error {
	log.Println("[MIGRATIONS] Checking for pending migrations...")

	migrations, err := loadMigrationsFromDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}

	if len(migrations) == 0 {
		log.Println("[MIGRATIONS] No migration files found")
		return nil
	}

	applied, err := c.GetAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("get applied migrations: %w", err)
	}

	pendingCount := 0
	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}

		log.Printf("[MIGRATIONS] Applying migration %d: %s", m.Version, m.Description)

		if err := c.ApplyMigration(ctx, m); err != nil {
			return fmt.Errorf("apply migration %d: %w", m.Version, err)
		}

		log.Printf("[MIGRATIONS] ✓ Migration %d applied successfully", m.Version)
		pendingCount++
	}

	if pendingCount == 0 {
		log.Println("[MIGRATIONS] All migrations already applied")
	} else {
		log.Printf("[MIGRATIONS] Applied %d migrations", pendingCount)
	}

	return nil
}

// ValidateSchema checks if database schema version matches expected
func (c *DatabaseClient) ValidateSchema(ctx context.Context, expectedVersion int) error {
	query := `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`

	var currentVersion int
	err := c.DB.QueryRowContext(ctx, query).Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("query schema version: %w", err)
	}

	if currentVersion < expectedVersion {
		return fmt.Errorf("schema version %d is behind expected %d - run migrations",
			currentVersion, expectedVersion)
	}

	if currentVersion > expectedVersion {
		log.Printf("[MIGRATIONS] Warning: database schema %d is ahead of code %d",
			currentVersion, expectedVersion)
	}

	return nil
}
