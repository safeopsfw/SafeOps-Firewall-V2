// Package postgres provides database migration utilities.
package postgres

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Migration represents a database migration
type Migration struct {
	Version     int
	Description string
	Up          string
	Down        string
}

// Migrator handles database migrations
type Migrator struct {
	pool       *Pool
	tableName  string
	migrations []Migration
}

// NewMigrator creates a new migrator
func NewMigrator(pool *Pool) *Migrator {
	return &Migrator{
		pool:       pool,
		tableName:  "schema_migrations",
		migrations: make([]Migration, 0),
	}
}

// WithTableName sets the migrations table name
func (m *Migrator) WithTableName(name string) *Migrator {
	m.tableName = name
	return m
}

// Add adds a migration
func (m *Migrator) Add(migration Migration) *Migrator {
	m.migrations = append(m.migrations, migration)
	return m
}

// AddMany adds multiple migrations
func (m *Migrator) AddMany(migrations ...Migration) *Migrator {
	m.migrations = append(m.migrations, migrations...)
	return m
}

// Initialize creates the migrations table
func (m *Migrator) Initialize(ctx context.Context) error {
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`, m.tableName)

	_, err := m.pool.Pool.Exec(ctx, query)
	return err
}

// CurrentVersion returns the current schema version
func (m *Migrator) CurrentVersion(ctx context.Context) (int, error) {
	var version int
	query := fmt.Sprintf("SELECT COALESCE(MAX(version), 0) FROM %s", m.tableName)
	err := m.pool.Pool.QueryRow(ctx, query).Scan(&version)
	return version, err
}

// AppliedMigrations returns list of applied migrations
func (m *Migrator) AppliedMigrations(ctx context.Context) ([]int, error) {
	query := fmt.Sprintf("SELECT version FROM %s ORDER BY version", m.tableName)
	rows, err := m.pool.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}

	return versions, rows.Err()
}

// Up runs all pending migrations
func (m *Migrator) Up(ctx context.Context) error {
	if err := m.Initialize(ctx); err != nil {
		return err
	}

	current, err := m.CurrentVersion(ctx)
	if err != nil {
		return err
	}

	// Sort migrations by version
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})

	for _, migration := range m.migrations {
		if migration.Version <= current {
			continue
		}

		if err := m.runMigration(ctx, migration, true); err != nil {
			return fmt.Errorf("migration %d failed: %w", migration.Version, err)
		}
	}

	return nil
}

// UpTo runs migrations up to a specific version
func (m *Migrator) UpTo(ctx context.Context, targetVersion int) error {
	if err := m.Initialize(ctx); err != nil {
		return err
	}

	current, err := m.CurrentVersion(ctx)
	if err != nil {
		return err
	}

	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})

	for _, migration := range m.migrations {
		if migration.Version <= current || migration.Version > targetVersion {
			continue
		}

		if err := m.runMigration(ctx, migration, true); err != nil {
			return fmt.Errorf("migration %d failed: %w", migration.Version, err)
		}
	}

	return nil
}

// Down rolls back the last migration
func (m *Migrator) Down(ctx context.Context) error {
	current, err := m.CurrentVersion(ctx)
	if err != nil {
		return err
	}

	if current == 0 {
		return nil
	}

	// Find the migration to rollback
	for _, migration := range m.migrations {
		if migration.Version == current {
			return m.runMigration(ctx, migration, false)
		}
	}

	return fmt.Errorf("migration %d not found", current)
}

// DownTo rolls back to a specific version
func (m *Migrator) DownTo(ctx context.Context, targetVersion int) error {
	current, err := m.CurrentVersion(ctx)
	if err != nil {
		return err
	}

	// Sort migrations by version descending
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version > m.migrations[j].Version
	})

	for _, migration := range m.migrations {
		if migration.Version <= targetVersion || migration.Version > current {
			continue
		}

		if err := m.runMigration(ctx, migration, false); err != nil {
			return fmt.Errorf("rollback %d failed: %w", migration.Version, err)
		}
	}

	return nil
}

// Reset rolls back all migrations and re-applies them
func (m *Migrator) Reset(ctx context.Context) error {
	if err := m.DownTo(ctx, 0); err != nil {
		return err
	}
	return m.Up(ctx)
}

// runMigration runs a single migration
func (m *Migrator) runMigration(ctx context.Context, migration Migration, up bool) error {
	tx, err := m.pool.BeginTx(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(ctx)
			panic(p)
		}
	}()

	var query string
	if up {
		query = migration.Up
	} else {
		query = migration.Down
	}

	if _, err := tx.Exec(ctx, query); err != nil {
		tx.Rollback(ctx)
		return err
	}

	if up {
		_, err = tx.Exec(ctx, fmt.Sprintf(
			"INSERT INTO %s (version, description) VALUES ($1, $2)",
			m.tableName,
		), migration.Version, migration.Description)
	} else {
		_, err = tx.Exec(ctx, fmt.Sprintf(
			"DELETE FROM %s WHERE version = $1",
			m.tableName,
		), migration.Version)
	}

	if err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

// Status returns migration status
type MigrationStatus struct {
	Version     int
	Description string
	Applied     bool
	AppliedAt   *time.Time
}

// Status returns the status of all migrations
func (m *Migrator) Status(ctx context.Context) ([]MigrationStatus, error) {
	applied, err := m.AppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	appliedSet := make(map[int]bool)
	for _, v := range applied {
		appliedSet[v] = true
	}

	var statuses []MigrationStatus
	for _, migration := range m.migrations {
		statuses = append(statuses, MigrationStatus{
			Version:     migration.Version,
			Description: migration.Description,
			Applied:     appliedSet[migration.Version],
		})
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Version < statuses[j].Version
	})

	return statuses, nil
}
