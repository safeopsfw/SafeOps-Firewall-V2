// Package postgres provides PostgreSQL connection utilities.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds PostgreSQL configuration
type Config struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		Host:            "localhost",
		Port:            5432,
		User:            "postgres",
		Database:        "safeops",
		SSLMode:         "disable",
		MaxConns:        25,
		MinConns:        5,
		MaxConnLifetime: time.Hour,
		MaxConnIdleTime: 30 * time.Minute,
	}
}

// DSN returns the connection string
func (c Config) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// Pool wraps pgxpool.Pool with additional functionality
type Pool struct {
	*pgxpool.Pool
	cfg Config
}

// NewPool creates a new connection pool
func NewPool(ctx context.Context, cfg Config) (*Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	}

	return &Pool{
		Pool: pool,
		cfg:  cfg,
	}, nil
}

// Ping checks the connection
func (p *Pool) Ping(ctx context.Context) error {
	return p.Pool.Ping(ctx)
}

// IsConnected returns true if connected
func (p *Pool) IsConnected(ctx context.Context) bool {
	return p.Ping(ctx) == nil
}

// HealthCheck performs a health check
func (p *Pool) HealthCheck(ctx context.Context) error {
	var result int
	err := p.Pool.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("unexpected result: %d", result)
	}
	return nil
}

// Stats returns pool statistics
func (p *Pool) Stats() *pgxpool.Stat {
	return p.Pool.Stat()
}

// Query helpers

// QueryOne queries and scans a single row
func QueryOne[T any](ctx context.Context, p *Pool, query string, args ...interface{}) (T, error) {
	var result T
	err := p.Pool.QueryRow(ctx, query, args...).Scan(&result)
	return result, err
}

// QueryMany queries and returns multiple rows
func QueryMany[T any](ctx context.Context, p *Pool, query string, scanner func(pgx.Rows) (T, error), args ...interface{}) ([]T, error) {
	rows, err := p.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []T
	for rows.Next() {
		result, err := scanner(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, rows.Err()
}

// Exec executes a query without returning rows
func (p *Pool) Exec(ctx context.Context, query string, args ...interface{}) (int64, error) {
	result, err := p.Pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// ExecMany executes multiple queries
func (p *Pool) ExecMany(ctx context.Context, queries []string) error {
	for _, query := range queries {
		if _, err := p.Pool.Exec(ctx, query); err != nil {
			return err
		}
	}
	return nil
}

// Conn gets a single connection from the pool
func (p *Pool) Conn(ctx context.Context) (*pgxpool.Conn, error) {
	return p.Pool.Acquire(ctx)
}

// Close closes the pool
func (p *Pool) Close() {
	p.Pool.Close()
}

// TableExists checks if a table exists
func (p *Pool) TableExists(ctx context.Context, tableName string) (bool, error) {
	var exists bool
	err := p.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public'
			AND table_name = $1
		)
	`, tableName).Scan(&exists)
	return exists, err
}

// ColumnExists checks if a column exists
func (p *Pool) ColumnExists(ctx context.Context, tableName, columnName string) (bool, error) {
	var exists bool
	err := p.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_schema = 'public'
			AND table_name = $1
			AND column_name = $2
		)
	`, tableName, columnName).Scan(&exists)
	return exists, err
}

// CurrentDatabase returns current database name
func (p *Pool) CurrentDatabase(ctx context.Context) (string, error) {
	var name string
	err := p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&name)
	return name, err
}

// ServerVersion returns PostgreSQL version
func (p *Pool) ServerVersion(ctx context.Context) (string, error) {
	var version string
	err := p.Pool.QueryRow(ctx, "SELECT version()").Scan(&version)
	return version, err
}
