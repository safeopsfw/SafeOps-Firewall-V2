package threatintel

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"firewall_engine/internal/config"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// DB wraps a connection pool to the threat_intel_db
type DB struct {
	pool   *sql.DB
	config config.DatabaseConfig
}

// NewDB creates a new threat intel database connection pool
func NewDB(cfg config.DatabaseConfig) (*DB, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to open threat_intel_db: %w", err)
	}

	db.SetMaxOpenConns(cfg.PoolSize)
	db.SetMaxIdleConns(cfg.PoolSize / 2)
	if cfg.PoolSize/2 < 2 {
		db.SetMaxIdleConns(2)
	}
	db.SetConnMaxLifetime(time.Duration(cfg.PoolMaxLifetimeMinutes) * time.Minute)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("threat_intel_db ping failed: %w", err)
	}

	return &DB{pool: db, config: cfg}, nil
}

// Pool returns the underlying *sql.DB for direct queries
func (d *DB) Pool() *sql.DB {
	return d.pool
}

// Ping checks database connectivity
func (d *DB) Ping(ctx context.Context) error {
	return d.pool.PingContext(ctx)
}

// Close closes the connection pool
func (d *DB) Close() error {
	if d.pool != nil {
		return d.pool.Close()
	}
	return nil
}

// Stats returns connection pool statistics
func (d *DB) Stats() sql.DBStats {
	return d.pool.Stats()
}
