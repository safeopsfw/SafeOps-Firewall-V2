// Package storage provides database connection and storage operations for the DNS server.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// ============================================================================
// Singleton Pattern
// ============================================================================

var (
	dbInstance *Database
	dbMutex    sync.Mutex
)

// ============================================================================
// Database Wrapper
// ============================================================================

// Database wraps the SQL connection pool with DNS-specific methods
type Database struct {
	pool   *sql.DB
	config *DatabaseConfig
}

// DatabaseConfig holds PostgreSQL connection parameters
type DatabaseConfig struct {
	Host              string
	Port              int
	Database          string
	Username          string
	Password          string
	SSLMode           string
	MaxConnections    int
	MinConnections    int
	ConnectionTimeout time.Duration
}

// ============================================================================
// Initialization
// ============================================================================

// InitDatabase creates the database connection pool
func InitDatabase(cfg *DatabaseConfig) (*Database, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if dbInstance != nil {
		return dbInstance, nil
	}

	// Build connection string
	connStr := buildConnectionString(cfg)

	// Open database connection
	pool, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	pool.SetMaxOpenConns(cfg.MaxConnections)
	if cfg.MinConnections > 0 {
		pool.SetMaxIdleConns(cfg.MinConnections)
	} else {
		pool.SetMaxIdleConns(5)
	}
	pool.SetConnMaxLifetime(time.Hour)
	pool.SetConnMaxIdleTime(30 * time.Minute)

	// Validate connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectionTimeout)
	defer cancel()

	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Store instance
	dbInstance = &Database{
		pool:   pool,
		config: cfg,
	}

	log.Printf("Database connection established: %s@%s:%d/%s",
		cfg.Username, cfg.Host, cfg.Port, cfg.Database)

	return dbInstance, nil
}

// MustInitDatabase initializes database and panics on error
func MustInitDatabase(cfg *DatabaseConfig) *Database {
	db, err := InitDatabase(cfg)
	if err != nil {
		panic(fmt.Sprintf("Fatal: Failed to initialize database: %v", err))
	}
	return db
}

// GetDatabase returns the singleton database instance
func GetDatabase() *Database {
	if dbInstance == nil {
		panic("Database not initialized - call InitDatabase first")
	}
	return dbInstance
}

// ============================================================================
// Database Methods
// ============================================================================

// GetPool returns the underlying SQL connection pool
func (d *Database) GetPool() *sql.DB {
	return d.pool
}

// Ping verifies database connectivity
func (d *Database) Ping(ctx context.Context) error {
	return d.pool.PingContext(ctx)
}

// Close gracefully shuts down the connection pool
func (d *Database) Close() error {
	if d.pool != nil {
		log.Printf("Closing database connection pool")
		return d.pool.Close()
	}
	return nil
}

// Stats returns connection pool statistics
func (d *Database) Stats() sql.DBStats {
	return d.pool.Stats()
}

// ============================================================================
// Query Helpers
// ============================================================================

// QueryRow executes a query returning a single row
func (d *Database) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return d.pool.QueryRowContext(ctx, query, args...)
}

// Query executes a query returning multiple rows
func (d *Database) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return d.pool.QueryContext(ctx, query, args...)
}

// Exec executes a statement without returning rows
func (d *Database) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return d.pool.ExecContext(ctx, query, args...)
}

// BeginTx starts a new transaction
func (d *Database) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return d.pool.BeginTx(ctx, opts)
}

// ============================================================================
// Connection String Builder
// ============================================================================

func buildConnectionString(cfg *DatabaseConfig) string {
	sslMode := cfg.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}

	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=10",
		cfg.Host,
		cfg.Port,
		cfg.Username,
		cfg.Password,
		cfg.Database,
		sslMode,
	)
}

// ============================================================================
// Schema Validation
// ============================================================================

// ValidateSchema checks if required tables exist
func (d *Database) ValidateSchema(ctx context.Context) error {
	requiredTables := []string{
		"dns_zones",
		"dns_soa",
		"dns_records",
		"dns_blocklist",
		"dns_allowlist",
		"dns_query_stats",
	}

	for _, table := range requiredTables {
		var exists bool
		query := `SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' AND table_name = $1
		)`
		if err := d.pool.QueryRowContext(ctx, query, table).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check table %s: %w", table, err)
		}
		if !exists {
			return fmt.Errorf("required table %s does not exist - run migrations", table)
		}
	}

	log.Printf("Schema validation passed: all required tables exist")
	return nil
}

// ============================================================================
// Health Check
// ============================================================================

// HealthCheck performs a comprehensive health check
func (d *Database) HealthCheck(ctx context.Context) error {
	// Ping the database
	if err := d.Ping(ctx); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Check connection pool health
	stats := d.Stats()
	if stats.OpenConnections == 0 {
		return fmt.Errorf("no open connections in pool")
	}

	return nil
}

// ============================================================================
// Default Configuration
// ============================================================================

// DefaultDatabaseConfig returns default database configuration
func DefaultDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Host:              "localhost",
		Port:              5432,
		Database:          "safeops_network",
		Username:          "dns_server",
		Password:          "",
		SSLMode:           "disable",
		MaxConnections:    20,
		MinConnections:    5,
		ConnectionTimeout: 10 * time.Second,
	}
}
