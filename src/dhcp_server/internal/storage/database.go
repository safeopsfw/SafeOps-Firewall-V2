// Package storage provides database operations for the DHCP server.
// This file implements core database connection management and transaction handling.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

// ============================================================================
// Database Configuration
// ============================================================================

// DatabaseDriver specifies the database type.
type DatabaseDriver string

const (
	DriverPostgres DatabaseDriver = "postgres"
	DriverSQLite   DatabaseDriver = "sqlite"
)

// SSLMode for PostgreSQL connections.
type SSLMode string

const (
	SSLDisable    SSLMode = "disable"
	SSLRequire    SSLMode = "require"
	SSLVerifyCA   SSLMode = "verify-ca"
	SSLVerifyFull SSLMode = "verify-full"
)

// DatabaseConfig holds all database connection parameters.
type DatabaseConfig struct {
	Driver             DatabaseDriver
	Host               string
	Port               int
	Database           string
	Username           string
	Password           string
	SSLMode            SSLMode
	MaxOpenConns       int
	MaxIdleConns       int
	ConnMaxLifetime    time.Duration
	ConnMaxIdleTime    time.Duration
	QueryTimeout       time.Duration
	AutoMigrate        bool
	LogQueries         bool
	SlowQueryThreshold time.Duration
}

// DefaultDatabaseConfig returns sensible defaults.
func DefaultDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Driver:             DriverPostgres,
		Host:               "localhost",
		Port:               5432,
		Database:           "dhcp_server",
		SSLMode:            SSLRequire,
		MaxOpenConns:       25,
		MaxIdleConns:       5,
		ConnMaxLifetime:    time.Hour,
		ConnMaxIdleTime:    15 * time.Minute,
		QueryTimeout:       30 * time.Second,
		AutoMigrate:        false,
		LogQueries:         false,
		SlowQueryThreshold: time.Second,
	}
}

// LoadFromEnv loads configuration from environment variables.
func (c *DatabaseConfig) LoadFromEnv() {
	if host := os.Getenv("DB_HOST"); host != "" {
		c.Host = host
	}
	if port := os.Getenv("DB_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			c.Port = p
		}
	}
	if name := os.Getenv("DB_NAME"); name != "" {
		c.Database = name
	}
	if user := os.Getenv("DB_USER"); user != "" {
		c.Username = user
	}
	if pass := os.Getenv("DB_PASSWORD"); pass != "" {
		c.Password = pass
	}
	if driver := os.Getenv("DB_DRIVER"); driver != "" {
		c.Driver = DatabaseDriver(driver)
	}
	if ssl := os.Getenv("DB_SSL_MODE"); ssl != "" {
		c.SSLMode = SSLMode(ssl)
	}
	if maxOpen := os.Getenv("DB_MAX_OPEN_CONNS"); maxOpen != "" {
		if n, err := strconv.Atoi(maxOpen); err == nil {
			c.MaxOpenConns = n
		}
	}
	if maxIdle := os.Getenv("DB_MAX_IDLE_CONNS"); maxIdle != "" {
		if n, err := strconv.Atoi(maxIdle); err == nil {
			c.MaxIdleConns = n
		}
	}
	if os.Getenv("DB_AUTO_MIGRATE") == "true" {
		c.AutoMigrate = true
	}
	if os.Getenv("DB_LOG_QUERIES") == "true" {
		c.LogQueries = true
	}
}

// BuildConnectionString creates the database DSN.
func (c *DatabaseConfig) BuildConnectionString() string {
	switch c.Driver {
	case DriverPostgres:
		return fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			c.Host, c.Port, c.Username, c.Password, c.Database, c.SSLMode,
		)
	case DriverSQLite:
		return c.Database
	default:
		return ""
	}
}

// ============================================================================
// Database Manager
// ============================================================================

// Database represents the database connection manager.
type Database struct {
	mu     sync.RWMutex
	db     *sql.DB
	config *DatabaseConfig

	// Health tracking
	healthy     bool
	lastHealthy time.Time

	// Statistics
	queryCount  int64
	errorCount  int64
	slowQueries int64
}

// NewDatabase creates a new database manager.
func NewDatabase(config *DatabaseConfig) *Database {
	if config == nil {
		config = DefaultDatabaseConfig()
	}
	return &Database{
		config:  config,
		healthy: false,
	}
}

// ============================================================================
// Connection Management
// ============================================================================

// Connect establishes the database connection.
func (d *Database) Connect(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	dsn := d.config.BuildConnectionString()
	driverName := string(d.config.Driver)
	if d.config.Driver == DriverPostgres {
		driverName = "pgx" // or "postgres" depending on driver
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure pool
	db.SetMaxOpenConns(d.config.MaxOpenConns)
	db.SetMaxIdleConns(d.config.MaxIdleConns)
	db.SetConnMaxLifetime(d.config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(d.config.ConnMaxIdleTime)

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	d.db = db
	d.healthy = true
	d.lastHealthy = time.Now()

	// Run migrations if enabled
	if d.config.AutoMigrate {
		mgr := NewMigrationManager(db, DefaultMigrationConfig())
		if err := mgr.ApplyAllPending(ctx); err != nil {
			return fmt.Errorf("failed to apply migrations: %w", err)
		}
	}

	return nil
}

// Close gracefully closes the database connection.
func (d *Database) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.db == nil {
		return nil
	}

	err := d.db.Close()
	d.db = nil
	d.healthy = false
	return err
}

// DB returns the underlying sql.DB.
func (d *Database) DB() *sql.DB {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.db
}

// IsConnected returns true if database is connected.
func (d *Database) IsConnected() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.db != nil && d.healthy
}

// ============================================================================
// Health Checking
// ============================================================================

// Ping checks database connectivity.
func (d *Database) Ping(ctx context.Context) error {
	d.mu.RLock()
	db := d.db
	d.mu.RUnlock()

	if db == nil {
		return ErrNotConnected
	}

	err := db.PingContext(ctx)

	d.mu.Lock()
	if err != nil {
		d.healthy = false
	} else {
		d.healthy = true
		d.lastHealthy = time.Now()
	}
	d.mu.Unlock()

	return err
}

// HealthCheck performs comprehensive health check.
func (d *Database) HealthCheck(ctx context.Context) error {
	if err := d.Ping(ctx); err != nil {
		return err
	}

	// Execute test query
	var result int
	err := d.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("health check query failed: %w", err)
	}

	return nil
}

// GetPoolStats returns connection pool statistics.
func (d *Database) GetPoolStats() sql.DBStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.db == nil {
		return sql.DBStats{}
	}
	return d.db.Stats()
}

// ============================================================================
// Transaction Management
// ============================================================================

// TxContext wraps a transaction with metadata.
type TxContext struct {
	Tx        *sql.Tx
	StartTime time.Time
	ReadOnly  bool
}

// BeginTx starts a new transaction.
func (d *Database) BeginTx(ctx context.Context, opts *sql.TxOptions) (*TxContext, error) {
	d.mu.RLock()
	db := d.db
	d.mu.RUnlock()

	if db == nil {
		return nil, ErrNotConnected
	}

	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &TxContext{
		Tx:        tx,
		StartTime: time.Now(),
		ReadOnly:  opts != nil && opts.ReadOnly,
	}, nil
}

// WithTransaction executes a function within a transaction.
func (d *Database) WithTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
	txCtx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			txCtx.Tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(txCtx.Tx); err != nil {
		txCtx.Tx.Rollback()
		return err
	}

	return txCtx.Tx.Commit()
}

// WithReadOnlyTransaction executes read-only function in transaction.
func (d *Database) WithReadOnlyTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
	txCtx, err := d.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}

	defer txCtx.Tx.Rollback()

	if err := fn(txCtx.Tx); err != nil {
		return err
	}

	return txCtx.Tx.Commit()
}

// ============================================================================
// Query Execution
// ============================================================================

// Query executes a query returning multiple rows.
func (d *Database) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	d.mu.RLock()
	db := d.db
	d.mu.RUnlock()

	if db == nil {
		return nil, ErrNotConnected
	}

	start := time.Now()
	rows, err := db.QueryContext(ctx, query, args...)
	d.recordQuery(query, time.Since(start), err)

	return rows, err
}

// QueryRow executes a query returning a single row.
func (d *Database) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	d.mu.RLock()
	db := d.db
	d.mu.RUnlock()

	if db == nil {
		return nil
	}

	start := time.Now()
	row := db.QueryRowContext(ctx, query, args...)
	d.recordQuery(query, time.Since(start), nil)

	return row
}

// Exec executes a query without returning rows.
func (d *Database) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	d.mu.RLock()
	db := d.db
	d.mu.RUnlock()

	if db == nil {
		return nil, ErrNotConnected
	}

	start := time.Now()
	result, err := db.ExecContext(ctx, query, args...)
	d.recordQuery(query, time.Since(start), err)

	return result, err
}

// recordQuery records query execution metrics.
func (d *Database) recordQuery(_ string, duration time.Duration, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.queryCount++
	if err != nil {
		d.errorCount++
	}
	if duration > d.config.SlowQueryThreshold {
		d.slowQueries++
	}
}

// ============================================================================
// Error Classification
// ============================================================================

// IsRetryableError checks if error is transient and can be retried.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"too many connections",
		"deadlock",
		"serialization failure",
	}

	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// IsConnectionError identifies connection-related failures.
func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNotConnected) {
		return true
	}

	errStr := err.Error()
	connectionPatterns := []string{
		"connection refused",
		"connection reset",
		"no such host",
		"network unreachable",
		"connection timed out",
	}

	for _, pattern := range connectionPatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// IsConstraintViolation detects unique/foreign key errors.
func IsConstraintViolation(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	patterns := []string{
		"duplicate key",
		"unique constraint",
		"foreign key",
		"UNIQUE constraint failed",
		"FOREIGN KEY constraint failed",
	}

	for _, pattern := range patterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ============================================================================
// Query Statistics
// ============================================================================

// QueryStats holds query execution statistics.
type QueryStats struct {
	TotalQueries int64
	ErrorCount   int64
	SlowQueries  int64
}

// GetQueryStats returns query statistics.
func (d *Database) GetQueryStats() QueryStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return QueryStats{
		TotalQueries: d.queryCount,
		ErrorCount:   d.errorCount,
		SlowQueries:  d.slowQueries,
	}
}

// ResetStats resets query statistics.
func (d *Database) ResetStats() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.queryCount = 0
	d.errorCount = 0
	d.slowQueries = 0
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrNotConnected is returned when database is not connected
	ErrNotConnected = errors.New("database not connected")

	// ErrTransactionFailed is returned when transaction fails
	ErrTransactionFailed = errors.New("transaction failed")

	// ErrQueryTimeout is returned when query times out
	ErrQueryTimeout = errors.New("query timeout")
)
