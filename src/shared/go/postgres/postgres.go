// Package postgres provides PostgreSQL connection pool manager using pgx driver.
package postgres

import (
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/safeops/shared/go/errors"
	"github.com/safeops/shared/go/logging"
	"github.com/safeops/shared/go/metrics"
)

// ============================================================================
// Configuration
// ============================================================================

// Config holds PostgreSQL configuration
type Config struct {
	// Connection settings
	Host     string
	Port     int
	Database string
	User     string
	Password string

	// SSL/TLS settings
	SSLMode     string // disable, allow, prefer, require, verify-ca, verify-full
	SSLCert     string // Client certificate path
	SSLKey      string // Client key path
	SSLRootCert string // CA certificate path

	// Pool settings
	MaxOpenConns    int32         // Maximum open connections (default: 25)
	MaxIdleConns    int32         // Maximum idle connections (default: 5)
	MaxConnLifetime time.Duration // Maximum connection lifetime (default: 1h)
	MaxConnIdleTime time.Duration // Maximum idle time (default: 15m)

	// Timeout settings
	ConnectTimeout   time.Duration // Connection timeout (default: 10s)
	StatementTimeout time.Duration // Query timeout (default: 30s)

	// Health check settings
	HealthCheckPeriod time.Duration // Health check interval (default: 30s)
}

// DefaultConfig returns default PostgreSQL configuration
func DefaultConfig() Config {
	return Config{
		Host:              "localhost",
		Port:              5432,
		Database:          "safeops",
		User:              "postgres",
		SSLMode:           "require",
		MaxOpenConns:      25,
		MaxIdleConns:      5,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   15 * time.Minute,
		ConnectTimeout:    10 * time.Second,
		StatementTimeout:  30 * time.Second,
		HealthCheckPeriod: 30 * time.Second,
	}
}

// DSN returns the PostgreSQL connection string
// Note: Password is included but will be sanitized in error messages
func (c Config) DSN() string {
	// Build base connection string
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)

	// Add SSL certificate paths if provided
	if c.SSLCert != "" {
		dsn += fmt.Sprintf(" sslcert=%s", c.SSLCert)
	}
	if c.SSLKey != "" {
		dsn += fmt.Sprintf(" sslkey=%s", c.SSLKey)
	}
	if c.SSLRootCert != "" {
		dsn += fmt.Sprintf(" sslrootcert=%s", c.SSLRootCert)
	}

	// Add timeouts
	if c.ConnectTimeout > 0 {
		dsn += fmt.Sprintf(" connect_timeout=%d", int(c.ConnectTimeout.Seconds()))
	}
	if c.StatementTimeout > 0 {
		dsn += fmt.Sprintf(" statement_timeout=%d", int(c.StatementTimeout.Milliseconds()))
	}

	return dsn
}

// SanitizeDSN returns DSN with password redacted for logging
func (c Config) SanitizeDSN() string {
	dsn := c.DSN()
	// Replace password with ***
	if c.Password != "" {
		dsn = strings.ReplaceAll(dsn, "password="+c.Password, "password=***")
	}
	return dsn
}

// ============================================================================
// Environment Variable Configuration
// ============================================================================

// NewConfigFromEnv creates configuration from environment variables
func NewConfigFromEnv() (Config, error) {
	cfg := DefaultConfig()

	// Host
	if host := os.Getenv("POSTGRES_HOST"); host != "" {
		cfg.Host = host
	}

	// Port
	if port := os.Getenv("POSTGRES_PORT"); port != "" {
		if val, err := strconv.Atoi(port); err == nil {
			cfg.Port = val
		}
	}

	// Database
	if db := os.Getenv("POSTGRES_DATABASE"); db != "" {
		cfg.Database = db
	}

	// User
	if user := os.Getenv("POSTGRES_USER"); user != "" {
		cfg.User = user
	}

	// Password
	if pass := os.Getenv("POSTGRES_PASSWORD"); pass != "" {
		cfg.Password = pass
	}

	// SSL Mode
	if sslMode := os.Getenv("POSTGRES_SSLMODE"); sslMode != "" {
		cfg.SSLMode = sslMode
	}

	// SSL Certificates
	cfg.SSLCert = os.Getenv("POSTGRES_SSL_CERT")
	cfg.SSLKey = os.Getenv("POSTGRES_SSL_KEY")
	cfg.SSLRootCert = os.Getenv("POSTGRES_SSL_ROOT_CERT")

	// Max open connections
	if maxConns := os.Getenv("POSTGRES_MAX_OPEN_CONNS"); maxConns != "" {
		if val, err := strconv.Atoi(maxConns); err == nil {
			cfg.MaxOpenConns = int32(val)
		}
	}

	// Max idle connections
	if maxIdle := os.Getenv("POSTGRES_MAX_IDLE_CONNS"); maxIdle != "" {
		if val, err := strconv.Atoi(maxIdle); err == nil {
			cfg.MaxIdleConns = int32(val)
		}
	}

	// Max connection lifetime (minutes)
	if lifetime := os.Getenv("POSTGRES_MAX_CONN_LIFETIME"); lifetime != "" {
		if val, err := strconv.Atoi(lifetime); err == nil {
			cfg.MaxConnLifetime = time.Duration(val) * time.Minute
		}
	}

	// Connect timeout (seconds)
	if timeout := os.Getenv("POSTGRES_CONNECT_TIMEOUT"); timeout != "" {
		if val, err := strconv.Atoi(timeout); err == nil {
			cfg.ConnectTimeout = time.Duration(val) * time.Second
		}
	}

	// Statement timeout (seconds)
	if timeout := os.Getenv("POSTGRES_STATEMENT_TIMEOUT"); timeout != "" {
		if val, err := strconv.Atoi(timeout); err == nil {
			cfg.StatementTimeout = time.Duration(val) * time.Second
		}
	}

	return cfg, nil
}

// ============================================================================
// PostgreSQL Client
// ============================================================================

// Client wraps pgxpool.Pool with additional functionality
type Client struct {
	pool    *pgxpool.Pool
	cfg     Config
	logger  *logging.Logger
	metrics *metrics.MetricsRegistry
}

// NewClient creates a new PostgreSQL client with connection pool
func NewClient(cfg Config) (*Client, error) {
	return NewClientWithContext(context.Background(), cfg)
}

// NewClientWithContext creates a client with custom context
func NewClientWithContext(ctx context.Context, cfg Config) (*Client, error) {
	// Parse connection string
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, errors.Wrap(err, "POSTGRES_CONFIG_PARSE_FAILED", "Failed to parse PostgreSQL configuration").
			WithField("host", cfg.Host).
			WithField("port", cfg.Port).
			WithField("database", cfg.Database)
	}

	// Configure pool settings
	poolConfig.MaxConns = cfg.MaxOpenConns
	poolConfig.MinConns = cfg.MaxIdleConns
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolConfig.HealthCheckPeriod = cfg.HealthCheckPeriod

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.Wrap(err, "POSTGRES_POOL_CREATE_FAILED", "Failed to create connection pool").
			WithField("dsn", cfg.SanitizeDSN())
	}

	// Test connectivity
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.Wrap(err, "POSTGRES_PING_FAILED", "Failed to ping PostgreSQL").
			WithField("host", cfg.Host).
			WithField("port", cfg.Port)
	}

	return &Client{
		pool: pool,
		cfg:  cfg,
	}, nil
}

// NewClientFromEnv creates a client from environment variables
func NewClientFromEnv() (*Client, error) {
	cfg, err := NewConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewClient(cfg)
}

// WithLogger attaches a logger to the client
func (c *Client) WithLogger(logger *logging.Logger) *Client {
	c.logger = logger
	return c
}

// WithMetrics attaches a metrics registry to the client
func (c *Client) WithMetrics(m *metrics.MetricsRegistry) *Client {
	c.metrics = m
	return c
}

// ============================================================================
// Query Operations
// ============================================================================

// Query executes a query that returns rows
func (c *Client) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	startTime := time.Now()

	rows, err := c.pool.Query(ctx, sql, args...)
	duration := time.Since(startTime)

	// Log query
	if c.logger != nil {
		if err != nil {
			c.logger.Error("Query failed",
				"sql", sql,
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		} else {
			c.logger.Debug("Query executed",
				"sql", sql,
				"duration_ms", duration.Milliseconds(),
			)
		}
	}

	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_QUERY_FAILED", "Query execution failed")
	}

	return rows, nil
}

// QueryRow executes a query that returns at most one row
func (c *Client) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	startTime := time.Now()

	row := c.pool.QueryRow(ctx, sql, args...)

	if c.logger != nil {
		c.logger.Debug("QueryRow executed",
			"sql", sql,
			"duration_ms", time.Since(startTime).Milliseconds(),
		)
	}

	return row
}

// Exec executes a query that doesn't return rows (INSERT, UPDATE, DELETE)
func (c *Client) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	startTime := time.Now()

	tag, err := c.pool.Exec(ctx, sql, args...)
	duration := time.Since(startTime)

	// Log execution
	if c.logger != nil {
		if err != nil {
			c.logger.Error("Exec failed",
				"sql", sql,
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		} else {
			c.logger.Debug("Exec completed",
				"sql", sql,
				"rows_affected", tag.RowsAffected(),
				"duration_ms", duration.Milliseconds(),
			)
		}
	}

	if err != nil {
		return tag, c.classifyError(err, "POSTGRES_EXEC_FAILED", "Exec execution failed")
	}

	return tag, nil
}

// CopyFrom performs bulk insert using COPY protocol
func (c *Client) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	startTime := time.Now()

	count, err := c.pool.CopyFrom(ctx, tableName, columnNames, rowSrc)
	duration := time.Since(startTime)

	// Log operation
	if c.logger != nil {
		if err != nil {
			c.logger.Error("CopyFrom failed",
				"table", tableName,
				"columns", columnNames,
				"duration_ms", duration.Milliseconds(),
				"error", err.Error(),
			)
		} else {
			c.logger.Debug("CopyFrom completed",
				"table", tableName,
				"rows_inserted", count,
				"duration_ms", duration.Milliseconds(),
			)
		}
	}

	if err != nil {
		return count, c.classifyError(err, "POSTGRES_COPY_FAILED", "Bulk insert failed")
	}

	return count, nil
}

// ============================================================================
// Error Classification
// ============================================================================

// classifyError wraps database errors with appropriate error codes
func (c *Client) classifyError(err error, defaultCode, defaultMsg string) error {
	if err == nil {
		return nil
	}

	// Check for pgconn.PgError (PostgreSQL-specific errors)
	var pgErr *pgconn.PgError
	if goerrors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return errors.Wrap(err, "POSTGRES_UNIQUE_VIOLATION", "Unique constraint violation").
				WithField("constraint", pgErr.ConstraintName).
				WithField("detail", pgErr.Detail)

		case "23503": // foreign_key_violation
			return errors.Wrap(err, "POSTGRES_FOREIGN_KEY_VIOLATION", "Foreign key constraint violation").
				WithField("constraint", pgErr.ConstraintName).
				WithField("detail", pgErr.Detail)

		case "23514": // check_violation
			return errors.Wrap(err, "POSTGRES_CHECK_VIOLATION", "Check constraint violation").
				WithField("constraint", pgErr.ConstraintName)

		case "40001": // serialization_failure
			return errors.Wrap(err, "POSTGRES_SERIALIZATION_FAILURE", "Transaction serialization failure (retry recommended)")

		case "40P01": // deadlock_detected
			return errors.Wrap(err, "POSTGRES_DEADLOCK", "Deadlock detected (retry recommended)")

		case "42P01": // undefined_table
			return errors.Wrap(err, "POSTGRES_UNDEFINED_TABLE", "Table does not exist").
				WithField("table", pgErr.TableName)

		case "42703": // undefined_column
			return errors.Wrap(err, "POSTGRES_UNDEFINED_COLUMN", "Column does not exist").
				WithField("column", pgErr.ColumnName)

		case "42601": // syntax_error
			return errors.Wrap(err, "POSTGRES_SYNTAX_ERROR", "SQL syntax error").
				WithField("position", pgErr.Position)

		case "42501": // insufficient_privilege
			return errors.Wrap(err, "POSTGRES_PERMISSION_DENIED", "Insufficient privileges")

		case "53300": // too_many_connections
			return errors.Wrap(err, "POSTGRES_TOO_MANY_CONNECTIONS", "Too many connections")

		case "57014": // query_canceled
			return errors.Wrap(err, "POSTGRES_QUERY_CANCELED", "Query was canceled")

		case "57P01": // admin_shutdown
			return errors.Wrap(err, "POSTGRES_SHUTDOWN", "Server is shutting down")

		default:
			return errors.Wrap(err, "POSTGRES_ERROR", fmt.Sprintf("PostgreSQL error: %s", pgErr.Code)).
				WithField("code", pgErr.Code).
				WithField("severity", pgErr.Severity).
				WithField("message", pgErr.Message)
		}
	}

	// Check for context errors
	if err == context.DeadlineExceeded {
		return errors.Wrap(err, "POSTGRES_TIMEOUT", "Query timeout exceeded")
	}
	if err == context.Canceled {
		return errors.Wrap(err, "POSTGRES_CANCELED", "Query was canceled")
	}

	// Default error wrapping
	return errors.Wrap(err, defaultCode, defaultMsg)
}

// ============================================================================
// Health Checking
// ============================================================================

// HealthCheck verifies database connectivity
func (c *Client) HealthCheck(ctx context.Context) error {
	// Create timeout context
	healthCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Execute simple query
	var result int
	err := c.pool.QueryRow(healthCtx, "SELECT 1").Scan(&result)
	if err != nil {
		return errors.Wrap(err, "POSTGRES_HEALTH_CHECK_FAILED", "Database health check failed")
	}

	if result != 1 {
		return errors.New("POSTGRES_HEALTH_CHECK_INVALID", "Health check returned unexpected result").
			WithField("expected", 1).
			WithField("actual", result)
	}

	return nil
}

// Ping checks basic connectivity
func (c *Client) Ping(ctx context.Context) error {
	return c.pool.Ping(ctx)
}

// IsConnected returns true if database is reachable
func (c *Client) IsConnected(ctx context.Context) bool {
	return c.Ping(ctx) == nil
}

// ============================================================================
// Pool Statistics
// ============================================================================

// Stats returns connection pool statistics
func (c *Client) Stats() *pgxpool.Stat {
	return c.pool.Stat()
}

// LogStats logs current pool statistics
func (c *Client) LogStats() {
	if c.logger == nil {
		return
	}

	stats := c.Stats()
	c.logger.Info("PostgreSQL pool statistics",
		"total_conns", stats.TotalConns(),
		"idle_conns", stats.IdleConns(),
		"acquired_conns", stats.AcquiredConns(),
		"max_conns", stats.MaxConns(),
	)
}

// ============================================================================
// Utility Methods
// ============================================================================

// TableExists checks if a table exists
func (c *Client) TableExists(ctx context.Context, tableName string) (bool, error) {
	var exists bool
	err := c.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public'
			AND table_name = $1
		)
	`, tableName).Scan(&exists)
	return exists, err
}

// ColumnExists checks if a column exists in a table
func (c *Client) ColumnExists(ctx context.Context, tableName, columnName string) (bool, error) {
	var exists bool
	err := c.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_schema = 'public'
			AND table_name = $1
			AND column_name = $2
		)
	`, tableName, columnName).Scan(&exists)
	return exists, err
}

// CurrentDatabase returns the current database name
func (c *Client) CurrentDatabase(ctx context.Context) (string, error) {
	var dbName string
	err := c.pool.QueryRow(ctx, "SELECT current_database()").Scan(&dbName)
	return dbName, err
}

// ServerVersion returns the PostgreSQL server version
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	var version string
	err := c.pool.QueryRow(ctx, "SELECT version()").Scan(&version)
	return version, err
}

// ============================================================================
// Connection Management
// ============================================================================

// Acquire gets a connection from the pool
func (c *Client) Acquire(ctx context.Context) (*pgxpool.Conn, error) {
	return c.pool.Acquire(ctx)
}

// Close closes the connection pool gracefully
func (c *Client) Close() {
	if c.logger != nil {
		c.logger.Info("Closing PostgreSQL connection pool")
	}
	c.pool.Close()
}

// ============================================================================
// Helper Functions for Retryable Errors
// ============================================================================

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Context errors are not retryable
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}

	// Check error code
	code := errors.GetCode(err)
	switch code {
	case "POSTGRES_SERIALIZATION_FAILURE",
		"POSTGRES_DEADLOCK",
		"POSTGRES_TOO_MANY_CONNECTIONS":
		return true
	default:
		return false
	}
}
