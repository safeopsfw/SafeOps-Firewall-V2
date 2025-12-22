package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// DB is the main database connection manager
type DB struct {
	conn        *sql.DB
	config      *DBConfig
	isConnected bool
	stats       *DBStats
	logger      *log.Logger
	statsMutex  sync.RWMutex
}

// DBConfig holds database connection configuration
type DBConfig struct {
	Host               string
	Port               int
	Database           string
	User               string
	Password           string
	SSLMode            string
	MaxConnections     int
	MaxIdleConnections int
	ConnectionLifetime time.Duration
	ConnectTimeout     int
	QueryTimeout       int
}

// DBStats tracks database operation statistics
type DBStats struct {
	TotalQueries      int64
	SuccessfulQueries int64
	FailedQueries     int64
	TotalInserts      int64
	TotalUpdates      int64
	TotalDeletes      int64
	AverageQueryTime  time.Duration
	queryTimes        []time.Duration
}

// HealthStatus represents database health
type HealthStatus struct {
	Status    string // healthy, degraded, unhealthy
	Latency   time.Duration
	Message   string
	Timestamp time.Time
}

// DefaultDBConfig returns default database configuration
func DefaultDBConfig() *DBConfig {
	return &DBConfig{
		Host:               getEnvOrDefault("DB_HOST", "localhost"),
		Port:               getEnvIntOrDefault("DB_PORT", 5432),
		Database:           getEnvOrDefault("DB_NAME", "threat_intel_db"),
		User:               getEnvOrDefault("DB_USER", "threat_intel"),
		Password:           os.Getenv("DB_PASSWORD"),
		SSLMode:            getEnvOrDefault("DB_SSLMODE", "disable"),
		MaxConnections:     getEnvIntOrDefault("DB_MAX_CONNECTIONS", 25),
		MaxIdleConnections: getEnvIntOrDefault("DB_MAX_IDLE_CONNECTIONS", 5),
		ConnectionLifetime: 30 * time.Minute,
		ConnectTimeout:     10,
		QueryTimeout:       30,
	}
}

// NewDatabase creates a new database connection with default config
func NewDatabase() (*DB, error) {
	return NewDatabaseWithConfig(DefaultDBConfig())
}

// NewDatabaseWithConfig creates database connection with custom config
func NewDatabaseWithConfig(cfg *DBConfig) (*DB, error) {
	db := &DB{
		config: cfg,
		stats:  &DBStats{queryTimes: make([]time.Duration, 0, 100)},
		logger: log.New(os.Stdout, "[DB] ", log.LstdFlags),
	}

	if err := db.Connect(); err != nil {
		return nil, err
	}

	return db, nil
}

// Connect establishes connection to PostgreSQL database
func (db *DB) Connect() error {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		db.config.Host,
		db.config.Port,
		db.config.User,
		db.config.Password,
		db.config.Database,
		db.config.SSLMode,
		db.config.ConnectTimeout,
	)

	conn, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(db.config.MaxConnections)
	conn.SetMaxIdleConns(db.config.MaxIdleConnections)
	conn.SetConnMaxLifetime(db.config.ConnectionLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.ConnectTimeout)*time.Second)
	defer cancel()

	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	db.conn = conn
	db.isConnected = true
	db.logger.Printf("Connected to PostgreSQL: %s:%d/%s", db.config.Host, db.config.Port, db.config.Database)

	return nil
}

// Ping tests database connectivity
func (db *DB) Ping() error {
	if db.conn == nil {
		return fmt.Errorf("database connection not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return db.conn.PingContext(ctx)
}

// Close gracefully closes database connection pool
func (db *DB) Close() error {
	if db.conn == nil {
		return nil
	}

	db.isConnected = false
	db.logger.Println("Closing database connection pool")
	return db.conn.Close()
}

// GetConn returns the underlying sql.DB connection
func (db *DB) GetConn() *sql.DB {
	return db.conn
}

// IsConnected returns connection status
func (db *DB) IsConnected() bool {
	return db.isConnected && db.conn != nil
}

// BeginTx starts a database transaction
func (db *DB) BeginTx(ctx context.Context) (*sql.Tx, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	tx, err := db.conn.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return tx, nil
}

// CommitTx commits a transaction
func (db *DB) CommitTx(tx *sql.Tx) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	return tx.Commit()
}

// RollbackTx rolls back a transaction
func (db *DB) RollbackTx(tx *sql.Tx) error {
	if tx == nil {
		return nil
	}
	return tx.Rollback()
}

// ExecuteQuery executes a SELECT query and returns rows
func (db *DB) ExecuteQuery(query string, args ...interface{}) (*sql.Rows, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.QueryTimeout)*time.Second)
	defer cancel()

	start := time.Now()
	rows, err := db.conn.QueryContext(ctx, query, args...)
	duration := time.Since(start)

	db.recordStats("SELECT", duration, err == nil)

	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	return rows, nil
}

// QueryRow executes query expecting single row result
func (db *DB) QueryRow(query string, args ...interface{}) *sql.Row {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.QueryTimeout)*time.Second)
	defer cancel()

	return db.conn.QueryRowContext(ctx, query, args...)
}

// ExecuteInsert executes INSERT and returns affected rows
func (db *DB) ExecuteInsert(query string, args ...interface{}) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.QueryTimeout)*time.Second)
	defer cancel()

	start := time.Now()
	result, err := db.conn.ExecContext(ctx, query, args...)
	duration := time.Since(start)

	db.recordStats("INSERT", duration, err == nil)

	if err != nil {
		return 0, fmt.Errorf("insert failed: %w", err)
	}

	affected, _ := result.RowsAffected()
	return affected, nil
}

// ExecuteUpdate executes UPDATE and returns affected rows
func (db *DB) ExecuteUpdate(query string, args ...interface{}) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.QueryTimeout)*time.Second)
	defer cancel()

	start := time.Now()
	result, err := db.conn.ExecContext(ctx, query, args...)
	duration := time.Since(start)

	db.recordStats("UPDATE", duration, err == nil)

	if err != nil {
		return 0, fmt.Errorf("update failed: %w", err)
	}

	affected, _ := result.RowsAffected()
	return affected, nil
}

// ExecuteDelete executes DELETE and returns affected rows
func (db *DB) ExecuteDelete(query string, args ...interface{}) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.QueryTimeout)*time.Second)
	defer cancel()

	start := time.Now()
	result, err := db.conn.ExecContext(ctx, query, args...)
	duration := time.Since(start)

	db.recordStats("DELETE", duration, err == nil)

	if err != nil {
		return 0, fmt.Errorf("delete failed: %w", err)
	}

	affected, _ := result.RowsAffected()
	return affected, nil
}

// Exec executes a query without returning rows (for INSERT/UPDATE/DELETE)
func (db *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.QueryTimeout)*time.Second)
	defer cancel()

	return db.conn.ExecContext(ctx, query, args...)
}

// BulkInsert efficiently inserts multiple records in a transaction
func (db *DB) BulkInsert(table string, columns []string, values [][]interface{}) (int64, error) {
	if len(values) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.QueryTimeout*2)*time.Second)
	defer cancel()

	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Build INSERT statement
	placeholders := make([]string, len(columns))
	for i := range columns {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		table,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
	)

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	var inserted int64
	for _, row := range values {
		_, err := stmt.ExecContext(ctx, row...)
		if err != nil {
			// Log error but continue (lenient mode)
			db.logger.Printf("Bulk insert row error: %v", err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	db.statsMutex.Lock()
	db.stats.TotalInserts += inserted
	db.statsMutex.Unlock()

	return inserted, nil
}

// BulkUpsert inserts or updates records using ON CONFLICT
func (db *DB) BulkUpsert(table string, columns []string, values [][]interface{}, conflictColumn string, updateColumns []string) (int64, error) {
	if len(values) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(db.config.QueryTimeout*2)*time.Second)
	defer cancel()

	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Build placeholders
	placeholders := make([]string, len(columns))
	for i := range columns {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	// Build update clause
	updateClauses := make([]string, len(updateColumns))
	for i, col := range updateColumns {
		updateClauses[i] = fmt.Sprintf("%s = EXCLUDED.%s", col, col)
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s",
		table,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
		conflictColumn,
		strings.Join(updateClauses, ", "),
	)

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	var affected int64
	for _, row := range values {
		result, err := stmt.ExecContext(ctx, row...)
		if err != nil {
			db.logger.Printf("Bulk upsert row error: %v", err)
			continue
		}
		n, _ := result.RowsAffected()
		affected += n
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return affected, nil
}

// PrepareStatement prepares SQL statement for repeated execution
func (db *DB) PrepareStatement(query string) (*sql.Stmt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return db.conn.PrepareContext(ctx, query)
}

// CheckHealth performs comprehensive health check
func (db *DB) CheckHealth() HealthStatus {
	status := HealthStatus{
		Timestamp: time.Now(),
	}

	// Check ping
	start := time.Now()
	err := db.Ping()
	status.Latency = time.Since(start)

	if err != nil {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("Ping failed: %v", err)
		return status
	}

	// Check with test query
	var result int
	err = db.QueryRow("SELECT 1").Scan(&result)
	if err != nil {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("Test query failed: %v", err)
		return status
	}

	// Evaluate latency
	switch {
	case status.Latency < 100*time.Millisecond:
		status.Status = "healthy"
		status.Message = "Database responding normally"
	case status.Latency < 500*time.Millisecond:
		status.Status = "degraded"
		status.Message = fmt.Sprintf("High latency: %v", status.Latency)
	default:
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("Critical latency: %v", status.Latency)
	}

	return status
}

// GetConnectionStats returns current pool statistics
func (db *DB) GetConnectionStats() map[string]interface{} {
	if db.conn == nil {
		return nil
	}

	stats := db.conn.Stats()
	return map[string]interface{}{
		"max_open_connections": stats.MaxOpenConnections,
		"open_connections":     stats.OpenConnections,
		"in_use":               stats.InUse,
		"idle":                 stats.Idle,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}
}

// GetStats returns query statistics
func (db *DB) GetStats() *DBStats {
	db.statsMutex.RLock()
	defer db.statsMutex.RUnlock()

	return &DBStats{
		TotalQueries:      db.stats.TotalQueries,
		SuccessfulQueries: db.stats.SuccessfulQueries,
		FailedQueries:     db.stats.FailedQueries,
		TotalInserts:      db.stats.TotalInserts,
		TotalUpdates:      db.stats.TotalUpdates,
		TotalDeletes:      db.stats.TotalDeletes,
		AverageQueryTime:  db.stats.AverageQueryTime,
	}
}

// GetTableRowCount returns row count for a table
func (db *DB) GetTableRowCount(tableName string) (int64, error) {
	// Sanitize table name to prevent SQL injection
	if !isValidTableName(tableName) {
		return 0, fmt.Errorf("invalid table name: %s", tableName)
	}

	var count int64
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count rows: %w", err)
	}

	return count, nil
}

// GetTableSize returns table size in bytes
func (db *DB) GetTableSize(tableName string) (int64, error) {
	if !isValidTableName(tableName) {
		return 0, fmt.Errorf("invalid table name: %s", tableName)
	}

	var size int64
	query := "SELECT pg_total_relation_size($1)"
	err := db.QueryRow(query, tableName).Scan(&size)
	if err != nil {
		return 0, fmt.Errorf("failed to get table size: %w", err)
	}

	return size, nil
}

// TruncateTable deletes all rows from table
func (db *DB) TruncateTable(tableName string) error {
	if !isValidTableName(tableName) {
		return fmt.Errorf("invalid table name: %s", tableName)
	}

	query := fmt.Sprintf("TRUNCATE TABLE %s CASCADE", tableName)
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to truncate table: %w", err)
	}

	db.logger.Printf("Truncated table: %s", tableName)
	return nil
}

// VacuumAnalyze runs VACUUM ANALYZE for maintenance
func (db *DB) VacuumAnalyze(tableName string) error {
	var query string
	if tableName == "" {
		query = "VACUUM ANALYZE"
	} else {
		if !isValidTableName(tableName) {
			return fmt.Errorf("invalid table name: %s", tableName)
		}
		query = fmt.Sprintf("VACUUM ANALYZE %s", tableName)
	}

	// VACUUM cannot run in transaction, use direct connection
	_, err := db.conn.Exec(query)
	if err != nil {
		return fmt.Errorf("vacuum analyze failed: %w", err)
	}

	db.logger.Printf("VACUUM ANALYZE completed: %s", tableName)
	return nil
}

// recordStats records query statistics
func (db *DB) recordStats(queryType string, duration time.Duration, success bool) {
	db.statsMutex.Lock()
	defer db.statsMutex.Unlock()

	db.stats.TotalQueries++
	if success {
		db.stats.SuccessfulQueries++
	} else {
		db.stats.FailedQueries++
	}

	switch queryType {
	case "INSERT":
		db.stats.TotalInserts++
	case "UPDATE":
		db.stats.TotalUpdates++
	case "DELETE":
		db.stats.TotalDeletes++
	}

	// Rolling average (keep last 100 queries)
	db.stats.queryTimes = append(db.stats.queryTimes, duration)
	if len(db.stats.queryTimes) > 100 {
		db.stats.queryTimes = db.stats.queryTimes[1:]
	}

	// Calculate average
	var total time.Duration
	for _, t := range db.stats.queryTimes {
		total += t
	}
	if len(db.stats.queryTimes) > 0 {
		db.stats.AverageQueryTime = total / time.Duration(len(db.stats.queryTimes))
	}
}

// isValidTableName validates table name to prevent SQL injection
func isValidTableName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		fmt.Sscanf(value, "%d", &result)
		if result > 0 {
			return result
		}
	}
	return defaultValue
}
