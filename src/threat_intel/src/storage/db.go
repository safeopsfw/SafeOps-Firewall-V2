package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"threat_intel/models"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// =============================================================================
// Database Connection Manager
// Core database connectivity used by all storage modules
// =============================================================================

// DB represents the database connection pool
type DB struct {
	pool      *sql.DB
	connected bool
	config    DBConfig
	mu        sync.RWMutex
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
	ConnectionLifetime int // minutes
}

// DefaultDBConfig returns sensible defaults
func DefaultDBConfig() *DBConfig {
	return &DBConfig{
		Host:               "localhost",
		Port:               5432,
		Database:           "threat_intel_db",
		User:               "postgres",
		Password:           "admin",
		SSLMode:            "disable",
		MaxConnections:     25,
		MaxIdleConnections: 5,
		ConnectionLifetime: 30,
	}
}

// TableInfo represents metadata about a database table
type TableInfo struct {
	TableName    string       `json:"table_name"`
	Columns      []ColumnInfo `json:"columns"`
	RowCount     int64        `json:"row_count"`
	Exists       bool         `json:"exists"`
	LastModified *time.Time   `json:"last_modified,omitempty"`
}

// ColumnInfo represents metadata about a table column
type ColumnInfo struct {
	Name         string `json:"name"`
	DataType     string `json:"data_type"`
	IsNullable   bool   `json:"is_nullable"`
	DefaultValue string `json:"default_value,omitempty"`
	MaxLength    int    `json:"max_length,omitempty"`
	Position     int    `json:"position"`
}

// ConnectionStatus represents database connection state
type ConnectionStatus struct {
	Connected   bool      `json:"connected"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Database    string    `json:"database"`
	User        string    `json:"user"`
	LastPing    time.Time `json:"last_ping"`
	PingLatency string    `json:"ping_latency"`
	OpenConns   int       `json:"open_connections"`
	InUseConns  int       `json:"in_use_connections"`
	IdleConns   int       `json:"idle_connections"`
	Error       string    `json:"error,omitempty"`
}

// =============================================================================
// Connection Management
// =============================================================================

// NewDB creates a new database connection pool
func NewDB(config *DBConfig) (*DB, error) {
	if config == nil {
		config = DefaultDBConfig()
	}

	db := &DB{
		config: *config,
	}

	// Build connection string
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password,
		config.Database, config.SSLMode,
	)

	// Open connection pool
	pool, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure pool
	pool.SetMaxOpenConns(config.MaxConnections)
	pool.SetMaxIdleConns(config.MaxIdleConnections)
	pool.SetConnMaxLifetime(time.Duration(config.ConnectionLifetime) * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.pool = pool
	db.connected = true

	return db, nil
}

// Connect establishes database connection (if not already connected)
func (db *DB) Connect() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.connected && db.pool != nil {
		return nil
	}

	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		db.config.Host, db.config.Port, db.config.User, db.config.Password,
		db.config.Database, db.config.SSLMode,
	)

	pool, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	pool.SetMaxOpenConns(db.config.MaxConnections)
	pool.SetMaxIdleConns(db.config.MaxIdleConnections)
	pool.SetConnMaxLifetime(time.Duration(db.config.ConnectionLifetime) * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	db.pool = pool
	db.connected = true
	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.pool != nil {
		err := db.pool.Close()
		db.pool = nil
		db.connected = false
		return err
	}
	return nil
}

// Ping tests the database connection
func (db *DB) Ping() error {
	if db.pool == nil {
		return fmt.Errorf("database not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return db.pool.PingContext(ctx)
}

// IsConnected returns connection status
func (db *DB) IsConnected() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.connected && db.pool != nil
}

// GetStatus returns detailed connection status
func (db *DB) GetStatus() ConnectionStatus {
	status := ConnectionStatus{
		Host:     db.config.Host,
		Port:     db.config.Port,
		Database: db.config.Database,
		User:     db.config.User,
	}

	if db.pool == nil {
		status.Connected = false
		status.Error = "Not connected"
		return status
	}

	// Ping with timing
	start := time.Now()
	err := db.Ping()
	latency := time.Since(start)

	if err != nil {
		status.Connected = false
		status.Error = err.Error()
	} else {
		status.Connected = true
		status.LastPing = time.Now()
		status.PingLatency = latency.String()

		// Get pool stats
		stats := db.pool.Stats()
		status.OpenConns = stats.OpenConnections
		status.InUseConns = stats.InUse
		status.IdleConns = stats.Idle
	}

	return status
}

// GetPool returns the underlying connection pool (for advanced usage)
func (db *DB) GetPool() *sql.DB {
	return db.pool
}

// =============================================================================
// Table Information Methods
// =============================================================================

// GetTableInfo returns metadata about a specific table
func (db *DB) GetTableInfo(tableName string) (*TableInfo, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info := &TableInfo{
		TableName: tableName,
		Columns:   []ColumnInfo{},
	}

	// Check if table exists
	var exists bool
	err := db.pool.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = $1
		)
	`, tableName).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("failed to check table existence: %w", err)
	}

	info.Exists = exists
	if !exists {
		return info, nil
	}

	// Get column information
	rows, err := db.pool.QueryContext(ctx, `
		SELECT 
			column_name,
			data_type,
			is_nullable = 'YES',
			COALESCE(column_default, ''),
			COALESCE(character_maximum_length, 0),
			ordinal_position
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
		ORDER BY ordinal_position
	`, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to query columns: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var col ColumnInfo
		if err := rows.Scan(&col.Name, &col.DataType, &col.IsNullable,
			&col.DefaultValue, &col.MaxLength, &col.Position); err != nil {
			return nil, fmt.Errorf("failed to scan column: %w", err)
		}
		info.Columns = append(info.Columns, col)
	}

	// Get row count
	err = db.pool.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName),
	).Scan(&info.RowCount)
	if err != nil {
		// Table might be empty or error counting
		info.RowCount = 0
	}

	return info, nil
}

// GetAllTables returns list of all tables in the database
func (db *DB) GetAllTables() ([]string, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := db.pool.QueryContext(ctx, `
		SELECT table_name 
		FROM information_schema.tables 
		WHERE table_schema = 'public' 
		AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, name)
	}

	return tables, nil
}

// =============================================================================
// Column Management (Add/Remove Headers)
// =============================================================================

// AddColumn adds a new column to a table
func (db *DB) AddColumn(tableName, columnName, dataType string, defaultValue string) error {
	if db.pool == nil {
		return fmt.Errorf("database not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build ALTER TABLE statement
	query := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s",
		tableName, columnName, dataType)

	if defaultValue != "" {
		query += fmt.Sprintf(" DEFAULT %s", defaultValue)
	}

	_, err := db.pool.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to add column: %w", err)
	}

	return nil
}

// RemoveColumn removes a column from a table
func (db *DB) RemoveColumn(tableName, columnName string) error {
	if db.pool == nil {
		return fmt.Errorf("database not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := fmt.Sprintf("ALTER TABLE %s DROP COLUMN IF EXISTS %s",
		tableName, columnName)

	_, err := db.pool.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to remove column: %w", err)
	}

	return nil
}

// RenameColumn renames a column in a table
func (db *DB) RenameColumn(tableName, oldName, newName string) error {
	if db.pool == nil {
		return fmt.Errorf("database not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s",
		tableName, oldName, newName)

	_, err := db.pool.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to rename column: %w", err)
	}

	return nil
}

// GetColumnNames returns just the column names for a table
func (db *DB) GetColumnNames(tableName string) ([]string, error) {
	info, err := db.GetTableInfo(tableName)
	if err != nil {
		return nil, err
	}

	if !info.Exists {
		return nil, fmt.Errorf("table %s does not exist", tableName)
	}

	names := make([]string, len(info.Columns))
	for i, col := range info.Columns {
		names[i] = col.Name
	}
	return names, nil
}

// =============================================================================
// Query Helpers
// =============================================================================

// ExecContext executes a query that doesn't return rows
func (db *DB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}
	return db.pool.ExecContext(ctx, query, args...)
}

// QueryContext executes a query that returns rows
func (db *DB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}
	return db.pool.QueryContext(ctx, query, args...)
}

// QueryRowContext executes a query that returns a single row
func (db *DB) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return db.pool.QueryRowContext(ctx, query, args...)
}

// BeginTx starts a new transaction
func (db *DB) BeginTx(ctx context.Context) (*sql.Tx, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}
	return db.pool.BeginTx(ctx, nil)
}

// =============================================================================
// Bulk Operations
// =============================================================================

// BulkInsert performs efficient bulk insert using COPY protocol
func (db *DB) BulkInsert(tableName string, columns []string, values [][]interface{}) (int64, error) {
	if db.pool == nil {
		return 0, fmt.Errorf("database not connected")
	}

	if len(values) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Build INSERT query with multiple value placeholders
	// Using batch insert instead of COPY for simplicity
	const batchSize = 1000
	var totalInserted int64

	for i := 0; i < len(values); i += batchSize {
		end := i + batchSize
		if end > len(values) {
			end = len(values)
		}
		batch := values[i:end]

		// Build placeholders
		var placeholders []string
		var args []interface{}
		argIdx := 1

		for _, row := range batch {
			var rowPlaceholders []string
			for range row {
				rowPlaceholders = append(rowPlaceholders, fmt.Sprintf("$%d", argIdx))
				argIdx++
			}
			placeholders = append(placeholders, fmt.Sprintf("(%s)", strings.Join(rowPlaceholders, ", ")))
			args = append(args, row...)
		}

		query := fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES %s ON CONFLICT DO NOTHING",
			tableName,
			strings.Join(columns, ", "),
			strings.Join(placeholders, ", "),
		)

		result, err := db.pool.ExecContext(ctx, query, args...)
		if err != nil {
			return totalInserted, fmt.Errorf("bulk insert failed: %w", err)
		}

		affected, _ := result.RowsAffected()
		totalInserted += affected
	}

	return totalInserted, nil
}

// =============================================================================
// Test Connection Function
// =============================================================================

// TestConnection attempts to connect and returns status
func TestConnection(config *DBConfig) ConnectionStatus {
	if config == nil {
		config = DefaultDBConfig()
	}

	status := ConnectionStatus{
		Host:     config.Host,
		Port:     config.Port,
		Database: config.Database,
		User:     config.User,
	}

	db, err := NewDB(config)
	if err != nil {
		status.Connected = false
		status.Error = err.Error()
		return status
	}
	defer db.Close()

	// Get full status
	return db.GetStatus()
}

// =============================================================================
// API Compatibility Methods
// These methods provide backwards compatibility with the API handlers
// =============================================================================

// GetIPReputation retrieves reputation data for an IP (API compatibility)
func (db *DB) GetIPReputation(ctx context.Context, ip string) (*models.IPReputation, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	// Query from ip_blacklist and ip_anonymization tables
	var result models.IPReputation
	result.IP = ip

	// Check blacklist
	var isMalicious bool
	var threatScore int
	var abuseType sql.NullString
	err := db.pool.QueryRowContext(ctx, `
		SELECT is_malicious, threat_score, abuse_type 
		FROM ip_blacklist WHERE ip_address = $1::inet
	`, ip).Scan(&isMalicious, &threatScore, &abuseType)

	if err == nil {
		result.Score = threatScore
		if threatScore >= 80 {
			result.Severity = "Critical"
		} else if threatScore >= 60 {
			result.Severity = "High"
		} else if threatScore >= 40 {
			result.Severity = "Medium"
		} else {
			result.Severity = "Low"
		}
		if abuseType.Valid {
			result.Categories = []string{abuseType.String}
		}
	}

	// Check anonymization
	var isVPN, isTor, isProxy bool
	err = db.pool.QueryRowContext(ctx, `
		SELECT is_vpn, is_tor, is_proxy 
		FROM ip_anonymization WHERE ip_address = $1::inet
	`, ip).Scan(&isVPN, &isTor, &isProxy)

	if err == nil {
		result.IsVPN = isVPN
		result.IsTor = isTor
		result.IsProxy = isProxy
	}

	// Check geolocation
	var countryCode sql.NullString
	var asn sql.NullString
	err = db.pool.QueryRowContext(ctx, `
		SELECT country_code, asn::text FROM ip_geolocation WHERE ip_address = $1::inet
	`, ip).Scan(&countryCode, &asn)

	if err == nil {
		if countryCode.Valid {
			result.CountryCode = countryCode.String
		}
		if asn.Valid {
			result.ASN = asn.String
		}
	}

	result.LastSeen = time.Now()
	return &result, nil
}

// GetDomainIntelligence retrieves intelligence for a domain (API compatibility)
func (db *DB) GetDomainIntelligence(ctx context.Context, domain string) (*models.DomainIntelligence, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	var result models.DomainIntelligence
	var category, registrar sql.NullString
	var threatScore sql.NullInt64
	var lastSeen time.Time

	err := db.pool.QueryRowContext(ctx, `
		SELECT domain, threat_score, category, registrar, last_seen 
		FROM domains WHERE domain = $1
	`, domain).Scan(&result.Domain, &threatScore, &category, &registrar, &lastSeen)

	if err != nil {
		return nil, err
	}

	if threatScore.Valid {
		result.Score = int(threatScore.Int64)
	}
	if threatScore.Int64 >= 80 {
		result.Severity = "Critical"
	} else if threatScore.Int64 >= 60 {
		result.Severity = "High"
	} else if threatScore.Int64 >= 40 {
		result.Severity = "Medium"
	} else {
		result.Severity = "Low"
	}
	if category.Valid {
		result.Categories = []string{category.String}
	}
	if registrar.Valid {
		result.Registrar = registrar.String
	}
	result.LastSeen = lastSeen

	return &result, nil
}

// GetHashReputation retrieves reputation for a file hash (API compatibility)
func (db *DB) GetHashReputation(ctx context.Context, hash string) (*models.HashReputation, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	var result models.HashReputation
	var malwareFamily, fileName sql.NullString
	var fileSize sql.NullInt64
	var threatScore sql.NullInt64
	var lastSeen time.Time

	// Try SHA256 first, then MD5
	query := `
		SELECT sha256, threat_score, malware_family, file_name, file_size, last_seen 
		FROM hashes WHERE sha256 = $1 OR md5 = $1
	`
	err := db.pool.QueryRowContext(ctx, query, hash).Scan(
		&result.Hash, &threatScore, &malwareFamily, &fileName, &fileSize, &lastSeen,
	)

	if err != nil {
		return nil, err
	}

	result.Type = "SHA256"
	if len(hash) == 32 {
		result.Type = "MD5"
	} else if len(hash) == 40 {
		result.Type = "SHA1"
	}

	if threatScore.Valid {
		result.Score = int(threatScore.Int64)
	}
	if threatScore.Int64 >= 80 {
		result.Severity = "Critical"
	} else if threatScore.Int64 >= 60 {
		result.Severity = "High"
	} else {
		result.Severity = "Medium"
	}
	if malwareFamily.Valid {
		result.Categories = []string{malwareFamily.String}
	}
	if fileName.Valid {
		result.FileName = fileName.String
	}
	if fileSize.Valid {
		result.FileSize = fileSize.Int64
	}
	result.LastSeen = lastSeen

	return &result, nil
}

// GetIOCs retrieves a paginated list of IOCs (API compatibility)
func (db *DB) GetIOCs(ctx context.Context, filter *models.IOCFilter) ([]models.IOC, int, error) {
	if db.pool == nil {
		return nil, 0, fmt.Errorf("database not connected")
	}

	// This is a simplified implementation
	// In production, query from iocs table or combine from multiple tables
	offset := (filter.Page - 1) * filter.PerPage

	query := `SELECT COUNT(*) FROM domains WHERE is_malicious = true`
	var total int
	db.pool.QueryRowContext(ctx, query).Scan(&total)

	query = `
		SELECT domain, threat_score, category, first_seen, last_seen 
		FROM domains WHERE is_malicious = true
		ORDER BY threat_score DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := db.pool.QueryContext(ctx, query, filter.PerPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var iocs []models.IOC
	for rows.Next() {
		var ioc models.IOC
		var category sql.NullString
		if err := rows.Scan(&ioc.Value, &ioc.Score, &category, &ioc.FirstSeen, &ioc.LastSeen); err != nil {
			continue
		}
		ioc.Type = "domain"
		if ioc.Score >= 80 {
			ioc.Severity = "Critical"
		} else if ioc.Score >= 60 {
			ioc.Severity = "High"
		} else {
			ioc.Severity = "Medium"
		}
		iocs = append(iocs, ioc)
	}

	return iocs, total, nil
}

// GetFeeds retrieves all configured feeds (API compatibility)
func (db *DB) GetFeeds(ctx context.Context) ([]models.Feed, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	query := `
		SELECT id, feed_name, feed_category, is_active, last_fetched 
		FROM threat_feeds 
		ORDER BY feed_name
	`

	rows, err := db.pool.QueryContext(ctx, query)
	if err != nil {
		// Return empty list if table doesn't exist
		return []models.Feed{}, nil
	}
	defer rows.Close()

	var feeds []models.Feed
	for rows.Next() {
		var f models.Feed
		var lastFetched sql.NullTime
		if err := rows.Scan(&f.ID, &f.Name, &f.Category, &f.Enabled, &lastFetched); err != nil {
			continue
		}
		if lastFetched.Valid {
			f.LastUpdated = lastFetched.Time
		}
		if f.Enabled {
			f.Status = "active"
		} else {
			f.Status = "disabled"
		}
		feeds = append(feeds, f)
	}

	return feeds, nil
}

// GetFeedByID retrieves a specific feed (API compatibility)
func (db *DB) GetFeedByID(ctx context.Context, id int) (*models.Feed, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	var f models.Feed
	var lastFetched sql.NullTime

	err := db.pool.QueryRowContext(ctx, `
		SELECT id, feed_name, feed_category, feed_url, is_active, last_fetched 
		FROM threat_feeds WHERE id = $1
	`, id).Scan(&f.ID, &f.Name, &f.Category, &f.URL, &f.Enabled, &lastFetched)

	if err != nil {
		return nil, err
	}

	if lastFetched.Valid {
		f.LastUpdated = lastFetched.Time
	}
	if f.Enabled {
		f.Status = "active"
	} else {
		f.Status = "disabled"
	}

	return &f, nil
}

// GetStats retrieves system statistics (API compatibility)
func (db *DB) GetStats(ctx context.Context) (*models.Stats, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	stats := &models.Stats{}

	// Count IPs
	db.pool.QueryRowContext(ctx, "SELECT COUNT(*) FROM ip_blacklist").Scan(&stats.TotalIPs)

	// Count domains
	db.pool.QueryRowContext(ctx, "SELECT COUNT(*) FROM domains").Scan(&stats.TotalDomains)

	// Count hashes
	db.pool.QueryRowContext(ctx, "SELECT COUNT(*) FROM hashes").Scan(&stats.TotalHashes)

	// Active threats (high score items)
	db.pool.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM ip_blacklist WHERE threat_score >= 70
	`).Scan(&stats.ActiveThreats)

	// Feed counts
	db.pool.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM threat_feeds WHERE is_active = true
	`).Scan(&stats.FeedsActive)

	return stats, nil
}

// Search performs a search across multiple intelligence types (API compatibility)
func (db *DB) Search(ctx context.Context, req *models.SearchRequest) (interface{}, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database not connected")
	}

	results := map[string]interface{}{
		"ips":     []models.IPReputation{},
		"domains": []models.DomainIntelligence{},
		"hashes":  []models.HashReputation{},
	}

	limit := req.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	// Search IPs
	ipRows, err := db.pool.QueryContext(ctx, `
		SELECT ip_address::text, threat_score FROM ip_blacklist 
		WHERE ip_address::text LIKE $1 LIMIT $2
	`, req.Query+"%", limit)
	if err == nil {
		defer ipRows.Close()
		var ips []models.IPReputation
		for ipRows.Next() {
			var r models.IPReputation
			ipRows.Scan(&r.IP, &r.Score)
			ips = append(ips, r)
		}
		results["ips"] = ips
	}

	// Search domains
	domainRows, err := db.pool.QueryContext(ctx, `
		SELECT domain, threat_score FROM domains 
		WHERE domain LIKE $1 LIMIT $2
	`, "%"+req.Query+"%", limit)
	if err == nil {
		defer domainRows.Close()
		var domains []models.DomainIntelligence
		for domainRows.Next() {
			var d models.DomainIntelligence
			domainRows.Scan(&d.Domain, &d.Score)
			domains = append(domains, d)
		}
		results["domains"] = domains
	}

	return results, nil
}

// BulkGetIPReputation performs bulk lookup for IPs (API compatibility)
func (db *DB) BulkGetIPReputation(ctx context.Context, ips []string) ([]models.IPReputation, error) {
	var results []models.IPReputation
	for _, ip := range ips {
		result, err := db.GetIPReputation(ctx, ip)
		if err == nil && result != nil {
			results = append(results, *result)
		}
	}
	return results, nil
}

// BulkGetDomainIntelligence performs bulk lookup for domains (API compatibility)
func (db *DB) BulkGetDomainIntelligence(ctx context.Context, domains []string) ([]models.DomainIntelligence, error) {
	var results []models.DomainIntelligence
	for _, domain := range domains {
		result, err := db.GetDomainIntelligence(ctx, domain)
		if err == nil && result != nil {
			results = append(results, *result)
		}
	}
	return results, nil
}

// BulkGetHashReputation performs bulk lookup for hashes (API compatibility)
func (db *DB) BulkGetHashReputation(ctx context.Context, hashes []string) ([]models.HashReputation, error) {
	var results []models.HashReputation
	for _, hash := range hashes {
		result, err := db.GetHashReputation(ctx, hash)
		if err == nil && result != nil {
			results = append(results, *result)
		}
	}
	return results, nil
}
