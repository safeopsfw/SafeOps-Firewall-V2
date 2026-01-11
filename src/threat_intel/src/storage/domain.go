package storage

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// =============================================================================
// Domain Storage - Manages domains table
// Connects to domains table, fetches headers, supports column modification
// =============================================================================

// DomainStorage handles domain reputation data
type DomainStorage struct {
	db        *DB
	tableName string
}

// DomainRecord represents a domain entry in the database
type DomainRecord struct {
	ID             int64     `json:"id"`
	Domain         string    `json:"domain"`
	TLD            string    `json:"tld,omitempty"`
	RootDomain     string    `json:"root_domain,omitempty"`
	IsMalicious    bool      `json:"is_malicious"`
	ThreatScore    int       `json:"threat_score"`
	Category       string    `json:"category,omitempty"`
	Subcategory    string    `json:"subcategory,omitempty"`
	Registrar      string    `json:"registrar,omitempty"`
	PhishingTarget string    `json:"phishing_target,omitempty"`
	DetectionCount int       `json:"detection_count"`
	Sources        []string  `json:"sources"`
	Tags           []string  `json:"tags"`
	Status         string    `json:"status"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	LastUpdated    time.Time `json:"last_updated"`
}

// DomainTableName is the table name for domains
const DomainTableName = "domains"

// NewDomainStorage creates a new domain storage instance
func NewDomainStorage(db *DB) *DomainStorage {
	return &DomainStorage{
		db:        db,
		tableName: DomainTableName,
	}
}

// =============================================================================
// Table Information
// =============================================================================

// GetTableInfo returns information about the domains table
func (s *DomainStorage) GetTableInfo() (*TableInfo, error) {
	return s.db.GetTableInfo(s.tableName)
}

// GetHeaders returns column names for the domains table
func (s *DomainStorage) GetHeaders() ([]string, error) {
	return s.db.GetColumnNames(s.tableName)
}

// TableExists checks if the domains table exists
func (s *DomainStorage) TableExists() (bool, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return false, err
	}
	return info.Exists, nil
}

// GetRowCount returns the number of records in the table
func (s *DomainStorage) GetRowCount() (int64, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return 0, err
	}
	return info.RowCount, nil
}

// =============================================================================
// Column Management
// =============================================================================

// AddColumn adds a new column to the domains table
func (s *DomainStorage) AddColumn(columnName, dataType, defaultValue string) error {
	return s.db.AddColumn(s.tableName, columnName, dataType, defaultValue)
}

// RemoveColumn removes a column from the domains table
func (s *DomainStorage) RemoveColumn(columnName string) error {
	return s.db.RemoveColumn(s.tableName, columnName)
}

// RenameColumn renames a column in the domains table
func (s *DomainStorage) RenameColumn(oldName, newName string) error {
	return s.db.RenameColumn(s.tableName, oldName, newName)
}

// =============================================================================
// CRUD Operations
// =============================================================================

// Insert adds a new domain record
func (s *DomainStorage) Insert(ctx context.Context, record *DomainRecord) error {
	query := `
		INSERT INTO domains (
			domain, tld, root_domain, is_malicious, threat_score,
			category, subcategory, registrar, phishing_target, 
			detection_count, sources, tags, status,
			first_seen, last_seen, last_updated
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)
		ON CONFLICT (domain) DO UPDATE SET
			is_malicious = EXCLUDED.is_malicious,
			threat_score = EXCLUDED.threat_score,
			category = EXCLUDED.category,
			detection_count = domains.detection_count + 1,
			last_seen = EXCLUDED.last_seen,
			last_updated = NOW()
	`

	_, err := s.db.ExecContext(ctx, query,
		record.Domain, record.TLD, record.RootDomain,
		record.IsMalicious, record.ThreatScore,
		record.Category, record.Subcategory, record.Registrar,
		record.PhishingTarget, record.DetectionCount,
		toJSONArray(record.Sources), toJSONArray(record.Tags),
		record.Status, record.FirstSeen, record.LastSeen, record.LastUpdated,
	)
	return err
}

// BulkInsert inserts multiple domain records efficiently
func (s *DomainStorage) BulkInsert(ctx context.Context, domains []string, source string, category string) (int64, error) {
	if len(domains) == 0 {
		return 0, nil
	}

	now := time.Now()
	columns := []string{
		"domain", "is_malicious", "threat_score", "category",
		"sources", "status", "first_seen", "last_seen", "last_updated",
	}

	values := make([][]interface{}, len(domains))
	for i, domain := range domains {
		values[i] = []interface{}{
			strings.ToLower(domain),
			true, // is_malicious
			50,   // default threat_score
			category,
			fmt.Sprintf(`["%s"]`, source), // sources as JSON array
			"active",
			now,
			now,
			now,
		}
	}

	return s.db.BulkInsert(s.tableName, columns, values)
}

// GetByDomain retrieves a domain record by domain name
func (s *DomainStorage) GetByDomain(ctx context.Context, domain string) (*DomainRecord, error) {
	query := `
		SELECT id, domain, tld, root_domain, is_malicious, threat_score,
			   category, subcategory, registrar, phishing_target,
			   detection_count, status, first_seen, last_seen, last_updated
		FROM domains
		WHERE domain = $1
	`

	var record DomainRecord
	err := s.db.QueryRowContext(ctx, query, domain).Scan(
		&record.ID, &record.Domain, &record.TLD, &record.RootDomain,
		&record.IsMalicious, &record.ThreatScore,
		&record.Category, &record.Subcategory, &record.Registrar,
		&record.PhishingTarget, &record.DetectionCount,
		&record.Status, &record.FirstSeen, &record.LastSeen, &record.LastUpdated,
	)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// Search searches domains by pattern
func (s *DomainStorage) Search(ctx context.Context, pattern string, limit int) ([]DomainRecord, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, domain, is_malicious, threat_score, category, status, last_seen
		FROM domains
		WHERE domain LIKE $1 OR domain LIKE $2
		ORDER BY threat_score DESC
		LIMIT $3
	`

	rows, err := s.db.QueryContext(ctx, query, pattern+"%", "%"+pattern+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []DomainRecord
	for rows.Next() {
		var r DomainRecord
		if err := rows.Scan(&r.ID, &r.Domain, &r.IsMalicious, &r.ThreatScore,
			&r.Category, &r.Status, &r.LastSeen); err != nil {
			continue
		}
		records = append(records, r)
	}

	return records, nil
}

// DeleteExpired removes expired domain records
func (s *DomainStorage) DeleteExpired(ctx context.Context, olderThan time.Duration) (int64, error) {
	query := `DELETE FROM domains WHERE last_seen < $1 AND status = 'expired'`
	result, err := s.db.ExecContext(ctx, query, time.Now().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Helper function to convert string slice to JSON array string
func toJSONArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	quoted := make([]string, len(arr))
	for i, s := range arr {
		quoted[i] = fmt.Sprintf(`"%s"`, s)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}
