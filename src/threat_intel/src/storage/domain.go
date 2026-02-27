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

// BulkInsert upserts multiple domain records efficiently
// Uses ON CONFLICT to update existing domains instead of creating duplicates
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

	updateExprs := map[string]string{
		"is_malicious":    "TRUE",
		"threat_score":    "GREATEST(domains.threat_score, EXCLUDED.threat_score)",
		"detection_count": "domains.detection_count + 1",
		"last_seen":       "NOW()",
		"last_updated":    "NOW()",
		"status":          "'active'",
	}

	return s.db.BulkUpsert(s.tableName, columns, values, "domain", updateExprs)
}

// Reconcile performs smart feed reconciliation for domains.
// 1. Upsert all current domains from this feed (insert new, update existing)
// 2. Remove domains that this feed no longer reports
func (s *DomainStorage) Reconcile(ctx context.Context, feedName string, domains []string, priority int) (*ReconcileResult, error) {
	result := &ReconcileResult{}
	if len(domains) == 0 {
		return result, nil
	}

	threatScore := priorityToScore(priority)
	now := time.Now()
	category := domainCategoryFromFeed(feedName)

	// Step 1: Batch upsert current domains
	columns := []string{
		"domain", "is_malicious", "threat_score", "category",
		"sources", "status", "first_seen", "last_seen", "last_updated",
	}
	values := make([][]interface{}, len(domains))
	for i, d := range domains {
		values[i] = []interface{}{
			strings.ToLower(d),
			true,
			threatScore,
			category,
			fmt.Sprintf(`["%s"]`, feedName),
			"active",
			now,
			now,
			now,
		}
	}

	updateExprs := map[string]string{
		"last_seen":       "NOW()",
		"last_updated":    "NOW()",
		"detection_count": "domains.detection_count + 1",
		"threat_score":    fmt.Sprintf("GREATEST(domains.threat_score, %d)", threatScore),
		"is_malicious":    "TRUE",
		"status":          "'active'",
		"sources":         fmt.Sprintf(`domains.sources || '["%s"]'::jsonb`, feedName),
	}

	affected, err := s.db.BulkUpsert(s.tableName, columns, values, "domain", updateExprs)
	if err != nil {
		return result, fmt.Errorf("domain reconcile upsert failed: %w", err)
	}
	result.Updated = affected

	// Step 2: Remove domains this feed no longer reports
	// Get existing domains from this source, diff with current
	existingQuery := fmt.Sprintf(`
		SELECT domain FROM %s WHERE sources @> $1::jsonb`, s.tableName)
	rows, err := s.db.QueryContext(ctx, existingQuery, fmt.Sprintf(`["%s"]`, feedName))
	if err == nil {
		defer rows.Close()
		currentSet := make(map[string]bool, len(domains))
		for _, d := range domains {
			currentSet[strings.ToLower(d)] = true
		}

		var toRemove []string
		for rows.Next() {
			var d string
			if rows.Scan(&d) == nil && !currentSet[d] {
				toRemove = append(toRemove, d)
			}
		}

		// Delete stale domains in batches
		for i := 0; i < len(toRemove); i += 500 {
			end := i + 500
			if end > len(toRemove) {
				end = len(toRemove)
			}
			batch := toRemove[i:end]
			ph := make([]string, len(batch))
			args := make([]interface{}, len(batch))
			for j, d := range batch {
				ph[j] = fmt.Sprintf("$%d", j+1)
				args[j] = d
			}
			delQuery := fmt.Sprintf(`DELETE FROM %s WHERE domain IN (%s)`,
				s.tableName, strings.Join(ph, ", "))
			delResult, err := s.db.ExecContext(ctx, delQuery, args...)
			if err == nil {
				removed, _ := delResult.RowsAffected()
				result.Removed += removed
			}
		}
	}

	return result, nil
}

// domainCategoryFromFeed maps feed name to domain category
func domainCategoryFromFeed(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "phish") || strings.Contains(lower, "openphish") {
		return "phishing"
	}
	if strings.Contains(lower, "urlhaus") || strings.Contains(lower, "malware") {
		return "malware"
	}
	if strings.Contains(lower, "threatfox") {
		return "c2"
	}
	return "unknown"
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
