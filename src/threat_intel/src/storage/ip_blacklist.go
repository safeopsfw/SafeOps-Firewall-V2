package storage

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// =============================================================================
// IP Blacklist Storage - Manages ip_blacklist table
// For malicious/blacklisted IPs (malware, botnets, C2, etc.)
// Can be used directly by any program
// =============================================================================

// IPBlacklistStorage handles malicious IP data
type IPBlacklistStorage struct {
	db        *DB
	tableName string
}

// IPBlacklistRecord represents an IP blacklist entry
type IPBlacklistRecord struct {
	ID                 int64      `json:"id"`
	IPAddress          string     `json:"ip_address"`
	IsMalicious        bool       `json:"is_malicious"`
	ThreatScore        int        `json:"threat_score"`
	ReputationScore    int        `json:"reputation_score"`
	AbuseType          string     `json:"abuse_type,omitempty"` // spam, malware, phishing, c2
	ThreatCategory     string     `json:"threat_category,omitempty"`
	MalwareFamily      string     `json:"malware_family,omitempty"`
	Confidence         int        `json:"confidence"`
	EvidenceCount      int        `json:"evidence_count"`
	FalsePositiveCount int        `json:"false_positive_count"`
	Description        string     `json:"description,omitempty"`
	Notes              string     `json:"notes,omitempty"`
	Sources            []string   `json:"sources"`
	Tags               []string   `json:"tags"`
	Status             string     `json:"status"` // active, expired, whitelisted
	FirstSeen          time.Time  `json:"first_seen"`
	LastSeen           time.Time  `json:"last_seen"`
	LastUpdated        time.Time  `json:"last_updated"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
}

// IPBlacklistTableName is the table name
const IPBlacklistTableName = "ip_blacklist"

// NewIPBlacklistStorage creates a new IP blacklist storage instance
func NewIPBlacklistStorage(db *DB) *IPBlacklistStorage {
	return &IPBlacklistStorage{
		db:        db,
		tableName: IPBlacklistTableName,
	}
}

// =============================================================================
// Table Information
// =============================================================================

// GetTableInfo returns information about the ip_blacklist table
func (s *IPBlacklistStorage) GetTableInfo() (*TableInfo, error) {
	return s.db.GetTableInfo(s.tableName)
}

// GetHeaders returns column names for the ip_blacklist table
func (s *IPBlacklistStorage) GetHeaders() ([]string, error) {
	return s.db.GetColumnNames(s.tableName)
}

// TableExists checks if the ip_blacklist table exists
func (s *IPBlacklistStorage) TableExists() (bool, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return false, err
	}
	return info.Exists, nil
}

// GetRowCount returns the number of records in the table
func (s *IPBlacklistStorage) GetRowCount() (int64, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return 0, err
	}
	return info.RowCount, nil
}

// =============================================================================
// Column Management
// =============================================================================

// AddColumn adds a new column to the ip_blacklist table
func (s *IPBlacklistStorage) AddColumn(columnName, dataType, defaultValue string) error {
	return s.db.AddColumn(s.tableName, columnName, dataType, defaultValue)
}

// RemoveColumn removes a column from the ip_blacklist table
func (s *IPBlacklistStorage) RemoveColumn(columnName string) error {
	return s.db.RemoveColumn(s.tableName, columnName)
}

// RenameColumn renames a column in the ip_blacklist table
func (s *IPBlacklistStorage) RenameColumn(oldName, newName string) error {
	return s.db.RenameColumn(s.tableName, oldName, newName)
}

// =============================================================================
// CRUD Operations
// =============================================================================

// Insert adds a new IP blacklist record
func (s *IPBlacklistStorage) Insert(ctx context.Context, record *IPBlacklistRecord) error {
	query := `
		INSERT INTO ip_blacklist (
			ip_address, is_malicious, threat_score, reputation_score,
			abuse_type, threat_category, malware_family, confidence,
			evidence_count, false_positive_count,
			description, notes, sources, tags, status,
			first_seen, last_seen, last_updated, expires_at
		) VALUES (
			$1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		)
		ON CONFLICT (ip_address) DO UPDATE SET
			is_malicious = EXCLUDED.is_malicious,
			threat_score = GREATEST(ip_blacklist.threat_score, EXCLUDED.threat_score),
			evidence_count = ip_blacklist.evidence_count + 1,
			last_seen = EXCLUDED.last_seen,
			last_updated = NOW()
	`

	_, err := s.db.ExecContext(ctx, query,
		record.IPAddress, record.IsMalicious, record.ThreatScore, record.ReputationScore,
		record.AbuseType, record.ThreatCategory, record.MalwareFamily, record.Confidence,
		record.EvidenceCount, record.FalsePositiveCount,
		record.Description, record.Notes,
		toJSONArray(record.Sources), toJSONArray(record.Tags),
		record.Status, record.FirstSeen, record.LastSeen, record.LastUpdated, record.ExpiresAt,
	)
	return err
}

// BulkInsert inserts multiple IP records efficiently
func (s *IPBlacklistStorage) BulkInsert(ctx context.Context, ips []string, source string, abuseType string) (int64, error) {
	if len(ips) == 0 {
		return 0, nil
	}

	now := time.Now()
	columns := []string{
		"ip_address", "is_malicious", "threat_score", "abuse_type",
		"sources", "status", "first_seen", "last_seen", "last_updated",
	}

	values := make([][]interface{}, len(ips))
	for i, ip := range ips {
		values[i] = []interface{}{
			ip,
			true, // is_malicious
			50,   // default threat_score
			abuseType,
			fmt.Sprintf(`["%s"]`, source), // sources as JSON array
			"active",
			now,
			now,
			now,
		}
	}

	return s.db.BulkInsert(s.tableName, columns, values)
}

// ReconcileResult holds reconciliation statistics
type ReconcileResult struct {
	Inserted int64
	Updated  int64
	Removed  int64
}

// Reconcile performs smart feed reconciliation for IP blacklist.
// 1. Upsert all current IPs from this feed (insert new, update existing)
// 2. Remove IPs that this feed no longer reports (but keep if other sources still report it)
func (s *IPBlacklistStorage) Reconcile(ctx context.Context, feedName string, ips []string, priority int) (*ReconcileResult, error) {
	result := &ReconcileResult{}
	if len(ips) == 0 {
		return result, nil
	}

	// Map priority to threat score
	threatScore := priorityToScore(priority)
	now := time.Now()

	// Step 1: Batch upsert current IPs
	columns := []string{
		"ip_address", "is_malicious", "threat_score", "abuse_type",
		"sources", "status", "first_seen", "last_seen", "last_updated",
	}
	values := make([][]interface{}, len(ips))
	for i, ip := range ips {
		values[i] = []interface{}{
			ip,
			true,
			threatScore,
			feedCategoryFromName(feedName),
			fmt.Sprintf(`["%s"]`, feedName),
			"active",
			now,
			now,
			now,
		}
	}

	updateExprs := map[string]string{
		"last_seen":      "NOW()",
		"last_updated":   "NOW()",
		"evidence_count": "ip_blacklist.evidence_count + 1",
		"threat_score":   fmt.Sprintf("GREATEST(ip_blacklist.threat_score, %d)", threatScore),
		"is_malicious":   "TRUE",
		"status":         "'active'",
		"sources":        fmt.Sprintf(`ip_blacklist.sources || '["%s"]'::jsonb`, feedName),
	}

	affected, err := s.db.BulkUpsert(s.tableName, columns, values, "ip_address", updateExprs)
	if err != nil {
		return result, fmt.Errorf("reconcile upsert failed: %w", err)
	}
	result.Updated = affected

	// Step 2: Remove IPs this feed no longer reports
	// Build a temp set of current IPs for the NOT IN check
	// For large feeds, use a temp table approach
	if len(ips) <= 10000 {
		// Small feed: use IN clause directly
		placeholders := make([]string, len(ips))
		args := make([]interface{}, len(ips)+1)
		args[0] = fmt.Sprintf(`["%s"]`, feedName) // for @> check
		for i, ip := range ips {
			placeholders[i] = fmt.Sprintf("$%d::inet", i+2)
			args[i+1] = ip
		}

		removeQuery := fmt.Sprintf(`
			DELETE FROM %s
			WHERE sources @> $1::jsonb
			AND ip_address NOT IN (%s)`,
			s.tableName,
			strings.Join(placeholders, ", "),
		)
		removeResult, err := s.db.ExecContext(ctx, removeQuery, args...)
		if err == nil {
			result.Removed, _ = removeResult.RowsAffected()
		}
	} else {
		// Large feed: batch the removal check
		// First get all IPs from this source
		existingQuery := fmt.Sprintf(`
			SELECT ip_address::text FROM %s WHERE sources @> $1::jsonb`,
			s.tableName,
		)
		rows, err := s.db.QueryContext(ctx, existingQuery, fmt.Sprintf(`["%s"]`, feedName))
		if err == nil {
			defer rows.Close()
			currentSet := make(map[string]bool, len(ips))
			for _, ip := range ips {
				currentSet[ip] = true
			}

			var toRemove []string
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil && !currentSet[ip] {
					toRemove = append(toRemove, ip)
				}
			}

			// Delete stale IPs in batches
			for i := 0; i < len(toRemove); i += 500 {
				end := i + 500
				if end > len(toRemove) {
					end = len(toRemove)
				}
				batch := toRemove[i:end]
				ph := make([]string, len(batch))
				args := make([]interface{}, len(batch))
				for j, ip := range batch {
					ph[j] = fmt.Sprintf("$%d::inet", j+1)
					args[j] = ip
				}
				delQuery := fmt.Sprintf(`DELETE FROM %s WHERE ip_address IN (%s)`,
					s.tableName, strings.Join(ph, ", "))
				delResult, err := s.db.ExecContext(ctx, delQuery, args...)
				if err == nil {
					removed, _ := delResult.RowsAffected()
					result.Removed += removed
				}
			}
		}
	}

	return result, nil
}

// priorityToScore maps feed priority (1-5) to threat score
func priorityToScore(priority int) int {
	switch priority {
	case 5:
		return 95
	case 4:
		return 80
	case 3:
		return 60
	case 2:
		return 40
	case 1:
		return 20
	default:
		return 50
	}
}

// feedCategoryFromName guesses abuse_type from feed name
func feedCategoryFromName(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "feodo") || strings.Contains(lower, "c2") || strings.Contains(lower, "botnet") {
		return "c2"
	}
	if strings.Contains(lower, "malware") || strings.Contains(lower, "bazaar") {
		return "malware"
	}
	if strings.Contains(lower, "ssl") {
		return "c2"
	}
	if strings.Contains(lower, "tor") {
		return "scanner"
	}
	if strings.Contains(lower, "firehol") || strings.Contains(lower, "emerging") {
		return "botnet"
	}
	return "unknown"
}

// GetByIP retrieves an IP blacklist record by IP address
func (s *IPBlacklistStorage) GetByIP(ctx context.Context, ip string) (*IPBlacklistRecord, error) {
	query := `
		SELECT id, ip_address::text, is_malicious, threat_score, reputation_score,
			   abuse_type, threat_category, malware_family, confidence,
			   evidence_count, false_positive_count, status,
			   first_seen, last_seen, last_updated
		FROM ip_blacklist
		WHERE ip_address = $1::inet
	`

	var record IPBlacklistRecord
	err := s.db.QueryRowContext(ctx, query, ip).Scan(
		&record.ID, &record.IPAddress, &record.IsMalicious,
		&record.ThreatScore, &record.ReputationScore,
		&record.AbuseType, &record.ThreatCategory, &record.MalwareFamily,
		&record.Confidence, &record.EvidenceCount, &record.FalsePositiveCount,
		&record.Status, &record.FirstSeen, &record.LastSeen, &record.LastUpdated,
	)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// CheckIP checks if an IP is blacklisted (quick lookup)
func (s *IPBlacklistStorage) CheckIP(ctx context.Context, ip string) (bool, int, error) {
	query := `
		SELECT is_malicious, threat_score 
		FROM ip_blacklist 
		WHERE ip_address = $1::inet AND status = 'active'
	`

	var isMalicious bool
	var score int
	err := s.db.QueryRowContext(ctx, query, ip).Scan(&isMalicious, &score)
	if err != nil {
		return false, 0, nil // Not found = not blacklisted
	}

	return isMalicious, score, nil
}

// Search searches IPs by pattern or abuse type
func (s *IPBlacklistStorage) Search(ctx context.Context, pattern string, limit int) ([]IPBlacklistRecord, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, ip_address::text, is_malicious, threat_score, abuse_type, status, last_seen
		FROM ip_blacklist
		WHERE ip_address::text LIKE $1 OR abuse_type ILIKE $2
		ORDER BY threat_score DESC
		LIMIT $3
	`

	rows, err := s.db.QueryContext(ctx, query, pattern+"%", "%"+pattern+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []IPBlacklistRecord
	for rows.Next() {
		var r IPBlacklistRecord
		if err := rows.Scan(&r.ID, &r.IPAddress, &r.IsMalicious, &r.ThreatScore,
			&r.AbuseType, &r.Status, &r.LastSeen); err != nil {
			continue
		}
		records = append(records, r)
	}

	return records, nil
}

// GetByAbuseType returns IPs of a specific abuse type
func (s *IPBlacklistStorage) GetByAbuseType(ctx context.Context, abuseType string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 1000
	}

	query := `
		SELECT ip_address::text 
		FROM ip_blacklist 
		WHERE abuse_type = $1 AND status = 'active'
		ORDER BY threat_score DESC
		LIMIT $2
	`

	rows, err := s.db.QueryContext(ctx, query, abuseType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// DeleteExpired removes expired IP records
func (s *IPBlacklistStorage) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM ip_blacklist WHERE expires_at IS NOT NULL AND expires_at < NOW()`
	result, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetAbuseTypes returns distinct abuse types
func (s *IPBlacklistStorage) GetAbuseTypes(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT abuse_type 
		FROM ip_blacklist 
		WHERE abuse_type IS NOT NULL AND abuse_type != ''
		ORDER BY abuse_type
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var types []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			continue
		}
		types = append(types, t)
	}

	return types, nil
}
