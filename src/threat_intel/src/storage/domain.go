package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

// ============================================================================
// Domain Storage - Connects with domain_intelligence table
// ============================================================================

// DomainStorage manages domain database operations.
// Provides CRUD operations for domain reputation data including phishing,
// malware, and C2 domains. Used by DNS filters, web proxies, and email gateways.
type DomainStorage struct {
	db             *DB
	batchSize      int
	minThreatScore int
	expiryDays     int
	logger         *log.Logger
}

// DomainRecord represents a domain intelligence entry matching domain_intelligence table
type DomainRecord struct {
	ID          int64          `json:"id"`
	Domain      string         `json:"domain"`
	ThreatScore int            `json:"threat_score"`
	Category    string         `json:"category"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Source      string         `json:"source"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// DomainStats holds domain database statistics
type DomainStats struct {
	TotalDomains       int64   `json:"total_domains"`
	PhishingCount      int64   `json:"phishing_count"`
	MalwareCount       int64   `json:"malware_count"`
	C2Count            int64   `json:"c2_count"`
	SpamCount          int64   `json:"spam_count"`
	AverageThreatScore float64 `json:"average_threat_score"`
}

// InsertStats tracks bulk insert operation results
type InsertStats struct {
	TotalProcessed int64 `json:"total_processed"`
	Inserted       int64 `json:"inserted"`
	Updated        int64 `json:"updated"`
	FilteredOut    int64 `json:"filtered_out"`
	Duplicates     int64 `json:"duplicates"`
	Errors         int64 `json:"errors"`
}

// ============================================================================
// Constructor & Domain Utilities
// ============================================================================

// NewDomainStorage creates a new domain storage handler
func NewDomainStorage(database *DB) *DomainStorage {
	return &DomainStorage{
		db:             database,
		batchSize:      getEnvIntOrDefault("DOMAIN_BATCH_SIZE", 1000),
		minThreatScore: getEnvIntOrDefault("DOMAIN_MIN_THREAT_SCORE", 30),
		expiryDays:     getEnvIntOrDefault("DOMAIN_EXPIRY_DAYS", 180),
		logger:         log.New(os.Stdout, "[DomainStorage] ", log.LstdFlags),
	}
}

// NormalizeDomain standardizes domain format (lowercase, removes protocol/www)
func NormalizeDomain(domain string) string {
	if domain == "" {
		return ""
	}

	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "ftp://")

	// Try parsing as URL to extract host
	if u, err := url.Parse("http://" + domain); err == nil && u.Host != "" {
		domain = u.Host
	}

	// Remove port if present
	if idx := strings.LastIndex(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove www prefix
	domain = strings.TrimPrefix(domain, "www.")

	// Lowercase and trim
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Remove trailing dots
	domain = strings.TrimSuffix(domain, ".")

	return domain
}

// ExtractTLD extracts top-level domain from a domain name
func ExtractTLD(domain string) string {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return ""
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}

	return parts[len(parts)-1]
}

// ExtractRootDomain extracts the root domain (e.g., "example.com" from "sub.example.com")
func ExtractRootDomain(domain string) string {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return ""
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}

	// Handle common multi-part TLDs (e.g., .co.uk, .com.br)
	multiPartTLDs := map[string]bool{
		"co.uk": true, "org.uk": true, "com.au": true, "com.br": true,
		"co.jp": true, "co.nz": true, "co.za": true, "com.cn": true,
	}

	if len(parts) >= 3 {
		possibleTLD := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if multiPartTLDs[possibleTLD] {
			return parts[len(parts)-3] + "." + possibleTLD
		}
	}

	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// ============================================================================
// Single Record Operations
// ============================================================================

// InsertDomain inserts a single domain record into domain_intelligence table
func (ds *DomainStorage) InsertDomain(record *DomainRecord) error {
	if record == nil || record.Domain == "" {
		return fmt.Errorf("invalid domain record: domain is required")
	}

	// Normalize domain
	record.Domain = NormalizeDomain(record.Domain)
	if record.Domain == "" {
		return fmt.Errorf("invalid domain after normalization")
	}

	// Check minimum threat score threshold
	if record.ThreatScore < ds.minThreatScore {
		ds.logger.Printf("Domain %s filtered: threat_score %d < min %d",
			record.Domain, record.ThreatScore, ds.minThreatScore)
		return nil // Not an error, just filtered
	}

	// Set timestamps
	now := time.Now()
	if record.FirstSeen.IsZero() {
		record.FirstSeen = now
	}
	record.LastSeen = now

	// Convert metadata to JSONB
	metadataJSON, err := json.Marshal(record.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO domain_intelligence (domain, threat_score, category, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = ds.db.ExecuteInsert(query,
		record.Domain, record.ThreatScore, record.Category,
		record.Source, string(metadataJSON), record.FirstSeen, record.LastSeen,
	)

	if err != nil {
		return fmt.Errorf("failed to insert domain %s: %w", record.Domain, err)
	}

	ds.logger.Printf("Inserted domain: %s (threat_score=%d, category=%s)",
		record.Domain, record.ThreatScore, record.Category)
	return nil
}

// UpsertDomain inserts or updates a domain record if it already exists
func (ds *DomainStorage) UpsertDomain(record *DomainRecord) error {
	if record == nil || record.Domain == "" {
		return fmt.Errorf("invalid domain record: domain is required")
	}

	// Normalize and validate
	record.Domain = NormalizeDomain(record.Domain)
	if record.Domain == "" {
		return fmt.Errorf("invalid domain after normalization")
	}

	now := time.Now()
	if record.FirstSeen.IsZero() {
		record.FirstSeen = now
	}
	record.LastSeen = now

	// Convert metadata to JSONB
	metadataJSON, err := json.Marshal(record.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO domain_intelligence (domain, threat_score, category, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (domain) DO UPDATE SET
			threat_score = CASE 
				WHEN EXCLUDED.threat_score > domain_intelligence.threat_score 
				THEN EXCLUDED.threat_score 
				ELSE domain_intelligence.threat_score 
			END,
			category = COALESCE(EXCLUDED.category, domain_intelligence.category),
			last_seen = EXCLUDED.last_seen,
			updated_at = NOW(),
			metadata = COALESCE(EXCLUDED.metadata, domain_intelligence.metadata)`

	_, err = ds.db.ExecuteInsert(query,
		record.Domain, record.ThreatScore, record.Category,
		record.Source, string(metadataJSON), record.FirstSeen, record.LastSeen,
	)

	if err != nil {
		return fmt.Errorf("failed to upsert domain %s: %w", record.Domain, err)
	}

	ds.logger.Printf("Upserted domain: %s", record.Domain)
	return nil
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkInsertDomains efficiently inserts multiple domain records in batches
func (ds *DomainStorage) BulkInsertDomains(records []*DomainRecord) (*InsertStats, error) {
	stats := &InsertStats{
		TotalProcessed: int64(len(records)),
	}

	if len(records) == 0 {
		return stats, nil
	}

	// Filter records by minimum threat score
	var filtered []*DomainRecord
	for _, record := range records {
		if record == nil || record.Domain == "" {
			stats.Errors++
			continue
		}

		record.Domain = NormalizeDomain(record.Domain)
		if record.Domain == "" {
			stats.Errors++
			continue
		}

		if record.ThreatScore < ds.minThreatScore {
			stats.FilteredOut++
			continue
		}

		filtered = append(filtered, record)
	}

	if len(filtered) == 0 {
		return stats, nil
	}

	// Process in batches
	for i := 0; i < len(filtered); i += ds.batchSize {
		end := i + ds.batchSize
		if end > len(filtered) {
			end = len(filtered)
		}
		batch := filtered[i:end]

		inserted, err := ds.insertBatch(batch)
		if err != nil {
			ds.logger.Printf("Batch insert error: %v", err)
			stats.Errors += int64(len(batch))
			continue
		}
		stats.Inserted += inserted
	}

	ds.logger.Printf("Bulk insert completed: %d inserted, %d filtered, %d errors",
		stats.Inserted, stats.FilteredOut, stats.Errors)

	return stats, nil
}

// insertBatch inserts a batch of records within a transaction
func (ds *DomainStorage) insertBatch(batch []*DomainRecord) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tx, err := ds.db.BeginTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	query := `
		INSERT INTO domain_intelligence (domain, threat_score, category, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (domain) DO UPDATE SET
			threat_score = GREATEST(domain_intelligence.threat_score, EXCLUDED.threat_score),
			last_seen = EXCLUDED.last_seen,
			updated_at = NOW()`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	var inserted int64
	now := time.Now()

	for _, record := range batch {
		metadataJSON, _ := json.Marshal(record.Metadata)

		_, err := stmt.ExecContext(ctx,
			record.Domain, record.ThreatScore, record.Category,
			record.Source, string(metadataJSON), now, now,
		)
		if err != nil {
			ds.logger.Printf("Row insert error for %s: %v", record.Domain, err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return inserted, nil
}

// BulkUpsertDomains performs bulk upsert of domain records (uses same logic with ON CONFLICT)
func (ds *DomainStorage) BulkUpsertDomains(records []*DomainRecord) (*InsertStats, error) {
	return ds.BulkInsertDomains(records)
}

// ============================================================================
// Query Operations
// ============================================================================

// GetDomain retrieves domain data for a specific domain name
func (ds *DomainStorage) GetDomain(domain string) (*DomainRecord, error) {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("invalid domain")
	}

	query := `
		SELECT id, domain, threat_score, category, first_seen, last_seen, updated_at, source, metadata
		FROM domain_intelligence 
		WHERE domain = $1`

	row := ds.db.QueryRow(query, domain)

	record := &DomainRecord{}
	var metadataJSON sql.NullString
	var updatedAt sql.NullTime

	err := row.Scan(
		&record.ID, &record.Domain, &record.ThreatScore, &record.Category,
		&record.FirstSeen, &record.LastSeen, &updatedAt, &record.Source, &metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %w", err)
	}

	if updatedAt.Valid {
		record.UpdatedAt = updatedAt.Time
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &record.Metadata)
	}

	return record, nil
}

// GetDomainsByThreatScore retrieves domains above specified threat score
func (ds *DomainStorage) GetDomainsByThreatScore(minScore, limit int) ([]*DomainRecord, error) {
	query := `
		SELECT id, domain, threat_score, category, first_seen, last_seen, source
		FROM domain_intelligence 
		WHERE threat_score >= $1 
		ORDER BY threat_score DESC 
		LIMIT $2`

	rows, err := ds.db.ExecuteQuery(query, minScore, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query domains: %w", err)
	}
	defer rows.Close()

	var records []*DomainRecord
	for rows.Next() {
		record := &DomainRecord{}
		err := rows.Scan(
			&record.ID, &record.Domain, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetDomainsByCategory retrieves domains by threat category
func (ds *DomainStorage) GetDomainsByCategory(category string, limit int) ([]*DomainRecord, error) {
	query := `
		SELECT id, domain, threat_score, category, first_seen, last_seen, source
		FROM domain_intelligence 
		WHERE category = $1
		ORDER BY threat_score DESC
		LIMIT $2`

	rows, err := ds.db.ExecuteQuery(query, category, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query domains by category: %w", err)
	}
	defer rows.Close()

	var records []*DomainRecord
	for rows.Next() {
		record := &DomainRecord{}
		err := rows.Scan(
			&record.ID, &record.Domain, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetDomainsBySource retrieves domains from a specific threat intel source
func (ds *DomainStorage) GetDomainsBySource(source string, limit int) ([]*DomainRecord, error) {
	query := `
		SELECT id, domain, threat_score, category, first_seen, last_seen, source
		FROM domain_intelligence 
		WHERE source = $1
		ORDER BY last_seen DESC
		LIMIT $2`

	rows, err := ds.db.ExecuteQuery(query, source, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query domains by source: %w", err)
	}
	defer rows.Close()

	var records []*DomainRecord
	for rows.Next() {
		record := &DomainRecord{}
		err := rows.Scan(
			&record.ID, &record.Domain, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetRecentDomains retrieves recently seen domains
func (ds *DomainStorage) GetRecentDomains(hours int, limit int) ([]*DomainRecord, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	query := `
		SELECT id, domain, threat_score, category, first_seen, last_seen, source
		FROM domain_intelligence 
		WHERE last_seen >= $1
		ORDER BY last_seen DESC
		LIMIT $2`

	rows, err := ds.db.ExecuteQuery(query, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent domains: %w", err)
	}
	defer rows.Close()

	var records []*DomainRecord
	for rows.Next() {
		record := &DomainRecord{}
		err := rows.Scan(
			&record.ID, &record.Domain, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// SearchDomains performs a pattern search on domains (use % for wildcards)
func (ds *DomainStorage) SearchDomains(pattern string, limit int) ([]*DomainRecord, error) {
	query := `
		SELECT id, domain, threat_score, category, first_seen, last_seen, source
		FROM domain_intelligence 
		WHERE domain LIKE $1
		ORDER BY threat_score DESC
		LIMIT $2`

	rows, err := ds.db.ExecuteQuery(query, pattern, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search domains: %w", err)
	}
	defer rows.Close()

	var records []*DomainRecord
	for rows.Next() {
		record := &DomainRecord{}
		err := rows.Scan(
			&record.ID, &record.Domain, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// ============================================================================
// Update & Delete Operations
// ============================================================================

// UpdateDomainThreatScore updates the threat score of a domain
func (ds *DomainStorage) UpdateDomainThreatScore(domain string, newScore int) error {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("invalid domain")
	}

	query := `UPDATE domain_intelligence SET threat_score = $1, updated_at = NOW() WHERE domain = $2`

	affected, err := ds.db.ExecuteUpdate(query, newScore, domain)
	if err != nil {
		return fmt.Errorf("failed to update threat score: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("domain not found: %s", domain)
	}

	ds.logger.Printf("Updated domain %s threat_score to: %d", domain, newScore)
	return nil
}

// UpdateDomainCategory updates the category of a domain
func (ds *DomainStorage) UpdateDomainCategory(domain, category string) error {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("invalid domain")
	}

	query := `UPDATE domain_intelligence SET category = $1, updated_at = NOW() WHERE domain = $2`

	affected, err := ds.db.ExecuteUpdate(query, category, domain)
	if err != nil {
		return fmt.Errorf("failed to update category: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("domain not found: %s", domain)
	}

	ds.logger.Printf("Updated domain %s category to: %s", domain, category)
	return nil
}

// DeleteDomain removes a domain from the database
func (ds *DomainStorage) DeleteDomain(domain string) error {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("invalid domain")
	}

	query := `DELETE FROM domain_intelligence WHERE domain = $1`

	affected, err := ds.db.ExecuteDelete(query, domain)
	if err != nil {
		return fmt.Errorf("failed to delete domain: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("domain not found: %s", domain)
	}

	ds.logger.Printf("Deleted domain: %s", domain)
	return nil
}

// DeleteOldDomains removes domains not seen since specified number of days
func (ds *DomainStorage) DeleteOldDomains(daysOld int) (int64, error) {
	if daysOld <= 0 {
		daysOld = ds.expiryDays
	}

	cutoffDate := time.Now().AddDate(0, 0, -daysOld)

	query := `DELETE FROM domain_intelligence WHERE last_seen < $1`

	affected, err := ds.db.ExecuteDelete(query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old domains: %w", err)
	}

	ds.logger.Printf("Deleted %d domains older than %d days", affected, daysOld)
	return affected, nil
}

// ============================================================================
// Statistics Operations
// ============================================================================

// GetDomainStats returns statistics about domain data
func (ds *DomainStorage) GetDomainStats() (*DomainStats, error) {
	stats := &DomainStats{}

	// Total domains
	err := ds.db.QueryRow(`SELECT COUNT(*) FROM domain_intelligence`).Scan(&stats.TotalDomains)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to count domains: %w", err)
	}

	// Phishing count
	ds.db.QueryRow(`SELECT COUNT(*) FROM domain_intelligence WHERE category = 'phishing'`).Scan(&stats.PhishingCount)

	// Malware count
	ds.db.QueryRow(`SELECT COUNT(*) FROM domain_intelligence WHERE category = 'malware'`).Scan(&stats.MalwareCount)

	// C2 count
	ds.db.QueryRow(`SELECT COUNT(*) FROM domain_intelligence WHERE category = 'c2'`).Scan(&stats.C2Count)

	// Spam count
	ds.db.QueryRow(`SELECT COUNT(*) FROM domain_intelligence WHERE category = 'spam'`).Scan(&stats.SpamCount)

	// Average threat score
	ds.db.QueryRow(`SELECT COALESCE(AVG(threat_score), 0) FROM domain_intelligence`).Scan(&stats.AverageThreatScore)

	return stats, nil
}

// GetDomainCount returns total count of domains in database
func (ds *DomainStorage) GetDomainCount() (int64, error) {
	var count int64
	err := ds.db.QueryRow(`SELECT COUNT(*) FROM domain_intelligence`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count domains: %w", err)
	}
	return count, nil
}

// ============================================================================
// Legacy Compatibility Methods (for existing code using DB methods directly)
// ============================================================================

// StoreDomain stores domain intelligence data (legacy compatibility method on DB)
func (db *DB) StoreDomain(domain, category, source string, threatScore int, metadata string) error {
	domain = NormalizeDomain(domain)

	query := `
		INSERT INTO domain_intelligence (domain, threat_score, category, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (domain) 
		DO UPDATE SET 
			threat_score = EXCLUDED.threat_score,
			category = EXCLUDED.category,
			last_seen = EXCLUDED.last_seen,
			updated_at = NOW()
	`

	now := time.Now()
	_, err := db.conn.Exec(query, domain, threatScore, category, source, metadata, now, now)
	if err != nil {
		return fmt.Errorf("failed to store domain: %w", err)
	}

	return nil
}

// GetDomainByName retrieves domain data (legacy compatibility method on DB)
func (db *DB) GetDomainByName(domain string) (map[string]interface{}, error) {
	domain = NormalizeDomain(domain)

	query := `
		SELECT domain, threat_score, category, first_seen, last_seen, source
		FROM domain_intelligence 
		WHERE domain = $1`

	row := db.QueryRow(query, domain)

	var domainVal, category, source string
	var threatScore int
	var firstSeen, lastSeen time.Time

	err := row.Scan(&domainVal, &threatScore, &category, &firstSeen, &lastSeen, &source)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %w", err)
	}

	result := map[string]interface{}{
		"domain":       domainVal,
		"threat_score": threatScore,
		"category":     category,
		"first_seen":   firstSeen,
		"last_seen":    lastSeen,
		"source":       source,
	}

	return result, nil
}
