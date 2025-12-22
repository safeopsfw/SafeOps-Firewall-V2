package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// ============================================================================
// IP Blacklist Storage - Connects with ip_blacklist table
// ============================================================================

// IPBlacklistStorage manages IP blacklist database operations.
// Stores IPs flagged by threat feeds with threat scores, abuse types, and metadata.
// Primary table for IP-based threat blocking, most frequently queried by security tools.
type IPBlacklistStorage struct {
	db             *DB
	batchSize      int
	minThreatScore int
	expiryDays     int
	logger         *log.Logger
}

// BlacklistRecord represents an IP blacklist entry matching ip_blacklist table
type BlacklistRecord struct {
	ID          int64          `json:"id"`
	IPAddress   string         `json:"ip_address"`
	ThreatScore int            `json:"threat_score"`
	Category    string         `json:"category"` // c2, ransomware, phishing, malware, spam, bruteforce
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Source      string         `json:"source"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// BlacklistStats holds IP blacklist database statistics
type BlacklistStats struct {
	TotalIPs           int64            `json:"total_ips"`
	HighThreatCount    int64            `json:"high_threat_count"`   // score >= 80
	MediumThreatCount  int64            `json:"medium_threat_count"` // score 50-79
	LowThreatCount     int64            `json:"low_threat_count"`    // score < 50
	AverageThreatScore float64          `json:"average_threat_score"`
	CategoryCounts     map[string]int64 `json:"category_counts"`
}

// BlacklistInsertStats tracks bulk insert operation results
type BlacklistInsertStats struct {
	TotalProcessed int64 `json:"total_processed"`
	Inserted       int64 `json:"inserted"`
	Updated        int64 `json:"updated"`
	FilteredOut    int64 `json:"filtered_out"`
	Errors         int64 `json:"errors"`
}

// ============================================================================
// Constructor & Validation Utilities
// ============================================================================

// NewIPBlacklistStorage creates a new IP blacklist storage handler
func NewIPBlacklistStorage(database *DB) *IPBlacklistStorage {
	return &IPBlacklistStorage{
		db:             database,
		batchSize:      getEnvIntOrDefault("BLACKLIST_BATCH_SIZE", 1000),
		minThreatScore: getEnvIntOrDefault("BLACKLIST_MIN_THREAT_SCORE", 30),
		expiryDays:     getEnvIntOrDefault("BLACKLIST_EXPIRY_DAYS", 90),
		logger:         log.New(os.Stdout, "[IPBlacklistStorage] ", log.LstdFlags),
	}
}

// ValidateIPAddress validates an IP address format (IPv4 or IPv6)
func ValidateIPAddress(ipAddress string) bool {
	return net.ParseIP(ipAddress) != nil
}

// ValidateThreatScore validates threat score is within valid range (0-100)
func ValidateThreatScore(score int) bool {
	return score >= 0 && score <= 100
}

// ValidateCategory validates IP category is a known type
func ValidateCategory(category string) bool {
	validCategories := map[string]bool{
		"c2": true, "ransomware": true, "phishing": true, "malware": true,
		"spam": true, "bruteforce": true, "botnet": true, "scanner": true,
		"proxy": true, "tor": true, "vpn": true, "unknown": true, "": true,
	}
	return validCategories[category]
}

// ============================================================================
// Single Record Operations
// ============================================================================

// InsertBlacklistedIP inserts a single malicious IP record into database
func (bs *IPBlacklistStorage) InsertBlacklistedIP(record *BlacklistRecord) error {
	if record == nil || record.IPAddress == "" {
		return fmt.Errorf("invalid blacklist record: IP address is required")
	}

	// Validate IP address
	if !ValidateIPAddress(record.IPAddress) {
		return fmt.Errorf("invalid IP address format: %s", record.IPAddress)
	}

	// Check minimum threat score threshold
	if record.ThreatScore < bs.minThreatScore {
		bs.logger.Printf("IP %s filtered: threat_score %d < min %d",
			record.IPAddress, record.ThreatScore, bs.minThreatScore)
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
		INSERT INTO ip_blacklist (ip_address, threat_score, category, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = bs.db.ExecuteInsert(query,
		record.IPAddress, record.ThreatScore, record.Category,
		record.Source, string(metadataJSON), record.FirstSeen, record.LastSeen,
	)

	if err != nil {
		return fmt.Errorf("failed to insert blacklisted IP %s: %w", record.IPAddress, err)
	}

	bs.logger.Printf("Inserted blacklisted IP: %s (threat_score=%d, category=%s)",
		record.IPAddress, record.ThreatScore, record.Category)
	return nil
}

// UpsertBlacklistedIP inserts or updates a blacklist record if IP already exists
func (bs *IPBlacklistStorage) UpsertBlacklistedIP(record *BlacklistRecord) error {
	if record == nil || record.IPAddress == "" {
		return fmt.Errorf("invalid blacklist record: IP address is required")
	}

	// Validate IP address
	if !ValidateIPAddress(record.IPAddress) {
		return fmt.Errorf("invalid IP address format: %s", record.IPAddress)
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
		INSERT INTO ip_blacklist (ip_address, threat_score, category, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (ip_address) DO UPDATE SET
			threat_score = CASE 
				WHEN EXCLUDED.threat_score > ip_blacklist.threat_score 
				THEN EXCLUDED.threat_score 
				ELSE ip_blacklist.threat_score 
			END,
			category = COALESCE(EXCLUDED.category, ip_blacklist.category),
			last_seen = EXCLUDED.last_seen,
			updated_at = NOW(),
			metadata = COALESCE(EXCLUDED.metadata, ip_blacklist.metadata)`

	_, err = bs.db.ExecuteInsert(query,
		record.IPAddress, record.ThreatScore, record.Category,
		record.Source, string(metadataJSON), record.FirstSeen, record.LastSeen,
	)

	if err != nil {
		return fmt.Errorf("failed to upsert blacklisted IP %s: %w", record.IPAddress, err)
	}

	bs.logger.Printf("Upserted blacklisted IP: %s", record.IPAddress)
	return nil
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkInsertBlacklistedIPs efficiently inserts multiple blacklist records in batches
func (bs *IPBlacklistStorage) BulkInsertBlacklistedIPs(records []*BlacklistRecord) (*BlacklistInsertStats, error) {
	stats := &BlacklistInsertStats{
		TotalProcessed: int64(len(records)),
	}

	if len(records) == 0 {
		return stats, nil
	}

	// Filter records by minimum threat score
	var filtered []*BlacklistRecord
	for _, record := range records {
		if record == nil || record.IPAddress == "" {
			stats.Errors++
			continue
		}

		if !ValidateIPAddress(record.IPAddress) {
			stats.Errors++
			continue
		}

		if record.ThreatScore < bs.minThreatScore {
			stats.FilteredOut++
			continue
		}

		filtered = append(filtered, record)
	}

	if len(filtered) == 0 {
		return stats, nil
	}

	// Process in batches
	for i := 0; i < len(filtered); i += bs.batchSize {
		end := i + bs.batchSize
		if end > len(filtered) {
			end = len(filtered)
		}
		batch := filtered[i:end]

		inserted, err := bs.insertBlacklistBatch(batch)
		if err != nil {
			bs.logger.Printf("Batch insert error: %v", err)
			stats.Errors += int64(len(batch))
			continue
		}
		stats.Inserted += inserted
	}

	bs.logger.Printf("Bulk blacklist insert completed: %d inserted, %d filtered, %d errors",
		stats.Inserted, stats.FilteredOut, stats.Errors)

	return stats, nil
}

// insertBlacklistBatch inserts a batch of records within a transaction
func (bs *IPBlacklistStorage) insertBlacklistBatch(batch []*BlacklistRecord) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tx, err := bs.db.BeginTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	query := `
		INSERT INTO ip_blacklist (ip_address, threat_score, category, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (ip_address) DO UPDATE SET
			threat_score = GREATEST(ip_blacklist.threat_score, EXCLUDED.threat_score),
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
			record.IPAddress, record.ThreatScore, record.Category,
			record.Source, string(metadataJSON), now, now,
		)
		if err != nil {
			bs.logger.Printf("Row insert error for %s: %v", record.IPAddress, err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return inserted, nil
}

// BulkUpsertBlacklistedIPs performs bulk upsert of blacklist records
func (bs *IPBlacklistStorage) BulkUpsertBlacklistedIPs(records []*BlacklistRecord) (*BlacklistInsertStats, error) {
	return bs.BulkInsertBlacklistedIPs(records) // Uses same logic with ON CONFLICT
}

// ============================================================================
// Query Operations
// ============================================================================

// GetBlacklistedIP retrieves blacklist data for a specific IP address
func (bs *IPBlacklistStorage) GetBlacklistedIP(ipAddress string) (*BlacklistRecord, error) {
	if !ValidateIPAddress(ipAddress) {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `
		SELECT id, ip_address, threat_score, category, first_seen, last_seen, updated_at, source, metadata
		FROM ip_blacklist 
		WHERE ip_address = $1`

	row := bs.db.QueryRow(query, ipAddress)

	record := &BlacklistRecord{}
	var metadataJSON sql.NullString
	var updatedAt sql.NullTime

	err := row.Scan(
		&record.ID, &record.IPAddress, &record.ThreatScore, &record.Category,
		&record.FirstSeen, &record.LastSeen, &updatedAt, &record.Source, &metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found (not an error for blacklist lookups)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get blacklisted IP: %w", err)
	}

	if updatedAt.Valid {
		record.UpdatedAt = updatedAt.Time
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &record.Metadata)
	}

	return record, nil
}

// IsBlacklisted checks if an IP is in the blacklist (fast boolean check)
func (bs *IPBlacklistStorage) IsBlacklisted(ipAddress string) (bool, error) {
	if !ValidateIPAddress(ipAddress) {
		return false, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `SELECT EXISTS(SELECT 1 FROM ip_blacklist WHERE ip_address = $1)`

	var exists bool
	err := bs.db.QueryRow(query, ipAddress).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}

	return exists, nil
}

// GetBlacklistedIPsByThreatScore retrieves IPs above specified threat score
func (bs *IPBlacklistStorage) GetBlacklistedIPsByThreatScore(minScore, limit int) ([]*BlacklistRecord, error) {
	query := `
		SELECT id, ip_address, threat_score, category, first_seen, last_seen, source
		FROM ip_blacklist 
		WHERE threat_score >= $1 
		ORDER BY threat_score DESC 
		LIMIT $2`

	rows, err := bs.db.ExecuteQuery(query, minScore, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query blacklisted IPs: %w", err)
	}
	defer rows.Close()

	var records []*BlacklistRecord
	for rows.Next() {
		record := &BlacklistRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetBlacklistedIPsByCategory retrieves IPs by abuse/threat category
func (bs *IPBlacklistStorage) GetBlacklistedIPsByCategory(category string, limit int) ([]*BlacklistRecord, error) {
	query := `
		SELECT id, ip_address, threat_score, category, first_seen, last_seen, source
		FROM ip_blacklist 
		WHERE category = $1
		ORDER BY threat_score DESC
		LIMIT $2`

	rows, err := bs.db.ExecuteQuery(query, category, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query blacklisted IPs by category: %w", err)
	}
	defer rows.Close()

	var records []*BlacklistRecord
	for rows.Next() {
		record := &BlacklistRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetBlacklistedIPsBySource retrieves IPs from a specific threat intel source
func (bs *IPBlacklistStorage) GetBlacklistedIPsBySource(source string, limit int) ([]*BlacklistRecord, error) {
	query := `
		SELECT id, ip_address, threat_score, category, first_seen, last_seen, source
		FROM ip_blacklist 
		WHERE source = $1
		ORDER BY last_seen DESC
		LIMIT $2`

	rows, err := bs.db.ExecuteQuery(query, source, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query blacklisted IPs by source: %w", err)
	}
	defer rows.Close()

	var records []*BlacklistRecord
	for rows.Next() {
		record := &BlacklistRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetRecentBlacklistedIPs retrieves recently added malicious IPs
func (bs *IPBlacklistStorage) GetRecentBlacklistedIPs(days int, limit int) ([]*BlacklistRecord, error) {
	cutoff := time.Now().AddDate(0, 0, -days)

	query := `
		SELECT id, ip_address, threat_score, category, first_seen, last_seen, source
		FROM ip_blacklist 
		WHERE first_seen >= $1
		ORDER BY first_seen DESC
		LIMIT $2`

	rows, err := bs.db.ExecuteQuery(query, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent blacklisted IPs: %w", err)
	}
	defer rows.Close()

	var records []*BlacklistRecord
	for rows.Next() {
		record := &BlacklistRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetActiveBlacklistedIPs retrieves IPs seen within specified hours
func (bs *IPBlacklistStorage) GetActiveBlacklistedIPs(hours int, limit int) ([]*BlacklistRecord, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	query := `
		SELECT id, ip_address, threat_score, category, first_seen, last_seen, source
		FROM ip_blacklist 
		WHERE last_seen >= $1
		ORDER BY last_seen DESC
		LIMIT $2`

	rows, err := bs.db.ExecuteQuery(query, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query active blacklisted IPs: %w", err)
	}
	defer rows.Close()

	var records []*BlacklistRecord
	for rows.Next() {
		record := &BlacklistRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.ThreatScore,
			&record.Category, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetCriticalThreatIPs retrieves IPs with critical threat score (>= 80)
func (bs *IPBlacklistStorage) GetCriticalThreatIPs(limit int) ([]*BlacklistRecord, error) {
	return bs.GetBlacklistedIPsByThreatScore(80, limit)
}

// SearchBlacklistedIPs performs a pattern search on IPs (useful for CIDR-like searches)
func (bs *IPBlacklistStorage) SearchBlacklistedIPs(pattern string, limit int) ([]*BlacklistRecord, error) {
	query := `
		SELECT id, ip_address, threat_score, category, first_seen, last_seen, source
		FROM ip_blacklist 
		WHERE ip_address::text LIKE $1
		ORDER BY threat_score DESC
		LIMIT $2`

	rows, err := bs.db.ExecuteQuery(query, pattern, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search blacklisted IPs: %w", err)
	}
	defer rows.Close()

	var records []*BlacklistRecord
	for rows.Next() {
		record := &BlacklistRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.ThreatScore,
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

// UpdateBlacklistThreatScore updates the threat score of a blacklisted IP
func (bs *IPBlacklistStorage) UpdateBlacklistThreatScore(ipAddress string, newScore int) error {
	if !ValidateIPAddress(ipAddress) {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	if !ValidateThreatScore(newScore) {
		return fmt.Errorf("invalid threat score: %d (must be 0-100)", newScore)
	}

	query := `UPDATE ip_blacklist SET threat_score = $1, updated_at = NOW() WHERE ip_address = $2`

	affected, err := bs.db.ExecuteUpdate(query, newScore, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to update threat score: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	bs.logger.Printf("Updated IP %s threat_score to: %d", ipAddress, newScore)
	return nil
}

// UpdateBlacklistCategory updates the category of a blacklisted IP
func (bs *IPBlacklistStorage) UpdateBlacklistCategory(ipAddress, category string) error {
	if !ValidateIPAddress(ipAddress) {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `UPDATE ip_blacklist SET category = $1, updated_at = NOW() WHERE ip_address = $2`

	affected, err := bs.db.ExecuteUpdate(query, category, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to update category: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	bs.logger.Printf("Updated IP %s category to: %s", ipAddress, category)
	return nil
}

// ReduceThreatScore reduces the threat score (for false positive feedback)
func (bs *IPBlacklistStorage) ReduceThreatScore(ipAddress string, reduction int) error {
	if !ValidateIPAddress(ipAddress) {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `
		UPDATE ip_blacklist 
		SET threat_score = GREATEST(0, threat_score - $1), updated_at = NOW() 
		WHERE ip_address = $2`

	affected, err := bs.db.ExecuteUpdate(query, reduction, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to reduce threat score: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	bs.logger.Printf("Reduced IP %s threat_score by: %d", ipAddress, reduction)
	return nil
}

// DeleteBlacklistedIP removes an IP from the blacklist
func (bs *IPBlacklistStorage) DeleteBlacklistedIP(ipAddress string) error {
	if !ValidateIPAddress(ipAddress) {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `DELETE FROM ip_blacklist WHERE ip_address = $1`

	affected, err := bs.db.ExecuteDelete(query, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to delete blacklisted IP: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	bs.logger.Printf("Deleted blacklisted IP: %s", ipAddress)
	return nil
}

// DeleteOldBlacklistEntries removes entries not seen since specified days
func (bs *IPBlacklistStorage) DeleteOldBlacklistEntries(daysOld int) (int64, error) {
	if daysOld <= 0 {
		daysOld = bs.expiryDays
	}

	cutoffDate := time.Now().AddDate(0, 0, -daysOld)

	query := `DELETE FROM ip_blacklist WHERE last_seen < $1`

	affected, err := bs.db.ExecuteDelete(query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old blacklist entries: %w", err)
	}

	bs.logger.Printf("Deleted %d blacklist entries older than %d days", affected, daysOld)
	return affected, nil
}

// DeleteLowScoreEntries removes entries with threat score below threshold
func (bs *IPBlacklistStorage) DeleteLowScoreEntries(maxScore int) (int64, error) {
	query := `DELETE FROM ip_blacklist WHERE threat_score < $1`

	affected, err := bs.db.ExecuteDelete(query, maxScore)
	if err != nil {
		return 0, fmt.Errorf("failed to delete low score entries: %w", err)
	}

	bs.logger.Printf("Deleted %d blacklist entries with threat_score < %d", affected, maxScore)
	return affected, nil
}

// ============================================================================
// Statistics Operations
// ============================================================================

// GetBlacklistStats returns statistics about IP blacklist data
func (bs *IPBlacklistStorage) GetBlacklistStats() (*BlacklistStats, error) {
	stats := &BlacklistStats{
		CategoryCounts: make(map[string]int64),
	}

	// Total IPs
	err := bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist`).Scan(&stats.TotalIPs)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to count IPs: %w", err)
	}

	// High threat count (>= 80)
	bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist WHERE threat_score >= 80`).Scan(&stats.HighThreatCount)

	// Medium threat count (50-79)
	bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist WHERE threat_score >= 50 AND threat_score < 80`).Scan(&stats.MediumThreatCount)

	// Low threat count (< 50)
	bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist WHERE threat_score < 50`).Scan(&stats.LowThreatCount)

	// Average threat score
	bs.db.QueryRow(`SELECT COALESCE(AVG(threat_score), 0) FROM ip_blacklist`).Scan(&stats.AverageThreatScore)

	// Category counts
	rows, err := bs.db.ExecuteQuery(`
		SELECT COALESCE(category, 'unknown'), COUNT(*) 
		FROM ip_blacklist 
		GROUP BY category`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var category string
			var count int64
			if err := rows.Scan(&category, &count); err == nil {
				stats.CategoryCounts[category] = count
			}
		}
	}

	return stats, nil
}

// GetBlacklistCount returns total count of blacklisted IPs
func (bs *IPBlacklistStorage) GetBlacklistCount() (int64, error) {
	var count int64
	err := bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count blacklisted IPs: %w", err)
	}
	return count, nil
}

// GetCategoryDistribution returns count of IPs per category
func (bs *IPBlacklistStorage) GetCategoryDistribution() (map[string]int64, error) {
	query := `
		SELECT COALESCE(category, 'unknown'), COUNT(*) as count
		FROM ip_blacklist 
		GROUP BY category
		ORDER BY count DESC`

	rows, err := bs.db.ExecuteQuery(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get category distribution: %w", err)
	}
	defer rows.Close()

	distribution := make(map[string]int64)
	for rows.Next() {
		var category string
		var count int64
		if err := rows.Scan(&category, &count); err != nil {
			continue
		}
		distribution[category] = count
	}

	return distribution, nil
}

// GetThreatScoreDistribution returns count of IPs per threat score range
func (bs *IPBlacklistStorage) GetThreatScoreDistribution() (map[string]int64, error) {
	distribution := make(map[string]int64)

	var count int64

	bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist WHERE threat_score >= 90`).Scan(&count)
	distribution["critical_90_100"] = count

	bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist WHERE threat_score >= 80 AND threat_score < 90`).Scan(&count)
	distribution["high_80_89"] = count

	bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist WHERE threat_score >= 60 AND threat_score < 80`).Scan(&count)
	distribution["medium_60_79"] = count

	bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist WHERE threat_score >= 40 AND threat_score < 60`).Scan(&count)
	distribution["low_40_59"] = count

	bs.db.QueryRow(`SELECT COUNT(*) FROM ip_blacklist WHERE threat_score < 40`).Scan(&count)
	distribution["minimal_0_39"] = count

	return distribution, nil
}

// ============================================================================
// Legacy Compatibility Methods (for existing code using DB methods directly)
// ============================================================================

// StoreIPBlacklist stores IP blacklist data (legacy compatibility method on DB)
func (db *DB) StoreIPBlacklist(ip, category, source string, threatScore int, metadata string) error {
	query := `
		INSERT INTO ip_blacklist (ip_address, threat_score, category, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (ip_address) 
		DO UPDATE SET 
			threat_score = EXCLUDED.threat_score,
			category = EXCLUDED.category,
			last_seen = EXCLUDED.last_seen,
			updated_at = NOW()
	`

	now := time.Now()
	_, err := db.conn.Exec(query, ip, threatScore, category, source, metadata, now, now)
	if err != nil {
		return fmt.Errorf("failed to store IP blacklist: %w", err)
	}

	return nil
}

// GetIPBlacklist retrieves IP blacklist data (legacy compatibility method on DB)
func (db *DB) GetIPBlacklist(ip string) (map[string]interface{}, error) {
	query := `
		SELECT ip_address, threat_score, category, first_seen, last_seen, source 
		FROM ip_blacklist 
		WHERE ip_address = $1`

	row := db.conn.QueryRow(query, ip)

	var ipAddr, category, source string
	var threatScore int
	var firstSeen, lastSeen time.Time

	err := row.Scan(&ipAddr, &threatScore, &category, &firstSeen, &lastSeen, &source)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get IP blacklist: %w", err)
	}

	result := map[string]interface{}{
		"ip_address":   ipAddr,
		"threat_score": threatScore,
		"category":     category,
		"first_seen":   firstSeen,
		"last_seen":    lastSeen,
		"source":       source,
	}

	return result, nil
}
