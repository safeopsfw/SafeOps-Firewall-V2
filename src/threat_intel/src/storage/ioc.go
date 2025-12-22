package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// IOCStorage manages Indicator of Compromise database operations
type IOCStorage struct {
	db            *DB
	batchSize     int
	minConfidence int
	defaultTLP    string
	logger        *log.Logger
}

// IOCRecord represents an ioc_storage table entry with extended metadata
type IOCRecord struct {
	ID          int64     `json:"id"`
	IOCValue    string    `json:"ioc_value"`
	IOCType     string    `json:"ioc_type"` // ip, domain, url, hash, email
	ThreatScore int       `json:"threat_score"`
	Confidence  int       `json:"confidence"`
	Category    string    `json:"category"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	UpdatedAt   time.Time `json:"updated_at"`
	Source      string    `json:"source"`
	// Extended fields stored in metadata JSONB
	ThreatActor    string    `json:"threat_actor,omitempty"`
	CampaignName   string    `json:"campaign_name,omitempty"`
	TLPLevel       string    `json:"tlp_level,omitempty"` // white, green, amber, red
	Severity       string    `json:"severity,omitempty"`  // low, medium, high, critical
	Description    string    `json:"description,omitempty"`
	Tags           []string  `json:"tags,omitempty"`
	RelatedIOCs    []string  `json:"related_iocs,omitempty"`
	MitreAttackIDs []string  `json:"mitre_attack_ids,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	Status         string    `json:"status,omitempty"` // active, expired, false_positive
}

// IOCMetadata stores extended fields in JSONB
type IOCMetadata struct {
	ThreatActor    string         `json:"threat_actor,omitempty"`
	CampaignName   string         `json:"campaign_name,omitempty"`
	TLPLevel       string         `json:"tlp_level,omitempty"`
	Severity       string         `json:"severity,omitempty"`
	Description    string         `json:"description,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	RelatedIOCs    []string       `json:"related_iocs,omitempty"`
	MitreAttackIDs []string       `json:"mitre_attack_ids,omitempty"`
	ExpiresAt      string         `json:"expires_at,omitempty"`
	Status         string         `json:"status,omitempty"`
	ExtraData      map[string]any `json:"extra,omitempty"`
}

// IOCFilters for flexible searching
type IOCFilters struct {
	IOCTypes      []string
	ThreatTypes   []string
	Categories    []string
	MinConfidence int
	MinScore      int
	ThreatActors  []string
	Campaigns     []string
	Tags          []string
	Status        string
	Since         *time.Time
	Until         *time.Time
}

// IOCStats holds IOC database statistics
type IOCStats struct {
	TotalIOCs          int64            `json:"total_iocs"`
	IPCount            int64            `json:"ip_count"`
	DomainCount        int64            `json:"domain_count"`
	URLCount           int64            `json:"url_count"`
	HashCount          int64            `json:"hash_count"`
	EmailCount         int64            `json:"email_count"`
	HighConfidence     int64            `json:"high_confidence"`
	AverageThreatScore float64          `json:"average_threat_score"`
	AverageConfidence  float64          `json:"average_confidence"`
	TypeCounts         map[string]int64 `json:"type_counts"`
	CategoryCounts     map[string]int64 `json:"category_counts"`
}

// IOCInsertStats tracks bulk insert results
type IOCInsertStats struct {
	TotalProcessed int64 `json:"total_processed"`
	Inserted       int64 `json:"inserted"`
	Updated        int64 `json:"updated"`
	Skipped        int64 `json:"skipped"`
	Errors         int64 `json:"errors"`
}

// Regex patterns for IOC type detection
var (
	ipv4Regex    = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	ipv6Regex    = regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)
	domainRegex  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	urlRegex     = regexp.MustCompile(`^https?://`)
	emailRegex   = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	md5Regex2    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1Regex2   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256Regex2 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

func NewIOCStorage(database *DB) *IOCStorage {
	return &IOCStorage{
		db:            database,
		batchSize:     getEnvIntOrDefault("IOC_BATCH_SIZE", 1000),
		minConfidence: getEnvIntOrDefault("IOC_MIN_CONFIDENCE", 40),
		defaultTLP:    getEnvOrDefault("IOC_DEFAULT_TLP", "white"),
		logger:        log.New(os.Stdout, "[IOCStorage] ", log.LstdFlags),
	}
}

// DetectIOCType auto-detects IOC type from value
func DetectIOCType(value string) string {
	value = strings.TrimSpace(value)
	switch {
	case ipv4Regex.MatchString(value):
		return "ip"
	case ipv6Regex.MatchString(value):
		return "ip"
	case net.ParseIP(value) != nil:
		return "ip"
	case urlRegex.MatchString(value):
		return "url"
	case emailRegex.MatchString(value):
		return "email"
	case sha256Regex2.MatchString(value):
		return "hash"
	case sha1Regex2.MatchString(value):
		return "hash"
	case md5Regex2.MatchString(value):
		return "hash"
	case domainRegex.MatchString(value):
		return "domain"
	default:
		return "unknown"
	}
}

// NormalizeIOCValue normalizes IOC value based on type
func NormalizeIOCValue(iocType, value string) string {
	value = strings.TrimSpace(value)
	switch iocType {
	case "domain", "email":
		return strings.ToLower(value)
	case "hash":
		return strings.ToLower(value)
	case "url":
		return strings.TrimSuffix(value, "/")
	default:
		return value
	}
}

// NormalizeIOCType normalizes IOC type string
func NormalizeIOCType(iocType string) string {
	iocType = strings.ToLower(strings.TrimSpace(iocType))
	typeMap := map[string]string{
		"ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip_address": "ip",
		"domain": "domain", "fqdn": "domain", "hostname": "domain",
		"url": "url", "uri": "url", "link": "url",
		"hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
		"email": "email", "mail": "email", "email_address": "email",
	}
	if normalized, ok := typeMap[iocType]; ok {
		return normalized
	}
	return iocType
}

// ValidateTLPLevel validates TLP level
func ValidateTLPLevel(tlp string) bool {
	valid := map[string]bool{"white": true, "green": true, "amber": true, "red": true, "": true}
	return valid[strings.ToLower(tlp)]
}

// buildMetadata creates JSONB metadata from record extended fields
func (r *IOCRecord) buildMetadata() (string, error) {
	meta := IOCMetadata{
		ThreatActor:    r.ThreatActor,
		CampaignName:   r.CampaignName,
		TLPLevel:       r.TLPLevel,
		Severity:       r.Severity,
		Description:    r.Description,
		Tags:           r.Tags,
		RelatedIOCs:    r.RelatedIOCs,
		MitreAttackIDs: r.MitreAttackIDs,
		Status:         r.Status,
	}
	if !r.ExpiresAt.IsZero() {
		meta.ExpiresAt = r.ExpiresAt.Format(time.RFC3339)
	}
	data, err := json.Marshal(meta)
	return string(data), err
}

// parseMetadata extracts extended fields from JSONB metadata
func (r *IOCRecord) parseMetadata(metadataJSON string) {
	if metadataJSON == "" {
		return
	}
	var meta IOCMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &meta); err != nil {
		return
	}
	r.ThreatActor = meta.ThreatActor
	r.CampaignName = meta.CampaignName
	r.TLPLevel = meta.TLPLevel
	r.Severity = meta.Severity
	r.Description = meta.Description
	r.Tags = meta.Tags
	r.RelatedIOCs = meta.RelatedIOCs
	r.MitreAttackIDs = meta.MitreAttackIDs
	r.Status = meta.Status
	if meta.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, meta.ExpiresAt); err == nil {
			r.ExpiresAt = t
		}
	}
}

func (is *IOCStorage) InsertIOC(record *IOCRecord) error {
	if record == nil || record.IOCValue == "" {
		return fmt.Errorf("IOC value required")
	}
	// Auto-detect type if not provided
	if record.IOCType == "" {
		record.IOCType = DetectIOCType(record.IOCValue)
	}
	record.IOCType = NormalizeIOCType(record.IOCType)
	record.IOCValue = NormalizeIOCValue(record.IOCType, record.IOCValue)
	// Check confidence threshold
	if record.Confidence < is.minConfidence && record.ThreatScore < 50 {
		is.logger.Printf("IOC skipped (low confidence): %s", record.IOCValue[:min(20, len(record.IOCValue))])
		return nil
	}
	// Set defaults
	if record.TLPLevel == "" {
		record.TLPLevel = is.defaultTLP
	}
	if record.Status == "" {
		record.Status = "active"
	}
	now := time.Now()
	if record.FirstSeen.IsZero() {
		record.FirstSeen = now
	}
	record.LastSeen = now
	// Build metadata JSONB
	metadataJSON, _ := record.buildMetadata()
	query := `INSERT INTO ioc_storage (ioc_value, ioc_type, threat_score, confidence, category, source, metadata, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := is.db.ExecuteInsert(query, record.IOCValue, record.IOCType, record.ThreatScore, record.Confidence, record.Category, record.Source, metadataJSON, record.FirstSeen, record.LastSeen)
	if err != nil {
		is.logger.Printf("Insert failed for %s: %v", record.IOCValue[:min(20, len(record.IOCValue))], err)
	}
	return err
}

func (is *IOCStorage) UpsertIOC(record *IOCRecord) error {
	if record == nil || record.IOCValue == "" {
		return fmt.Errorf("IOC value required")
	}
	if record.IOCType == "" {
		record.IOCType = DetectIOCType(record.IOCValue)
	}
	record.IOCType = NormalizeIOCType(record.IOCType)
	record.IOCValue = NormalizeIOCValue(record.IOCType, record.IOCValue)
	if record.TLPLevel == "" {
		record.TLPLevel = is.defaultTLP
	}
	if record.Status == "" {
		record.Status = "active"
	}
	now := time.Now()
	if record.FirstSeen.IsZero() {
		record.FirstSeen = now
	}
	record.LastSeen = now
	metadataJSON, _ := record.buildMetadata()
	query := `INSERT INTO ioc_storage (ioc_value, ioc_type, threat_score, confidence, category, source, metadata, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (ioc_value, ioc_type) DO UPDATE SET threat_score = GREATEST(ioc_storage.threat_score, EXCLUDED.threat_score), confidence = GREATEST(ioc_storage.confidence, EXCLUDED.confidence), category = COALESCE(EXCLUDED.category, ioc_storage.category), metadata = EXCLUDED.metadata, last_seen = EXCLUDED.last_seen, updated_at = NOW()`
	_, err := is.db.ExecuteInsert(query, record.IOCValue, record.IOCType, record.ThreatScore, record.Confidence, record.Category, record.Source, metadataJSON, record.FirstSeen, record.LastSeen)
	return err
}

func (is *IOCStorage) BulkInsertIOCs(records []*IOCRecord) (*IOCInsertStats, error) {
	stats := &IOCInsertStats{TotalProcessed: int64(len(records))}
	if len(records) == 0 {
		return stats, nil
	}
	var valid []*IOCRecord
	for _, r := range records {
		if r == nil || r.IOCValue == "" {
			stats.Errors++
			continue
		}
		if r.IOCType == "" {
			r.IOCType = DetectIOCType(r.IOCValue)
		}
		r.IOCType = NormalizeIOCType(r.IOCType)
		r.IOCValue = NormalizeIOCValue(r.IOCType, r.IOCValue)
		if r.Confidence < is.minConfidence && r.ThreatScore < 50 {
			stats.Skipped++
			continue
		}
		valid = append(valid, r)
	}
	for i := 0; i < len(valid); i += is.batchSize {
		end := i + is.batchSize
		if end > len(valid) {
			end = len(valid)
		}
		inserted, err := is.insertIOCBatch(valid[i:end])
		if err != nil {
			stats.Errors += int64(end - i)
			continue
		}
		stats.Inserted += inserted
	}
	is.logger.Printf("Bulk IOC insert: %d inserted, %d skipped, %d errors", stats.Inserted, stats.Skipped, stats.Errors)
	return stats, nil
}

func (is *IOCStorage) insertIOCBatch(batch []*IOCRecord) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tx, err := is.db.BeginTx(ctx)
	if err != nil {
		return 0, err
	}
	query := `INSERT INTO ioc_storage (ioc_value, ioc_type, threat_score, confidence, category, source, metadata, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (ioc_value, ioc_type) DO UPDATE SET threat_score = GREATEST(ioc_storage.threat_score, EXCLUDED.threat_score), confidence = GREATEST(ioc_storage.confidence, EXCLUDED.confidence), last_seen = EXCLUDED.last_seen, updated_at = NOW()`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	var inserted int64
	now := time.Now()
	for _, r := range batch {
		if r.TLPLevel == "" {
			r.TLPLevel = is.defaultTLP
		}
		if r.Status == "" {
			r.Status = "active"
		}
		if r.FirstSeen.IsZero() {
			r.FirstSeen = now
		}
		r.LastSeen = now
		metadataJSON, _ := r.buildMetadata()
		if _, err := stmt.ExecContext(ctx, r.IOCValue, r.IOCType, r.ThreatScore, r.Confidence, r.Category, r.Source, metadataJSON, r.FirstSeen, r.LastSeen); err == nil {
			inserted++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

func (is *IOCStorage) GetIOC(iocValue, iocType string) (*IOCRecord, error) {
	iocType = NormalizeIOCType(iocType)
	iocValue = NormalizeIOCValue(iocType, iocValue)
	query := `SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, updated_at, source, metadata FROM ioc_storage WHERE ioc_value = $1 AND ioc_type = $2`
	row := is.db.QueryRow(query, iocValue, iocType)
	record := &IOCRecord{}
	var metadataJSON sql.NullString
	var updatedAt sql.NullTime
	err := row.Scan(&record.ID, &record.IOCValue, &record.IOCType, &record.ThreatScore, &record.Confidence, &record.Category, &record.FirstSeen, &record.LastSeen, &updatedAt, &record.Source, &metadataJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if updatedAt.Valid {
		record.UpdatedAt = updatedAt.Time
	}
	if metadataJSON.Valid {
		record.parseMetadata(metadataJSON.String)
	}
	return record, nil
}

func (is *IOCStorage) GetIOCByValue(iocValue string) ([]*IOCRecord, error) {
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE ioc_value = $1`, iocValue)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*IOCRecord
	for rows.Next() {
		r := &IOCRecord{}
		var metadataJSON sql.NullString
		if err := rows.Scan(&r.ID, &r.IOCValue, &r.IOCType, &r.ThreatScore, &r.Confidence, &r.Category, &r.FirstSeen, &r.LastSeen, &r.Source, &metadataJSON); err == nil {
			if metadataJSON.Valid {
				r.parseMetadata(metadataJSON.String)
			}
			records = append(records, r)
		}
	}
	return records, nil
}

func (is *IOCStorage) IsKnownIOC(iocValue string) (bool, error) {
	var exists bool
	err := is.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM ioc_storage WHERE ioc_value = $1)`, iocValue).Scan(&exists)
	return exists, err
}

func (is *IOCStorage) GetIOCsByType(iocType string, limit int) ([]*IOCRecord, error) {
	iocType = NormalizeIOCType(iocType)
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE ioc_type = $1 ORDER BY threat_score DESC LIMIT $2`, iocType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) GetIOCsByCategory(category string, limit int) ([]*IOCRecord, error) {
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE category = $1 ORDER BY threat_score DESC LIMIT $2`, category, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) GetIOCsByThreatScore(minScore, limit int) ([]*IOCRecord, error) {
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE threat_score >= $1 ORDER BY threat_score DESC LIMIT $2`, minScore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) GetHighConfidenceIOCs(minConfidence, limit int) ([]*IOCRecord, error) {
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE confidence >= $1 ORDER BY confidence DESC LIMIT $2`, minConfidence, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) GetIOCsByThreatActor(actorName string, limit int) ([]*IOCRecord, error) {
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE metadata->>'threat_actor' = $1 ORDER BY threat_score DESC LIMIT $2`, actorName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) GetIOCsByCampaign(campaignName string, limit int) ([]*IOCRecord, error) {
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE metadata->>'campaign_name' = $1 ORDER BY threat_score DESC LIMIT $2`, campaignName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) GetRecentIOCs(days, limit int) ([]*IOCRecord, error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE first_seen >= $1 ORDER BY first_seen DESC LIMIT $2`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) GetActiveIOCs(limit int) ([]*IOCRecord, error) {
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE metadata->>'status' = 'active' OR metadata->>'status' IS NULL ORDER BY threat_score DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) SearchIOCs(pattern string, limit int) ([]*IOCRecord, error) {
	rows, err := is.db.ExecuteQuery(`SELECT id, ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE ioc_value LIKE $1 ORDER BY threat_score DESC LIMIT $2`, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return is.scanIOCRows(rows)
}

func (is *IOCStorage) scanIOCRows(rows *sql.Rows) ([]*IOCRecord, error) {
	var records []*IOCRecord
	for rows.Next() {
		r := &IOCRecord{}
		var metadataJSON sql.NullString
		if err := rows.Scan(&r.ID, &r.IOCValue, &r.IOCType, &r.ThreatScore, &r.Confidence, &r.Category, &r.FirstSeen, &r.LastSeen, &r.Source, &metadataJSON); err == nil {
			if metadataJSON.Valid {
				r.parseMetadata(metadataJSON.String)
			}
			records = append(records, r)
		}
	}
	return records, nil
}

func (is *IOCStorage) UpdateIOCStatus(iocValue, iocType, newStatus string) error {
	// Get existing record
	record, err := is.GetIOC(iocValue, iocType)
	if err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("IOC not found")
	}
	record.Status = newStatus
	metadataJSON, _ := record.buildMetadata()
	affected, err := is.db.ExecuteUpdate(`UPDATE ioc_storage SET metadata = $1, updated_at = NOW() WHERE ioc_value = $2 AND ioc_type = $3`, metadataJSON, iocValue, NormalizeIOCType(iocType))
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("IOC not found")
	}
	return nil
}

func (is *IOCStorage) DeleteIOC(iocValue, iocType string) error {
	affected, err := is.db.ExecuteDelete(`DELETE FROM ioc_storage WHERE ioc_value = $1 AND ioc_type = $2`, iocValue, NormalizeIOCType(iocType))
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("IOC not found")
	}
	return nil
}

func (is *IOCStorage) DeleteOldIOCs(daysOld int) (int64, error) {
	return is.db.ExecuteDelete(`DELETE FROM ioc_storage WHERE last_seen < $1`, time.Now().AddDate(0, 0, -daysOld))
}

func (is *IOCStorage) ExpireOldIOCs() (int64, error) {
	// Mark as expired in metadata where expires_at has passed
	return is.db.ExecuteUpdate(`UPDATE ioc_storage SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{status}', '"expired"'), updated_at = NOW() WHERE metadata->>'expires_at' IS NOT NULL AND (metadata->>'expires_at')::timestamp < NOW() AND COALESCE(metadata->>'status', 'active') = 'active'`)
}

func (is *IOCStorage) GetIOCStats() (*IOCStats, error) {
	stats := &IOCStats{TypeCounts: make(map[string]int64), CategoryCounts: make(map[string]int64)}
	is.db.QueryRow(`SELECT COUNT(*) FROM ioc_storage`).Scan(&stats.TotalIOCs)
	is.db.QueryRow(`SELECT COUNT(*) FROM ioc_storage WHERE ioc_type = 'ip'`).Scan(&stats.IPCount)
	is.db.QueryRow(`SELECT COUNT(*) FROM ioc_storage WHERE ioc_type = 'domain'`).Scan(&stats.DomainCount)
	is.db.QueryRow(`SELECT COUNT(*) FROM ioc_storage WHERE ioc_type = 'url'`).Scan(&stats.URLCount)
	is.db.QueryRow(`SELECT COUNT(*) FROM ioc_storage WHERE ioc_type = 'hash'`).Scan(&stats.HashCount)
	is.db.QueryRow(`SELECT COUNT(*) FROM ioc_storage WHERE ioc_type = 'email'`).Scan(&stats.EmailCount)
	is.db.QueryRow(`SELECT COUNT(*) FROM ioc_storage WHERE confidence >= 80`).Scan(&stats.HighConfidence)
	is.db.QueryRow(`SELECT COALESCE(AVG(threat_score), 0) FROM ioc_storage`).Scan(&stats.AverageThreatScore)
	is.db.QueryRow(`SELECT COALESCE(AVG(confidence), 0) FROM ioc_storage`).Scan(&stats.AverageConfidence)
	rows, _ := is.db.ExecuteQuery(`SELECT COALESCE(ioc_type, 'unknown'), COUNT(*) FROM ioc_storage GROUP BY ioc_type`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			var c int64
			if rows.Scan(&t, &c) == nil {
				stats.TypeCounts[t] = c
			}
		}
	}
	rows2, _ := is.db.ExecuteQuery(`SELECT COALESCE(category, 'unknown'), COUNT(*) FROM ioc_storage GROUP BY category`)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var cat string
			var cnt int64
			if rows2.Scan(&cat, &cnt) == nil {
				stats.CategoryCounts[cat] = cnt
			}
		}
	}
	return stats, nil
}

func (is *IOCStorage) GetIOCCount() (int64, error) {
	var count int64
	err := is.db.QueryRow(`SELECT COUNT(*) FROM ioc_storage`).Scan(&count)
	return count, err
}

// Legacy compatibility
func (db *DB) StoreIOC(iocValue, iocType, category, source string, threatScore, confidence int, metadata string) error {
	now := time.Now()
	if iocType == "" {
		iocType = DetectIOCType(iocValue)
	}
	iocType = NormalizeIOCType(iocType)
	iocValue = NormalizeIOCValue(iocType, iocValue)
	_, err := db.conn.Exec(`INSERT INTO ioc_storage (ioc_value, ioc_type, threat_score, confidence, category, source, metadata, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (ioc_value, ioc_type) DO UPDATE SET threat_score = EXCLUDED.threat_score, confidence = EXCLUDED.confidence, category = EXCLUDED.category, last_seen = EXCLUDED.last_seen, updated_at = NOW()`, iocValue, iocType, threatScore, confidence, category, source, metadata, now, now)
	return err
}

func (db *DB) GetIOCByValueAndType(iocValue, iocType string) (map[string]interface{}, error) {
	row := db.QueryRow(`SELECT ioc_value, ioc_type, threat_score, confidence, category, first_seen, last_seen, source, metadata FROM ioc_storage WHERE ioc_value = $1 AND ioc_type = $2`, iocValue, NormalizeIOCType(iocType))
	var val, typ, cat, src string
	var score, conf int
	var first, last time.Time
	var metaJSON sql.NullString
	if err := row.Scan(&val, &typ, &score, &conf, &cat, &first, &last, &src, &metaJSON); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	result := map[string]interface{}{"ioc_value": val, "ioc_type": typ, "threat_score": score, "confidence": conf, "category": cat, "first_seen": first, "last_seen": last, "source": src}
	if metaJSON.Valid {
		result["metadata"] = metaJSON.String
	}
	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
