package storage

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// =============================================================================
// Hash Storage - Manages hashes table
// Connects to hashes table, fetches headers, supports column modification
// Can be used directly by any program
// =============================================================================

// HashStorage handles file hash intelligence data
type HashStorage struct {
	db        *DB
	tableName string
}

// HashRecord represents a hash entry in the database
type HashRecord struct {
	ID              int64     `json:"id"`
	MD5             string    `json:"md5,omitempty"`
	SHA1            string    `json:"sha1,omitempty"`
	SHA256          string    `json:"sha256"`
	SHA512          string    `json:"sha512,omitempty"`
	SSDeep          string    `json:"ssdeep,omitempty"`
	IsMalicious     bool      `json:"is_malicious"`
	ThreatScore     int       `json:"threat_score"`
	FileName        string    `json:"file_name,omitempty"`
	FileType        string    `json:"file_type,omitempty"`
	FileSize        int64     `json:"file_size,omitempty"`
	MimeType        string    `json:"mime_type,omitempty"`
	MalwareFamily   string    `json:"malware_family,omitempty"`
	MalwareType     string    `json:"malware_type,omitempty"`
	AVDetections    int       `json:"av_detections"`
	TotalAVEngines  int       `json:"total_av_engines"`
	AVDetectionRate float64   `json:"av_detection_rate"`
	SandboxVerdict  string    `json:"sandbox_verdict,omitempty"`
	VirusTotalLink  string    `json:"virustotal_link,omitempty"`
	Sources         []string  `json:"sources"`
	Tags            []string  `json:"tags"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	LastUpdated     time.Time `json:"last_updated"`
}

// HashTableName is the table name for hashes
const HashTableName = "hashes"

// NewHashStorage creates a new hash storage instance
func NewHashStorage(db *DB) *HashStorage {
	return &HashStorage{
		db:        db,
		tableName: HashTableName,
	}
}

// =============================================================================
// Table Information
// =============================================================================

// GetTableInfo returns information about the hashes table
func (s *HashStorage) GetTableInfo() (*TableInfo, error) {
	return s.db.GetTableInfo(s.tableName)
}

// GetHeaders returns column names for the hashes table
func (s *HashStorage) GetHeaders() ([]string, error) {
	return s.db.GetColumnNames(s.tableName)
}

// TableExists checks if the hashes table exists
func (s *HashStorage) TableExists() (bool, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return false, err
	}
	return info.Exists, nil
}

// GetRowCount returns the number of records in the table
func (s *HashStorage) GetRowCount() (int64, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return 0, err
	}
	return info.RowCount, nil
}

// =============================================================================
// Column Management
// =============================================================================

// AddColumn adds a new column to the hashes table
func (s *HashStorage) AddColumn(columnName, dataType, defaultValue string) error {
	return s.db.AddColumn(s.tableName, columnName, dataType, defaultValue)
}

// RemoveColumn removes a column from the hashes table
func (s *HashStorage) RemoveColumn(columnName string) error {
	return s.db.RemoveColumn(s.tableName, columnName)
}

// RenameColumn renames a column in the hashes table
func (s *HashStorage) RenameColumn(oldName, newName string) error {
	return s.db.RenameColumn(s.tableName, oldName, newName)
}

// =============================================================================
// CRUD Operations
// =============================================================================

// Insert adds a new hash record
func (s *HashStorage) Insert(ctx context.Context, record *HashRecord) error {
	query := `
		INSERT INTO hashes (
			md5, sha1, sha256, sha512, ssdeep,
			is_malicious, threat_score,
			file_name, file_type, file_size, mime_type,
			malware_family, malware_type,
			av_detections, total_av_engines, av_detection_rate,
			sandbox_verdict, virustotal_link,
			sources, tags, first_seen, last_seen, last_updated
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		)
		ON CONFLICT (sha256) DO UPDATE SET
			is_malicious = EXCLUDED.is_malicious,
			threat_score = GREATEST(hashes.threat_score, EXCLUDED.threat_score),
			av_detections = GREATEST(hashes.av_detections, EXCLUDED.av_detections),
			last_seen = EXCLUDED.last_seen,
			last_updated = NOW()
	`

	_, err := s.db.ExecContext(ctx, query,
		record.MD5, record.SHA1, record.SHA256, record.SHA512, record.SSDeep,
		record.IsMalicious, record.ThreatScore,
		record.FileName, record.FileType, record.FileSize, record.MimeType,
		record.MalwareFamily, record.MalwareType,
		record.AVDetections, record.TotalAVEngines, record.AVDetectionRate,
		record.SandboxVerdict, record.VirusTotalLink,
		toJSONArray(record.Sources), toJSONArray(record.Tags),
		record.FirstSeen, record.LastSeen, record.LastUpdated,
	)
	return err
}

// BulkInsert upserts multiple hash records efficiently
// Uses ON CONFLICT to update existing hashes instead of creating duplicates
func (s *HashStorage) BulkInsert(ctx context.Context, hashes []string, hashType string, source string, malwareFamily string) (int64, error) {
	if len(hashes) == 0 {
		return 0, nil
	}

	now := time.Now()

	// Determine which column based on hash type
	hashColumn := "sha256"
	switch strings.ToLower(hashType) {
	case "md5":
		hashColumn = "md5"
	case "sha1":
		hashColumn = "sha1"
	case "sha512":
		hashColumn = "sha512"
	}

	columns := []string{
		hashColumn, "is_malicious", "threat_score", "malware_family",
		"sources", "first_seen", "last_seen", "last_updated",
	}

	values := make([][]interface{}, len(hashes))
	for i, hash := range hashes {
		values[i] = []interface{}{
			strings.ToLower(hash),
			true, // is_malicious
			75,   // default threat_score for malware
			malwareFamily,
			fmt.Sprintf(`["%s"]`, source), // sources as JSON array
			now,
			now,
			now,
		}
	}

	updateExprs := map[string]string{
		"is_malicious":  "TRUE",
		"threat_score":  "GREATEST(hashes.threat_score, EXCLUDED.threat_score)",
		"last_seen":     "NOW()",
		"last_updated":  "NOW()",
		"malware_family": "COALESCE(EXCLUDED.malware_family, hashes.malware_family)",
	}

	return s.db.BulkUpsert(s.tableName, columns, values, hashColumn, updateExprs)
}

// GetBySHA256 retrieves a hash record by SHA256
func (s *HashStorage) GetBySHA256(ctx context.Context, sha256 string) (*HashRecord, error) {
	query := `
		SELECT id, md5, sha1, sha256, sha512, 
			   is_malicious, threat_score,
			   file_name, file_type, file_size, mime_type,
			   malware_family, malware_type,
			   av_detections, total_av_engines, sandbox_verdict,
			   first_seen, last_seen, last_updated
		FROM hashes
		WHERE sha256 = $1
	`

	var record HashRecord
	err := s.db.QueryRowContext(ctx, query, sha256).Scan(
		&record.ID, &record.MD5, &record.SHA1, &record.SHA256, &record.SHA512,
		&record.IsMalicious, &record.ThreatScore,
		&record.FileName, &record.FileType, &record.FileSize, &record.MimeType,
		&record.MalwareFamily, &record.MalwareType,
		&record.AVDetections, &record.TotalAVEngines, &record.SandboxVerdict,
		&record.FirstSeen, &record.LastSeen, &record.LastUpdated,
	)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// GetByMD5 retrieves a hash record by MD5
func (s *HashStorage) GetByMD5(ctx context.Context, md5 string) (*HashRecord, error) {
	query := `
		SELECT id, md5, sha1, sha256, is_malicious, threat_score, 
			   malware_family, first_seen, last_seen
		FROM hashes
		WHERE md5 = $1
	`

	var record HashRecord
	err := s.db.QueryRowContext(ctx, query, md5).Scan(
		&record.ID, &record.MD5, &record.SHA1, &record.SHA256,
		&record.IsMalicious, &record.ThreatScore,
		&record.MalwareFamily, &record.FirstSeen, &record.LastSeen,
	)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// Search searches hashes by pattern or malware family
func (s *HashStorage) Search(ctx context.Context, query string, limit int) ([]HashRecord, error) {
	if limit <= 0 {
		limit = 100
	}

	sqlQuery := `
		SELECT id, sha256, md5, is_malicious, threat_score, malware_family, 
			   malware_type, file_name, last_seen
		FROM hashes
		WHERE sha256 LIKE $1 OR md5 LIKE $1 OR malware_family ILIKE $2
		ORDER BY threat_score DESC
		LIMIT $3
	`

	rows, err := s.db.QueryContext(ctx, sqlQuery, query+"%", "%"+query+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []HashRecord
	for rows.Next() {
		var r HashRecord
		if err := rows.Scan(&r.ID, &r.SHA256, &r.MD5, &r.IsMalicious, &r.ThreatScore,
			&r.MalwareFamily, &r.MalwareType, &r.FileName, &r.LastSeen); err != nil {
			continue
		}
		records = append(records, r)
	}

	return records, nil
}

// GetMalwareFamilies returns distinct malware families
func (s *HashStorage) GetMalwareFamilies(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT malware_family 
		FROM hashes 
		WHERE malware_family IS NOT NULL AND malware_family != ''
		ORDER BY malware_family
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var families []string
	for rows.Next() {
		var family string
		if err := rows.Scan(&family); err != nil {
			continue
		}
		families = append(families, family)
	}

	return families, nil
}
