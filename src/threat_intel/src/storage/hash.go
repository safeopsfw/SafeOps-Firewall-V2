package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

// HashStorage manages file hash database operations
type HashStorage struct {
	db             *DB
	batchSize      int
	minThreatScore int
	logger         *log.Logger
}

// HashRecord represents a hash_intelligence table entry
type HashRecord struct {
	ID          int64          `json:"id"`
	HashValue   string         `json:"hash_value"`
	HashType    string         `json:"hash_type"`
	ThreatScore int            `json:"threat_score"`
	Category    string         `json:"category"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Source      string         `json:"source"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// HashStats holds hash database statistics
type HashStats struct {
	TotalHashes        int64            `json:"total_hashes"`
	MD5Count           int64            `json:"md5_count"`
	SHA1Count          int64            `json:"sha1_count"`
	SHA256Count        int64            `json:"sha256_count"`
	HighThreatCount    int64            `json:"high_threat_count"`
	AverageThreatScore float64          `json:"average_threat_score"`
	CategoryCounts     map[string]int64 `json:"category_counts"`
}

// HashInsertStats tracks bulk insert results
type HashInsertStats struct {
	TotalProcessed int64 `json:"total_processed"`
	Inserted       int64 `json:"inserted"`
	FilteredOut    int64 `json:"filtered_out"`
	Errors         int64 `json:"errors"`
}

var (
	md5Regex    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1Regex   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

func NewHashStorage(database *DB) *HashStorage {
	return &HashStorage{
		db:             database,
		batchSize:      getEnvIntOrDefault("HASH_BATCH_SIZE", 1000),
		minThreatScore: getEnvIntOrDefault("HASH_MIN_THREAT_SCORE", 30),
		logger:         log.New(os.Stdout, "[HashStorage] ", log.LstdFlags),
	}
}

func NormalizeHash(hash string) string {
	return strings.ToLower(strings.TrimSpace(hash))
}

func ValidateHash(hash, hashType string) bool {
	hash = NormalizeHash(hash)
	switch strings.ToLower(hashType) {
	case "md5":
		return md5Regex.MatchString(hash)
	case "sha1":
		return sha1Regex.MatchString(hash)
	case "sha256":
		return sha256Regex.MatchString(hash)
	default:
		return len(hash) >= 32
	}
}

func DetectHashType(hash string) string {
	switch len(NormalizeHash(hash)) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	default:
		return "unknown"
	}
}

func (hs *HashStorage) InsertHash(record *HashRecord) error {
	if record == nil || record.HashValue == "" {
		return fmt.Errorf("hash value required")
	}
	record.HashValue = NormalizeHash(record.HashValue)
	if record.HashType == "" {
		record.HashType = DetectHashType(record.HashValue)
	}
	if record.ThreatScore < hs.minThreatScore {
		return nil
	}
	now := time.Now()
	if record.FirstSeen.IsZero() {
		record.FirstSeen = now
	}
	record.LastSeen = now
	metadataJSON, _ := json.Marshal(record.Metadata)

	query := `INSERT INTO hash_intelligence (hash_value, hash_type, threat_score, category, source, metadata, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := hs.db.ExecuteInsert(query, record.HashValue, record.HashType, record.ThreatScore, record.Category, record.Source, string(metadataJSON), record.FirstSeen, record.LastSeen)
	return err
}

func (hs *HashStorage) UpsertHash(record *HashRecord) error {
	if record == nil || record.HashValue == "" {
		return fmt.Errorf("hash value required")
	}
	record.HashValue = NormalizeHash(record.HashValue)
	if record.HashType == "" {
		record.HashType = DetectHashType(record.HashValue)
	}
	now := time.Now()
	if record.FirstSeen.IsZero() {
		record.FirstSeen = now
	}
	record.LastSeen = now
	metadataJSON, _ := json.Marshal(record.Metadata)

	query := `INSERT INTO hash_intelligence (hash_value, hash_type, threat_score, category, source, metadata, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (hash_value) DO UPDATE SET threat_score = GREATEST(hash_intelligence.threat_score, EXCLUDED.threat_score), category = COALESCE(EXCLUDED.category, hash_intelligence.category), last_seen = EXCLUDED.last_seen, updated_at = NOW()`
	_, err := hs.db.ExecuteInsert(query, record.HashValue, record.HashType, record.ThreatScore, record.Category, record.Source, string(metadataJSON), record.FirstSeen, record.LastSeen)
	return err
}

func (hs *HashStorage) BulkInsertHashes(records []*HashRecord) (*HashInsertStats, error) {
	stats := &HashInsertStats{TotalProcessed: int64(len(records))}
	if len(records) == 0 {
		return stats, nil
	}
	var valid []*HashRecord
	for _, r := range records {
		if r == nil || r.HashValue == "" {
			stats.Errors++
			continue
		}
		r.HashValue = NormalizeHash(r.HashValue)
		if r.HashType == "" {
			r.HashType = DetectHashType(r.HashValue)
		}
		if r.ThreatScore < hs.minThreatScore {
			stats.FilteredOut++
			continue
		}
		valid = append(valid, r)
	}
	for i := 0; i < len(valid); i += hs.batchSize {
		end := i + hs.batchSize
		if end > len(valid) {
			end = len(valid)
		}
		inserted, err := hs.insertHashBatch(valid[i:end])
		if err != nil {
			stats.Errors += int64(end - i)
			continue
		}
		stats.Inserted += inserted
	}
	return stats, nil
}

func (hs *HashStorage) insertHashBatch(batch []*HashRecord) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tx, err := hs.db.BeginTx(ctx)
	if err != nil {
		return 0, err
	}
	query := `INSERT INTO hash_intelligence (hash_value, hash_type, threat_score, category, source, metadata, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (hash_value) DO UPDATE SET threat_score = GREATEST(hash_intelligence.threat_score, EXCLUDED.threat_score), last_seen = EXCLUDED.last_seen, updated_at = NOW()`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	var inserted int64
	now := time.Now()
	for _, r := range batch {
		metadataJSON, _ := json.Marshal(r.Metadata)
		if _, err := stmt.ExecContext(ctx, r.HashValue, r.HashType, r.ThreatScore, r.Category, r.Source, string(metadataJSON), now, now); err == nil {
			inserted++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

func (hs *HashStorage) GetHash(hashValue string) (*HashRecord, error) {
	hashValue = NormalizeHash(hashValue)
	query := `SELECT id, hash_value, hash_type, threat_score, category, first_seen, last_seen, updated_at, source, metadata FROM hash_intelligence WHERE hash_value = $1`
	row := hs.db.QueryRow(query, hashValue)
	record := &HashRecord{}
	var metadataJSON sql.NullString
	var updatedAt sql.NullTime
	err := row.Scan(&record.ID, &record.HashValue, &record.HashType, &record.ThreatScore, &record.Category, &record.FirstSeen, &record.LastSeen, &updatedAt, &record.Source, &metadataJSON)
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
		json.Unmarshal([]byte(metadataJSON.String), &record.Metadata)
	}
	return record, nil
}

func (hs *HashStorage) IsKnownMalicious(hashValue string) (bool, error) {
	hashValue = NormalizeHash(hashValue)
	var exists bool
	err := hs.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM hash_intelligence WHERE hash_value = $1 AND threat_score >= 50)`, hashValue).Scan(&exists)
	return exists, err
}

func (hs *HashStorage) GetHashesByType(hashType string, limit int) ([]*HashRecord, error) {
	rows, err := hs.db.ExecuteQuery(`SELECT id, hash_value, hash_type, threat_score, category, first_seen, last_seen, source FROM hash_intelligence WHERE hash_type = $1 ORDER BY threat_score DESC LIMIT $2`, strings.ToLower(hashType), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*HashRecord
	for rows.Next() {
		r := &HashRecord{}
		if err := rows.Scan(&r.ID, &r.HashValue, &r.HashType, &r.ThreatScore, &r.Category, &r.FirstSeen, &r.LastSeen, &r.Source); err == nil {
			records = append(records, r)
		}
	}
	return records, nil
}

func (hs *HashStorage) GetHashesByCategory(category string, limit int) ([]*HashRecord, error) {
	rows, err := hs.db.ExecuteQuery(`SELECT id, hash_value, hash_type, threat_score, category, first_seen, last_seen, source FROM hash_intelligence WHERE category = $1 ORDER BY threat_score DESC LIMIT $2`, category, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*HashRecord
	for rows.Next() {
		r := &HashRecord{}
		if err := rows.Scan(&r.ID, &r.HashValue, &r.HashType, &r.ThreatScore, &r.Category, &r.FirstSeen, &r.LastSeen, &r.Source); err == nil {
			records = append(records, r)
		}
	}
	return records, nil
}

func (hs *HashStorage) GetHashesByThreatScore(minScore, limit int) ([]*HashRecord, error) {
	rows, err := hs.db.ExecuteQuery(`SELECT id, hash_value, hash_type, threat_score, category, first_seen, last_seen, source FROM hash_intelligence WHERE threat_score >= $1 ORDER BY threat_score DESC LIMIT $2`, minScore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*HashRecord
	for rows.Next() {
		r := &HashRecord{}
		if err := rows.Scan(&r.ID, &r.HashValue, &r.HashType, &r.ThreatScore, &r.Category, &r.FirstSeen, &r.LastSeen, &r.Source); err == nil {
			records = append(records, r)
		}
	}
	return records, nil
}

func (hs *HashStorage) GetRecentHashes(days, limit int) ([]*HashRecord, error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	rows, err := hs.db.ExecuteQuery(`SELECT id, hash_value, hash_type, threat_score, category, first_seen, last_seen, source FROM hash_intelligence WHERE first_seen >= $1 ORDER BY first_seen DESC LIMIT $2`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*HashRecord
	for rows.Next() {
		r := &HashRecord{}
		if err := rows.Scan(&r.ID, &r.HashValue, &r.HashType, &r.ThreatScore, &r.Category, &r.FirstSeen, &r.LastSeen, &r.Source); err == nil {
			records = append(records, r)
		}
	}
	return records, nil
}

func (hs *HashStorage) UpdateHashThreatScore(hashValue string, newScore int) error {
	affected, err := hs.db.ExecuteUpdate(`UPDATE hash_intelligence SET threat_score = $1, updated_at = NOW() WHERE hash_value = $2`, newScore, NormalizeHash(hashValue))
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("hash not found")
	}
	return nil
}

func (hs *HashStorage) DeleteHash(hashValue string) error {
	affected, err := hs.db.ExecuteDelete(`DELETE FROM hash_intelligence WHERE hash_value = $1`, NormalizeHash(hashValue))
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("hash not found")
	}
	return nil
}

func (hs *HashStorage) DeleteOldHashes(daysOld int) (int64, error) {
	return hs.db.ExecuteDelete(`DELETE FROM hash_intelligence WHERE last_seen < $1`, time.Now().AddDate(0, 0, -daysOld))
}

func (hs *HashStorage) GetHashStats() (*HashStats, error) {
	stats := &HashStats{CategoryCounts: make(map[string]int64)}
	hs.db.QueryRow(`SELECT COUNT(*) FROM hash_intelligence`).Scan(&stats.TotalHashes)
	hs.db.QueryRow(`SELECT COUNT(*) FROM hash_intelligence WHERE hash_type = 'md5'`).Scan(&stats.MD5Count)
	hs.db.QueryRow(`SELECT COUNT(*) FROM hash_intelligence WHERE hash_type = 'sha1'`).Scan(&stats.SHA1Count)
	hs.db.QueryRow(`SELECT COUNT(*) FROM hash_intelligence WHERE hash_type = 'sha256'`).Scan(&stats.SHA256Count)
	hs.db.QueryRow(`SELECT COUNT(*) FROM hash_intelligence WHERE threat_score >= 80`).Scan(&stats.HighThreatCount)
	hs.db.QueryRow(`SELECT COALESCE(AVG(threat_score), 0) FROM hash_intelligence`).Scan(&stats.AverageThreatScore)
	rows, _ := hs.db.ExecuteQuery(`SELECT COALESCE(category, 'unknown'), COUNT(*) FROM hash_intelligence GROUP BY category`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cat string
			var cnt int64
			if rows.Scan(&cat, &cnt) == nil {
				stats.CategoryCounts[cat] = cnt
			}
		}
	}
	return stats, nil
}

func (hs *HashStorage) GetHashCount() (int64, error) {
	var count int64
	err := hs.db.QueryRow(`SELECT COUNT(*) FROM hash_intelligence`).Scan(&count)
	return count, err
}

// Legacy compatibility
func (db *DB) StoreHash(hashValue, hashType, category, source string, threatScore int, metadata string) error {
	now := time.Now()
	_, err := db.conn.Exec(`INSERT INTO hash_intelligence (hash_value, hash_type, threat_score, category, source, metadata, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (hash_value) DO UPDATE SET threat_score = EXCLUDED.threat_score, category = EXCLUDED.category, last_seen = EXCLUDED.last_seen, updated_at = NOW()`, NormalizeHash(hashValue), strings.ToLower(hashType), threatScore, category, source, metadata, now, now)
	return err
}

func (db *DB) GetHashByValue(hashValue string) (map[string]interface{}, error) {
	row := db.QueryRow(`SELECT hash_value, hash_type, threat_score, category, first_seen, last_seen, source FROM hash_intelligence WHERE hash_value = $1`, NormalizeHash(hashValue))
	var hash, hashType, category, source string
	var threatScore int
	var firstSeen, lastSeen time.Time
	if err := row.Scan(&hash, &hashType, &threatScore, &category, &firstSeen, &lastSeen, &source); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return map[string]interface{}{"hash_value": hash, "hash_type": hashType, "threat_score": threatScore, "category": category, "first_seen": firstSeen, "last_seen": lastSeen, "source": source}, nil
}
