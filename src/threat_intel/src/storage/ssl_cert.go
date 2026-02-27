package storage

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// =============================================================================
// SSL Certificate Storage - Manages ssl_certificates table
// For malicious SSL/TLS certificate fingerprints from abuse.ch SSLBL
// =============================================================================

// SSLCertStorage handles malicious SSL certificate data
type SSLCertStorage struct {
	db        *DB
	tableName string
}

// SSLCertRecord represents an SSL certificate entry
type SSLCertRecord struct {
	ID              int64     `json:"id"`
	SHA1Fingerprint string    `json:"sha1_fingerprint"`
	SubjectCN       string    `json:"subject_cn,omitempty"`
	IssuerCN        string    `json:"issuer_cn,omitempty"`
	SerialNumber    string    `json:"serial_number,omitempty"`
	IsMalicious     bool      `json:"is_malicious"`
	ThreatScore     int       `json:"threat_score"`
	ListingReason   string    `json:"listing_reason,omitempty"`
	Sources         []string  `json:"sources"`
	EvidenceCount   int       `json:"evidence_count"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Status          string    `json:"status"`
}

const SSLCertTableName = "ssl_certificates"

// NewSSLCertStorage creates a new SSL certificate storage instance
func NewSSLCertStorage(db *DB) *SSLCertStorage {
	return &SSLCertStorage{
		db:        db,
		tableName: SSLCertTableName,
	}
}

// GetTableInfo returns information about the ssl_certificates table
func (s *SSLCertStorage) GetTableInfo() (*TableInfo, error) {
	return s.db.GetTableInfo(s.tableName)
}

// GetRowCount returns the number of records in the table
func (s *SSLCertStorage) GetRowCount() (int64, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return 0, err
	}
	return info.RowCount, nil
}

// Reconcile performs smart feed reconciliation for SSL certificates.
func (s *SSLCertStorage) Reconcile(ctx context.Context, feedName string, certs []SSLCertRecord, priority int) (*ReconcileResult, error) {
	result := &ReconcileResult{}
	if len(certs) == 0 {
		return result, nil
	}

	threatScore := priorityToScore(priority)
	now := time.Now()

	// Step 1: Batch upsert current certs
	columns := []string{
		"sha1_fingerprint", "is_malicious", "threat_score", "listing_reason",
		"sources", "status", "first_seen", "last_seen",
	}
	values := make([][]interface{}, len(certs))
	for i, cert := range certs {
		values[i] = []interface{}{
			strings.ToLower(cert.SHA1Fingerprint),
			true,
			threatScore,
			cert.ListingReason,
			fmt.Sprintf(`["%s"]`, feedName),
			"active",
			now,
			now,
		}
	}

	updateExprs := map[string]string{
		"last_seen":      "NOW()",
		"evidence_count": "ssl_certificates.evidence_count + 1",
		"threat_score":   fmt.Sprintf("GREATEST(ssl_certificates.threat_score, %d)", threatScore),
		"is_malicious":   "TRUE",
		"status":         "'active'",
		"sources":        fmt.Sprintf(`ssl_certificates.sources || '["%s"]'::jsonb`, feedName),
	}

	affected, err := s.db.BulkUpsert(s.tableName, columns, values, "sha1_fingerprint", updateExprs)
	if err != nil {
		return result, fmt.Errorf("ssl cert reconcile upsert failed: %w", err)
	}
	result.Updated = affected

	// Step 2: Remove certs this feed no longer reports
	existingQuery := fmt.Sprintf(`
		SELECT sha1_fingerprint FROM %s WHERE sources @> $1::jsonb`, s.tableName)
	rows, err := s.db.QueryContext(ctx, existingQuery, fmt.Sprintf(`["%s"]`, feedName))
	if err == nil {
		defer rows.Close()
		currentSet := make(map[string]bool, len(certs))
		for _, c := range certs {
			currentSet[strings.ToLower(c.SHA1Fingerprint)] = true
		}

		var toRemove []string
		for rows.Next() {
			var fp string
			if rows.Scan(&fp) == nil && !currentSet[fp] {
				toRemove = append(toRemove, fp)
			}
		}

		for i := 0; i < len(toRemove); i += 500 {
			end := i + 500
			if end > len(toRemove) {
				end = len(toRemove)
			}
			batch := toRemove[i:end]
			ph := make([]string, len(batch))
			args := make([]interface{}, len(batch))
			for j, fp := range batch {
				ph[j] = fmt.Sprintf("$%d", j+1)
				args[j] = fp
			}
			delQuery := fmt.Sprintf(`DELETE FROM %s WHERE sha1_fingerprint IN (%s)`,
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

// GetByFingerprint retrieves a cert record by SHA1 fingerprint
func (s *SSLCertStorage) GetByFingerprint(ctx context.Context, sha1 string) (*SSLCertRecord, error) {
	query := `
		SELECT id, sha1_fingerprint, subject_cn, issuer_cn, serial_number,
			   is_malicious, threat_score, listing_reason, evidence_count,
			   status, first_seen, last_seen
		FROM ssl_certificates
		WHERE sha1_fingerprint = $1`

	var record SSLCertRecord
	err := s.db.QueryRowContext(ctx, query, strings.ToLower(sha1)).Scan(
		&record.ID, &record.SHA1Fingerprint, &record.SubjectCN, &record.IssuerCN,
		&record.SerialNumber, &record.IsMalicious, &record.ThreatScore,
		&record.ListingReason, &record.EvidenceCount,
		&record.Status, &record.FirstSeen, &record.LastSeen,
	)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// CheckFingerprint checks if a cert SHA1 is blacklisted (quick lookup)
func (s *SSLCertStorage) CheckFingerprint(ctx context.Context, sha1 string) (bool, int, error) {
	query := `
		SELECT is_malicious, threat_score
		FROM ssl_certificates
		WHERE sha1_fingerprint = $1 AND status = 'active'`

	var isMalicious bool
	var score int
	err := s.db.QueryRowContext(ctx, query, strings.ToLower(sha1)).Scan(&isMalicious, &score)
	if err != nil {
		return false, 0, nil // Not found = not blacklisted
	}
	return isMalicious, score, nil
}
