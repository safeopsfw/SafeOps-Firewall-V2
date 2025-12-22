package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// ============================================================================
// IP Anonymization Storage - Connects with ip_anonymization table
// ============================================================================

// IPAnonymizationStorage manages IP anonymization database operations.
// Stores information about VPN, Tor, proxy, and datacenter IP addresses.
// Critical for fraud detection, access control, and understanding attack infrastructure.
type IPAnonymizationStorage struct {
	db           *DB
	batchSize    int
	inactiveDays int
	logger       *log.Logger
}

// AnonymizationRecord represents an IP anonymization entry matching ip_anonymization table
type AnonymizationRecord struct {
	ID                int64          `json:"id"`
	IPAddress         string         `json:"ip_address"`
	AnonymizationType string         `json:"anonymization_type"` // tor, vpn, proxy, hosting, datacenter
	Provider          string         `json:"provider"`
	FirstSeen         time.Time      `json:"first_seen"`
	LastSeen          time.Time      `json:"last_seen"`
	UpdatedAt         time.Time      `json:"updated_at"`
	Source            string         `json:"source"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

// AnonymizationStats holds IP anonymization database statistics
type AnonymizationStats struct {
	TotalIPs        int64            `json:"total_ips"`
	VPNCount        int64            `json:"vpn_count"`
	TorCount        int64            `json:"tor_count"`
	ProxyCount      int64            `json:"proxy_count"`
	HostingCount    int64            `json:"hosting_count"`
	DatacenterCount int64            `json:"datacenter_count"`
	UniqueProviders int64            `json:"unique_providers"`
	TypeCounts      map[string]int64 `json:"type_counts"`
}

// AnonymizationInsertStats tracks bulk insert operation results
type AnonymizationInsertStats struct {
	TotalProcessed int64 `json:"total_processed"`
	Inserted       int64 `json:"inserted"`
	Updated        int64 `json:"updated"`
	VPNCount       int64 `json:"vpn_count"`
	TorCount       int64 `json:"tor_count"`
	ProxyCount     int64 `json:"proxy_count"`
	Errors         int64 `json:"errors"`
}

// ============================================================================
// Constructor & Validation Utilities
// ============================================================================

// NewIPAnonymizationStorage creates a new IP anonymization storage handler
func NewIPAnonymizationStorage(database *DB) *IPAnonymizationStorage {
	return &IPAnonymizationStorage{
		db:           database,
		batchSize:    getEnvIntOrDefault("ANONYMIZATION_BATCH_SIZE", 1000),
		inactiveDays: getEnvIntOrDefault("ANONYMIZATION_INACTIVE_DAYS", 30),
		logger:       log.New(os.Stdout, "[IPAnonymizationStorage] ", log.LstdFlags),
	}
}

// ValidateAnonymizationType validates the anonymization type
func ValidateAnonymizationType(anonType string) bool {
	validTypes := map[string]bool{
		"tor": true, "vpn": true, "proxy": true, "hosting": true,
		"datacenter": true, "relay": true, "residential": true, "": true,
	}
	return validTypes[strings.ToLower(anonType)]
}

// NormalizeAnonymizationType normalizes anonymization type to lowercase
func NormalizeAnonymizationType(anonType string) string {
	return strings.ToLower(strings.TrimSpace(anonType))
}

// NormalizeProviderName normalizes provider name for consistency
func NormalizeProviderName(provider string) string {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return ""
	}
	// Title case for known providers
	knownProviders := map[string]string{
		"nordvpn": "NordVPN", "expressvpn": "ExpressVPN", "surfshark": "Surfshark",
		"protonvpn": "ProtonVPN", "cyberghost": "CyberGhost", "pia": "PIA",
		"mullvad": "Mullvad", "ipvanish": "IPVanish", "windscribe": "Windscribe",
		"aws": "AWS", "azure": "Azure", "gcp": "GCP", "digitalocean": "DigitalOcean",
		"linode": "Linode", "vultr": "Vultr", "ovh": "OVH", "hetzner": "Hetzner",
	}
	if normalized, ok := knownProviders[strings.ToLower(provider)]; ok {
		return normalized
	}
	return provider
}

// ============================================================================
// Single Record Operations
// ============================================================================

// InsertAnonymizationData inserts a single IP anonymization record
func (as *IPAnonymizationStorage) InsertAnonymizationData(record *AnonymizationRecord) error {
	if record == nil || record.IPAddress == "" {
		return fmt.Errorf("invalid anonymization record: IP address is required")
	}

	// Validate IP address
	if net.ParseIP(record.IPAddress) == nil {
		return fmt.Errorf("invalid IP address format: %s", record.IPAddress)
	}

	// Normalize type and provider
	record.AnonymizationType = NormalizeAnonymizationType(record.AnonymizationType)
	record.Provider = NormalizeProviderName(record.Provider)

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
		INSERT INTO ip_anonymization (ip_address, anonymization_type, provider, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = as.db.ExecuteInsert(query,
		record.IPAddress, record.AnonymizationType, record.Provider,
		record.Source, string(metadataJSON), record.FirstSeen, record.LastSeen,
	)

	if err != nil {
		return fmt.Errorf("failed to insert anonymization data for %s: %w", record.IPAddress, err)
	}

	as.logger.Printf("Inserted anonymization: %s (type=%s, provider=%s)",
		record.IPAddress, record.AnonymizationType, record.Provider)
	return nil
}

// UpsertAnonymizationData inserts or updates an anonymization record if IP already exists
func (as *IPAnonymizationStorage) UpsertAnonymizationData(record *AnonymizationRecord) error {
	if record == nil || record.IPAddress == "" {
		return fmt.Errorf("invalid anonymization record: IP address is required")
	}

	// Validate IP address
	if net.ParseIP(record.IPAddress) == nil {
		return fmt.Errorf("invalid IP address format: %s", record.IPAddress)
	}

	// Normalize
	record.AnonymizationType = NormalizeAnonymizationType(record.AnonymizationType)
	record.Provider = NormalizeProviderName(record.Provider)

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
		INSERT INTO ip_anonymization (ip_address, anonymization_type, provider, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (ip_address) DO UPDATE SET
			anonymization_type = COALESCE(EXCLUDED.anonymization_type, ip_anonymization.anonymization_type),
			provider = COALESCE(EXCLUDED.provider, ip_anonymization.provider),
			last_seen = EXCLUDED.last_seen,
			updated_at = NOW(),
			metadata = COALESCE(EXCLUDED.metadata, ip_anonymization.metadata)`

	_, err = as.db.ExecuteInsert(query,
		record.IPAddress, record.AnonymizationType, record.Provider,
		record.Source, string(metadataJSON), record.FirstSeen, record.LastSeen,
	)

	if err != nil {
		return fmt.Errorf("failed to upsert anonymization data for %s: %w", record.IPAddress, err)
	}

	as.logger.Printf("Upserted anonymization: %s", record.IPAddress)
	return nil
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkInsertAnonymizationData efficiently inserts multiple anonymization records in batches
func (as *IPAnonymizationStorage) BulkInsertAnonymizationData(records []*AnonymizationRecord) (*AnonymizationInsertStats, error) {
	stats := &AnonymizationInsertStats{
		TotalProcessed: int64(len(records)),
	}

	if len(records) == 0 {
		return stats, nil
	}

	// Filter and validate records
	var valid []*AnonymizationRecord
	for _, record := range records {
		if record == nil || record.IPAddress == "" {
			stats.Errors++
			continue
		}

		if net.ParseIP(record.IPAddress) == nil {
			stats.Errors++
			continue
		}

		// Normalize
		record.AnonymizationType = NormalizeAnonymizationType(record.AnonymizationType)
		record.Provider = NormalizeProviderName(record.Provider)

		// Count by type
		switch record.AnonymizationType {
		case "vpn":
			stats.VPNCount++
		case "tor":
			stats.TorCount++
		case "proxy":
			stats.ProxyCount++
		}

		valid = append(valid, record)
	}

	if len(valid) == 0 {
		return stats, nil
	}

	// Process in batches
	for i := 0; i < len(valid); i += as.batchSize {
		end := i + as.batchSize
		if end > len(valid) {
			end = len(valid)
		}
		batch := valid[i:end]

		inserted, err := as.insertAnonymizationBatch(batch)
		if err != nil {
			as.logger.Printf("Batch insert error: %v", err)
			stats.Errors += int64(len(batch))
			continue
		}
		stats.Inserted += inserted
	}

	as.logger.Printf("Bulk anonymization insert completed: %d inserted, %d errors (VPN: %d, Tor: %d, Proxy: %d)",
		stats.Inserted, stats.Errors, stats.VPNCount, stats.TorCount, stats.ProxyCount)

	return stats, nil
}

// insertAnonymizationBatch inserts a batch of records within a transaction
func (as *IPAnonymizationStorage) insertAnonymizationBatch(batch []*AnonymizationRecord) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tx, err := as.db.BeginTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	query := `
		INSERT INTO ip_anonymization (ip_address, anonymization_type, provider, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (ip_address) DO UPDATE SET
			anonymization_type = COALESCE(EXCLUDED.anonymization_type, ip_anonymization.anonymization_type),
			provider = COALESCE(EXCLUDED.provider, ip_anonymization.provider),
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
			record.IPAddress, record.AnonymizationType, record.Provider,
			record.Source, string(metadataJSON), now, now,
		)
		if err != nil {
			as.logger.Printf("Row insert error for %s: %v", record.IPAddress, err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return inserted, nil
}

// BulkUpsertAnonymizationData performs bulk upsert of anonymization records
func (as *IPAnonymizationStorage) BulkUpsertAnonymizationData(records []*AnonymizationRecord) (*AnonymizationInsertStats, error) {
	return as.BulkInsertAnonymizationData(records) // Uses same logic with ON CONFLICT
}

// ============================================================================
// Query Operations
// ============================================================================

// GetAnonymizationData retrieves anonymization data for a specific IP address
func (as *IPAnonymizationStorage) GetAnonymizationData(ipAddress string) (*AnonymizationRecord, error) {
	if net.ParseIP(ipAddress) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `
		SELECT id, ip_address, anonymization_type, provider, first_seen, last_seen, updated_at, source, metadata
		FROM ip_anonymization 
		WHERE ip_address = $1`

	row := as.db.QueryRow(query, ipAddress)

	record := &AnonymizationRecord{}
	var metadataJSON sql.NullString
	var updatedAt sql.NullTime

	err := row.Scan(
		&record.ID, &record.IPAddress, &record.AnonymizationType, &record.Provider,
		&record.FirstSeen, &record.LastSeen, &updatedAt, &record.Source, &metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get anonymization data: %w", err)
	}

	if updatedAt.Valid {
		record.UpdatedAt = updatedAt.Time
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &record.Metadata)
	}

	return record, nil
}

// IsAnonymized checks if an IP is in the anonymization database (fast boolean check)
func (as *IPAnonymizationStorage) IsAnonymized(ipAddress string) (bool, error) {
	if net.ParseIP(ipAddress) == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `SELECT EXISTS(SELECT 1 FROM ip_anonymization WHERE ip_address = $1)`

	var exists bool
	err := as.db.QueryRow(query, ipAddress).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check anonymization: %w", err)
	}

	return exists, nil
}

// GetAnonymizationType returns the anonymization type for an IP (tor, vpn, proxy, etc.)
func (as *IPAnonymizationStorage) GetAnonymizationType(ipAddress string) (string, error) {
	if net.ParseIP(ipAddress) == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `SELECT anonymization_type FROM ip_anonymization WHERE ip_address = $1`

	var anonType sql.NullString
	err := as.db.QueryRow(query, ipAddress).Scan(&anonType)
	if err == sql.ErrNoRows {
		return "", nil // Not found
	}
	if err != nil {
		return "", fmt.Errorf("failed to get anonymization type: %w", err)
	}

	if anonType.Valid {
		return anonType.String, nil
	}
	return "", nil
}

// GetTorExitNodes retrieves all Tor exit node IPs
func (as *IPAnonymizationStorage) GetTorExitNodes(limit int) ([]*AnonymizationRecord, error) {
	query := `
		SELECT id, ip_address, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE anonymization_type = 'tor'
		ORDER BY last_seen DESC
		LIMIT $1`

	rows, err := as.db.ExecuteQuery(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query Tor exit nodes: %w", err)
	}
	defer rows.Close()

	var records []*AnonymizationRecord
	for rows.Next() {
		record := &AnonymizationRecord{AnonymizationType: "tor"}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.Provider,
			&record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetVPNIPs retrieves all VPN IPs
func (as *IPAnonymizationStorage) GetVPNIPs(limit int) ([]*AnonymizationRecord, error) {
	query := `
		SELECT id, ip_address, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE anonymization_type = 'vpn'
		ORDER BY last_seen DESC
		LIMIT $1`

	rows, err := as.db.ExecuteQuery(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query VPN IPs: %w", err)
	}
	defer rows.Close()

	var records []*AnonymizationRecord
	for rows.Next() {
		record := &AnonymizationRecord{AnonymizationType: "vpn"}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.Provider,
			&record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetVPNIPsByProvider retrieves all VPN IPs from a specific provider
func (as *IPAnonymizationStorage) GetVPNIPsByProvider(providerName string, limit int) ([]*AnonymizationRecord, error) {
	query := `
		SELECT id, ip_address, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE anonymization_type = 'vpn' AND provider ILIKE $1
		ORDER BY last_seen DESC
		LIMIT $2`

	rows, err := as.db.ExecuteQuery(query, "%"+providerName+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query VPN IPs by provider: %w", err)
	}
	defer rows.Close()

	var records []*AnonymizationRecord
	for rows.Next() {
		record := &AnonymizationRecord{AnonymizationType: "vpn"}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.Provider,
			&record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetProxyIPs retrieves all proxy IPs
func (as *IPAnonymizationStorage) GetProxyIPs(limit int) ([]*AnonymizationRecord, error) {
	query := `
		SELECT id, ip_address, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE anonymization_type = 'proxy'
		ORDER BY last_seen DESC
		LIMIT $1`

	rows, err := as.db.ExecuteQuery(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query proxy IPs: %w", err)
	}
	defer rows.Close()

	var records []*AnonymizationRecord
	for rows.Next() {
		record := &AnonymizationRecord{AnonymizationType: "proxy"}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.Provider,
			&record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetDatacenterIPs retrieves all datacenter/hosting IPs
func (as *IPAnonymizationStorage) GetDatacenterIPs(limit int) ([]*AnonymizationRecord, error) {
	query := `
		SELECT id, ip_address, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE anonymization_type IN ('datacenter', 'hosting')
		ORDER BY last_seen DESC
		LIMIT $1`

	rows, err := as.db.ExecuteQuery(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query datacenter IPs: %w", err)
	}
	defer rows.Close()

	var records []*AnonymizationRecord
	for rows.Next() {
		record := &AnonymizationRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.Provider,
			&record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetAnonymizationByType retrieves IPs by anonymization type
func (as *IPAnonymizationStorage) GetAnonymizationByType(anonType string, limit int) ([]*AnonymizationRecord, error) {
	anonType = NormalizeAnonymizationType(anonType)

	query := `
		SELECT id, ip_address, anonymization_type, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE anonymization_type = $1
		ORDER BY last_seen DESC
		LIMIT $2`

	rows, err := as.db.ExecuteQuery(query, anonType, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query anonymization by type: %w", err)
	}
	defer rows.Close()

	var records []*AnonymizationRecord
	for rows.Next() {
		record := &AnonymizationRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.AnonymizationType,
			&record.Provider, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// GetRecentAnonymizationIPs retrieves recently added anonymization IPs
func (as *IPAnonymizationStorage) GetRecentAnonymizationIPs(hours int, limit int) ([]*AnonymizationRecord, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	query := `
		SELECT id, ip_address, anonymization_type, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE first_seen >= $1
		ORDER BY first_seen DESC
		LIMIT $2`

	rows, err := as.db.ExecuteQuery(query, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent anonymization IPs: %w", err)
	}
	defer rows.Close()

	var records []*AnonymizationRecord
	for rows.Next() {
		record := &AnonymizationRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.AnonymizationType,
			&record.Provider, &record.FirstSeen, &record.LastSeen, &record.Source,
		)
		if err != nil {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

// SearchAnonymizationIPs performs pattern search on IPs
func (as *IPAnonymizationStorage) SearchAnonymizationIPs(pattern string, limit int) ([]*AnonymizationRecord, error) {
	query := `
		SELECT id, ip_address, anonymization_type, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE ip_address::text LIKE $1
		ORDER BY last_seen DESC
		LIMIT $2`

	rows, err := as.db.ExecuteQuery(query, pattern, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search anonymization IPs: %w", err)
	}
	defer rows.Close()

	var records []*AnonymizationRecord
	for rows.Next() {
		record := &AnonymizationRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.AnonymizationType,
			&record.Provider, &record.FirstSeen, &record.LastSeen, &record.Source,
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

// UpdateAnonymizationType updates the type of an anonymization IP
func (as *IPAnonymizationStorage) UpdateAnonymizationType(ipAddress, newType string) error {
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	newType = NormalizeAnonymizationType(newType)
	if !ValidateAnonymizationType(newType) {
		return fmt.Errorf("invalid anonymization type: %s", newType)
	}

	query := `UPDATE ip_anonymization SET anonymization_type = $1, updated_at = NOW() WHERE ip_address = $2`

	affected, err := as.db.ExecuteUpdate(query, newType, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to update anonymization type: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	as.logger.Printf("Updated IP %s anonymization_type to: %s", ipAddress, newType)
	return nil
}

// UpdateAnonymizationProvider updates the provider of an anonymization IP
func (as *IPAnonymizationStorage) UpdateAnonymizationProvider(ipAddress, provider string) error {
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	provider = NormalizeProviderName(provider)

	query := `UPDATE ip_anonymization SET provider = $1, updated_at = NOW() WHERE ip_address = $2`

	affected, err := as.db.ExecuteUpdate(query, provider, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to update provider: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	as.logger.Printf("Updated IP %s provider to: %s", ipAddress, provider)
	return nil
}

// DeleteAnonymizationIP removes an IP from the anonymization database
func (as *IPAnonymizationStorage) DeleteAnonymizationIP(ipAddress string) error {
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `DELETE FROM ip_anonymization WHERE ip_address = $1`

	affected, err := as.db.ExecuteDelete(query, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to delete anonymization IP: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	as.logger.Printf("Deleted anonymization IP: %s", ipAddress)
	return nil
}

// DeleteOldAnonymizationEntries removes entries not seen since specified days
func (as *IPAnonymizationStorage) DeleteOldAnonymizationEntries(daysOld int) (int64, error) {
	if daysOld <= 0 {
		daysOld = as.inactiveDays
	}

	cutoffDate := time.Now().AddDate(0, 0, -daysOld)

	query := `DELETE FROM ip_anonymization WHERE last_seen < $1`

	affected, err := as.db.ExecuteDelete(query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old anonymization entries: %w", err)
	}

	as.logger.Printf("Deleted %d anonymization entries older than %d days", affected, daysOld)
	return affected, nil
}

// DeleteAnonymizationByType removes all entries of a specific type
func (as *IPAnonymizationStorage) DeleteAnonymizationByType(anonType string) (int64, error) {
	anonType = NormalizeAnonymizationType(anonType)

	query := `DELETE FROM ip_anonymization WHERE anonymization_type = $1`

	affected, err := as.db.ExecuteDelete(query, anonType)
	if err != nil {
		return 0, fmt.Errorf("failed to delete anonymization by type: %w", err)
	}

	as.logger.Printf("Deleted %d entries of type: %s", affected, anonType)
	return affected, nil
}

// ============================================================================
// Statistics Operations
// ============================================================================

// GetAnonymizationStats returns statistics about anonymization data
func (as *IPAnonymizationStorage) GetAnonymizationStats() (*AnonymizationStats, error) {
	stats := &AnonymizationStats{
		TypeCounts: make(map[string]int64),
	}

	// Total IPs
	err := as.db.QueryRow(`SELECT COUNT(*) FROM ip_anonymization`).Scan(&stats.TotalIPs)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to count IPs: %w", err)
	}

	// VPN count
	as.db.QueryRow(`SELECT COUNT(*) FROM ip_anonymization WHERE anonymization_type = 'vpn'`).Scan(&stats.VPNCount)

	// Tor count
	as.db.QueryRow(`SELECT COUNT(*) FROM ip_anonymization WHERE anonymization_type = 'tor'`).Scan(&stats.TorCount)

	// Proxy count
	as.db.QueryRow(`SELECT COUNT(*) FROM ip_anonymization WHERE anonymization_type = 'proxy'`).Scan(&stats.ProxyCount)

	// Hosting count
	as.db.QueryRow(`SELECT COUNT(*) FROM ip_anonymization WHERE anonymization_type = 'hosting'`).Scan(&stats.HostingCount)

	// Datacenter count
	as.db.QueryRow(`SELECT COUNT(*) FROM ip_anonymization WHERE anonymization_type = 'datacenter'`).Scan(&stats.DatacenterCount)

	// Unique providers
	as.db.QueryRow(`SELECT COUNT(DISTINCT provider) FROM ip_anonymization WHERE provider IS NOT NULL AND provider != ''`).Scan(&stats.UniqueProviders)

	// Type counts
	rows, err := as.db.ExecuteQuery(`
		SELECT COALESCE(anonymization_type, 'unknown'), COUNT(*) 
		FROM ip_anonymization 
		GROUP BY anonymization_type`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var anonType string
			var count int64
			if err := rows.Scan(&anonType, &count); err == nil {
				stats.TypeCounts[anonType] = count
			}
		}
	}

	return stats, nil
}

// GetAnonymizationCount returns total count of anonymization IPs
func (as *IPAnonymizationStorage) GetAnonymizationCount() (int64, error) {
	var count int64
	err := as.db.QueryRow(`SELECT COUNT(*) FROM ip_anonymization`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count anonymization IPs: %w", err)
	}
	return count, nil
}

// GetProviderDistribution returns count of IPs per provider
func (as *IPAnonymizationStorage) GetProviderDistribution(limit int) (map[string]int64, error) {
	query := `
		SELECT COALESCE(provider, 'unknown'), COUNT(*) as count
		FROM ip_anonymization 
		WHERE provider IS NOT NULL AND provider != ''
		GROUP BY provider
		ORDER BY count DESC
		LIMIT $1`

	rows, err := as.db.ExecuteQuery(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider distribution: %w", err)
	}
	defer rows.Close()

	distribution := make(map[string]int64)
	for rows.Next() {
		var provider string
		var count int64
		if err := rows.Scan(&provider, &count); err != nil {
			continue
		}
		distribution[provider] = count
	}

	return distribution, nil
}

// GetTypeDistribution returns count of IPs per anonymization type
func (as *IPAnonymizationStorage) GetTypeDistribution() (map[string]int64, error) {
	query := `
		SELECT COALESCE(anonymization_type, 'unknown'), COUNT(*) as count
		FROM ip_anonymization 
		GROUP BY anonymization_type
		ORDER BY count DESC`

	rows, err := as.db.ExecuteQuery(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get type distribution: %w", err)
	}
	defer rows.Close()

	distribution := make(map[string]int64)
	for rows.Next() {
		var anonType string
		var count int64
		if err := rows.Scan(&anonType, &count); err != nil {
			continue
		}
		distribution[anonType] = count
	}

	return distribution, nil
}

// ============================================================================
// Legacy Compatibility Methods (for existing code using DB methods directly)
// ============================================================================

// StoreIPAnonymization stores IP anonymization data (legacy compatibility method on DB)
func (db *DB) StoreIPAnonymization(ip, anonType, provider, source string, metadata string) error {
	anonType = NormalizeAnonymizationType(anonType)
	provider = NormalizeProviderName(provider)

	query := `
		INSERT INTO ip_anonymization (ip_address, anonymization_type, provider, source, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (ip_address) 
		DO UPDATE SET 
			anonymization_type = EXCLUDED.anonymization_type,
			provider = EXCLUDED.provider,
			last_seen = EXCLUDED.last_seen,
			updated_at = NOW()
	`

	now := time.Now()
	_, err := db.conn.Exec(query, ip, anonType, provider, source, metadata, now, now)
	if err != nil {
		return fmt.Errorf("failed to store IP anonymization: %w", err)
	}

	return nil
}

// GetIPAnonymization retrieves IP anonymization data (legacy compatibility method on DB)
func (db *DB) GetIPAnonymization(ipAddress string) (map[string]interface{}, error) {
	query := `
		SELECT ip_address, anonymization_type, provider, first_seen, last_seen, source
		FROM ip_anonymization 
		WHERE ip_address = $1`

	row := db.QueryRow(query, ipAddress)

	var ip, anonType, provider, source string
	var firstSeen, lastSeen time.Time

	err := row.Scan(&ip, &anonType, &provider, &firstSeen, &lastSeen, &source)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get IP anonymization: %w", err)
	}

	result := map[string]interface{}{
		"ip_address":         ip,
		"anonymization_type": anonType,
		"provider":           provider,
		"first_seen":         firstSeen,
		"last_seen":          lastSeen,
		"source":             source,
	}

	return result, nil
}
