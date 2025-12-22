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
// IP Geolocation Storage - Connects with ip_geolocation table
// ============================================================================

// IPGeoStorage manages IP geolocation database operations.
// Stores enriched location information (country, city, coordinates, ASN)
// for use in threat context and geographic analysis.
type IPGeoStorage struct {
	db        *DB
	batchSize int
	logger    *log.Logger
}

// GeoLocationRecord represents an IP geolocation entry matching ip_geolocation table
type GeoLocationRecord struct {
	ID           int64          `json:"id"`
	IPAddress    string         `json:"ip_address"`
	CountryCode  string         `json:"country_code"`
	CountryName  string         `json:"country_name"`
	Region       string         `json:"region"`
	City         string         `json:"city"`
	Latitude     float64        `json:"latitude"`
	Longitude    float64        `json:"longitude"`
	Timezone     string         `json:"timezone"`
	ISP          string         `json:"isp"`
	Organization string         `json:"organization"`
	ASN          int            `json:"asn"`
	ASNOrg       string         `json:"asn_org"`
	UpdatedAt    time.Time      `json:"updated_at"`
	Source       string         `json:"source"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// GeoStats holds IP geolocation database statistics
type GeoStats struct {
	TotalIPs        int64 `json:"total_ips"`
	UniqueCountries int64 `json:"unique_countries"`
	UniqueASNs      int64 `json:"unique_asns"`
	UniqueCities    int64 `json:"unique_cities"`
}

// GeoInsertStats tracks bulk insert operation results
type GeoInsertStats struct {
	TotalProcessed int64 `json:"total_processed"`
	Inserted       int64 `json:"inserted"`
	Updated        int64 `json:"updated"`
	Errors         int64 `json:"errors"`
}

// ============================================================================
// Constructor & Validation Utilities
// ============================================================================

// NewIPGeoStorage creates a new IP geolocation storage handler
func NewIPGeoStorage(database *DB) *IPGeoStorage {
	return &IPGeoStorage{
		db:        database,
		batchSize: getEnvIntOrDefault("STORAGE_BATCH_SIZE", 1000),
		logger:    log.New(os.Stdout, "[IPGeoStorage] ", log.LstdFlags),
	}
}

// ValidateIP validates an IP address format (IPv4 or IPv6)
func ValidateIP(ipAddress string) bool {
	return net.ParseIP(ipAddress) != nil
}

// ValidateCoordinates validates latitude/longitude ranges
func ValidateCoordinates(lat, lon float64) bool {
	return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180
}

// ValidateASN validates ASN is a positive integer
func ValidateASN(asn int) bool {
	return asn >= 0
}

// ============================================================================
// Single Record Operations
// ============================================================================

// InsertGeoLocation inserts a single IP geolocation record into database
func (gs *IPGeoStorage) InsertGeoLocation(record *GeoLocationRecord) error {
	if record == nil || record.IPAddress == "" {
		return fmt.Errorf("invalid geolocation record: IP address is required")
	}

	// Validate IP address
	if !ValidateIP(record.IPAddress) {
		return fmt.Errorf("invalid IP address format: %s", record.IPAddress)
	}

	// Validate coordinates if provided
	if record.Latitude != 0 || record.Longitude != 0 {
		if !ValidateCoordinates(record.Latitude, record.Longitude) {
			gs.logger.Printf("Warning: Invalid coordinates for %s (lat: %f, lon: %f)",
				record.IPAddress, record.Latitude, record.Longitude)
		}
	}

	// Set updated timestamp
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = time.Now()
	}

	// Convert metadata to JSONB
	metadataJSON, err := json.Marshal(record.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO ip_geolocation (
			ip_address, country_code, country_name, region, city,
			latitude, longitude, timezone, isp, organization, 
			asn, asn_org, updated_at, source, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`

	_, err = gs.db.ExecuteInsert(query,
		record.IPAddress, record.CountryCode, record.CountryName,
		record.Region, record.City, record.Latitude, record.Longitude,
		record.Timezone, record.ISP, record.Organization,
		record.ASN, record.ASNOrg, record.UpdatedAt, record.Source, string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to insert geolocation for %s: %w", record.IPAddress, err)
	}

	gs.logger.Printf("Inserted geolocation: %s (%s, %s)",
		record.IPAddress, record.CountryCode, record.City)
	return nil
}

// UpsertGeoLocation inserts or updates a geolocation record if IP already exists
func (gs *IPGeoStorage) UpsertGeoLocation(record *GeoLocationRecord) error {
	if record == nil || record.IPAddress == "" {
		return fmt.Errorf("invalid geolocation record: IP address is required")
	}

	// Validate IP address
	if !ValidateIP(record.IPAddress) {
		return fmt.Errorf("invalid IP address format: %s", record.IPAddress)
	}

	now := time.Now()
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = now
	}

	// Convert metadata to JSONB
	metadataJSON, err := json.Marshal(record.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO ip_geolocation (
			ip_address, country_code, country_name, region, city,
			latitude, longitude, timezone, isp, organization, 
			asn, asn_org, updated_at, source, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (ip_address) DO UPDATE SET
			country_code = EXCLUDED.country_code,
			country_name = EXCLUDED.country_name,
			region = EXCLUDED.region,
			city = EXCLUDED.city,
			latitude = EXCLUDED.latitude,
			longitude = EXCLUDED.longitude,
			timezone = EXCLUDED.timezone,
			isp = EXCLUDED.isp,
			organization = EXCLUDED.organization,
			asn = EXCLUDED.asn,
			asn_org = EXCLUDED.asn_org,
			updated_at = EXCLUDED.updated_at,
			source = EXCLUDED.source,
			metadata = COALESCE(EXCLUDED.metadata, ip_geolocation.metadata)`

	_, err = gs.db.ExecuteInsert(query,
		record.IPAddress, record.CountryCode, record.CountryName,
		record.Region, record.City, record.Latitude, record.Longitude,
		record.Timezone, record.ISP, record.Organization,
		record.ASN, record.ASNOrg, record.UpdatedAt, record.Source, string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to upsert geolocation for %s: %w", record.IPAddress, err)
	}

	gs.logger.Printf("Upserted geolocation: %s", record.IPAddress)
	return nil
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkInsertGeoLocations efficiently inserts multiple geolocation records in batches
func (gs *IPGeoStorage) BulkInsertGeoLocations(records []*GeoLocationRecord) (*GeoInsertStats, error) {
	stats := &GeoInsertStats{
		TotalProcessed: int64(len(records)),
	}

	if len(records) == 0 {
		return stats, nil
	}

	// Filter and validate records
	var valid []*GeoLocationRecord
	for _, record := range records {
		if record == nil || record.IPAddress == "" {
			stats.Errors++
			continue
		}
		if !ValidateIP(record.IPAddress) {
			stats.Errors++
			continue
		}
		valid = append(valid, record)
	}

	if len(valid) == 0 {
		return stats, nil
	}

	// Process in batches
	for i := 0; i < len(valid); i += gs.batchSize {
		end := i + gs.batchSize
		if end > len(valid) {
			end = len(valid)
		}
		batch := valid[i:end]

		inserted, err := gs.insertGeoBatch(batch)
		if err != nil {
			gs.logger.Printf("Batch insert error: %v", err)
			stats.Errors += int64(len(batch))
			continue
		}
		stats.Inserted += inserted
	}

	gs.logger.Printf("Bulk geolocation insert completed: %d inserted, %d errors",
		stats.Inserted, stats.Errors)

	return stats, nil
}

// insertGeoBatch inserts a batch of geolocation records within a transaction
func (gs *IPGeoStorage) insertGeoBatch(batch []*GeoLocationRecord) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tx, err := gs.db.BeginTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	query := `
		INSERT INTO ip_geolocation (
			ip_address, country_code, country_name, region, city,
			latitude, longitude, timezone, isp, organization, 
			asn, asn_org, updated_at, source, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (ip_address) DO UPDATE SET
			country_code = EXCLUDED.country_code,
			country_name = EXCLUDED.country_name,
			city = EXCLUDED.city,
			latitude = EXCLUDED.latitude,
			longitude = EXCLUDED.longitude,
			asn = EXCLUDED.asn,
			updated_at = EXCLUDED.updated_at`

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
			record.IPAddress, record.CountryCode, record.CountryName,
			record.Region, record.City, record.Latitude, record.Longitude,
			record.Timezone, record.ISP, record.Organization,
			record.ASN, record.ASNOrg, now, record.Source, string(metadataJSON),
		)
		if err != nil {
			gs.logger.Printf("Row insert error for %s: %v", record.IPAddress, err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return inserted, nil
}

// BulkUpsertGeoLocations performs bulk upsert of geolocation records
func (gs *IPGeoStorage) BulkUpsertGeoLocations(records []*GeoLocationRecord) (*GeoInsertStats, error) {
	return gs.BulkInsertGeoLocations(records) // Uses same logic with ON CONFLICT
}

// ============================================================================
// Query Operations
// ============================================================================

// GetGeoLocation retrieves geolocation data for a specific IP address
func (gs *IPGeoStorage) GetGeoLocation(ipAddress string) (*GeoLocationRecord, error) {
	if !ValidateIP(ipAddress) {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `
		SELECT id, ip_address, country_code, country_name, region, city,
			   latitude, longitude, timezone, isp, organization, 
			   asn, asn_org, updated_at, source, metadata
		FROM ip_geolocation 
		WHERE ip_address = $1`

	row := gs.db.QueryRow(query, ipAddress)

	record := &GeoLocationRecord{}
	var metadataJSON sql.NullString
	var updatedAt sql.NullTime

	err := row.Scan(
		&record.ID, &record.IPAddress, &record.CountryCode, &record.CountryName,
		&record.Region, &record.City, &record.Latitude, &record.Longitude,
		&record.Timezone, &record.ISP, &record.Organization,
		&record.ASN, &record.ASNOrg, &updatedAt, &record.Source, &metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get geolocation: %w", err)
	}

	if updatedAt.Valid {
		record.UpdatedAt = updatedAt.Time
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &record.Metadata)
	}

	return record, nil
}

// GetGeoLocationsByCountry retrieves all IPs from a specific country
func (gs *IPGeoStorage) GetGeoLocationsByCountry(countryCode string, limit int) ([]*GeoLocationRecord, error) {
	query := `
		SELECT id, ip_address, country_code, country_name, region, city,
			   latitude, longitude, timezone, isp, asn, asn_org, updated_at, source
		FROM ip_geolocation 
		WHERE country_code = $1
		ORDER BY updated_at DESC
		LIMIT $2`

	rows, err := gs.db.ExecuteQuery(query, countryCode, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query geolocations by country: %w", err)
	}
	defer rows.Close()

	var records []*GeoLocationRecord
	for rows.Next() {
		record := &GeoLocationRecord{}
		var updatedAt sql.NullTime
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.CountryCode, &record.CountryName,
			&record.Region, &record.City, &record.Latitude, &record.Longitude,
			&record.Timezone, &record.ISP, &record.ASN, &record.ASNOrg,
			&updatedAt, &record.Source,
		)
		if err != nil {
			continue
		}
		if updatedAt.Valid {
			record.UpdatedAt = updatedAt.Time
		}
		records = append(records, record)
	}

	return records, nil
}

// GetGeoLocationsByASN retrieves all IPs belonging to a specific ASN
func (gs *IPGeoStorage) GetGeoLocationsByASN(asn int) ([]*GeoLocationRecord, error) {
	query := `
		SELECT id, ip_address, country_code, country_name, region, city,
			   latitude, longitude, timezone, isp, organization, asn, asn_org, updated_at, source
		FROM ip_geolocation 
		WHERE asn = $1
		ORDER BY updated_at DESC`

	rows, err := gs.db.ExecuteQuery(query, asn)
	if err != nil {
		return nil, fmt.Errorf("failed to query geolocations by ASN: %w", err)
	}
	defer rows.Close()

	var records []*GeoLocationRecord
	for rows.Next() {
		record := &GeoLocationRecord{}
		var updatedAt sql.NullTime
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.CountryCode, &record.CountryName,
			&record.Region, &record.City, &record.Latitude, &record.Longitude,
			&record.Timezone, &record.ISP, &record.Organization, &record.ASN,
			&record.ASNOrg, &updatedAt, &record.Source,
		)
		if err != nil {
			continue
		}
		if updatedAt.Valid {
			record.UpdatedAt = updatedAt.Time
		}
		records = append(records, record)
	}

	return records, nil
}

// GetGeoLocationsByCity retrieves all IPs from a specific city
func (gs *IPGeoStorage) GetGeoLocationsByCity(city string, limit int) ([]*GeoLocationRecord, error) {
	query := `
		SELECT id, ip_address, country_code, country_name, region, city,
			   latitude, longitude, asn, updated_at, source
		FROM ip_geolocation 
		WHERE city ILIKE $1
		ORDER BY updated_at DESC
		LIMIT $2`

	rows, err := gs.db.ExecuteQuery(query, city, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query geolocations by city: %w", err)
	}
	defer rows.Close()

	var records []*GeoLocationRecord
	for rows.Next() {
		record := &GeoLocationRecord{}
		var updatedAt sql.NullTime
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.CountryCode, &record.CountryName,
			&record.Region, &record.City, &record.Latitude, &record.Longitude,
			&record.ASN, &updatedAt, &record.Source,
		)
		if err != nil {
			continue
		}
		if updatedAt.Valid {
			record.UpdatedAt = updatedAt.Time
		}
		records = append(records, record)
	}

	return records, nil
}

// GetGeoLocationsByISP retrieves all IPs from a specific ISP
func (gs *IPGeoStorage) GetGeoLocationsByISP(isp string, limit int) ([]*GeoLocationRecord, error) {
	query := `
		SELECT id, ip_address, country_code, country_name, city, isp, asn, updated_at
		FROM ip_geolocation 
		WHERE isp ILIKE $1
		ORDER BY updated_at DESC
		LIMIT $2`

	rows, err := gs.db.ExecuteQuery(query, "%"+isp+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query geolocations by ISP: %w", err)
	}
	defer rows.Close()

	var records []*GeoLocationRecord
	for rows.Next() {
		record := &GeoLocationRecord{}
		var updatedAt sql.NullTime
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.CountryCode, &record.CountryName,
			&record.City, &record.ISP, &record.ASN, &updatedAt,
		)
		if err != nil {
			continue
		}
		if updatedAt.Valid {
			record.UpdatedAt = updatedAt.Time
		}
		records = append(records, record)
	}

	return records, nil
}

// GetRecentGeoLocations retrieves recently updated geolocation records
func (gs *IPGeoStorage) GetRecentGeoLocations(hours int, limit int) ([]*GeoLocationRecord, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	query := `
		SELECT id, ip_address, country_code, country_name, city, asn, updated_at, source
		FROM ip_geolocation 
		WHERE updated_at >= $1
		ORDER BY updated_at DESC
		LIMIT $2`

	rows, err := gs.db.ExecuteQuery(query, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent geolocations: %w", err)
	}
	defer rows.Close()

	var records []*GeoLocationRecord
	for rows.Next() {
		record := &GeoLocationRecord{}
		err := rows.Scan(
			&record.ID, &record.IPAddress, &record.CountryCode, &record.CountryName,
			&record.City, &record.ASN, &record.UpdatedAt, &record.Source,
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

// UpdateGeoLocationSource updates the source field of a geolocation record
func (gs *IPGeoStorage) UpdateGeoLocationSource(ipAddress, newSource string) error {
	if !ValidateIP(ipAddress) {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `UPDATE ip_geolocation SET source = $1, updated_at = NOW() WHERE ip_address = $2`

	affected, err := gs.db.ExecuteUpdate(query, newSource, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to update source: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	gs.logger.Printf("Updated geolocation source for %s to: %s", ipAddress, newSource)
	return nil
}

// DeleteGeoLocation removes a geolocation record from the database
func (gs *IPGeoStorage) DeleteGeoLocation(ipAddress string) error {
	if !ValidateIP(ipAddress) {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	query := `DELETE FROM ip_geolocation WHERE ip_address = $1`

	affected, err := gs.db.ExecuteDelete(query, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to delete geolocation: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ipAddress)
	}

	gs.logger.Printf("Deleted geolocation: %s", ipAddress)
	return nil
}

// DeleteOldGeoLocations removes geolocation records not updated since specified days
func (gs *IPGeoStorage) DeleteOldGeoLocations(daysOld int) (int64, error) {
	cutoffDate := time.Now().AddDate(0, 0, -daysOld)

	query := `DELETE FROM ip_geolocation WHERE updated_at < $1`

	affected, err := gs.db.ExecuteDelete(query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old geolocations: %w", err)
	}

	gs.logger.Printf("Deleted %d geolocations older than %d days", affected, daysOld)
	return affected, nil
}

// ============================================================================
// Statistics Operations
// ============================================================================

// GetGeoStats returns statistics about geolocation data in database
func (gs *IPGeoStorage) GetGeoStats() (*GeoStats, error) {
	stats := &GeoStats{}

	// Total IPs
	err := gs.db.QueryRow(`SELECT COUNT(*) FROM ip_geolocation`).Scan(&stats.TotalIPs)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to count IPs: %w", err)
	}

	// Unique countries
	gs.db.QueryRow(`SELECT COUNT(DISTINCT country_code) FROM ip_geolocation WHERE country_code IS NOT NULL`).Scan(&stats.UniqueCountries)

	// Unique ASNs
	gs.db.QueryRow(`SELECT COUNT(DISTINCT asn) FROM ip_geolocation WHERE asn IS NOT NULL AND asn > 0`).Scan(&stats.UniqueASNs)

	// Unique cities
	gs.db.QueryRow(`SELECT COUNT(DISTINCT city) FROM ip_geolocation WHERE city IS NOT NULL`).Scan(&stats.UniqueCities)

	return stats, nil
}

// GetGeoCount returns total count of geolocation records
func (gs *IPGeoStorage) GetGeoCount() (int64, error) {
	var count int64
	err := gs.db.QueryRow(`SELECT COUNT(*) FROM ip_geolocation`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count geolocations: %w", err)
	}
	return count, nil
}

// GetCountryDistribution returns count of IPs per country
func (gs *IPGeoStorage) GetCountryDistribution(limit int) (map[string]int64, error) {
	query := `
		SELECT country_code, COUNT(*) as count
		FROM ip_geolocation 
		WHERE country_code IS NOT NULL
		GROUP BY country_code
		ORDER BY count DESC
		LIMIT $1`

	rows, err := gs.db.ExecuteQuery(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get country distribution: %w", err)
	}
	defer rows.Close()

	distribution := make(map[string]int64)
	for rows.Next() {
		var countryCode string
		var count int64
		if err := rows.Scan(&countryCode, &count); err != nil {
			continue
		}
		distribution[countryCode] = count
	}

	return distribution, nil
}

// GetASNDistribution returns count of IPs per ASN
func (gs *IPGeoStorage) GetASNDistribution(limit int) (map[int]int64, error) {
	query := `
		SELECT asn, COUNT(*) as count
		FROM ip_geolocation 
		WHERE asn IS NOT NULL AND asn > 0
		GROUP BY asn
		ORDER BY count DESC
		LIMIT $1`

	rows, err := gs.db.ExecuteQuery(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get ASN distribution: %w", err)
	}
	defer rows.Close()

	distribution := make(map[int]int64)
	for rows.Next() {
		var asn int
		var count int64
		if err := rows.Scan(&asn, &count); err != nil {
			continue
		}
		distribution[asn] = count
	}

	return distribution, nil
}

// ============================================================================
// Legacy Compatibility Methods (for existing code using DB methods directly)
// ============================================================================

// StoreIPGeo stores IP geolocation data (legacy compatibility method on DB)
func (db *DB) StoreIPGeo(ip, countryCode, countryName, region, city, isp, org string, lat, lon float64, asn int, metadata string) error {
	query := `
		INSERT INTO ip_geolocation (
			ip_address, country_code, country_name, region, city,
			latitude, longitude, isp, organization, asn, updated_at, metadata
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (ip_address) 
		DO UPDATE SET 
			country_code = EXCLUDED.country_code,
			country_name = EXCLUDED.country_name,
			region = EXCLUDED.region,
			city = EXCLUDED.city,
			latitude = EXCLUDED.latitude,
			longitude = EXCLUDED.longitude,
			isp = EXCLUDED.isp,
			organization = EXCLUDED.organization,
			asn = EXCLUDED.asn,
			updated_at = EXCLUDED.updated_at
	`

	_, err := db.conn.Exec(query, ip, countryCode, countryName, region, city, lat, lon, isp, org, asn, time.Now(), metadata)
	if err != nil {
		return fmt.Errorf("failed to store IP geolocation: %w", err)
	}

	return nil
}

// GetIPGeoByAddress retrieves geolocation data for an IP (legacy compatibility method on DB)
func (db *DB) GetIPGeoByAddress(ipAddress string) (map[string]interface{}, error) {
	query := `
		SELECT ip_address, country_code, country_name, region, city, 
			   latitude, longitude, isp, organization, asn, updated_at
		FROM ip_geolocation 
		WHERE ip_address = $1`

	row := db.QueryRow(query, ipAddress)

	var ip, countryCode, countryName, region, city, isp, org string
	var lat, lon float64
	var asn int
	var updatedAt time.Time

	err := row.Scan(&ip, &countryCode, &countryName, &region, &city,
		&lat, &lon, &isp, &org, &asn, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get IP geolocation: %w", err)
	}

	result := map[string]interface{}{
		"ip_address":   ip,
		"country_code": countryCode,
		"country_name": countryName,
		"region":       region,
		"city":         city,
		"latitude":     lat,
		"longitude":    lon,
		"isp":          isp,
		"organization": org,
		"asn":          asn,
		"updated_at":   updatedAt,
	}

	return result, nil
}
