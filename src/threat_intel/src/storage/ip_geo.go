package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// =============================================================================
// IP Geolocation Storage - Manages ip_geolocation table
// For IP location and network information (reference data)
// Can be used directly by any program
// =============================================================================

// IPGeoStorage handles IP geolocation data
type IPGeoStorage struct {
	db        *DB
	tableName string
}

// IPGeoRecord represents an IP geolocation entry
type IPGeoRecord struct {
	ID             int64     `json:"id"`
	IPAddress      string    `json:"ip_address"`
	IPEnd          string    `json:"ip_end,omitempty"` // For range-based records
	CountryCode    string    `json:"country_code,omitempty"`
	CountryName    string    `json:"country_name,omitempty"`
	City           string    `json:"city,omitempty"`
	Region         string    `json:"region,omitempty"`
	PostalCode     string    `json:"postal_code,omitempty"`
	Latitude       float64   `json:"latitude,omitempty"`
	Longitude      float64   `json:"longitude,omitempty"`
	AccuracyRadius int       `json:"accuracy_radius,omitempty"`
	ASN            int       `json:"asn,omitempty"`
	ASNOrg         string    `json:"asn_org,omitempty"`
	ISP            string    `json:"isp,omitempty"`
	ConnectionType string    `json:"connection_type,omitempty"` // Cable/DSL/Cellular
	Timezone       string    `json:"timezone,omitempty"`
	IsMobile       bool      `json:"is_mobile"`
	IsHosting      bool      `json:"is_hosting"`
	Sources        []string  `json:"sources"`
	Confidence     int       `json:"confidence"`
	LastUpdated    time.Time `json:"last_updated"`
	CreatedAt      time.Time `json:"created_at"`
}

// IPGeoTableName is the table name
const IPGeoTableName = "ip_geolocation"

// NewIPGeoStorage creates a new IP geolocation storage instance
func NewIPGeoStorage(db *DB) *IPGeoStorage {
	return &IPGeoStorage{
		db:        db,
		tableName: IPGeoTableName,
	}
}

// =============================================================================
// Table Information
// =============================================================================

// GetTableInfo returns information about the ip_geolocation table
func (s *IPGeoStorage) GetTableInfo() (*TableInfo, error) {
	return s.db.GetTableInfo(s.tableName)
}

// GetHeaders returns column names for the ip_geolocation table
func (s *IPGeoStorage) GetHeaders() ([]string, error) {
	return s.db.GetColumnNames(s.tableName)
}

// TableExists checks if the ip_geolocation table exists
func (s *IPGeoStorage) TableExists() (bool, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return false, err
	}
	return info.Exists, nil
}

// GetRowCount returns the number of records in the table
func (s *IPGeoStorage) GetRowCount() (int64, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return 0, err
	}
	return info.RowCount, nil
}

// =============================================================================
// Column Management
// =============================================================================

// AddColumn adds a new column to the ip_geolocation table
func (s *IPGeoStorage) AddColumn(columnName, dataType, defaultValue string) error {
	return s.db.AddColumn(s.tableName, columnName, dataType, defaultValue)
}

// RemoveColumn removes a column from the ip_geolocation table
func (s *IPGeoStorage) RemoveColumn(columnName string) error {
	return s.db.RemoveColumn(s.tableName, columnName)
}

// RenameColumn renames a column in the ip_geolocation table
func (s *IPGeoStorage) RenameColumn(oldName, newName string) error {
	return s.db.RenameColumn(s.tableName, oldName, newName)
}

// =============================================================================
// CRUD Operations
// =============================================================================

// Insert adds a new IP geolocation record
func (s *IPGeoStorage) Insert(ctx context.Context, record *IPGeoRecord) error {
	query := `
		INSERT INTO ip_geolocation (
			ip_address, ip_end, country_code, country_name, city, region,
			postal_code, latitude, longitude, accuracy_radius,
			asn, asn_org, isp, connection_type, timezone,
			is_mobile, is_hosting, sources, confidence,
			last_updated, created_at
		) VALUES (
			$1::inet, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
		ON CONFLICT (ip_address) DO UPDATE SET
			country_code = COALESCE(EXCLUDED.country_code, ip_geolocation.country_code),
			country_name = COALESCE(EXCLUDED.country_name, ip_geolocation.country_name),
			city = COALESCE(EXCLUDED.city, ip_geolocation.city),
			asn = COALESCE(EXCLUDED.asn, ip_geolocation.asn),
			asn_org = COALESCE(EXCLUDED.asn_org, ip_geolocation.asn_org),
			ip_end = COALESCE(EXCLUDED.ip_end, ip_geolocation.ip_end),
			last_updated = NOW()
	`

	var ipEnd interface{}
	if record.IPEnd != "" {
		ipEnd = record.IPEnd
	} else {
		ipEnd = nil
	}

	_, err := s.db.ExecContext(ctx, query,
		record.IPAddress, ipEnd, record.CountryCode, record.CountryName,
		record.City, record.Region, record.PostalCode,
		record.Latitude, record.Longitude, record.AccuracyRadius,
		record.ASN, record.ASNOrg, record.ISP, record.ConnectionType,
		record.Timezone, record.IsMobile, record.IsHosting,
		toJSONArray(record.Sources), record.Confidence,
		record.LastUpdated, record.CreatedAt,
	)
	return err
}

// BulkInsertIPRanges inserts IP-to-ASN data (IP range to ASN mapping)
func (s *IPGeoStorage) BulkInsertIPRanges(ctx context.Context, records []IPGeoRecord, source string) (int64, error) {
	if len(records) == 0 {
		return 0, nil
	}

	now := time.Now()
	columns := []string{
		"ip_address", "ip_end", "country_code", "asn", "asn_org",
		"sources", "confidence", "last_updated", "created_at",
	}

	values := make([][]interface{}, len(records))
	for i, rec := range records {
		var ipEnd interface{}
		if rec.IPEnd != "" {
			ipEnd = rec.IPEnd
		} else {
			ipEnd = nil
		}

		values[i] = []interface{}{
			rec.IPAddress,
			ipEnd,
			rec.CountryCode,
			rec.ASN,
			rec.ASNOrg,
			fmt.Sprintf(`["%s"]`, source),
			50, // default confidence
			now,
			now,
		}
	}

	return s.db.BulkInsert(s.tableName, columns, values)
}

// GetByIP retrieves geolocation info for an IP
func (s *IPGeoStorage) GetByIP(ctx context.Context, ip string) (*IPGeoRecord, error) {
	// Look for exact match OR range containment
	// Priority: Exact match > Range match (highest confidence/latest update)
	// For now, simpler: finds any valid record covering the IP
	query := `
		SELECT id, ip_address::text, ip_end::text, country_code, country_name, city, region,
			   postal_code, latitude, longitude, accuracy_radius,
			   asn, asn_org, isp, connection_type, timezone,
			   is_mobile, is_hosting, confidence, last_updated, created_at
		FROM ip_geolocation
		WHERE ip_address = $1::inet 
		   OR ($1::inet BETWEEN ip_address AND ip_end)
		ORDER BY ip_address DESC -- Logic: More specific (higher start IP) likely smaller range? Roughly.
		LIMIT 1
	`

	var record IPGeoRecord
	var ipEnd sql.NullString

	err := s.db.QueryRowContext(ctx, query, ip).Scan(
		&record.ID, &record.IPAddress, &ipEnd, &record.CountryCode, &record.CountryName,
		&record.City, &record.Region, &record.PostalCode,
		&record.Latitude, &record.Longitude, &record.AccuracyRadius,
		&record.ASN, &record.ASNOrg, &record.ISP, &record.ConnectionType,
		&record.Timezone, &record.IsMobile, &record.IsHosting,
		&record.Confidence, &record.LastUpdated, &record.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if ipEnd.Valid {
		record.IPEnd = ipEnd.String
	}

	return &record, nil
}

// GetCountry gets just the country code for an IP (quick lookup)
func (s *IPGeoStorage) GetCountry(ctx context.Context, ip string) (string, error) {
	query := `SELECT country_code FROM ip_geolocation WHERE ip_address = $1::inet`
	var country string
	err := s.db.QueryRowContext(ctx, query, ip).Scan(&country)
	return country, err
}

// GetASN gets the ASN for an IP
func (s *IPGeoStorage) GetASN(ctx context.Context, ip string) (int, string, error) {
	query := `SELECT asn, asn_org FROM ip_geolocation WHERE ip_address = $1::inet`
	var asn int
	var asnOrg string
	err := s.db.QueryRowContext(ctx, query, ip).Scan(&asn, &asnOrg)
	return asn, asnOrg, err
}

// GetByCountry returns IPs from a specific country
func (s *IPGeoStorage) GetByCountry(ctx context.Context, countryCode string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 1000
	}

	query := `
		SELECT ip_address::text 
		FROM ip_geolocation 
		WHERE country_code = $1
		ORDER BY last_updated DESC
		LIMIT $2
	`

	rows, err := s.db.QueryContext(ctx, query, countryCode, limit)
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

// GetByASN returns IPs for a specific ASN
func (s *IPGeoStorage) GetByASN(ctx context.Context, asn int, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 1000
	}

	query := `
		SELECT ip_address::text 
		FROM ip_geolocation 
		WHERE asn = $1
		LIMIT $2
	`

	rows, err := s.db.QueryContext(ctx, query, asn, limit)
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

// GetCountryStats returns count of IPs per country
func (s *IPGeoStorage) GetCountryStats(ctx context.Context) (map[string]int64, error) {
	query := `
		SELECT country_code, COUNT(*) as count
		FROM ip_geolocation
		WHERE country_code IS NOT NULL AND country_code != ''
		GROUP BY country_code
		ORDER BY count DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]int64)
	for rows.Next() {
		var code string
		var count int64
		if err := rows.Scan(&code, &count); err != nil {
			continue
		}
		stats[code] = count
	}

	return stats, nil
}

// GetASNStats returns count of IPs per ASN (top N)
func (s *IPGeoStorage) GetASNStats(ctx context.Context, topN int) ([]map[string]interface{}, error) {
	if topN <= 0 {
		topN = 20
	}

	query := `
		SELECT asn, asn_org, COUNT(*) as count
		FROM ip_geolocation
		WHERE asn IS NOT NULL AND asn > 0
		GROUP BY asn, asn_org
		ORDER BY count DESC
		LIMIT $1
	`

	rows, err := s.db.QueryContext(ctx, query, topN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []map[string]interface{}
	for rows.Next() {
		var asn int
		var asnOrg string
		var count int64
		if err := rows.Scan(&asn, &asnOrg, &count); err != nil {
			continue
		}
		stats = append(stats, map[string]interface{}{
			"asn":     asn,
			"asn_org": asnOrg,
			"count":   count,
		})
	}

	return stats, nil
}

// NearbySearch finds IPs within a radius (in km) of coordinates
func (s *IPGeoStorage) NearbySearch(ctx context.Context, lat, lon float64, radiusKm int, limit int) ([]IPGeoRecord, error) {
	if limit <= 0 {
		limit = 100
	}

	// Use Haversine formula approximation
	query := `
		SELECT id, ip_address::text, country_code, city, latitude, longitude
		FROM ip_geolocation
		WHERE latitude IS NOT NULL AND longitude IS NOT NULL
		AND (
			6371 * acos(
				cos(radians($1)) * cos(radians(latitude)) * cos(radians(longitude) - radians($2)) +
				sin(radians($1)) * sin(radians(latitude))
			)
		) <= $3
		LIMIT $4
	`

	rows, err := s.db.QueryContext(ctx, query, lat, lon, radiusKm, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []IPGeoRecord
	for rows.Next() {
		var r IPGeoRecord
		if err := rows.Scan(&r.ID, &r.IPAddress, &r.CountryCode, &r.City, &r.Latitude, &r.Longitude); err != nil {
			continue
		}
		records = append(records, r)
	}

	return records, nil
}
