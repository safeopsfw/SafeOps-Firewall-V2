package storage

import (
	"context"
	"fmt"
	"time"
)

// =============================================================================
// IP Anonymization Storage - Manages ip_anonymization table
// For VPN, Tor, Proxy, and datacenter IP detection
// Can be used directly by any program
// =============================================================================

// IPAnonymizationStorage handles anonymization IP data
type IPAnonymizationStorage struct {
	db        *DB
	tableName string
}

// IPAnonymizationRecord represents an anonymization IP entry
type IPAnonymizationRecord struct {
	ID              int64     `json:"id"`
	IPAddress       string    `json:"ip_address"`
	IsVPN           bool      `json:"is_vpn"`
	IsTor           bool      `json:"is_tor"`
	IsProxy         bool      `json:"is_proxy"`
	IsDatacenter    bool      `json:"is_datacenter"`
	IsRelay         bool      `json:"is_relay"`
	IsHosting       bool      `json:"is_hosting"`
	ProviderName    string    `json:"provider_name,omitempty"`   // NordVPN, ExpressVPN, etc.
	ServiceType     string    `json:"service_type,omitempty"`    // commercial_vpn, free_vpn
	AnonymityLevel  string    `json:"anonymity_level,omitempty"` // transparent, anonymous, elite
	TorExitNode     bool      `json:"tor_exit_node"`
	TorNodeName     string    `json:"tor_node_name,omitempty"`
	ProxyType       string    `json:"proxy_type,omitempty"` // http, https, socks4, socks5
	ProxyPort       int       `json:"proxy_port,omitempty"`
	DatacenterName  string    `json:"datacenter_name,omitempty"`
	HostingProvider string    `json:"hosting_provider,omitempty"` // AWS, Azure, etc.
	CountryCode     string    `json:"country_code,omitempty"`
	City            string    `json:"city,omitempty"`
	RiskScore       int       `json:"risk_score"`
	AbuseHistory    bool      `json:"abuse_history"`
	IsActive        bool      `json:"is_active"`
	Sources         []string  `json:"sources"`
	Tags            []string  `json:"tags"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	LastUpdated     time.Time `json:"last_updated"`
}

// IPAnonymizationTableName is the table name
const IPAnonymizationTableName = "ip_anonymization"

// NewIPAnonymizationStorage creates a new IP anonymization storage instance
func NewIPAnonymizationStorage(db *DB) *IPAnonymizationStorage {
	return &IPAnonymizationStorage{
		db:        db,
		tableName: IPAnonymizationTableName,
	}
}

// =============================================================================
// Table Information
// =============================================================================

// GetTableInfo returns information about the ip_anonymization table
func (s *IPAnonymizationStorage) GetTableInfo() (*TableInfo, error) {
	return s.db.GetTableInfo(s.tableName)
}

// GetHeaders returns column names for the ip_anonymization table
func (s *IPAnonymizationStorage) GetHeaders() ([]string, error) {
	return s.db.GetColumnNames(s.tableName)
}

// TableExists checks if the ip_anonymization table exists
func (s *IPAnonymizationStorage) TableExists() (bool, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return false, err
	}
	return info.Exists, nil
}

// GetRowCount returns the number of records in the table
func (s *IPAnonymizationStorage) GetRowCount() (int64, error) {
	info, err := s.db.GetTableInfo(s.tableName)
	if err != nil {
		return 0, err
	}
	return info.RowCount, nil
}

// =============================================================================
// Column Management
// =============================================================================

// AddColumn adds a new column to the ip_anonymization table
func (s *IPAnonymizationStorage) AddColumn(columnName, dataType, defaultValue string) error {
	return s.db.AddColumn(s.tableName, columnName, dataType, defaultValue)
}

// RemoveColumn removes a column from the ip_anonymization table
func (s *IPAnonymizationStorage) RemoveColumn(columnName string) error {
	return s.db.RemoveColumn(s.tableName, columnName)
}

// RenameColumn renames a column in the ip_anonymization table
func (s *IPAnonymizationStorage) RenameColumn(oldName, newName string) error {
	return s.db.RenameColumn(s.tableName, oldName, newName)
}

// =============================================================================
// CRUD Operations
// =============================================================================

// Insert adds a new IP anonymization record
func (s *IPAnonymizationStorage) Insert(ctx context.Context, record *IPAnonymizationRecord) error {
	query := `
		INSERT INTO ip_anonymization (
			ip_address, is_vpn, is_tor, is_proxy, is_datacenter,
			is_relay, is_hosting, provider_name, service_type,
			anonymity_level, tor_exit_node, tor_node_name,
			proxy_type, proxy_port, datacenter_name, hosting_provider,
			country_code, city, risk_score, abuse_history, is_active,
			sources, tags, first_seen, last_seen, last_updated
		) VALUES (
			$1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 
			$13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26
		)
		ON CONFLICT (ip_address) DO UPDATE SET
			is_vpn = EXCLUDED.is_vpn OR ip_anonymization.is_vpn,
			is_tor = EXCLUDED.is_tor OR ip_anonymization.is_tor,
			is_proxy = EXCLUDED.is_proxy OR ip_anonymization.is_proxy,
			last_seen = EXCLUDED.last_seen,
			last_updated = NOW()
	`

	_, err := s.db.ExecContext(ctx, query,
		record.IPAddress, record.IsVPN, record.IsTor, record.IsProxy,
		record.IsDatacenter, record.IsRelay, record.IsHosting,
		record.ProviderName, record.ServiceType, record.AnonymityLevel,
		record.TorExitNode, record.TorNodeName,
		record.ProxyType, record.ProxyPort, record.DatacenterName,
		record.HostingProvider, record.CountryCode, record.City,
		record.RiskScore, record.AbuseHistory, record.IsActive,
		toJSONArray(record.Sources), toJSONArray(record.Tags),
		record.FirstSeen, record.LastSeen, record.LastUpdated,
	)
	return err
}

// BulkInsertTorNodes inserts Tor exit node IPs efficiently
func (s *IPAnonymizationStorage) BulkInsertTorNodes(ctx context.Context, ips []string, source string) (int64, error) {
	if len(ips) == 0 {
		return 0, nil
	}

	now := time.Now()
	columns := []string{
		"ip_address", "is_tor", "tor_exit_node", "is_active",
		"sources", "first_seen", "last_seen", "last_updated",
	}

	values := make([][]interface{}, len(ips))
	for i, ip := range ips {
		values[i] = []interface{}{
			ip,
			true, // is_tor
			true, // tor_exit_node
			true, // is_active
			fmt.Sprintf(`["%s"]`, source),
			now,
			now,
			now,
		}
	}

	return s.db.BulkInsert(s.tableName, columns, values)
}

// BulkInsertVPNs inserts VPN IPs efficiently
func (s *IPAnonymizationStorage) BulkInsertVPNs(ctx context.Context, ips []string, providerName string, source string) (int64, error) {
	if len(ips) == 0 {
		return 0, nil
	}

	now := time.Now()
	columns := []string{
		"ip_address", "is_vpn", "provider_name", "is_active",
		"sources", "first_seen", "last_seen", "last_updated",
	}

	values := make([][]interface{}, len(ips))
	for i, ip := range ips {
		values[i] = []interface{}{
			ip,
			true, // is_vpn
			providerName,
			true, // is_active
			fmt.Sprintf(`["%s"]`, source),
			now,
			now,
			now,
		}
	}

	return s.db.BulkInsert(s.tableName, columns, values)
}

// BulkInsertProxies inserts proxy IPs efficiently
func (s *IPAnonymizationStorage) BulkInsertProxies(ctx context.Context, ips []string, proxyType string, source string) (int64, error) {
	if len(ips) == 0 {
		return 0, nil
	}

	now := time.Now()
	columns := []string{
		"ip_address", "is_proxy", "proxy_type", "is_active",
		"sources", "first_seen", "last_seen", "last_updated",
	}

	values := make([][]interface{}, len(ips))
	for i, ip := range ips {
		values[i] = []interface{}{
			ip,
			true, // is_proxy
			proxyType,
			true, // is_active
			fmt.Sprintf(`["%s"]`, source),
			now,
			now,
			now,
		}
	}

	return s.db.BulkInsert(s.tableName, columns, values)
}

// GetByIP retrieves anonymization info for an IP
func (s *IPAnonymizationStorage) GetByIP(ctx context.Context, ip string) (*IPAnonymizationRecord, error) {
	query := `
		SELECT id, ip_address::text, is_vpn, is_tor, is_proxy, is_datacenter,
			   is_relay, is_hosting, provider_name, service_type,
			   tor_exit_node, tor_node_name, proxy_type,
			   datacenter_name, hosting_provider,
			   country_code, city, risk_score, is_active,
			   first_seen, last_seen, last_updated
		FROM ip_anonymization
		WHERE ip_address = $1::inet
	`

	var record IPAnonymizationRecord
	err := s.db.QueryRowContext(ctx, query, ip).Scan(
		&record.ID, &record.IPAddress, &record.IsVPN, &record.IsTor,
		&record.IsProxy, &record.IsDatacenter, &record.IsRelay, &record.IsHosting,
		&record.ProviderName, &record.ServiceType,
		&record.TorExitNode, &record.TorNodeName, &record.ProxyType,
		&record.DatacenterName, &record.HostingProvider,
		&record.CountryCode, &record.City, &record.RiskScore, &record.IsActive,
		&record.FirstSeen, &record.LastSeen, &record.LastUpdated,
	)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// CheckAnonymization checks if an IP uses anonymization (quick lookup)
func (s *IPAnonymizationStorage) CheckAnonymization(ctx context.Context, ip string) (isVPN, isTor, isProxy bool, err error) {
	query := `
		SELECT is_vpn, is_tor, is_proxy 
		FROM ip_anonymization 
		WHERE ip_address = $1::inet AND is_active = true
	`

	err = s.db.QueryRowContext(ctx, query, ip).Scan(&isVPN, &isTor, &isProxy)
	if err != nil {
		return false, false, false, nil // Not found = not anonymized
	}

	return isVPN, isTor, isProxy, nil
}

// GetTorExitNodes returns all active Tor exit node IPs
func (s *IPAnonymizationStorage) GetTorExitNodes(ctx context.Context) ([]string, error) {
	query := `
		SELECT ip_address::text 
		FROM ip_anonymization 
		WHERE is_tor = true AND tor_exit_node = true AND is_active = true
		ORDER BY last_seen DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
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

// GetVPNProviders returns distinct VPN provider names
func (s *IPAnonymizationStorage) GetVPNProviders(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT provider_name 
		FROM ip_anonymization 
		WHERE is_vpn = true AND provider_name IS NOT NULL AND provider_name != ''
		ORDER BY provider_name
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			continue
		}
		providers = append(providers, p)
	}

	return providers, nil
}

// GetStats returns anonymization type statistics
func (s *IPAnonymizationStorage) GetStats(ctx context.Context) (map[string]int64, error) {
	query := `
		SELECT 
			COUNT(*) FILTER (WHERE is_vpn = true) as vpn_count,
			COUNT(*) FILTER (WHERE is_tor = true) as tor_count,
			COUNT(*) FILTER (WHERE is_proxy = true) as proxy_count,
			COUNT(*) FILTER (WHERE is_datacenter = true) as datacenter_count,
			COUNT(*) FILTER (WHERE is_active = true) as active_count,
			COUNT(*) as total_count
		FROM ip_anonymization
	`

	var vpn, tor, proxy, datacenter, active, total int64
	err := s.db.QueryRowContext(ctx, query).Scan(&vpn, &tor, &proxy, &datacenter, &active, &total)
	if err != nil {
		return nil, err
	}

	return map[string]int64{
		"vpn":        vpn,
		"tor":        tor,
		"proxy":      proxy,
		"datacenter": datacenter,
		"active":     active,
		"total":      total,
	}, nil
}
