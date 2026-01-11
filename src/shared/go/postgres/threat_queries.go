// Package postgres provides threat intelligence query helpers for SafeOps database.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// ============================================================================
// IP Reputation Queries
// ============================================================================

// IPReputationResult contains comprehensive IP reputation data
type IPReputationResult struct {
	IPAddress     string
	IsMalicious   bool
	ThreatScore   int
	AbuseType     string
	Confidence    int
	Sources       []string
	EvidenceCount int
	Description   string
	FirstSeen     time.Time
	LastSeen      time.Time
}

// GetIPReputation queries ip_blacklist table for comprehensive IP intelligence
// Returns nil if IP not found (not in database = assume clean)
func (c *Client) GetIPReputation(ctx context.Context, ipAddr string) (*IPReputationResult, error) {
	var result IPReputationResult
	var sourcesJSON []byte

	err := c.pool.QueryRow(ctx, `
		SELECT ip_address::text, is_malicious, threat_score, abuse_type, confidence, 
		       sources, evidence_count, description, first_seen, last_seen
		FROM ip_blacklist
		WHERE ip_address = $1::inet
	`, ipAddr).Scan(
		&result.IPAddress,
		&result.IsMalicious,
		&result.ThreatScore,
		&result.AbuseType,
		&result.Confidence,
		&sourcesJSON,
		&result.EvidenceCount,
		&result.Description,
		&result.FirstSeen,
		&result.LastSeen,
	)

	if err == pgx.ErrNoRows {
		return nil, nil // IP not found - assume clean
	}
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_IP_REP_FAILED", "Failed to get IP reputation")
	}

	// Decode JSONB sources
	if len(sourcesJSON) > 0 {
		json.Unmarshal(sourcesJSON, &result.Sources)
	}

	return &result, nil
}

// BulkGetIPReputation batch queries for checking multiple IPs efficiently
func (c *Client) BulkGetIPReputation(ctx context.Context, ipAddrs []string) (map[string]*IPReputationResult, error) {
	results := make(map[string]*IPReputationResult)

	rows, err := c.pool.Query(ctx, `
		SELECT ip_address::text, is_malicious, threat_score, abuse_type, confidence,
		       sources, evidence_count, description, first_seen, last_seen
		FROM ip_blacklist
		WHERE ip_address = ANY($1::inet[])
	`, ipAddrs)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_BULK_IP_REP_FAILED", "Failed to bulk get IP reputations")
	}
	defer rows.Close()

	for rows.Next() {
		var result IPReputationResult
		var sourcesJSON []byte

		err := rows.Scan(
			&result.IPAddress,
			&result.IsMalicious,
			&result.ThreatScore,
			&result.AbuseType,
			&result.Confidence,
			&sourcesJSON,
			&result.EvidenceCount,
			&result.Description,
			&result.FirstSeen,
			&result.LastSeen,
		)
		if err != nil {
			return nil, c.classifyError(err, "POSTGRES_SCAN_IP_REP_FAILED", "Failed to scan IP reputation")
		}

		if len(sourcesJSON) > 0 {
			json.Unmarshal(sourcesJSON, &result.Sources)
		}

		results[result.IPAddress] = &result
	}

	return results, nil
}

// IsIPMalicious simplified boolean check
func (c *Client) IsIPMalicious(ctx context.Context, ipAddr string) (bool, error) {
	var isMalicious bool

	err := c.pool.QueryRow(ctx, `
		SELECT COALESCE((SELECT is_malicious FROM check_ip_malicious($1) LIMIT 1), FALSE)
	`, ipAddr).Scan(&isMalicious)

	if err != nil {
		return false, c.classifyError(err, "POSTGRES_IS_IP_MALICIOUS_FAILED", "Failed to check if IP is malicious")
	}

	return isMalicious, nil
}

// GetHighThreatIPs returns all IPs with threat_score >= minScore
func (c *Client) GetHighThreatIPs(ctx context.Context, minScore int) ([]*IPReputationResult, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT ip_address::text, is_malicious, threat_score, abuse_type, confidence,
		       sources, evidence_count, description, first_seen, last_seen
		FROM ip_blacklist
		WHERE threat_score >= $1 AND is_malicious = TRUE
		ORDER BY threat_score DESC
	`, minScore)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_HIGH_THREAT_IPS_FAILED", "Failed to get high threat IPs")
	}
	defer rows.Close()

	var results []*IPReputationResult
	for rows.Next() {
		var result IPReputationResult
		var sourcesJSON []byte

		err := rows.Scan(
			&result.IPAddress,
			&result.IsMalicious,
			&result.ThreatScore,
			&result.AbuseType,
			&result.Confidence,
			&sourcesJSON,
			&result.EvidenceCount,
			&result.Description,
			&result.FirstSeen,
			&result.LastSeen,
		)
		if err != nil {
			return nil, c.classifyError(err, "POSTGRES_SCAN_HIGH_THREAT_FAILED", "Failed to scan high threat IPs")
		}

		if len(sourcesJSON) > 0 {
			json.Unmarshal(sourcesJSON, &result.Sources)
		}

		results = append(results, &result)
	}

	return results, nil
}

// ============================================================================
// VPN/Proxy Detection
// ============================================================================

// VPNResult contains VPN/proxy detection information
type VPNResult struct {
	IPAddress   string
	IsVPN       bool
	VPNProvider string
	ServiceType string // commercial_vpn, tor_exit, proxy
	RiskScore   int
	LastSeen    time.Time
}

// CheckVPN queries vpn_ips table, returns nil if IP is not a VPN
func (c *Client) CheckVPN(ctx context.Context, ipAddr string) (*VPNResult, error) {
	var result VPNResult

	err := c.pool.QueryRow(ctx, `
		SELECT ip_address::text, TRUE, vpn_provider, service_type, risk_score, last_seen
		FROM vpn_ips
		WHERE ip_address = $1::inet AND is_active = TRUE
	`, ipAddr).Scan(
		&result.IPAddress,
		&result.IsVPN,
		&result.VPNProvider,
		&result.ServiceType,
		&result.RiskScore,
		&result.LastSeen,
	)

	if err == pgx.ErrNoRows {
		return nil, nil // Not a VPN
	}
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_CHECK_VPN_FAILED", "Failed to check VPN")
	}

	return &result, nil
}

// GetAllTorExitNodes returns list of all Tor exit node IP addresses
func (c *Client) GetAllTorExitNodes(ctx context.Context) ([]string, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT ip_address::text
		FROM vpn_ips
		WHERE service_type = 'tor_exit' AND is_active = TRUE
	`)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_TOR_NODES_FAILED", "Failed to get Tor exit nodes")
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, c.classifyError(err, "POSTGRES_SCAN_TOR_NODES_FAILED", "Failed to scan Tor nodes")
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// ============================================================================
// Domain Reputation Queries
// ============================================================================

// DomainReputationResult contains comprehensive domain reputation data
type DomainReputationResult struct {
	Domain            string
	RootDomain        string
	IsMalicious       bool
	ThreatScore       int
	Category          string
	ReportedReason    string
	PhishingTarget    sql.NullString
	Confidence        int
	Sources           []string
	FirstSeen         time.Time
	RegistrationDate  sql.NullTime
	IsNewlyRegistered bool
}

// GetDomainReputation queries domains table, returns nil if domain not in database
func (c *Client) GetDomainReputation(ctx context.Context, domain string) (*DomainReputationResult, error) {
	var result DomainReputationResult
	var sourcesJSON []byte

	err := c.pool.QueryRow(ctx, `
		SELECT domain, root_domain, is_malicious, threat_score, category,
		       reported_reason, phishing_target, confidence, sources, first_seen,
		       registration_date, is_newly_registered
		FROM domains
		WHERE domain = $1 AND status = 'active'
	`, domain).Scan(
		&result.Domain,
		&result.RootDomain,
		&result.IsMalicious,
		&result.ThreatScore,
		&result.Category,
		&result.ReportedReason,
		&result.PhishingTarget,
		&result.Confidence,
		&sourcesJSON,
		&result.FirstSeen,
		&result.RegistrationDate,
		&result.IsNewlyRegistered,
	)

	if err == pgx.ErrNoRows {
		return nil, nil // Domain not found
	}
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_DOMAIN_REP_FAILED", "Failed to get domain reputation")
	}

	if len(sourcesJSON) > 0 {
		json.Unmarshal(sourcesJSON, &result.Sources)
	}

	return &result, nil
}

// IsDomainMalicious simplified boolean check
func (c *Client) IsDomainMalicious(ctx context.Context, domain string) (bool, error) {
	var isMalicious bool

	err := c.pool.QueryRow(ctx, `
		SELECT COALESCE((SELECT is_malicious FROM check_domain_malicious($1) LIMIT 1), FALSE)
	`, domain).Scan(&isMalicious)

	if err != nil {
		return false, c.classifyError(err, "POSTGRES_IS_DOMAIN_MALICIOUS_FAILED", "Failed to check if domain is malicious")
	}

	return isMalicious, nil
}

// FindSimilarDomains uses fuzzy matching to detect typosquatting
func (c *Client) FindSimilarDomains(ctx context.Context, domain string, minSimilarity float64) ([]string, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT domain FROM find_similar_domains($1, $2)
		ORDER BY similarity_score DESC LIMIT 50
	`, domain, minSimilarity)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_FIND_SIMILAR_DOMAINS_FAILED", "Failed to find similar domains")
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var dom string
		if err := rows.Scan(&dom); err != nil {
			return nil, c.classifyError(err, "POSTGRES_SCAN_SIMILAR_DOMAINS_FAILED", "Failed to scan similar domains")
		}
		domains = append(domains, dom)
	}

	return domains, nil
}

// GetNewlyRegisteredDomains returns domains registered within last N days
func (c *Client) GetNewlyRegisteredDomains(ctx context.Context, daysThreshold int) ([]*DomainReputationResult, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT domain, root_domain, is_malicious, threat_score, category,
		       reported_reason, phishing_target, confidence, sources, first_seen,
		       registration_date, is_newly_registered
		FROM domains
		WHERE registration_date >= CURRENT_DATE - INTERVAL '1 day' * $1
		  AND is_malicious = TRUE
		ORDER BY registration_date DESC
	`, daysThreshold)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_NEW_DOMAINS_FAILED", "Failed to get newly registered domains")
	}
	defer rows.Close()

	var results []*DomainReputationResult
	for rows.Next() {
		var result DomainReputationResult
		var sourcesJSON []byte

		err := rows.Scan(
			&result.Domain,
			&result.RootDomain,
			&result.IsMalicious,
			&result.ThreatScore,
			&result.Category,
			&result.ReportedReason,
			&result.PhishingTarget,
			&result.Confidence,
			&sourcesJSON,
			&result.FirstSeen,
			&result.RegistrationDate,
			&result.IsNewlyRegistered,
		)
		if err != nil {
			return nil, c.classifyError(err, "POSTGRES_SCAN_NEW_DOMAINS_FAI LED", "Failed to scan newly registered domains")
		}

		if len(sourcesJSON) > 0 {
			json.Unmarshal(sourcesJSON, &result.Sources)
		}

		results = append(results, &result)
	}

	return results, nil
}

// ============================================================================
// File Hash Lookups
// ============================================================================

// HashReputationResult contains comprehensive hash reputation data
type HashReputationResult struct {
	SHA256             string
	MD5                sql.NullString
	SHA1               sql.NullString
	IsMalicious        bool
	ThreatScore        int
	MalwareFamily      sql.NullString
	MalwareType        sql.NullString
	MalwareDescription sql.NullString
	AVDetectionRate    sql.NullFloat64
	AVDetections       sql.NullInt32
	AVTotalEngines     sql.NullInt32
	VirusTotalLink     sql.NullString
	FirstSeen          time.Time
}

// GetHashReputation auto-detects hash type and queries file_hashes table
func (c *Client) GetHashReputation(ctx context.Context, hash string) (*HashReputationResult, error) {
	var result HashReputationResult

	err := c.pool.QueryRow(ctx, `
		SELECT sha256, md5, sha1, is_malicious, threat_score, malware_family,
		       malware_type, malware_description, av_detection_rate, av_detections,
		       av_total_engines, virustotal_link, first_seen
		FROM file_hashes
		WHERE (LENGTH($1) = 64 AND sha256 = $1)
		   OR (LENGTH($1) = 40 AND sha1 = $1)
		   OR (LENGTH($1) = 32 AND md5 = $1)
		AND status = 'active'
	`, hash).Scan(
		&result.SHA256,
		&result.MD5,
		&result.SHA1,
		&result.IsMalicious,
		&result.ThreatScore,
		&result.MalwareFamily,
		&result.MalwareType,
		&result.MalwareDescription,
		&result.AVDetectionRate,
		&result.AVDetections,
		&result.AVTotalEngines,
		&result.VirusTotalLink,
		&result.FirstSeen,
	)

	if err == pgx.ErrNoRows {
		return nil, nil // Hash not found
	}
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_HASH_REP_FAILED", "Failed to get hash reputation")
	}

	return &result, nil
}

// IsHashMalicious simplified boolean check
func (c *Client) IsHashMalicious(ctx context.Context, hash string) (bool, error) {
	var isMalicious bool

	err := c.pool.QueryRow(ctx, `
		SELECT COALESCE((SELECT is_malicious FROM check_hash_malicious($1) LIMIT 1), FALSE)
	`, hash).Scan(&isMalicious)

	if err != nil {
		return false, c.classifyError(err, "POSTGRES_IS_HASH_MALICIOUS_FAILED", "Failed to check if hash is malicious")
	}

	return isMalicious, nil
}

// GetMalwareFamily returns all known samples of a malware family
func (c *Client) GetMalwareFamily(ctx context.Context, family string) ([]*HashReputationResult, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT sha256, md5, sha1, threat_score, file_name, av_detection_rate, first_seen, last_seen
		FROM get_malware_variants($1)
	`, family)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_MALWARE_FAMILY_FAILED", "Failed to get malware family")
	}
	defer rows.Close()

	var results []*HashReputationResult
	for rows.Next() {
		var result HashReputationResult
		var fileName sql.NullString
		var lastSeen time.Time

		err := rows.Scan(
			&result.SHA256,
			&result.MD5,
			&result.SHA1,
			&result.ThreatScore,
			&fileName,
			&result.AVDetectionRate,
			&result.FirstSeen,
			&lastSeen,
		)
		if err != nil {
			return nil, c.classifyError(err, "POSTGRES_SCAN_MALWARE_FAMILY_FAILED", "Failed to scan malware family")
		}

		result.IsMalicious = true
		results = append(results, &result)
	}

	return results, nil
}

// ============================================================================
// Feed Management
// ============================================================================

// FeedInfo contains threat feed configuration and status
type FeedInfo struct {
	FeedID               int64
	FeedName             string
	FeedURL              string
	FeedType             string
	IsActive             bool
	UpdateFrequency      int
	ReliabilityScore     sql.NullInt32
	LastFetchStatus      sql.NullString
	LastSuccessfulFetch  sql.NullTime
	NextScheduledFetch   sql.NullTime
	TotalRecordsImported int64
	ConsecutiveFailures  int
}

// GetAllActiveFeeds returns all feeds where is_active = TRUE
func (c *Client) GetAllActiveFeeds(ctx context.Context) ([]*FeedInfo, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT id, feed_name, feed_url, feed_type, is_active, update_frequency,
		       reliability_score, last_fetch_status, last_successful_fetch,
		       next_scheduled_fetch, total_records_imported, consecutive_failures
		FROM threat_feeds
		WHERE is_active = TRUE
		ORDER BY priority DESC NULLS LAST
	`)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_ACTIVE_FEEDS_FAILED", "Failed to get active feeds")
	}
	defer rows.Close()

	return c.scanFeedRows(rows)
}

// GetFeedsDueForUpdate returns feeds where next_scheduled_fetch <= NOW()
func (c *Client) GetFeedsDueForUpdate(ctx context.Context) ([]*FeedInfo, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT feed_id, feed_name, feed_url, feed_type, priority, update_frequency
		FROM get_feeds_due_for_update()
	`)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_DUE_FEEDS_FAILED", "Failed to get feeds due for update")
	}
	defer rows.Close()

	var feeds []*FeedInfo
	for rows.Next() {
		var feed FeedInfo
		var priority int

		err := rows.Scan(
			&feed.FeedID,
			&feed.FeedName,
			&feed.FeedURL,
			&feed.FeedType,
			&priority,
			&feed.UpdateFrequency,
		)
		if err != nil {
			return nil, c.classifyError(err, "POSTGRES_SCAN_DUE_FEEDS_FAILED", "Failed to scan feeds due for update")
		}

		feeds = append(feeds, &feed)
	}

	return feeds, nil
}

// UpdateFeedStatus updates last_fetch_status and last_error fields
func (c *Client) UpdateFeedStatus(ctx context.Context, feedID int64, status string, errorMsg string) error {
	_, err := c.pool.Exec(ctx, `
		UPDATE threat_feeds
		SET last_fetch_status = $2,
		    last_error = $3,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`, feedID, status, errorMsg)

	if err != nil {
		return c.classifyError(err, "POSTGRES_UPDATE_FEED_STATUS_FAILED", "Failed to update feed status")
	}

	return nil
}

// FeedExecution contains feed execution details for history tracking
type FeedExecution struct {
	FeedID          int64
	FeedName        string
	Status          string
	RecordsAdded    int
	RecordsUpdated  int
	RecordsRejected int
	ExecutionTimeMS int
	ErrorMessage    string
}

// RecordFeedExecution inserts record into feed_history table
func (c *Client) RecordFeedExecution(ctx context.Context, execution *FeedExecution) error {
	_, err := c.pool.Exec(ctx, `
		INSERT INTO feed_history (
			feed_id, feed_name, status, records_added, records_updated,
			records_rejected, execution_time_ms, error_message, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
	`, execution.FeedID, execution.FeedName, execution.Status,
		execution.RecordsAdded, execution.RecordsUpdated, execution.RecordsRejected,
		execution.ExecutionTimeMS, execution.ErrorMessage)

	if err != nil {
		return c.classifyError(err, "POSTGRES_RECORD_FEED_EXEC_FAILED", "Failed to record feed execution")
	}

	return nil
}

// ============================================================================
// Statistics and Monitoring
// ============================================================================

// ThreatStats contains aggregated threat intelligence statistics
type ThreatStats struct {
	TotalMaliciousIPs     int64
	TotalMaliciousDomains int64
	TotalMalwareHashes    int64
	TotalVPNIPs           int64
	TotalTorNodes         int64
	TotalActiveFeeds      int
	LastFeedUpdate        sql.NullTime
	DatabaseSizeBytes     int64

	// Per-category breakdowns
	IPsByAbuseType      map[string]int64
	DomainsByCategory   map[string]int64
	HashesByMalwareType map[string]int64
}

// GetThreatStats aggregates statistics from all tables
func (c *Client) GetThreatStats(ctx context.Context) (*ThreatStats, error) {
	stats := &ThreatStats{
		IPsByAbuseType:      make(map[string]int64),
		DomainsByCategory:   make(map[string]int64),
		HashesByMalwareType: make(map[string]int64),
	}

	// Get total counts
	err := c.pool.QueryRow(ctx, `
		SELECT 
			(SELECT COUNT(*) FROM ip_blacklist WHERE is_malicious = TRUE),
			(SELECT COUNT(*) FROM domains WHERE is_malicious = TRUE),
			(SELECT COUNT(*) FROM file_hashes WHERE is_malicious = TRUE),
			(SELECT COUNT(*) FROM vpn_ips WHERE is_active = TRUE),
			(SELECT COUNT(*) FROM vpn_ips WHERE service_type = 'tor_exit' AND is_active = TRUE),
			(SELECT COUNT(*) FROM threat_feeds WHERE is_active = TRUE),
			(SELECT MAX(last_successful_fetch) FROM threat_feeds)
	`).Scan(
		&stats.TotalMaliciousIPs,
		&stats.TotalMaliciousDomains,
		&stats.TotalMalwareHashes,
		&stats.TotalVPNIPs,
		&stats.TotalTorNodes,
		&stats.TotalActiveFeeds,
		&stats.LastFeedUpdate,
	)
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_THREAT_STATS_FAILED", "Failed to get threat statistics")
	}

	// Get IP breakdown by abuse type
	ipRows, err := c.pool.Query(ctx, `
		SELECT abuse_type, COUNT(*) 
		FROM ip_blacklist 
		WHERE is_malicious = TRUE 
		GROUP BY abuse_type
	`)
	if err == nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var abuseType string
			var count int64
			if err := ipRows.Scan(&abuseType, &count); err == nil {
				stats.IPsByAbuseType[abuseType] = count
			}
		}
	}

	// Get domain breakdown by category
	domRows, err := c.pool.Query(ctx, `
		SELECT category, COUNT(*) 
		FROM domains 
		WHERE is_malicious = TRUE
		GROUP BY category
	`)
	if err == nil {
		defer domRows.Close()
		for domRows.Next() {
			var category string
			var count int64
			if err := domRows.Scan(&category, &count); err == nil {
				stats.DomainsByCategory[category] = count
			}
		}
	}

	// Get hash breakdown by malware type
	hashRows, err := c.pool.Query(ctx, `
		SELECT malware_type, COUNT(*) 
		FROM file_hashes 
		WHERE is_malicious = TRUE 
		GROUP BY malware_type
	`)
	if err == nil {
		defer hashRows.Close()
		for hashRows.Next() {
			var malwareType sql.NullString
			var count int64
			if err := hashRows.Scan(&malwareType, &count); err == nil && malwareType.Valid {
				stats.HashesByMalwareType[malwareType.String] = count
			}
		}
	}

	return stats, nil
}

// ============================================================================
// Geolocation Helpers
// ============================================================================

// IPLocationResult contains IP geolocation information
type IPLocationResult struct {
	CountryCode    string
	CountryName    string
	City           string
	Latitude       sql.NullFloat64
	Longitude      sql.NullFloat64
	ASN            sql.NullInt32
	ASNOrg         sql.NullString
	ConnectionType sql.NullString
}

// GetIPLocation wraps the get_ip_location() database function
func (c *Client) GetIPLocation(ctx context.Context, ipAddr string) (*IPLocationResult, error) {
	var result IPLocationResult

	err := c.pool.QueryRow(ctx, `
		SELECT country_code, country_name, city, latitude, longitude, asn, asn_org, connection_type
		FROM get_ip_location($1)
	`, ipAddr).Scan(
		&result.CountryCode,
		&result.CountryName,
		&result.City,
		&result.Latitude,
		&result.Longitude,
		&result.ASN,
		&result.ASNOrg,
		&result.ConnectionType,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, c.classifyError(err, "POSTGRES_GET_LOCATION_FAILED", "Failed to get IP location")
	}

	return &result, nil
}

// GetIPCountry fast country-only lookup
func (c *Client) GetIPCountry(ctx context.Context, ipAddr string) (string, error) {
	var countryCode sql.NullString

	err := c.pool.QueryRow(ctx, "SELECT get_ip_country($1)", ipAddr).Scan(&countryCode)
	if err != nil {
		return "", c.classifyError(err, "POSTGRES_GET_COUNTRY_FAILED", "Failed to get IP country")
	}

	if countryCode.Valid {
		return countryCode.String, nil
	}
	return "", nil
}

// IsIPInCountry checks if IP is from allowed countries
func (c *Client) IsIPInCountry(ctx context.Context, ipAddr string, allowedCountries []string) (bool, error) {
	var isAllowed bool

	err := c.pool.QueryRow(ctx, "SELECT is_ip_in_country($1, $2)", ipAddr, allowedCountries).Scan(&isAllowed)
	if err != nil {
		return false, c.classifyError(err, "POSTGRES_CHECK_COUNTRY_FAILED", "Failed to check IP country")
	}

	return isAllowed, nil
}

// ============================================================================
// Helper Methods
// ============================================================================

func (c *Client) scanFeedRows(rows pgx.Rows) ([]*FeedInfo, error) {
	var feeds []*FeedInfo

	for rows.Next() {
		var feed FeedInfo

		err := rows.Scan(
			&feed.FeedID,
			&feed.FeedName,
			&feed.FeedURL,
			&feed.FeedType,
			&feed.IsActive,
			&feed.UpdateFrequency,
			&feed.ReliabilityScore,
			&feed.LastFetchStatus,
			&feed.LastSuccessfulFetch,
			&feed.NextScheduledFetch,
			&feed.TotalRecordsImported,
			&feed.ConsecutiveFailures,
		)
		if err != nil {
			return nil, c.classifyError(err, "POSTGRES_SCAN_FEEDS_FAILED", "Failed to scan feed rows")
		}

		feeds = append(feeds, &feed)
	}

	return feeds, nil
}

// ============================================================================
// Legacy Compatibility Aliases
// ============================================================================

// DatabaseStats is a simplified version for backward compatibility
type DatabaseStats struct {
	TotalMaliciousIPs     int64
	TotalMaliciousDomains int64
	TotalMalwareHashes    int64
	TotalVPNIPs           int64
	TotalActiveFeeds      int
	DatabaseSize          string
	LastFeedUpdate        time.Time
}

// GetDatabaseStats is an alias for GetThreatStats with simplified output
func (c *Client) GetDatabaseStats(ctx context.Context) (*DatabaseStats, error) {
	fullStats, err := c.GetThreatStats(ctx)
	if err != nil {
		return nil, err
	}

	stats := &DatabaseStats{
		TotalMaliciousIPs:     fullStats.TotalMaliciousIPs,
		TotalMaliciousDomains: fullStats.TotalMaliciousDomains,
		TotalMalwareHashes:    fullStats.TotalMalwareHashes,
		TotalVPNIPs:           fullStats.TotalVPNIPs,
		TotalActiveFeeds:      fullStats.TotalActiveFeeds,
	}

	// Get database size
	err = c.pool.QueryRow(ctx, `SELECT pg_size_pretty(pg_database_size(current_database()))`).Scan(&stats.DatabaseSize)
	if err == nil && fullStats.LastFeedUpdate.Valid {
		stats.LastFeedUpdate = fullStats.LastFeedUpdate.Time
	}

	return stats, nil
}

// GetTableStats returns row count for specified table
func (c *Client) GetTableStats(ctx context.Context, tableName string) (int64, error) {
	var count int64

	err := c.pool.QueryRow(ctx, `SELECT count(*) FROM `+tableName).Scan(&count)
	if err != nil {
		return 0, c.classifyError(err, "POSTGRES_TABLE_STATS_FAILED", "Failed to get table statistics for "+tableName)
	}

	return count, nil
}
