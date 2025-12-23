package models

import "time"

// ============================================================================
// Core Domain Models
// ============================================================================

// Feed represents a threat intelligence feed source
type Feed struct {
	ID              int       `json:"id"`
	Name            string    `json:"name"`
	Category        string    `json:"category"`
	URL             string    `json:"url"`
	Format          string    `json:"format"`
	Enabled         bool      `json:"enabled"`
	UpdateFrequency int       `json:"update_frequency"`
	LastUpdated     time.Time `json:"last_updated"`
	Status          string    `json:"status"` // "active", "error"
}

// IPReputation represents intelligence data for an IP address
type IPReputation struct {
	IP          string    `json:"ip"`
	Score       int       `json:"score"`
	Severity    string    `json:"severity"`
	Categories  []string  `json:"categories"`
	Sources     []string  `json:"sources"`
	LastSeen    time.Time `json:"last_seen"`
	CountryCode string    `json:"country_code"`
	ASN         string    `json:"asn"`
	IsVPN       bool      `json:"is_vpn"`
	IsTor       bool      `json:"is_tor"`
	IsProxy     bool      `json:"is_proxy"`
}

// DomainIntelligence represents intelligence data for a domain
type DomainIntelligence struct {
	Domain      string    `json:"domain"`
	Score       int       `json:"score"`
	Severity    string    `json:"severity"`
	Categories  []string  `json:"categories"`
	Sources     []string  `json:"sources"`
	LastSeen    time.Time `json:"last_seen"`
	DNSRecords  []string  `json:"dns_records"`
	Registrar   string    `json:"registrar"`
	CreatedDate time.Time `json:"created_date"`
}

// HashReputation represents intelligence data for a file hash
type HashReputation struct {
	Hash       string    `json:"hash"`
	Type       string    `json:"type"` // MD5, SHA1, SHA256
	Score      int       `json:"score"`
	Severity   string    `json:"severity"`
	Categories []string  `json:"categories"`
	Sources    []string  `json:"sources"`
	LastSeen   time.Time `json:"last_seen"`
	FileName   string    `json:"file_name"`
	FileSize   int64     `json:"file_size"`
}

// IOC represents a generic Indicator of Compromise
type IOC struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // ip, domain, hash, url
	Value     string    `json:"value"`
	Score     int       `json:"score"`
	Severity  string    `json:"severity"`
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Tags      []string  `json:"tags"`
}

// Stats represents system statistics
type Stats struct {
	TotalIPs        int64             `json:"total_ips"`
	TotalDomains    int64             `json:"total_domains"`
	TotalHashes     int64             `json:"total_hashes"`
	ActiveThreats   int64             `json:"active_threats"`
	FeedsActive     int               `json:"feeds_active"`
	FeedsFailed     int               `json:"feeds_failed"`
	ThreatsOverTime []TimeSeriesPoint `json:"threats_over_time"`
}

// TimeSeriesPoint represents a point in a time series chart
type TimeSeriesPoint struct {
	Time  time.Time `json:"time"`
	Value int       `json:"value"`
}

// ============================================================================
// Request/Filter Models
// ============================================================================

// IOCFilter defines filters for listing IOCs
type IOCFilter struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Source    string `json:"source"`
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
}

// SearchRequest defines the body for search requests
type SearchRequest struct {
	Query    string   `json:"query"`
	Types    []string `json:"types"` // ip, domain, hash
	Limit    int      `json:"limit"`
	MinScore int      `json:"min_score"`
}
