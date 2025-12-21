// Package types provides common types and data structures for threat intelligence
package types

import (
	"time"
)

// ============================================================================
// Feed Category Enumeration
// ============================================================================

// FeedCategory represents the primary category of a threat intelligence feed
type FeedCategory string

const (
	CategoryMalicious   FeedCategory = "malicious"   // Malware, C2, botnets
	CategoryPhishing    FeedCategory = "phishing"    // Phishing domains/URLs
	CategoryAnonymizers FeedCategory = "anonymizers" // Tor, VPN, proxy, datacenter
	CategoryGeolocation FeedCategory = "geolocation" // IP-to-country mapping
	CategoryASN         FeedCategory = "asn"         // ASN mapping and metadata
	CategoryHashes      FeedCategory = "hashes"      // File hashes for malware
	CategoryReputation  FeedCategory = "reputation"  // IP/domain reputation scores
)

// String returns the string representation of the category
func (fc FeedCategory) String() string {
	return string(fc)
}

// ============================================================================
// Update Frequency Specification
// ============================================================================

// UpdateFrequency defines how often a feed should be fetched
type UpdateFrequency string

const (
	FrequencyRealtime    UpdateFrequency = "realtime"      // Continuous/frequent polling
	FrequencyHourly      UpdateFrequency = "hourly"        // Every hour
	FrequencyEvery6Hours UpdateFrequency = "every_6_hours" // Every 6 hours
	FrequencyDaily       UpdateFrequency = "daily"         // Once per day
	FrequencyWeekly      UpdateFrequency = "weekly"        // Once per week
	FrequencyMonthly     UpdateFrequency = "monthly"       // Once per month
	FrequencyOnDemand    UpdateFrequency = "on_demand"     // Manual trigger only
)

// Duration returns the time duration for the frequency
func (uf UpdateFrequency) Duration() time.Duration {
	switch uf {
	case FrequencyRealtime:
		return 5 * time.Minute
	case FrequencyHourly:
		return 1 * time.Hour
	case FrequencyEvery6Hours:
		return 6 * time.Hour
	case FrequencyDaily:
		return 24 * time.Hour
	case FrequencyWeekly:
		return 7 * 24 * time.Hour
	case FrequencyMonthly:
		return 30 * 24 * time.Hour
	default:
		return 0 // OnDemand has no automatic interval
	}
}

// ============================================================================
// Feed Format Type
// ============================================================================

// FormatType represents the data format of a feed
type FormatType string

const (
	FormatCSV       FormatType = "csv"
	FormatJSON      FormatType = "json"
	FormatPlainText FormatType = "plain_text"
	FormatHosts     FormatType = "hosts"
	FormatNetset    FormatType = "netset"
	FormatXML       FormatType = "xml"
)

// ============================================================================
// Authentication Type
// ============================================================================

// AuthType represents the authentication mechanism for a feed
type AuthType string

const (
	AuthNone         AuthType = "none"
	AuthAPIKey       AuthType = "api_key"
	AuthBasic        AuthType = "basic"
	AuthBearerToken  AuthType = "bearer_token"
	AuthCustomHeader AuthType = "custom_header"
)

// ============================================================================
// Threat Scoring Strategy
// ============================================================================

// ScoringStrategy defines how threat scores are assigned
type ScoringStrategy string

const (
	ScoringFeedProvided ScoringStrategy = "feed_provided" // Use score from feed
	ScoringCalculated   ScoringStrategy = "calculated"    // Calculate internally
	ScoringHybrid       ScoringStrategy = "hybrid"        // Combine both
)

// ============================================================================
// Feed Authentication Configuration
// ============================================================================

// FeedAuthentication defines authentication configuration for a feed
type FeedAuthentication struct {
	Type              AuthType `json:"type" yaml:"type"`
	APIKey            string   `json:"api_key,omitempty" yaml:"api_key,omitempty"`
	APIKeyLocation    string   `json:"api_key_location,omitempty" yaml:"api_key_location,omitempty"` // url_param, header, query
	APIKeyName        string   `json:"api_key_name,omitempty" yaml:"api_key_name,omitempty"`
	Username          string   `json:"username,omitempty" yaml:"username,omitempty"`
	Password          string   `json:"password,omitempty" yaml:"password,omitempty"` // Should be encrypted at rest
	BearerToken       string   `json:"bearer_token,omitempty" yaml:"bearer_token,omitempty"`
	CustomHeaderName  string   `json:"custom_header_name,omitempty" yaml:"custom_header_name,omitempty"`
	CustomHeaderValue string   `json:"custom_header_value,omitempty" yaml:"custom_header_value,omitempty"`
}

// ============================================================================
// Feed Format Specification
// ============================================================================

// FeedFormat defines the data format and parsing instructions for a feed
type FeedFormat struct {
	FormatType       FormatType        `json:"format_type" yaml:"format_type"`
	Encoding         string            `json:"encoding" yaml:"encoding"`                                         // utf-8, iso-8859-1, etc.
	Compression      string            `json:"compression,omitempty" yaml:"compression,omitempty"`               // gzip, zip, bzip2, none
	Delimiter        string            `json:"delimiter,omitempty" yaml:"delimiter,omitempty"`                   // CSV delimiter
	HasHeader        bool              `json:"has_header" yaml:"has_header"`                                     // CSV has header row
	ColumnMapping    map[string]string `json:"column_mapping,omitempty" yaml:"column_mapping,omitempty"`         // CSV column mappings
	JSONPath         map[string]string `json:"json_path,omitempty" yaml:"json_path,omitempty"`                   // JSONPath for field extraction
	CommentPrefix    string            `json:"comment_prefix,omitempty" yaml:"comment_prefix,omitempty"`         // Comment line prefix
	SkipLines        int               `json:"skip_lines" yaml:"skip_lines"`                                     // Lines to skip at start
	IPColumn         string            `json:"ip_column,omitempty" yaml:"ip_column,omitempty"`                   // IP column name/index
	DomainColumn     string            `json:"domain_column,omitempty" yaml:"domain_column,omitempty"`           // Domain column
	HashColumn       string            `json:"hash_column,omitempty" yaml:"hash_column,omitempty"`               // Hash column
	ThreatTypeColumn string            `json:"threat_type_column,omitempty" yaml:"threat_type_column,omitempty"` // Threat type
	ConfidenceColumn string            `json:"confidence_column,omitempty" yaml:"confidence_column,omitempty"`   // Confidence score
}

// ============================================================================
// Feed Processing Options
// ============================================================================

// FeedProcessingOptions defines processing behavior for a feed
type FeedProcessingOptions struct {
	ValidateIOCs         bool            `json:"validate_iocs" yaml:"validate_iocs"`
	DeduplicateEnabled   bool            `json:"deduplicate_enabled" yaml:"deduplicate_enabled"`
	EnrichmentEnabled    bool            `json:"enrichment_enabled" yaml:"enrichment_enabled"`
	ThreatScoring        ScoringStrategy `json:"threat_scoring" yaml:"threat_scoring"`
	DefaultThreatType    string          `json:"default_threat_type,omitempty" yaml:"default_threat_type,omitempty"`
	DefaultConfidence    float64         `json:"default_confidence" yaml:"default_confidence"`
	ConfidenceMultiplier float64         `json:"confidence_multiplier" yaml:"confidence_multiplier"`
	TagsToAdd            []string        `json:"tags_to_add,omitempty" yaml:"tags_to_add,omitempty"`
	RequiredFields       []string        `json:"required_fields,omitempty" yaml:"required_fields,omitempty"`
	MaxIOCsPerFetch      int             `json:"max_iocs_per_fetch" yaml:"max_iocs_per_fetch"`
	FilterPrivateIPs     bool            `json:"filter_private_ips" yaml:"filter_private_ips"`
	FilterOldIOCs        bool            `json:"filter_old_iocs" yaml:"filter_old_iocs"`
	OldIOCThreshold      int             `json:"old_ioc_threshold" yaml:"old_ioc_threshold"` // Days
}

// ============================================================================
// Feed Rate Limiting
// ============================================================================

// FeedRateLimit defines rate limiting configuration
type FeedRateLimit struct {
	RequestsPerMinute int           `json:"requests_per_minute" yaml:"requests_per_minute"`
	RetryBackoff      time.Duration `json:"retry_backoff" yaml:"retry_backoff"`
	MaxRetries        int           `json:"max_retries" yaml:"max_retries"`
}

// ============================================================================
// Feed Status Tracking
// ============================================================================

// FeedStatus defines the runtime status and health metrics for a feed
type FeedStatus struct {
	LastFetchTime        time.Time `json:"last_fetch_time" yaml:"last_fetch_time"`
	LastSuccessTime      time.Time `json:"last_success_time" yaml:"last_success_time"`
	LastErrorTime        time.Time `json:"last_error_time" yaml:"last_error_time"`
	LastError            string    `json:"last_error,omitempty" yaml:"last_error,omitempty"`
	ConsecutiveFailures  int       `json:"consecutive_failures" yaml:"consecutive_failures"`
	TotalFetches         int64     `json:"total_fetches" yaml:"total_fetches"`
	TotalSuccesses       int64     `json:"total_successes" yaml:"total_successes"`
	TotalFailures        int64     `json:"total_failures" yaml:"total_failures"`
	TotalIOCsImported    int64     `json:"total_iocs_imported" yaml:"total_iocs_imported"`
	LastFetchIOCCount    int       `json:"last_fetch_ioc_count" yaml:"last_fetch_ioc_count"`
	LastFetchDuration    int64     `json:"last_fetch_duration_ms" yaml:"last_fetch_duration_ms"` // Milliseconds
	AverageFetchDuration int64     `json:"average_fetch_duration_ms" yaml:"average_fetch_duration_ms"`
	DataQualityScore     float64   `json:"data_quality_score" yaml:"data_quality_score"` // 0-100
	IsHealthy            bool      `json:"is_healthy" yaml:"is_healthy"`
	NextScheduledFetch   time.Time `json:"next_scheduled_fetch" yaml:"next_scheduled_fetch"`
}

// ============================================================================
// Feed Source Structure
// ============================================================================

// Feed represents a complete threat intelligence feed source configuration
type Feed struct {
	// Core Identification
	ID          string       `json:"id" yaml:"id"`
	Name        string       `json:"name" yaml:"name"`
	Category    FeedCategory `json:"category" yaml:"category"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`

	// Feed Source
	URL            string             `json:"url" yaml:"url"`
	Format         FeedFormat         `json:"format" yaml:"format"`
	Authentication FeedAuthentication `json:"authentication,omitempty" yaml:"authentication,omitempty"`

	// Scheduling
	UpdateFrequency UpdateFrequency `json:"update_frequency" yaml:"update_frequency"`
	Enabled         bool            `json:"enabled" yaml:"enabled"`
	Priority        int             `json:"priority" yaml:"priority"` // 1=highest, 10=lowest

	// HTTP Configuration
	Timeout         int               `json:"timeout" yaml:"timeout"` // Seconds
	UserAgent       string            `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
	CustomHeaders   map[string]string `json:"custom_headers,omitempty" yaml:"custom_headers,omitempty"`
	FollowRedirects bool              `json:"follow_redirects" yaml:"follow_redirects"`

	// Rate Limiting
	RateLimit FeedRateLimit `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`

	// Processing
	ProcessingOptions FeedProcessingOptions `json:"processing_options" yaml:"processing_options"`

	// Metadata
	Tags     []string               `json:"tags,omitempty" yaml:"tags,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Status (runtime, not persisted in config)
	Status FeedStatus `json:"status,omitempty" yaml:"-"`

	// Timestamps
	CreatedAt time.Time `json:"created_at,omitempty" yaml:"-"`
	UpdatedAt time.Time `json:"updated_at,omitempty" yaml:"-"`
}

// ============================================================================
// Helper Methods
// ============================================================================

// IsEnabled returns true if the feed is enabled
func (f *Feed) IsEnabled() bool {
	return f.Enabled
}

// IsHealthy returns true if the feed is currently healthy
func (f *Feed) IsHealthy() bool {
	return f.Status.IsHealthy
}

// GetNextFetchTime calculates the next scheduled fetch time
func (f *Feed) GetNextFetchTime() time.Time {
	if f.Status.LastFetchTime.IsZero() {
		// Never fetched, fetch immediately
		return time.Now()
	}

	// Calculate next fetch based on frequency
	interval := f.UpdateFrequency.Duration()
	if interval == 0 {
		// OnDemand, no automatic schedule
		return time.Time{}
	}

	return f.Status.LastFetchTime.Add(interval)
}

// ShouldFetch determines if the feed should be fetched now
func (f *Feed) ShouldFetch() bool {
	if !f.IsEnabled() {
		return false
	}

	if f.UpdateFrequency == FrequencyOnDemand {
		return false // Only fetch when manually triggered
	}

	nextFetch := f.GetNextFetchTime()
	return time.Now().After(nextFetch) || time.Now().Equal(nextFetch)
}

// RecordFetchAttempt updates status for a fetch attempt
func (f *Feed) RecordFetchAttempt(success bool, iocsCount int, duration time.Duration, err error) {
	f.Status.LastFetchTime = time.Now()
	f.Status.TotalFetches++
	f.Status.LastFetchDuration = duration.Milliseconds()

	if success {
		f.Status.LastSuccessTime = time.Now()
		f.Status.TotalSuccesses++
		f.Status.ConsecutiveFailures = 0
		f.Status.LastFetchIOCCount = iocsCount
		f.Status.TotalIOCsImported += int64(iocsCount)
		f.Status.IsHealthy = true
	} else {
		f.Status.LastErrorTime = time.Now()
		f.Status.TotalFailures++
		f.Status.ConsecutiveFailures++
		if err != nil {
			f.Status.LastError = err.Error()
		}

		// Mark unhealthy after 3 consecutive failures
		if f.Status.ConsecutiveFailures >= 3 {
			f.Status.IsHealthy = false
		}
	}

	// Update average fetch duration (simple moving average of last 10)
	if f.Status.TotalFetches > 0 {
		totalDuration := f.Status.AverageFetchDuration * (f.Status.TotalFetches - 1)
		f.Status.AverageFetchDuration = (totalDuration + f.Status.LastFetchDuration) / f.Status.TotalFetches
	} else {
		f.Status.AverageFetchDuration = f.Status.LastFetchDuration
	}

	// Calculate next scheduled fetch
	f.Status.NextScheduledFetch = f.GetNextFetchTime()
}

// GetSuccessRate returns the success rate as a percentage
func (f *Feed) GetSuccessRate() float64 {
	if f.Status.TotalFetches == 0 {
		return 0.0
	}
	return float64(f.Status.TotalSuccesses) / float64(f.Status.TotalFetches) * 100.0
}

// ============================================================================
// Default Values
// ============================================================================

// NewFeed creates a new Feed with default values
func NewFeed(name, url string, category FeedCategory) *Feed {
	return &Feed{
		Name:            name,
		URL:             url,
		Category:        category,
		Enabled:         true,
		Priority:        5,
		Timeout:         30,
		UpdateFrequency: FrequencyDaily,
		FollowRedirects: true,
		Format: FeedFormat{
			Encoding:  "utf-8",
			HasHeader: false,
			SkipLines: 0,
		},
		Authentication: FeedAuthentication{
			Type: AuthNone,
		},
		ProcessingOptions: FeedProcessingOptions{
			ValidateIOCs:         true,
			DeduplicateEnabled:   true,
			EnrichmentEnabled:    true,
			ThreatScoring:        ScoringCalculated,
			DefaultConfidence:    50.0,
			ConfidenceMultiplier: 1.0,
			MaxIOCsPerFetch:      1000000,
			FilterPrivateIPs:     true,
			FilterOldIOCs:        false,
			OldIOCThreshold:      365,
		},
		RateLimit: FeedRateLimit{
			RequestsPerMinute: 60,
			RetryBackoff:      5 * time.Second,
			MaxRetries:        3,
		},
		Status: FeedStatus{
			IsHealthy:        true,
			DataQualityScore: 100.0,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
