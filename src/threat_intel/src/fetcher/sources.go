package fetcher

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ==========================================================================
// Source Category Constants
// ==========================================================================

const (
	CategoryIPGeo           = "ip_geo"
	CategoryIPBlacklist     = "ip_blacklist"
	CategoryIPAnonymization = "ip_anonymization"
	CategoryDomain          = "domain"
	CategoryHash            = "hash"
	CategoryIOC             = "ioc"
	CategoryASN             = "asn"
	CategoryMixed           = "mixed"
)

// ==========================================================================
// Source Format Constants
// ==========================================================================

const (
	FormatCSV  = "csv"
	FormatJSON = "json"
	FormatTXT  = "txt"
	FormatXML  = "xml"
	FormatTSV  = "tsv"
	FormatMMDB = "mmdb" // MaxMind database format
	FormatSTIX = "stix" // Structured Threat Information Expression
	FormatMISP = "misp" // Malware Information Sharing Platform
	FormatRSS  = "rss"  // RSS feed
)

// ==========================================================================
// Main Source Struct
// ==========================================================================

// Source represents a threat intelligence feed source
type Source struct {
	Name            string                 `yaml:"name" json:"name" validate:"required"`
	Category        string                 `yaml:"category" json:"category" validate:"required"`
	URL             string                 `yaml:"url" json:"url" validate:"required,url"`
	Format          string                 `yaml:"format" json:"format" validate:"required"`
	Enabled         bool                   `yaml:"enabled" json:"enabled"`
	UpdateFrequency int                    `yaml:"update_frequency" json:"update_frequency" validate:"required,min=60"`
	Description     string                 `yaml:"description" json:"description"`
	AuthRequired    bool                   `yaml:"auth_required" json:"auth_required"`
	AuthType        string                 `yaml:"auth_type" json:"auth_type"`
	ParserConfig    map[string]interface{} `yaml:"parser_config,omitempty" json:"parser_config,omitempty"`
	Tags            []string               `yaml:"tags,omitempty" json:"tags,omitempty"`
	Priority        int                    `yaml:"priority" json:"priority"`
}

// ==========================================================================
// Authentication Configuration
// ==========================================================================

// AuthConfig holds authentication details for feeds requiring auth
type AuthConfig struct {
	Type       string `yaml:"type" json:"type"`
	APIKey     string `yaml:"api_key,omitempty" json:"-"`
	Username   string `yaml:"username,omitempty" json:"username,omitempty"`
	Password   string `yaml:"password,omitempty" json:"-"`
	Token      string `yaml:"token,omitempty" json:"-"`
	HeaderName string `yaml:"header_name,omitempty" json:"header_name,omitempty"`
}

// ==========================================================================
// Parser Configuration
// ==========================================================================

// ParserConfig holds format-specific parsing instructions
type ParserConfigStruct struct {
	Delimiter       string            `yaml:"delimiter,omitempty" json:"delimiter,omitempty"`
	SkipRows        int               `yaml:"skip_rows,omitempty" json:"skip_rows,omitempty"`
	ColumnMapping   map[string]int    `yaml:"column_mapping,omitempty" json:"column_mapping,omitempty"`
	JSONPath        string            `yaml:"json_path,omitempty" json:"json_path,omitempty"`
	FieldExtractors map[string]string `yaml:"field_extractors,omitempty" json:"field_extractors,omitempty"`
}

// ==========================================================================
// Validation Functions
// ==========================================================================

// IsValidCategory checks if a category string matches known categories
func IsValidCategory(category string) bool {
	validCategories := []string{
		CategoryIPGeo,
		CategoryIPBlacklist,
		CategoryIPAnonymization,
		CategoryDomain,
		CategoryHash,
		CategoryIOC,
		CategoryASN,
		CategoryMixed,
	}

	for _, valid := range validCategories {
		if category == valid {
			return true
		}
	}
	return false
}

// IsValidFormat checks if a format string matches supported formats
func IsValidFormat(format string) bool {
	validFormats := []string{
		FormatCSV,
		FormatJSON,
		FormatTXT,
		FormatXML,
		FormatTSV,
		FormatMMDB,
		FormatSTIX,
		FormatMISP,
		FormatRSS,
	}

	for _, valid := range validFormats {
		if format == valid {
			return true
		}
	}
	return false
}

// ValidateURL validates that URL is properly formatted
func ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got: %s", parsedURL.Scheme)
	}

	if parsedURL.Host == "" {
		return fmt.Errorf("URL host cannot be empty")
	}

	return nil
}

// ValidateSource performs comprehensive validation of a Source
func ValidateSource(source *Source) error {
	if source.Name == "" {
		return fmt.Errorf("source name is required")
	}

	if !IsValidCategory(source.Category) {
		return fmt.Errorf("invalid category: %s", source.Category)
	}

	if err := ValidateURL(source.URL); err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if !IsValidFormat(source.Format) {
		return fmt.Errorf("invalid format: %s", source.Format)
	}

	if source.UpdateFrequency < 60 {
		return fmt.Errorf("update_frequency must be at least 60 seconds, got: %d", source.UpdateFrequency)
	}

	// 30 days in seconds
	if source.UpdateFrequency > 2592000 {
		return fmt.Errorf("update_frequency cannot exceed 30 days (2592000 seconds), got: %d", source.UpdateFrequency)
	}

	if source.AuthRequired && source.AuthType == "" {
		return fmt.Errorf("auth_type is required when auth_required is true")
	}

	return nil
}

// ValidateSources validates an array of Source structs
func ValidateSources(sources []Source) []error {
	var errors []error
	namesSeen := make(map[string]bool)
	urlsSeen := make(map[string]bool)

	for i, source := range sources {
		// Validate individual source
		if err := ValidateSource(&source); err != nil {
			errors = append(errors, fmt.Errorf("source at index %d (%s): %w", i, source.Name, err))
		}

		// Check for duplicate names
		if namesSeen[source.Name] {
			errors = append(errors, fmt.Errorf("duplicate source name: %s", source.Name))
		}
		namesSeen[source.Name] = true

		// Check for duplicate URLs
		if urlsSeen[source.URL] {
			errors = append(errors, fmt.Errorf("duplicate URL: %s (used by %s)", source.URL, source.Name))
		}
		urlsSeen[source.URL] = true
	}

	return errors
}

// ==========================================================================
// Helper Functions
// ==========================================================================

// GetUpdateDuration converts UpdateFrequency (seconds) to time.Duration
func GetUpdateDuration(source *Source) time.Duration {
	return time.Duration(source.UpdateFrequency) * time.Second
}

// GetSourcesByCategory filters sources by category
func GetSourcesByCategory(sources []Source, category string) []Source {
	var filtered []Source
	for _, source := range sources {
		if source.Category == category {
			filtered = append(filtered, source)
		}
	}
	return filtered
}

// GetEnabledSources filters sources to only enabled feeds
func GetEnabledSources(sources []Source) []Source {
	var enabled []Source
	for _, source := range sources {
		if source.Enabled {
			enabled = append(enabled, source)
		}
	}
	return enabled
}

// GetSourcesByPriority sorts sources by priority (lower number = higher priority)
func GetSourcesByPriority(sources []Source) []Source {
	// Create a copy to avoid modifying original
	sorted := make([]Source, len(sources))
	copy(sorted, sources)

	// Simple bubble sort by priority
	for i := 0; i < len(sorted)-1; i++ {
		for j := 0; j < len(sorted)-i-1; j++ {
			// If priority not set, default to 5
			priority1 := sorted[j].Priority
			if priority1 == 0 {
				priority1 = 5
			}
			priority2 := sorted[j+1].Priority
			if priority2 == 0 {
				priority2 = 5
			}

			if priority1 > priority2 {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}

	return sorted
}

// GetFileExtension returns the expected file extension for a format
func GetFileExtension(format string) string {
	extensions := map[string]string{
		FormatCSV:  ".csv",
		FormatJSON: ".json",
		FormatTXT:  ".txt",
		FormatXML:  ".xml",
		FormatTSV:  ".tsv",
		FormatMMDB: ".mmdb",
		FormatSTIX: ".xml",
		FormatMISP: ".json",
		FormatRSS:  ".xml",
	}

	if ext, exists := extensions[format]; exists {
		return ext
	}
	return ".dat" // Default extension
}

// IsGitHubURL checks if URL is from GitHub (requires GitHub-specific handling)
func IsGitHubURL(urlStr string) bool {
	return strings.Contains(urlStr, "github.com") || strings.Contains(urlStr, "raw.githubusercontent.com")
}

// GetCategoryDisplayName returns a human-readable category name
func GetCategoryDisplayName(category string) string {
	names := map[string]string{
		CategoryIPGeo:           "IP Geolocation",
		CategoryIPBlacklist:     "IP Blacklist",
		CategoryIPAnonymization: "IP Anonymization (VPN/Tor/Proxy)",
		CategoryDomain:          "Domain Intelligence",
		CategoryHash:            "File Hash Intelligence",
		CategoryIOC:             "Indicators of Compromise",
		CategoryASN:             "ASN Data",
		CategoryMixed:           "Mixed IOCs",
	}

	if name, exists := names[category]; exists {
		return name
	}
	return category
}
