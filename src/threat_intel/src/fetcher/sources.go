package fetcher

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ==========================================================================
// Source Category Constants (YAML source categories)
// ==========================================================================

const (
	// Original YAML categories (for reading sources.yaml)
	CategoryIPGeo           = "ip_geo"
	CategoryIPBlacklist     = "ip_blacklist"
	CategoryIPAnonymization = "ip_anonymization"
	CategoryDomain          = "domain"
	CategoryHash            = "hash"
	CategoryIOC             = "ioc"
	CategoryMixed           = "mixed"
	CategoryASN             = "asn"
)

// ==========================================================================
// Output Folder Categories (simplified output structure)
// ==========================================================================

const (
	// Output folder names - files are organized into these folders
	OutputFolderDomain = "domain" // Domain threat feeds
	OutputFolderIP     = "ip"     // Blacklisted/anonymous IPs (malicious, Tor, VPN, Proxy)
	OutputFolderIPGeo  = "ip_geo" // IP geolocation and ASN data
	OutputFolderHash   = "hash"   // Hash/malware feeds
)

// ==========================================================================
// Source Format Constants
// ==========================================================================

const (
	FormatCSV  = "csv"
	FormatJSON = "json"
	FormatTXT  = "txt"
	FormatXML  = "xml"
	FormatMMDB = "mmdb" // MaxMind database format
	FormatSTIX = "stix" // Structured Threat Information Expression
	FormatMISP = "misp" // Malware Information Sharing Platform
	FormatTSV  = "tsv"  // Tab-separated values
	FormatRSS  = "rss"  // RSS feed
)

// ==========================================================================
// Authentication Type Constants
// ==========================================================================

const (
	AuthTypeNone   = "none"
	AuthTypeAPIKey = "api_key"
	AuthTypeBasic  = "basic"
	AuthTypeBearer = "bearer"
	AuthTypeOAuth  = "oauth"
)

// ==========================================================================
// Source Struct Definition
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

	// Runtime fields (not in YAML)
	LastFetched time.Time `yaml:"-" json:"last_fetched,omitempty"`
	LastError   string    `yaml:"-" json:"last_error,omitempty"`
	FetchCount  int       `yaml:"-" json:"fetch_count"`
}

// ==========================================================================
// AuthConfig Struct Definition
// ==========================================================================

// AuthConfig holds authentication configuration for a source
type AuthConfig struct {
	Type       string `yaml:"type" json:"type"`
	APIKey     string `yaml:"api_key,omitempty" json:"-"` // Never serialize to JSON
	Username   string `yaml:"username,omitempty" json:"username,omitempty"`
	Password   string `yaml:"password,omitempty" json:"-"` // Never serialize to JSON
	Token      string `yaml:"token,omitempty" json:"-"`    // Never serialize to JSON
	HeaderName string `yaml:"header_name,omitempty" json:"header_name,omitempty"`
}

// ==========================================================================
// ParserConfig Struct Definition
// ==========================================================================

// ParserConfig holds format-specific parsing instructions
type ParserConfig struct {
	Delimiter       string            `yaml:"delimiter,omitempty" json:"delimiter,omitempty"`
	SkipRows        int               `yaml:"skip_rows,omitempty" json:"skip_rows,omitempty"`
	ColumnMapping   map[string]int    `yaml:"column_mapping,omitempty" json:"column_mapping,omitempty"`
	JSONPath        string            `yaml:"json_path,omitempty" json:"json_path,omitempty"`
	FieldExtractors map[string]string `yaml:"field_extractors,omitempty" json:"field_extractors,omitempty"`
	Encoding        string            `yaml:"encoding,omitempty" json:"encoding,omitempty"`
	CommentPrefix   string            `yaml:"comment_prefix,omitempty" json:"comment_prefix,omitempty"`
}

// ==========================================================================
// Validation Constants
// ==========================================================================

const (
	MinUpdateFrequency = 60      // 1 minute minimum
	MaxUpdateFrequency = 2592000 // 30 days maximum
	DefaultPriority    = 5       // Medium priority
)

// validCategories lists all supported feed categories
var validCategories = map[string]bool{
	CategoryIPGeo:           true,
	CategoryIPBlacklist:     true,
	CategoryIPAnonymization: true,
	CategoryDomain:          true,
	CategoryHash:            true,
	CategoryIOC:             true,
	CategoryMixed:           true,
	CategoryASN:             true,
}

// validFormats lists all supported file formats
var validFormats = map[string]bool{
	FormatCSV:  true,
	FormatJSON: true,
	FormatTXT:  true,
	FormatXML:  true,
	FormatMMDB: true,
	FormatSTIX: true,
	FormatMISP: true,
	FormatTSV:  true,
	FormatRSS:  true,
}

// validAuthTypes lists all supported authentication types
var validAuthTypes = map[string]bool{
	AuthTypeNone:   true,
	AuthTypeAPIKey: true,
	AuthTypeBasic:  true,
	AuthTypeBearer: true,
	AuthTypeOAuth:  true,
}

// ==========================================================================
// Validation Helper Functions
// ==========================================================================

// IsValidCategory checks if a category string matches known categories
func IsValidCategory(category string) bool {
	return validCategories[category]
}

// IsValidFormat checks if a format string matches supported formats
func IsValidFormat(format string) bool {
	return validFormats[format]
}

// IsValidAuthType checks if an authentication type is supported
func IsValidAuthType(authType string) bool {
	if authType == "" {
		return true // Empty is valid (no auth)
	}
	return validAuthTypes[authType]
}

// ==========================================================================
// Source Helper Functions
// ==========================================================================

// GetUpdateDuration converts UpdateFrequency (seconds) to Go time.Duration
func (s *Source) GetUpdateDuration() time.Duration {
	return time.Duration(s.UpdateFrequency) * time.Second
}

// ShouldFetch determines if the source should be fetched based on last fetch time
func (s *Source) ShouldFetch() bool {
	if s.LastFetched.IsZero() {
		return true // Never fetched before
	}

	nextFetch := s.LastFetched.Add(s.GetUpdateDuration())
	return time.Now().After(nextFetch)
}

// GetPriority returns the source priority, defaulting to medium if not set
func (s *Source) GetPriority() int {
	if s.Priority <= 0 {
		return DefaultPriority
	}
	return s.Priority
}

// HasTag checks if the source has a specific tag
func (s *Source) HasTag(tag string) bool {
	for _, t := range s.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// ==========================================================================
// URL Validation Function
// ==========================================================================

// ValidateURL validates that URL is properly formatted and accessible
func ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL is empty")
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Check scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got: %s", parsedURL.Scheme)
	}

	// Check host is not empty
	if parsedURL.Host == "" {
		return fmt.Errorf("URL host is empty")
	}

	return nil
}

// ==========================================================================
// Source Validation Functions
// ==========================================================================

// ValidateSource performs comprehensive validation of a single Source struct
func ValidateSource(s *Source) error {
	var errs []string

	// Validate required fields
	if s.Name == "" {
		errs = append(errs, "name is required")
	}

	if s.Category == "" {
		errs = append(errs, "category is required")
	} else if !IsValidCategory(s.Category) {
		errs = append(errs, fmt.Sprintf("invalid category: %s", s.Category))
	}

	if s.URL == "" {
		errs = append(errs, "url is required")
	} else if err := ValidateURL(s.URL); err != nil {
		errs = append(errs, fmt.Sprintf("invalid url: %v", err))
	}

	if s.Format == "" {
		errs = append(errs, "format is required")
	} else if !IsValidFormat(s.Format) {
		errs = append(errs, fmt.Sprintf("invalid format: %s", s.Format))
	}

	// Validate update frequency
	if s.UpdateFrequency < MinUpdateFrequency {
		errs = append(errs, fmt.Sprintf("update_frequency must be at least %d seconds", MinUpdateFrequency))
	}
	if s.UpdateFrequency > MaxUpdateFrequency {
		errs = append(errs, fmt.Sprintf("update_frequency must not exceed %d seconds (30 days)", MaxUpdateFrequency))
	}

	// Validate authentication
	if s.AuthRequired {
		if s.AuthType == "" {
			errs = append(errs, "auth_type is required when auth_required is true")
		} else if !IsValidAuthType(s.AuthType) {
			errs = append(errs, fmt.Sprintf("invalid auth_type: %s", s.AuthType))
		}
	}

	// Validate priority
	if s.Priority < 0 || s.Priority > 10 {
		errs = append(errs, "priority must be between 0 and 10")
	}

	if len(errs) > 0 {
		return fmt.Errorf("source validation failed for '%s': %s", s.Name, strings.Join(errs, "; "))
	}

	return nil
}

// ValidateSources validates an entire array of Source structs
func ValidateSources(sources []Source) []error {
	var errors []error
	seenNames := make(map[string]bool)
	seenURLs := make(map[string]bool)

	for i, source := range sources {
		// Validate individual source
		if err := ValidateSource(&source); err != nil {
			errors = append(errors, fmt.Errorf("source[%d]: %w", i, err))
			continue
		}

		// Check for duplicate names
		if seenNames[source.Name] {
			errors = append(errors, fmt.Errorf("source[%d]: duplicate name '%s'", i, source.Name))
		}
		seenNames[source.Name] = true

		// Check for duplicate URLs
		if seenURLs[source.URL] {
			errors = append(errors, fmt.Errorf("source[%d]: duplicate URL '%s'", i, source.URL))
		}
		seenURLs[source.URL] = true
	}

	return errors
}

// ==========================================================================
// Source Filtering and Selection Functions
// ==========================================================================

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

// GetSourcesByPriority sorts sources by priority (ascending, so 1 runs first)
func GetSourcesByPriority(sources []Source) []Source {
	// Create a copy to avoid modifying original
	sorted := make([]Source, len(sources))
	copy(sorted, sources)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].GetPriority() < sorted[j].GetPriority()
	})

	return sorted
}

// GetSourcesByTag filters sources that have a specific tag
func GetSourcesByTag(sources []Source, tag string) []Source {
	var filtered []Source
	for _, source := range sources {
		if source.HasTag(tag) {
			filtered = append(filtered, source)
		}
	}
	return filtered
}

// GetSourceByName finds a source by name (case-insensitive)
func GetSourceByName(sources []Source, name string) *Source {
	for i := range sources {
		if strings.EqualFold(sources[i].Name, name) {
			return &sources[i]
		}
	}
	return nil
}

// GetDueSources returns sources that need to be fetched
func GetDueSources(sources []Source) []Source {
	var due []Source
	for _, source := range sources {
		if source.Enabled && source.ShouldFetch() {
			due = append(due, source)
		}
	}
	return due
}

// ==========================================================================
// Category Helper Functions
// ==========================================================================

// GetAllCategories returns a list of all valid categories
func GetAllCategories() []string {
	categories := make([]string, 0, len(validCategories))
	for cat := range validCategories {
		categories = append(categories, cat)
	}
	sort.Strings(categories)
	return categories
}

// GetAllFormats returns a list of all supported formats
func GetAllFormats() []string {
	formats := make([]string, 0, len(validFormats))
	for fmt := range validFormats {
		formats = append(formats, fmt)
	}
	sort.Strings(formats)
	return formats
}

// ==========================================================================
// Source Statistics Functions
// ==========================================================================

// SourceStats holds statistics about a collection of sources
type SourceStats struct {
	Total            int
	Enabled          int
	Disabled         int
	ByCategory       map[string]int
	ByFormat         map[string]int
	RequiringAuth    int
	DueForUpdate     int
	AverageFrequency float64
}

// GetSourceStats calculates statistics for a collection of sources
func GetSourceStats(sources []Source) SourceStats {
	stats := SourceStats{
		Total:      len(sources),
		ByCategory: make(map[string]int),
		ByFormat:   make(map[string]int),
	}

	var totalFrequency int

	for _, source := range sources {
		if source.Enabled {
			stats.Enabled++
			if source.ShouldFetch() {
				stats.DueForUpdate++
			}
		} else {
			stats.Disabled++
		}

		stats.ByCategory[source.Category]++
		stats.ByFormat[source.Format]++

		if source.AuthRequired {
			stats.RequiringAuth++
		}

		totalFrequency += source.UpdateFrequency
	}

	if stats.Total > 0 {
		stats.AverageFrequency = float64(totalFrequency) / float64(stats.Total)
	}

	return stats
}

// ==========================================================================
// YAML Configuration Structure
// ==========================================================================

// SourcesConfig represents the root structure of sources.yaml
type SourcesConfig struct {
	Feeds        []Source   `yaml:"feeds"`
	ParserConfig ParserYAML `yaml:"parser_config"`
}

// ParserYAML holds parser configuration from YAML
type ParserYAML struct {
	CSV  CSVParserConfig  `yaml:"csv"`
	TXT  TXTParserConfig  `yaml:"txt"`
	JSON JSONParserConfig `yaml:"json"`
	TSV  TSVParserConfig  `yaml:"tsv"`
}

// CSVParserConfig holds CSV parsing settings
type CSVParserConfig struct {
	DefaultDelimiter string `yaml:"default_delimiter"`
	SkipHeader       bool   `yaml:"skip_header"`
	CommentChar      string `yaml:"comment_char"`
}

// TXTParserConfig holds TXT parsing settings
type TXTParserConfig struct {
	CommentChars   []string `yaml:"comment_chars"`
	TrimWhitespace bool     `yaml:"trim_whitespace"`
}

// JSONParserConfig holds JSON parsing settings
type JSONParserConfig struct {
	ValidateSchema bool `yaml:"validate_schema"`
}

// TSVParserConfig holds TSV parsing settings
type TSVParserConfig struct {
	Delimiter  string `yaml:"delimiter"`
	SkipHeader bool   `yaml:"skip_header"`
}

// ==========================================================================
// YAML Loading Functions
// ==========================================================================

// LoadSourcesFromYAML loads and parses sources.yaml file
func LoadSourcesFromYAML(yamlPath string) (*SourcesConfig, error) {
	// Validate path
	if yamlPath == "" {
		return nil, fmt.Errorf("YAML path is empty")
	}

	// Check if file exists
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("sources.yaml not found at: %s", yamlPath)
	}

	// Read file
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read sources.yaml: %w", err)
	}

	// Parse YAML
	var config SourcesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse sources.yaml: %w", err)
	}

	// Validate sources
	if errs := ValidateSources(config.Feeds); len(errs) > 0 {
		return nil, fmt.Errorf("source validation errors: %v", errs)
	}

	return &config, nil
}

// FindSourcesYAML searches for sources.yaml in common locations
func FindSourcesYAML(basePath string) (string, error) {
	// Search paths in order of preference
	searchPaths := []string{
		filepath.Join(basePath, "config", "sources.yaml"),
		filepath.Join(basePath, "sources.yaml"),
		filepath.Join(basePath, "..", "config", "sources.yaml"),
	}

	for _, path := range searchPaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath, nil
		}
	}

	return "", fmt.Errorf("sources.yaml not found in any expected location")
}

// ==========================================================================
// Output Folder Mapping Functions
// ==========================================================================

// categoryToOutputFolder maps YAML categories to simplified output folders
// NOTE: IOC and Mixed categories are NOT included here - they need content-based analysis
var categoryToOutputFolder = map[string]string{
	// IP blacklist and anonymization -> ip folder (malicious/anonymous IPs)
	CategoryIPBlacklist:     OutputFolderIP,
	CategoryIPAnonymization: OutputFolderIP,

	// IP geolocation and ASN -> ip_geo folder (enrichment data)
	CategoryIPGeo: OutputFolderIPGeo,
	CategoryASN:   OutputFolderIPGeo,

	// Domain category -> domain folder
	CategoryDomain: OutputFolderDomain,

	// Hash category -> hash folder
	CategoryHash: OutputFolderHash,
}

// NeedsContentAnalysis returns true if the source category requires
// content-based analysis to determine output folder (domain/ip/hash)
// IOC and Mixed feeds contain multiple data types and must be parsed
// to extract and separate domains, IPs, and hashes into their respective folders
func NeedsContentAnalysis(category string) bool {
	return category == CategoryIOC || category == CategoryMixed
}

// IsIOCCategory checks if a category is an IOC/Mixed type that needs content separation
func IsIOCCategory(category string) bool {
	return NeedsContentAnalysis(category)
}

// GetOutputFolder returns the output folder name for a given source category
// This maps the granular YAML categories to simplified output structure (domain/ip/hash)
// For IOC/Mixed categories, returns empty string - these need content analysis
func GetOutputFolder(category string) string {
	// IOC and Mixed feeds need content-based analysis - return empty
	if NeedsContentAnalysis(category) {
		return "" // Signal to fetcher that content analysis is needed
	}

	if folder, ok := categoryToOutputFolder[category]; ok {
		return folder
	}
	// Default to domain for unknown categories
	return OutputFolderDomain
}

// GetAllOutputFolders returns list of all output folder names
// Includes domain, ip, ip_geo, hash for categorized feeds + pending for IOC feeds needing analysis
func GetAllOutputFolders() []string {
	return []string{OutputFolderDomain, OutputFolderIP, OutputFolderIPGeo, OutputFolderHash, "pending"}
}

// CreateOutputDirectories creates the simplified output directory structure
// Creates: domain/, ip/, ip_geo/, hash/, pending/
func CreateOutputDirectories(basePath string) error {
	folders := GetAllOutputFolders()

	for _, folder := range folders {
		dirPath := filepath.Join(basePath, folder)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
		}
	}

	return nil
}

// GetSourcesByOutputFolder groups sources by their output folder
func GetSourcesByOutputFolder(sources []Source) map[string][]Source {
	grouped := make(map[string][]Source)

	for _, source := range sources {
		folder := GetOutputFolder(source.Category)
		grouped[folder] = append(grouped[folder], source)
	}

	return grouped
}
