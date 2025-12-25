package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// =============================================================================
// Parser - Main Orchestrator
// Coordinates all file readers (TXT, CSV, JSON)
// Auto-detects formats, provides unified interface
// Can be used directly or by other programs
// =============================================================================

// FileFormat represents detected file format
type FileFormat string

const (
	FormatTXT     FileFormat = "txt"
	FormatCSV     FileFormat = "csv"
	FormatTSV     FileFormat = "tsv"
	FormatJSON    FileFormat = "json"
	FormatUnknown FileFormat = "unknown"
)

// ParseResult is a unified result from any parser
type ParseResult struct {
	FilePath         string              `json:"file_path"`
	FileName         string              `json:"file_name"`
	Format           FileFormat          `json:"format"`
	DetectedCategory string              `json:"detected_category"` // ip, domain, hash, url, mixed
	TotalRecords     int                 `json:"total_records"`
	ContentSummary   map[ContentType]int `json:"content_summary"`

	// Format-specific data (only one will be populated)
	TXTData  *TXTData  `json:"txt_data,omitempty"`
	CSVData  *CSVData  `json:"csv_data,omitempty"`
	JSONData *JSONData `json:"json_data,omitempty"`

	Error string `json:"error,omitempty"`
}

// Parser configuration
type ParserConfig struct {
	MaxRecords    int    // Maximum records to read per file (0 = unlimited)
	DefaultFormat string // Default format if detection fails
}

// DefaultParserConfig returns sensible defaults
func DefaultParserConfig() *ParserConfig {
	return &ParserConfig{
		MaxRecords:    0,
		DefaultFormat: "txt",
	}
}

// =============================================================================
// Format Detection
// =============================================================================

// DetectFormat determines file format from extension and content
func DetectFormat(filePath string) FileFormat {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Extension-based detection
	switch ext {
	case ".txt", ".text", ".list", ".netset":
		return FormatTXT
	case ".csv":
		return FormatCSV
	case ".tsv":
		return FormatTSV
	case ".json":
		return FormatJSON
	}

	// Content-based detection for unknown extensions
	file, err := os.Open(filePath)
	if err != nil {
		return FormatUnknown
	}
	defer file.Close()

	// Read first 512 bytes
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil || n == 0 {
		return FormatUnknown
	}

	content := strings.TrimSpace(string(buf[:n]))

	// JSON detection (starts with { or [)
	if strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
		return FormatJSON
	}

	// CSV detection (contains commas in multiple lines)
	lines := strings.Split(content, "\n")
	commaCount := 0
	tabCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		commaCount += strings.Count(line, ",")
		tabCount += strings.Count(line, "\t")
	}

	if tabCount > commaCount && tabCount > 3 {
		return FormatTSV
	}
	if commaCount > 3 {
		return FormatCSV
	}

	// Default to TXT
	return FormatTXT
}

// =============================================================================
// Unified Parse Functions
// =============================================================================

// ParseFile reads any file and returns unified result
func ParseFile(filePath string, config *ParserConfig) (*ParseResult, error) {
	if config == nil {
		config = DefaultParserConfig()
	}

	result := &ParseResult{
		FilePath:       filePath,
		FileName:       filepath.Base(filePath),
		ContentSummary: make(map[ContentType]int),
	}

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		result.Error = fmt.Sprintf("file not found: %s", filePath)
		return result, err
	}

	// Detect format
	format := DetectFormat(filePath)
	result.Format = format

	// Parse based on format
	var err error
	switch format {
	case FormatTXT:
		err = parseTXTFile(filePath, result, config)
	case FormatCSV:
		err = parseCSVFile(filePath, result, config)
	case FormatTSV:
		err = parseTSVFile(filePath, result, config)
	case FormatJSON:
		err = parseJSONFile(filePath, result, config)
	default:
		// Try TXT as fallback
		result.Format = FormatTXT
		err = parseTXTFile(filePath, result, config)
	}

	if err != nil {
		result.Error = err.Error()
	}

	return result, err
}

func parseTXTFile(filePath string, result *ParseResult, config *ParserConfig) error {
	txtConfig := DefaultTXTConfig()
	txtConfig.MaxLines = config.MaxRecords

	data, err := ReadTXT(filePath, txtConfig)
	if err != nil {
		return err
	}

	result.TXTData = data
	result.TotalRecords = data.ValidLines
	result.DetectedCategory = data.DetectedCategory
	result.ContentSummary = data.ContentSummary

	return nil
}

func parseCSVFile(filePath string, result *ParseResult, config *ParserConfig) error {
	csvConfig := DefaultCSVConfig()
	csvConfig.MaxRows = config.MaxRecords

	// Auto-detect delimiter
	if delim, err := DetectDelimiter(filePath); err == nil {
		csvConfig.Delimiter = delim
	}

	data, err := ReadCSV(filePath, csvConfig)
	if err != nil {
		return err
	}

	result.CSVData = data
	result.TotalRecords = data.TotalRows
	result.DetectedCategory = data.DetectedCategory
	result.ContentSummary = data.ContentSummary

	return nil
}

func parseTSVFile(filePath string, result *ParseResult, config *ParserConfig) error {
	csvConfig := DefaultCSVConfig()
	csvConfig.Delimiter = '\t'
	csvConfig.MaxRows = config.MaxRecords

	data, err := ReadCSV(filePath, csvConfig)
	if err != nil {
		return err
	}

	result.CSVData = data
	result.TotalRecords = data.TotalRows
	result.DetectedCategory = data.DetectedCategory
	result.ContentSummary = data.ContentSummary

	return nil
}

func parseJSONFile(filePath string, result *ParseResult, config *ParserConfig) error {
	jsonConfig := DefaultJSONConfig()
	jsonConfig.MaxRecords = config.MaxRecords

	data, err := ReadJSON(filePath, jsonConfig)
	if err != nil {
		return err
	}

	result.JSONData = data
	result.TotalRecords = data.TotalRecords
	result.DetectedCategory = data.DetectedCategory
	result.ContentSummary = data.ContentSummary

	return nil
}

// =============================================================================
// Directory Parsing
// =============================================================================

// ParseDirectory reads all supported files in a directory
func ParseDirectory(dirPath string, config *ParserConfig) ([]*ParseResult, error) {
	if config == nil {
		config = DefaultParserConfig()
	}

	var results []*ParseResult

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())
		format := DetectFormat(filePath)

		// Skip unknown formats
		if format == FormatUnknown {
			continue
		}

		result, _ := ParseFile(filePath, config)
		results = append(results, result)
	}

	return results, nil
}

// ParseDirectoryByCategory reads files organized by category
func ParseDirectoryByCategory(basePath string, config *ParserConfig) (map[string][]*ParseResult, error) {
	categoryResults := make(map[string][]*ParseResult)
	categories := []string{"ip", "domain", "hash", "ip_geo", "pending"}

	for _, cat := range categories {
		catPath := filepath.Join(basePath, cat)
		if _, err := os.Stat(catPath); os.IsNotExist(err) {
			continue
		}

		results, err := ParseDirectory(catPath, config)
		if err != nil {
			continue
		}

		if len(results) > 0 {
			categoryResults[cat] = results
		}
	}

	return categoryResults, nil
}

// =============================================================================
// Helper Functions for Unified Access
// =============================================================================

// GetAllIPs returns all IPs from parse result regardless of format
func (r *ParseResult) GetAllIPs() []string {
	switch {
	case r.TXTData != nil:
		ips := r.TXTData.GetIPs()
		values := make([]string, len(ips))
		for i, rec := range ips {
			values[i] = rec.Value
		}
		return values
	case r.CSVData != nil:
		return r.CSVData.GetIPs()
	case r.JSONData != nil:
		return r.JSONData.GetIPs()
	}
	return nil
}

// GetAllDomains returns all domains from parse result regardless of format
func (r *ParseResult) GetAllDomains() []string {
	switch {
	case r.TXTData != nil:
		domains := r.TXTData.GetDomains()
		values := make([]string, len(domains))
		for i, rec := range domains {
			values[i] = rec.Value
		}
		return values
	case r.CSVData != nil:
		return r.CSVData.GetDomains()
	case r.JSONData != nil:
		return r.JSONData.GetDomains()
	}
	return nil
}

// GetAllURLs returns all URLs from parse result regardless of format
func (r *ParseResult) GetAllURLs() []string {
	switch {
	case r.TXTData != nil:
		urls := r.TXTData.GetURLs()
		values := make([]string, len(urls))
		for i, rec := range urls {
			values[i] = rec.Value
		}
		return values
	case r.CSVData != nil:
		return r.CSVData.GetURLs()
	case r.JSONData != nil:
		return r.JSONData.GetURLs()
	}
	return nil
}

// GetAllHashes returns all hashes from parse result regardless of format
func (r *ParseResult) GetAllHashes() []string {
	switch {
	case r.TXTData != nil:
		hashes := r.TXTData.GetHashes()
		values := make([]string, len(hashes))
		for i, rec := range hashes {
			values[i] = rec.Value
		}
		return values
	case r.CSVData != nil:
		return r.CSVData.GetHashes()
	case r.JSONData != nil:
		return r.JSONData.GetHashes()
	}
	return nil
}

// =============================================================================
// Category Detection from Source Name
// =============================================================================

// InferCategoryFromSource infers the data category from source/filename
func InferCategoryFromSource(fileName string) string {
	name := strings.ToLower(fileName)

	// IP-related keywords
	ipKeywords := []string{"ip", "blacklist", "blocklist", "firehol", "feodo", "ssl",
		"tor", "vpn", "proxy", "emergingthreats", "botvrij"}
	for _, kw := range ipKeywords {
		if strings.Contains(name, kw) {
			return "ip"
		}
	}

	// Domain-related keywords
	domainKeywords := []string{"domain", "phish", "spam", "hosts", "urlhaus", "threatfox",
		"openphish", "malware", "hacked"}
	for _, kw := range domainKeywords {
		if strings.Contains(name, kw) {
			return "domain"
		}
	}

	// Hash-related keywords
	hashKeywords := []string{"hash", "malwarebazaar", "sha256", "md5", "sha1", "virustotal"}
	for _, kw := range hashKeywords {
		if strings.Contains(name, kw) {
			return "hash"
		}
	}

	// Geo-related keywords
	geoKeywords := []string{"geo", "asn", "country", "ip2location", "iptoasn", "location"}
	for _, kw := range geoKeywords {
		if strings.Contains(name, kw) {
			return "ip_geo"
		}
	}

	return "unknown"
}

// =============================================================================
// Test/Demo Function - Main Entry Point for Testing
// =============================================================================

// TestAllParsers demonstrates all parser capabilities
func TestAllParsers() {
	fmt.Println()
	fmt.Println("╔" + strings.Repeat("═", 78) + "╗")
	fmt.Println("║" + centerText("THREAT INTEL PARSER SUBSYSTEM", 78) + "║")
	fmt.Println("║" + centerText("Complete File Reading Demonstration", 78) + "║")
	fmt.Println("╚" + strings.Repeat("═", 78) + "╝")

	// Run individual parser tests
	TestTXTReader()
	fmt.Println()
	TestCSVReader()
	fmt.Println()
	TestJSONReader()

	// Test unified parser
	fmt.Println()
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println("UNIFIED PARSER - Auto-Detection Demo")
	fmt.Println("=" + strings.Repeat("=", 79))

	basePath := "data/fetch"
	config := DefaultParserConfig()
	config.MaxRecords = 5 // Just sample

	categoryResults, err := ParseDirectoryByCategory(basePath, config)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if len(categoryResults) == 0 {
		fmt.Println("No files found in data/fetch/ - run fetcher first!")
		return
	}

	// Print summary per category
	for cat, results := range categoryResults {
		fmt.Printf("\n[%s] %d files parsed\n", strings.ToUpper(cat), len(results))

		for _, r := range results {
			fmt.Printf("  ├─ %s [%s] → %s\n", r.FileName, r.Format, r.DetectedCategory)

			// Show counts
			ips := len(r.GetAllIPs())
			domains := len(r.GetAllDomains())
			urls := len(r.GetAllURLs())
			hashes := len(r.GetAllHashes())

			if ips > 0 || domains > 0 || urls > 0 || hashes > 0 {
				fmt.Printf("  │    IPs:%d Domains:%d URLs:%d Hashes:%d\n",
					ips, domains, urls, hashes)
			}

			// Show first few values
			showSample := func(label string, values []string) {
				if len(values) > 0 {
					limit := 3
					if len(values) < limit {
						limit = len(values)
					}
					fmt.Printf("  │    %s: %v\n", label, values[:limit])
				}
			}

			showSample("Sample IPs", r.GetAllIPs())
			showSample("Sample Domains", r.GetAllDomains())
		}
	}

	// Final summary
	fmt.Println("\n" + strings.Repeat("─", 80))
	totalFiles := 0
	for _, results := range categoryResults {
		totalFiles += len(results)
	}
	fmt.Printf("Total files parsed: %d across %d categories\n", totalFiles, len(categoryResults))
	fmt.Println(strings.Repeat("=", 80))
}

func centerText(text string, width int) string {
	if len(text) >= width {
		return text
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
}

// =============================================================================
// Convenience Functions for Direct Module Usage
// =============================================================================

// QuickParse is a one-liner to parse any file
func QuickParse(filePath string) (*ParseResult, error) {
	return ParseFile(filePath, nil)
}

// QuickParseDir is a one-liner to parse a directory
func QuickParseDir(dirPath string) ([]*ParseResult, error) {
	return ParseDirectory(dirPath, nil)
}
