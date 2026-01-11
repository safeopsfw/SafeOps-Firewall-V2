package parser

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// =============================================================================
// CSV Reader - Smart CSV/TSV File Parser
// Reads CSV/TSV files, detects content types in columns
// Supports different delimiters: comma, tab, semicolon, pipe
// Can be used directly by any program
// =============================================================================

// CSVColumn represents metadata about a detected column
type CSVColumn struct {
	Index       int         `json:"index"`
	Name        string      `json:"name"`         // Header name or col_0, col_1
	ContentType ContentType `json:"content_type"` // Detected type from sampling
	SampleValue string      `json:"sample_value"` // Example value
}

// CSVRecord represents a single parsed row with typed values
type CSVRecord struct {
	RowNumber int                    `json:"row_number"`
	Fields    map[string]string      `json:"fields"`     // Column name -> value
	RawFields []string               `json:"raw_fields"` // Original field array
	Detected  map[string]ContentType `json:"detected"`   // Column name -> detected type
}

// CSVData represents the complete parsed CSV file
type CSVData struct {
	FilePath         string              `json:"file_path"`
	FileName         string              `json:"file_name"`
	Delimiter        rune                `json:"delimiter"`
	TotalRows        int                 `json:"total_rows"`
	HeaderRow        []string            `json:"header_row"`
	Columns          []CSVColumn         `json:"columns"`
	Records          []CSVRecord         `json:"records"`
	DetectedCategory string              `json:"detected_category"` // ip, domain, hash, ip_geo, mixed
	ContentSummary   map[ContentType]int `json:"content_summary"`
}

// CSVConfig holds configuration for CSV parsing
type CSVConfig struct {
	Delimiter   rune // ',' '\t' ';' '|'
	HasHeader   bool // First row is header
	SkipRows    int  // Rows to skip before data
	TrimSpaces  bool // Trim whitespace from fields
	CommentChar rune // Comment line indicator
	LazyQuotes  bool // Allow malformed quotes
	MaxRows     int  // Maximum rows to read (0 = unlimited)
}

// DefaultCSVConfig returns sensible defaults
func DefaultCSVConfig() *CSVConfig {
	return &CSVConfig{
		Delimiter:   ',',
		HasHeader:   true,
		SkipRows:    0,
		TrimSpaces:  true,
		CommentChar: '#',
		LazyQuotes:  true,
		MaxRows:     0,
	}
}

// Known column name mappings for threat intel feeds
var knownColumnMappings = map[string]ContentType{
	// IP columns
	"ip":          ContentTypeIP,
	"ip_address":  ContentTypeIP,
	"ipaddress":   ContentTypeIP,
	"dst_ip":      ContentTypeIP,
	"src_ip":      ContentTypeIP,
	"address":     ContentTypeIP,
	"host":        ContentTypeIP,
	"ip_start":    ContentTypeIP,
	"ip_end":      ContentTypeIP,
	"first_ip":    ContentTypeIP,
	"last_ip":     ContentTypeIP,
	"range_start": ContentTypeIPRange,
	"range_end":   ContentTypeIPRange,

	// Domain columns
	"domain":    ContentTypeDomain,
	"hostname":  ContentTypeDomain,
	"fqdn":      ContentTypeDomain,
	"host_name": ContentTypeDomain,

	// URL columns
	"url":  ContentTypeURL,
	"uri":  ContentTypeURL,
	"link": ContentTypeURL,
	"ioc":  ContentTypeUnknown, // Could be any type

	// Hash columns
	"hash":        ContentTypeHash,
	"md5":         ContentTypeHash,
	"sha1":        ContentTypeHash,
	"sha256":      ContentTypeHash,
	"sha256_hash": ContentTypeHash,
	"file_hash":   ContentTypeHash,
}

// =============================================================================
// CSV Reader Functions
// =============================================================================

// ReadCSV reads a CSV file and returns parsed data with content detection
func ReadCSV(filePath string, config *CSVConfig) (*CSVData, error) {
	if config == nil {
		config = DefaultCSVConfig()
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data := &CSVData{
		FilePath:       filePath,
		FileName:       filepath.Base(filePath),
		Delimiter:      config.Delimiter,
		Records:        []CSVRecord{},
		Columns:        []CSVColumn{},
		ContentSummary: make(map[ContentType]int),
	}

	reader := csv.NewReader(file)
	reader.Comma = config.Delimiter
	reader.Comment = config.CommentChar
	reader.TrimLeadingSpace = config.TrimSpaces
	reader.LazyQuotes = config.LazyQuotes
	reader.ReuseRecord = false
	reader.FieldsPerRecord = -1 // Allow variable field counts

	// Skip initial rows if configured
	for i := 0; i < config.SkipRows; i++ {
		_, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error skipping rows: %w", err)
		}
	}

	// Read header row
	if config.HasHeader {
		headerRow, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				return data, nil // Empty file
			}
			return nil, fmt.Errorf("error reading header: %w", err)
		}

		// Clean and store headers
		data.HeaderRow = make([]string, len(headerRow))
		for i, h := range headerRow {
			cleaned := cleanHeaderName(h)
			data.HeaderRow[i] = cleaned

			// Create column metadata
			col := CSVColumn{
				Index:       i,
				Name:        cleaned,
				ContentType: inferColumnTypeFromName(cleaned),
			}
			data.Columns = append(data.Columns, col)
		}
	}

	// Read data rows
	rowNum := 0
	for {
		rowNum++
		if config.MaxRows > 0 && rowNum > config.MaxRows {
			break
		}

		row, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			// Log error but continue
			continue
		}

		data.TotalRows++

		// If no header, generate column names on first row
		if !config.HasHeader && len(data.HeaderRow) == 0 {
			data.HeaderRow = make([]string, len(row))
			for i := range row {
				data.HeaderRow[i] = fmt.Sprintf("col_%d", i)
				data.Columns = append(data.Columns, CSVColumn{
					Index: i,
					Name:  data.HeaderRow[i],
				})
			}
		}

		// Build record
		record := CSVRecord{
			RowNumber: rowNum,
			Fields:    make(map[string]string),
			RawFields: row,
			Detected:  make(map[string]ContentType),
		}

		// Map fields to columns and detect types
		for i, field := range row {
			if config.TrimSpaces {
				field = strings.TrimSpace(field)
			}

			colName := fmt.Sprintf("col_%d", i)
			if i < len(data.HeaderRow) {
				colName = data.HeaderRow[i]
			}

			record.Fields[colName] = field

			// Detect content type
			detected := detectContentType(field)
			record.Detected[colName] = detected
			data.ContentSummary[detected]++

			// Update column sample if first data row
			if rowNum == 1 && i < len(data.Columns) && data.Columns[i].SampleValue == "" {
				data.Columns[i].SampleValue = field
				if data.Columns[i].ContentType == ContentTypeUnknown {
					data.Columns[i].ContentType = detected
				}
			}
		}

		data.Records = append(data.Records, record)
	}

	// Detect overall category
	data.DetectedCategory = detectCSVCategory(data)

	return data, nil
}

// ReadTSV reads a TSV (tab-separated) file
func ReadTSV(filePath string, config *CSVConfig) (*CSVData, error) {
	if config == nil {
		config = DefaultCSVConfig()
	}
	config.Delimiter = '\t'
	return ReadCSV(filePath, config)
}

// DetectDelimiter auto-detects the delimiter by sampling the file
func DetectDelimiter(filePath string) (rune, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return ',', err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Read first 5 non-comment lines
	delimiters := map[rune]int{
		',':  0,
		'\t': 0,
		';':  0,
		'|':  0,
	}

	linesRead := 0
	for scanner.Scan() && linesRead < 5 {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		linesRead++

		for d := range delimiters {
			delimiters[d] += strings.Count(line, string(d))
		}
	}

	// Find most common delimiter
	maxCount := 0
	bestDelim := ','
	for d, count := range delimiters {
		if count > maxCount {
			maxCount = count
			bestDelim = d
		}
	}

	return bestDelim, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// cleanHeaderName normalizes header names
func cleanHeaderName(header string) string {
	// Trim whitespace and quotes
	header = strings.TrimSpace(header)
	header = strings.Trim(header, "\"'")

	// Convert to lowercase
	header = strings.ToLower(header)

	// Replace spaces and special chars with underscores
	replacer := strings.NewReplacer(
		" ", "_",
		"-", "_",
		".", "_",
		"(", "",
		")", "",
	)
	header = replacer.Replace(header)

	return header
}

// inferColumnTypeFromName guesses content type from column name
func inferColumnTypeFromName(name string) ContentType {
	name = strings.ToLower(name)

	if ct, ok := knownColumnMappings[name]; ok {
		return ct
	}

	// Pattern matching
	if strings.Contains(name, "ip") || strings.Contains(name, "address") {
		return ContentTypeIP
	}
	if strings.Contains(name, "domain") || strings.Contains(name, "host") {
		return ContentTypeDomain
	}
	if strings.Contains(name, "url") || strings.Contains(name, "uri") {
		return ContentTypeURL
	}
	if strings.Contains(name, "hash") || strings.Contains(name, "md5") ||
		strings.Contains(name, "sha1") || strings.Contains(name, "sha256") {
		return ContentTypeHash
	}

	return ContentTypeUnknown
}

// detectContentType analyzes a value and determines its type
func detectContentType(value string) ContentType {
	value = strings.TrimSpace(value)
	if value == "" {
		return ContentTypeUnknown
	}

	// URL check first (contains protocol)
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return ContentTypeURL
	}

	// CIDR notation
	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err == nil {
			return ContentTypeIPRange
		}
	}

	// IPv4
	if ip := net.ParseIP(value); ip != nil {
		if ip.To4() != nil {
			return ContentTypeIP
		}
		return ContentTypeIP // IPv6
	}

	// Hashes - check by length and hex pattern
	if isHex(value) {
		switch len(value) {
		case 32:
			return ContentTypeHash // MD5
		case 40:
			return ContentTypeHash // SHA1
		case 64:
			return ContentTypeHash // SHA256
		}
	}

	// Domain check (simple pattern)
	if domainPatternCSV.MatchString(value) {
		return ContentTypeDomain
	}

	return ContentTypeUnknown
}

var domainPatternCSV = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// detectCSVCategory determines file category based on columns and content
func detectCSVCategory(data *CSVData) string {
	// Check if this looks like IP geo data (has country, lat/lng columns)
	hasGeoColumns := false
	for _, col := range data.Columns {
		name := strings.ToLower(col.Name)
		if strings.Contains(name, "country") || strings.Contains(name, "latitude") ||
			strings.Contains(name, "longitude") || strings.Contains(name, "asn") ||
			strings.Contains(name, "city") || strings.Contains(name, "region") {
			hasGeoColumns = true
			break
		}
	}

	if hasGeoColumns {
		return "ip_geo"
	}

	// Check dominant content type
	total := 0
	for _, count := range data.ContentSummary {
		total += count
	}
	if total == 0 {
		return "empty"
	}

	ipCount := data.ContentSummary[ContentTypeIP] + data.ContentSummary[ContentTypeIPRange]
	domainCount := data.ContentSummary[ContentTypeDomain]
	urlCount := data.ContentSummary[ContentTypeURL]
	hashCount := data.ContentSummary[ContentTypeHash]

	threshold := float64(total) * 0.3 // Lower threshold for CSV since multiple columns

	if float64(hashCount) > threshold {
		return "hash"
	}
	if float64(urlCount) > threshold {
		return "url"
	}
	if float64(domainCount) > threshold {
		return "domain"
	}
	if float64(ipCount) > threshold {
		return "ip"
	}

	return "mixed"
}

// =============================================================================
// Helper Methods for Direct Usage
// =============================================================================

// GetColumn returns all values for a specific column
func (d *CSVData) GetColumn(name string) []string {
	values := make([]string, 0, len(d.Records))
	for _, r := range d.Records {
		if v, ok := r.Fields[name]; ok {
			values = append(values, v)
		}
	}
	return values
}

// GetIPs returns all detected IP values from any column
func (d *CSVData) GetIPs() []string {
	var ips []string
	for _, r := range d.Records {
		for col, ct := range r.Detected {
			if ct == ContentTypeIP || ct == ContentTypeIPRange {
				if v, ok := r.Fields[col]; ok && v != "" {
					ips = append(ips, v)
				}
			}
		}
	}
	return ips
}

// GetDomains returns all detected domain values from any column
func (d *CSVData) GetDomains() []string {
	var domains []string
	for _, r := range d.Records {
		for col, ct := range r.Detected {
			if ct == ContentTypeDomain {
				if v, ok := r.Fields[col]; ok && v != "" {
					domains = append(domains, v)
				}
			}
		}
	}
	return domains
}

// GetURLs returns all detected URL values from any column
func (d *CSVData) GetURLs() []string {
	var urls []string
	seen := make(map[string]bool)
	for _, r := range d.Records {
		for col, ct := range r.Detected {
			if ct == ContentTypeURL {
				if v, ok := r.Fields[col]; ok && v != "" && !seen[v] {
					urls = append(urls, v)
					seen[v] = true
				}
			}
		}
	}
	return urls
}

// GetHashes returns all detected hash values from any column
func (d *CSVData) GetHashes() []string {
	var hashes []string
	for _, r := range d.Records {
		for col, ct := range r.Detected {
			if ct == ContentTypeHash {
				if v, ok := r.Fields[col]; ok && v != "" {
					hashes = append(hashes, v)
				}
			}
		}
	}
	return hashes
}

// ExtractDomainsFromURLs parses URLs and extracts domain names
func (d *CSVData) ExtractDomainsFromURLs() []string {
	var domains []string
	seen := make(map[string]bool)

	for _, r := range d.Records {
		for col, ct := range r.Detected {
			if ct == ContentTypeURL {
				if v, ok := r.Fields[col]; ok && v != "" {
					if u, err := url.Parse(v); err == nil && u.Host != "" {
						host := strings.TrimPrefix(u.Host, "www.")
						// Remove port if present
						if colonIdx := strings.Index(host, ":"); colonIdx > 0 {
							host = host[:colonIdx]
						}
						if !seen[host] {
							domains = append(domains, host)
							seen[host] = true
						}
					}
				}
			}
		}
	}
	return domains
}

// =============================================================================
// Test/Demo Function - Prints sample output when run directly
// =============================================================================

// TestCSVReader demonstrates CSV reader capabilities
func TestCSVReader() {
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println("CSV READER - Content Detection Demo")
	fmt.Println("=" + strings.Repeat("=", 79))

	// Test content detection
	testValues := []string{
		"192.168.1.1",
		"10.0.0.0/8",
		"malware.com",
		"https://phishing.example.com/login",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"d41d8cd98f00b204e9800998ecf8427e",
		"some random text",
		"",
	}

	fmt.Println("\n--- Testing Value Detection ---")
	for _, val := range testValues {
		ct := detectContentType(val)
		display := val
		if display == "" {
			display = "(empty)"
		}
		fmt.Printf("  [%-8s] %s\n", ct, display)
	}

	fmt.Println("\n--- Looking for CSV/TSV files in data/fetch/ ---")

	// Try to find and parse actual feed files
	basePath := "data/fetch"
	patterns := []string{"*.csv", "*.tsv"}
	categories := []string{"ip", "domain", "hash", "ip_geo"}

	for _, cat := range categories {
		catPath := filepath.Join(basePath, cat)

		for _, pattern := range patterns {
			files, err := filepath.Glob(filepath.Join(catPath, pattern))
			if err != nil || len(files) == 0 {
				continue
			}

			ext := strings.TrimPrefix(pattern, "*")
			fmt.Printf("\n[%s] Found %d %s files\n", strings.ToUpper(cat), len(files), ext)

			// Parse first file as demo
			if len(files) > 0 {
				config := DefaultCSVConfig()
				config.MaxRows = 5 // Just sample first 5 rows

				// Detect delimiter
				if delim, err := DetectDelimiter(files[0]); err == nil {
					config.Delimiter = delim
				}

				data, err := ReadCSV(files[0], config)
				if err != nil {
					fmt.Printf("  Error: %v\n", err)
					continue
				}

				fmt.Printf("  File: %s\n", data.FileName)
				fmt.Printf("  Delimiter: '%c'\n", data.Delimiter)
				fmt.Printf("  Detected Category: %s\n", data.DetectedCategory)
				fmt.Printf("  Headers: %v\n", data.HeaderRow)

				// Show columns with detected types
				fmt.Println("  Columns:")
				for _, col := range data.Columns {
					fmt.Printf("    [%d] %s (%s) sample: %s\n",
						col.Index, col.Name, col.ContentType, truncate(col.SampleValue, 40))
				}

				// Show IPs/Domains/Hashes found
				ips := data.GetIPs()
				domains := data.GetDomains()
				urls := data.GetURLs()
				hashes := data.GetHashes()

				fmt.Printf("  Found: %d IPs, %d domains, %d URLs, %d hashes\n",
					len(ips), len(domains), len(urls), len(hashes))

				// Show sample records
				if len(data.Records) > 0 {
					fmt.Println("  First record fields:")
					for k, v := range data.Records[0].Fields {
						fmt.Printf("    %s: %s\n", k, truncate(v, 50))
					}
				}
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
