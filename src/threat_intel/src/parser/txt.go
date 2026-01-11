package parser

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// =============================================================================
// TXT Reader - Smart Text File Parser
// Reads TXT files and detects content type (IP, Domain, URL, Hash)
// Can be used directly by any program
// =============================================================================

// ContentType represents the detected type of content in a line
type ContentType string

const (
	ContentTypeIP       ContentType = "ip"
	ContentTypeIPRange  ContentType = "ip_range"   // CIDR notation
	ContentTypeDomain   ContentType = "domain"
	ContentTypeURL      ContentType = "url"
	ContentTypeHash     ContentType = "hash"
	ContentTypeHostsEntry ContentType = "hosts_entry" // 0.0.0.0 domain.com
	ContentTypeTorExit  ContentType = "tor_exit"     // Tor exit node format
	ContentTypeUnknown  ContentType = "unknown"
)

// TXTRecord represents a single parsed line with detected content
type TXTRecord struct {
	LineNumber  int         `json:"line_number"`
	RawLine     string      `json:"raw_line"`
	Value       string      `json:"value"`        // Extracted value (IP, domain, etc.)
	ContentType ContentType `json:"content_type"`
	Extra       map[string]string `json:"extra,omitempty"` // Additional extracted data
}

// TXTData represents the complete parsed TXT file
type TXTData struct {
	FilePath    string       `json:"file_path"`
	FileName    string       `json:"file_name"`
	TotalLines  int          `json:"total_lines"`
	ValidLines  int          `json:"valid_lines"`
	SkippedLines int         `json:"skipped_lines"` // Comments + empty
	Records     []TXTRecord  `json:"records"`
	ContentSummary map[ContentType]int `json:"content_summary"` // Count per type
	DetectedCategory string `json:"detected_category"` // ip, domain, hash, mixed
}

// TXTConfig holds configuration for TXT parsing
type TXTConfig struct {
	CommentChars []string // Characters that start comment lines
	SkipEmpty    bool     // Skip empty lines
	TrimSpaces   bool     // Trim whitespace from lines
	MaxLines     int      // Maximum lines to read (0 = unlimited)
}

// DefaultTXTConfig returns sensible defaults
func DefaultTXTConfig() *TXTConfig {
	return &TXTConfig{
		CommentChars: []string{"#", "//", ";"},
		SkipEmpty:    true,
		TrimSpaces:   true,
		MaxLines:     0, // Unlimited
	}
}

// Regex patterns for content detection
var (
	// IPv4 address
	ipv4Pattern = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
	
	// IPv4 with CIDR
	cidrPattern = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$`)
	
	// IPv6 address (simplified)
	ipv6Pattern = regexp.MustCompile(`^([0-9a-fA-F:]+)$`)
	
	// MD5 hash (32 hex chars)
	md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	
	// SHA1 hash (40 hex chars)
	sha1Pattern = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	
	// SHA256 hash (64 hex chars)
	sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	
	// Domain pattern (simple)
	domainPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
	
	// Hosts file entry: IP domain
	hostsPattern = regexp.MustCompile(`^(0\.0\.0\.0|127\.0\.0\.1)\s+(.+)$`)
	
	// Tor exit node: ExitAddress IP date
	torExitPattern = regexp.MustCompile(`^ExitAddress\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(.+)$`)
	
	// URL pattern
	urlPattern = regexp.MustCompile(`^https?://`)
)

// =============================================================================
// TXT Reader Functions
// =============================================================================

// ReadTXT reads a TXT file and returns parsed data with content detection
func ReadTXT(filePath string, config *TXTConfig) (*TXTData, error) {
	if config == nil {
		config = DefaultTXTConfig()
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data := &TXTData{
		FilePath:       filePath,
		FileName:       filepath.Base(filePath),
		Records:        []TXTRecord{},
		ContentSummary: make(map[ContentType]int),
	}

	scanner := bufio.NewScanner(file)
	// Handle very long lines (some feeds have long URLs)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) // Up to 1MB per line

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		data.TotalLines++

		// Check max lines limit
		if config.MaxLines > 0 && lineNum > config.MaxLines {
			break
		}

		rawLine := scanner.Text()
		line := rawLine
		
		if config.TrimSpaces {
			line = strings.TrimSpace(line)
		}

		// Skip empty lines
		if config.SkipEmpty && line == "" {
			data.SkippedLines++
			continue
		}

		// Skip comment lines
		isComment := false
		for _, cc := range config.CommentChars {
			if strings.HasPrefix(line, cc) {
				isComment = true
				break
			}
		}
		if isComment {
			data.SkippedLines++
			continue
		}

		// Detect content type and extract value
		record := detectContent(line, lineNum)
		record.RawLine = rawLine
		
		data.Records = append(data.Records, record)
		data.ValidLines++
		data.ContentSummary[record.ContentType]++
	}

	if err := scanner.Err(); err != nil {
		return data, fmt.Errorf("scanner error: %w", err)
	}

	// Detect overall category based on content summary
	data.DetectedCategory = detectCategory(data.ContentSummary)

	return data, nil
}

// detectContent analyzes a line and determines its content type
func detectContent(line string, lineNum int) TXTRecord {
	record := TXTRecord{
		LineNumber: lineNum,
		Extra:      make(map[string]string),
	}

	// Check for Tor exit node format first
	if matches := torExitPattern.FindStringSubmatch(line); len(matches) == 3 {
		record.ContentType = ContentTypeTorExit
		record.Value = matches[1] // IP address
		record.Extra["timestamp"] = matches[2]
		return record
	}

	// Check for hosts file entry (0.0.0.0 domain or 127.0.0.1 domain)
	if matches := hostsPattern.FindStringSubmatch(line); len(matches) == 3 {
		record.ContentType = ContentTypeHostsEntry
		record.Value = strings.TrimSpace(matches[2]) // Domain
		record.Extra["hosts_ip"] = matches[1]
		return record
	}

	// Check for URL
	if urlPattern.MatchString(line) {
		record.ContentType = ContentTypeURL
		record.Value = line
		// Try to extract domain from URL
		if u, err := url.Parse(line); err == nil {
			record.Extra["domain"] = u.Host
			record.Extra["scheme"] = u.Scheme
			record.Extra["path"] = u.Path
		}
		return record
	}

	// Check for CIDR notation
	if cidrPattern.MatchString(line) {
		_, _, err := net.ParseCIDR(line)
		if err == nil {
			record.ContentType = ContentTypeIPRange
			record.Value = line
			return record
		}
	}

	// Check for IPv4
	if ipv4Pattern.MatchString(line) {
		ip := net.ParseIP(line)
		if ip != nil && ip.To4() != nil {
			record.ContentType = ContentTypeIP
			record.Value = line
			return record
		}
	}

	// Check for IPv6
	if strings.Contains(line, ":") && !strings.Contains(line, ".") {
		ip := net.ParseIP(line)
		if ip != nil {
			record.ContentType = ContentTypeIP
			record.Value = line
			record.Extra["version"] = "ipv6"
			return record
		}
	}

	// Check for hashes
	if sha256Pattern.MatchString(line) {
		record.ContentType = ContentTypeHash
		record.Value = strings.ToLower(line)
		record.Extra["hash_type"] = "sha256"
		return record
	}
	if sha1Pattern.MatchString(line) {
		record.ContentType = ContentTypeHash
		record.Value = strings.ToLower(line)
		record.Extra["hash_type"] = "sha1"
		return record
	}
	if md5Pattern.MatchString(line) {
		record.ContentType = ContentTypeHash
		record.Value = strings.ToLower(line)
		record.Extra["hash_type"] = "md5"
		return record
	}

	// Check for domain
	if domainPattern.MatchString(line) {
		record.ContentType = ContentTypeDomain
		record.Value = strings.ToLower(line)
		return record
	}

	// Unknown content type
	record.ContentType = ContentTypeUnknown
	record.Value = line
	return record
}

// detectCategory determines the overall file category based on content types
func detectCategory(summary map[ContentType]int) string {
	total := 0
	for _, count := range summary {
		total += count
	}
	if total == 0 {
		return "empty"
	}

	// Calculate percentages
	ipCount := summary[ContentTypeIP] + summary[ContentTypeIPRange] + summary[ContentTypeTorExit]
	domainCount := summary[ContentTypeDomain] + summary[ContentTypeHostsEntry]
	urlCount := summary[ContentTypeURL]
	hashCount := summary[ContentTypeHash]

	// Determine dominant type (>70% of content)
	threshold := float64(total) * 0.7

	if float64(ipCount) > threshold {
		return "ip"
	}
	if float64(domainCount) > threshold {
		return "domain"
	}
	if float64(urlCount) > threshold {
		return "url"
	}
	if float64(hashCount) > threshold {
		return "hash"
	}

	return "mixed"
}

// =============================================================================
// Helper Functions for Direct Usage
// =============================================================================

// GetIPs returns only IP records from parsed data
func (d *TXTData) GetIPs() []TXTRecord {
	var ips []TXTRecord
	for _, r := range d.Records {
		if r.ContentType == ContentTypeIP || r.ContentType == ContentTypeIPRange || r.ContentType == ContentTypeTorExit {
			ips = append(ips, r)
		}
	}
	return ips
}

// GetDomains returns only domain records from parsed data
func (d *TXTData) GetDomains() []TXTRecord {
	var domains []TXTRecord
	for _, r := range d.Records {
		if r.ContentType == ContentTypeDomain || r.ContentType == ContentTypeHostsEntry {
			domains = append(domains, r)
		}
	}
	return domains
}

// GetURLs returns only URL records from parsed data
func (d *TXTData) GetURLs() []TXTRecord {
	var urls []TXTRecord
	for _, r := range d.Records {
		if r.ContentType == ContentTypeURL {
			urls = append(urls, r)
		}
	}
	return urls
}

// GetHashes returns only hash records from parsed data
func (d *TXTData) GetHashes() []TXTRecord {
	var hashes []TXTRecord
	for _, r := range d.Records {
		if r.ContentType == ContentTypeHash {
			hashes = append(hashes, r)
		}
	}
	return hashes
}

// GetValues returns just the values as a string slice
func (d *TXTData) GetValues() []string {
	values := make([]string, len(d.Records))
	for i, r := range d.Records {
		values[i] = r.Value
	}
	return values
}

// =============================================================================
// Test/Demo Function - Prints sample output when run directly
// =============================================================================

// TestTXTReader demonstrates TXT reader capabilities
func TestTXTReader() {
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println("TXT READER - Content Detection Demo")
	fmt.Println("=" + strings.Repeat("=", 79))

	// Test data with different content types
	testLines := []string{
		"# This is a comment",
		"192.168.1.1",
		"10.0.0.0/8",
		"2001:db8::1",
		"malware-domain.com",
		"https://phishing.example.com/login",
		"0.0.0.0 adware.tracking.com",
		"ExitAddress 185.220.101.1 2024-12-25 10:00:00",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"d41d8cd98f00b204e9800998ecf8427e",
		"",
		"// Another comment style",
		"bad-actor.org",
	}

	fmt.Println("\n--- Testing Content Detection ---")
	for i, line := range testLines {
		record := detectContent(line, i+1)
		if record.ContentType == ContentTypeUnknown && (strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || line == "") {
			fmt.Printf("Line %2d: [SKIP    ] %s\n", i+1, line)
		} else {
			extra := ""
			if len(record.Extra) > 0 {
				parts := []string{}
				for k, v := range record.Extra {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
				extra = " {" + strings.Join(parts, ", ") + "}"
			}
			fmt.Printf("Line %2d: [%-8s] %s%s\n", i+1, record.ContentType, record.Value, extra)
		}
	}

	fmt.Println("\n--- Looking for actual TXT files in data/fetch/ ---")
	
	// Try to find and parse actual feed files
	basePath := "data/fetch"
	categories := []string{"ip", "domain", "hash", "ip_geo"}
	
	for _, cat := range categories {
		catPath := filepath.Join(basePath, cat)
		files, err := filepath.Glob(filepath.Join(catPath, "*.txt"))
		if err != nil || len(files) == 0 {
			continue
		}
		
		fmt.Printf("\n[%s] Found %d TXT files\n", strings.ToUpper(cat), len(files))
		
		// Parse first file as demo
		if len(files) > 0 {
			config := DefaultTXTConfig()
			config.MaxLines = 10 // Just sample first 10 lines
			
			data, err := ReadTXT(files[0], config)
			if err != nil {
				fmt.Printf("  Error: %v\n", err)
				continue
			}
			
			fmt.Printf("  File: %s\n", data.FileName)
			fmt.Printf("  Detected Category: %s\n", data.DetectedCategory)
			fmt.Printf("  Content Summary: %v\n", data.ContentSummary)
			fmt.Println("  First 5 records:")
			
			limit := 5
			if len(data.Records) < limit {
				limit = len(data.Records)
			}
			for i := 0; i < limit; i++ {
				r := data.Records[i]
				fmt.Printf("    [%s] %s\n", r.ContentType, r.Value)
			}
		}
	}
	
	fmt.Println("\n" + strings.Repeat("=", 80))
}
