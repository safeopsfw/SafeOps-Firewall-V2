package parsers

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/safeops/threat-intel/pkg/types"
	"github.com/safeops/threat-intel/pkg/utils"
)

// ExtractionMode defines how the parser processes text
type ExtractionMode string

const (
	ModeLineByLine   ExtractionMode = "line_by_line"
	ModeFullText     ExtractionMode = "full_text"
	ModeRegexPattern ExtractionMode = "regex_patterns"
)

// CustomPattern represents a user-defined regex extraction pattern
type CustomPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	IOCType    types.IOCType
	Confidence float64
	ThreatType types.ThreatType
	Tags       []string
}

// PlainTextParser extracts IOCs from unstructured text using regex patterns
type PlainTextParser struct {
	extractionMode    ExtractionMode
	ipRegex           *regexp.Regexp
	domainRegex       *regexp.Regexp
	urlRegex          *regexp.Regexp
	md5Regex          *regexp.Regexp
	sha1Regex         *regexp.Regexp
	sha256Regex       *regexp.Regexp
	sha512Regex       *regexp.Regexp
	customPatterns    []CustomPattern
	commentChars      []rune
	caseSensitive     bool
	deduplicateInline bool
	filterPrivateIPs  bool
	logger            Logger

	// Statistics
	totalLines         int
	extractedIPs       int
	extractedDomains   int
	extractedURLs      int
	extractedHashes    int
	duplicatesFiltered int
	falsePositives     int
}

// PlainTextParserConfig holds configuration for plain text parser
type PlainTextParserConfig struct {
	ExtractionMode    string
	CommentChars      string
	CaseSensitive     bool
	DeduplicateInline bool
	FilterPrivateIPs  bool
	CustomPatterns    []map[string]interface{} // Custom regex patterns from config
}

// NewPlainTextParser creates a new plain text parser
func NewPlainTextParser(config *PlainTextParserConfig, logger Logger) (*PlainTextParser, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// Parse extraction mode
	mode := ModeLineByLine
	if config.ExtractionMode != "" {
		mode = ExtractionMode(config.ExtractionMode)
	}

	// Compile default regex patterns
	// IPv4 pattern - matches standard dotted decimal notation
	ipv4Pattern := `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`

	// IPv6 pattern - simplified for common formats
	ipv6Pattern := `\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b`

	// Combined IP pattern
	ipPattern := fmt.Sprintf(`(%s|%s)`, ipv4Pattern, ipv6Pattern)
	ipRegex, err := regexp.Compile(ipPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile IP regex: %w", err)
	}

	// Domain pattern - matches valid domain names
	domainPattern := `\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`
	domainRegex, err := regexp.Compile(domainPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile domain regex: %w", err)
	}

	// URL pattern - matches http/https URLs
	urlPattern := `https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`
	urlRegex, err := regexp.Compile(urlPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile URL regex: %w", err)
	}

	// Hash patterns by length
	md5Pattern := `\b[a-fA-F0-9]{32}\b`
	md5Regex, err := regexp.Compile(md5Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile MD5 regex: %w", err)
	}

	sha1Pattern := `\b[a-fA-F0-9]{40}\b`
	sha1Regex, err := regexp.Compile(sha1Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile SHA1 regex: %w", err)
	}

	sha256Pattern := `\b[a-fA-F0-9]{64}\b`
	sha256Regex, err := regexp.Compile(sha256Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile SHA256 regex: %w", err)
	}

	sha512Pattern := `\b[a-fA-F0-9]{128}\b`
	sha512Regex, err := regexp.Compile(sha512Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile SHA512 regex: %w", err)
	}

	// Parse comment characters
	commentChars := []rune{'#'}
	if config.CommentChars != "" {
		commentChars = []rune(config.CommentChars)
	}

	parser := &PlainTextParser{
		extractionMode:    mode,
		ipRegex:           ipRegex,
		domainRegex:       domainRegex,
		urlRegex:          urlRegex,
		md5Regex:          md5Regex,
		sha1Regex:         sha1Regex,
		sha256Regex:       sha256Regex,
		sha512Regex:       sha512Regex,
		customPatterns:    make([]CustomPattern, 0),
		commentChars:      commentChars,
		caseSensitive:     config.CaseSensitive,
		deduplicateInline: config.DeduplicateInline,
		filterPrivateIPs:  config.FilterPrivateIPs,
		logger:            logger,
	}

	// TODO: Parse custom patterns from config
	// This would require additional configuration structure

	return parser, nil
}

// Parse processes plain text and extracts IOCs
func (p *PlainTextParser) Parse(reader io.Reader, feedID string) ([]types.IOC, error) {
	var iocs []types.IOC
	var err error

	switch p.extractionMode {
	case ModeLineByLine:
		iocs, err = p.extractByLine(reader, feedID)
	case ModeFullText:
		// Read all text first
		scanner := bufio.NewScanner(reader)
		scanner.Split(bufio.ScanBytes)
		var textBuilder strings.Builder
		for scanner.Scan() {
			textBuilder.Write(scanner.Bytes())
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading text: %w", err)
		}
		iocs, err = p.extractFromFullText(textBuilder.String(), feedID)
	default:
		return nil, fmt.Errorf("unsupported extraction mode: %s", p.extractionMode)
	}

	if err != nil {
		return nil, err
	}

	// Deduplicate if configured
	if p.deduplicateInline {
		iocs = p.deduplicate(iocs)
	}

	p.logger.Infof("Plain text parsing complete: %d lines, %d IPs, %d domains, %d URLs, %d hashes, %d duplicates",
		p.totalLines, p.extractedIPs, p.extractedDomains, p.extractedURLs, p.extractedHashes, p.duplicatesFiltered)

	return iocs, nil
}

// extractByLine processes text line by line
func (p *PlainTextParser) extractByLine(reader io.Reader, feedID string) ([]types.IOC, error) {
	scanner := bufio.NewScanner(reader)
	iocs := make([]types.IOC, 0)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		p.totalLines++
		line := scanner.Text()

		// Skip comment lines
		if p.isCommentLine(line) {
			continue
		}

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Extract indicators from this line
		lineIOCs := p.extractFromLine(line, feedID, lineNumber)
		iocs = append(iocs, lineIOCs...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading text: %w", err)
	}

	return iocs, nil
}

// extractFromLine extracts all indicators from a single line
func (p *PlainTextParser) extractFromLine(line string, feedID string, lineNumber int) []types.IOC {
	iocs := make([]types.IOC, 0)

	// Extract IPs
	ips := p.extractIPAddresses(line)
	for _, ip := range ips {
		if ioc, err := p.createIOCFromExtraction(ip, "ip", feedID, lineNumber, 60.0); err == nil {
			iocs = append(iocs, *ioc)
			p.extractedIPs++
		}
	}

	// Extract domains
	domains := p.extractDomains(line)
	for _, domain := range domains {
		if ioc, err := p.createIOCFromExtraction(domain, "domain", feedID, lineNumber, 55.0); err == nil {
			iocs = append(iocs, *ioc)
			p.extractedDomains++
		}
	}

	// Extract URLs
	urls := p.extractURLs(line)
	for _, url := range urls {
		if ioc, err := p.createIOCFromExtraction(url, "url", feedID, lineNumber, 65.0); err == nil {
			iocs = append(iocs, *ioc)
			p.extractedURLs++
		}
	}

	// Extract hashes
	hashes := p.extractHashes(line)
	for _, hash := range hashes {
		if ioc, err := p.createIOCFromExtraction(hash.Value, hash.Type, feedID, lineNumber, 70.0); err == nil {
			iocs = append(iocs, *ioc)
			p.extractedHashes++
		}
	}

	return iocs
}

// extractFromFullText processes entire text as one block
func (p *PlainTextParser) extractFromFullText(text string, feedID string) ([]types.IOC, error) {
	iocs := make([]types.IOC, 0)

	// Extract IPs
	ips := p.extractIPAddresses(text)
	for _, ip := range ips {
		if ioc, err := p.createIOCFromExtraction(ip, "ip", feedID, 0, 60.0); err == nil {
			iocs = append(iocs, *ioc)
			p.extractedIPs++
		}
	}

	// Extract domains
	domains := p.extractDomains(text)
	for _, domain := range domains {
		if ioc, err := p.createIOCFromExtraction(domain, "domain", feedID, 0, 55.0); err == nil {
			iocs = append(iocs, *ioc)
			p.extractedDomains++
		}
	}

	// Extract URLs
	urls := p.extractURLs(text)
	for _, url := range urls {
		if ioc, err := p.createIOCFromExtraction(url, "url", feedID, 0, 65.0); err == nil {
			iocs = append(iocs, *ioc)
			p.extractedURLs++
		}
	}

	// Extract hashes
	hashes := p.extractHashes(text)
	for _, hash := range hashes {
		if ioc, err := p.createIOCFromExtraction(hash.Value, hash.Type, feedID, 0, 70.0); err == nil {
			iocs = append(iocs, *ioc)
			p.extractedHashes++
		}
	}

	return iocs, nil
}

// HashMatch represents an extracted hash with its detected type
type HashMatch struct {
	Value string
	Type  string
}

// extractIPAddresses extracts IP addresses from text
func (p *PlainTextParser) extractIPAddresses(text string) []string {
	matches := p.ipRegex.FindAllString(text, -1)
	validIPs := make([]string, 0, len(matches))

	for _, match := range matches {
		// Validate it's actually an IP
		if utils.IsValidIP(match) {
			// Filter private IPs if configured
			if p.filterPrivateIPs && !utils.IsPublicIP(match) {
				p.falsePositives++
				continue
			}
			validIPs = append(validIPs, match)
		} else {
			p.falsePositives++
		}
	}

	return p.filterFalsePositives(validIPs, "ip")
}

// extractDomains extracts domain names from text
func (p *PlainTextParser) extractDomains(text string) []string {
	matches := p.domainRegex.FindAllString(text, -1)
	validDomains := make([]string, 0, len(matches))

	for _, match := range matches {
		// Normalize and validate
		normalized, err := utils.NormalizeDomain(match, false)
		if err != nil {
			p.falsePositives++
			continue
		}
		validDomains = append(validDomains, normalized)
	}

	return p.filterFalsePositives(validDomains, "domain")
}

// extractURLs extracts URLs from text
func (p *PlainTextParser) extractURLs(text string) []string {
	matches := p.urlRegex.FindAllString(text, -1)
	validURLs := make([]string, 0, len(matches))

	for _, match := range matches {
		// Basic validation - ensure it's not truncated
		if len(match) > 10 { // Minimum reasonable URL length
			validURLs = append(validURLs, match)
		} else {
			p.falsePositives++
		}
	}

	return validURLs
}

// extractHashes extracts file hashes from text
func (p *PlainTextParser) extractHashes(text string) []HashMatch {
	hashes := make([]HashMatch, 0)

	// Extract MD5 (32 chars)
	md5Matches := p.md5Regex.FindAllString(text, -1)
	for _, match := range md5Matches {
		if utils.IsValidHash(match) {
			hashes = append(hashes, HashMatch{Value: match, Type: "md5"})
		} else {
			p.falsePositives++
		}
	}

	// Extract SHA1 (40 chars)
	sha1Matches := p.sha1Regex.FindAllString(text, -1)
	for _, match := range sha1Matches {
		if utils.IsValidHash(match) {
			hashes = append(hashes, HashMatch{Value: match, Type: "sha1"})
		} else {
			p.falsePositives++
		}
	}

	// Extract SHA256 (64 chars)
	sha256Matches := p.sha256Regex.FindAllString(text, -1)
	for _, match := range sha256Matches {
		if utils.IsValidHash(match) {
			hashes = append(hashes, HashMatch{Value: match, Type: "sha256"})
		} else {
			p.falsePositives++
		}
	}

	// Extract SHA512 (128 chars)
	sha512Matches := p.sha512Regex.FindAllString(text, -1)
	for _, match := range sha512Matches {
		if utils.IsValidHash(match) {
			hashes = append(hashes, HashMatch{Value: match, Type: "sha512"})
		} else {
			p.falsePositives++
		}
	}

	return hashes
}

// filterFalsePositives removes common false positive indicators
func (p *PlainTextParser) filterFalsePositives(indicators []string, indicatorType string) []string {
	filtered := make([]string, 0, len(indicators))

	for _, indicator := range indicators {
		lowerIndicator := strings.ToLower(indicator)

		// Domain false positive filtering
		if indicatorType == "domain" {
			// Skip common example domains
			if lowerIndicator == "example.com" || lowerIndicator == "example.org" ||
				lowerIndicator == "example.net" || lowerIndicator == "test.com" ||
				lowerIndicator == "localhost" || lowerIndicator == "test.local" ||
				strings.HasSuffix(lowerIndicator, ".local") ||
				strings.HasSuffix(lowerIndicator, ".test") ||
				strings.HasSuffix(lowerIndicator, ".example") {
				p.falsePositives++
				continue
			}

			// Skip domains that are likely file extensions or paths
			if len(lowerIndicator) < 4 || !strings.Contains(lowerIndicator, ".") {
				p.falsePositives++
				continue
			}
		}

		// IP false positive filtering
		if indicatorType == "ip" {
			// Skip localhost
			if indicator == "127.0.0.1" || indicator == "::1" {
				p.falsePositives++
				continue
			}

			// Skip common version numbers that look like IPs
			if indicator == "0.0.0.0" || indicator == "255.255.255.255" {
				p.falsePositives++
				continue
			}
		}

		filtered = append(filtered, indicator)
	}

	return filtered
}

// createIOCFromExtraction creates an IOC from an extracted indicator
func (p *PlainTextParser) createIOCFromExtraction(indicator, indicatorType, feedID string, lineNumber int, confidence float64) (*types.IOC, error) {
	now := time.Now()

	ioc := &types.IOC{
		Value:           indicator,
		NormalizedValue: strings.ToLower(indicator),
		ThreatType:      types.ThreatSuspicious, // Lower confidence for plain text
		Confidence:      confidence,
		Severity:        types.SeverityMedium,
		Sources:         []string{feedID},
		SourceCount:     1,
		FirstSeen:       now,
		LastSeen:        now,
		Tags:            []string{"plain-text", "regex-extracted"},
		Metadata:        make(map[string]interface{}),
		IsActive:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Set IOC type based on indicator type
	switch indicatorType {
	case "ip":
		if utils.GetIPVersion(indicator) == 4 {
			ioc.IOCType = types.IOCTypeIPv4
		} else {
			ioc.IOCType = types.IOCTypeIPv6
		}
	case "domain":
		ioc.IOCType = types.IOCTypeDomain
	case "url":
		ioc.IOCType = types.IOCTypeURL
	case "md5":
		ioc.IOCType = types.IOCTypeMD5
	case "sha1":
		ioc.IOCType = types.IOCTypeSHA1
	case "sha256":
		ioc.IOCType = types.IOCTypeSHA256
	case "sha512":
		ioc.IOCType = types.IOCTypeSHA512
	default:
		return nil, fmt.Errorf("unknown indicator type: %s", indicatorType)
	}

	// Add extraction metadata
	if lineNumber > 0 {
		ioc.Metadata["source_line"] = lineNumber
	}
	ioc.Metadata["extraction_method"] = "regex"

	return ioc, nil
}

// deduplicate removes duplicate IOCs
func (p *PlainTextParser) deduplicate(iocs []types.IOC) []types.IOC {
	seen := make(map[string]int) // Maps normalized value to index in result
	result := make([]types.IOC, 0, len(iocs))

	for _, ioc := range iocs {
		key := strings.ToLower(ioc.Value)

		if idx, exists := seen[key]; exists {
			// Duplicate found - update existing
			p.duplicatesFiltered++

			// Update last seen
			result[idx].LastSeen = ioc.LastSeen
			result[idx].UpdatedAt = time.Now()

			// Increment occurrence count
			if count, ok := result[idx].Metadata["occurrence_count"].(int); ok {
				result[idx].Metadata["occurrence_count"] = count + 1
			} else {
				result[idx].Metadata["occurrence_count"] = 2
			}
		} else {
			// New indicator
			seen[key] = len(result)
			result = append(result, ioc)
		}
	}

	return result
}

// isCommentLine checks if a line is a comment
func (p *PlainTextParser) isCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	for _, char := range p.commentChars {
		if rune(trimmed[0]) == char {
			return true
		}
	}

	return false
}

// Close performs cleanup
func (p *PlainTextParser) Close() error {
	p.logger.Debugf("Plain text parser closed. Stats: %d lines, %d IPs, %d domains, %d URLs, %d hashes, %d false positives, %d duplicates",
		p.totalLines, p.extractedIPs, p.extractedDomains, p.extractedURLs, p.extractedHashes, p.falsePositives, p.duplicatesFiltered)
	return nil
}
