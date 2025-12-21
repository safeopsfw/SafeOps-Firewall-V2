package parsers

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/safeops/threat-intel/pkg/types"
	"github.com/safeops/threat-intel/pkg/utils"
)

// HostsParser handles parsing of hosts file format threat intelligence feeds
type HostsParser struct {
	commentChar             rune
	extractIPMapping        bool
	ignoreLoopbackRedirects bool
	ignoreIPv6              bool
	splitMultipleHosts      bool
	logger                  Logger

	// Parsing statistics
	totalLines     int
	parsedEntries  int
	skippedEntries int
	duplicateCount int
	errorCount     int
}

// HostsParserConfig holds configuration for hosts file parser initialization
type HostsParserConfig struct {
	CommentChar             string
	ExtractIPMapping        bool // Extract IP addresses or just domains
	IgnoreLoopbackRedirects bool // Skip 127.0.0.1/0.0.0.0 entries
	IgnoreIPv6              bool // Skip IPv6 entries
	SplitMultipleHosts      bool // Handle multiple hostnames per line
}

// NewHostsParser creates a new hosts file parser with the given configuration
func NewHostsParser(config *HostsParserConfig, logger Logger) (*HostsParser, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// Parse comment character
	commentChar := '#'
	if config.CommentChar != "" {
		commentRunes := []rune(config.CommentChar)
		if len(commentRunes) > 0 {
			commentChar = commentRunes[0]
		}
	}

	return &HostsParser{
		commentChar:             commentChar,
		extractIPMapping:        config.ExtractIPMapping,
		ignoreLoopbackRedirects: config.IgnoreLoopbackRedirects,
		ignoreIPv6:              config.IgnoreIPv6,
		splitMultipleHosts:      config.SplitMultipleHosts,
		logger:                  logger,
	}, nil
}

// Parse processes hosts file data and extracts IOCs
func (p *HostsParser) Parse(reader io.Reader, feedID string) ([]types.IOC, error) {
	scanner := bufio.NewScanner(reader)
	iocs := make([]types.IOC, 0)

	p.totalLines = 0
	p.parsedEntries = 0
	p.skippedEntries = 0
	p.duplicateCount = 0
	p.errorCount = 0

	for scanner.Scan() {
		p.totalLines++
		line := scanner.Text()

		// Parse the line
		lineIOCs, err := p.parseLine(line, p.totalLines, feedID)
		if err != nil {
			p.errorCount++
			p.logger.Warnf("Line %d: parsing error: %v", p.totalLines, err)
			continue
		}

		// Add IOCs, handling duplicates
		for _, newIOC := range lineIOCs {
			iocs = p.handleDuplicates(iocs, newIOC)
			p.parsedEntries++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading hosts file: %w", err)
	}

	p.logger.Infof("Hosts file parsing complete: %d lines, %d entries parsed, %d skipped, %d duplicates, %d errors",
		p.totalLines, p.parsedEntries, p.skippedEntries, p.duplicateCount, p.errorCount)

	return iocs, nil
}

// parseLine processes a single line from the hosts file
func (p *HostsParser) parseLine(line string, lineNumber int, feedID string) ([]types.IOC, error) {
	// Remove inline comments
	if idx := strings.IndexRune(line, p.commentChar); idx >= 0 {
		line = line[:idx]
	}

	// Trim whitespace
	line = strings.TrimSpace(line)

	// Skip empty lines
	if line == "" {
		return nil, nil
	}

	// Split on whitespace
	fields := strings.Fields(line)
	if len(fields) < 2 {
		// Need at least IP and hostname
		return nil, fmt.Errorf("invalid hosts entry: need IP and hostname")
	}

	// Extract IP address from first field
	ipAddress := fields[0]
	isLoopback, err := p.extractIPAddress(ipAddress, lineNumber)
	if err != nil {
		return nil, err
	}

	// Extract hostnames from remaining fields
	hostnames, err := p.extractHostnames(fields[1:], lineNumber)
	if err != nil {
		return nil, err
	}

	// Filter entries based on configuration
	iocs := make([]types.IOC, 0)
	for _, hostname := range hostnames {
		// Check if we should ignore this entry
		if shouldIgnore, reason := p.shouldIgnoreEntry(ipAddress, hostname, isLoopback); shouldIgnore {
			p.skippedEntries++
			p.logger.Debugf("Line %d: skipping %s -> %s: %s", lineNumber, ipAddress, hostname, reason)
			continue
		}

		// Create IOC
		ioc, err := p.createIOCFromEntry(ipAddress, hostname, feedID, lineNumber)
		if err != nil {
			p.logger.Warnf("Line %d: failed to create IOC: %v", lineNumber, err)
			continue
		}

		iocs = append(iocs, *ioc)

		// If not splitting multiple hosts, only take the first one
		if !p.splitMultipleHosts {
			break
		}
	}

	return iocs, nil
}

// extractIPAddress extracts and validates the IP address from a hosts file entry
func (p *HostsParser) extractIPAddress(ipStr string, lineNumber int) (bool, error) {
	// Validate IP format
	if !utils.IsValidIP(ipStr) {
		return false, fmt.Errorf("line %d: invalid IP address: %s", lineNumber, ipStr)
	}

	// Check if it's a loopback redirect
	isLoopback := false
	if ipStr == "127.0.0.1" || ipStr == "0.0.0.0" || ipStr == "::1" || ipStr == "::" {
		isLoopback = true
	}

	return isLoopback, nil
}

// extractHostnames extracts and validates hostnames from the hosts file entry
func (p *HostsParser) extractHostnames(fields []string, lineNumber int) ([]string, error) {
	hostnames := make([]string, 0, len(fields))

	for _, hostname := range fields {
		// Normalize and validate domain
		normalized, err := utils.NormalizeDomain(hostname, false)
		if err != nil {
			p.logger.Debugf("Line %d: invalid domain %s: %v", lineNumber, hostname, err)
			continue
		}

		// Filter out localhost
		if normalized == "localhost" || normalized == "localhost.localdomain" {
			continue
		}

		// Filter out wildcard entries (unless explicitly supported)
		if strings.HasPrefix(normalized, "*.") {
			continue
		}

		hostnames = append(hostnames, normalized)
	}

	if len(hostnames) == 0 {
		return nil, fmt.Errorf("no valid hostnames found")
	}

	return hostnames, nil
}

// shouldIgnoreEntry determines if a hosts entry should be skipped
func (p *HostsParser) shouldIgnoreEntry(ipAddress, hostname string, isLoopback bool) (bool, string) {
	// Ignore loopback redirects if configured
	if p.ignoreLoopbackRedirects && isLoopback {
		return true, "loopback redirect ignored"
	}

	// Ignore IPv6 if configured
	if p.ignoreIPv6 && utils.GetIPVersion(ipAddress) == 6 {
		return true, "IPv6 entry ignored"
	}

	// Check for obviously invalid domains
	if hostname == "" {
		return true, "empty hostname"
	}

	return false, ""
}

// createIOCFromEntry creates an IOC struct from a validated hosts file entry
func (p *HostsParser) createIOCFromEntry(ipAddress, hostname, feedID string, lineNumber int) (*types.IOC, error) {
	now := time.Now()

	ioc := &types.IOC{
		IOCType:         types.IOCTypeDomain,
		Value:           hostname,
		NormalizedValue: hostname,
		ThreatType:      types.ThreatMalware, // General malicious domain
		Confidence:      70.0,                // Medium-high confidence for hosts file entries
		Severity:        types.SeverityMedium,
		Sources:         []string{feedID},
		SourceCount:     1,
		FirstSeen:       now,
		LastSeen:        now,
		Tags:            []string{"hosts-file", "blocklist"},
		Metadata:        make(map[string]interface{}),
		IsActive:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Add IP address to metadata if extracting IP mappings
	if p.extractIPMapping {
		ioc.Metadata["ip_address"] = ipAddress
		ioc.Metadata["is_redirect"] = (ipAddress == "127.0.0.1" || ipAddress == "0.0.0.0")
	}

	// Add line number for reference
	ioc.Metadata["source_line"] = lineNumber

	return ioc, nil
}

// handleDuplicates manages duplicate domain entries in the IOC list
func (p *HostsParser) handleDuplicates(iocs []types.IOC, newIOC types.IOC) []types.IOC {
	// Normalize domain for comparison
	domainKey := strings.ToLower(newIOC.Value)

	// Check if this domain already exists
	for i := range iocs {
		existingDomain := strings.ToLower(iocs[i].Value)
		if existingDomain == domainKey {
			// Duplicate found - merge metadata
			p.duplicateCount++

			// Update last seen timestamp
			iocs[i].LastSeen = newIOC.LastSeen
			iocs[i].UpdatedAt = time.Now()

			// Merge sources if different
			sourceExists := false
			for _, source := range iocs[i].Sources {
				if source == newIOC.Sources[0] {
					sourceExists = true
					break
				}
			}
			if !sourceExists {
				iocs[i].Sources = append(iocs[i].Sources, newIOC.Sources...)
				iocs[i].SourceCount = len(iocs[i].Sources)
			}

			// Increment occurrence counter in metadata
			if occurrences, ok := iocs[i].Metadata["occurrence_count"].(int); ok {
				iocs[i].Metadata["occurrence_count"] = occurrences + 1
			} else {
				iocs[i].Metadata["occurrence_count"] = 2
			}

			// Merge line numbers if present
			if existingLine, ok := iocs[i].Metadata["source_line"].(int); ok {
				if newLine, ok := newIOC.Metadata["source_line"].(int); ok {
					// Store multiple line numbers as array
					if lines, ok := iocs[i].Metadata["source_lines"].([]int); ok {
						iocs[i].Metadata["source_lines"] = append(lines, newLine)
					} else {
						iocs[i].Metadata["source_lines"] = []int{existingLine, newLine}
					}
				}
			}

			// Increase confidence slightly for repeated observations (up to max 95)
			if iocs[i].Confidence < 95.0 {
				iocs[i].Confidence = min(95.0, iocs[i].Confidence+2.0)
			}

			return iocs
		}
	}

	// Not a duplicate - add new IOC
	return append(iocs, newIOC)
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// validateHostsFormat validates that input data appears to be in hosts file format
func (p *HostsParser) validateHostsFormat(sample string) (bool, float64) {
	lines := strings.Split(sample, "\n")
	validLines := 0
	totalDataLines := 0

	for _, line := range lines {
		// Remove comments
		if idx := strings.IndexRune(line, p.commentChar); idx >= 0 {
			line = line[:idx]
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		totalDataLines++

		// Check if line starts with valid IP
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if utils.IsValidIP(fields[0]) {
				validLines++
			}
		}
	}

	if totalDataLines == 0 {
		return false, 0.0
	}

	confidence := float64(validLines) / float64(totalDataLines)
	isValid := confidence > 0.7 // At least 70% of lines should be valid

	return isValid, confidence
}

// Close performs cleanup when parsing is complete
func (p *HostsParser) Close() error {
	p.logger.Debugf("Hosts parser closed. Stats: %d lines, %d parsed, %d skipped, %d duplicates, %d errors",
		p.totalLines, p.parsedEntries, p.skippedEntries, p.duplicateCount, p.errorCount)
	return nil
}

// ValidateHostsFormat is a public wrapper for format validation
func ValidateHostsFormat(reader io.Reader) (bool, float64, error) {
	// Read first 1KB or 50 lines for format detection
	scanner := bufio.NewScanner(reader)
	sample := strings.Builder{}
	lineCount := 0
	maxLines := 50

	for scanner.Scan() && lineCount < maxLines {
		sample.WriteString(scanner.Text())
		sample.WriteString("\n")
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return false, 0.0, err
	}

	// Create temporary parser for validation
	config := &HostsParserConfig{
		CommentChar: "#",
	}

	// Create a no-op logger for validation
	noopLogger := &NoopLogger{}

	parser, err := NewHostsParser(config, noopLogger)
	if err != nil {
		return false, 0.0, err
	}

	isValid, confidence := parser.validateHostsFormat(sample.String())
	return isValid, confidence, nil
}

// NoopLogger is a logger that does nothing (for validation)
type NoopLogger struct{}

func (l *NoopLogger) Debugf(format string, args ...interface{}) {}
func (l *NoopLogger) Infof(format string, args ...interface{})  {}
func (l *NoopLogger) Warnf(format string, args ...interface{})  {}
func (l *NoopLogger) Errorf(format string, args ...interface{}) {}
