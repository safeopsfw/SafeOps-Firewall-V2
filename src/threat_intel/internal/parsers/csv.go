package parsers

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/safeops/threat-intel/pkg/types"
	"github.com/safeops/threat-intel/pkg/utils"
)

// Logger interface for parser logging
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// CSVParser handles parsing of CSV-formatted threat intelligence feeds
type CSVParser struct {
	delimiter       rune
	commentChar     rune
	skipLines       int
	hasHeader       bool
	columnMappings  map[string]interface{} // Maps field names to column indices or names
	requiredColumns []string
	errorMode       string // skip_line, skip_feed, fail_immediately
	errorCount      int
	errorThreshold  int
	logger          Logger
}

// CSVParserConfig holds configuration for CSV parser initialization
type CSVParserConfig struct {
	Delimiter       string
	CommentChar     string
	SkipLines       int
	HasHeader       bool
	ColumnMappings  map[string]interface{}
	RequiredColumns []string
	ErrorMode       string
	ErrorThreshold  int
}

// NewCSVParser creates a new CSV parser with the given configuration
func NewCSVParser(config *CSVParserConfig, logger Logger) (*CSVParser, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// Validate and parse delimiter
	delimiter := ','
	if config.Delimiter != "" {
		delimiterRunes := []rune(config.Delimiter)
		if len(delimiterRunes) == 0 {
			return nil, fmt.Errorf("delimiter cannot be empty")
		}
		delimiter = delimiterRunes[0]

		// Handle special delimiter names
		switch strings.ToLower(config.Delimiter) {
		case "comma":
			delimiter = ','
		case "semicolon":
			delimiter = ';'
		case "tab":
			delimiter = '\t'
		case "pipe":
			delimiter = '|'
		}
	}

	// Parse comment character
	commentChar := '#'
	if config.CommentChar != "" {
		commentRunes := []rune(config.CommentChar)
		if len(commentRunes) > 0 {
			commentChar = commentRunes[0]
		}
	}

	// Set error threshold default
	errorThreshold := config.ErrorThreshold
	if errorThreshold == 0 {
		errorThreshold = 100 // Default to 100 errors before stopping
	}

	// Set error mode default
	errorMode := config.ErrorMode
	if errorMode == "" {
		errorMode = "skip_line"
	}

	parser := &CSVParser{
		delimiter:       delimiter,
		commentChar:     commentChar,
		skipLines:       config.SkipLines,
		hasHeader:       config.HasHeader,
		columnMappings:  config.ColumnMappings,
		requiredColumns: config.RequiredColumns,
		errorMode:       errorMode,
		errorThreshold:  errorThreshold,
		logger:          logger,
	}

	// Validate that required columns are present in mappings
	for _, reqCol := range config.RequiredColumns {
		if _, exists := config.ColumnMappings[reqCol]; !exists {
			return nil, fmt.Errorf("required column '%s' not found in column mappings", reqCol)
		}
	}

	return parser, nil
}

// Parse processes CSV data and extracts IOCs
func (p *CSVParser) Parse(reader io.Reader, feedID string) ([]types.IOC, error) {
	csvReader := csv.NewReader(reader)
	csvReader.Comma = p.delimiter
	csvReader.Comment = p.commentChar
	csvReader.FieldsPerRecord = -1 // Allow variable field counts
	csvReader.TrimLeadingSpace = true

	iocs := make([]types.IOC, 0)
	var columnNameIndex map[string]int
	lineNumber := 0
	dataLineNumber := 0

	// Skip configured number of lines
	for i := 0; i < p.skipLines; i++ {
		_, err := csvReader.Read()
		if err == io.EOF {
			return iocs, nil
		}
		if err != nil {
			p.logger.Warnf("Error skipping line %d: %v", i+1, err)
		}
		lineNumber++
	}

	for {
		record, err := csvReader.Read()
		lineNumber++

		if err == io.EOF {
			break
		}

		if err != nil {
			if !p.handleParsingError(lineNumber, err) {
				break
			}
			continue
		}

		// Parse header if this is the first data line and hasHeader is true
		if dataLineNumber == 0 && p.hasHeader {
			columnNameIndex, err = p.parseHeader(record)
			if err != nil {
				return nil, fmt.Errorf("failed to parse header: %w", err)
			}
			dataLineNumber++
			continue
		}

		// Parse data row
		ioc, err := p.parseRow(record, columnNameIndex, feedID, lineNumber)
		if err != nil {
			if !p.handleParsingError(lineNumber, err) {
				break
			}
			continue
		}

		if ioc != nil {
			iocs = append(iocs, *ioc)
		}
		dataLineNumber++
	}

	p.logger.Infof("CSV parsing complete: %d lines processed, %d IOCs extracted, %d errors",
		lineNumber, len(iocs), p.errorCount)

	return iocs, nil
}

// parseHeader processes the CSV header row to create column name mappings
func (p *CSVParser) parseHeader(headerRow []string) (map[string]int, error) {
	columnIndex := make(map[string]int)
	seenNames := make(map[string]bool)

	for idx, name := range headerRow {
		// Normalize column name (trim, lowercase)
		normalizedName := strings.ToLower(strings.TrimSpace(name))

		// Check for duplicate column names
		if seenNames[normalizedName] {
			return nil, fmt.Errorf("duplicate column name: %s", name)
		}

		columnIndex[normalizedName] = idx
		seenNames[normalizedName] = true
	}

	// Validate that required columns are present
	for _, reqCol := range p.requiredColumns {
		if _, exists := columnIndex[strings.ToLower(reqCol)]; !exists {
			return nil, fmt.Errorf("required column '%s' not found in header", reqCol)
		}
	}

	return columnIndex, nil
}

// parseRow extracts an IOC from a CSV row
func (p *CSVParser) parseRow(row []string, columnNameIndex map[string]int, feedID string, lineNumber int) (*types.IOC, error) {
	ioc := &types.IOC{
		Sources:     []string{feedID},
		SourceCount: 1,
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		Metadata:    make(map[string]interface{}),
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Extract primary indicator (IP, domain, hash, or URL)
	if ipCol, exists := p.columnMappings["ip"]; exists {
		ip, err := p.extractValue(row, ipCol, columnNameIndex)
		if err == nil && ip != "" {
			// Validate IP
			if utils.IsValidIP(ip) {
				// Determine IPv4 or IPv6
				if utils.GetIPVersion(ip) == 4 {
					ioc.IOCType = types.IOCTypeIPv4
				} else {
					ioc.IOCType = types.IOCTypeIPv6
				}
				ioc.Value = ip
				ioc.NormalizedValue = utils.NormalizeIP(ip)
			} else {
				return nil, fmt.Errorf("invalid IP address: %s", ip)
			}
		}
	}

	if domainCol, exists := p.columnMappings["domain"]; exists && ioc.Value == "" {
		domain, err := p.extractValue(row, domainCol, columnNameIndex)
		if err == nil && domain != "" {
			// Validate and normalize domain
			normalizedDomain, err := utils.NormalizeDomain(domain, false)
			if err != nil {
				return nil, fmt.Errorf("invalid domain: %s: %w", domain, err)
			}
			ioc.IOCType = types.IOCTypeDomain
			ioc.Value = normalizedDomain
			ioc.NormalizedValue = normalizedDomain
		}
	}

	if urlCol, exists := p.columnMappings["url"]; exists && ioc.Value == "" {
		url, err := p.extractValue(row, urlCol, columnNameIndex)
		if err == nil && url != "" {
			ioc.IOCType = types.IOCTypeURL
			ioc.Value = url
			ioc.NormalizedValue = strings.ToLower(url)
		}
	}

	if hashCol, exists := p.columnMappings["hash"]; exists && ioc.Value == "" {
		hash, err := p.extractValue(row, hashCol, columnNameIndex)
		if err == nil && hash != "" {
			// Validate hash and detect type
			hashType, err := utils.DetectHashType(hash)
			if err != nil {
				return nil, fmt.Errorf("invalid hash: %s: %w", hash, err)
			}

			switch hashType {
			case utils.HashMD5:
				ioc.IOCType = types.IOCTypeMD5
			case utils.HashSHA1:
				ioc.IOCType = types.IOCTypeSHA1
			case utils.HashSHA256:
				ioc.IOCType = types.IOCTypeSHA256
			case utils.HashSHA512:
				ioc.IOCType = types.IOCTypeSHA512
			default:
				// For unknown hash types, default to SHA256
				ioc.IOCType = types.IOCTypeSHA256
			}
			normalizedHash := strings.ToLower(hash)
			ioc.Value = normalizedHash
			ioc.NormalizedValue = normalizedHash
		}
	}

	// Require at least one primary indicator
	if ioc.Value == "" {
		return nil, fmt.Errorf("no valid indicator found in row")
	}

	// Extract metadata fields
	if err := p.extractMetadata(row, columnNameIndex, ioc); err != nil {
		p.logger.Warnf("Line %d: metadata extraction warning: %v", lineNumber, err)
	}

	// Validate the IOC
	if err := p.validateRow(ioc); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return ioc, nil
}

// extractValue retrieves a field value from a CSV row
func (p *CSVParser) extractValue(row []string, columnConfig interface{}, columnNameIndex map[string]int) (string, error) {
	var columnIdx int

	switch v := columnConfig.(type) {
	case int:
		// Direct column index
		columnIdx = v
	case string:
		// Column name lookup
		if columnNameIndex == nil {
			return "", fmt.Errorf("column name '%s' specified but no header present", v)
		}
		idx, exists := columnNameIndex[strings.ToLower(v)]
		if !exists {
			return "", fmt.Errorf("column name '%s' not found in header", v)
		}
		columnIdx = idx
	case float64:
		// JSON numbers come as float64
		columnIdx = int(v)
	default:
		return "", fmt.Errorf("invalid column config type: %T", v)
	}

	// Check bounds
	if columnIdx < 0 || columnIdx >= len(row) {
		return "", fmt.Errorf("column index %d out of bounds (row has %d columns)", columnIdx, len(row))
	}

	return strings.TrimSpace(row[columnIdx]), nil
}

// extractMetadata extracts additional metadata fields from the CSV row
func (p *CSVParser) extractMetadata(row []string, columnNameIndex map[string]int, ioc *types.IOC) error {
	// Threat type/category
	if col, exists := p.columnMappings["threat_type"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			ioc.Metadata["threat_type"] = value
		}
	}

	if col, exists := p.columnMappings["malware_family"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			ioc.Metadata["malware_family"] = value
		}
	}

	// Confidence score
	if col, exists := p.columnMappings["confidence"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			if confidence, err := strconv.ParseFloat(value, 64); err == nil {
				ioc.Confidence = confidence
			}
		}
	}

	// Severity
	if col, exists := p.columnMappings["severity"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			ioc.Metadata["severity"] = value
		}
	}

	// Tags
	if col, exists := p.columnMappings["tags"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			// Split tags by comma or semicolon
			tags := strings.FieldsFunc(value, func(r rune) bool {
				return r == ',' || r == ';'
			})
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
			ioc.Tags = tags
		}
	}

	// Timestamps
	if col, exists := p.columnMappings["first_seen"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			if ts, err := p.parseTimestamp(value); err == nil {
				ioc.FirstSeen = ts
			}
		}
	}

	if col, exists := p.columnMappings["last_seen"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			if ts, err := p.parseTimestamp(value); err == nil {
				ioc.LastSeen = ts
			}
		}
	}

	// Description
	if col, exists := p.columnMappings["description"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			ioc.Metadata["description"] = value
		}
	}

	// Country
	if col, exists := p.columnMappings["country"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			ioc.Metadata["country"] = value
		}
	}

	// ASN
	if col, exists := p.columnMappings["asn"]; exists {
		if value, err := p.extractValue(row, col, columnNameIndex); err == nil && value != "" {
			if asn, err := strconv.Atoi(value); err == nil {
				ioc.Metadata["asn"] = asn
			}
		}
	}

	return nil
}

// parseTimestamp converts a timestamp string to time.Time
func (p *CSVParser) parseTimestamp(timestampStr string) (time.Time, error) {
	// Try common formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"01/02/2006",
	}

	for _, format := range formats {
		if ts, err := time.Parse(format, timestampStr); err == nil {
			return ts.UTC(), nil
		}
	}

	// Try Unix timestamp
	if timestamp, err := strconv.ParseInt(timestampStr, 10, 64); err == nil {
		return time.Unix(timestamp, 0).UTC(), nil
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", timestampStr)
}

// validateRow performs validation on the extracted IOC
func (p *CSVParser) validateRow(ioc *types.IOC) error {
	// Ensure primary indicator is present
	if ioc.Value == "" {
		return fmt.Errorf("missing primary indicator value")
	}

	// Validate IOC type is set
	if ioc.IOCType == "" {
		return fmt.Errorf("missing IOC type")
	}

	// Validate confidence score range if present
	if ioc.Confidence < 0 || ioc.Confidence > 100 {
		return fmt.Errorf("confidence score %g out of range (0-100)", ioc.Confidence)
	}

	// Validate timestamps
	if ioc.FirstSeen.After(ioc.LastSeen) {
		return fmt.Errorf("first_seen is after last_seen")
	}

	return nil
}

// handleParsingError manages parsing errors
func (p *CSVParser) handleParsingError(lineNumber int, err error) bool {
	p.errorCount++
	p.logger.Warnf("Line %d: parsing error: %v", lineNumber, err)

	// Check if error threshold exceeded
	if p.errorCount >= p.errorThreshold {
		p.logger.Errorf("Error threshold (%d) exceeded, stopping parsing", p.errorThreshold)
		return false
	}

	// Handle based on error mode
	switch p.errorMode {
	case "fail_immediately":
		return false
	case "skip_feed":
		return false
	case "skip_line":
		// Continue processing
		return true
	default:
		return true
	}
}

// Close performs cleanup when parsing is complete
func (p *CSVParser) Close() error {
	// Log final statistics
	p.logger.Debugf("CSV parser closed. Total errors: %d", p.errorCount)
	return nil
}
