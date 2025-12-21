package parsers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/safeops/threat-intel/pkg/types"
)

// AutoDetectParser orchestrates format detection and parser routing
type AutoDetectParser struct {
	csvParser       *CSVParser
	jsonParser      *JSONParser
	plainTextParser *PlainTextParser
	hostsParser     *HostsParser
	netsetParser    *NetsetParser
	logger          Logger

	// Statistics
	totalDetections   int
	correctDetections int
	detectionByFormat map[string]int
	fallbackAttempts  int
}

// FeedMetadata contains additional context for format detection
type FeedMetadata struct {
	Filename    string
	ContentType string
	FileSize    int64
	Headers     map[string]string
}

// NewAutoDetectParser creates a new auto-detection parser
func NewAutoDetectParser(logger Logger) (*AutoDetectParser, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// Initialize specialized parsers with default configs
	csvParser, err := NewCSVParser(&CSVParserConfig{}, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSV parser: %w", err)
	}

	jsonParser, err := NewJSONParser(&JSONParserConfig{
		IndicatorField: "indicator",
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON parser: %w", err)
	}

	plainTextParser, err := NewPlainTextParser(&PlainTextParserConfig{
		ExtractionMode: "line_by_line",
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create plain text parser: %w", err)
	}

	hostsParser, err := NewHostsParser(&HostsParserConfig{
		CommentChar:             "#",
		IgnoreLoopbackRedirects: true,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create hosts parser: %w", err)
	}

	netsetParser, err := NewNetsetParser(&NetsetParserConfig{
		PreserveRanges: true,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create netset parser: %w", err)
	}

	return &AutoDetectParser{
		csvParser:         csvParser,
		jsonParser:        jsonParser,
		plainTextParser:   plainTextParser,
		hostsParser:       hostsParser,
		netsetParser:      netsetParser,
		logger:            logger,
		detectionByFormat: make(map[string]int),
	}, nil
}

// Parse auto-detects format and routes to appropriate parser
func (p *AutoDetectParser) Parse(reader io.Reader, feedID string, metadata *FeedMetadata) ([]types.IOC, error) {
	if metadata == nil {
		metadata = &FeedMetadata{}
	}

	// Extract content sample for detection
	sample, fullReader, err := p.extractContentSample(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	// Detect format
	detectedFormat, confidence, rationale := p.detectFormat(sample, metadata)

	p.logDetectionDecision(detectedFormat, confidence, rationale, metadata)
	p.totalDetections++
	p.detectionByFormat[detectedFormat]++

	// Parse with detected format and fallback
	iocs, actualFormat, err := p.parseWithFallback(fullReader, detectedFormat, feedID)
	if err != nil {
		return nil, err
	}

	// Update statistics
	p.updateDetectionStatistics(detectedFormat, actualFormat, confidence)

	return iocs, nil
}

// detectFormat analyzes content to determine format
func (p *AutoDetectParser) detectFormat(content []byte, metadata *FeedMetadata) (string, float64, string) {
	// Check each format with weighted scoring
	formatScores := make(map[string]float64)
	reasons := make(map[string]string)

	// JSON detection
	if isJSON, conf := p.checkJSONFormat(content); isJSON {
		formatScores["json"] = conf
		reasons["json"] = "valid JSON syntax detected"
	}

	// CSV detection
	if isCSV, conf := p.checkCSVFormat(content); isCSV {
		formatScores["csv"] = conf
		reasons["csv"] = "consistent delimiter pattern detected"
	}

	// Hosts file detection
	if isHosts, conf := p.checkHostsFormat(content); isHosts {
		formatScores["hosts"] = conf
		reasons["hosts"] = "IP-to-hostname mapping pattern detected"
	}

	// Netset detection
	if isNetset, conf := p.checkNetsetFormat(content); isNetset {
		formatScores["netset"] = conf
		reasons["netset"] = "CIDR/range notation detected"
	}

	// Plain text detection (always has some confidence as fallback)
	if isPlain, conf := p.checkPlainTextFormat(content); isPlain {
		formatScores["plaintext"] = conf
		reasons["plaintext"] = "newline-delimited indicator list"
	}

	// Apply file extension hints
	if metadata.Filename != "" {
		for format := range formatScores {
			formatScores[format] = p.applyFileExtensionHint(metadata.Filename, format, formatScores[format])
		}
	}

	// Apply content-type hints
	if metadata.ContentType != "" {
		for format := range formatScores {
			formatScores[format] = p.applyContentTypeHint(metadata.ContentType, format, formatScores[format])
		}
	}

	// Find highest confidence format
	maxConfidence := 0.0
	detectedFormat := "plaintext" // default fallback
	var rationale string

	for format, score := range formatScores {
		if score > maxConfidence {
			maxConfidence = score
			detectedFormat = format
			rationale = reasons[format]
		}
	}

	return detectedFormat, maxConfidence, rationale
}

// checkJSONFormat validates JSON format
func (p *AutoDetectParser) checkJSONFormat(content []byte) (bool, float64) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return false, 0.0
	}

	// Must start with { or [
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return false, 0.0
	}

	// Validate JSON syntax
	if json.Valid(trimmed) {
		return true, 0.95
	}

	// Partial JSON might be valid in full document
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return true, 0.5
	}

	return false, 0.0
}

// checkCSVFormat validates CSV format
func (p *AutoDetectParser) checkCSVFormat(content []byte) (bool, float64) {
	lines := bytes.Split(content, []byte("\n"))
	if len(lines) < 2 {
		return false, 0.0
	}

	// Detect delimiter candidates
	delimiters := []byte{',', ';', '|', '\t'}
	delimiterCounts := make(map[byte]int)
	delimiterConsistency := make(map[byte]int)

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		for _, delim := range delimiters {
			count := bytes.Count(line, []byte{delim})
			if count > 0 {
				delimiterCounts[delim]++
				if delimiterConsistency[delim] == 0 {
					delimiterConsistency[delim] = count
				}
			}
		}
	}

	// Find most consistent delimiter
	maxConsistency := 0
	for delim, count := range delimiterCounts {
		if count > maxConsistency && delimiterConsistency[delim] > 1 {
			maxConsistency = count
		}
	}

	if maxConsistency >= 2 {
		confidence := float64(maxConsistency) / float64(len(lines))
		if confidence > 0.5 {
			return true, minFloat(confidence, 0.9)
		}
	}

	return false, 0.0
}

// checkPlainTextFormat validates plain text format
func (p *AutoDetectParser) checkPlainTextFormat(content []byte) (bool, float64) {
	lines := bytes.Split(content, []byte("\n"))
	if len(lines) == 0 {
		return false, 0.0
	}

	// Count lines with IOC-like patterns
	iocPattern := regexp.MustCompile(`(?i)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-f0-9]{32,128}|https?://|[a-z0-9-]+\.[a-z]{2,})`)
	iocLines := 0
	totalLines := 0

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		totalLines++
		if iocPattern.Match(line) {
			iocLines++
		}
	}

	if totalLines == 0 {
		return false, 0.0
	}

	ratio := float64(iocLines) / float64(totalLines)
	if ratio > 0.3 {
		return true, minFloat(0.3+ratio*0.4, 0.7)
	}

	return false, 0.0
}

// checkHostsFormat validates hosts file format
func (p *AutoDetectParser) checkHostsFormat(content []byte) (bool, float64) {
	lines := bytes.Split(content, []byte("\n"))
	hostsLines := 0
	totalLines := 0

	// Pattern: IP whitespace hostname
	hostsPattern := regexp.MustCompile(`^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f:]+)\s+[a-z0-9\-\.]+`)

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		totalLines++
		if hostsPattern.Match(line) {
			hostsLines++
		}
	}

	if totalLines == 0 {
		return false, 0.0
	}

	ratio := float64(hostsLines) / float64(totalLines)
	if ratio > 0.5 {
		return true, minFloat(0.6+ratio*0.3, 0.9)
	}

	return false, 0.0
}

// checkNetsetFormat validates network range format
func (p *AutoDetectParser) checkNetsetFormat(content []byte) (bool, float64) {
	lines := bytes.Split(content, []byte("\n"))
	netsetLines := 0
	totalLines := 0

	// Pattern: CIDR or range notation
	cidrPattern := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}`)
	rangePattern := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*-\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		totalLines++
		if cidrPattern.Match(line) || rangePattern.Match(line) {
			netsetLines++
		}
	}

	if totalLines == 0 {
		return false, 0.0
	}

	ratio := float64(netsetLines) / float64(totalLines)
	if ratio > 0.5 {
		return true, minFloat(0.7+ratio*0.25, 0.95)
	}

	return false, 0.0
}

// extractContentSample reads sample while preserving full stream
func (p *AutoDetectParser) extractContentSample(reader io.Reader) ([]byte, io.Reader, error) {
	// Read full content into buffer
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	// Take sample (first 8KB or full content if smaller)
	sampleSize := 8192
	sample := content
	if len(content) > sampleSize {
		sample = content[:sampleSize]
	}

	// Create new reader with full content
	fullReader := bytes.NewReader(content)

	return sample, fullReader, nil
}

// applyFileExtensionHint adjusts confidence based on file extension
func (p *AutoDetectParser) applyFileExtensionHint(filename, format string, confidence float64) float64 {
	lower := strings.ToLower(filename)

	boost := 0.0
	switch format {
	case "json":
		if strings.HasSuffix(lower, ".json") {
			boost = 0.15
		}
	case "csv":
		if strings.HasSuffix(lower, ".csv") {
			boost = 0.15
		}
	case "hosts":
		if strings.HasSuffix(lower, ".hosts") || strings.Contains(lower, "hosts") {
			boost = 0.1
		}
	case "plaintext":
		if strings.HasSuffix(lower, ".txt") {
			boost = 0.05
		}
	}

	return minFloat(confidence+boost, 1.0)
}

// applyContentTypeHint adjusts confidence based on Content-Type
func (p *AutoDetectParser) applyContentTypeHint(contentType, format string, confidence float64) float64 {
	lower := strings.ToLower(contentType)

	boost := 0.0
	switch format {
	case "json":
		if strings.Contains(lower, "application/json") {
			boost = 0.2
		}
	case "csv":
		if strings.Contains(lower, "text/csv") {
			boost = 0.2
		}
	case "plaintext":
		if strings.Contains(lower, "text/plain") {
			boost = 0.1
		}
	}

	return minFloat(confidence+boost, 1.0)
}

// parseWithFallback attempts parsing with fallback
func (p *AutoDetectParser) parseWithFallback(reader io.Reader, primaryFormat, feedID string) ([]types.IOC, string, error) {
	// Try primary format
	iocs, err := p.parseWithFormat(reader, primaryFormat, feedID)
	if err == nil && len(iocs) > 0 {
		return iocs, primaryFormat, nil
	}

	p.logger.Warnf("Primary format %s failed: %v, attempting fallback", primaryFormat, err)
	p.fallbackAttempts++

	// Define fallback order
	fallbackOrder := []string{"plaintext", "csv", "json", "hosts", "netset"}

	// Try each fallback format
	for _, format := range fallbackOrder {
		if format == primaryFormat {
			continue
		}

		// Need to re-read content for each attempt
		content, ok := reader.(*bytes.Reader)
		if !ok {
			return nil, "", fmt.Errorf("cannot retry with non-seekable reader")
		}
		content.Seek(0, io.SeekStart)

		iocs, err = p.parseWithFormat(content, format, feedID)
		if err == nil && len(iocs) > 0 {
			p.logger.Infof("Fallback to %s succeeded, extracted %d IOCs", format, len(iocs))
			return iocs, format, nil
		}
	}

	return nil, "", fmt.Errorf("all parsers failed")
}

// parseWithFormat routes to specific parser
func (p *AutoDetectParser) parseWithFormat(reader io.Reader, format, feedID string) ([]types.IOC, error) {
	switch format {
	case "json":
		return p.jsonParser.Parse(reader, feedID)
	case "csv":
		return p.csvParser.Parse(reader, feedID)
	case "plaintext":
		return p.plainTextParser.Parse(reader, feedID)
	case "hosts":
		return p.hostsParser.Parse(reader, feedID)
	case "netset":
		return p.netsetParser.Parse(reader, feedID)
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}

// logDetectionDecision records format detection decision
func (p *AutoDetectParser) logDetectionDecision(format string, confidence float64, rationale string, metadata *FeedMetadata) {
	if confidence < 0.5 {
		p.logger.Warnf("Low confidence (%.2f) format detection: %s - %s (file: %s)",
			confidence, format, rationale, metadata.Filename)
	} else {
		p.logger.Infof("Detected format: %s (confidence: %.2f) - %s",
			format, confidence, rationale)
	}
}

// updateDetectionStatistics tracks accuracy
func (p *AutoDetectParser) updateDetectionStatistics(detected, actual string, confidence float64) {
	if detected == actual {
		p.correctDetections++
	}

	// Log statistics periodically with confidence info
	if p.totalDetections%100 == 0 {
		accuracy := float64(p.correctDetections) / float64(p.totalDetections) * 100
		p.logger.Infof("Detection statistics: %d total, %.1f%% accuracy, %d fallback attempts, last confidence: %.2f",
			p.totalDetections, accuracy, p.fallbackAttempts, confidence)
	}
}

// Close cleans up parser resources
func (p *AutoDetectParser) Close() error {
	p.csvParser.Close()
	p.jsonParser.Close()
	p.plainTextParser.Close()
	p.hostsParser.Close()
	p.netsetParser.Close()

	accuracy := 0.0
	if p.totalDetections > 0 {
		accuracy = float64(p.correctDetections) / float64(p.totalDetections) * 100
	}

	p.logger.Infof("Auto-detect parser closed. Final stats: %d detections, %.1f%% accuracy, %d fallbacks",
		p.totalDetections, accuracy, p.fallbackAttempts)

	return nil
}

// Helper function
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
