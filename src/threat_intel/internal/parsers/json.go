package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/safeops/threat-intel/pkg/types"
	"github.com/safeops/threat-intel/pkg/utils"
)

// JSONParser handles parsing of JSON-formatted threat intelligence feeds
type JSONParser struct {
	config             *JSONParserConfig
	fieldMappings      map[string]string
	arrayPaths         []string
	metadataExtractors map[string]func(interface{}) interface{}
	validationRules    map[string]ValidationRule
	logger             Logger

	// Statistics
	totalParsed       int
	successfulParsed  int
	failedValidation  int
	duplicatesRemoved int
}

// JSONParserConfig defines how JSON documents should be parsed
type JSONParserConfig struct {
	RootArrayPath      string
	IndicatorField     string
	TypeField          string
	TypeMappings       map[string]string
	TimestampFields    []string
	ConfidenceField    string
	SeverityField      string
	TagsFields         []string
	ContextFields      map[string]string
	DateFormat         string
	StrictMode         bool
	MaxDepth           int
	StreamingThreshold int64
}

// ValidationRule defines validation logic for a field
type ValidationRule struct {
	Required  bool
	Validator func(interface{}) bool
}

// NewJSONParser creates a new JSON parser with configuration
func NewJSONParser(config *JSONParserConfig, logger Logger) (*JSONParser, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	if config == nil {
		config = &JSONParserConfig{
			MaxDepth:           10,
			StreamingThreshold: 10 * 1024 * 1024, // 10MB default
			DateFormat:         time.RFC3339,
		}
	}

	// Set defaults
	if config.MaxDepth == 0 {
		config.MaxDepth = 10
	}
	if config.StreamingThreshold == 0 {
		config.StreamingThreshold = 10 * 1024 * 1024
	}
	if config.DateFormat == "" {
		config.DateFormat = time.RFC3339
	}

	parser := &JSONParser{
		config:             config,
		fieldMappings:      make(map[string]string),
		arrayPaths:         make([]string, 0),
		metadataExtractors: make(map[string]func(interface{}) interface{}),
		validationRules:    make(map[string]ValidationRule),
		logger:             logger,
	}

	// Initialize field mappings from config
	if config.ContextFields != nil {
		parser.fieldMappings = config.ContextFields
	}

	return parser, nil
}

// Parse processes JSON data and extracts IOCs
func (p *JSONParser) Parse(reader io.Reader, feedID string) ([]types.IOC, error) {
	// Read all data first (streaming implementation would be more complex)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON data: %w", err)
	}

	// Parse based on root structure
	var rawData interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var iocs []types.IOC

	// Handle root array vs object
	switch v := rawData.(type) {
	case []interface{}:
		// Root is an array
		iocs, err = p.parseJSONArray(v, feedID)
	case map[string]interface{}:
		// Root is an object - check for nested array
		if p.config.RootArrayPath != "" {
			arrayData, found := p.extractNestedField(v, p.config.RootArrayPath)
			if !found {
				return nil, fmt.Errorf("array path not found: %s", p.config.RootArrayPath)
			}
			if arr, ok := arrayData.([]interface{}); ok {
				iocs, err = p.parseJSONArray(arr, feedID)
			} else {
				return nil, fmt.Errorf("path does not contain array: %s", p.config.RootArrayPath)
			}
		} else {
			// Single object
			ioc, parseErr := p.parseJSONObject(v, feedID)
			if parseErr != nil {
				err = parseErr
			} else {
				iocs = []types.IOC{ioc}
			}
		}
	default:
		return nil, fmt.Errorf("unexpected JSON root type: %T", v)
	}

	if err != nil && p.config.StrictMode {
		return nil, err
	}

	// Deduplicate
	iocs = p.deduplicateIOCs(iocs)

	p.logger.Infof("JSON parsing complete: %d total, %d successful, %d failed, %d duplicates removed",
		p.totalParsed, p.successfulParsed, p.failedValidation, p.duplicatesRemoved)

	return iocs, nil
}

// parseJSONArray processes array of indicators
func (p *JSONParser) parseJSONArray(arrayData []interface{}, feedID string) ([]types.IOC, error) {
	iocs := make([]types.IOC, 0, len(arrayData))
	var lastError error

	for i, item := range arrayData {
		p.totalParsed++

		switch v := item.(type) {
		case map[string]interface{}:
			// Object in array
			ioc, err := p.parseJSONObject(v, feedID)
			if err != nil {
				p.failedValidation++
				p.logger.Warnf("Failed to parse array element %d: %v", i, err)
				lastError = err
				continue
			}
			iocs = append(iocs, ioc)
			p.successfulParsed++

		case string:
			// Direct string indicator
			ioc, err := p.createIOCFromString(v, feedID)
			if err != nil {
				p.failedValidation++
				p.logger.Warnf("Failed to parse string element %d: %v", i, err)
				lastError = err
				continue
			}
			iocs = append(iocs, ioc)
			p.successfulParsed++

		default:
			p.failedValidation++
			p.logger.Warnf("Unexpected array element type at %d: %T", i, v)
		}
	}

	return iocs, lastError
}

// parseJSONObject processes a single JSON object containing indicator data
func (p *JSONParser) parseJSONObject(objData map[string]interface{}, feedID string) (types.IOC, error) {
	now := time.Now()

	// Extract indicator value
	indicatorValue, found := p.extractNestedField(objData, p.config.IndicatorField)
	if !found {
		return types.IOC{}, fmt.Errorf("indicator field not found: %s", p.config.IndicatorField)
	}

	indicatorStr, ok := indicatorValue.(string)
	if !ok {
		return types.IOC{}, fmt.Errorf("indicator value is not a string: %T", indicatorValue)
	}

	// Extract type
	var iocType types.IOCType
	if p.config.TypeField != "" {
		typeValue, found := p.extractNestedField(objData, p.config.TypeField)
		if found {
			if typeStr, ok := typeValue.(string); ok {
				mappedType, err := p.applyTypeMapping(typeStr, indicatorStr)
				if err != nil {
					return types.IOC{}, err
				}
				iocType = types.IOCType(mappedType)
			}
		}
	}

	// Auto-detect type if not found
	if iocType == "" {
		detectedType := p.detectIndicatorType(indicatorStr)
		iocType = detectedType
	}

	// Create base IOC
	ioc := types.IOC{
		IOCType:         iocType,
		Value:           indicatorStr,
		NormalizedValue: strings.ToLower(indicatorStr),
		ThreatType:      types.ThreatSuspicious,
		Confidence:      50.0, // Default
		Severity:        types.SeverityMedium,
		Sources:         []string{feedID},
		SourceCount:     1,
		FirstSeen:       now,
		LastSeen:        now,
		Tags:            make([]string, 0),
		Metadata:        make(map[string]interface{}),
		IsActive:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Extract timestamps
	if len(p.config.TimestampFields) > 0 {
		for _, field := range p.config.TimestampFields {
			tsValue, found := p.extractNestedField(objData, field)
			if found {
				if ts, err := p.parseTimestamp(tsValue, p.config.DateFormat); err == nil {
					ioc.FirstSeen = ts
					ioc.LastSeen = ts
					break
				}
			}
		}
	}

	// Extract confidence
	if p.config.ConfidenceField != "" {
		confValue, found := p.extractNestedField(objData, p.config.ConfidenceField)
		if found {
			if conf, err := p.calculateConfidence(confValue); err == nil {
				ioc.Confidence = conf
			}
		}
	}

	// Extract tags
	if len(p.config.TagsFields) > 0 {
		tags := make([]string, 0)
		for _, field := range p.config.TagsFields {
			tagValue, found := p.extractNestedField(objData, field)
			if found {
				switch v := tagValue.(type) {
				case []interface{}:
					for _, tag := range v {
						if tagStr, ok := tag.(string); ok {
							tags = append(tags, tagStr)
						}
					}
				case string:
					tags = append(tags, v)
				}
			}
		}
		ioc.Tags = tags
	}

	// Extract metadata
	if err := p.extractMetadata(objData, &ioc); err != nil {
		p.logger.Warnf("Metadata extraction warning: %v", err)
	}

	return ioc, nil
}

// createIOCFromString creates IOC from plain string indicator
func (p *JSONParser) createIOCFromString(indicator, feedID string) (types.IOC, error) {
	now := time.Now()

	iocType := p.detectIndicatorType(indicator)
	if iocType == "" {
		return types.IOC{}, fmt.Errorf("unable to detect indicator type: %s", indicator)
	}

	return types.IOC{
		IOCType:         iocType,
		Value:           indicator,
		NormalizedValue: strings.ToLower(indicator),
		ThreatType:      types.ThreatSuspicious,
		Confidence:      50.0,
		Severity:        types.SeverityMedium,
		Sources:         []string{feedID},
		SourceCount:     1,
		FirstSeen:       now,
		LastSeen:        now,
		Tags:            []string{"json-array"},
		Metadata:        make(map[string]interface{}),
		IsActive:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// extractNestedField retrieves values from nested JSON using dot notation
func (p *JSONParser) extractNestedField(data map[string]interface{}, path string) (interface{}, bool) {
	if path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")
	var current interface{} = data

	for _, part := range parts {
		// Handle array indices like "items[0]"
		if strings.Contains(part, "[") {
			// For simplicity, skip array index handling in this implementation
			// Production code would parse and handle indices
			part = strings.Split(part, "[")[0]
		}

		if currentMap, ok := current.(map[string]interface{}); ok {
			val, found := currentMap[part]
			if !found {
				return nil, false
			}
			current = val
		} else {
			return nil, false
		}
	}

	return current, true
}

// parseTimestamp converts various timestamp formats to time.Time
func (p *JSONParser) parseTimestamp(value interface{}, format string) (time.Time, error) {
	switch v := value.(type) {
	case string:
		// Try configured format first
		if t, err := time.Parse(format, v); err == nil {
			return t.UTC(), nil
		}

		// Try common formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			time.RFC1123,
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}

		for _, fmt := range formats {
			if t, err := time.Parse(fmt, v); err == nil {
				return t.UTC(), nil
			}
		}

		return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", v)

	case float64:
		// Unix timestamp (seconds or milliseconds)
		if v > 1e12 {
			// Milliseconds
			return time.Unix(0, int64(v)*int64(time.Millisecond)).UTC(), nil
		}
		// Seconds
		return time.Unix(int64(v), 0).UTC(), nil

	case int64:
		// Unix timestamp
		if v > 1e12 {
			return time.Unix(0, v*int64(time.Millisecond)).UTC(), nil
		}
		return time.Unix(v, 0).UTC(), nil

	default:
		return time.Time{}, fmt.Errorf("unsupported timestamp type: %T", value)
	}
}

// extractMetadata extracts configured metadata fields
func (p *JSONParser) extractMetadata(objData map[string]interface{}, ioc *types.IOC) error {
	for sourceField, targetField := range p.config.ContextFields {
		value, found := p.extractNestedField(objData, sourceField)
		if found && value != nil {
			ioc.Metadata[targetField] = value
		}
	}
	return nil
}

// applyTypeMapping converts source type to internal IOC type
func (p *JSONParser) applyTypeMapping(sourceType, indicatorValue string) (string, error) {
	// Check configured mappings
	if p.config.TypeMappings != nil {
		if mapped, ok := p.config.TypeMappings[strings.ToLower(sourceType)]; ok {
			return mapped, nil
		}
	}

	// Fallback to auto-detection
	detectedType := p.detectIndicatorType(indicatorValue)
	if detectedType == "" {
		return "", fmt.Errorf("unable to map or detect type: %s", sourceType)
	}

	return string(detectedType), nil
}

// detectIndicatorType automatically detects indicator type
func (p *JSONParser) detectIndicatorType(indicator string) types.IOCType {
	// Try IP
	if utils.IsValidIP(indicator) {
		if utils.GetIPVersion(indicator) == 4 {
			return types.IOCTypeIPv4
		}
		return types.IOCTypeIPv6
	}

	// Try domain
	if _, err := utils.NormalizeDomain(indicator, false); err == nil {
		return types.IOCTypeDomain
	}

	// Try hash
	if hashType, err := utils.DetectHashType(indicator); err == nil {
		switch hashType {
		case utils.HashMD5:
			return types.IOCTypeMD5
		case utils.HashSHA1:
			return types.IOCTypeSHA1
		case utils.HashSHA256:
			return types.IOCTypeSHA256
		case utils.HashSHA512:
			return types.IOCTypeSHA512
		}
	}

	// Try URL
	if strings.HasPrefix(strings.ToLower(indicator), "http://") ||
		strings.HasPrefix(strings.ToLower(indicator), "https://") {
		return types.IOCTypeURL
	}

	return ""
}

// calculateConfidence normalizes confidence scores to 0-100 range
func (p *JSONParser) calculateConfidence(rawConfidence interface{}) (float64, error) {
	switch v := rawConfidence.(type) {
	case float64:
		// Detect scale
		if v >= 0 && v <= 1 {
			// 0-1 scale
			return v * 100, nil
		} else if v >= 0 && v <= 10 {
			// 0-10 scale
			return v * 10, nil
		} else if v >= 0 && v <= 100 {
			// 0-100 scale
			return v, nil
		}
		return 50.0, fmt.Errorf("confidence out of recognizable range: %f", v)

	case int, int64:
		// Convert to float64
		var val float64
		switch vv := v.(type) {
		case int:
			val = float64(vv)
		case int64:
			val = float64(vv)
		}

		if val >= 0 && val <= 10 {
			return val * 10, nil
		} else if val >= 0 && val <= 100 {
			return val, nil
		}
		return 50.0, fmt.Errorf("confidence out of range: %v", v)

	case string:
		// Handle qualitative values
		lower := strings.ToLower(v)
		switch lower {
		case "high", "confirmed":
			return 80.0, nil
		case "medium", "probable":
			return 50.0, nil
		case "low", "possible":
			return 20.0, nil
		default:
			// Try parsing as number
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return p.calculateConfidence(f)
			}
			return 50.0, fmt.Errorf("unrecognized confidence string: %s", v)
		}

	default:
		return 50.0, fmt.Errorf("unsupported confidence type: %T", v)
	}
}

// deduplicateIOCs removes duplicate indicators
func (p *JSONParser) deduplicateIOCs(iocs []types.IOC) []types.IOC {
	seen := make(map[string]int) // Maps normalized value to index
	result := make([]types.IOC, 0, len(iocs))

	for _, ioc := range iocs {
		key := strings.ToLower(ioc.Value) + ":" + string(ioc.IOCType)

		if idx, exists := seen[key]; exists {
			// Duplicate found
			p.duplicatesRemoved++

			// Keep higher confidence
			if ioc.Confidence > result[idx].Confidence {
				result[idx] = ioc
			} else {
				// Merge tags
				tagSet := make(map[string]bool)
				for _, tag := range result[idx].Tags {
					tagSet[tag] = true
				}
				for _, tag := range ioc.Tags {
					tagSet[tag] = true
				}
				tags := make([]string, 0, len(tagSet))
				for tag := range tagSet {
					tags = append(tags, tag)
				}
				result[idx].Tags = tags

				// Update last seen
				if ioc.LastSeen.After(result[idx].LastSeen) {
					result[idx].LastSeen = ioc.LastSeen
				}
			}
		} else {
			// New indicator
			seen[key] = len(result)
			result = append(result, ioc)
		}
	}

	return result
}

// Close performs cleanup
func (p *JSONParser) Close() error {
	p.logger.Debugf("JSON parser closed. Stats: %d total, %d successful, %d failed, %d duplicates",
		p.totalParsed, p.successfulParsed, p.failedValidation, p.duplicatesRemoved)
	return nil
}
