package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// =============================================================================
// JSON Reader - Smart JSON File Parser
// Reads JSON files (arrays, objects, NDJSON)
// Detects content types in values (IP, Domain, URL, Hash)
// Can be used directly by any program
// =============================================================================

// JSONData represents the complete parsed JSON file
type JSONData struct {
	FilePath         string                   `json:"file_path"`
	FileName         string                   `json:"file_name"`
	Format           string                   `json:"format"` // "array", "object", "ndjson"
	TotalRecords     int                      `json:"total_records"`
	Records          []map[string]interface{} `json:"records"`
	Fields           []string                 `json:"fields"` // All unique field names found
	DetectedCategory string                   `json:"detected_category"`
	ContentSummary   map[ContentType]int      `json:"content_summary"`
	RootPath         string                   `json:"root_path,omitempty"` // Path used to extract data
}

// JSONConfig holds configuration for JSON parsing
type JSONConfig struct {
	RootPath   string // JSONPath-like root (e.g., "data", "data.items", "query.results")
	MaxRecords int    // Maximum records to read (0 = unlimited)
	StreamMode bool   // Use streaming for large files
}

// DefaultJSONConfig returns sensible defaults
func DefaultJSONConfig() *JSONConfig {
	return &JSONConfig{
		RootPath:   "",
		MaxRecords: 0,
		StreamMode: false,
	}
}

// Common root paths for threat intel JSON feeds
var commonRootPaths = []string{
	"data",       // ThreatFox: {"query_status": "ok", "data": [...]}
	"items",      // Some feeds: {"items": [...]}
	"results",    // {"results": [...]}
	"iocs",       // {"iocs": [...]}
	"indicators", // {"indicators": [...]}
	"threats",    // {"threats": [...]}
	"records",    // {"records": [...]}
}

// =============================================================================
// JSON Reader Functions
// =============================================================================

// ReadJSON reads a JSON file and returns parsed data with content detection
func ReadJSON(filePath string, config *JSONConfig) (*JSONData, error) {
	if config == nil {
		config = DefaultJSONConfig()
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data := &JSONData{
		FilePath:       filePath,
		FileName:       filepath.Base(filePath),
		Records:        []map[string]interface{}{},
		Fields:         []string{},
		ContentSummary: make(map[ContentType]int),
		RootPath:       config.RootPath,
	}

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Trim whitespace
	trimmed := strings.TrimSpace(string(content))
	if len(trimmed) == 0 {
		data.Format = "empty"
		return data, nil
	}

	// Detect JSON format
	firstChar := trimmed[0]

	switch firstChar {
	case '[':
		// JSON Array
		data.Format = "array"
		err = parseJSONArray(trimmed, data, config)
	case '{':
		// JSON Object - could be single object or object containing array
		if strings.Contains(trimmed, "\n{") {
			// Likely NDJSON
			data.Format = "ndjson"
			err = parseNDJSON(filePath, data, config)
		} else {
			data.Format = "object"
			err = parseJSONObject(trimmed, data, config)
		}
	default:
		// Check if NDJSON
		data.Format = "ndjson"
		err = parseNDJSON(filePath, data, config)
	}

	if err != nil {
		return data, err
	}

	// Extract unique field names
	fieldSet := make(map[string]bool)
	for _, record := range data.Records {
		for k := range record {
			fieldSet[k] = true
		}
	}
	for field := range fieldSet {
		data.Fields = append(data.Fields, field)
	}

	// Analyze content and detect category
	analyzeJSONContent(data)
	data.DetectedCategory = detectJSONCategory(data)

	return data, nil
}

// parseJSONArray parses a JSON array of objects
func parseJSONArray(content string, data *JSONData, config *JSONConfig) error {
	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(content), &arr); err != nil {
		// Try as array of mixed types
		var mixedArr []interface{}
		if err2 := json.Unmarshal([]byte(content), &mixedArr); err2 != nil {
			return fmt.Errorf("failed to parse JSON array: %w", err)
		}

		// Convert to maps
		for i, item := range mixedArr {
			if config.MaxRecords > 0 && i >= config.MaxRecords {
				break
			}
			switch v := item.(type) {
			case map[string]interface{}:
				data.Records = append(data.Records, v)
			case string:
				// Simple string value
				data.Records = append(data.Records, map[string]interface{}{"value": v})
			default:
				data.Records = append(data.Records, map[string]interface{}{"value": fmt.Sprintf("%v", v)})
			}
		}
	} else {
		for i, record := range arr {
			if config.MaxRecords > 0 && i >= config.MaxRecords {
				break
			}
			data.Records = append(data.Records, record)
		}
	}

	data.TotalRecords = len(data.Records)
	return nil
}

// parseJSONObject parses a JSON object, extracting array from root path
func parseJSONObject(content string, data *JSONData, config *JSONConfig) error {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(content), &obj); err != nil {
		return fmt.Errorf("failed to parse JSON object: %w", err)
	}

	// If root path specified, use it
	if config.RootPath != "" {
		return extractFromPath(obj, config.RootPath, data, config)
	}

	// Try to auto-detect data array
	for _, path := range commonRootPaths {
		if val, ok := obj[path]; ok {
			if arr, isArray := val.([]interface{}); isArray {
				data.RootPath = path
				return convertInterfaceArray(arr, data, config)
			}
		}
	}

	// No array found, treat object itself as single record
	data.Records = append(data.Records, obj)
	data.TotalRecords = 1
	return nil
}

// extractFromPath extracts data from a nested path like "data.items"
func extractFromPath(obj map[string]interface{}, path string, data *JSONData, config *JSONConfig) error {
	parts := strings.Split(path, ".")
	current := interface{}(obj)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			if next, ok := v[part]; ok {
				current = next
			} else {
				return fmt.Errorf("path '%s' not found at '%s'", path, part)
			}
		default:
			return fmt.Errorf("cannot traverse path '%s' at '%s'", path, part)
		}
	}

	// Current should now be the array
	switch v := current.(type) {
	case []interface{}:
		return convertInterfaceArray(v, data, config)
	case map[string]interface{}:
		data.Records = append(data.Records, v)
		data.TotalRecords = 1
	default:
		return fmt.Errorf("path '%s' does not point to array or object", path)
	}

	return nil
}

// convertInterfaceArray converts []interface{} to records
func convertInterfaceArray(arr []interface{}, data *JSONData, config *JSONConfig) error {
	for i, item := range arr {
		if config.MaxRecords > 0 && i >= config.MaxRecords {
			break
		}
		switch v := item.(type) {
		case map[string]interface{}:
			data.Records = append(data.Records, v)
		case string:
			data.Records = append(data.Records, map[string]interface{}{"value": v})
		default:
			data.Records = append(data.Records, map[string]interface{}{"value": fmt.Sprintf("%v", v)})
		}
	}
	data.TotalRecords = len(data.Records)
	return nil
}

// parseNDJSON parses newline-delimited JSON
func parseNDJSON(filePath string, data *JSONData, config *JSONConfig) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lineNum++
		if config.MaxRecords > 0 && lineNum > config.MaxRecords {
			break
		}

		var record map[string]interface{}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			// Try as simple value
			var value interface{}
			if err2 := json.Unmarshal([]byte(line), &value); err2 != nil {
				continue // Skip malformed lines
			}
			record = map[string]interface{}{"value": value}
		}

		data.Records = append(data.Records, record)
	}

	data.TotalRecords = len(data.Records)
	return scanner.Err()
}

// analyzeJSONContent detects content types in all records
func analyzeJSONContent(data *JSONData) {
	for _, record := range data.Records {
		for _, val := range record {
			if strVal, ok := val.(string); ok {
				ct := detectContentType(strVal)
				data.ContentSummary[ct]++
			}
		}
	}
}

// detectJSONCategory determines the file category
func detectJSONCategory(data *JSONData) string {
	if len(data.Records) == 0 {
		return "empty"
	}

	// Check for IOC-specific fields
	hasIOCFields := false
	for _, record := range data.Records {
		for key := range record {
			keyLower := strings.ToLower(key)
			if strings.Contains(keyLower, "ioc") || strings.Contains(keyLower, "indicator") ||
				strings.Contains(keyLower, "threat") || strings.Contains(keyLower, "malware") {
				hasIOCFields = true
				break
			}
		}
		if hasIOCFields {
			break
		}
	}

	if hasIOCFields {
		return "ioc"
	}

	// Check content summary
	total := 0
	for _, count := range data.ContentSummary {
		total += count
	}
	if total == 0 {
		return "unknown"
	}

	ipCount := data.ContentSummary[ContentTypeIP] + data.ContentSummary[ContentTypeIPRange]
	domainCount := data.ContentSummary[ContentTypeDomain]
	urlCount := data.ContentSummary[ContentTypeURL]
	hashCount := data.ContentSummary[ContentTypeHash]

	threshold := float64(total) * 0.3

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

// GetFieldValues returns all values for a specific field across records
func (d *JSONData) GetFieldValues(fieldName string) []string {
	var values []string
	for _, record := range d.Records {
		if val, ok := record[fieldName]; ok {
			switch v := val.(type) {
			case string:
				values = append(values, v)
			default:
				values = append(values, fmt.Sprintf("%v", v))
			}
		}
	}
	return values
}

// GetIPs returns all detected IP values from records
func (d *JSONData) GetIPs() []string {
	var ips []string
	seen := make(map[string]bool)

	for _, record := range d.Records {
		for _, val := range record {
			if strVal, ok := val.(string); ok {
				ct := detectContentType(strVal)
				if (ct == ContentTypeIP || ct == ContentTypeIPRange) && !seen[strVal] {
					ips = append(ips, strVal)
					seen[strVal] = true
				}
			}
		}
	}
	return ips
}

// GetDomains returns all detected domain values from records
func (d *JSONData) GetDomains() []string {
	var domains []string
	seen := make(map[string]bool)

	for _, record := range d.Records {
		for _, val := range record {
			if strVal, ok := val.(string); ok {
				ct := detectContentType(strVal)
				if ct == ContentTypeDomain && !seen[strVal] {
					domains = append(domains, strVal)
					seen[strVal] = true
				}
			}
		}
	}
	return domains
}

// GetURLs returns all detected URL values from records
func (d *JSONData) GetURLs() []string {
	var urls []string
	seen := make(map[string]bool)

	for _, record := range d.Records {
		for _, val := range record {
			if strVal, ok := val.(string); ok {
				ct := detectContentType(strVal)
				if ct == ContentTypeURL && !seen[strVal] {
					urls = append(urls, strVal)
					seen[strVal] = true
				}
			}
		}
	}
	return urls
}

// GetHashes returns all detected hash values from records
func (d *JSONData) GetHashes() []string {
	var hashes []string
	seen := make(map[string]bool)

	for _, record := range d.Records {
		for _, val := range record {
			if strVal, ok := val.(string); ok {
				ct := detectContentType(strVal)
				if ct == ContentTypeHash && !seen[strVal] {
					hashes = append(hashes, strVal)
					seen[strVal] = true
				}
			}
		}
	}
	return hashes
}

// GetIOCs returns all IOC values (from common IOC field names)
func (d *JSONData) GetIOCs() []map[string]string {
	var iocs []map[string]string
	iocFields := []string{"ioc", "indicator", "value", "ioc_value", "indicator_value"}
	typeFields := []string{"ioc_type", "type", "indicator_type"}

	for _, record := range d.Records {
		ioc := map[string]string{}

		// Find IOC value
		for _, field := range iocFields {
			if val, ok := record[field]; ok {
				if strVal, isStr := val.(string); isStr && strVal != "" {
					ioc["value"] = strVal
					ioc["detected_type"] = string(detectContentType(strVal))
					break
				}
			}
		}

		// Find IOC type
		for _, field := range typeFields {
			if val, ok := record[field]; ok {
				if strVal, isStr := val.(string); isStr {
					ioc["type"] = strVal
					break
				}
			}
		}

		if ioc["value"] != "" {
			iocs = append(iocs, ioc)
		}
	}

	return iocs
}

// =============================================================================
// Test/Demo Function - Prints sample output when run directly
// =============================================================================

// TestJSONReader demonstrates JSON reader capabilities
func TestJSONReader() {
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println("JSON READER - Content Detection Demo")
	fmt.Println("=" + strings.Repeat("=", 79))

	// Test JSON formats
	fmt.Println("\n--- Testing JSON Format Detection ---")

	// Test 1: Simple array
	testArray := `[
		{"ip": "192.168.1.1", "type": "c2"},
		{"ip": "10.0.0.1", "type": "malware"}
	]`
	fmt.Println("\nTest 1: Simple Array")
	fmt.Printf("Input: %s\n", truncateJSON(testArray, 60))

	testFile1 := createTempJSON(testArray)
	if testFile1 != "" {
		defer os.Remove(testFile1)
		data, _ := ReadJSON(testFile1, nil)
		printJSONSummary(data)
	}

	// Test 2: Object with data array (ThreatFox format)
	testObject := `{
		"query_status": "ok",
		"data": [
			{"ioc": "malware.com", "ioc_type": "domain", "threat_type": "c2"},
			{"ioc": "1.2.3.4", "ioc_type": "ip", "threat_type": "botnet"}
		]
	}`
	fmt.Println("\nTest 2: Object with 'data' Array (ThreatFox format)")
	fmt.Printf("Input: %s\n", truncateJSON(testObject, 60))

	testFile2 := createTempJSON(testObject)
	if testFile2 != "" {
		defer os.Remove(testFile2)
		data, _ := ReadJSON(testFile2, nil)
		printJSONSummary(data)
	}

	// Test 3: Object with nested path
	testNested := `{
		"response": {
			"data": {
				"items": [
					{"hash": "d41d8cd98f00b204e9800998ecf8427e", "malware": "emotet"},
					{"hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "malware": "trickbot"}
				]
			}
		}
	}`
	fmt.Println("\nTest 3: Nested Object with Custom Path")
	fmt.Printf("Input: %s\n", truncateJSON(testNested, 60))

	testFile3 := createTempJSON(testNested)
	if testFile3 != "" {
		defer os.Remove(testFile3)
		config := DefaultJSONConfig()
		config.RootPath = "response.data.items"
		data, _ := ReadJSON(testFile3, config)
		printJSONSummary(data)
	}

	fmt.Println("\n--- Looking for JSON files in data/fetch/ ---")

	// Try to find and parse actual feed files
	basePath := "data/fetch"
	categories := []string{"ip", "domain", "hash", "ip_geo", "pending"}

	for _, cat := range categories {
		catPath := filepath.Join(basePath, cat)
		files, err := filepath.Glob(filepath.Join(catPath, "*.json"))
		if err != nil || len(files) == 0 {
			continue
		}

		fmt.Printf("\n[%s] Found %d JSON files\n", strings.ToUpper(cat), len(files))

		// Parse first file as demo
		if len(files) > 0 {
			config := DefaultJSONConfig()
			config.MaxRecords = 5 // Just sample first 5 records

			data, err := ReadJSON(files[0], config)
			if err != nil {
				fmt.Printf("  Error: %v\n", err)
				continue
			}

			fmt.Printf("  File: %s\n", data.FileName)
			fmt.Printf("  Format: %s\n", data.Format)
			fmt.Printf("  Root Path: %s\n", data.RootPath)
			fmt.Printf("  Detected Category: %s\n", data.DetectedCategory)
			fmt.Printf("  Total Records: %d\n", data.TotalRecords)
			fmt.Printf("  Fields: %v\n", data.Fields)

			// Show content summary
			fmt.Println("  Content Summary:")
			for ct, count := range data.ContentSummary {
				fmt.Printf("    %s: %d\n", ct, count)
			}

			// Show IPs/Domains found
			ips := data.GetIPs()
			domains := data.GetDomains()
			hashes := data.GetHashes()

			fmt.Printf("  Found: %d IPs, %d domains, %d hashes\n",
				len(ips), len(domains), len(hashes))

			// Show IOCs
			iocs := data.GetIOCs()
			if len(iocs) > 0 {
				fmt.Println("  Sample IOCs:")
				limit := 3
				if len(iocs) < limit {
					limit = len(iocs)
				}
				for i := 0; i < limit; i++ {
					fmt.Printf("    %v\n", iocs[i])
				}
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
}

func createTempJSON(content string) string {
	tmpFile, err := os.CreateTemp("", "test_*.json")
	if err != nil {
		return ""
	}
	defer tmpFile.Close()
	tmpFile.WriteString(content)
	return tmpFile.Name()
}

func truncateJSON(s string, maxLen int) string {
	// Remove newlines and extra spaces
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	s = strings.TrimSpace(s)

	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func printJSONSummary(data *JSONData) {
	fmt.Printf("  Format: %s, RootPath: %s, Records: %d\n",
		data.Format, data.RootPath, data.TotalRecords)
	fmt.Printf("  Category: %s, Fields: %v\n", data.DetectedCategory, data.Fields)

	if len(data.Records) > 0 {
		fmt.Println("  First record:")
		for k, v := range data.Records[0] {
			fmt.Printf("    %s: %v\n", k, v)
		}
	}
}
