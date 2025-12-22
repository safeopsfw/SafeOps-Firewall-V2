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

// JSONReader handles JSON file reading with support for various JSON structures
type JSONReader struct {
	rootPath        string            // Path to nested data (e.g., "data.indicators")
	fieldMappings   map[string]string // Field name mappings (e.g., "ip_addr" -> "ip_address")
	maxFileSizeMB   int               // Maximum file size in MB
	streamThreshold int               // File size threshold for streaming mode in MB
}

// JSONConfig provides optional configuration for JSON reading behavior
type JSONConfig struct {
	RootPath        string            // Path to nested data (e.g., "data.items")
	FieldMappings   map[string]string // Field name remapping
	MaxFileSizeMB   int               // Maximum file size in MB (default 100)
	StreamThreshold int               // Threshold for streaming mode in MB (default 50)
	FlattenNested   bool              // Flatten nested objects with dot notation
}

// JSONStructure represents the type of JSON structure detected
type JSONStructure int

const (
	JSONStructureUnknown JSONStructure = iota
	JSONStructureArray                 // Top-level array: [...]
	JSONStructureObject                // Top-level object: {...}
	JSONStructureNDJSON                // Newline-delimited JSON
)

// NewJSONReader creates a JSON reader with default settings
func NewJSONReader() *JSONReader {
	return &JSONReader{
		rootPath:        "",
		fieldMappings:   make(map[string]string),
		maxFileSizeMB:   100,
		streamThreshold: 50,
	}
}

// Read is the main entry point to read a JSON file
func (r *JSONReader) Read(filePath string, config *JSONConfig) ParsedData {
	result := ParsedData{
		FileName:   filepath.Base(filePath),
		FilePath:   filePath,
		Format:     "json",
		ReadErrors: []error{},
		Success:    false,
		Data:       []map[string]interface{}{},
	}

	// Apply configuration
	if config != nil {
		if config.RootPath != "" {
			r.rootPath = config.RootPath
		}
		if config.FieldMappings != nil {
			r.fieldMappings = config.FieldMappings
		}
		if config.MaxFileSizeMB > 0 {
			r.maxFileSizeMB = config.MaxFileSizeMB
		}
		if config.StreamThreshold > 0 {
			r.streamThreshold = config.StreamThreshold
		}
	}

	// STEP 1: Validate file
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		result.ReadErrors = append(result.ReadErrors, fmt.Errorf("failed to stat file: %w", err))
		return result
	}

	fileSizeMB := int(fileInfo.Size() / (1024 * 1024))

	// Check file size limit
	if fileSizeMB > r.maxFileSizeMB {
		result.ReadErrors = append(result.ReadErrors, fmt.Errorf("file size %dMB exceeds limit %dMB", fileSizeMB, r.maxFileSizeMB))
		return result
	}

	// STEP 2: Choose reading strategy based on file size
	var data []map[string]interface{}
	if fileSizeMB > r.streamThreshold {
		// Use streaming for large files
		data, err = r.readStream(filePath, config)
	} else {
		// Load entire file for smaller files
		data, err = r.readFile(filePath, config)
	}

	if err != nil {
		result.ReadErrors = append(result.ReadErrors, err)
		return result
	}

	result.Data = data
	result.RowCount = len(data)
	result.Success = true

	return result
}

// readFile reads entire JSON file into memory
func (r *JSONReader) readFile(filePath string, config *JSONConfig) ([]map[string]interface{}, error) {
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read all content
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse JSON
	var parsed interface{}
	if err := json.Unmarshal(content, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Extract records based on structure
	return r.extractRecords(parsed, config)
}

// readStream reads JSON file using streaming for large files
func (r *JSONReader) readStream(filePath string, config *JSONConfig) ([]map[string]interface{}, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var records []map[string]interface{}

	// Try newline-delimited JSON first
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record map[string]interface{}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			// Not NDJSON, fall back to standard JSON decoder
			file.Seek(0, io.SeekStart)
			return r.readFileWithDecoder(file, config)
		}

		// Apply field mappings
		record = r.applyFieldMappings(record)
		records = append(records, record)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return records, nil
}

// readFileWithDecoder uses json.Decoder for streaming standard JSON
func (r *JSONReader) readFileWithDecoder(file *os.File, config *JSONConfig) ([]map[string]interface{}, error) {
	decoder := json.NewDecoder(file)

	// Read first token to detect structure
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON token: %w", err)
	}

	var records []map[string]interface{}

	// Check if it's an array
	if delim, ok := token.(json.Delim); ok && delim == '[' {
		// It's an array, decode each element
		for decoder.More() {
			var record map[string]interface{}
			if err := decoder.Decode(&record); err != nil {
				return nil, fmt.Errorf("failed to decode array element: %w", err)
			}
			record = r.applyFieldMappings(record)
			records = append(records, record)
		}
	} else {
		// It's a single object, rewind and decode
		file.Seek(0, io.SeekStart)
		var parsed interface{}
		decoder = json.NewDecoder(file)
		if err := decoder.Decode(&parsed); err != nil {
			return nil, fmt.Errorf("failed to decode JSON: %w", err)
		}
		return r.extractRecords(parsed, config)
	}

	return records, nil
}

// extractRecords extracts records from parsed JSON structure
func (r *JSONReader) extractRecords(parsed interface{}, config *JSONConfig) ([]map[string]interface{}, error) {
	// Navigate to nested path if specified
	if r.rootPath != "" {
		navigated, err := r.navigateToPath(parsed, r.rootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to navigate to path '%s': %w", r.rootPath, err)
		}
		parsed = navigated
	}

	var records []map[string]interface{}

	// Check structure type
	switch v := parsed.(type) {
	case []interface{}:
		// Array of objects
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				obj = r.applyFieldMappings(obj)
				if config != nil && config.FlattenNested {
					obj = r.flattenObject(obj, "")
				}
				records = append(records, obj)
			}
		}
	case map[string]interface{}:
		// Single object
		obj := r.applyFieldMappings(v)
		if config != nil && config.FlattenNested {
			obj = r.flattenObject(obj, "")
		}
		records = append(records, obj)
	default:
		return nil, fmt.Errorf("unsupported JSON structure: expected array or object")
	}

	return records, nil
}

// navigateToPath navigates to a nested JSON path (e.g., "data.indicators")
func (r *JSONReader) navigateToPath(data interface{}, path string) (interface{}, error) {
	if path == "" {
		return data, nil
	}

	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		if obj, ok := current.(map[string]interface{}); ok {
			if val, exists := obj[part]; exists {
				current = val
			} else {
				return nil, fmt.Errorf("path element '%s' not found", part)
			}
		} else {
			return nil, fmt.Errorf("cannot navigate to '%s': not an object", part)
		}
	}

	return current, nil
}

// flattenObject flattens nested objects with dot notation keys
func (r *JSONReader) flattenObject(obj map[string]interface{}, prefix string) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range obj {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]interface{}:
			// Recursively flatten nested objects
			flattened := r.flattenObject(v, fullKey)
			for k, val := range flattened {
				result[k] = val
			}
		case []interface{}:
			// Convert arrays to JSON string
			jsonBytes, _ := json.Marshal(v)
			result[fullKey] = string(jsonBytes)
		default:
			// Keep primitive values as-is
			result[fullKey] = value
		}
	}

	return result
}

// applyFieldMappings applies field name mappings to a record
func (r *JSONReader) applyFieldMappings(record map[string]interface{}) map[string]interface{} {
	if len(r.fieldMappings) == 0 {
		return record
	}

	result := make(map[string]interface{})
	for key, value := range record {
		// Check if there's a mapping for this field
		if mappedKey, exists := r.fieldMappings[key]; exists {
			result[mappedKey] = value
		} else {
			result[key] = value
		}
	}

	return result
}

// DetectStructure detects the JSON structure type
func (r *JSONReader) DetectStructure(filePath string) (JSONStructure, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return JSONStructureUnknown, err
	}
	defer file.Close()

	// Read first 1KB to detect structure
	buffer := make([]byte, 1024)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return JSONStructureUnknown, err
	}

	content := strings.TrimSpace(string(buffer[:n]))

	// Check for newline-delimited JSON
	if strings.Contains(content, "\n{") {
		return JSONStructureNDJSON, nil
	}

	// Check first character
	if len(content) > 0 {
		switch content[0] {
		case '[':
			return JSONStructureArray, nil
		case '{':
			return JSONStructureObject, nil
		}
	}

	return JSONStructureUnknown, nil
}
