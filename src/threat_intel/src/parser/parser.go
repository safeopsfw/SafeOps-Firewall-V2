package parser

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Parser is the main orchestrator for file reading operations
// It detects file formats and delegates to appropriate readers
type Parser struct {
	csvReader  *CSVReader
	jsonReader *JSONReader
	txtReader  *TXTReader
	logger     *log.Logger
}

// FileInfo represents metadata about a file without reading it
type FileInfo struct {
	Size      int64  // File size in bytes
	Modified  string // Last modified timestamp
	Extension string // File extension
	Format    string // Detected format
	Readable  bool   // Whether file can be opened
}

// NewParser creates a parser with all readers initialized
func NewParser() *Parser {
	return &Parser{
		csvReader:  NewCSVReader(),
		jsonReader: NewJSONReader(),
		txtReader:  NewTXTReader(),
		logger:     log.New(os.Stdout, "[PARSER] ", log.LstdFlags),
	}
}

// ParseFile is the main entry point to read any file format
// It detects format and delegates to appropriate reader
func (p *Parser) ParseFile(filePath string) ParsedData {
	// STEP 1: Check file exists
	if _, err := os.Stat(filePath); err != nil {
		p.logger.Printf("File not found or inaccessible: %s", filePath)
		return ParsedData{
			FileName:   filepath.Base(filePath),
			FilePath:   filePath,
			Success:    false,
			ReadErrors: []error{fmt.Errorf("file not found: %w", err)},
		}
	}

	// STEP 2: Detect format
	format := p.DetectFormat(filePath)
	p.logger.Printf("Detected format '%s' for file: %s", format, filepath.Base(filePath))

	// STEP 3: Delegate to appropriate reader
	var result ParsedData

	switch format {
	case "csv":
		result = p.csvReader.Read(filePath, nil)

	case "tsv":
		config := &CSVConfig{
			Delimiter: '\t',
			HasHeader: false,
		}
		result = p.csvReader.Read(filePath, config)

	case "json":
		result = p.jsonReader.Read(filePath, nil)

	case "txt":
		result = p.txtReader.Read(filePath, nil)

	default:
		// Default to TXT for unknown formats
		p.logger.Printf("Unknown format, defaulting to TXT: %s", filePath)
		result = p.txtReader.Read(filePath, nil)
	}

	// STEP 4: Return ParsedData
	return result
}

// DetectFormat auto-detects file format from extension or content
func (p *Parser) DetectFormat(filePath string) string {
	// STEP 1: Try extension first
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".csv":
		return "csv"
	case ".json":
		return "json"
	case ".txt":
		return "txt"
	case ".tsv":
		return "tsv"
	}

	// STEP 2: If no extension, peek at content
	file, err := os.Open(filePath)
	if err != nil {
		p.logger.Printf("Cannot open file for format detection: %s", err)
		return "txt" // Default to txt
	}
	defer file.Close()

	// Read first 512 bytes
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && n == 0 {
		return "txt"
	}

	content := string(buf[:n])
	contentTrimmed := strings.TrimSpace(content)

	// STEP 3: Detect patterns
	// JSON: First non-whitespace is { or [
	if len(contentTrimmed) > 0 {
		firstChar := contentTrimmed[0]
		if firstChar == '{' || firstChar == '[' {
			return "json"
		}
	}

	// TSV: Contains tabs
	if strings.Contains(content, "\t") {
		return "tsv"
	}

	// CSV: Contains commas (but not in first line if it's a comment)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ",") {
			return "csv"
		}
		break // Only check first non-comment line
	}

	// STEP 4: Default to TXT
	return "txt"
}

// ParseDirectory reads all files in a directory
func (p *Parser) ParseDirectory(dirPath string, recursive bool) []ParsedData {
	results := []ParsedData{}

	// Walk directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			p.logger.Printf("Error accessing path %s: %v", path, err)
			return nil // Continue walking
		}

		// Skip directories
		if info.IsDir() {
			if !recursive && path != dirPath {
				return filepath.SkipDir
			}
			return nil
		}

		// Filter to relevant extensions
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".csv" || ext == ".json" || ext == ".txt" || ext == ".tsv" {
			result := p.ParseFile(path)
			results = append(results, result)
		}

		return nil
	})

	if err != nil {
		p.logger.Printf("Error walking directory %s: %v", dirPath, err)
	}

	// Log summary
	successCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		}
	}
	p.logger.Printf("Parsed %d files: %d successful, %d failed",
		len(results), successCount, len(results)-successCount)

	return results
}

// GetFileInfo returns metadata about file without reading it
func (p *Parser) GetFileInfo(filePath string) FileInfo {
	info := FileInfo{
		Extension: filepath.Ext(filePath),
		Readable:  false,
	}

	// Get file stats
	stat, err := os.Stat(filePath)
	if err != nil {
		p.logger.Printf("Cannot stat file: %s", err)
		return info
	}

	info.Size = stat.Size()
	info.Modified = stat.ModTime().Format("2006-01-02 15:04:05")
	info.Format = p.DetectFormat(filePath)

	// Check if readable
	file, err := os.Open(filePath)
	if err == nil {
		info.Readable = true
		file.Close()
	}

	return info
}

// ParseFileWithConfig parses file with custom configurations
func (p *Parser) ParseFileWithConfig(filePath string, csvConfig *CSVConfig, jsonConfig *JSONConfig, txtConfig *TXTConfig) ParsedData {
	format := p.DetectFormat(filePath)

	switch format {
	case "csv", "tsv":
		return p.csvReader.Read(filePath, csvConfig)
	case "json":
		return p.jsonReader.Read(filePath, jsonConfig)
	case "txt":
		return p.txtReader.Read(filePath, txtConfig)
	default:
		return p.txtReader.Read(filePath, txtConfig)
	}
}

// ValidateFileExists checks if file exists and is readable
func (p *Parser) ValidateFileExists(filePath string) error {
	stat, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file does not exist: %w", err)
	}

	if stat.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", filePath)
	}

	// Try to open
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("file is not readable: %w", err)
	}
	file.Close()

	return nil
}

// GetSupportedFormats returns list of supported file formats
func (p *Parser) GetSupportedFormats() []string {
	return []string{"csv", "tsv", "json", "txt"}
}
