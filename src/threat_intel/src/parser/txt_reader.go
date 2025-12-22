package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// TXTReader handles line-by-line text file reading
type TXTReader struct {
	commentChars []string // Comment indicators (default: ["#", "//", ";"])
	skipEmpty    bool     // Skip empty lines (default: true)
	trimSpaces   bool     // Trim whitespace (default: true)
	delimiter    string   // Optional delimiter for multi-column text
}

// TXTConfig provides optional configuration for TXT reading behavior
type TXTConfig struct {
	CommentChars []string // Comment line indicators (default ["#", "//", ";"])
	SkipEmpty    bool     // Skip blank lines (default: true)
	TrimSpaces   bool     // Trim leading/trailing whitespace (default: true)
	Delimiter    string   // Field separator for multi-column files (space, tab, etc.)
	HasHeaders   bool     // First non-comment line is header (rare for TXT files)
}

// NewTXTReader creates a TXT reader with default settings
func NewTXTReader() *TXTReader {
	return &TXTReader{
		commentChars: []string{"#", "//", ";"},
		skipEmpty:    true,
		trimSpaces:   true,
		delimiter:    "", // Single column by default
	}
}

// Read is the main entry point to read a TXT file
func (r *TXTReader) Read(filePath string, config *TXTConfig) ParsedData {
	result := ParsedData{
		FileName:   filepath.Base(filePath),
		FilePath:   filePath,
		Format:     "txt",
		ReadErrors: []error{},
		Success:    false,
		Data:       []map[string]interface{}{},
	}

	// Apply configuration
	if config != nil {
		if len(config.CommentChars) > 0 {
			r.commentChars = config.CommentChars
		}
		r.skipEmpty = config.SkipEmpty
		r.trimSpaces = config.TrimSpaces
		r.delimiter = config.Delimiter
	}

	// STEP 1: Open File
	file, err := os.Open(filePath)
	if err != nil {
		result.ReadErrors = append(result.ReadErrors, fmt.Errorf("failed to open file: %w", err))
		return result
	}
	defer file.Close()

	// STEP 2: Create Scanner
	scanner := bufio.NewScanner(file)

	// Set buffer size for large lines (URLs can be very long)
	const maxCapacity = 512 * 1024 // 512KB per line
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	// STEP 3: Process Line by Line
	var data []map[string]interface{}
	var headers []string
	lineNumber := 0
	dataLineCount := 0

	for scanner.Scan() {
		lineNumber++
		rawLine := scanner.Text()

		// Step 3a: Trim whitespace
		line := rawLine
		if r.trimSpaces {
			line = strings.TrimSpace(rawLine)
		}

		// Step 3b: Skip empty lines
		if r.skipEmpty && line == "" {
			continue
		}

		// Step 3c: Skip comment lines
		if r.isCommentLine(line) {
			continue
		}

		// Step 3d: Parse line based on delimiter
		if r.delimiter == "" {
			// Simple: One value per line
			record := map[string]interface{}{
				"line":        line,
				"line_number": lineNumber,
			}
			data = append(data, record)
			dataLineCount++
		} else {
			// Multi-column: Split by delimiter
			fields := r.splitDelimitedLine(line, r.delimiter)

			// First non-comment line as headers
			if config != nil && config.HasHeaders && dataLineCount == 0 {
				headers = fields
				continue
			}

			// Build record from fields
			record := make(map[string]interface{})
			record["line_number"] = lineNumber

			for i, field := range fields {
				var key string
				if len(headers) > i {
					key = headers[i]
				} else {
					key = fmt.Sprintf("col_%d", i)
				}
				record[key] = field
			}

			data = append(data, record)
			dataLineCount++
		}
	}

	// STEP 4: Check Scanner Errors
	if err := scanner.Err(); err != nil {
		result.ReadErrors = append(result.ReadErrors, fmt.Errorf("scanner error: %w", err))
		return result
	}

	// STEP 5: Return Results
	if r.delimiter == "" {
		result.Headers = []string{"line", "line_number"}
	} else if len(headers) > 0 {
		result.Headers = headers
	} else {
		result.Headers = []string{} // Will be auto-generated (col_0, col_1, etc.)
	}

	result.Data = data
	result.RowCount = len(data)
	result.Success = true

	return result
}

// ReadLines is a simple helper to read all lines as string array
func (r *TXTReader) ReadLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	// Set buffer size for large lines
	const maxCapacity = 512 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Text()

		if r.trimSpaces {
			line = strings.TrimSpace(line)
		}

		// Skip empty lines and comments
		if r.skipEmpty && line == "" {
			continue
		}
		if r.isCommentLine(line) {
			continue
		}

		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return lines, nil
}

// ExtractPattern uses regex to extract patterns from a line
func (r *TXTReader) ExtractPattern(line string, pattern string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid regex pattern: %w", err)
	}

	match := re.FindString(line)
	return match, nil
}

// ExtractIPv4 extracts IPv4 address from a line
func (r *TXTReader) ExtractIPv4(line string) string {
	// IPv4 pattern: \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b
	ipv4Pattern := `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
	match, _ := r.ExtractPattern(line, ipv4Pattern)
	return match
}

// ExtractDomain extracts domain from a line
func (r *TXTReader) ExtractDomain(line string) string {
	// Domain pattern: \b[a-z0-9.-]+\.[a-z]{2,}\b
	domainPattern := `\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\b`
	match, _ := r.ExtractPattern(line, domainPattern)
	return match
}

// ExtractSHA256 extracts SHA256 hash from a line
func (r *TXTReader) ExtractSHA256(line string) string {
	// SHA256 pattern: 64 hexadecimal characters
	sha256Pattern := `\b[a-fA-F0-9]{64}\b`
	match, _ := r.ExtractPattern(line, sha256Pattern)
	return match
}

// splitDelimitedLine splits a line by delimiter
func (r *TXTReader) splitDelimitedLine(line string, delimiter string) []string {
	if delimiter == "" || delimiter == " " {
		// Split on any whitespace and collapse multiple spaces
		return strings.Fields(line)
	}

	// Split by specific delimiter
	fields := strings.Split(line, delimiter)

	// Trim spaces from each field
	if r.trimSpaces {
		for i, field := range fields {
			fields[i] = strings.TrimSpace(field)
		}
	}

	return fields
}

// isCommentLine checks if a line is a comment
func (r *TXTReader) isCommentLine(line string) bool {
	if line == "" {
		return false
	}

	for _, commentChar := range r.commentChars {
		if strings.HasPrefix(line, commentChar) {
			return true
		}
	}

	return false
}

// DetectLinePattern detects common patterns in the file
func (r *TXTReader) DetectLinePattern(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "unknown", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	linesSampled := 0
	maxSamples := 100

	ipCount := 0
	domainCount := 0
	hashCount := 0
	urlCount := 0

	for scanner.Scan() && linesSampled < maxSamples {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || r.isCommentLine(line) {
			continue
		}

		linesSampled++

		// Check patterns
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			urlCount++
		} else if matched, _ := regexp.MatchString(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`, line); matched {
			ipCount++
		} else if matched, _ := regexp.MatchString(`^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$`, line); matched {
			hashCount++
		} else if matched, _ := regexp.MatchString(`^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$`, line); matched {
			domainCount++
		}
	}

	// Determine predominant pattern
	if urlCount > linesSampled/2 {
		return "url", nil
	} else if ipCount > linesSampled/2 {
		return "ip", nil
	} else if hashCount > linesSampled/2 {
		return "hash", nil
	} else if domainCount > linesSampled/2 {
		return "domain", nil
	}

	return "mixed", nil
}
