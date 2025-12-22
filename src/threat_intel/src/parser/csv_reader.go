package parser

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CSVReader handles CSV/TSV file reading with configurable options
type CSVReader struct {
	delimiter  rune
	hasHeader  bool
	skipRows   int
	trimSpaces bool
	comment    rune
}

// CSVConfig provides optional configuration for CSV reading behavior
type CSVConfig struct {
	Delimiter         rune // Field separator character (,, \t, ;, |)
	HasHeader         bool // First row contains column names
	SkipRows          int  // Rows to skip before reading
	TrimSpaces        bool // Trim whitespace from field values
	Comment           rune // Comment indicator (lines starting with this are skipped)
	LazyQuotes        bool // Allow malformed quotes (lenient parsing)
	SkipCommentHeader bool // Automatically skip comment lines before header detection
}

// ParsedData represents the result of reading a CSV/TSV file
type ParsedData struct {
	FileName   string                   // Base filename
	FilePath   string                   // Full file path
	Format     string                   // "csv" or "tsv"
	RowCount   int                      // Number of data rows
	Headers    []string                 // Column names
	Data       []map[string]interface{} // Raw data as array of maps
	ReadErrors []error                  // Any errors encountered during reading
	Success    bool                     // Overall success status
}

// NewCSVReader creates a CSV reader with default settings
func NewCSVReader() *CSVReader {
	return &CSVReader{
		delimiter:  ',',
		hasHeader:  true,
		skipRows:   0,
		trimSpaces: true,
		comment:    '#',
	}
}

// Read is the main entry point to read a CSV/TSV file
func (r *CSVReader) Read(filePath string, config *CSVConfig) ParsedData {
	result := ParsedData{
		FileName:   filepath.Base(filePath),
		FilePath:   filePath,
		ReadErrors: []error{},
		Success:    false,
	}

	// STEP 1: Open File
	file, err := os.Open(filePath)
	if err != nil {
		result.ReadErrors = append(result.ReadErrors, fmt.Errorf("failed to open file: %w", err))
		return result
	}
	defer file.Close()

	// Apply config or use defaults
	delimiter := r.delimiter
	hasHeader := r.hasHeader
	skipRows := r.skipRows
	trimSpaces := r.trimSpaces
	comment := r.comment
	lazyQuotes := false

	if config != nil {
		if config.Delimiter != 0 {
			delimiter = config.Delimiter
		}
		hasHeader = config.HasHeader
		skipRows = config.SkipRows
		trimSpaces = config.TrimSpaces
		if config.Comment != 0 {
			comment = config.Comment
		}
		lazyQuotes = config.LazyQuotes
	}

	// Set format based on delimiter
	if delimiter == '\t' {
		result.Format = "tsv"
	} else {
		result.Format = "csv"
	}

	// STEP 2: Skip Comment Header Block (if configured)
	// This handles feeds with metadata comments before the actual CSV data
	if config != nil && config.SkipCommentHeader && comment != 0 {
		skipped, err := r.skipCommentBlock(file, comment)
		if err != nil {
			result.ReadErrors = append(result.ReadErrors, fmt.Errorf("error skipping comment block: %w", err))
		}
		if skipped > 0 {
			// Successfully skipped comment lines, continue with CSV parsing
			_ = skipped // Comment lines were skipped
		}
	}

	// STEP 3: Create CSV Reader
	csvReader := csv.NewReader(file)
	csvReader.Comma = delimiter
	csvReader.Comment = comment
	csvReader.TrimLeadingSpace = trimSpaces
	csvReader.LazyQuotes = lazyQuotes
	csvReader.ReuseRecord = true // Memory efficiency

	// STEP 4: Skip Rows (if configured)
	for i := 0; i < skipRows; i++ {
		_, err := csvReader.Read()
		if err != nil {
			result.ReadErrors = append(result.ReadErrors, fmt.Errorf("error skipping row %d: %w", i, err))
			return result
		}
	}

	// STEP 5: Read Header Row
	var headers []string
	if hasHeader {
		headerRow, err := csvReader.Read()
		if err != nil {
			result.ReadErrors = append(result.ReadErrors, fmt.Errorf("failed to read header: %w", err))
			return result
		}
		headers = r.NormalizeHeaders(headerRow)
	} else {
		// Generate headers if no header row
		// We'll need to read first row to know column count
		firstRow, err := csvReader.Read()
		if err != nil {
			result.ReadErrors = append(result.ReadErrors, fmt.Errorf("failed to read first row: %w", err))
			return result
		}
		headers = make([]string, len(firstRow))
		for i := range firstRow {
			headers[i] = fmt.Sprintf("col_%d", i)
		}
		// We'll need to process this first row as data later
		// Store it temporarily
		result.Data = []map[string]interface{}{r.buildRecord(headers, firstRow, trimSpaces)}
	}

	result.Headers = headers

	// STEP 6: Read All Data Rows
	if result.Data == nil {
		result.Data = []map[string]interface{}{}
	}
	rowNumber := skipRows + 1
	if hasHeader {
		rowNumber++
	}

	for {
		fields, err := csvReader.Read()

		// If EOF, break loop
		if err == io.EOF {
			break
		}

		// If error, log and continue
		if err != nil {
			result.ReadErrors = append(result.ReadErrors, fmt.Errorf("error reading row %d: %w", rowNumber, err))
			rowNumber++
			continue
		}

		// Check field count
		if len(fields) != len(headers) {
			result.ReadErrors = append(result.ReadErrors, fmt.Errorf("row %d has %d fields, expected %d", rowNumber, len(fields), len(headers)))
			// In lenient mode, we'll pad or truncate
			if len(fields) < len(headers) {
				// Pad with empty strings
				for i := len(fields); i < len(headers); i++ {
					fields = append(fields, "")
				}
			} else {
				// Truncate extra fields
				fields = fields[:len(headers)]
			}
		}

		// Build map from row
		record := r.buildRecord(headers, fields, trimSpaces)
		result.Data = append(result.Data, record)
		rowNumber++
	}

	// STEP 7: Return Results
	result.RowCount = len(result.Data)
	result.Success = true

	return result
}

// buildRecord creates a map from headers and field values
func (r *CSVReader) buildRecord(headers []string, fields []string, trimSpaces bool) map[string]interface{} {
	record := make(map[string]interface{})
	for i := 0; i < len(headers) && i < len(fields); i++ {
		fieldValue := fields[i]
		if trimSpaces {
			fieldValue = strings.TrimSpace(fieldValue)
		}
		record[headers[i]] = fieldValue
	}
	return record
}

// ReadWithDelimiter is a helper to read files with a specific delimiter
func (r *CSVReader) ReadWithDelimiter(filePath string, delimiter rune) ParsedData {
	config := &CSVConfig{
		Delimiter:  delimiter,
		HasHeader:  r.hasHeader,
		SkipRows:   r.skipRows,
		TrimSpaces: r.trimSpaces,
		Comment:    r.comment,
		LazyQuotes: false,
	}
	return r.Read(filePath, config)
}

// DetectDelimiter auto-detects delimiter by sampling file
func (r *CSVReader) DetectDelimiter(filePath string) rune {
	file, err := os.Open(filePath)
	if err != nil {
		return ',' // Default to comma on error
	}
	defer file.Close()

	// Read first 1000 bytes or 5 rows
	buffer := make([]byte, 1000)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return ',' // Default to comma on error
	}

	sample := string(buffer[:n])

	// Count delimiter occurrences
	delimiters := map[rune]int{
		',':  strings.Count(sample, ","),
		'\t': strings.Count(sample, "\t"),
		';':  strings.Count(sample, ";"),
		'|':  strings.Count(sample, "|"),
	}

	// Find most common delimiter
	maxCount := 0
	detectedDelimiter := ','
	for delim, count := range delimiters {
		if count > maxCount {
			maxCount = count
			detectedDelimiter = delim
		}
	}

	return detectedDelimiter
}

// skipCommentBlock skips comment lines at the beginning of the file
// Returns the number of comment lines skipped
func (r *CSVReader) skipCommentBlock(file *os.File, commentChar rune) (int, error) {
	// Save current position
	startPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	scanner := strings.NewReader("")
	buffer := make([]byte, 0, 4096)
	skippedLines := 0

	// Read file line by line
	for {
		// Read one byte at a time to detect newlines
		b := make([]byte, 1)
		n, err := file.Read(b)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			break
		}

		buffer = append(buffer, b[0])

		// Check if we have a complete line
		if b[0] == '\n' || b[0] == '\r' {
			line := strings.TrimSpace(string(buffer))

			// Skip empty lines
			if line == "" {
				buffer = buffer[:0]
				continue
			}

			// Check if line starts with comment character
			if len(line) > 0 && rune(line[0]) == commentChar {
				skippedLines++
				buffer = buffer[:0]
				continue
			}

			// Non-comment line found, rewind to start of this line
			currentPos, _ := file.Seek(0, io.SeekCurrent)
			file.Seek(currentPos-int64(len(buffer)), io.SeekStart)
			return skippedLines, nil
		}
	}

	// If we reach EOF, reset to start position
	file.Seek(startPos, io.SeekStart)
	_ = scanner
	return skippedLines, nil
}

// NormalizeHeaders cleans and standardizes header names
func (r *CSVReader) NormalizeHeaders(headers []string) []string {
	normalized := make([]string, len(headers))
	seen := make(map[string]int)

	for i, header := range headers {
		// 1. Trim whitespace
		cleaned := strings.TrimSpace(header)

		// 2. Lowercase
		cleaned = strings.ToLower(cleaned)

		// 3. Replace spaces with underscores
		cleaned = strings.ReplaceAll(cleaned, " ", "_")

		// 4. Remove special characters (keep alphanumeric and underscore)
		var result strings.Builder
		for _, ch := range cleaned {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' {
				result.WriteRune(ch)
			}
		}
		cleaned = result.String()

		// Remove leading/trailing underscores
		cleaned = strings.Trim(cleaned, "_")

		// Handle empty header
		if cleaned == "" {
			cleaned = fmt.Sprintf("col_%d", i)
		}

		// 5. Handle duplicates
		if count, exists := seen[cleaned]; exists {
			seen[cleaned] = count + 1
			cleaned = fmt.Sprintf("%s_%d", cleaned, count+1)
		} else {
			seen[cleaned] = 0
		}

		normalized[i] = cleaned
	}

	return normalized
}
