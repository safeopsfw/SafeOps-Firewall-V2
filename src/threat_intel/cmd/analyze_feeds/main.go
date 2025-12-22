package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	basePath := filepath.Join(".", "data", "feeds")

	// Log file
	logPath := filepath.Join(".", "src", "parser", "file_format_analysis.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		log.Fatalf("Failed to create log: %v", err)
	}
	defer logFile.Close()

	logBoth := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		fmt.Println(msg)
		logFile.WriteString(msg + "\n")
	}

	logBoth(strings.Repeat("=", 120))
	logBoth("COMPREHENSIVE FILE FORMAT ANALYSIS - ALL 28 FILES")
	logBoth("Analysis Date: %s", time.Now().Format("2006-01-02 15:04:05"))
	logBoth("Purpose: Analyze EVERY file with 40 lines of content for parser development")
	logBoth(strings.Repeat("=", 120))

	categories := []string{"ip_blacklist", "ip_anonymization", "domain", "hash", "ioc", "ip_geo", "asn"}

	fileCount := 0
	formatStats := make(map[string]int)

	for _, category := range categories {
		categoryPath := filepath.Join(basePath, category)

		if _, err := os.Stat(categoryPath); os.IsNotExist(err) {
			continue
		}

		files, err := os.ReadDir(categoryPath)
		if err != nil {
			continue
		}

		if len(files) == 0 {
			continue
		}

		logBoth("\n")
		logBoth(strings.Repeat("█", 120))
		logBoth("CATEGORY: %s (%d files)", strings.ToUpper(category), len(files))
		logBoth(strings.Repeat("█", 120))

		for _, file := range files {
			if file.IsDir() || strings.HasPrefix(file.Name(), ".") {
				continue
			}

			filePath := filepath.Join(categoryPath, file.Name())
			info, _ := file.Info()

			fileCount++
			ext := strings.ToLower(filepath.Ext(file.Name()))
			formatStats[ext]++

			logBoth("\n")
			logBoth(strings.Repeat("=", 120))
			logBoth("FILE #%d", fileCount)
			logBoth(strings.Repeat("=", 120))
			logBoth("Name: %s", file.Name())
			logBoth("Path: %s", filePath)
			logBoth("Size: %d bytes (%.2f KB)", info.Size(), float64(info.Size())/1024)
			logBoth("Format: %s", ext)
			logBoth("Category: %s", category)

			// Read file content - handle gzip if needed
			var lines []string
			var totalLines int

			if strings.HasSuffix(file.Name(), ".gz") {
				lines, totalLines = readGzipFile(filePath, 40)
				logBoth("Compression: GZIP")
			} else {
				lines, totalLines = readTextFile(filePath, 40)
			}

			logBoth("Total Lines: %d", totalLines)
			logBoth("")
			logBoth("┌" + strings.Repeat("─", 118) + "┐")
			logBoth("│ FIRST 40 LINES OF RAW CONTENT" + strings.Repeat(" ", 86) + "│")
			logBoth("├" + strings.Repeat("─", 118) + "┤")

			for i, line := range lines {
				displayLine := line
				if len(displayLine) > 110 {
					displayLine = displayLine[:110] + "..."
				}
				// Escape special characters for display
				displayLine = strings.ReplaceAll(displayLine, "\t", "→")
				logBoth("│ %02d: %-112s │", i+1, displayLine)
			}

			logBoth("└" + strings.Repeat("─", 118) + "┘")

			// Format-specific analysis
			logBoth("")
			logBoth("┌" + strings.Repeat("─", 118) + "┐")
			logBoth("│ FORMAT ANALYSIS" + strings.Repeat(" ", 101) + "│")
			logBoth("├" + strings.Repeat("─", 118) + "┤")

			analyzeFormat(logBoth, ext, lines, category)

			logBoth("└" + strings.Repeat("─", 118) + "┘")
		}
	}

	// Summary
	logBoth("\n")
	logBoth(strings.Repeat("=", 120))
	logBoth("FINAL SUMMARY")
	logBoth(strings.Repeat("=", 120))
	logBoth("Total files analyzed: %d", fileCount)
	logBoth("")
	logBoth("Files by format:")
	for ext, count := range formatStats {
		logBoth("  %s: %d files", ext, count)
	}
	logBoth("")
	logBoth("Log saved to: %s", logPath)
	logBoth(strings.Repeat("=", 120))

	fmt.Printf("\n✅ Analysis complete! %d files analyzed.\n", fileCount)
	fmt.Printf("📄 Full log: %s\n", logPath)
}

func readTextFile(path string, maxLines int) ([]string, int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 2*1024*1024)

	for scanner.Scan() && len(lines) < maxLines {
		lines = append(lines, scanner.Text())
	}

	// Count remaining
	totalLines := len(lines)
	for scanner.Scan() {
		totalLines++
	}

	return lines, totalLines
}

func readGzipFile(path string, maxLines int) ([]string, int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return []string{"[ERROR: Cannot decompress gzip file]"}, 0
	}
	defer gr.Close()

	var lines []string
	reader := bufio.NewReader(gr)
	totalLines := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			break
		}
		line = strings.TrimSuffix(line, "\n")
		totalLines++
		if len(lines) < maxLines {
			lines = append(lines, line)
		}
		if err == io.EOF {
			break
		}
	}

	return lines, totalLines
}

func analyzeFormat(logBoth func(string, ...interface{}), ext string, lines []string, category string) {
	if len(lines) == 0 {
		logBoth("│ %-116s │", "ERROR: No content to analyze")
		return
	}

	// Find first non-comment, non-empty line
	var firstDataLine string
	var headerLine string
	commentCount := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, ";") {
			commentCount++
			// Check for header in comments
			if strings.Contains(trimmed, ",") && i < 10 {
				headerLine = trimmed
			}
			continue
		}
		if firstDataLine == "" {
			firstDataLine = trimmed
		}
		break
	}

	logBoth("│ %-116s │", fmt.Sprintf("Comment lines at start: %d", commentCount))

	switch ext {
	case ".csv":
		logBoth("│ %-116s │", "Format Type: CSV (Comma-Separated Values)")

		// Detect delimiter
		delimiter := ","
		delimName := "COMMA"
		if strings.Count(firstDataLine, "\t") > strings.Count(firstDataLine, ",") {
			delimiter = "\t"
			delimName = "TAB"
		} else if strings.Count(firstDataLine, ";") > strings.Count(firstDataLine, ",") {
			delimiter = ";"
			delimName = "SEMICOLON"
		}
		logBoth("│ %-116s │", fmt.Sprintf("Delimiter: %s", delimName))

		// Parse columns
		var cols []string
		if delimiter == "\t" {
			cols = strings.Split(firstDataLine, "\t")
		} else {
			cols = parseCSVLine(firstDataLine)
		}
		logBoth("│ %-116s │", fmt.Sprintf("Column count: %d", len(cols)))

		// Show header if found
		if headerLine != "" {
			logBoth("│ %-116s │", "Header (from comments):")
			hdr := strings.TrimPrefix(headerLine, "# ")
			logBoth("│   %-114s │", truncate(hdr, 110))
		}

		// Show sample values
		logBoth("│ %-116s │", "Sample values from first data row:")
		for i, col := range cols {
			if i >= 8 {
				logBoth("│   %-114s │", fmt.Sprintf("... (%d more columns)", len(cols)-8))
				break
			}
			logBoth("│   %-114s │", fmt.Sprintf("[%d] %s", i, truncate(strings.TrimSpace(col), 100)))
		}

	case ".json":
		logBoth("│ %-116s │", "Format Type: JSON")

		content := strings.Join(lines, "")
		if strings.HasPrefix(strings.TrimSpace(content), "[") {
			logBoth("│ %-116s │", "Structure: ROOT ARRAY")
		} else if strings.HasPrefix(strings.TrimSpace(content), "{") {
			logBoth("│ %-116s │", "Structure: ROOT OBJECT (keyed)")
		}

		// Detect fields
		fields := []string{"ioc_value", "ioc_type", "threat_type", "malware", "confidence_level",
			"first_seen", "last_seen", "reporter", "tags", "reference"}
		found := []string{}
		for _, f := range fields {
			if strings.Contains(content, "\""+f+"\"") {
				found = append(found, f)
			}
		}
		if len(found) > 0 {
			logBoth("│ %-116s │", fmt.Sprintf("Detected fields: %s", strings.Join(found, ", ")))
		}

	case ".txt":
		logBoth("│ %-116s │", "Format Type: Plain Text")

		// Check structure
		if strings.Contains(firstDataLine, "\t") {
			parts := strings.Split(firstDataLine, "\t")
			logBoth("│ %-116s │", fmt.Sprintf("Delimiter: TAB (%d columns)", len(parts)))
		} else if strings.Contains(firstDataLine, ",") && !strings.HasPrefix(firstDataLine, "http") {
			parts := strings.Split(firstDataLine, ",")
			logBoth("│ %-116s │", fmt.Sprintf("Delimiter: COMMA (%d columns)", len(parts)))
		} else if strings.Contains(firstDataLine, " ") && !strings.HasPrefix(firstDataLine, "http") {
			parts := strings.Fields(firstDataLine)
			logBoth("│ %-116s │", fmt.Sprintf("Delimiter: SPACE (%d fields)", len(parts)))
		} else {
			logBoth("│ %-116s │", "Delimiter: NONE (single value per line)")
		}

		// Content type detection
		if isIPv4(firstDataLine) {
			logBoth("│ %-116s │", "Content: IPv4 ADDRESSES")
		} else if strings.HasPrefix(firstDataLine, "ExitAddress") {
			logBoth("│ %-116s │", "Content: TOR EXIT NODE FORMAT")
		} else if strings.HasPrefix(firstDataLine, "http") {
			logBoth("│ %-116s │", "Content: URLs")
		} else if strings.Contains(firstDataLine, "/") && strings.Contains(firstDataLine, ".") {
			logBoth("│ %-116s │", "Content: CIDR RANGES")
		} else if isDomain(firstDataLine) {
			logBoth("│ %-116s │", "Content: DOMAIN NAMES")
		} else {
			logBoth("│ %-116s │", "Content: MIXED/STRUCTURED")
		}

	case ".tsv":
		logBoth("│ %-116s │", "Format Type: TSV (Tab-Separated Values)")
		parts := strings.Split(firstDataLine, "\t")
		logBoth("│ %-116s │", fmt.Sprintf("Column count: %d", len(parts)))

		logBoth("│ %-116s │", "Sample columns:")
		for i, p := range parts {
			if i >= 6 {
				break
			}
			logBoth("│   %-114s │", fmt.Sprintf("[%d] %s", i, truncate(p, 100)))
		}

	default:
		logBoth("│ %-116s │", fmt.Sprintf("Unknown format: %s", ext))
	}

	// Parser requirements
	logBoth("│ %-116s │", "")
	logBoth("│ %-116s │", "PARSER EXTRACTION TARGETS:")
	switch category {
	case "ip_blacklist":
		logBoth("│   %-114s │", "→ ip_address (REQUIRED)")
		logBoth("│   %-114s │", "→ port, threat_type, first_seen, description (optional)")
	case "ip_anonymization":
		logBoth("│   %-114s │", "→ ip_address (REQUIRED), service_type: tor/vpn/proxy")
		logBoth("│   %-114s │", "→ port, country (optional)")
	case "domain":
		logBoth("│   %-114s │", "→ domain or url (REQUIRED)")
		logBoth("│   %-114s │", "→ threat_type, target, first_seen (optional)")
	case "hash":
		logBoth("│   %-114s │", "→ hash_value, hash_type: md5/sha1/sha256 (REQUIRED)")
		logBoth("│   %-114s │", "→ malware_family, first_seen (optional)")
	case "ioc":
		logBoth("│   %-114s │", "→ ioc_value, ioc_type (REQUIRED)")
		logBoth("│   %-114s │", "→ confidence, tags, reference (optional)")
	case "ip_geo", "asn":
		logBoth("│   %-114s │", "→ ip_range/CIDR, asn_number, country_code (REQUIRED)")
		logBoth("│   %-114s │", "→ asn_name (optional)")
	}
}

func parseCSVLine(line string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				current.WriteRune(r)
			} else {
				result = append(result, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	result = append(result, current.String())
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func isIPv4(s string) bool {
	s = strings.TrimSpace(s)
	// Handle CIDR notation
	if idx := strings.Index(s, "/"); idx > 0 {
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func isDomain(s string) bool {
	s = strings.TrimSpace(s)
	return strings.Contains(s, ".") && !strings.Contains(s, "/") && !isIPv4(s) && !strings.Contains(s, " ")
}
