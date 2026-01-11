package processor

import (
	"fmt"
	"strings"

	"threat_intel/src/storage"
)

// =============================================================================
// Hash Processor
// Processes hash/ folder -> hashes table
// For: malware hashes (MD5, SHA1, SHA256)
// =============================================================================

// ProcessHashFolder processes all files in the hash folder
func (p *Processor) ProcessHashFolder() (*Result, error) {
	result := &Result{}

	files, err := p.getFilesInFolder("hash")
	if err != nil {
		return result, err
	}

	if len(files) == 0 {
		p.logger.Println("  No Hash files to process")
		return result, nil
	}

	hashStore := storage.NewHashStorage(p.db)
	ctx := getContext()
	batchSize := p.config.BatchSize

	for _, filePath := range files {
		p.logger.Printf("  Processing: %s\n", filePath)

		// Parse file
		parsed, err := p.parseFile(filePath)
		if err != nil {
			p.logger.Printf("    Error parsing: %v\n", err)
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filePath, err))
			continue
		}

		result.FilesProcessed++
		source := getSourceFromFilename(filePath)
		malwareFamily := getCategoryFromFilename(filePath)

		// Try to extract hashes from CSV data directly
		var hashes []string
		var hashType string = "sha256"

		if parsed.CSVData != nil {
			p.logger.Printf("    CSV detected with %d records\n", len(parsed.CSVData.Records))

			// Find sha256 or md5 column
			sha256Col := -1
			md5Col := -1
			for i, col := range parsed.CSVData.Columns {
				lowerName := strings.ToLower(col.Name)
				if strings.Contains(lowerName, "sha256") {
					sha256Col = i
				} else if strings.Contains(lowerName, "md5") {
					md5Col = i
				}
			}

			p.logger.Printf("    SHA256 col: %d, MD5 col: %d\n", sha256Col, md5Col)

			// Extract hashes from the appropriate column
			for _, rec := range parsed.CSVData.Records {
				var hash string
				if sha256Col >= 0 && sha256Col < len(rec.RawFields) {
					hash = strings.Trim(rec.RawFields[sha256Col], `" `)
					hashType = "sha256"
				} else if md5Col >= 0 && md5Col < len(rec.RawFields) {
					hash = strings.Trim(rec.RawFields[md5Col], `" `)
					hashType = "md5"
				}

				// Validate hash
				hash = strings.TrimSpace(hash)
				if isValidHash(hash, 64) || isValidHash(hash, 32) {
					hashes = append(hashes, strings.ToLower(hash))
				}
			}
		}

		// Fallback: use parser's GetAllHashes
		if len(hashes) == 0 {
			hashes = parsed.GetAllHashes()
			if len(hashes) > 0 {
				switch len(hashes[0]) {
				case 32:
					hashType = "md5"
				case 40:
					hashType = "sha1"
				case 64:
					hashType = "sha256"
				}
			}
		}

		result.RowsRead += len(hashes)

		if len(hashes) == 0 {
			p.logger.Printf("    No valid hashes found\n")
			continue
		}

		p.logger.Printf("    Found %d hashes (type: %s)\n", len(hashes), hashType)

		// Batch insert hashes
		var totalInserted int64
		for i := 0; i < len(hashes); i += batchSize {
			end := i + batchSize
			if end > len(hashes) {
				end = len(hashes)
			}
			batch := hashes[i:end]

			// BulkInsert takes: (ctx, hashes []string, hashType string, source string, malwareFamily string)
			inserted, err := hashStore.BulkInsert(ctx, batch, hashType, source, malwareFamily)
			if err != nil {
				p.logger.Printf("    Batch insert error: %v\n", err)
			} else {
				totalInserted += inserted
			}
		}

		result.RowsInserted += totalInserted
		p.logger.Printf("    Inserted %d hashes\n", totalInserted)

		// Delete file after processing
		if p.config.DeleteAfter {
			if err := p.deleteFile(filePath); err != nil {
				p.logger.Printf("    Error deleting file: %v\n", err)
			} else {
				result.DeletedFiles++
			}
		}
	}

	return result, nil
}

// isValidHash checks if a string is a valid hex hash of expected length
func isValidHash(s string, expectedLen int) bool {
	s = strings.TrimSpace(s)
	if len(s) != expectedLen {
		return false
	}

	s = strings.ToLower(s)
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
