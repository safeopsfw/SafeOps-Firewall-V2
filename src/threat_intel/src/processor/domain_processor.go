package processor

import (
	"fmt"

	"threat_intel/src/storage"
)

// =============================================================================
// Domain Processor
// Processes domain/ folder -> domains table
// For: phishing, malware, spam domains
// =============================================================================

// ProcessDomainFolder processes all files in the domain folder
func (p *Processor) ProcessDomainFolder() (*Result, error) {
	result := &Result{}

	files, err := p.getFilesInFolder("domain")
	if err != nil {
		return result, err
	}

	if len(files) == 0 {
		p.logger.Println("  No Domain files to process")
		return result, nil
	}

	domainStore := storage.NewDomainStorage(p.db)
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
		category := getCategoryFromFilename(filePath)

		// Use parser's GetAllDomains helper
		domains := parsed.GetAllDomains()
		result.RowsRead += len(domains)

		if len(domains) == 0 {
			p.logger.Printf("    No valid domains found\n")
			continue
		}

		// Batch insert domains
		var totalInserted int64
		for i := 0; i < len(domains); i += batchSize {
			end := i + batchSize
			if end > len(domains) {
				end = len(domains)
			}
			batch := domains[i:end]

			// BulkInsert takes: (ctx, domains []string, source string, category string)
			inserted, err := domainStore.BulkInsert(ctx, batch, source, category)
			if err != nil {
				p.logger.Printf("    Batch insert error: %v\n", err)
			} else {
				totalInserted += inserted
			}
		}

		result.RowsInserted += totalInserted
		p.logger.Printf("    Inserted %d domains (category: %s)\n", totalInserted, category)

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
