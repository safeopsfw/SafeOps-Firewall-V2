package processor

import (
	"fmt"

	"threat_intel/src/storage"
)

// =============================================================================
// Domain Processor
// Processes domain/ folder -> domains table
// Uses smart reconciliation: upsert current, remove stale per-feed
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

	for _, filePath := range files {
		p.logger.Printf("  Processing: %s\n", filePath)

		// Parse file
		parsed, err := p.parseFile(filePath)
		if err != nil {
			p.logger.Printf("    Error parsing: %v\n", err)
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filePath, err))
			if p.config.DeleteAfter {
				p.deleteFile(filePath)
				result.DeletedFiles++
			}
			continue
		}

		result.FilesProcessed++
		source := getSourceFromFilename(filePath)
		priority := p.getPriority(source)

		// Use parser's GetAllDomains helper
		domains := parsed.GetAllDomains()
		result.RowsRead += len(domains)

		if len(domains) > 0 {
			// Smart reconciliation for domains
			reconcileResult, err := domainStore.Reconcile(ctx, source, domains, priority)
			if err != nil {
				p.logger.Printf("    Reconcile error: %v\n", err)
			} else {
				result.RowsInserted += reconcileResult.Updated
				p.logger.Printf("    Reconciled: upserted=%d, removed=%d (priority=%d, feed=%s)\n",
					reconcileResult.Updated, reconcileResult.Removed, priority, source)
			}
		} else {
			p.logger.Printf("    No valid domains found\n")
		}

		// Always delete file after processing
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
