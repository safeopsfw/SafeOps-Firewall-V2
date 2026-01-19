package processor

import (
	"fmt"

	"threat_intel/src/storage"
)

// =============================================================================
// IP Processor
// Processes ip/ folder -> ip_blacklist + ip_anonymization tables
// For: malware, abuse, vpn, tor, proxy, blacklist IPs
// =============================================================================

// ProcessIPFolder processes all files in the ip folder
func (p *Processor) ProcessIPFolder() (*Result, error) {
	result := &Result{}

	files, err := p.getFilesInFolder("ip")
	if err != nil {
		return result, err
	}

	if len(files) == 0 {
		p.logger.Println("  No IP files to process")
		return result, nil
	}

	ipStore := storage.NewIPBlacklistStorage(p.db)
	anonStore := storage.NewIPAnonymizationStorage(p.db)
	ctx := getContext()

	for _, filePath := range files {
		p.logger.Printf("  Processing: %s\n", filePath)

		// Parse file using parser
		parsed, err := p.parseFile(filePath)
		if err != nil {
			p.logger.Printf("    Error parsing: %v\n", err)
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filePath, err))
			// Still delete failed files
			if p.config.DeleteAfter {
				p.deleteFile(filePath)
				result.DeletedFiles++
			}
			continue
		}

		result.FilesProcessed++
		source := getSourceFromFilename(filePath)
		category := getCategoryFromFilename(filePath)

		// Use parser's GetAllIPs helper
		ips := parsed.GetAllIPs()
		result.RowsRead += len(ips)

		if len(ips) > 0 {
			// Batch IPs
			batchSize := p.config.BatchSize
			var totalInserted int64

			for i := 0; i < len(ips); i += batchSize {
				end := i + batchSize
				if end > len(ips) {
					end = len(ips)
				}
				batch := ips[i:end]

				var inserted int64
				var insertErr error

				// Route to correct storage based on category
				switch category {
				case "tor":
					inserted, insertErr = anonStore.BulkInsertTorNodes(ctx, batch, source)
				case "vpn":
					inserted, insertErr = anonStore.BulkInsertVPNs(ctx, batch, source, source)
				case "proxy":
					inserted, insertErr = anonStore.BulkInsertProxies(ctx, batch, "http", source)
				default:
					// Use IP Blacklist for malware, abuse, etc.
					inserted, insertErr = ipStore.BulkInsert(ctx, batch, source, category)
				}

				if insertErr != nil {
					p.logger.Printf("    Batch insert error: %v\n", insertErr)
				} else {
					totalInserted += inserted
				}
			}

			result.RowsInserted += totalInserted
			p.logger.Printf("    Inserted %d IPs (category: %s)\n", totalInserted, category)
		} else {
			p.logger.Printf("    No valid IPs found\n")
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
