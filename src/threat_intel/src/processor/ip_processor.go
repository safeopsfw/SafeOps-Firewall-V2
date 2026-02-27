package processor

import (
	"fmt"

	"threat_intel/src/storage"
)

// =============================================================================
// IP Processor
// Processes ip/ folder -> ip_blacklist + ip_anonymization tables
// Uses smart reconciliation: upsert current, remove stale per-feed
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
			if p.config.DeleteAfter {
				p.deleteFile(filePath)
				result.DeletedFiles++
			}
			continue
		}

		result.FilesProcessed++
		source := getSourceFromFilename(filePath)
		category := getCategoryFromFilename(filePath)
		priority := p.getPriority(source)

		// Use parser's GetAllIPs helper
		ips := parsed.GetAllIPs()
		result.RowsRead += len(ips)

		if len(ips) > 0 {
			// Route to correct storage based on category
			switch category {
			case "tor":
				inserted, err := anonStore.BulkInsertTorNodes(ctx, ips, source)
				if err != nil {
					p.logger.Printf("    Tor insert error: %v\n", err)
				} else {
					result.RowsInserted += inserted
					p.logger.Printf("    Inserted %d Tor exit nodes\n", inserted)
				}
			case "vpn":
				inserted, err := anonStore.BulkInsertVPNs(ctx, ips, source, source)
				if err != nil {
					p.logger.Printf("    VPN insert error: %v\n", err)
				} else {
					result.RowsInserted += inserted
					p.logger.Printf("    Inserted %d VPN IPs\n", inserted)
				}
			case "proxy":
				inserted, err := anonStore.BulkInsertProxies(ctx, ips, "http", source)
				if err != nil {
					p.logger.Printf("    Proxy insert error: %v\n", err)
				} else {
					result.RowsInserted += inserted
					p.logger.Printf("    Inserted %d proxy IPs\n", inserted)
				}
			default:
				// Smart reconciliation for IP blacklist
				reconcileResult, err := ipStore.Reconcile(ctx, source, ips, priority)
				if err != nil {
					p.logger.Printf("    Reconcile error: %v\n", err)
				} else {
					result.RowsInserted += reconcileResult.Updated
					p.logger.Printf("    Reconciled: upserted=%d, removed=%d (priority=%d, feed=%s)\n",
						reconcileResult.Updated, reconcileResult.Removed, priority, source)
				}
			}
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
