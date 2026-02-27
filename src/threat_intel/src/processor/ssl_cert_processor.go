package processor

import (
	"fmt"
	"strings"

	"threat_intel/src/parser"
	"threat_intel/src/storage"
)

// =============================================================================
// SSL Certificate Processor
// Processes ssl_cert/ folder -> ssl_certificates table
// Parses abuse.ch SSLBL CSV format: Listingdate,SHA1,Listingreason
// Uses smart reconciliation: upsert current, remove stale per-feed
// =============================================================================

// ProcessSSLCertFolder processes all files in the ssl_cert folder
func (p *Processor) ProcessSSLCertFolder() (*Result, error) {
	result := &Result{}

	files, err := p.getFilesInFolder("ssl_cert")
	if err != nil {
		return result, err
	}

	if len(files) == 0 {
		p.logger.Println("  No SSL Certificate files to process")
		return result, nil
	}

	sslStore := storage.NewSSLCertStorage(p.db)
	ctx := getContext()

	for _, filePath := range files {
		p.logger.Printf("  Processing: %s\n", filePath)

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

		// Extract SSL cert records from parsed CSV data
		certs := extractSSLCerts(parsed)
		result.RowsRead += len(certs)

		if len(certs) > 0 {
			reconcileResult, err := sslStore.Reconcile(ctx, source, certs, priority)
			if err != nil {
				p.logger.Printf("    Reconcile error: %v\n", err)
			} else {
				result.RowsInserted += reconcileResult.Updated
				p.logger.Printf("    Reconciled: upserted=%d, removed=%d (priority=%d, feed=%s)\n",
					reconcileResult.Updated, reconcileResult.Removed, priority, source)
			}
		} else {
			p.logger.Printf("    No valid SSL certificates found\n")
		}

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

// extractSSLCerts extracts SSL certificate records from parsed data.
// Handles abuse.ch SSLBL CSV format: Listingdate,SHA1,Listingreason
// Also handles TXT format (one SHA1 per line) as fallback.
func extractSSLCerts(parsed *parser.ParseResult) []storage.SSLCertRecord {
	var certs []storage.SSLCertRecord
	seen := make(map[string]bool)

	// CSV format (abuse.ch SSLBL: Listingdate,SHA1,Listingreason)
	if parsed.CSVData != nil {
		for _, rec := range parsed.CSVData.Records {
			sha1 := findField(rec.Fields, "SHA1", "sha1", "sha1_fingerprint", "fingerprint")
			if sha1 == "" {
				// Try raw fields — column index 1 is SHA1 in SSLBL
				if len(rec.RawFields) >= 2 {
					sha1 = rec.RawFields[1]
				}
			}
			sha1 = strings.ToLower(strings.TrimSpace(sha1))
			if len(sha1) != 40 {
				continue
			}
			if seen[sha1] {
				continue
			}
			seen[sha1] = true

			reason := findField(rec.Fields, "Listingreason", "listing_reason", "reason", "Reason")
			if reason == "" && len(rec.RawFields) >= 3 {
				reason = strings.TrimSpace(rec.RawFields[2])
			}
			certs = append(certs, storage.SSLCertRecord{
				SHA1Fingerprint: sha1,
				ListingReason:   reason,
			})
		}
		return certs
	}

	// TXT fallback — one SHA1 per line (from GetAllHashes)
	for _, h := range parsed.GetAllHashes() {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) != 40 || seen[h] {
			continue
		}
		seen[h] = true
		certs = append(certs, storage.SSLCertRecord{
			SHA1Fingerprint: h,
		})
	}
	return certs
}

// findField tries multiple column name variations
func findField(row map[string]string, names ...string) string {
	for _, name := range names {
		if v, ok := row[name]; ok && v != "" {
			return v
		}
	}
	return ""
}
