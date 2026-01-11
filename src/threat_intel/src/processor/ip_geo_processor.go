package processor

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"threat_intel/src/storage"
)

// =============================================================================
// IP Geo Processor
// Processes ip_geo/ folder -> ip_geolocation table
// For: IP to Country/ASN mapping data
// =============================================================================

// ProcessGeoFolder processes all files in the ip_geo folder
func (p *Processor) ProcessGeoFolder() (*Result, error) {
	result := &Result{}

	files, err := p.getFilesInFolder("ip_geo")
	if err != nil {
		return result, err
	}

	if len(files) == 0 {
		p.logger.Println("  No IP Geo files to process")
		return result, nil
	}

	geoStore := storage.NewIPGeoStorage(p.db)
	_ = geoStore // Used in sub-functions

	for _, filePath := range files {
		p.logger.Printf("  Processing: %s\n", filePath)

		source := getSourceFromFilename(filePath)
		lowerPath := strings.ToLower(filePath)

		var inserted int64
		var processErr error

		// Different processing based on file type
		if strings.Contains(lowerPath, "iptoasn") {
			inserted, processErr = p.processIPtoASN(filePath, geoStore, source)
		} else if strings.Contains(lowerPath, "ip2location") {
			inserted, processErr = p.processIP2Location(filePath, geoStore, source)
		} else if strings.Contains(lowerPath, "geolite2") || strings.Contains(lowerPath, "ipinfo") {
			inserted, processErr = p.processGeoLite(filePath, geoStore, source)
		} else {
			// Generic geo processing
			inserted, processErr = p.processGenericGeo(filePath, geoStore, source)
		}

		result.FilesProcessed++

		if processErr != nil {
			p.logger.Printf("    Error: %v\n", processErr)
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filePath, processErr))
		} else {
			result.RowsInserted += inserted
			p.logger.Printf("    Inserted %d geo records\n", inserted)
		}

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

// processIPtoASN handles iptoasn.tsv format
func (p *Processor) processIPtoASN(filePath string, store *storage.IPGeoStorage, source string) (int64, error) {
	parsed, err := p.parseFile(filePath)
	if err != nil {
		return 0, err
	}

	ctx := getContext()
	now := time.Now()

	var records []storage.IPGeoRecord
	batchSize := p.config.BatchSize
	var totalInserted int64

	// Use parser's GetAllIPs and extract additional data
	ips := parsed.GetAllIPs()

	for i, ip := range ips {
		records = append(records, storage.IPGeoRecord{
			IPAddress:   ip,
			Sources:     []string{source},
			Confidence:  50,
			LastUpdated: now,
			CreatedAt:   now,
		})

		if len(records) >= batchSize {
			inserted, err := store.BulkInsertIPRanges(ctx, records, source)
			if err != nil {
				return totalInserted, err
			}
			totalInserted += inserted
			records = records[:0]

			// Progress log every 10000
			if i > 0 && i%10000 == 0 {
				p.logger.Printf("    Progress: %d/%d IPs\n", i, len(ips))
			}
		}
	}

	if len(records) > 0 {
		inserted, err := store.BulkInsertIPRanges(ctx, records, source)
		if err != nil {
			return totalInserted, err
		}
		totalInserted += inserted
	}

	return totalInserted, nil
}

// processIP2Location handles IP2Location LITE DB1 format
func (p *Processor) processIP2Location(filePath string, store *storage.IPGeoStorage, source string) (int64, error) {
	parsed, err := p.parseFile(filePath)
	if err != nil {
		return 0, err
	}

	ctx := getContext()
	now := time.Now()

	var records []storage.IPGeoRecord
	batchSize := p.config.BatchSize
	var totalInserted int64

	// IP2Location uses CSV with numeric IPs
	if parsed.CSVData != nil {
		for i, rec := range parsed.CSVData.Records {
			row := rec.RawFields
			if len(row) < 4 {
				continue
			}

			// Convert numeric IP to string
			ipFrom := numericToIP(row[0])
			if ipFrom == "" {
				continue
			}

			countryCode := ""
			countryName := ""
			if len(row) > 2 {
				countryCode = row[2]
			}
			if len(row) > 3 {
				countryName = row[3]
			}

			records = append(records, storage.IPGeoRecord{
				IPAddress:   ipFrom,
				CountryCode: countryCode,
				CountryName: countryName,
				Sources:     []string{source},
				Confidence:  60,
				LastUpdated: now,
				CreatedAt:   now,
			})

			if len(records) >= batchSize {
				inserted, err := store.BulkInsertIPRanges(ctx, records, source)
				if err != nil {
					return totalInserted, err
				}
				totalInserted += inserted
				records = records[:0]

				if i > 0 && i%10000 == 0 {
					p.logger.Printf("    Progress: %d rows\n", i)
				}
			}
		}
	}

	if len(records) > 0 {
		inserted, err := store.BulkInsertIPRanges(ctx, records, source)
		if err != nil {
			return totalInserted, err
		}
		totalInserted += inserted
	}

	return totalInserted, nil
}

// processGeoLite handles GeoLite2/IPInfo TSV format
func (p *Processor) processGeoLite(filePath string, store *storage.IPGeoStorage, source string) (int64, error) {
	parsed, err := p.parseFile(filePath)
	if err != nil {
		return 0, err
	}

	ctx := getContext()
	now := time.Now()

	var records []storage.IPGeoRecord
	batchSize := p.config.BatchSize
	var totalInserted int64

	// Use parsed IPs directly
	ips := parsed.GetAllIPs()

	for i, ip := range ips {
		// Extract IP from CIDR if present
		cleanIP := ip
		if strings.Contains(ip, "/") {
			cleanIP = strings.Split(ip, "/")[0]
		}

		records = append(records, storage.IPGeoRecord{
			IPAddress:   cleanIP,
			Sources:     []string{source},
			Confidence:  70,
			LastUpdated: now,
			CreatedAt:   now,
		})

		if len(records) >= batchSize {
			inserted, err := store.BulkInsertIPRanges(ctx, records, source)
			if err != nil {
				return totalInserted, err
			}
			totalInserted += inserted
			records = records[:0]

			if i > 0 && i%10000 == 0 {
				p.logger.Printf("    Progress: %d/%d IPs\n", i, len(ips))
			}
		}
	}

	if len(records) > 0 {
		inserted, err := store.BulkInsertIPRanges(ctx, records, source)
		if err != nil {
			return totalInserted, err
		}
		totalInserted += inserted
	}

	return totalInserted, nil
}

// processGenericGeo handles unknown geo file formats
func (p *Processor) processGenericGeo(filePath string, store *storage.IPGeoStorage, source string) (int64, error) {
	parsed, err := p.parseFile(filePath)
	if err != nil {
		return 0, err
	}

	ctx := getContext()
	now := time.Now()

	var records []storage.IPGeoRecord
	batchSize := p.config.BatchSize
	var totalInserted int64

	ips := parsed.GetAllIPs()

	for _, ip := range ips {
		cleanIP := ip
		if strings.Contains(ip, "/") {
			cleanIP = strings.Split(ip, "/")[0]
		}

		records = append(records, storage.IPGeoRecord{
			IPAddress:   cleanIP,
			Sources:     []string{source},
			Confidence:  50,
			LastUpdated: now,
			CreatedAt:   now,
		})

		if len(records) >= batchSize {
			inserted, err := store.BulkInsertIPRanges(ctx, records, source)
			if err != nil {
				return totalInserted, err
			}
			totalInserted += inserted
			records = records[:0]
		}
	}

	if len(records) > 0 {
		inserted, err := store.BulkInsertIPRanges(ctx, records, source)
		if err != nil {
			return totalInserted, err
		}
		totalInserted += inserted
	}

	return totalInserted, nil
}

// numericToIP converts numeric IP (from IP2Location) to dotted string
func numericToIP(numStr string) string {
	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%d.%d.%d.%d",
		(num>>24)&255,
		(num>>16)&255,
		(num>>8)&255,
		num&255)
}
