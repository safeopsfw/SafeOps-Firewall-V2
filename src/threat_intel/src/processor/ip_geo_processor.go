package processor

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"threat_intel/src/parser"
	"threat_intel/src/storage"
)

// IPGeoProcessor handles IP geolocation data processing
type IPGeoProcessor struct {
	parser    *parser.Parser
	validator *Validator
	storage   *storage.DB
	logger    *log.Logger
	batchSize int
}

// IPGeoRecord represents a validated geolocation record
type IPGeoRecord struct {
	IPAddress   string
	CountryCode string
	CountryName string
	Region      string
	City        string
	Latitude    float64
	Longitude   float64
	PostalCode  string
	Timezone    string
	ISP         string
	Org         string
	ASN         int
	Valid       bool
	Error       string
}

// ProcessingResult contains results from processing a batch
type ProcessingResult struct {
	TotalRecords     int
	ValidRecords     int
	InvalidRecords   int
	DuplicateRecords int
	InsertedRecords  int
	UpdatedRecords   int
	ErrorRecords     int
	Duration         time.Duration
	ValidationErrors []string
	Success          bool
	SourceFile       string
}

// NewIPGeoProcessor creates a new IP geolocation processor
func NewIPGeoProcessor(db *storage.DB) *IPGeoProcessor {
	return &IPGeoProcessor{
		parser:    parser.NewParser(),
		validator: NewValidator(),
		storage:   db,
		logger:    log.New(os.Stdout, "[IP-GEO] ", log.LstdFlags),
		batchSize: 1000,
	}
}

// ProcessFile processes a single geolocation file
func (p *IPGeoProcessor) ProcessFile(filePath string, sourceName string) ProcessingResult {
	startTime := time.Now()
	result := ProcessingResult{
		SourceFile:       filePath,
		ValidationErrors: []string{},
	}

	p.logger.Printf("Processing file: %s (source: %s)", filePath, sourceName)

	// STAGE 1: Parse File
	parsedData := p.parser.ParseFile(filePath)
	if !parsedData.Success {
		result.ValidationErrors = append(result.ValidationErrors, "Failed to parse file")
		result.Duration = time.Since(startTime)
		return result
	}

	result.TotalRecords = len(parsedData.Data)
	p.logger.Printf("Parsed %d records from file", result.TotalRecords)

	// STAGE 2: Validate Records
	validRecords := make([]IPGeoRecord, 0, result.TotalRecords)

	for i, rawRecord := range parsedData.Data {
		record, err := p.validateRecord(rawRecord)
		if err != nil {
			result.InvalidRecords++
			if len(result.ValidationErrors) < 100 { // Limit error log size
				result.ValidationErrors = append(result.ValidationErrors,
					fmt.Sprintf("Row %d: %s", i+1, err.Error()))
			}
			continue
		}

		validRecords = append(validRecords, record)
		result.ValidRecords++
	}

	p.logger.Printf("Validation: %d valid, %d invalid", result.ValidRecords, result.InvalidRecords)

	// STAGE 3: Insert into Database (batch)
	if len(validRecords) > 0 {
		inserted, updated, errors := p.insertBatch(validRecords, sourceName)
		result.InsertedRecords = inserted
		result.UpdatedRecords = updated
		result.ErrorRecords = errors
	}

	result.Duration = time.Since(startTime)
	result.Success = result.ErrorRecords == 0 && result.ValidRecords > 0

	p.logger.Printf("Completed: %d inserted, %d updated, %d errors in %v",
		result.InsertedRecords, result.UpdatedRecords, result.ErrorRecords, result.Duration)

	return result
}

// ProcessDirectory processes all geolocation files in a directory
func (p *IPGeoProcessor) ProcessDirectory(dirPath string) []ProcessingResult {
	results := make([]ProcessingResult, 0)

	parsedFiles := p.parser.ParseDirectory(dirPath, false)

	for _, parsed := range parsedFiles {
		if parsed.Success {
			result := p.ProcessFile(parsed.FilePath, "directory")
			results = append(results, result)
		}
	}

	return results
}

// validateRecord validates a single raw record
func (p *IPGeoProcessor) validateRecord(raw map[string]interface{}) (IPGeoRecord, error) {
	record := IPGeoRecord{}

	// Try standard field names first, then IPtoASN TSV format (col_0, col_1, etc.)
	// IPtoASN format: col_0=ip_from, col_1=ip_to, col_2=asn, col_3=country, col_4=asn_org
	ipStr := p.getStringField(raw, "ip_address", "ip", "network", "ip_from", "col_0")
	if ipStr == "" {
		return record, fmt.Errorf("missing required field: ip_address")
	}

	ip, err := p.validator.ValidateIP(ipStr)
	if err != nil {
		return record, err
	}
	record.IPAddress = ip.String()

	// Extract country code (required) - try standard names then col_3 for IPtoASN
	countryCode := p.getStringField(raw, "country_code", "cc", "country", "col_3")
	if countryCode == "" {
		return record, fmt.Errorf("missing required field: country_code")
	}

	normalizedCode, err := p.validator.ValidateCountryCode(countryCode)
	if err != nil {
		return record, err
	}
	record.CountryCode = normalizedCode

	// Extract optional fields
	record.CountryName = NormalizeCityName(p.getStringField(raw, "country_name", "country"))
	record.Region = NormalizeString(p.getStringField(raw, "region", "region_name", "state"))
	record.City = NormalizeCityName(p.getStringField(raw, "city", "city_name"))
	record.PostalCode = NormalizeString(p.getStringField(raw, "postal_code", "zip", "zipcode"))
	record.Timezone = p.getStringField(raw, "timezone", "tz", "time_zone")
	record.ISP = NormalizeString(p.getStringField(raw, "isp"))
	// For IPtoASN format, col_4 contains ASN organization description
	record.Org = NormalizeString(p.getStringField(raw, "organization", "org", "asn_org", "col_4"))

	// Extract coordinates
	record.Latitude = p.getFloatField(raw, "latitude", "lat")
	record.Longitude = p.getFloatField(raw, "longitude", "lon", "lng")

	// Validate coordinates
	if record.Latitude != 0 && !p.validator.ValidateLatitude(record.Latitude) {
		record.Latitude = 0 // Reset invalid
	}
	if record.Longitude != 0 && !p.validator.ValidateLongitude(record.Longitude) {
		record.Longitude = 0 // Reset invalid
	}

	// Extract ASN - try standard names then col_2 for IPtoASN format
	record.ASN = p.getIntField(raw, "asn", "as_number", "col_2")

	record.Valid = true
	return record, nil
}

// insertBatch inserts records in batches
func (p *IPGeoProcessor) insertBatch(records []IPGeoRecord, source string) (inserted, updated, errors int) {
	for i := 0; i < len(records); i += p.batchSize {
		end := i + p.batchSize
		if end > len(records) {
			end = len(records)
		}

		batch := records[i:end]
		for _, rec := range batch {
			err := p.storage.StoreIPGeo(
				rec.IPAddress,
				rec.CountryCode,
				rec.CountryName,
				rec.Region,
				rec.City,
				rec.ISP,
				rec.Org,
				rec.Latitude,
				rec.Longitude,
				rec.ASN,
				fmt.Sprintf(`{"source":"%s"}`, source),
			)
			if err != nil {
				errors++
				p.logger.Printf("Insert error for %s: %v", rec.IPAddress, err)
			} else {
				inserted++
			}
		}
	}
	return
}

// getStringField extracts string value from record trying multiple field names
func (p *IPGeoProcessor) getStringField(record map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := record[key]; ok {
			switch v := val.(type) {
			case string:
				return strings.TrimSpace(v)
			case fmt.Stringer:
				return strings.TrimSpace(v.String())
			default:
				return strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
	}
	return ""
}

// getFloatField extracts float value from record
func (p *IPGeoProcessor) getFloatField(record map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		if val, ok := record[key]; ok {
			switch v := val.(type) {
			case float64:
				return v
			case float32:
				return float64(v)
			case int:
				return float64(v)
			case int64:
				return float64(v)
			case string:
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					return f
				}
			}
		}
	}
	return 0
}

// getIntField extracts int value from record
func (p *IPGeoProcessor) getIntField(record map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if val, ok := record[key]; ok {
			switch v := val.(type) {
			case int:
				return v
			case int64:
				return int(v)
			case float64:
				return int(v)
			case string:
				if i, err := strconv.Atoi(v); err == nil {
					return i
				}
			}
		}
	}
	return 0
}

// SetBatchSize sets the batch size for database operations
func (p *IPGeoProcessor) SetBatchSize(size int) {
	if size > 0 {
		p.batchSize = size
	}
}

// GetStats returns current processing statistics
func (p *IPGeoProcessor) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"batch_size": p.batchSize,
	}
}
