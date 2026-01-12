package processor

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"threat_intel/src/parser"
	"threat_intel/src/storage"
)

// =============================================================================
// Processor Configuration
// =============================================================================

// Config holds processor configuration
type Config struct {
	FetchPath     string // data/fetch directory
	BatchSize     int    // rows per batch insert
	DeleteAfter   bool   // delete files after processing
	StorageConfig *storage.DBConfig
}

// DefaultConfig returns default processor configuration
func DefaultConfig(fetchPath string) *Config {
	return &Config{
		FetchPath:     fetchPath,
		BatchSize:     1000,
		DeleteAfter:   true,
		StorageConfig: storage.DefaultDBConfig(),
	}
}

// =============================================================================
// Processor Result
// =============================================================================

// Result holds processing statistics
type Result struct {
	FilesProcessed int
	RowsRead       int
	RowsInserted   int64
	RowsFailed     int
	Errors         []string
	ProcessingTime time.Duration
	DeletedFiles   int
}

// =============================================================================
// Main Processor
// =============================================================================

// Processor orchestrates all data processing
type Processor struct {
	config       *Config
	db           *storage.DB
	parserConfig *parser.ParserConfig
	logger       *log.Logger
}

// NewProcessor creates a new processor instance
func NewProcessor(config *Config) (*Processor, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	logger := log.New(os.Stdout, "[PROCESSOR] ", log.LstdFlags)

	// Connect to database
	logger.Println("Connecting to database...")
	db, err := storage.NewDB(config.StorageConfig)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}

	// Verify database connectivity
	logger.Println("Verifying database connectivity...")
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}
	logger.Println("  ✓ Database connection OK")

	// Check required tables exist
	logger.Println("Checking required tables...")
	requiredTables := []string{"ip_blacklist", "ip_anonymization", "ip_geolocation", "domains", "hashes"}
	for _, table := range requiredTables {
		info, err := db.GetTableInfo(table)
		if err != nil {
			logger.Printf("  ⚠ Warning: Could not check table '%s': %v\n", table, err)
			continue
		}
		if !info.Exists {
			logger.Printf("  ⚠ Warning: Table '%s' does not exist - data will not be stored\n", table)
		} else {
			logger.Printf("  ✓ Table '%s' exists (%d rows)\n", table, info.RowCount)
		}
	}

	// Check fetch directory exists
	if _, err := os.Stat(config.FetchPath); os.IsNotExist(err) {
		db.Close()
		return nil, fmt.Errorf("fetch directory does not exist: %s", config.FetchPath)
	}
	logger.Printf("  ✓ Fetch directory: %s\n", config.FetchPath)

	return &Processor{
		config:       config,
		db:           db,
		parserConfig: parser.DefaultParserConfig(),
		logger:       logger,
	}, nil
}

// Close closes database connection
func (p *Processor) Close() {
	if p.db != nil {
		p.db.Close()
	}
}

// =============================================================================
// Process All
// =============================================================================

// ProcessAll processes all data folders
func (p *Processor) ProcessAll() (*Result, error) {
	startTime := time.Now()
	result := &Result{}

	p.logger.Println("===========================================")
	p.logger.Println("Starting data processing")
	p.logger.Println("===========================================")

	// 1. Process IP files (malware, abuse, vpn, tor, proxy -> ip_blacklist)
	p.logger.Println("Processing IP files...")
	ipResult, err := p.ProcessIPFolder()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("IP processing: %v", err))
	} else {
		result.FilesProcessed += ipResult.FilesProcessed
		result.RowsRead += ipResult.RowsRead
		result.RowsInserted += ipResult.RowsInserted
		result.DeletedFiles += ipResult.DeletedFiles
	}

	// 2. Process IP Geo files (iptoasn, ip2location -> ip_geolocation)
	p.logger.Println("Processing IP Geo files...")
	geoResult, err := p.ProcessGeoFolder()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Geo processing: %v", err))
	} else {
		result.FilesProcessed += geoResult.FilesProcessed
		result.RowsRead += geoResult.RowsRead
		result.RowsInserted += geoResult.RowsInserted
		result.DeletedFiles += geoResult.DeletedFiles
	}

	// 3. Process Domain files (phishing, malware -> domains)
	p.logger.Println("Processing Domain files...")
	domainResult, err := p.ProcessDomainFolder()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Domain processing: %v", err))
	} else {
		result.FilesProcessed += domainResult.FilesProcessed
		result.RowsRead += domainResult.RowsRead
		result.RowsInserted += domainResult.RowsInserted
		result.DeletedFiles += domainResult.DeletedFiles
	}

	// 4. Process Hash files (malware hashes -> hashes)
	p.logger.Println("Processing Hash files...")
	hashResult, err := p.ProcessHashFolder()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Hash processing: %v", err))
	} else {
		result.FilesProcessed += hashResult.FilesProcessed
		result.RowsRead += hashResult.RowsRead
		result.RowsInserted += hashResult.RowsInserted
		result.DeletedFiles += hashResult.DeletedFiles
	}

	result.ProcessingTime = time.Since(startTime)

	p.logger.Println("===========================================")
	p.logger.Println("Processing Complete")
	p.logger.Printf("Files: %d, Rows: %d, Inserted: %d, Deleted: %d\n",
		result.FilesProcessed, result.RowsRead, result.RowsInserted, result.DeletedFiles)
	p.logger.Printf("Duration: %s\n", result.ProcessingTime)
	if len(result.Errors) > 0 {
		p.logger.Printf("Errors: %d\n", len(result.Errors))
	}
	p.logger.Println("===========================================")

	return result, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// getFilesInFolder returns all files in a folder
func (p *Processor) getFilesInFolder(folder string) ([]string, error) {
	folderPath := filepath.Join(p.config.FetchPath, folder)

	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		return nil, nil // Folder doesn't exist, skip
	}

	var files []string
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !strings.HasPrefix(info.Name(), ".") {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// deleteFile removes a file after processing
func (p *Processor) deleteFile(filePath string) error {
	if !p.config.DeleteAfter {
		return nil
	}
	return os.Remove(filePath)
}

// getSourceFromFilename extracts source name from filename
func getSourceFromFilename(filename string) string {
	base := filepath.Base(filename)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	parts := strings.Split(name, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ")
}

// getCategoryFromFilename guesses category from filename
func getCategoryFromFilename(filename string) string {
	lower := strings.ToLower(filename)

	if strings.Contains(lower, "tor") {
		return "tor"
	}
	if strings.Contains(lower, "vpn") {
		return "vpn"
	}
	if strings.Contains(lower, "proxy") {
		return "proxy"
	}
	if strings.Contains(lower, "malware") || strings.Contains(lower, "feodo") || strings.Contains(lower, "bazaar") {
		return "malware"
	}
	if strings.Contains(lower, "phish") {
		return "phishing"
	}
	if strings.Contains(lower, "spam") {
		return "spam"
	}
	if strings.Contains(lower, "abuse") || strings.Contains(lower, "blacklist") || strings.Contains(lower, "blocklist") {
		return "abuse"
	}

	return "unknown"
}

// parseFile reads and parses a file using the parser package
func (p *Processor) parseFile(filePath string) (*parser.ParseResult, error) {
	return parser.ParseFile(filePath, p.parserConfig)
}

// getContext returns background context (simplified to avoid leaks)
func getContext() context.Context {
	return context.Background()
}
