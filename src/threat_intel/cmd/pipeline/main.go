package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"threat_intel/src/fetcher"
	"threat_intel/src/processor"
	"threat_intel/src/storage"
)

// =============================================================================
// Threat Intel Pipeline - Unified Command
// =============================================================================
// Usage:
//   go run ./cmd/pipeline                     # Run all (fetch + process)
//   go run ./cmd/pipeline -fetch              # Fetch only
//   go run ./cmd/pipeline -process            # Process only
//   go run ./cmd/pipeline -category=ip_geo    # Fetch specific category
//   go run ./cmd/pipeline -status             # Show database status
//   go run ./cmd/pipeline -headers            # Show table headers
// =============================================================================

func main() {
	// Flags
	fetchOnly := flag.Bool("fetch", false, "Run fetcher only")
	processOnly := flag.Bool("process", false, "Run processor only")
	category := flag.String("category", "", "Fetch specific category (ip_geo, ip_blacklist, domain, hash)")
	showStatus := flag.Bool("status", false, "Show database status and row counts")
	showHeaders := flag.Bool("headers", false, "Show table headers/columns")
	deleteAfter := flag.Bool("delete", true, "Delete files after processing")
	scheduler := flag.Bool("scheduler", false, "Run continuously every 30 minutes")
	flag.Parse()

	// Get executable directory for relative paths
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	exeDir = filepath.Dir(exePath)

	log.Println("===========================================")
	log.Println("SafeOps Threat Intelligence Pipeline")
	log.Printf("Working Directory: %s", exeDir)
	log.Println("===========================================")

	// Handle status
	if *showStatus {
		showDatabaseStatus()
		return
	}

	// Handle headers
	if *showHeaders {
		showTableHeaders()
		return
	}

	// Scheduler mode - run every 30 minutes
	if *scheduler {
		log.Println("[SCHEDULER] Running in continuous mode (every 30 minutes)")
		for {
			runPipeline(*fetchOnly, *processOnly, *category, *deleteAfter)
			log.Println("[SCHEDULER] Sleeping for 30 minutes...")
			time.Sleep(30 * time.Minute)
		}
	}

	// Single run
	runPipeline(*fetchOnly, *processOnly, *category, *deleteAfter)
}

// Global variable for exe directory
var exeDir string

// runPipeline executes fetch and/or process based on flags
func runPipeline(fetchOnly, processOnly bool, category string, deleteAfter bool) {
	// Default: run both if no flags
	runFetch := fetchOnly || (!fetchOnly && !processOnly)
	runProcess := processOnly || (!fetchOnly && !processOnly)

	startTime := time.Now()

	// Step 1: Fetch
	if runFetch {
		if err := runFetcher(category); err != nil {
			log.Printf("Fetcher error: %v\n", err)
		}
	}

	// Step 2: Process
	if runProcess {
		if err := runProcessor(deleteAfter); err != nil {
			log.Printf("Processor error: %v\n", err)
		}
	}

	log.Println("===========================================")
	log.Printf("Pipeline Complete - Duration: %s\n", time.Since(startTime))
	log.Println("===========================================")
}

// runFetcher runs the fetcher component
func runFetcher(category string) error {
	log.Println("\n[FETCH] Starting fetcher...")

	// Load config from exe directory
	configPath, err := fetcher.FindSourcesYAML(exeDir)
	if err != nil {
		return fmt.Errorf("failed to find sources.yaml: %w", err)
	}

	sourcesConfig, err := fetcher.LoadSourcesFromYAML(configPath)
	if err != nil {
		return fmt.Errorf("failed to load sources: %w", err)
	}

	enabledSources := fetcher.GetEnabledSources(sourcesConfig.Feeds)
	log.Printf("[FETCH] Loaded %d enabled sources\n", len(enabledSources))

	// Create fetcher config
	fetchConfig := &fetcher.Config{
		StoragePath:   filepath.Join(exeDir, "data", "fetch"),
		MaxConcurrent: 5,
		RetryAttempts: 3,
		RetryDelay:    5,
		MaxFileSize:   100,
		JobTimeout:    60,
		CreateSubdirs: true,
	}

	f, err := fetcher.NewFetcher(fetchConfig, enabledSources)
	if err != nil {
		return fmt.Errorf("failed to create fetcher: %w", err)
	}

	var stats *fetcher.FetchStats
	if category != "" {
		categories := strings.Split(category, ",")
		log.Printf("[FETCH] Fetching categories: %v\n", categories)
		stats, err = f.FetchByCategory(categories...)
	} else {
		log.Println("[FETCH] Fetching all enabled feeds...")
		stats, err = f.FetchAll()
	}

	if err != nil {
		return err
	}

	log.Printf("[FETCH] Complete - Success: %d, Failed: %d\n", stats.SuccessfulJobs, stats.FailedJobs)
	return nil
}

// runProcessor runs the processor component
func runProcessor(deleteAfter bool) error {
	log.Println("\n[PROCESS] Starting processor...")

	config := processor.DefaultConfig(filepath.Join(exeDir, "data", "fetch"))
	config.DeleteAfter = deleteAfter

	proc, err := processor.NewProcessor(config)
	if err != nil {
		return fmt.Errorf("failed to create processor: %w", err)
	}
	defer proc.Close()

	result, err := proc.ProcessAll()
	if err != nil {
		return err
	}

	log.Printf("[PROCESS] Complete - Files: %d, Rows: %d, Inserted: %d\n",
		result.FilesProcessed, result.RowsRead, result.RowsInserted)
	return nil
}

// showDatabaseStatus shows current database row counts
func showDatabaseStatus() {
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer db.Close()

	fmt.Println("\n📊 DATABASE STATUS:")
	fmt.Println("─────────────────────────────────────────")

	tables := []string{"domains", "hashes", "ip_blacklist", "ip_geolocation", "ip_anonymization"}
	for _, table := range tables {
		info, err := db.GetTableInfo(table)
		if err != nil {
			fmt.Printf("  %-20s ERROR: %v\n", table, err)
		} else if info.Exists {
			fmt.Printf("  %-20s %d rows\n", table, info.RowCount)
		} else {
			fmt.Printf("  %-20s (not found)\n", table)
		}
	}
	fmt.Println("─────────────────────────────────────────")
}

// showTableHeaders shows columns for each table
func showTableHeaders() {
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer db.Close()

	tables := []string{"domains", "hashes", "ip_blacklist", "ip_geolocation", "ip_anonymization"}

	for _, table := range tables {
		info, err := db.GetTableInfo(table)
		if err != nil {
			fmt.Printf("\n❌ %s: ERROR - %v\n", table, err)
			continue
		}
		if !info.Exists {
			fmt.Printf("\n❌ %s: (table not found)\n", table)
			continue
		}

		fmt.Printf("\n📋 %s (%d rows):\n", strings.ToUpper(table), info.RowCount)
		fmt.Println("─────────────────────────────────────────")
		for _, col := range info.Columns {
			nullable := ""
			if col.IsNullable {
				nullable = " (nullable)"
			}
			fmt.Printf("  %-25s %s%s\n", col.Name, col.DataType, nullable)
		}
	}
}

// =============================================================================
// Individual Component Triggers (for API/backend use)
// =============================================================================

// FetchCategory fetches a specific category - can be called by backend
func FetchCategory(category string) error {
	return runFetcher(category)
}

// ProcessAllData processes all fetched data - can be called by backend
func ProcessAllData(deleteAfter bool) error {
	return runProcessor(deleteAfter)
}

// GetStatus returns database status - can be called by backend
func GetStatus() (map[string]int64, error) {
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		return nil, err
	}
	defer db.Close()

	status := make(map[string]int64)
	tables := []string{"domains", "hashes", "ip_blacklist", "ip_geolocation", "ip_anonymization"}

	for _, table := range tables {
		info, err := db.GetTableInfo(table)
		if err == nil && info.Exists {
			status[table] = info.RowCount
		}
	}
	return status, nil
}

// QueryIP checks an IP against all threat tables - can be called by backend
func QueryIP(ip string) (map[string]interface{}, error) {
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		return nil, err
	}
	defer db.Close()

	ctx := context.Background()
	result := make(map[string]interface{})

	// Check IP blacklist
	ipStore := storage.NewIPBlacklistStorage(db)
	if rec, err := ipStore.GetByIP(ctx, ip); err == nil && rec != nil {
		result["blacklist"] = rec
	}

	// Check IP geolocation
	geoStore := storage.NewIPGeoStorage(db)
	if rec, err := geoStore.GetByIP(ctx, ip); err == nil && rec != nil {
		result["geolocation"] = rec
	}

	// Check IP anonymization
	anonStore := storage.NewIPAnonymizationStorage(db)
	if rec, err := anonStore.GetByIP(ctx, ip); err == nil && rec != nil {
		result["anonymization"] = rec
	}

	return result, nil
}

// QueryDomain checks a domain against threat tables - can be called by backend
func QueryDomain(domain string) (*storage.DomainRecord, error) {
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		return nil, err
	}
	defer db.Close()

	ctx := context.Background()
	domainStore := storage.NewDomainStorage(db)
	return domainStore.GetByDomain(ctx, domain)
}

// QueryHash checks a hash against threat tables - can be called by backend
func QueryHash(hash string) (*storage.HashRecord, error) {
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		return nil, err
	}
	defer db.Close()

	ctx := context.Background()
	hashStore := storage.NewHashStorage(db)

	if len(hash) == 64 {
		return hashStore.GetBySHA256(ctx, hash)
	}
	return hashStore.GetByMD5(ctx, hash)
}
