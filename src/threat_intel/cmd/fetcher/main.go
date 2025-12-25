package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"threat_intel/src/fetcher"
)

func main() {
	log.Println("===========================================")
	log.Println("SafeOps Threat Intel Fetcher v2.0")
	log.Println("===========================================")

	// Check for category argument
	// Usage: go run ./cmd/fetcher [category1,category2,...]
	// Example: go run ./cmd/fetcher ip_geo
	// Example: go run ./cmd/fetcher ip_geo,asn
	var filterCategories []string
	if len(os.Args) > 1 {
		arg := os.Args[1]
		if arg != "" && arg != "all" {
			filterCategories = strings.Split(arg, ",")
			log.Printf("Filtering by categories: %v\n", filterCategories)
		}
	}

	// Get base path (threat_intel directory)
	execPath, err := os.Executable()
	if err != nil {
		execPath, _ = os.Getwd()
	}

	// Calculate base path - go up from cmd/fetcher to threat_intel root
	basePath := filepath.Dir(filepath.Dir(filepath.Dir(execPath)))

	// If running with go run, use current working directory approach
	cwd, _ := os.Getwd()
	if _, err := os.Stat(filepath.Join(cwd, "config", "sources.yaml")); err == nil {
		basePath = cwd
	} else if _, err := os.Stat(filepath.Join(cwd, "..", "..", "config", "sources.yaml")); err == nil {
		basePath = filepath.Join(cwd, "..", "..")
	}

	log.Printf("Base path: %s\n", basePath)

	// Load sources from YAML
	yamlPath := filepath.Join(basePath, "config", "sources.yaml")
	log.Printf("Loading sources from: %s\n", yamlPath)

	sourcesConfig, err := fetcher.LoadSourcesFromYAML(yamlPath)
	if err != nil {
		log.Fatalf("Failed to load sources.yaml: %v", err)
	}

	log.Printf("Loaded %d feeds from sources.yaml\n", len(sourcesConfig.Feeds))

	// Count enabled sources by output folder
	enabledSources := fetcher.GetEnabledSources(sourcesConfig.Feeds)
	grouped := fetcher.GetSourcesByOutputFolder(enabledSources)

	log.Println("-------------------------------------------")
	log.Println("Enabled feeds by output folder:")
	for folder, sources := range grouped {
		if folder == "" {
			folder = "pending (IOC)"
		}
		log.Printf("  %s: %d feeds", folder, len(sources))
	}
	log.Println("-------------------------------------------")

	// Configure fetcher
	storagePath := filepath.Join(basePath, "data", "fetch")
	config := &fetcher.Config{
		StoragePath:   storagePath,
		MaxConcurrent: 5,
		RetryAttempts: 3,
		RetryDelay:    5,
		MaxFileSize:   500, // 500 MB max
		JobTimeout:    120, // 2 minutes per job
		CreateSubdirs: true,
	}

	log.Printf("Storage path: %s\n", storagePath)
	log.Printf("Max concurrent downloads: %d\n", config.MaxConcurrent)

	// Create fetcher
	f, err := fetcher.NewFetcher(config, sourcesConfig.Feeds)
	if err != nil {
		log.Fatalf("Failed to create fetcher: %v", err)
	}

	// Run fetch
	startTime := time.Now()
	var stats *fetcher.FetchStats

	if len(filterCategories) > 0 {
		log.Printf("Starting download for categories: %v\n", filterCategories)
		stats, err = f.FetchByCategory(filterCategories...)
	} else {
		log.Println("Starting download of all enabled feeds...")
		stats, err = f.FetchAll()
	}

	duration := time.Since(startTime)

	if err != nil {
		log.Printf("Fetch completed with errors: %v\n", err)
	}

	// Print results
	log.Println("===========================================")
	log.Println("FETCH COMPLETE")
	log.Println("===========================================")
	log.Printf("Duration: %s\n", duration)
	log.Printf("Total jobs: %d\n", stats.TotalJobs)
	log.Printf("Successful: %d\n", stats.SuccessfulJobs)
	log.Printf("Failed: %d\n", stats.FailedJobs)
	log.Printf("Bytes downloaded: %d (%.2f MB)\n",
		stats.TotalBytesDownloaded,
		float64(stats.TotalBytesDownloaded)/(1024*1024))

	// Save single report (overwrites previous)
	reportPath := filepath.Join(storagePath, "fetch_report.json")
	if err := f.SaveReport(reportPath); err != nil {
		log.Printf("Failed to save report: %v\n", err)
	}

	// Stop fetcher
	f.Stop()

	log.Println("===========================================")
	log.Println("Fetcher shutdown complete")
	log.Println("===========================================")
}
