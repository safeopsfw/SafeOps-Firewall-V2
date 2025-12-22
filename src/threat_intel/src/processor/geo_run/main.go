package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"threat_intel/src/processor"
	"threat_intel/src/storage"
)

func main() {
	// 1. Initialize Logger
	logger := log.New(os.Stdout, "[MAIN] ", log.LstdFlags)
	logger.Println("Starting IP Geolocation Processor...")

	// 2. Connect to Database
	logger.Println("Connecting to database...")
	dbConfig := storage.DefaultDBConfig()
	db, err := storage.NewDatabaseWithConfig(dbConfig)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		logger.Fatalf("Database ping failed: %v", err)
	}
	logger.Println("Database connected successfully.")

	// 3. Initialize Processor
	geoProcessor := processor.NewIPGeoProcessor(db)

	// 4. Locate Feed File
	// Using the specific file we analyzed: IPtoASN_20251222_131733.tsv
	feedDir := "data/feeds/ip_geo"
	var targetFile string

	// Check if directory exists
	if _, err := os.Stat(feedDir); os.IsNotExist(err) {
		// Try relative path from root if running from nested dir
		feedDir = "../../../data/feeds/ip_geo"
	}

	files, err := os.ReadDir(feedDir)
	if err != nil {
		logger.Fatalf("Failed to read feed directory %s: %v", feedDir, err)
	}

	for _, f := range files {
		if !f.IsDir() {
			targetFile = filepath.Join(feedDir, f.Name())
			logger.Printf("Found feed file: %s", targetFile)
			break
		}
	}

	if targetFile == "" {
		logger.Fatalf("No feed file found in %s", feedDir)
	}

	// 5. Run Processor
	logger.Printf("Processing file: %s...", targetFile)
	startTime := time.Now()

	// We use "IPtoASN" as the source name
	result := geoProcessor.ProcessFile(targetFile, "IPtoASN")

	duration := time.Since(startTime)

	// 6. Report Results
	fmt.Println("\n========================================")
	fmt.Println("PROCESSING COMPLETE")
	fmt.Println("========================================")
	fmt.Printf("File:      %s\n", result.SourceFile)
	fmt.Printf("Time:      %v\n", duration)
	fmt.Printf("Total:     %d\n", result.TotalRecords)
	fmt.Printf("Valid:     %d\n", result.ValidRecords)
	fmt.Printf("Invalid:   %d\n", result.InvalidRecords)
	fmt.Printf("Inserted:  %d\n", result.InsertedRecords)
	fmt.Printf("Updated:   %d\n", result.UpdatedRecords)
	fmt.Printf("Errors:    %d\n", result.ErrorRecords)
	fmt.Println("========================================")

	if len(result.ValidationErrors) > 0 {
		fmt.Println("\nTop 5 Validation Errors:")
		count := 0
		for _, errMsg := range result.ValidationErrors {
			fmt.Println("- " + errMsg)
			count++
			if count >= 5 {
				break
			}
		}
	}

	// 7. Verify Database Content (Head 30 as requested)
	fmt.Println("\n========================================")
	fmt.Println("DATABASE VERIFICATION (First 30 Records)")
	fmt.Println("========================================")

	// Query the database directly to show what was stored
	query := `
		SELECT ip_address, country_code, city, organization, asn 
		FROM ip_geolocation 
		ORDER BY updated_at DESC 
		LIMIT 30`

	rows, err := db.ExecuteQuery(query)
	if err != nil {
		logger.Printf("Failed to query database verification: %v", err)
		return
	}
	defer rows.Close()

	fmt.Printf("%-18s %-5s %-20s %-30s %-8s\n", "IP Address", "CC", "City", "Organization", "ASN")
	fmt.Println("-----------------------------------------------------------------------------------------")

	var ip, cc, city, org string
	var asn int
	for rows.Next() {
		if err := rows.Scan(&ip, &cc, &city, &org, &asn); err != nil {
			logger.Printf("Error scanning row: %v", err)
			continue
		}

		// Truncate org for display
		if len(org) > 28 {
			org = org[:25] + "..."
		}
		if len(city) > 18 {
			city = city[:15] + "..."
		}

		fmt.Printf("%-18s %-5s %-20s %-30s %-8d\n", ip, cc, city, org, asn)
	}
	fmt.Println("========================================")
}
