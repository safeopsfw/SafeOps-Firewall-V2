package main

import (
	"flag"
	"log"
	"path/filepath"

	"threat_intel/src/processor"
)

func main() {
	// Flags
	fetchPath := flag.String("fetch", "", "Path to fetch directory (default: data/fetch)")
	deleteAfter := flag.Bool("delete", true, "Delete files after processing")
	batchSize := flag.Int("batch", 1000, "Batch size for database inserts")
	flag.Parse()

	// Default fetch path
	if *fetchPath == "" {
		*fetchPath = filepath.Join(".", "data", "fetch")
	}

	log.Println("===========================================")
	log.Println("SafeOps Threat Intel Processor")
	log.Println("===========================================")
	log.Printf("Fetch Path: %s\n", *fetchPath)
	log.Printf("Delete After: %v\n", *deleteAfter)
	log.Printf("Batch Size: %d\n", *batchSize)
	log.Println("===========================================")

	// Create processor config
	config := processor.DefaultConfig(*fetchPath)
	config.DeleteAfter = *deleteAfter
	config.BatchSize = *batchSize

	// Create processor
	proc, err := processor.NewProcessor(config)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer proc.Close()

	// Process all data
	result, err := proc.ProcessAll()
	if err != nil {
		log.Fatalf("Processing failed: %v", err)
	}

	// Summary
	log.Println("===========================================")
	log.Println("Processing Summary")
	log.Println("===========================================")
	log.Printf("Files Processed: %d\n", result.FilesProcessed)
	log.Printf("Rows Read: %d\n", result.RowsRead)
	log.Printf("Rows Inserted: %d\n", result.RowsInserted)
	log.Printf("Files Deleted: %d\n", result.DeletedFiles)
	log.Printf("Duration: %s\n", result.ProcessingTime)
	if len(result.Errors) > 0 {
		log.Printf("Errors: %d\n", len(result.Errors))
		for _, e := range result.Errors {
			log.Printf("  - %s\n", e)
		}
	}
	log.Println("===========================================")
}
