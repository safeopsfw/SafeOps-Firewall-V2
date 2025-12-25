package main

import (
	"fmt"
	"os"
	"path/filepath"

	"threat_intel/src/storage"
)

func main() {
	fmt.Println("===========================================")
	fmt.Println("Database vs File Verification")
	fmt.Println("===========================================")

	// Connect to database
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		return
	}
	defer db.Close()

	// Get table counts
	tables := []string{"domains", "hashes", "ip_blacklist", "ip_geolocation", "ip_anonymization"}
	fmt.Println("\nDATABASE ROW COUNTS:")
	fmt.Println("-----------------------------------------")
	for _, table := range tables {
		info, err := db.GetTableInfo(table)
		if err != nil {
			fmt.Printf("  %-20s ERROR: %v\n", table, err)
		} else if info.Exists {
			fmt.Printf("  %-20s %d rows\n", table, info.RowCount)
		} else {
			fmt.Printf("  %-20s (table doesn't exist)\n", table)
		}
	}

	// Count files
	fmt.Println("\nFILE COUNTS:")
	fmt.Println("-----------------------------------------")
	fetchPath := filepath.Join(".", "data", "fetch")
	folders := []string{"domain", "hash", "ip", "ip_geo"}

	for _, folder := range folders {
		folderPath := filepath.Join(fetchPath, folder)
		files, _ := os.ReadDir(folderPath)

		totalLines := 0
		for _, file := range files {
			if !file.IsDir() {
				filePath := filepath.Join(folderPath, file.Name())
				data, err := os.ReadFile(filePath)
				if err == nil {
					lines := 0
					for _, c := range data {
						if c == '\n' {
							lines++
						}
					}
					totalLines += lines
				}
			}
		}
		fmt.Printf("  %-20s %d files, ~%d lines\n", folder+"/", len(files), totalLines)
	}

	fmt.Println("\n===========================================")
	fmt.Println("Verification Complete")
	fmt.Println("===========================================")
}
