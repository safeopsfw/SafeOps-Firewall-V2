package worker

import (
	"log"
	"os"
	"path/filepath"
	"time"
)

// CleanupOldFiles removes feed files older than the specified retention period
func CleanupOldFiles(feedsDir string, retentionDays int) error {
	log.Printf("Cleaning up files older than %d days in %s", retentionDays, feedsDir)

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	deletedCount := 0

	err := filepath.Walk(feedsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.ModTime().Before(cutoffTime) {
			if err := os.Remove(path); err != nil {
				log.Printf("Failed to delete %s: %v", path, err)
			} else {
				deletedCount++
			}
		}

		return nil
	})

	log.Printf("Cleanup complete: %d files deleted", deletedCount)
	return err
}
