package common

import (
	"os"
	"path/filepath"
)

// ==========================================================================
// Common Data Paths for Threat Intelligence System
// All components (fetcher, parser, processor, storage) use these paths
// ==========================================================================

var (
	// BaseDataDir is the root directory for all threat intelligence data
	BaseDataDir = getBaseDataDir()

	// FeedsDir is where fetcher downloads raw feed files
	// Structure: feeds/{category}/{source}_{timestamp}.{ext}
	FeedsDir = filepath.Join(BaseDataDir, "feeds")

	// ProcessedDir is where parser saves processed/validated data
	// Structure: processed/{category}/{source}_{timestamp}.json
	ProcessedDir = filepath.Join(BaseDataDir, "processed")

	// ArchiveDir is where old feeds are moved after processing
	// Structure: archive/{category}/{source}_{timestamp}.{ext}
	ArchiveDir = filepath.Join(BaseDataDir, "archive")

	// LogsDir is where component logs are stored
	LogsDir = filepath.Join(BaseDataDir, "logs")
)

// Category-specific feed directories
var (
	IPGeoFeedsDir           = filepath.Join(FeedsDir, "ip_geo")
	IPBlacklistFeedsDir     = filepath.Join(FeedsDir, "ip_blacklist")
	IPAnonymizationFeedsDir = filepath.Join(FeedsDir, "ip_anonymization")
	DomainFeedsDir          = filepath.Join(FeedsDir, "domain")
	HashFeedsDir            = filepath.Join(FeedsDir, "hash")
	IOCFeedsDir             = filepath.Join(FeedsDir, "ioc")
	ASNFeedsDir             = filepath.Join(FeedsDir, "asn")
)

// ==========================================================================
// Helper Functions
// ==========================================================================

// getBaseDataDir returns the base data directory
// Priority: THREAT_INTEL_DATA env var > default ./data
func getBaseDataDir() string {
	if envPath := os.Getenv("THREAT_INTEL_DATA"); envPath != "" {
		return envPath
	}

	// Default to ./data relative to project root
	// When running from cmd/, this resolves correctly
	return filepath.Join(".", "data")
}

// GetFeedDir returns the directory for a specific category
func GetFeedDir(category string) string {
	return filepath.Join(FeedsDir, category)
}

// GetProcessedDir returns the processed data directory for a category
func GetProcessedDir(category string) string {
	return filepath.Join(ProcessedDir, category)
}

// GetArchiveDir returns the archive directory for a category
func GetArchiveDir(category string) string {
	return filepath.Join(ArchiveDir, category)
}

// EnsureDataDirs creates all necessary data directories
func EnsureDataDirs() error {
	dirs := []string{
		FeedsDir,
		ProcessedDir,
		ArchiveDir,
		LogsDir,
		IPGeoFeedsDir,
		IPBlacklistFeedsDir,
		IPAnonymizationFeedsDir,
		DomainFeedsDir,
		HashFeedsDir,
		IOCFeedsDir,
		ASNFeedsDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}

// GetAllCategories returns list of all threat intel categories
func GetAllCategories() []string {
	return []string{
		"ip_geo",
		"ip_blacklist",
		"ip_anonymization",
		"domain",
		"hash",
		"ioc",
		"asn",
	}
}
