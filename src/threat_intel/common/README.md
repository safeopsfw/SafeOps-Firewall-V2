# Threat Intelligence Data Directory Structure

This document describes the common data directory structure used by all threat intelligence components.

## Directory Layout

```
data/
├── feeds/              # Raw downloaded feeds from fetcher
│   ├── ip_geo/
│   ├── ip_blacklist/
│   ├── ip_anonymization/
│   ├── domain/
│   ├── hash/
│   ├── ioc/
│   └── asn/
├── processed/          # Validated/parsed data ready for database
│   ├── ip_geo/
│   ├── ip_blacklist/
│   └── ...
├── archive/            # Old feeds after successful processing
│   └── ...
└── logs/               # Component logs
    ├── fetcher.log
    ├── parser.log
    └── processor.log
```

## Access from Components

All components import the common paths module:

```go
import "threat_intel/common"

// Fetcher saves to:
filePath := filepath.Join(common.IPBlacklistFeedsDir, filename)

// Parser reads from:
files, _ := filepath.Glob(filepath.Join(common.IPBlacklistFeedsDir, "*.txt"))

// Processor reads from:
processedFiles := filepath.Join(common.ProcessedDir, category, "*.json")
```

## Environment Variables

- `THREAT_INTEL_DATA` - Override base data directory
  - Default: `./data` (relative to project root)
  - Example: `export THREAT_INTEL_DATA=/var/threat_intel/data`

## Usage

### Initialize Directories

```go
import "threat_intel/common"

func main() {
    // Create all necessary directories
    if err := common.EnsureDataDirs(); err != nil {
        log.Fatalf("Failed to create data dirs: %v", err)
    }
    
    // Now all components can read/write safely
}
```

### Component-Specific Paths

```go
// Fetcher
outputPath := filepath.Join(common.GetFeedDir("ip_blacklist"), "source_20241221.txt")

// Parser
inputFiles := filepath.Join(common.GetFeedDir(category), "*."+format)
outputPath := filepath.Join(common.GetProcessedDir(category), "parsed.json")

// Archiver
archivePath := filepath.Join(common.GetArchiveDir(category), oldFile)
```

## Benefits

1. ✅ **Single Source of Truth** - One place defines all paths
2. ✅ **Consistency** - All components use same structure
3. ✅ **Flexibility** - Change paths via environment variable
4. ✅ **Safety** - Auto-creates directories before use
5. ✅ **Testability** - Easy to point to test directories
