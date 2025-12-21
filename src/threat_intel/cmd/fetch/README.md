# Threat Intelligence Feed Fetcher

Standalone utility to download all configured threat intelligence feeds.

## Quick Start

### Build and Run

```powershell
# Navigate to the fetch command directory
cd src\threat_intel\cmd\fetch

# Build the executable
go build -o fetch.exe main.go

# Run the fetcher
.\fetch.exe
```

Or build and run in one step:

```powershell
cd src\threat_intel\cmd\fetch
go run main.go
```

## What It Does

1. ✅ Loads configuration from `config/config.yaml`
2. ✅ Loads threat intelligence sources from `config/sources.yaml`
3. ✅ Shows enabled sources grouped by category
4. ✅ Downloads all enabled feeds concurrently
5. ✅ Saves files to `./feeds/{category}/` directories
6. ✅ Reports statistics (success/failed, bytes downloaded, duration)

## Output Structure

Downloaded files are saved to:
```
./feeds/
  ├── ip_geo/
  │   ├── MaxMind_GeoLite2_20241221_230841.mmdb
  │   └── IP2Location_LITE_20241221_230845.csv
  ├── ip_blacklist/
  │   ├── Feodo_Tracker_C2_IPs_20241221_230841.txt
  │   ├── URLhaus_Malicious_IPs_20241221_230842.csv
  │   └── ...
  ├── domain/
  │   ├── PhishTank_20241221_230843.csv
  │   └── OpenPhish_20241221_230844.txt
  ├── hash/
  └── ioc/
```

## Configuration

Edit `config/sources.yaml` to:
- Enable/disable specific feeds (`enabled: true/false`)
- Change update frequencies
- Add new sources

Edit `config/config.yaml` to:
- Change download location (`storage.base_path`)
- Adjust concurrent downloads (`worker.concurrent_jobs`)
- Modify retry settings (`worker.retry_attempts`, `worker.retry_delay`)

## Example Output

```
==========================================================
SafeOps Threat Intelligence - Feed Fetcher Utility
==========================================================

📋 Loading configuration...
✅ Configuration loaded from: config/config.yaml

📂 Loading threat intelligence sources...
✅ Loaded 57 total sources (52 enabled)

📋 Enabled Sources by Category:

   IP Geolocation (3 feeds):
      • MaxMind GeoLite2
      • IP2Location LITE
      • DB-IP Lite

   IP Blacklist (19 feeds):
      • Feodo Tracker C2 IPs
      • URLhaus Malicious IPs
      • Blocklist.de All
      ...

🚀 Initializing fetcher...
✅ Fetcher initialized

📁 Download location: ./feeds
   Files will be saved to: ./feeds/{category}/{source}_{timestamp}.{ext}

🔄 About to download 52 feeds. This may take several minutes.
   Press ENTER to continue or Ctrl+C to cancel...

⏬ Starting download of all feeds...

[Download progress...]

==========================================================
📊 FETCH RESULTS
==========================================================
Total Jobs:        52
Successful:        48 ✅
Failed:            4 ❌
Total Downloaded:  2.3 GB
Average Duration:  4.2s
Total Time:        3m 45s
==========================================================

📂 Downloaded files are in: ./feeds
   Next step: Run parser to process these files into database
```

## Next Steps

After downloading:
1. **Parse the files**: Run parser to extract threat intelligence
2. **Process the data**: Validate, deduplicate, enrich
3. **Store in database**: Insert into PostgreSQL tables

## Troubleshooting

### Authentication Errors
Some feeds require API keys. Set environment variables:
```powershell
$env:GITHUB_TOKEN="your_github_token"
```

### Rate Limiting
- GitHub: 60 req/hour (unauthenticated), 5000 req/hour (with token)
- Some feeds may block excessive requests

### Failed Downloads
Check `config/sources.yaml` for:
- Correct URLs
- Valid formats
- Network connectivity

## Environment Variables

- `GITHUB_TOKEN` - For GitHub API authentication
- `DB_PASSWORD` - Database password (not used by fetcher)
- `STORAGE_PATH` - Override download location
