# Threat Intelligence Service

A comprehensive threat intelligence aggregation and analysis service for SafeOps Firewall V2.

## Quick Start

### Build Pipeline
```bash
cd d:\SafeOpsFV2\src\threat_intel

# Build pipeline (fetch + process)
go build -o threat_intel_pipeline.exe ./cmd/pipeline
```

### Update Database (Run Pipeline)
```bash
.\threat_intel_pipeline.exe
```
This downloads all threat feeds and inserts them into PostgreSQL.

## Direct Python Integration

The `realtime_capture.py` connects **directly to PostgreSQL** - no API server needed!

```python
# In realtime_capture.py - ThreatIntelClient connects directly to DB
# Database: threat_intel_db
# Tables: ip_geolocation (1.1M IPs), ip_blacklist (34K), ip_anonymization (1.3K)
```

## Database Tables

| Table | Records | Purpose |
|-------|---------|---------|
| `domains` | 1.1M+ | Malicious domain reputation (phishing, malware) |
| `ip_blacklist` | 34K | Known malicious IPs + threat scores |
| `ip_geolocation` | 1.1M | IP → Country, ASN, ISP (range-based lookup) |
| `ip_anonymization` | 1.3K | VPN/Tor/Proxy detection |

## Pipeline Commands

```bash
# Full update (fetch + process)
.\threat_intel_pipeline.exe

# Fetch only (download feeds)
.\threat_intel_pipeline.exe -fetch

# Process only (insert to DB)
.\threat_intel_pipeline.exe -process

# Specific category
.\threat_intel_pipeline.exe -category=ip_geo

# Check DB status
.\threat_intel_pipeline.exe -status
```

## Threat Feed Sources

Feeds are configured in `config/sources.yaml`:

| Category | Example Sources |
|----------|-----------------|
| IP Blacklist | Feodo Tracker, FireHOL, Blocklist.de |
| Domains | OpenPhish, URLhaus, ThreatFox |
| VPN/Tor | Tor Exit Nodes, VPN Gate |
| Geo/ASN | IPtoASN, GeoLite2, IP2Location |

## Database Requirements

PostgreSQL connection in `config/config.yaml`:
```yaml
database:
  host: localhost
  port: 5432
  database: threat_intel_db
  user: threat_intel_app
  password: ${DB_PASSWORD}
```

## Directory Structure

```
threat_intel/
├── cmd/
│   ├── fetcher/    → Feed downloader
│   ├── processor/  → DB inserter
│   └── pipeline/   → All-in-one
├── config/
│   ├── config.yaml    → Database settings
│   └── sources.yaml   → Threat feed URLs
├── src/
│   ├── fetcher/    → HTTP download logic
│   ├── parser/     → CSV/JSON/TXT parsers
│   ├── processor/  → Data processing
│   └── storage/    → PostgreSQL operations
├── data/
│   └── fetch/      → Downloaded feeds
└── *.exe           → Built executables
```

## License

Part of SafeOps Firewall V2 project.
