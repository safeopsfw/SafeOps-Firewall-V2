# Threat Intelligence Service

A comprehensive threat intelligence aggregation and analysis service for the SafeOps Firewall V2 project.

## Overview

This service fetches, parses, processes, and stores threat intelligence data from multiple open-source feeds. It provides a RESTful API for querying IP reputation, domain intelligence, hash signatures, and IOC data.

## Architecture

```
threat_intel/
├── cmd/server/          # Main application entry point
├── config/             # Configuration management
├── src/
│   ├── api/           # REST API handlers and routes
│   ├── fetcher/       # Feed downloading and scheduling
│   ├── parser/        # Data parsing (CSV, JSON, TXT)
│   ├── storage/       # Database operations
│   ├── processor/     # Data enrichment and scoring
│   └── worker/        # Background job processing
├── feeds/             # Downloaded feed files (gitignored)
├── models/            # Data structures
└── utils/             # Utility functions
```

## Features

- **Multi-format Parser**: Supports CSV, JSON, and plain text feeds
- **Automatic Scheduling**: Configurable feed update intervals
- **Data Enrichment**: Geolocation, ASN, and threat scoring
- **Deduplication**: Removes duplicate entries
- **RESTful API**: Query threat intelligence via HTTP
- **Worker Pool**: Concurrent processing with configurable workers
- **PostgreSQL Storage**: Efficient indexed storage

## Database Schema

The service uses PostgreSQL 18 with the following tables:
- `ip_geolocation` - IP address location data
- `ip_blacklist` - Malicious IP addresses
- `ip_anonymization` - VPN/Tor/Proxy detection
- `domain_intelligence` - Domain reputation
- `hash_intelligence` - File hash reputation
- `ioc_storage` - Generic IOC storage
- `threat_feeds` - Feed source management
- `asn_data` - AS number information

## Configuration

Edit `config/config.yaml`:

```yaml
server:
  port: 8080

database:
  host: localhost
  port: 5432
  user: postgres
  password: your_password
  dbname: threat_intel
  sslmode: disable

worker:
  max_workers: 5
  fetch_interval: 3600
```

## API Endpoints

- `GET /health` - Health check
- `GET /api/v1/ip/{ip}` - Get IP reputation
- `GET /api/v1/domain/{domain}` - Get domain intelligence
- `GET /api/v1/hash/{hash}` - Get hash reputation
- `GET /api/v1/ioc` - Get IOC data

## Running

```bash
# Build
go build -o threat_intel cmd/server/main.go

# Run
./threat_intel
```

## Development

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Run with custom config
CONFIG_PATH=/path/to/config.yaml ./threat_intel
```

## Threat Intelligence Sources

Default sources include:
- AlienVault IP Reputation
- Abuse.ch URLhaus
- Feodo Tracker
- Tor Exit Nodes

Additional sources can be added in `config/sources.yaml`.

## License

Part of the SafeOps Firewall V2 project.
