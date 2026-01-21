# Threat Intelligence - Component Documentation

## Overview
The Threat Intelligence Service is a comprehensive threat data aggregation and lookup system built in Go. It fetches, parses, and stores threat indicators from multiple open-source intelligence (OSINT) feeds, providing real-time IP reputation, domain blacklists, malware hash lookups, and geolocation enrichment for the SafeOps firewall ecosystem.

## Component Information

**Component Type:** Threat Intelligence Platform
**Language:** Go
**Architecture:** Multi-pipeline feed processor with REST API and gRPC services
**Platform:** Cross-platform (Windows, Linux)

## Files and Locations

### Source Files
```
D:\SafeOpsFV2\src\threat_intel\
├── cmd\
│   ├── api\main.go                  # REST API server
│   ├── fetcher\main.go              # Feed fetcher service
│   ├── processor\main.go            # Feed processor service
│   └── pipeline\main.go             # Full pipeline orchestrator
├── config\config.go                 # YAML configuration loader
├── internal\
│   ├── feeds\
│   │   ├── feed_manager.go          # Feed lifecycle management
│   │   ├── feed_fetcher.go          # HTTP download
│   │   ├── feed_parser.go           # Format parsing
│   │   ├── feed_updater.go          # Update scheduler
│   │   └── feed_validator.go        # Data validation
│   ├── sources\
│   │   ├── abuse_ch.go              # Abuse.ch feeds
│   │   ├── alienvault_otx.go        # AlienVault OTX
│   │   ├── emergingthreats.go       # Emerging Threats
│   │   ├── phishtank.go             # PhishTank
│   │   ├── spamhaus.go              # Spamhaus DROP
│   │   ├── tor_exit_nodes.go        # Tor exit node list
│   │   └── custom_feeds.go          # User-defined feeds
│   ├── ioc\
│   │   ├── ioc_manager.go           # IOC management
│   │   ├── ip_ioc.go                # IP indicator matching
│   │   ├── domain_ioc.go            # Domain matching
│   │   ├── hash_ioc.go              # Hash matching (MD5, SHA256)
│   │   ├── url_ioc.go               # URL matching
│   │   └── matcher.go               # Pattern matching engine
│   ├── enrichment\
│   │   ├── ip_enricher.go           # IP metadata enrichment
│   │   ├── domain_enricher.go       # Domain WHOIS/DNS
│   │   ├── asn_lookup.go            # AS number lookup
│   │   └── geolocation.go           # GeoIP lookup
│   ├── reputation\
│   │   ├── ip_reputation.go         # IP reputation scoring
│   │   ├── domain_reputation.go     # Domain reputation
│   │   ├── scoring_engine.go        # Threat score calculation
│   │   └── confidence_calculator.go # Confidence levels
│   ├── cache\
│   │   ├── ioc_cache.go             # In-memory IOC cache
│   │   ├── redis_cache.go           # Redis backend (optional)
│   │   └── cache_warmer.go          # Cache pre-loading
│   ├── api\
│   │   ├── grpc_server.go           # gRPC service
│   │   └── handlers.go              # REST API handlers
│   ├── storage\
│   │   ├── database.go              # PostgreSQL client
│   │   ├── ioc_store.go             # IOC persistence
│   │   ├── feed_store.go            # Feed metadata storage
│   │   ├── ip_blacklist.go          # IP blacklist storage
│   │   ├── domain.go                # Domain storage
│   │   ├── hash.go                  # Hash storage
│   │   ├── ip_geo.go                # GeoIP storage
│   │   └── ip_anonymization.go      # VPN/Proxy/Tor detection
│   ├── metrics\
│   │   ├── collector.go             # Prometheus metrics
│   │   └── feed_metrics.go          # Feed-specific metrics
│   └── worker\
│       ├── pipeline.go              # Worker pipeline
│       ├── worker.go                # Background workers
│       └── cleanup.go               # Old data cleanup
├── pkg\models\
│   ├── ioc.go                       # IOC data models
│   ├── threat.go                    # Threat models
│   └── feed.go                      # Feed metadata models
├── src\
│   ├── api\
│   │   ├── handlers.go              # API route handlers
│   │   ├── routes.go                # Route definitions
│   │   └── middleware.go            # Auth/logging middleware
│   ├── fetcher\
│   │   ├── fetcher.go               # Feed fetcher
│   │   ├── http.go                  # HTTP client
│   │   ├── github.go                # GitHub raw file fetcher
│   │   ├── scheduler.go             # Update scheduler
│   │   └── sources.go               # Feed source definitions
│   ├── parser\
│   │   ├── parser.go                # Parser interface
│   │   ├── csv.go                   # CSV parser
│   │   ├── json.go                  # JSON parser
│   │   ├── txt.go                   # Plain text parser
│   │   └── validator.go             # Data validation
│   ├── processor\
│   │   ├── base_processor.go        # Base processor
│   │   ├── ip_processor.go          # IP processing
│   │   ├── domain_processor.go      # Domain processing
│   │   ├── hash_processor.go        # Hash processing
│   │   └── ip_geo_processor.go      # GeoIP processing
│   └── storage\
│       └── db.go                    # Database utilities
└── tests\
    ├── ioc_test.go                  # IOC tests
    ├── feed_test.go                 # Feed tests
    └── integration_test.go          # Integration tests
```

### Binary/Executable
```
D:\SafeOpsFV2\bin\threat_intel\
├── threat_intel.exe                 # Main service (API + fetcher + processor)
└── threat_intel_api.exe             # Standalone API server
```

### Configuration Files
```
D:\SafeOpsFV2\bin\threat_intel\config\
├── config.yaml                      # Main configuration
└── sources.yaml                     # Feed source definitions
```

### Database Schema
```
D:\SafeOpsFV2\database\schemas\021_threat_intel.sql
```

## Functionality

### Core Functions

#### 1. Threat Feed Management
- **Multi-source Aggregation** - 20+ OSINT feeds (Abuse.ch, PhishTank, Emerging Threats, etc.)
- **Automatic Updates** - Configurable update intervals (hourly, daily)
- **Feed Validation** - Data integrity checks before ingestion
- **Format Support** - CSV, JSON, TXT, MMDB, XML, TSV, RSS
- **GitHub Integration** - Direct fetching from GitHub raw URLs
- **Custom Feeds** - User-defined feed support
- **Feed Scheduling** - Staggered updates to avoid API rate limits
- **Feed Metrics** - Update success/failure tracking

#### 2. Indicator of Compromise (IOC) Management
**IP Address IOCs:**
- Blacklist/blocklist IPs from malicious sources
- Botnet C&C servers
- Scanner IPs (Shodan, Censys)
- Tor exit nodes
- VPN/Proxy server detection

**Domain IOCs:**
- Phishing domains (PhishTank, OpenPhish)
- Malware distribution domains
- C&C domains
- DGA (Domain Generation Algorithm) detection
- Typosquatting detection

**Hash IOCs:**
- Malware file hashes (MD5, SHA256)
- Known malicious samples
- VirusTotal integration ready
- File reputation scoring

**URL IOCs:**
- Malicious URLs
- Phishing URLs
- Exploit kit URLs

#### 3. IP Reputation & Enrichment
- **Reputation Scoring** - 0-100 threat score based on multiple feeds
- **Confidence Levels** - HIGH, MEDIUM, LOW based on source quality
- **GeoIP Lookup** - Country, city, latitude/longitude
- **ASN Lookup** - Autonomous System Number and organization
- **Anonymization Detection** - VPN, Proxy, Tor identification
- **IP Metadata** - ISP, connection type, hosting provider

#### 4. Domain Reputation
- **Domain Scoring** - Multi-source reputation aggregation
- **Age Analysis** - Domain registration date checks
- **DNS Resolution** - A, AAAA, MX, TXT record lookups
- **WHOIS Enrichment** - Registrar, registrant information
- **Category Classification** - Phishing, malware, spam, legitimate

#### 5. Real-time Lookup API
**REST API Endpoints:**
- `/api/threat-intel/lookup/ip/{ip}` - IP reputation lookup
- `/api/threat-intel/lookup/domain/{domain}` - Domain reputation
- `/api/threat-intel/lookup/hash/{hash}` - File hash lookup
- `/api/threat-intel/status` - Service status and database stats
- `/api/threat-intel/health` - Health check
- `/api/threat-intel/update` - Trigger manual feed update

**Response Format:**
```json
{
  "ip": "1.2.3.4",
  "found": true,
  "blacklist": {
    "ip": "1.2.3.4",
    "source": "abuse.ch",
    "category": "malware",
    "added_at": "2024-01-01T00:00:00Z"
  },
  "geolocation": {
    "country": "US",
    "city": "New York",
    "lat": 40.7128,
    "lon": -74.0060
  },
  "anonymization": {
    "is_vpn": false,
    "is_proxy": false,
    "is_tor": false
  }
}
```

#### 6. Background Workers
- **Feed Fetcher** - Downloads feeds from remote sources
- **Feed Processor** - Parses and normalizes data
- **Database Updater** - Batch inserts to PostgreSQL
- **Cache Warmer** - Pre-loads frequently accessed IOCs
- **Cleanup Worker** - Removes stale/expired indicators
- **Metrics Collector** - Prometheus metrics export

#### 7. Caching Layer
- **In-memory Cache** - Fast IOC lookups (10,000+ entries)
- **Redis Support** - Distributed caching (optional)
- **Cache TTL** - Configurable expiration (300s default)
- **Cache Warming** - Pre-load on startup
- **Cache Metrics** - Hit/miss ratio tracking

## Default Ports

| Port | Service | Purpose | Mode |
|------|---------|---------|------|
| **5050** | REST API | HTTP threat intel API | Server |
| **50058** | gRPC Server | Threat Intel gRPC API | Bidirectional |
| 5432 | PostgreSQL | Database connection | Client |
| 6379 | Redis | Cache backend (optional) | Client |
| 9090 | Prometheus | Metrics export | Server |

### API Configuration
- Listen address: 0.0.0.0:5050 (REST), 0.0.0.0:50058 (gRPC)
- CORS: Enabled (all origins for development)
- Rate limit: 100 requests/minute (configurable)
- Read timeout: 30 seconds
- Write timeout: 30 seconds
- Idle timeout: 60 seconds

## API Endpoints (REST + gRPC)

### REST API

**Lookup Operations:**
- `GET /api/threat-intel/lookup/ip/:ip` - IP reputation lookup
- `GET /api/threat-intel/lookup/domain/:domain` - Domain reputation
- `GET /api/threat-intel/lookup/hash/:hash` - Hash lookup (MD5/SHA256)

**Service Operations:**
- `GET /api/threat-intel/health` - Health check
- `GET /api/threat-intel/status` - Database row counts
- `GET /api/threat-intel/headers` - Database schema info
- `POST /api/threat-intel/update` - Trigger feed update

### gRPC API

**IOC Lookup:**
- `LookupIP(LookupIPRequest)` - IP reputation and geolocation
- `LookupDomain(LookupDomainRequest)` - Domain reputation
- `LookupHash(LookupHashRequest)` - File hash lookup
- `BatchLookupIPs(BatchLookupIPsRequest)` - Bulk IP lookup (up to 1000)

**Feed Management:**
- `GetFeedStatus(GetFeedStatusRequest)` - Feed update status
- `UpdateFeed(UpdateFeedRequest)` - Trigger specific feed update
- `ListFeeds(ListFeedsRequest)` - List all configured feeds

**Statistics:**
- `GetStatistics(GetStatisticsRequest)` - IOC counts, feed stats
- `GetReputationScore(GetReputationScoreRequest)` - Threat score calculation

## Dependencies

### Go Dependencies

**HTTP & API:**
- github.com/gorilla/mux - HTTP router
- github.com/rs/cors - CORS middleware
- google.golang.org/grpc - gRPC framework

**Database:**
- github.com/lib/pq - PostgreSQL driver
- github.com/jmoiron/sqlx - SQL extensions

**Data Processing:**
- encoding/csv - CSV parsing
- encoding/json - JSON parsing
- gopkg.in/yaml.v3 - YAML configuration

**Caching:**
- github.com/go-redis/redis/v8 - Redis client (optional)
- sync.Map - In-memory cache

**Utilities:**
- github.com/robfig/cron/v3 - Scheduled tasks
- github.com/prometheus/client_golang - Metrics

### External Service Dependencies
- PostgreSQL 14+ - IOC storage
- Redis 6+ (optional) - Distributed caching

### Threat Intelligence Sources

**IP Blacklists:**
- Abuse.ch Feodo Tracker (botnet C&C)
- Emerging Threats RBN
- Spamhaus DROP/EDROP
- Blocklist.de
- ThreatFox
- Tor Exit Nodes
- VPN Gate List

**Domain Blacklists:**
- PhishTank (phishing domains)
- OpenPhish
- URLhaus (malware URLs)
- Phishing.Army
- DGA domains

**Hash Lists:**
- Abuse.ch MalwareBazaar
- URLhaus payloads
- ThreatFox malware samples

**GeoIP:**
- IP2Location LITE database
- MaxMind GeoLite2 (optional)

## Component Interconnections

### Architecture
```
┌─────────────────────────────────────────────────┐
│      Threat Intelligence Service (50058)        │
│   (IOC Aggregation & Reputation Scoring)        │
└─────────────────────────────────────────────────┘
    ↓           ↓          ↓          ↓
[IDS/IPS]   [Firewall]  [DNS Proxy] [PostgreSQL]
(50057)     (50051)     (15353)      (5432)
    ↓
[Network     [Redis      [Prometheus]
Logger]      Cache]      (9090)
(50056)      (6379)
```

### Integration Points

**To Other Components:**
1. **IDS/IPS (50057)** - Provides IOC data for signature matching
2. **Firewall Engine (50051)** - IP reputation for block/allow decisions
3. **DNS Proxy (15353)** - Domain reputation for DNS filtering
4. **Network Logger (50056)** - Enriches logs with threat intel

**From External Sources:**
- OSINT feeds (HTTP/HTTPS downloads)
- GitHub raw file URLs
- Public threat intelligence APIs

## Database Schema

**PostgreSQL 14+ Tables:**

1. **ip_blacklist** - Malicious IP addresses
   - ip (INET, PK)
   - source (VARCHAR)
   - category (VARCHAR) - malware, botnet, scanner, tor
   - confidence (INTEGER) - 0-100
   - added_at (TIMESTAMP)
   - last_seen (TIMESTAMP)

2. **domains** - Malicious domains
   - domain (VARCHAR, PK)
   - category (VARCHAR) - phishing, malware, spam
   - source (VARCHAR)
   - added_at (TIMESTAMP)
   - confidence (INTEGER)

3. **hashes** - Malware file hashes
   - hash_id (UUID, PK)
   - md5 (VARCHAR(32))
   - sha256 (VARCHAR(64))
   - file_type (VARCHAR)
   - malware_family (VARCHAR)
   - source (VARCHAR)
   - added_at (TIMESTAMP)

4. **ip_geolocation** - GeoIP database
   - ip_start (INET)
   - ip_end (INET)
   - country_code (CHAR(2))
   - country_name (VARCHAR)
   - city (VARCHAR)
   - latitude (DECIMAL)
   - longitude (DECIMAL)
   - timezone (VARCHAR)

5. **ip_anonymization** - VPN/Proxy/Tor detection
   - ip (INET, PK)
   - is_vpn (BOOLEAN)
   - is_proxy (BOOLEAN)
   - is_tor (BOOLEAN)
   - provider (VARCHAR)
   - updated_at (TIMESTAMP)

6. **threat_feeds** - Feed metadata
   - feed_id (UUID, PK)
   - name (VARCHAR)
   - url (VARCHAR)
   - category (VARCHAR)
   - last_update (TIMESTAMP)
   - next_update (TIMESTAMP)
   - update_interval (INTERVAL)
   - record_count (INTEGER)
   - status (VARCHAR) - active, failed, disabled

**Indexes:**
- ip_blacklist: source, category, added_at
- domains: category, source, added_at
- hashes: md5, sha256, malware_family
- ip_geolocation: country_code, city
- ip_anonymization: is_vpn, is_tor

## Configuration

### Database Configuration
```yaml
database:
  host: localhost
  port: 5432
  database: safeops
  user: safeops
  password: ${DB_PASSWORD}
  sslmode: disable
  max_connections: 25
  max_idle_connections: 5
  connection_lifetime: 30  # minutes
```

### API Configuration
```yaml
api:
  host: 0.0.0.0
  port: 5050
  enable_cors: true
  cors_origins: ["*"]
  rate_limit: 100          # requests/minute
  read_timeout: 30         # seconds
  write_timeout: 30
  idle_timeout: 60
```

### Worker Configuration
```yaml
worker:
  enabled: true
  concurrent_jobs: 5
  retry_attempts: 3
  retry_delay: 60          # seconds
  job_timeout: 300         # seconds
  cleanup_interval: 24     # hours
  cleanup_age_days: 7      # delete old IOCs after 7 days
```

### Performance Configuration
```yaml
performance:
  batch_size: 1000         # Records per batch insert
  buffer_size: 10          # MB
  parallel_parsers: 4      # Concurrent feed parsers
  enable_caching: true
  cache_ttl: 300           # seconds
```

## Important Notes

### Performance
- Batch database inserts (1000 records/batch)
- In-memory caching (300s TTL)
- Parallel feed processing (5 concurrent jobs)
- Connection pooling (5-25 connections)
- Indexed lookups for fast queries

### Reliability
- Retry logic (3 attempts with 60s delay)
- Feed validation before ingestion
- Transaction support for data consistency
- Graceful degradation if feeds fail
- Health check monitoring

### Security
- IP address validation
- Domain name validation
- SQL injection prevention (prepared statements)
- Rate limiting (100 req/min)
- Optional authentication (Bearer token)

### Data Freshness
- Hourly updates for critical feeds
- Daily updates for stable feeds
- Automatic cleanup of stale data (7 days)
- Feed status monitoring
- Failed update alerts

### Capacity
- 10M+ IP addresses
- 1M+ domains
- 100K+ malware hashes
- 4M+ GeoIP entries
- Fast lookups (<10ms)

## Connection to Other Components

| Component | Connection Type | Purpose |
|-----------|----------------|---------|
| IDS/IPS | gRPC Client | IOC signature matching |
| Firewall Engine | gRPC Client | IP reputation blocking |
| DNS Proxy | gRPC Client | Domain filtering |
| Network Logger | gRPC Client | Log enrichment |
| PostgreSQL | Database | IOC storage |
| Redis | Cache | Distributed caching (optional) |
| Prometheus | Metrics | Performance monitoring |

---

**Status:** Production Ready
**Auto-Start:** Via SafeOps Launcher
**Dependencies:** PostgreSQL
**Optional:** Redis (caching)
**Managed By:** Orchestrator
**Version:** 1.0.0
