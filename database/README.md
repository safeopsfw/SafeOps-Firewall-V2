# Threat Intelligence Database

## Overview

A standalone PostgreSQL 18 database system for comprehensive threat intelligence management. This database can be used independently or integrated with any application for IP/Domain/Hash/IOC intelligence queries.

## Database Name

```
threat_intel_db
```

## Architecture

### Core Tables (8)
1. **`ip_geolocation`** - IP address location and network information
2. **`ip_blacklist`** - Malicious and blacklisted IP addresses  
3. **`ip_anonymization`** - VPN/Tor/Proxy/Datacenter detection
4. **`domains`** - Domain reputation and intelligence
5. **`hashes`** - File hash intelligence and malware analysis
6. **`iocs`** - Indicators of Compromise (centralized repository)
7. **`threat_feeds`** - Feed source management (management table)
8. **`feed_history`** - Feed execution history and logs (management table)

### Supporting Components
- **11 Views** - Common queries and statistics
- **2 Materialized Views** - Performance-optimized aggregations
- **8 Functions** - Helper functions for threat checking
- **6 Triggers** - Automatic timestamp and validation updates

## Quick Setup

### Prerequisites
- PostgreSQL 18+ installed
- `pg_trgm`, `btree_gin`, `btree_gist` extensions (auto-enabled by init script)

### Installation

```bash
# Method 1: Run complete init script
psql -U postgres -f database/init_threat_intel.sql

# Method 2: Run individual files in order
psql -U postgres -c "CREATE DATABASE threat_intel_db"
psql -U postgres -d threat_intel_db -f database/init_threat_intel.sql
```

### Create Application User

```sql
CREATE USER threat_intel_app WITH PASSWORD 'your_secure_password';
GRANT CONNECT ON DATABASE threat_intel_db TO threat_intel_app;
-- Use threat_intel_reader or threat_intel_writer roles as needed
```

## Usage Examples

### Check if IP is Malicious

```sql
-- Using function
SELECT * FROM is_ip_malicious('1.2.3.4'::INET);

-- Direct query
SELECT is_malicious, threat_score, abuse_type 
FROM ip_blacklist 
WHERE ip_address = '1.2.3.4';

-- Get full intelligence (all IP tables combined)
SELECT * FROM get_ip_intelligence('1.2.3.4'::INET);
```

### Check if Domain is Malicious

```sql
-- Using function
SELECT * FROM is_domain_malicious('example.com');

-- Find similar domains (typosquatting detection)
SELECT domain, similarity(domain, 'paypal.com') AS sim
FROM domains 
WHERE domain % 'paypal.com' 
ORDER BY sim DESC LIMIT 10;
```

### Check if Hash is Malicious

```sql
-- Checks MD5, SHA1, or SHA256
SELECT * FROM is_hash_malicious('abc123def456...');

-- Get detailed malware info
SELECT sha256, malware_family, av_detection_rate
FROM hashes 
WHERE sha256 = 'abc123...';
```

### Get Statistics

```sql
-- Overall threat stats
SELECT * FROM threat_stats;

-- High threat IPs
SELECT * FROM high_threat_ips LIMIT 100;

-- Active Tor exit nodes
SELECT * FROM active_tor_exits;

-- Top threat actors
SELECT * FROM top_threat_actors LIMIT 20;
```

## Files Structure

```
database/
├── init_threat_intel.sql              # Complete setup script (run this)
├── schemas/                           # Individual table schemas
│   ├── 001_ip_geolocation.sql
│   ├── 002_ip_blacklist.sql
│   ├── 003_ip_anonymization.sql
│   ├── 004_domains.sql
│   ├── 005_hashes.sql
│   ├── 006_iocs.sql
│   ├── 007_threat_feeds.sql
│   └── 008_feed_history.sql
├── views/
│   └── threat_intel_views.sql         # All views and materialized views
├── functions/
│   └── threat_intel_functions.sql     # Helper functions
├── triggers/
│   └── threat_intel_triggers.sql      # Automatic triggers
├── seeds/
│   └── initial_threat_feeds.sql       # Default feed sources
└── README.md                          # This file
```

## Connection String

```
postgresql://username:password@host:port/threat_intel_db

# Example
postgresql://threat_intel_app:password@localhost:5432/threat_intel_db
```

## Maintenance

### Daily Tasks
```sql
-- Refresh statistics
SELECT refresh_all_materialized_views();

-- Update threat scores
SELECT update_threat_scores();

-- Clean expired IOCs
SELECT cleanup_expired_iocs();
```

### Weekly Tasks
```sql
-- Archive old feed history
SELECT archive_old_feed_history();

-- Vacuum and analyze
VACUUM ANALYZE;
```

## Storage Estimates

| Data Type | Typical Size | Enterprise Size |
|-----------|-------------|-----------------|
| Small Deployment | ~5-10 GB | ~500 GB |
| Medium Deployment | ~50-100 GB | ~2 TB |
| Large Deployment | ~500 GB | ~10+ TB |

## Features

✅ **PostgreSQL Native Types** - INET for IPs, JSONB for flexible metadata  
✅ **Full-Text Search** - Fuzzy matching for domains and IOCs  
✅ **Automatic Timestamps** - Triggers maintain last_seen/last_updated  
✅ **Partial Indexes** - Optimized for malicious-only queries  
✅ **GIN Indexes** - Fast JSONB tag searches  
✅ **Materialized Views** - Pre-computed statistics  
✅ **10 Default Feeds** - Pre-configured threat intelligence sources  

## License

Part of the SafeOps Firewall V2 project.
