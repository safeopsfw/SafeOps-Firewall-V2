# SafeOps Threat Intelligence Database

> PostgreSQL 16+ database for high-performance threat intelligence storage and querying.

## Overview

The SafeOps database stores IP/domain/hash reputation, IOCs, geolocation, and ASN data with sub-10ms query response times. Designed for 100K+ queries/second with proper indexing and partitioned tables.

### Key Features

- **Real-time threat intelligence** - Multi-feed aggregation with conflict resolution
- **Geographic/network context** - IP geolocation, ASN tracking, threat zones
- **Campaign attribution** - Threat actor and campaign correlation
- **Automated maintenance** - Cleanup, partitioning, and optimization
- **Audit trails** - Complete history tracking for all changes

---

## Architecture

| Component | Count | Description |
|-----------|-------|-------------|
| Schema Files | 10 | Table definitions and relationships |
| Views | 3 | Aggregated threat intelligence |
| Seed Files | 3 | Initial configuration and test data |
| Tables | 50+ | Comprehensive threat data storage |
| Indexes | 100+ | Performance optimization |

---

## Schema Files

Applied in order:

| File | Purpose |
|------|---------|
| `001_initial_setup.sql` | Database, extensions, core tables (threat_feeds, threat_categories) |
| `002_ip_reputation.sql` | IP reputation scoring, whitelist/blacklist, history |
| `003_domain_reputation.sql` | Domain reputation, DNS filtering, fuzzy matching |
| `004_hash_reputation.sql` | Multi-hash support (MD5/SHA1/SHA256/SHA512), malware families |
| `005_ioc_storage.sql` | 15+ IOC types, STIX/TAXII support, campaigns |
| `006_proxy_anonymizer.sql` | VPN/proxy/TOR detection, hosting providers |
| `007_geolocation.sql` | IP geolocation, geofencing, threat zones |
| `008_threat_feeds.sql` | Feed credentials, scheduling, health monitoring |
| `009_asn_data.sql` | ASN ownership, BGP prefixes, peering, abuse tracking |
| `999_indexes_and_maintenance.sql` | Performance indexes, maintenance functions |

---

## Views

| View | Purpose |
|------|---------|
| `active_threats_view` | Real-time feed of active high-severity threats with priority scoring |
| `high_confidence_iocs` | Validated IOCs (confidence ≥0.80) suitable for automated blocking |
| `threat_summary_stats` | Aggregated statistics for dashboards (24H/7D/30D/90D) |

---

## Quick Start

### Installation (Windows PowerShell)

```powershell
cd SafeOps\database

# Run initialization script
.\init_database.ps1

# With options
.\init_database.ps1 -DatabaseName my_threat_db -SkipTestData

# Dry run (preview)
.\init_database.ps1 -DryRun
```

### Verification

```sql
-- Connect to database
psql -U safeops_admin -d safeops_threat_intel

-- Check tables
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';

-- Check seed data
SELECT COUNT(*) FROM threat_categories;  -- Expected: 37
SELECT COUNT(*) FROM threat_feeds;       -- Expected: 18

-- Test query
SELECT * FROM active_threats_view LIMIT 10;
```

---

## Usage Examples

### IP Reputation Lookup

```sql
SELECT reputation_score, confidence_level, tc.category_name
FROM ip_reputation ir
LEFT JOIN threat_categories tc ON ir.threat_category_id = tc.category_id
WHERE ir.ip_address = '203.0.113.10';
```

### Domain Reputation (Case-Insensitive)

```sql
SELECT reputation_score, confidence_level, last_seen
FROM domain_reputation
WHERE domain_name = 'evil.example.com';
```

### File Hash Lookup (Any Hash Type)

```sql
SELECT reputation_score, malware_family, file_type
FROM hash_reputation
WHERE sha256_hash = 'abc123...'
   OR md5_hash = 'def456...';
```

### Get Active Threats for Blocking

```sql
SELECT threat_type, threat_value, priority, action_recommended
FROM active_threats_view
WHERE priority > 75 AND action_recommended = 'BLOCK'
ORDER BY priority DESC LIMIT 100;
```

### Geographic Threat Distribution

```sql
SELECT country_code, COUNT(*) as threat_count
FROM ip_reputation
WHERE reputation_score < -50 AND country_code IS NOT NULL
GROUP BY country_code
ORDER BY threat_count DESC LIMIT 10;
```

---

## PostgreSQL Configuration

### Recommended Settings (postgresql.conf)

```ini
# Memory (adjust based on available RAM)
shared_buffers = 4GB              # 25% of RAM
effective_cache_size = 12GB       # 75% of RAM
maintenance_work_mem = 2GB
work_mem = 256MB

# Performance (SSD optimized)
random_page_cost = 1.1
effective_io_concurrency = 200

# Autovacuum (high-update workload)
autovacuum_naptime = 30s
autovacuum_vacuum_scale_factor = 0.05
```

### Connection Pooling (PgBouncer Recommended)

```ini
[databases]
safeops_threat_intel = host=localhost port=5432

[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
```

---

## Maintenance

### Automated (via pg_cron)

| Schedule | Function | Purpose |
|----------|----------|---------|
| Daily 2:00 AM | `cleanup_expired_records()` | Remove expired data |
| Daily 3:00 AM | `update_reputation_scores()` | Recalculate with decay |
| Daily 4:00 AM | `vacuum_and_analyze_tables()` | Database maintenance |
| Weekly Sunday | `partition_maintenance()` | Create/drop partitions |
| Hourly | `update_statistics()` | Refresh aggregates |

### Manual Commands

```sql
-- Force cleanup
SELECT cleanup_expired_records(dry_run := false);

-- Recalculate scores
SELECT update_reputation_scores();

-- Detect anomalies
SELECT detect_anomalies(sensitivity := 3);

-- Refresh materialized views
REFRESH MATERIALIZED VIEW CONCURRENTLY threat_summary_stats;
```

---

## Backup & Recovery

### Backup

```bash
# Full backup (daily)
pg_dump -U safeops_admin -F c safeops_threat_intel > backup_$(date +%Y%m%d).dump

# Schema only
pg_dump -U safeops_admin -s safeops_threat_intel > schema.sql
```

### Restore

```bash
pg_restore -U safeops_admin -d safeops_threat_intel backup.dump
```

---

## Integration

### Service Connections

| Service | Purpose | Operations |
|---------|---------|------------|
| `threat_intel` (Rust) | Feed ingestion | Write threat data, update scores |
| `firewall_engine` (Rust) | Packet filtering | Query IP/domain reputation |
| `ids_ips` (Go) | Detection | Query IOCs, record sightings |
| `dns_server` (Go) | DNS filtering | Domain reputation lookups |

### Connection Details

```
Host:     localhost (or PgBouncer)
Port:     5432 (or 6432 for PgBouncer)
Database: safeops_threat_intel
User:     safeops_admin
SSL:      require (production)
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Slow queries | Check `pg_stat_statements`, verify indexes with `EXPLAIN ANALYZE` |
| High disk usage | Run `VACUUM FULL`, check partition cleanup |
| Connection errors | Check `max_connections`, verify PgBouncer status |
| Missing data | Verify feed updates, check `feed_update_history` |

### Monitoring Queries

```sql
-- Check index usage
SELECT indexname, idx_scan FROM pg_stat_user_indexes ORDER BY idx_scan ASC;

-- Find slow queries
SELECT query, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;

-- Check table sizes
SELECT tablename, pg_size_pretty(pg_total_relation_size('public.' || tablename))
FROM pg_tables WHERE schemaname = 'public' ORDER BY pg_total_relation_size('public.' || tablename) DESC;
```

---

## Security

- **Credentials**: Encrypt all API keys in `feed_credentials` table using pgcrypto
- **Access**: Limit network access via `pg_hba.conf`, use SSL
- **Audit**: All schema changes logged, admin operations tracked
- **Roles**: Separate roles for different services (read-only, read-write)

---

## File Structure

```
database/
├── schemas/
│   ├── 001_initial_setup.sql
│   ├── 002_ip_reputation.sql
│   ├── 003_domain_reputation.sql
│   ├── 004_hash_reputation.sql
│   ├── 005_ioc_storage.sql
│   ├── 006_proxy_anonymizer.sql
│   ├── 007_geolocation.sql
│   ├── 008_threat_feeds.sql
│   ├── 009_asn_data.sql
│   └── 999_indexes_and_maintenance.sql
├── views/
│   ├── active_threats_view.sql
│   ├── high_confidence_iocs.sql
│   └── threat_summary_stats.sql
├── seeds/
│   ├── feed_sources_config.sql      (18 feeds)
│   ├── initial_threat_categories.sql (37 categories)
│   └── test_ioc_data.sql            (sample data)
├── init_database.ps1                 (Windows setup script)
└── README.md                         (this file)
```

---

## Version

**v1.0.0** - Initial Release
- 10 schema files, 3 views, 3 seed files
- PostgreSQL 16+ support
- Automated maintenance and partitioning
