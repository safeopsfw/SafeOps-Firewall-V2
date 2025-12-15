# SafeOps Threat Intelligence Database

> **Purpose**: PostgreSQL database optimized for threat intelligence storage, IOC management, and security operations. Designed to complement (not replace) your SIEM with high-performance threat lookups.

---

## Overview

This database stores **threat intelligence data only** - no network traffic, firewall logs, or real-time events (those belong in your SIEM). Instead, it provides:

- ✅ **IP/Domain/Hash Reputation** - Fast threat lookups
- ✅ **IOC Management** - Indicators from 20+ threat feeds
- ✅ **Anonymizer Detection** - VPN, Tor, Proxy identification
- ✅ **Geolocation** - IP→Country/City/ASN mapping
- ✅ **Feed Management** - Automated threat feed ingestion
- ✅ **ASN Intelligence** - Network owner & abuse tracking

### Relationship with SIEM

| Database (Threat Intel) | SIEM (Events) |
|------------------------|---------------|
| Threat reputation data | Real-time network traffic |
| IOC indicators | Firewall/IDS logs |
| Malware hashes | Authentication events |
| Feed aggregation | Alert correlation |
| **Enrichment source** | **Event processing** |

---

## Quick Start

### Prerequisites

- **PostgreSQL 15+** (required for partitioning features)
- **psql** command-line client
- **Admin access** to create databases and roles

### Installation

```bash
# 1. Initialize database and schemas
./init_database.sh

# 2. Verify installation
psql -U safeops -d safeops_threatintel -c "\dt threat_intel.*"

# 3. Load threat feed sources (20+ pre-configured feeds)
psql -U safeops -d safeops_threatintel -f seeds/feed_sources_config.sql

# 4. Check database stats
psql -U safeops -d safeops_threatintel -c "SELECT * FROM threat_intel.get_database_stats();"
```

### Verify Setup

```sql
-- Connect to database
psql -U safeops safeops_threatintel

-- Check table count
SELECT COUNT(*) FROM information_schema.tables 
WHERE table_schema IN ('threat_intel', 'geo');

-- Check roles
\du

-- Test a lookup function
SELECT * FROM threat_intel.lookup_ip('8.8.8.8');
```

---

## Architecture

### Database Structure

```
safeops_threatintel
├── threat_intel (schema)   # Core threat data
│   ├── ip_reputation       # IP threat scores & history
│   ├── domain_reputation   # Domain/URL reputation
│   ├── hash_reputation     # File hash malware data
│   ├── ioc_indicators      # Generic IOCs (IP/domain/URL/hash)
│   ├── ioc_matches         # Detection events (partitioned)
│   ├── ioc_campaigns       # Threat campaigns
│   ├── anonymizer_ips      # VPN/Tor/Proxy detection
│   ├── threat_feed_sources # Feed configuration
│   ├── feed_update_history # Feed ingestion logs
│   ├── asn_reputation      # ASN-level threat data
│   └── threat_by_country   # Geographic threat stats
│
├── geo (schema)            # Geolocation data
│   ├── ip_geolocation      # IP→Location cache
│   ├── asn_information     # ASN registry
│   ├── asn_prefixes        # IP→ASN mapping
│   ├── ip_to_asn           # Fast ASN lookup
│   └── bogon_prefixes      # Reserved/invalid IPs
│
└── audit (schema)          # Change tracking
    └── change_log          # Audit trail
```

### Schema Files (001-999)

| File | Tables | Purpose |
|------|--------|---------|
| **001_initial_setup.sql** | N/A | Database, roles, enums, extensions |
| **002_ip_reputation.sql** | 4 | IP reputation, history (partitioned), blocklist, whitelist |
| **003_domain_reputation.sql** | 5 | Domain/URL reputation, categories, DGA detection |
| **004_hash_reputation.sql** | 3 | File hash malware, families, relationships |
| **005_ioc_storage.sql** | 4 | IOCs, matches (partitioned), campaigns, relationships |
| **006_proxy_anonymizer.sql** | 6 | VPN providers, Tor, hosting, anonymizer IPs, proxies |
| **007_geolocation.sql** | 6 | IP geolocation, ASN info, country stats, regional stats |
| **008_threat_feeds.sql** | 4 | Feed sources, update history, statistics, health checks |
| **009_asn_data.sql** | 5 | ASN prefixes, reputation, threat history, peers, bogons |
| **999_indexes_maintenance.sql** | N/A | Performance indexes, maintenance functions |

**Total**: 40+ tables, 100+ functions, 200+ indexes

---

## Schema Details

### 1. IP Reputation (`002_ip_reputation.sql`)

**Main Table**: `threat_intel.ip_reputation`

```sql
-- Lookup IP threat score
SELECT * FROM threat_intel.lookup_ip('203.0.113.50');

-- Check if IP is blocked
SELECT * FROM threat_intel.check_ips_blocked(ARRAY['1.2.3.4', '5.6.7.8']);

-- Add/update IP reputation
SELECT threat_intel.upsert_ip_reputation(
    '192.0.2.100', 'MALWARE', 'HIGH', 'CONFIRMED', 'AbuseIPDB'
);
```

**Features**:
- Reputation score (0-100)
- Threat categories: MALWARE, BOTNET, C2, PHISHING, etc.
- Anonymizer detection
- Source tracking (multi-feed aggregation)
- Monthly partitioned history (12-month retention)

---

### 2. Domain Reputation (`003_domain_reputation.sql`)

**Main Tables**: `domain_reputation`, `url_reputation`, `domain_categories`

```sql
-- Lookup domain
SELECT * FROM threat_intel.lookup_domain('example.com');

-- Find similar domains (typosquatting)
SELECT * FROM threat_intel.search_similar_domains('google.com', 0.3, 10);

-- Check content policy
SELECT * FROM threat_intel.check_domain_policy('example.com', ARRAY['adult', 'gambling']);
```

**Features**:
- DGA (Domain Generation Algorithm) detection
- Typosquatting detection (fuzzy matching)
- WHOIS data (registration date, registrar)
- DNS records (A, MX, NS)
- Content categories (adult, gambling, malware, etc.)
- Auto-extraction of parent domain & TLD

---

### 3. Hash Reputation (`004_hash_reputation.sql`)

**Main Tables**: `hash_reputation`, `malware_families`, `hash_relationships`

```sql
-- Lookup file hash
SELECT * FROM threat_intel.lookup_hash('5d41402abc4b2a76b9719d911017c592');

-- Check if malware
SELECT threat_intel.is_known_malware('098f6bcd4621d373cade4e832627b4f6');

-- Get related hashes (dropper→payload relationships)
SELECT * FROM threat_intel.get_related_hashes('abc123...', 2);
```

**Features**:
- MD5, SHA1, SHA256, SHA512, SSDEEP, IMPHASH
- Auto-computed detection rate (% of AVs that flagged it)
- Malware family cataloging (Emotet, TrickBot, etc.)
- Sample relationships (DROPS, VARIANT_OF, etc.)
- PE file analysis (imports, exports, signatures)

---

### 4. IOC Storage (`005_ioc_storage.sql`)

**Main Tables**: `ioc_indicators`, `ioc_matches`, `ioc_campaigns`

```sql
-- Lookup IOC
SELECT * FROM threat_intel.lookup_ioc('malicious.com', 'DOMAIN');

-- Record detection
SELECT threat_intel.record_ioc_match(
    'uuid-of-ioc', 'malicious.com', '192.0.2.1'::INET, 
    '203.0.113.50'::INET, 'BLOCKED', 'HIGH'
);

-- Get campaign IOCs
SELECT * FROM threat_intel.get_campaign_iocs('APT29');
```

**Features**:
- MITRE ATT&CK TTP mapping
- Campaign/threat actor attribution
- Daily partitioned matches (90-day retention)
- GIN trigram fuzzy search
- Source reliability scoring (A-F grades)

---

### 5. Anonymizer Detection (`006_proxy_anonymizer.sql`)

**Main Tables**: `anonymizer_ips`, `vpn_providers`, `tor_exit_nodes`, `hosting_providers`

```sql
-- Check if IP is anonymizer
SELECT * FROM threat_intel.is_anonymizer('1.2.3.4');

-- Check if Tor exit node
SELECT threat_intel.is_tor_exit('185.220.101.1');

-- Comprehensive check (all sources)
SELECT * FROM threat_intel.check_ip_anonymization('1.2.3.4');
```

**Features**:
- VPN provider catalog (logging policies, jurisdictions)
- Tor exit node tracking (exit policies, fingerprints)
- Bulletproof hosting detection
- Residential proxy networks
- GiST indexed IP ranges for fast lookups

---

### 6. Geolocation (`007_geolocation.sql`)

**Main Tables**: `ip_geolocation`, `asn_information`, `threat_by_country`

```sql
-- Get IP location
SELECT * FROM geo.lookup_ip_location('8.8.8.8');

-- Get ASN for IP
SELECT * FROM geo.lookup_ip_asn('1.1.1.1');

-- Calculate distance between IPs
SELECT geo.ip_distance_km('8.8.8.8', '1.1.1.1');

-- Get country threats
SELECT * FROM threat_intel.get_country_threats('CN');
```

**Features**:
- Country→City hierarchy
- ASN information (abuse contacts, registry)
- Per-capita threat analysis
- Monthly partitioned regional stats
- 30-day geolocation cache TTL

---

### 7. Threat Feeds (`008_threat_feeds.sql`)

**Main Tables**: `threat_feed_sources`, `feed_update_history`, `feed_statistics`

```sql
-- Get feeds due for update
SELECT * FROM threat_intel.get_feeds_due_for_update();

-- Start feed update
SELECT threat_intel.start_feed_update(1, 'MANUAL');

-- Complete feed update
SELECT threat_intel.complete_feed_update(123, 'SUCCESS', 1500, 100, 50);
```

**Features**:
- 20+ pre-configured feeds (Abuse.ch, Firehol, Emerging Threats)
- Auto-health monitoring (HEALTHY/DEGRADED/DOWN)
- Auto-computed uptime percentage
- Monthly partitioned update history
- Priority-based update scheduling

---

### 8. ASN Data (`009_asn_data.sql`)

**Main Tables**: `asn_prefixes`, `asn_reputation`, `asn_threat_history`

```sql
-- Get ASN for IP
SELECT * FROM geo.get_asn_for_ip('8.8.8.8');

-- Check if IP is in bogon range
SELECT * FROM geo.is_bogon('192.168.1.1');

-- Get ASN reputation
SELECT * FROM threat_intel.get_asn_reputation(15169);

-- Get top malicious ASNs
SELECT * FROM threat_intel.get_top_malicious_asns(20);
```

**Features**:
- IP prefix assignments (GiST indexed)
- ASN reputation (auto trust/risk levels)
- Threat density (threats per IP in ASN)
- BGP peering relationships
- Pre-populated bogon ranges (RFC 1918, etc.)

---

## Performance Tuning

### Recommended PostgreSQL Settings

Add to `postgresql.conf`:

```ini
# Memory
shared_buffers = 4GB                 # 25% of system RAM
effective_cache_size = 12GB          # 75% of system RAM
work_mem = 64MB                      # For sorting/joins
maintenance_work_mem = 1GB           # For VACUUM, index creation

# Checkpoint
checkpoint_timeout = 15min
checkpoint_completion_target = 0.9
max_wal_size = 4GB

# Query Planner
random_page_cost = 1.1               # For SSD storage
effective_io_concurrency = 200       # For SSD

# Parallel Query
max_parallel_workers_per_gather = 4
max_parallel_workers = 8

# Connection Pooling
max_connections = 200

# Logging (for performance analysis)
log_min_duration_statement = 1000    # Log queries > 1s
log_line_prefix = '%t [%p]: '
```

### Index Strategy

Indexes are automatically created by schema files:

- **Hash indexes**: O(1) lookups for exact matches (IP, hash values)
- **GIN indexes**: Array/JSONB/full-text search
- **GiST indexes**: IP range searches (CIDR matching)
- **BRIN indexes**: Time-series data (low overhead)
- **Partial indexes**: Filtered queries (active IOCs only)

### Maintenance Schedule

```sql
-- Daily (automated via pg_cron)
SELECT threat_intel.cleanup_expired_iocs();
SELECT threat_intel.update_threat_statistics();

-- Weekly
SELECT threat_intel.recalculate_all_reputations();
VACUUM ANALYZE;

-- Monthly
SELECT threat_intel.create_future_partitions(3);
SELECT threat_intel.drop_old_partitions(12);
```

---

## Backup & Recovery

### Backup Strategy

**Option 1: pg_dump (Recommended for <100GB)**

```bash
# Full backup
pg_dump -U safeops -F c -b -v \
  -f /backups/threatintel_$(date +%Y%m%d).backup \
  safeops_threatintel

# Schema only
pg_dump -U safeops -s -f /backups/schema_only.sql safeops_threatintel

# Data only (for specific tables)
pg_dump -U safeops -t threat_intel.ioc_indicators \
  -f /backups/iocs_$(date +%Y%m%d).sql safeops_threatintel
```

**Option 2: Continuous Archiving (Enterprise)**

```bash
# Enable WAL archiving in postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'rsync -a %p /mnt/wal_archive/%f'

# Base backup
pg_basebackup -U postgres -D /backups/base -F tar -z -P
```

### Restore Procedures

```bash
# Restore from pg_dump
pg_restore -U safeops -d safeops_threatintel \
  -v /backups/threatintel_20250101.backup

# Restore specific table
pg_restore -U safeops -d safeops_threatintel \
  -t ioc_indicators /backups/threatintel_20250101.backup
```

### Disaster Recovery

1. **Restore database structure**: Run `init_database.sh`
2. **Restore data**: `pg_restore` from backup
3. **Rebuild indexes**: `REINDEX DATABASE safeops_threatintel;`
4. **Update statistics**: `ANALYZE;`
5. **Verify integrity**: `SELECT * FROM threat_intel.get_database_stats();`

---

## Integration Examples

### Rust (Threat Intelligence Service)

```rust
use tokio_postgres::{NoTls, Error};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=safeops dbname=safeops_threatintel",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        connection.await.unwrap();
    });

    // Lookup IP reputation
    let rows = client.query(
        "SELECT * FROM threat_intel.lookup_ip($1)",
        &[&"203.0.113.50"],
    ).await?;

    for row in rows {
        let threat_level: String = row.get("threat_level");
        let score: i32 = row.get("reputation_score");
        println!("IP threat: {} (score: {})", threat_level, score);
    }

    Ok(())
}
```

### Python (Feed Ingestion)

```python
import psycopg2

conn = psycopg2.connect(
    host="localhost",
    database="safeops_threatintel",
    user="safeops",
    password="your_password"
)

cur = conn.cursor()

# Upsert IP reputation
cur.execute("""
    SELECT threat_intel.upsert_ip_reputation(
        %s, %s, %s, %s, %s
    )
""", ('192.0.2.100', 'MALWARE', 'HIGH', 'CONFIRMED', 'AbuseIPDB'))

conn.commit()
cur.close()
conn.close()
```

---

## Data Retention Policies

| Table | Retention | Cleanup Method |
|-------|-----------|----------------|
| `ioc_matches` | 90 days | Auto-partition drop |
| `feed_update_history` | 12 months | Auto-partition drop |
| `ip_reputation_history` | 12 months | Auto-partition drop |
| `regional_threat_stats` | 12 months | Auto-partition drop |
| `ioc_indicators` | Until `valid_until` | `cleanup_expired_iocs()` |
| `ip_geolocation` | 30 days | Cache expiry, refresh on access |

---

## Monitoring

### Database Health

```sql
-- Table sizes
SELECT * FROM threat_intel.get_table_sizes();

-- Database statistics
SELECT * FROM threat_intel.get_database_stats();

-- Index usage
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE schemaname = 'threat_intel'
ORDER BY idx_scan DESC;

-- Slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
WHERE mean_exec_time > 1000
ORDER BY mean_exec_time DESC
LIMIT 10;
```

### Feed Health

```sql
-- Get feed status
SELECT * FROM threat_intel.get_feed_status(1);

-- Check failed feeds
SELECT feed_name, last_error, last_error_at
FROM threat_intel.threat_feed_sources
WHERE health_status IN ('DEGRADED', 'DOWN');
```

---

## Future Enhancements

### Planned Features

- [ ] **STIX/TAXII 2.1 Support** - Native STIX JSON ingestion
- [ ] **Graph Relationships** - IOC relationship visualization
- [ ] **ML-Based Reputation** - Auto-scoring using ensemble models
- [ ] **Real-Time Streaming** - Kafka/Redis pub-sub for IOC updates
- [ ] **Multi-Tenancy** - Organization-level data isolation
- [ ] **API Gateway Integration** - RESTful/GraphQL query layer

### Migration Strategy

Schema updates use numbered migration files:

```bash
database/migrations/
├── up/
│   ├── 001_add_stix_column.sql
│   └── 002_ml_scores.sql
└── down/
    ├── 001_remove_stix_column.sql
    └── 002_remove_ml_scores.sql
```

Run migrations:
```bash
psql -U safeops -d safeops_threatintel -f migrations/up/001_add_stix_column.sql
```

---

## File Reference

### Schema Files (schemas/)

#### 001_initial_setup.sql
**Purpose**: Database foundation - creates database, roles, schemas, extensions, and enums

**Creates**:
- Database: `safeops_threatintel` (UTF-8, UTC timezone)
- Extensions: `uuid-ossp`, `pg_trgm`, `btree_gin`, `citext`, `pg_stat_statements`, `pgcrypto`
- Schemas: `threat_intel`, `audit`, `geo`
- Enums: 9 types (threat_category, threat_level, ioc_type, confidence_level, feed_status, anonymizer_type, tlp_level, action_type, feed_status)
- Roles: `ti_admin`, `ti_writer`, `ti_reader`, `ti_api`, `ti_ingest`, `safeops`
- Audit: `audit.change_log` table with triggers

**Key Features**:
- Role-based permissions (admin/writer/reader)
- Comprehensive audit logging
- Utility functions (IP/domain validation, threat scoring)
- Default grants for future objects

**Run By**: `postgres` user (database creation)

---

#### 002_ip_reputation.sql
**Purpose**: IP reputation tracking with history and blocklists

**Tables** (4):
1. `ip_reputation` - Main IP threat data (reputation score, threat category, anonymizer detection)
2. `ip_reputation_history` - Monthly partitioned history (12-month retention)
3. `ip_blocklist` - Fast lookup for blocked IPs
4. `ip_whitelist` - Trusted IP exceptions

**Key Features**:
- Reputation score (0-100) with threat categorization
- Anonymizer detection (VPN, Tor, Proxy)
- Multi-source aggregation
- Auto-update triggers for timestamps and history
- Helper functions: `lookup_ip()`, `check_ips_blocked()`, `upsert_ip_reputation()`

**Indexes**: Hash (IP), B-tree (threat level), GIN (sources, tags), Partial (critical threats)

---

#### 003_domain_reputation.sql
**Purpose**: Domain and URL reputation with DGA detection

**Tables** (5):
1. `domain_reputation` - Domain threat data with DGA/typosquat flags
2. `url_reputation` - Full URL reputation with malware tracking
3. `domain_categories` - Content filtering (adult, gambling, etc.)
4. `domain_blocklist` - Fast domain blocking
5. `domain_whitelist` - Trusted domain exceptions

**Key Features**:
- DGA (Domain Generation Algorithm) detection
- Typosquatting fuzzy matching (GIN trigram)
- Auto-extraction of parent domain and TLD
- WHOIS data storage (registration date, registrar)
- Helper functions: `lookup_domain()`, `search_similar_domains()`, `check_domain_policy()`

**Indexes**: GIN trigram (fuzzy search), Hash (domain), Partial (DGA/newly registered)

---

#### 004_hash_reputation.sql
**Purpose**: File hash malware detection

**Tables** (3):
1. `hash_reputation` - Multi-algorithm hash storage (MD5, SHA1, SHA256, SHA512, SSDEEP, IMPHASH)
2. `malware_families` - Catalog of known malware families
3. `hash_relationships` - Sample relationships (DROPS, VARIANT_OF, etc.)

**Key Features**:
- Auto-computed detection rate (% of AVs flagged)
- PE file analysis (imports, exports, signatures)
- Malware family linking with auto-update
- Sample relationship tracking
- Helper functions: `lookup_hash()`, `is_known_malware()`, `get_related_hashes()`

**Indexes**: Hash (hash_value), B-tree (family), GIN (sources, detected_by), Partial (malicious)

---

#### 005_ioc_storage.sql
**Purpose**: Generic IOC storage with campaign tracking

**Tables** (4):
1. `ioc_indicators` - Master IOC table (IP, domain, URL, hash, email)
2. `ioc_matches` - Detection events (daily partitioned, 90-day retention)
3. `ioc_campaigns` - Threat campaign grouping
4. `ioc_relationships` - IOC linkage (RESOLVES_TO, DROPS, etc.)

**Key Features**:
- MITRE ATT&CK TTP mapping
- Campaign/threat actor attribution
- Source reliability scoring (A-F grades)
- GIN trigram fuzzy search
- Daily partitioned matches (auto-created for 90 days)
- Helper functions: `lookup_ioc()`, `record_ioc_match()`, `get_campaign_iocs()`

**Indexes**: GIN trigram (fuzzy), B-tree (type), BRIN (time-series), Partial (active high-confidence)

---

#### 006_proxy_anonymizer.sql
**Purpose**: VPN, Tor, Proxy, and hosting IP detection

**Tables** (6):
1. `anonymizer_ips` - Main anonymizer detection table
2. `vpn_providers` - VPN service catalog (logging policies, jurisdictions)
3. `tor_exit_nodes` - Tor network tracking (exit policies, fingerprints)
4. `hosting_providers` - Cloud/datacenter IP ranges
5. `proxy_servers` - Individual proxy tracking
6. `residential_proxy_networks` - Residential proxy cataloging

**Key Features**:
- VPN privacy scoring (logging policy, abuse score)
- Tor bad exit detection
- Bulletproof hosting identification
- GiST indexed IP ranges for fast lookups
- Helper functions: `is_anonymizer()`, `is_tor_exit()`, `check_ip_anonymization()`

**Indexes**: Hash (IP), GiST (CIDR ranges), GIN (ASN arrays), Partial (high-risk)

---

#### 007_geolocation.sql
**Purpose**: IP geolocation and regional threat tracking

**Tables** (6):
1. `ip_geolocation` - IP→Location cache (30-day TTL)
2. `asn_information` - ASN registry (abuse contacts, RIR)
3. `threat_by_country` - Country-level threat aggregation with per-capita analysis
4. `regional_threat_stats` - Monthly partitioned regional stats
5. `continents` - Reference data (pre-populated)
6. `ip_to_asn` - Fast ASN lookup mapping

**Key Features**:
- Country→City→Coordinates hierarchy
- Per-capita threat analysis (threats per million population)
- Monthly partitioned regional stats (auto-created for 12 months)
- Haversine distance calculation between IPs
- Helper functions: `lookup_ip_location()`, `lookup_ip_asn()`, `ip_distance_km()`

**Indexes**: Hash (IP), B-tree (country/city), GiST (IP ranges), GIN (JSONB)

---

#### 008_threat_feeds.sql
**Purpose**: Threat feed management and monitoring

**Tables** (4):
1. `threat_feed_sources` - Feed configuration (auth, parsing, scheduling)
2. `feed_update_history` - Monthly partitioned update logs
3. `feed_statistics` - Daily aggregations with auto-computed uptime
4. `feed_health_checks` - Health monitoring results

**Key Features**:
- Auto-health status (HEALTHY/DEGRADED/DOWN based on failures)
- Auto-next update calculation
- Priority-based scheduling (1-10)
- Multiple auth types (API_KEY, BEARER, OAUTH, etc.)
- Helper functions: `get_feeds_due_for_update()`, `start_feed_update()`, `complete_feed_update()`

**Indexes**: B-tree (status, priority), Partial (enabled active feeds), GIN (tags)

---

#### 009_asn_data.sql
**Purpose**: Extended ASN information and reputation

**Tables** (5):
1. `asn_prefixes` - IP prefix assignments with GiST indexing
2. `asn_reputation` - ASN-level threat data with auto trust/risk levels
3. `asn_threat_history` - Monthly partitioned threat tracking
4. `asn_peers` - BGP peering relationships
5. `bogon_prefixes` - Reserved/invalid IP ranges (pre-populated with 14 ranges)

**Key Features**:
- Auto trust level (TRUSTED/NEUTRAL/SUSPICIOUS/MALICIOUS based on score)
- Threat density (computed: threats per IP in ASN)
- Bulletproof hosting detection
- Pre-populated bogon ranges (RFC 1918, etc.)
- Helper functions: `get_asn_for_ip()`, `is_bogon()`, `get_top_malicious_asns()`

**Indexes**: GiST (IP prefixes), B-tree (reputation), Partial (bulletproof/bad actors)

---

#### 999_indexes_and_maintenance.sql
**Purpose**: Performance optimization and automated maintenance

**Creates**:
- **Composite indexes**: Multi-column queries (type+value, country+city)
- **Partial indexes**: Filtered queries (active IOCs, recent threats)
- **Expression indexes**: Computed columns (date truncation)
- **Covering indexes**: Include columns to avoid table access

**Maintenance Functions**:
- `cleanup_expired_iocs()` - Remove expired indicators
- `cleanup_expired_blocklists()` - Clean IP/domain/hash blocklists
- `update_threat_statistics()` - Recalculate aggregations
- `archive_old_ioc_matches()` - Archive old matches (90+ days)
- `recalculate_all_reputations()` - Batch reputation updates
- `create_future_partitions()` - Auto-create partitions
- `drop_old_partitions()` - Remove old partitions (retention enforcement)

**Utility Functions**:
- `get_database_stats()` - Row counts for all tables
- `get_table_sizes()` - Disk usage analysis

**pg_cron Examples**: Daily cleanup, weekly stats, monthly archiving

---

### Seed Files (seeds/)

#### initial_threat_categories.sql
**Purpose**: Bootstrap database with reference data

**Populates**:
- **Malware Families** (15): Emotet, TrickBot, Ryuk, LockBit, WannaCry, Cobalt Strike, RedLine, Mirai, etc.
- **ASN Information** (8): Google, AWS, Cloudflare, Microsoft, Meta, DigitalOcean, Akamai
- **IP Whitelists** (6): Cloudflare CDN ranges, Google DNS
- **Domain Whitelists** (10): google.com, microsoft.com, github.com, etc.
- **Countries** (8): Initial threat tracking for US, CN, RU, DE, GB, FR, NL, IN
- **IOC Campaigns** (3): APT29 SolarWinds, Emotet Distribution, LockBit Ransomware
- **VPN Providers** (6): NordVPN, ExpressVPN, ProtonVPN, etc.

**Use Case**: Production initialization with known-good data

---

#### test_ioc_data.sql
**Purpose**: Sample test data for development and testing

**Populates**:
- **IP Reputations** (9): Malicious IPs, Tor exit nodes, VPN IPs, clean IPs (Google/Cloudflare DNS)
- **Domain Reputations** (7): Malware C2, phishing, DGA domains, legitimate sites
- **URL Reputations** (3): Malware download URLs, phishing pages
- **Hash Reputations** (4): Emotet, TrickBot, Cobalt Strike samples, clean files
- **IOC Indicators** (5): Sample IOCs with MITRE ATT&CK TTPs
- **Geolocation** (4): Sample IP→Location mappings
- **Anonymizer IPs** (3): Tor, VPN, Proxy samples

**Use Case**: Development, testing, demo environments

---

#### feed_sources_config.sql
**Purpose**: Pre-configure 20+ public threat feeds

**Feed Categories**:
- **IP Lists** (7): Firehol L1/L2, Feodo, SSL Blacklist, ET Compromised, Blocklist.de, CINS, Spamhaus DROP
- **Domain/URL** (4): URLhaus URLs/Domains, Phishing Army, OpenPhish
- **Hashes** (1): MalwareBazaar Recent
- **Anonymizers** (2): Tor Exit Nodes, VPN Gate
- **IOCs** (2): ThreatFox, AlienVault OTX (disabled - requires API key)
- **Geolocation** (2): MaxMind GeoLite2 City/ASN (disabled - requires processing)

**Features**:
- Priority-based scheduling (1-10)
- Pre-configured timeouts and retries
- Update frequencies (1-168 hours)
- Source type tagging

**Use Case**: Production feed initialization

---

### View Files (views/)

#### active_threats_view.sql
**Purpose**: Unified view of all active threats

**Views** (1):
- `active_threats` - Combines IPs, domains, hashes, and IOCs into single view

**Features**:
- 90-day recency filter
- Excludes whitelisted items
- CRITICAL/HIGH/MEDIUM severity only
- Unified schema across threat types
- Optional materialized view for performance

**Use Case**: Dashboard displays, threat hunting

**Query**: `SELECT * FROM threat_intel.active_threats LIMIT 100;`

---

#### high_confidence_iocs.sql
**Purpose**: Filtered views for high-confidence indicators

**Views** (7):
1. `high_confidence_iocs` - CONFIRMED/HIGH confidence IOCs with recency calculation
2. `critical_iocs` - Critical severity, seen in last 7 days
3. `high_confidence_ips` - High-confidence IP IOCs only
4. `high_confidence_domains` - High-confidence domain IOCs only
5. `high_confidence_hashes` - High-confidence hash IOCs only
6. `high_confidence_urls` - High-confidence URL IOCs only
7. `campaign_iocs` - IOCs grouped by campaign with statistics

**Features**:
- Computed confidence score (0-100)
- Recency categorization (VERY_RECENT, RECENT, CURRENT, OLDER)
- Validity checking
- Campaign attribution

**Use Case**: Automated blocking, SOC dashboards, SIEM integration

**Query**: `SELECT * FROM threat_intel.critical_iocs;`

---

#### threat_summary_stats.sql
**Purpose**: Dashboard statistics and metrics

**Views** (7):
1. `threat_summary_stats` - High-level metrics (total counts, 24h activity, feed health)
2. `threat_breakdown_by_severity` - Count/percentage by threat level
3. `threat_breakdown_by_category` - Count by threat category with severity breakdown
4. `feed_health_summary` - Feed health grouped by type
5. `top_malware_families` - Top 25 malware families by hash count
6. `recent_threat_activity` - Daily new threats for last 7 days
7. `top_threat_countries` - Top 25 countries by threat count

**Features**:
- Real-time statistics
- Percentage calculations
- Trend analysis (24h, 7d activity)
- Geographic threat distribution

**Use Case**: Executive dashboards, monitoring, reporting

**Query**: `SELECT * FROM threat_intel.threat_summary_stats;`

---

### Utility Scripts

#### init_database.sh
**Purpose**: Automated database initialization

**Steps**:
1. Create database, roles, extensions (as postgres user)
2. Create 9 core schemas in order (002-009)
3. Create indexes and maintenance (999)
4. Create views (3 files)
5. Optional: Load seed data (3 files)

**Features**:
- Color-coded output (✓ ✗ ▶)
- Progress tracking (1/5, 2/5, etc.)
- Error handling with exit codes
- Seed file counting and confirmation
- Post-install statistics display
- Quick command examples

**Environment Variables**:
```bash
DB_HOST=localhost        # Database server
DB_PORT=5432            # PostgreSQL port
DB_NAME=safeops_threatintel  # Database name
DB_USER=safeops         # Application user
ADMIN_USER=postgres     # Admin user for setup
```

**Usage**:
```bash
# Default settings
./init_database.sh

# Custom settings
DB_HOST=db.example.com DB_USER=custom_user ./init_database.sh
```

**Output**: Database statistics, connection string, next steps

---

### File Execution Order

**Correct Initialization Sequence**:
```
1. schemas/001_initial_setup.sql      (as postgres)
2. schemas/002_ip_reputation.sql      (as safeops)
3. schemas/003_domain_reputation.sql  (as safeops)
4. schemas/004_hash_reputation.sql    (as safeops)
5. schemas/005_ioc_storage.sql        (as safeops)
6. schemas/006_proxy_anonymizer.sql   (as safeops)
7. schemas/007_geolocation.sql        (as safeops)
8. schemas/008_threat_feeds.sql       (as safeops)
9. schemas/009_asn_data.sql           (as safeops)
10. schemas/999_indexes_and_maintenance.sql  (as safeops)
11. views/*.sql                        (as safeops)
12. seeds/*.sql (optional)             (as safeops)
```

**Dependencies**:
- 007 (geolocation) must run before 009 (asn_data) - references `geo.asn_information`
- 004 (hash_reputation) creates `malware_families` before 005 references it
- 001 must always run first (creates database and roles)
- 999 must run after all schemas (creates indexes on existing tables)

---

## Support & Contributing

- **Documentation**: [SafeOps Full Docs](../docs/)
- **Issues**: Create GitHub issue with `[database]` tag
- **Schema Changes**: Follow migration strategy above
- **Performance Issues**: Include `EXPLAIN ANALYZE` output
- **New Feeds**: Add to `seeds/feed_sources_config.sql` and submit PR

---

## License

SafeOps v2.0 - Threat Intelligence Database
Licensed under MIT License - See [LICENSE](../LICENSE) for details.

---

**Database Version**: 2.0.0  
**PostgreSQL Requirement**: 15+  
**Last Updated**: 2025-12-13
