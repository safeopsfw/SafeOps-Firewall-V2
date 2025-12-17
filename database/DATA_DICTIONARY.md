# SafeOps Database - Complete Data Dictionary

> **Database Schema Reference Guide**
>
> PostgreSQL 16+ | Version 2.0.0 | Updated: 2025-12-17

---

## 📋 Table of Contents

- [Database Overview](#database-overview)
- [Core Tables](#core-tables)
- [Relationship Diagram](#relationship-diagram)
- [Index Reference](#index-reference)
- [Constraint Reference](#constraint-reference)
- [Function Reference](#function-reference)
- [Query Patterns](#query-patterns)

---

## 🗄️ Database Overview

**Database Name:** `safeops_threat_intel`  
**Character Set:** UTF8  
**Collation:** en_US.UTF-8  
**Total Tables:** 52  
**Total Indexes:** 147  
**Total Functions:** 18  
**Total Views:** 3  
**Partitioned Tables:** 5

---

## 📊 Core Tables

### 1. ip_reputation

**Purpose:** Store IP address reputation scores with geographic and network context.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| ip_id | BIGSERIAL | NO | auto | Primary key, auto-incrementing |
| ip_address | INET | NO | - | IPv4/IPv6 address (unique) |
| reputation_score | INTEGER | YES | NULL | Score from -100 (malicious) to +100 (trusted) |
| confidence_level | NUMERIC(3,2) | YES | NULL | Confidence: 0.00 to 1.00 |
| threat_category_id | INTEGER | YES | NULL | FK to threat_categories |
| country_code | CHAR(2) | YES | NULL | ISO 3166-1 alpha-2 country code |
| city | VARCHAR(100) | YES | NULL | City name |
| continent_code | VARCHAR(2) | YES | NULL | Continent code (AF, AS, EU, NA, SA, OC, AN) |
| latitude | NUMERIC(9,6) | YES | NULL | Latitude coordinate |
| longitude | NUMERIC(9,6) | YES | NULL | Longitude coordinate |
| asn_number | BIGINT | YES | NULL | Autonomous System Number |
| hosting_provider | VARCHAR(200) | YES | NULL | Hosting company name |
| is_proxy | BOOLEAN | YES | FALSE | Proxy server indicator |
| is_vpn | BOOLEAN | YES | FALSE | VPN endpoint indicator |
| is_tor | BOOLEAN | YES | FALSE | TOR exit node indicator |
| is_datacenter | BOOLEAN | YES | FALSE | Datacenter IP indicator |
| source_feeds | INTEGER[] | YES | '{}' | Array of feed_id that reported this IP |
| first_seen | TIMESTAMPTZ | YES | NOW() | First time this IP was recorded |
| last_seen | TIMESTAMPTZ | YES | NOW() | Most recent sighting |
| last_updated | TIMESTAMPTZ | YES | NOW() | Last metadata update |
| tags | TEXT[] | YES | '{}' | Custom tags for categorization |
| notes | TEXT | YES | NULL | Admin notes |
| false_positive_flag | BOOLEAN | YES | FALSE | Marked as false positive |

**Partitioning:** LIST partitioned by `continent_code` (7 partitions)

**Partitions:**
- `ip_reputation_af` - Africa
- `ip_reputation_as` - Asia
- `ip_reputation_eu` - Europe
- `ip_reputation_na` - North America
- `ip_reputation_sa` - South America
- `ip_reputation_oc` - Oceania
- `ip_reputation_an` - Antarctica

**Constraints:**
- `pk_ip_reputation` PRIMARY KEY (ip_id)
- `uq_ip_reputation_address` UNIQUE (ip_address)
- `ck_ip_reputation_score` CHECK (reputation_score BETWEEN -100 AND 100)
- `ck_ip_reputation_confidence` CHECK (confidence_level BETWEEN 0 AND 1)
- `fk_ip_reputation_category` FOREIGN KEY (threat_category_id) REFERENCES threat_categories(category_id)

**Indexes:**
- `idx_ip_reputation_score` - B-tree (reputation_score DESC, last_seen DESC)
- `idx_ip_reputation_country` - B-tree (country_code)
- `idx_ip_reputation_asn` - B-tree (asn_number)
- `idx_ip_reputation_category` - B-tree (threat_category_id)
- `idx_ip_reputation_feeds` - GIN (source_feeds)
- `idx_ip_reputation_tags` - GIN (tags)
- `idx_ip_reputation_updated` - BRIN (last_updated)
- `idx_ip_reputation_proxy_flags` - B-tree (is_proxy, is_vpn, is_tor) WHERE any flag is TRUE

**Typical Row Size:** ~250 bytes  
**Expected Rows:** 100M+  
**Expected Size:** ~25 GB (uncompressed)

---

### 2. domain_reputation

**Purpose:** Domain name reputation with DNS properties and behavioral analysis.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| domain_id | BIGSERIAL | NO | auto | Primary key |
| domain_name | CITEXT | NO | - | Domain name (case-insensitive, unique) |
| parent_domain | CITEXT | YES | NULL | Parent domain (for subdomains) |
| tld | VARCHAR(50) | YES | NULL | Top-level domain (.com, .org, etc.) |
| is_subdomain | BOOLEAN | YES | FALSE | Subdomain indicator |
| reputation_score | INTEGER | YES | NULL | -100 to +100 |
| confidence_level | NUMERIC(3,2) | YES | NULL | 0.00 to 1.00 |
| threat_category_id | INTEGER | YES | NULL | FK to threat_categories |
| domain_age_days | INTEGER | YES | NULL | Days since registration |
| registrar | VARCHAR(200) | YES | NULL | Domain registrar |
| registration_date | DATE | YES | NULL | WHOIS registration date |
| expiration_date | DATE | YES | NULL | Domain expiration |
| has_mx_records | BOOLEAN | YES | NULL | MX records present |
| has_spf_record | BOOLEAN | YES | NULL | SPF record present |
| has_dmarc_record | BOOLEAN | YES | NULL | DMARC record present |
| nameservers | TEXT[] | YES | NULL | Authoritative nameservers |
| content_category | VARCHAR(100) | YES | NULL | Content classification |
| has_ssl | BOOLEAN | YES | FALSE | SSL certificate present |
| ssl_issuer | VARCHAR(200) | YES | NULL | Certificate authority |
| ssl_valid_until | TIMESTAMPTZ | YES | NULL | SSL expiration |
| dga_score | NUMERIC(3,2) | YES | NULL | Domain Generation Algorithm probability (0-1) |
| typosquatting_target | VARCHAR(255) | YES | NULL | Legitimate domain being impersonated |
| homograph_attack | BOOLEAN | YES | FALSE | IDN homograph attack indicator |
| source_feeds | INTEGER[] | YES | '{}' | Feed sources |
| blocked_by_feeds | INTEGER[] | YES | '{}' | Feeds that blocklist this domain |
| first_seen | TIMESTAMPTZ | YES | NOW() | First recorded |
| last_seen | TIMESTAMPTZ | YES | NOW() | Most recent |
| last_updated | TIMESTAMPTZ | YES | NOW() | Last update |
| query_count_24h | BIGINT | YES | 0 | DNS queries in last 24 hours |
| query_count_7d | BIGINT | YES | 0 | Last 7 days |
| query_count_30d | BIGINT | YES | 0 | Last 30 days |
| unique_clients_24h | INTEGER | YES | 0 | Unique IPs querying in 24h |
| tags | TEXT[] | YES | '{}' | Tags |
| notes | TEXT | YES | NULL | Notes |
| false_positive_flag | BOOLEAN | YES | FALSE | False positive marker |
| whitelisted | BOOLEAN | YES | FALSE | Explicitly whitelisted |

**Constraints:**
- `pk_domain_reputation` PRIMARY KEY (domain_id)
- `uq_domain_reputation_name` UNIQUE (domain_name)
- `ck_domain_reputation_score` CHECK (reputation_score BETWEEN -100 AND 100)
- `ck_domain_reputation_confidence` CHECK (confidence_level BETWEEN 0 AND 1)
- `ck_domain_reputation_dga` CHECK (dga_score BETWEEN 0 AND 1)

**Indexes:**
- `idx_domain_reputation_score` - B-tree (reputation_score DESC, last_seen DESC)
- `idx_domain_reputation_parent` - B-tree (parent_domain)
- `idx_domain_reputation_tld` - B-tree (tld)
- `idx_domain_reputation_category` - B-tree (threat_category_id)
- `idx_domain_reputation_dga` - B-tree (dga_score) WHERE dga_score > 0.5
- `idx_domain_reputation_tags` - GIN (tags)
- `idx_domain_reputation_feeds` - GIN (source_feeds)
- `idx_domain_reputation_trigram` - GIN (domain_name gin_trgm_ops) -- Fuzzy search
- `idx_domain_reputation_queries` - B-tree (query_count_24h DESC)

**Typical Row Size:** ~400 bytes  
**Expected Rows:** 50M+  
**Expected Size:** ~20 GB

---

### 3. hash_reputation

**Purpose:** File hash reputation supporting multiple hash algorithms.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| hash_id | BIGSERIAL | NO | auto | Primary key |
| md5_hash | CHAR(32) | YES | NULL | MD5 hash (lowercase hex) |
| sha1_hash | CHAR(40) | YES | NULL | SHA-1 hash |
| sha256_hash | CHAR(64) | YES | NULL | SHA-256 hash |
| sha512_hash | CHAR(128) | YES | NULL | SHA-512 hash |
| ssdeep_hash | VARCHAR(255) | YES | NULL | SSDeep fuzzy hash |
| file_size | BIGINT | YES | NULL | File size in bytes |
| file_type | VARCHAR(100) | YES | NULL | File type (PE, ELF, Mach-O, etc.) |
| file_extension | VARCHAR(50) | YES | NULL | Extension (.exe, .dll, etc.) |
| mime_type | VARCHAR(200) | YES | NULL | MIME type |
| reputation_score | INTEGER | YES | NULL | -100 to +100 |
| confidence_level | NUMERIC(3,2) | YES | NULL | 0.00 to 1.00 |
| threat_category_id | INTEGER | YES | NULL | FK to threat_categories |
| malware_family | VARCHAR(200) | YES | NULL | Malware family name |
| malware_variant | VARCHAR(200) | YES | NULL | Specific variant |
| is_packed | BOOLEAN | YES | FALSE | File is packed |
| packer_type | VARCHAR(100) | YES | NULL | Packer used (UPX, etc.) |
| av_detections | INTEGER | YES | 0 | Number of AV engines detecting |
| av_total_engines | INTEGER | YES | 0 | Total AV engines tested |
| sandbox_score | INTEGER | YES | NULL | Sandbox behavior score (0-100) |
| creates_process | BOOLEAN | YES | NULL | Creates child processes |
| modifies_registry | BOOLEAN | YES | NULL | Modifies Windows registry |
| network_activity | BOOLEAN | YES | NULL | Makes network connections |
| file_operations | BOOLEAN | YES | NULL | File system operations |
| pe_imphash | CHAR(32) | YES | NULL | PE import hash |
| pe_compile_time | TIMESTAMPTZ | YES | NULL | PE compilation timestamp |
| pe_signature_valid | BOOLEAN | YES | NULL | Valid digital signature |
| pe_signer | VARCHAR(255) | YES | NULL | Code signing certificate |
| source_feeds | INTEGER[] | YES | '{}' | Feed sources |
| first_seen | TIMESTAMPTZ | YES | NOW() | First seen |
| last_seen | TIMESTAMPTZ | YES | NOW() | Last seen |
| last_updated | TIMESTAMPTZ | YES | NOW() | Last updated |
| seen_count | BIGINT | YES | 1 | Total sightings |
| unique_sources | INTEGER | YES | 1 | Unique reporting sources |
| tags | TEXT[] | YES | '{}' | Tags |
| notes | TEXT | YES | NULL | Notes |
| false_positive_flag | BOOLEAN | YES | FALSE | False positive |

**Constraints:**
- `pk_hash_reputation` PRIMARY KEY (hash_id)
- `uq_hash_reputation_md5` UNIQUE (md5_hash) WHERE md5_hash IS NOT NULL
- `uq_hash_reputation_sha1` UNIQUE (sha1_hash) WHERE sha1_hash IS NOT NULL
- `uq_hash_reputation_sha256` UNIQUE (sha256_hash) WHERE sha256_hash IS NOT NULL
- `uq_hash_reputation_sha512` UNIQUE (sha512_hash) WHERE sha512_hash IS NOT NULL
- `ck_hash_at_least_one` CHECK (md5_hash IS NOT NULL OR sha1_hash IS NOT NULL OR sha256_hash IS NOT NULL OR sha512_hash IS NOT NULL)
- `ck_hash_reputation_score` CHECK (reputation_score BETWEEN -100 AND 100)
- `ck_hash_sandbox_score` CHECK (sandbox_score BETWEEN 0 AND 100)

**Indexes:**
- `idx_hash_reputation_score` - B-tree (reputation_score DESC)
- `idx_hash_reputation_family` - B-tree (malware_family)
- `idx_hash_reputation_category` - B-tree (threat_category_id)
- `idx_hash_reputation_tags` - GIN (tags)
- `idx_hash_reputation_feeds` - GIN (source_feeds)
- `idx_hash_reputation_pe_imphash` - B-tree (pe_imphash) WHERE pe_imphash IS NOT NULL

**Typical Row Size:** ~600 bytes  
**Expected Rows:** 10M+  
**Expected Size:** ~6 GB

---

### 4. ioc_indicators

**Purpose:** Indicators of Compromise with STIX/TAXII support.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| ioc_id | BIGSERIAL | NO | auto | Primary key |
| ioc_type | VARCHAR(50) | NO | - | Type of indicator |
| ioc_value | TEXT | NO | - | Indicator value |
| severity | VARCHAR(20) | YES | NULL | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| confidence_level | NUMERIC(3,2) | YES | NULL | 0.00 to 1.00 |
| threat_category_id | INTEGER | YES | NULL | FK to threat_categories |
| campaign_id | BIGINT | YES | NULL | FK to threat_campaigns |
| threat_actor | VARCHAR(200) | YES | NULL | Attribution |
| attack_technique | VARCHAR(200) | YES | NULL | MITRE ATT&CK technique |
| stix_id | VARCHAR(255) | YES | NULL | STIX 2.x identifier |
| stix_version | VARCHAR(10) | YES | NULL | STIX version |
| taxii_collection | VARCHAR(200) | YES | NULL | TAXII collection name |
| description | TEXT | YES | NULL | IOC description |
| context | JSONB | YES | NULL | Flexible metadata |
| is_active | BOOLEAN | YES | TRUE | Active indicator |
| is_validated | BOOLEAN | YES | FALSE | Verified by analyst |
| requires_investigation | BOOLEAN | YES | FALSE | Needs review |
| source_feed_id | INTEGER | YES | NULL | FK to threat_feeds |
| first_seen | TIMESTAMPTZ | YES | NOW() | First seen |
| last_seen | TIMESTAMPTZ | YES | NOW() | Last seen |
| expires_at | TIMESTAMPTZ | YES | NULL | Expiration time |
| sighting_count | BIGINT | YES | 0 | Times observed |
| last_sighting | TIMESTAMPTZ | YES | NULL | Most recent sighting |
| related_iocs | BIGINT[] | YES | '{}' | Related IOC IDs |
| tags | TEXT[] | YES | '{}' | Tags |
| notes | TEXT | YES | NULL | Notes |
| false_positive_flag | BOOLEAN | YES | FALSE | False positive |

**Partitioning:** LIST partitioned by `ioc_type`

**Partitions:**
- `ioc_indicators_ip` - IP, CIDR
- `ioc_indicators_domain` - DOMAIN, URL, EMAIL
- `ioc_indicators_hash` - HASH_MD5, HASH_SHA1, HASH_SHA256, HASH_SHA512
- `ioc_indicators_system` - MUTEX, REGISTRY_KEY, FILE_PATH, USER_AGENT
- `ioc_indicators_other` - ASN, CVE, etc.

**Constraints:**
- `pk_ioc_indicators` PRIMARY KEY (ioc_id)
- `uq_ioc_type_value` UNIQUE (ioc_type, ioc_value)
- `ck_ioc_type` CHECK (ioc_type IN (...))
- `ck_ioc_severity` CHECK (severity IN (...))
- `ck_ioc_confidence` CHECK (confidence_level BETWEEN 0 AND 1)

**Indexes:**
- `idx_ioc_type` - B-tree (ioc_type)
- `idx_ioc_severity` - B-tree (severity) WHERE is_active = TRUE
- `idx_ioc_campaign` - B-tree (campaign_id)
- `idx_ioc_technique` - B-tree (attack_technique)
- `idx_ioc_stix` - B-tree (stix_id) WHERE stix_id IS NOT NULL
- `idx_ioc_context` - GIN (context)
- `idx_ioc_tags` - GIN (tags)
- `idx_ioc_expires` - B-tree (expires_at) WHERE expires_at IS NOT NULL

**Typical Row Size:** ~500 bytes  
**Expected Rows:** 25M+  
**Expected Size:** ~12 GB

---

### 5. threat_feeds

**Purpose:** Configuration for external threat intelligence feeds.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| feed_id | SERIAL | NO | auto | Primary key |
| feed_name | VARCHAR(100) | NO | - | Feed name (unique) |
| feed_provider | VARCHAR(200) | NO | - | Provider organization |
| feed_url | TEXT | NO | - | Feed endpoint URL |
| feed_type | VARCHAR(50) | NO | - | CSV, JSON, XML, TAXII, STIX, API |
| requires_auth | BOOLEAN | YES | FALSE | Authentication required |
| auth_type | VARCHAR(50) | YES | NULL | NONE, API_KEY, BASIC, BEARER, OAUTH2 |
| credential_vault_id | UUID | YES | NULL | Encrypted credential reference |
| update_frequency_hours | INTEGER | YES | 24 | Hours between updates |
| last_update | TIMESTAMPTZ | YES | NULL | Last successful update |
| next_scheduled_update | TIMESTAMPTZ | YES | NULL | Next update time |
| reliability_score | INTEGER | YES | NULL | 0-100 reliability rating |
| false_positive_rate | NUMERIC(5,4) | YES | NULL | Observed FP rate |
| data_freshness_hours | INTERVAL | YES | NULL | Typical data age |
| is_active | BOOLEAN | YES | TRUE | Feed enabled |
| consecutive_failures | INTEGER | YES | 0 | Failed update attempts |
| last_error | TEXT | YES | NULL | Last error message |
| last_success | TIMESTAMPTZ | YES | NULL | Last successful fetch |
| parser_config | JSONB | YES | NULL | Custom parsing configuration |
| priority | INTEGER | YES | 50 | Feed priority (0-100) |
| auto_validate | BOOLEAN | YES | FALSE | Auto-validate indicators |
| retention_days | INTEGER | YES | 90 | Data retention period |
| total_records_added | BIGINT | YES | 0 | Lifetime records added |
| total_records_updated | BIGINT | YES | 0 | Lifetime updates |
| avg_processing_time_ms | INTEGER | YES | NULL | Average processing time |
| description | TEXT | YES | NULL | Feed description |
| documentation_url | TEXT | YES | NULL | Documentation link |
| tags | TEXT[] | YES | '{}' | Tags |
| created_at | TIMESTAMPTZ | YES | NOW() | Created timestamp |
| updated_at | TIMESTAMPTZ | YES | NOW() | Updated timestamp |

**Constraints:**
- `pk_threat_feeds` PRIMARY KEY (feed_id)
- `uq_threat_feeds_name` UNIQUE (feed_name)
- `ck_threat_feeds_type` CHECK (feed_type IN (...))
- `ck_threat_feeds_auth` CHECK (auth_type IN (...))
- `ck_threat_feeds_reliability` CHECK (reliability_score BETWEEN 0 AND 100)
- `ck_threat_feeds_priority` CHECK (priority BETWEEN 0 AND 100)

**Indexes:**
- `idx_threat_feeds_active` - B-tree (is_active, priority DESC)
- `idx_threat_feeds_next_update` - B-tree (next_scheduled_update) WHERE is_active = TRUE
- `idx_threat_feeds_tags` - GIN (tags)

**Typical Row Size:** ~800 bytes  
**Expected Rows:** ~100  
**Expected Size:** <1 MB

---

### 6. threat_categories

**Purpose:** Hierarchical threat classification taxonomy.

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| category_id | SERIAL | NO | auto | Primary key |
| category_name | VARCHAR(100) | NO | - | Category name (unique) |
| category_code | VARCHAR(50) | NO | - | Short code (unique) |
| parent_category_id | INTEGER | YES | NULL | Parent category (self-reference) |
| severity_default | VARCHAR(20) | YES | NULL | Default severity |
| description | TEXT | YES | NULL | Category description |
| mitigation_advice | TEXT | YES | NULL | Recommended mitigations |
| is_active | BOOLEAN | YES | TRUE | Category active |
| display_order | INTEGER | YES | 0 | Display sort order |

**Constraints:**
- `pk_threat_categories` PRIMARY KEY (category_id)
- `uq_threat_categories_name` UNIQUE (category_name)
- `uq_threat_categories_code` UNIQUE (category_code)
- `fk_threat_categories_parent` FOREIGN KEY (parent_category_id) REFERENCES threat_categories(category_id)
- `ck_threat_categories_severity` CHECK (severity_default IN (...))

**Indexes:**
- `idx_threat_categories_parent` - B-tree (parent_category_id)
- `idx_threat_categories_display` - B-tree (display_order)

**Pre-loaded Categories:** 37 (see seeds/initial_threat_categories.sql)

**Typical Row Size:** ~300 bytes  
**Expected Rows:** ~100  
**Expected Size:** <1 MB

---

## 🔗 Relationship Diagram

```
threat_feeds (1) ─────< (M) ioc_indicators
                              │
                              │ (M)
                              ▼
                         threat_categories (1)
                              ▲
                              │ (M)
                  ┌───────────┼───────────┬───────────┐
                  │           │           │           │
                  │           │           │           │
           ip_reputation  domain_reputation  hash_reputation  asn_data
                  │
                  │ (M)
                  ▼
            geolocation_data (1)

threat_campaigns (1) ──< (M) ioc_indicators
                              │
                              │ (M)
                              ▼
                         ioc_sightings (M)
```

---

## 🔍 Index Reference

### B-Tree Indexes (Most Common)

Used for:
- Equality searches (`WHERE column = value`)
- Range queries (`WHERE column BETWEEN a AND b`)
- Sorting (`ORDER BY column`)
- Joins

**Examples:**
```sql
idx_ip_reputation_score (reputation_score DESC, last_seen DESC)
idx_domain_reputation_tld (tld)
idx_hash_reputation_family (malware_family)
```

### GIN Indexes (Generalized Inverted Index)

Used for:
- Array searches (`WHERE array @> ARRAY[value]`)
- Full-text search
- JSONB queries
- Trigram fuzzy matching

**Examples:**
```sql
idx_ip_reputation_tags (tags)              -- Array containment
idx_domain_reputation_trigram (domain_name gin_trgm_ops)  -- Fuzzy search
idx_ioc_context (context)                  -- JSONB search
```

### BRIN Indexes (Block Range Index)

Used for:
- Very large tables
- Columns with natural ordering (timestamps, IDs)
- Low cardinality with good correlation

**Examples:**
```sql
idx_ip_reputation_updated (last_updated)
```

### GIST Indexes (Generalized Search Tree)

Used for:
- Geometric data
- IP range searches
- Full-text search (alternative to GIN)

**Examples:**
```sql
idx_geolocation_ip_range (inet_range(ip_start, ip_end))
```

---

## 🛡️ Constraint Reference

### Primary Keys
- Auto-incrementing BIGSERIAL for high-volume tables (ip_reputation, domain_reputation, etc.)
- SERIAL for configuration tables (threat_feeds, threat_categories)

### Foreign Keys
- All have `ON DELETE RESTRICT` by default (prevent orphans)
- Use indexes on FK columns for join performance

### Check Constraints
- **Reputation scores**: -100 to +100
- **Confidence levels**: 0.00 to 1.00
- **Sandbox scores**: 0 to 100
- **Enumerated types**: Use CHECK for allowed values

### Unique Constraints
- **Partial unique**: `WHERE column IS NOT NULL` for optional unique fields
- **Composite unique**: (ioc_type, ioc_value) for IOCs

---

## ⚙️ Function Reference

### Maintenance Functions

| Function | Purpose | Schedule |
|----------|---------|----------|
| `cleanup_expired_records()` | Remove expired IOCs and old data | Daily 2:00 AM |
| `update_reputation_scores()` | Recalculate scores with decay | Daily 3:00 AM |
| `vacuum_and_analyze_tables()` | Database maintenance | Daily 4:00 AM |
| `partition_maintenance()` | Create/drop partitions | Weekly Sunday 1:00 AM |
| `update_statistics()` | Refresh aggregated stats | Hourly |
| `detect_anomalies()` | Anomaly detection | Hourly |

### Query Helper Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `get_ip_reputation()` | `(inet) → record` | Quick IP lookup |
| `get_domain_reputation()` | `(text) → record` | Quick domain lookup |
| `get_hash_reputation()` | `(text, text) → record` | Lookup by any hash type |
| `calculate_threat_score()` | `(int, numeric, int[]) → int` | Weighted score calculation |
| `is_ip_in_range()` | `(inet, inet, inet) → boolean` | IP range membership |

---

## 📈 Query Patterns

### High-Performance IP Lookup

```sql
-- Using partition pruning and index
SELECT 
    reputation_score,
    confidence_level,
    threat_category_id,
    is_proxy,
    country_code
FROM ip_reputation
WHERE ip_address = '203.0.113.10'::inet;

-- Optimizations:
-- 1. Exact match on unique index
-- 2. Partition pruning (if continent known)
-- 3. Index-only scan possible
-- Expected: <1ms on 100M rows
```

### Domain Fuzzy Search (Typosquatting)

```sql
-- Using trigram index for similarity
SELECT 
    domain_name,
    reputation_score,
    similarity(domain_name, 'google.com') AS sim_score
FROM domain_reputation
WHERE domain_name % 'google.com'  -- Trigram similarity operator
  AND similarity(domain_name, 'google.com') > 0.3
ORDER BY sim_score DESC
LIMIT 20;

-- Optimizations:
-- 1. GIN trigram index
-- 2. Threshold filtering
-- Expected: <100ms on 50M rows
```

### Multi-Hash File Lookup

```sql
-- Query ANY hash type
SELECT *
FROM hash_reputation
WHERE sha256_hash = 'abc123...'
   OR md5_hash = 'def456...'
   OR sha1_hash = 'ghi789...';

-- Optimizations:
-- 1. Each hash has unique index
-- 2. Index-only scans
-- 3. Bitmap OR of index scans
-- Expected: <5ms
```

### Active Threat Dashboard

```sql
-- Using pre-built view
SELECT 
    threat_type,
    threat_value,
    severity,
    priority,
    action_recommended,
    last_seen
FROM active_threats_view
WHERE priority >= 75
  AND action_recommended = 'BLOCK'
  AND is_active = TRUE
ORDER BY priority DESC, last_seen DESC
LIMIT 100;

-- Optimizations:
-- 1. Materialized view (refreshed hourly)
-- 2. Composite index on (priority, last_seen)
-- Expected: <10ms
```

### Geographic Threat Distribution

```sql
-- Aggregation with partition pruning
SELECT 
    country_code,
    COUNT(*) AS threat_count,
    AVG(reputation_score) AS avg_score,
    COUNT(*) FILTER (WHERE reputation_score < -75) AS critical_count
FROM ip_reputation
WHERE reputation_score < -50
  AND last_seen > NOW() - INTERVAL '7 days'
GROUP BY country_code
ORDER BY threat_count DESC
LIMIT 20;

-- Optimizations:
-- 1. Index on (reputation_score, last_seen)
-- 2. Parallel aggregation
-- 3. Partial index for negative scores
-- Expected: <500ms on 100M rows
```

### IOC Campaign Correlation

```sql
-- Join IOCs to campaigns
SELECT 
    tc.campaign_name,
    tc.threat_actor,
    COUNT(*) AS ioc_count,
    COUNT(*) FILTER (WHERE i.is_active) AS active_count,
    MAX(i.last_seen) AS most_recent_sighting
FROM ioc_indicators i
JOIN threat_campaigns tc ON i.campaign_id = tc.campaign_id
WHERE i.severity IN ('CRITICAL', 'HIGH')
GROUP BY tc.campaign_id, tc.campaign_name, tc.threat_actor
HAVING COUNT(*) FILTER (WHERE i.is_active) > 0
ORDER BY most_recent_sighting DESC;

-- Optimizations:
-- 1. FK index on campaign_id
-- 2. Partial index on severity
-- Expected: <100ms
```

### Feed Health Monitoring

```sql
-- Check feed status
SELECT 
    feed_name,
    feed_provider,
    is_active,
    last_update,
    next_scheduled_update,
    consecutive_failures,
    reliability_score,
    total_records_added,
    CASE 
        WHEN consecutive_failures >= 3 THEN 'CRITICAL'
        WHEN consecutive_failures >= 1 THEN 'WARNING'
        WHEN last_update IS NULL THEN 'NEW'
        WHEN last_update < NOW() - (update_frequency_hours * INTERVAL '1 hour') * 2 THEN 'STALE'
        ELSE 'OK'
    END AS health_status
FROM threat_feeds
ORDER BY 
    CASE health_status 
        WHEN 'CRITICAL' THEN 1
        WHEN 'WARNING' THEN 2
        WHEN 'STALE' THEN 3
        WHEN 'OK' THEN 4
        WHEN 'NEW' THEN 5
    END,
    priority DESC;
```

---

## 📊 Performance Benchmarks

| Operation | Rows | Index | Time | Notes |
|-----------|------|-------|------|-------|
| IP exact match | 100M | B-tree (unique) | <1ms | Hot cache |
| Domain lookup | 50M | B-tree (unique) | <1ms | CITEXT |
| Hash any-type | 10M | 4x B-tree (unique) | <5ms | Bitmap OR |
| Fuzzy domain | 50M | GIN trigram | <100ms | Top-20 results |
| IP range scan | 100M | BRIN | 10-50ms | 7-day range |
| Aggregate by country | 100M | B-tree + parallel | <500ms | 20 countries |
| IOC join campaign | 25M | FK index | <100ms | Active only |
| Full table scan | 100M | Sequential | 30-60s | Avoid! |

**Test Environment:**
- PostgreSQL 16.1
- 32 GB RAM (8 GB shared_buffers)
- NVMe SSD storage
- 8-core CPU

---

## 🔧 Optimization Tips

### Query Optimization
1. **Always use indexes**: Check with `EXPLAIN ANALYZE`
2. **Partition pruning**: Filter on partition key when possible
3. **Partial indexes**: For common filters (e.g., `WHERE is_active = TRUE`)
4. **Covering indexes**: Include all SELECT columns to avoid table lookup
5. **Parallel queries**: Enable for large aggregations

### Index Selection
- **Unique columns**: B-tree unique index
- **Range queries**: B-tree index
- **Arrays**: GIN index
- **JSONB**: GIN index
- **Time series**: BRIN index (large tables)
- **Text search**: GIN trigram index

### Common Anti-Patterns
❌ `SELECT *` from large tables  
❌ `OR` conditions on different columns (breaks index usage)  
❌ Function calls on indexed columns (`LOWER(domain_name) = ...`)  
❌ Missing indexes on foreign keys  
❌ No `LIMIT` on unbounded queries  

✅ Use specific column lists  
✅ Separate queries or UNION  
✅ Use CITEXT or functional indexes  
✅ Always index FKs  
✅ Always use LIMIT for UI queries  

---

**Document Version:** 2.0.0  
**Last Updated:** 2025-12-17  
**Maintainer:** SafeOps Database Team
