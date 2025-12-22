# Threat Intelligence Database Map

## Database: `threat_intel_db` (PostgreSQL 18)

---

## Tables Overview

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   ip_geolocation    │    │    ip_blacklist     │    │  ip_anonymization   │
│   (Reference Data)  │    │   (Threat Data)     │    │   (VPN/Tor/Proxy)   │
│   ───────────────   │    │   ───────────────   │    │   ───────────────   │
│   ip_address (PK)   │    │   ip_address (PK)   │    │   ip_address (PK)   │
│   country_code      │    │   threat_score      │    │   is_vpn            │
│   city, region      │    │   abuse_type        │    │   is_tor            │
│   lat/lon           │    │   malware_family    │    │   is_proxy          │
│   asn, isp          │    │   confidence        │    │   provider_name     │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘

┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│      domains        │    │       hashes        │    │        iocs         │
│ (Domain Reputation) │    │  (File Hashes)      │    │ (Generic IOCs)      │
│   ───────────────   │    │   ───────────────   │    │   ───────────────   │
│   domain (PK)       │    │   sha256 (PK)       │    │   ioc_type+value    │
│   threat_score      │    │   md5, sha1         │    │   threat_type       │
│   category          │    │   malware_family    │    │   confidence        │
│   registration_date │    │   av_detection_rate │    │   severity          │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘

┌─────────────────────┐    ┌─────────────────────┐
│    threat_feeds     │───▶│    feed_history     │
│  (Feed Config)      │    │  (Execution Logs)   │
│   ───────────────   │    │   ───────────────   │
│   feed_name (PK)    │    │   feed_id (FK)      │
│   feed_url          │    │   status            │
│   update_frequency  │    │   records_added     │
└─────────────────────┘    └─────────────────────┘
```

---

## Table 1: `ip_geolocation`

**Purpose:** IP address location and network information (reference data)

| Column            | Type          | Constraints      | Description               |
| ----------------- | ------------- | ---------------- | ------------------------- |
| `id`              | BIGSERIAL     | PRIMARY KEY      | Auto-increment ID         |
| `ip_address`      | INET          | NOT NULL, UNIQUE | IPv4/IPv6 address         |
| `country_code`    | VARCHAR(2)    |                  | ISO 2-letter code         |
| `country_name`    | VARCHAR(100)  |                  | Full country name         |
| `city`            | VARCHAR(100)  |                  | City name                 |
| `region`          | VARCHAR(100)  |                  | State/Province            |
| `postal_code`     | VARCHAR(20)   |                  | ZIP/Postal code           |
| `latitude`        | DECIMAL(10,8) |                  | -90 to +90                |
| `longitude`       | DECIMAL(11,8) |                  | -180 to +180              |
| `accuracy_radius` | INTEGER       |                  | Accuracy in KM            |
| `asn`             | INTEGER       |                  | Autonomous System Number  |
| `asn_org`         | VARCHAR(255)  |                  | ASN Organization          |
| `isp`             | VARCHAR(255)  |                  | Internet Service Provider |
| `connection_type` | VARCHAR(50)   |                  | Cable/DSL/Cellular        |
| `timezone`        | VARCHAR(50)   |                  | IANA timezone             |
| `is_mobile`       | BOOLEAN       | DEFAULT FALSE    | Mobile network?           |
| `is_hosting`      | BOOLEAN       | DEFAULT FALSE    | Datacenter IP?            |
| `sources`         | JSONB         | DEFAULT '[]'     | Source names array        |
| `confidence`      | INTEGER       | DEFAULT 50       | 0-100 confidence          |
| `last_updated`    | TIMESTAMP     | DEFAULT NOW()    | Last update time          |
| `created_at`      | TIMESTAMP     | DEFAULT NOW()    | Creation time             |

**Indexes:** `ip_address`, `country_code`, `asn`, `city`, `last_updated`

---

## Table 2: `ip_blacklist`

**Purpose:** Malicious and blacklisted IP addresses (threat data)

| Column                 | Type         | Constraints      | Description                 |
| ---------------------- | ------------ | ---------------- | --------------------------- |
| `id`                   | BIGSERIAL    | PRIMARY KEY      | Auto-increment ID           |
| `ip_address`           | INET         | NOT NULL, UNIQUE | IPv4/IPv6 address           |
| `is_malicious`         | BOOLEAN      | DEFAULT TRUE     | Currently malicious?        |
| `threat_score`         | INTEGER      | CHECK 0-100      | Threat score                |
| `reputation_score`     | INTEGER      | CHECK 0-100      | Reputation score            |
| `abuse_type`           | VARCHAR(50)  |                  | spam, malware, phishing, c2 |
| `threat_category`      | VARCHAR(100) |                  | Specific category           |
| `malware_family`       | VARCHAR(100) |                  | Associated malware          |
| `confidence`           | INTEGER      | CHECK 0-100      | Detection confidence        |
| `evidence_count`       | INTEGER      | DEFAULT 1        | Sources reporting this      |
| `false_positive_count` | INTEGER      | DEFAULT 0        | False positive count        |
| `attack_types`         | JSONB        | DEFAULT '[]'     | Attack types array          |
| `target_ports`         | JSONB        | DEFAULT '[]'     | Targeted ports              |
| `target_services`      | JSONB        | DEFAULT '[]'     | Targeted services           |
| `description`          | TEXT         |                  | Description                 |
| `notes`                | TEXT         |                  | Analyst notes               |
| `tags`                 | JSONB        | DEFAULT '[]'     | Custom tags                 |
| `sources`              | JSONB        | DEFAULT '[]'     | Source names                |
| `raw_data`             | JSONB        |                  | Original source data        |
| `status`               | VARCHAR(20)  | DEFAULT 'active' | active/expired/whitelisted  |
| `first_seen`           | TIMESTAMP    | DEFAULT NOW()    | First detection             |
| `last_seen`            | TIMESTAMP    | DEFAULT NOW()    | Last seen active            |
| `last_updated`         | TIMESTAMP    | DEFAULT NOW()    | Last update                 |
| `expires_at`           | TIMESTAMP    |                  | Expiration date             |

**Indexes:** `ip_address`, `is_malicious`, `threat_score DESC`, `abuse_type`, `status`, `first_seen`, `expires_at`, `tags (GIN)`

---

## Table 3: `ip_anonymization`

**Purpose:** VPN, Tor, Proxy, and datacenter IP detection

| Column             | Type         | Constraints      | Description                 |
| ------------------ | ------------ | ---------------- | --------------------------- |
| `id`               | BIGSERIAL    | PRIMARY KEY      | Auto-increment ID           |
| `ip_address`       | INET         | NOT NULL, UNIQUE | IPv4/IPv6 address           |
| `is_vpn`           | BOOLEAN      | DEFAULT FALSE    | VPN endpoint?               |
| `is_tor`           | BOOLEAN      | DEFAULT FALSE    | Tor node?                   |
| `is_proxy`         | BOOLEAN      | DEFAULT FALSE    | Proxy server?               |
| `is_datacenter`    | BOOLEAN      | DEFAULT FALSE    | Datacenter IP?              |
| `is_relay`         | BOOLEAN      | DEFAULT FALSE    | Relay server?               |
| `is_hosting`       | BOOLEAN      | DEFAULT FALSE    | Hosting provider?           |
| `provider_name`    | VARCHAR(255) |                  | NordVPN, ExpressVPN, etc    |
| `service_type`     | VARCHAR(50)  |                  | commercial_vpn, free_vpn    |
| `anonymity_level`  | VARCHAR(20)  |                  | transparent/anonymous/elite |
| `tor_exit_node`    | BOOLEAN      | DEFAULT FALSE    | Tor exit node?              |
| `tor_node_name`    | VARCHAR(255) |                  | Tor node fingerprint        |
| `proxy_type`       | VARCHAR(20)  |                  | http/https/socks4/socks5    |
| `proxy_port`       | INTEGER      |                  | Proxy port number           |
| `datacenter_name`  | VARCHAR(255) |                  | Datacenter name             |
| `hosting_provider` | VARCHAR(255) |                  | AWS, Azure, etc             |
| `country_code`     | VARCHAR(2)   |                  | Location country            |
| `city`             | VARCHAR(100) |                  | Location city               |
| `risk_score`       | INTEGER      | CHECK 0-100      | Risk score                  |
| `abuse_history`    | BOOLEAN      | DEFAULT FALSE    | Has abuse history?          |
| `is_active`        | BOOLEAN      | DEFAULT TRUE     | Currently active?           |
| `sources`          | JSONB        | DEFAULT '[]'     | Source names                |
| `tags`             | JSONB        | DEFAULT '[]'     | Custom tags                 |
| `first_seen`       | TIMESTAMP    | DEFAULT NOW()    | First detection             |
| `last_seen`        | TIMESTAMP    | DEFAULT NOW()    | Last seen                   |
| `last_updated`     | TIMESTAMP    | DEFAULT NOW()    | Last update                 |

**Indexes:** `ip_address`, `is_vpn`, `is_tor`, `is_proxy`, `is_datacenter`, `provider_name`, `is_active`

---

## Table 4: `domains`

**Purpose:** Domain reputation and intelligence

| Column               | Type         | Constraints             | Description              |
| -------------------- | ------------ | ----------------------- | ------------------------ |
| `id`                 | BIGSERIAL    | PRIMARY KEY             | Auto-increment ID        |
| `domain`             | VARCHAR(255) | NOT NULL, UNIQUE        | Full domain name         |
| `tld`                | VARCHAR(50)  |                         | .com, .org, .net         |
| `subdomain`          | VARCHAR(255) |                         | www, mail, api           |
| `root_domain`        | VARCHAR(255) |                         | example.com              |
| `is_malicious`       | BOOLEAN      | DEFAULT FALSE           | Currently malicious?     |
| `threat_score`       | INTEGER      | CHECK 0-100             | Threat score             |
| `reputation_score`   | INTEGER      | CHECK 0-100, DEFAULT 50 | Reputation               |
| `category`           | VARCHAR(100) |                         | phishing, malware, c2    |
| `subcategory`        | VARCHAR(100) |                         | Subcategory              |
| `threat_types`       | JSONB        | DEFAULT '[]'            | Threat types array       |
| `registrar`          | VARCHAR(255) |                         | Domain registrar         |
| `registration_date`  | TIMESTAMP    |                         | When registered          |
| `expiration_date`    | TIMESTAMP    |                         | When expires             |
| `registrant_name`    | VARCHAR(255) |                         | Owner name               |
| `registrant_org`     | VARCHAR(255) |                         | Owner organization       |
| `registrant_country` | VARCHAR(2)   |                         | Owner country            |
| `nameservers`        | JSONB        |                         | NS records               |
| `dns_records`        | JSONB        |                         | A, MX, TXT, etc          |
| `ip_addresses`       | JSONB        | DEFAULT '[]'            | Resolved IPs             |
| `has_ssl`            | BOOLEAN      | DEFAULT FALSE           | Has SSL cert?            |
| `ssl_issuer`         | VARCHAR(255) |                         | Certificate issuer       |
| `phishing_target`    | VARCHAR(100) |                         | PayPal, Microsoft, etc   |
| `malware_families`   | JSONB        | DEFAULT '[]'            | Associated malware       |
| `detection_count`    | INTEGER      | DEFAULT 0               | Times flagged            |
| `tags`               | JSONB        | DEFAULT '[]'            | Custom tags              |
| `sources`            | JSONB        | DEFAULT '[]'            | Source names             |
| `status`             | VARCHAR(20)  | DEFAULT 'active'        | active/expired/sinkholed |
| `first_seen`         | TIMESTAMP    | DEFAULT NOW()           | First detection          |
| `last_seen`          | TIMESTAMP    | DEFAULT NOW()           | Last seen                |
| `last_updated`       | TIMESTAMP    | DEFAULT NOW()           | Last update              |

**Indexes:** `domain`, `root_domain`, `tld`, `is_malicious`, `threat_score DESC`, `category`, `is_newly_registered`, `domain (GIN trigram)`

---

## Table 5: `hashes`

**Purpose:** File hash intelligence and malware analysis

| Column              | Type         | Constraints      | Description                 |
| ------------------- | ------------ | ---------------- | --------------------------- |
| `id`                | BIGSERIAL    | PRIMARY KEY      | Auto-increment ID           |
| `md5`               | VARCHAR(32)  |                  | MD5 hash                    |
| `sha1`              | VARCHAR(40)  |                  | SHA1 hash                   |
| `sha256`            | VARCHAR(64)  | NOT NULL, UNIQUE | SHA256 hash (primary)       |
| `sha512`            | VARCHAR(128) |                  | SHA512 hash                 |
| `ssdeep`            | VARCHAR(255) |                  | Fuzzy hash                  |
| `imphash`           | VARCHAR(32)  |                  | Import hash (PE)            |
| `is_malicious`      | BOOLEAN      | DEFAULT FALSE    | Is malware?                 |
| `threat_score`      | INTEGER      | CHECK 0-100      | Threat score                |
| `file_name`         | VARCHAR(500) |                  | Original filename           |
| `file_type`         | VARCHAR(50)  |                  | exe, dll, pdf, doc          |
| `file_size`         | BIGINT       |                  | Size in bytes               |
| `mime_type`         | VARCHAR(100) |                  | MIME type                   |
| `malware_family`    | VARCHAR(255) |                  | Emotet, Dridex, etc         |
| `malware_type`      | VARCHAR(100) |                  | trojan, ransomware          |
| `malware_aliases`   | JSONB        | DEFAULT '[]'     | Other names                 |
| `av_detections`     | INTEGER      | DEFAULT 0        | AV detection count          |
| `total_av_engines`  | INTEGER      | DEFAULT 0        | Total AVs scanned           |
| `av_detection_rate` | DECIMAL(5,2) |                  | Detection percentage        |
| `av_results`        | JSONB        |                  | Individual AV results       |
| `sandbox_verdict`   | VARCHAR(50)  |                  | malicious/suspicious/benign |
| `sandbox_behaviors` | JSONB        | DEFAULT '[]'     | Observed behaviors          |
| `network_activity`  | JSONB        |                  | IPs/domains contacted       |
| `virustotal_link`   | VARCHAR(500) |                  | VirusTotal URL              |
| `tags`              | JSONB        | DEFAULT '[]'     | Custom tags                 |
| `sources`           | JSONB        | DEFAULT '[]'     | Source names                |
| `first_seen`        | TIMESTAMP    | DEFAULT NOW()    | First detection             |
| `last_seen`         | TIMESTAMP    | DEFAULT NOW()    | Last seen                   |
| `last_updated`      | TIMESTAMP    | DEFAULT NOW()    | Last update                 |

**Indexes:** `md5`, `sha1`, `sha256`, `sha512`, `is_malicious`, `threat_score DESC`, `malware_family`, `malware_type`, `file_type`, `av_detection_rate DESC`

---

## Table 6: `iocs`

**Purpose:** Indicators of Compromise - centralized repository

| Column                | Type         | Constraints      | Description                   |
| --------------------- | ------------ | ---------------- | ----------------------------- |
| `id`                  | BIGSERIAL    | PRIMARY KEY      | Auto-increment ID             |
| `ioc_type`            | VARCHAR(50)  | NOT NULL         | ip, domain, url, hash         |
| `ioc_value`           | TEXT         | NOT NULL         | The actual IOC value          |
| `threat_type`         | VARCHAR(100) |                  | malware, phishing, c2         |
| `threat_category`     | VARCHAR(100) |                  | Category                      |
| `severity`            | VARCHAR(20)  |                  | low/medium/high/critical      |
| `confidence`          | INTEGER      | CHECK 0-100      | Confidence level              |
| `tlp_level`           | VARCHAR(20)  | DEFAULT 'white'  | TLP: white/green/amber/red    |
| `title`               | VARCHAR(500) |                  | IOC title                     |
| `description`         | TEXT         |                  | Description                   |
| `context`             | TEXT         |                  | Additional context            |
| `threat_actor`        | VARCHAR(255) |                  | APT28, Lazarus, etc           |
| `campaign_name`       | VARCHAR(255) |                  | Campaign name                 |
| `related_iocs`        | JSONB        | DEFAULT '[]'     | Related IOC IDs               |
| `tags`                | JSONB        | DEFAULT '[]'     | Custom tags                   |
| `sources`             | JSONB        | DEFAULT '[]'     | Source names                  |
| `mitre_attack_ids`    | JSONB        | DEFAULT '[]'     | MITRE ATT&CK IDs              |
| `external_references` | JSONB        | DEFAULT '[]'     | External links                |
| `status`              | VARCHAR(20)  | DEFAULT 'active' | active/expired/false_positive |
| `first_seen`          | TIMESTAMP    | DEFAULT NOW()    | First detection               |
| `last_seen`           | TIMESTAMP    | DEFAULT NOW()    | Last seen                     |
| `last_updated`        | TIMESTAMP    | DEFAULT NOW()    | Last update                   |
| `expires_at`          | TIMESTAMP    |                  | Expiration date               |

**Indexes:** `(ioc_type, ioc_value) UNIQUE`, `ioc_type`, `ioc_value`, `threat_type`, `severity`, `status`, `expires_at`, `description (FTS)`, `tags (GIN)`

---

## Table 7: `threat_feeds`

**Purpose:** Feed source management and configuration

| Column                   | Type         | Constraints             | Description                  |
| ------------------------ | ------------ | ----------------------- | ---------------------------- |
| `id`                     | BIGSERIAL    | PRIMARY KEY             | Auto-increment ID            |
| `feed_name`              | VARCHAR(255) | NOT NULL, UNIQUE        | Feed name                    |
| `feed_url`               | TEXT         |                         | Download URL                 |
| `feed_description`       | TEXT         |                         | Description                  |
| `feed_type`              | VARCHAR(50)  |                         | ip_geo, ip_blacklist, domain |
| `feed_format`            | VARCHAR(20)  |                         | csv, json, xml, txt          |
| `feed_category`          | VARCHAR(100) |                         | Category                     |
| `is_active`              | BOOLEAN      | DEFAULT TRUE            | Enabled?                     |
| `is_premium`             | BOOLEAN      | DEFAULT FALSE           | Paid feed?                   |
| `update_frequency`       | INTEGER      | DEFAULT 3600            | Seconds between updates      |
| `update_schedule`        | VARCHAR(50)  |                         | Cron expression              |
| `requires_auth`          | BOOLEAN      | DEFAULT FALSE           | Needs auth?                  |
| `auth_type`              | VARCHAR(50)  |                         | api_key, basic, oauth        |
| `auth_config`            | JSONB        |                         | Auth credentials             |
| `parser_type`            | VARCHAR(50)  |                         | csv, json, custom            |
| `parser_config`          | JSONB        |                         | Column mappings              |
| `reliability_score`      | INTEGER      | CHECK 0-100, DEFAULT 50 | Reliability                  |
| `false_positive_rate`    | DECIMAL(5,2) |                         | FP rate                      |
| `total_records_fetched`  | BIGINT       | DEFAULT 0               | Total fetched                |
| `total_records_imported` | BIGINT       | DEFAULT 0               | Total imported               |
| `last_fetch_status`      | VARCHAR(20)  |                         | success/failed/partial       |
| `last_error`             | TEXT         |                         | Last error message           |
| `consecutive_failures`   | INTEGER      | DEFAULT 0               | Failure count                |
| `last_fetched`           | TIMESTAMP    |                         | Last fetch time              |
| `next_scheduled_fetch`   | TIMESTAMP    |                         | Next scheduled               |
| `created_at`             | TIMESTAMP    | DEFAULT NOW()           | Created time                 |
| `updated_at`             | TIMESTAMP    | DEFAULT NOW()           | Updated time                 |

**Indexes:** `is_active`, `feed_type`, `next_scheduled_fetch`, `last_fetched`

---

## Table 8: `feed_history`

**Purpose:** Feed execution history and logs

| Column                 | Type         | Constraints       | Description                      |
| ---------------------- | ------------ | ----------------- | -------------------------------- |
| `id`                   | BIGSERIAL    | PRIMARY KEY       | Auto-increment ID                |
| `feed_id`              | BIGINT       | FK → threat_feeds | Feed reference                   |
| `feed_name`            | VARCHAR(255) |                   | Denormalized name                |
| `fetch_timestamp`      | TIMESTAMP    | DEFAULT NOW()     | Fetch time                       |
| `execution_time_ms`    | INTEGER      |                   | Duration in ms                   |
| `status`               | VARCHAR(20)  |                   | started/parsing/completed/failed |
| `records_downloaded`   | INTEGER      | DEFAULT 0         | Downloaded count                 |
| `records_parsed`       | INTEGER      | DEFAULT 0         | Parsed count                     |
| `records_added`        | INTEGER      | DEFAULT 0         | New records                      |
| `records_updated`      | INTEGER      | DEFAULT 0         | Updated records                  |
| `records_skipped`      | INTEGER      | DEFAULT 0         | Skipped records                  |
| `records_rejected`     | INTEGER      | DEFAULT 0         | Rejected records                 |
| `error_message`        | TEXT         |                   | Error message                    |
| `error_details`        | JSONB        |                   | Error details                    |
| `warnings`             | JSONB        | DEFAULT '[]'      | Warnings array                   |
| `downloaded_file_path` | VARCHAR(500) |                   | File path                        |
| `file_size_bytes`      | BIGINT       |                   | File size                        |
| `file_hash`            | VARCHAR(64)  |                   | SHA256 of file                   |
| `started_at`           | TIMESTAMP    |                   | Start time                       |
| `completed_at`         | TIMESTAMP    |                   | Completion time                  |

**Indexes:** `feed_id`, `fetch_timestamp DESC`, `status`, `feed_name`

---

## Pre-Configured Feeds (10)

| Feed Name        | Type             | URL                   | Frequency |
| ---------------- | ---------------- | --------------------- | --------- |
| Feodo Tracker    | ip_blacklist     | feodotracker.abuse.ch | 5 min     |
| URLhaus Recent   | domain           | urlhaus.abuse.ch      | 5 min     |
| Blocklist.de All | ip_blacklist     | lists.blocklist.de    | 15 min    |
| IPsum            | ip_blacklist     | github.com/stamparm   | 24 hr     |
| Tor Exit Nodes   | ip_anonymization | check.torproject.org  | 1 hr      |
| PhishTank        | domain           | data.phishtank.com    | 1 hr      |
| OpenPhish        | domain           | openphish.com         | 1 hr      |
| MalwareBazaar    | hash             | bazaar.abuse.ch       | 5 min     |
| ThreatFox        | ioc              | threatfox.abuse.ch    | 5 min     |
| Emerging Threats | ip_blacklist     | emergingthreats.net   | 24 hr     |

---

## Extensions Enabled

- `pg_trgm` - Fuzzy text matching
- `btree_gin` - Better GIN indexes
- `btree_gist` - Better GiST indexes

## Connection

```
postgresql://postgres:postgres@localhost:5432/threat_intel_db
```
