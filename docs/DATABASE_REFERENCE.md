# SafeOps PostgreSQL Database Reference

> Integration guide for IDS/IPS engines, firewalls, DHCP servers, DNS resolvers, and any program that needs to query SafeOps threat intelligence or network data.

---

## Connection Details

| Property | Value |
|----------|-------|
| Host | `localhost` |
| Port | `5432` |
| SSL Mode | `disable` (local only) |
| Max Connections | 25 per pool (recommended) |
| Connection Lifetime | 30 minutes |

### Application Users

| Username | Password | Databases | Use Case |
|----------|----------|-----------|----------|
| `threat_intel_app` | `admin` | threat_intel_db | Threat intel pipeline, IDS/IPS lookups |
| `safeops` | `admin` | threat_intel_db, safeops_network, safeops | Firewall engine, dashboard, all services |
| `dhcp_server` | `admin` | safeops_network | DHCP service only |
| `dns_server` | `admin` | safeops_network | DNS service only |

### Connection Strings

```
# For IDS/IPS or Firewall connecting to threat intel
postgresql://threat_intel_app:admin@localhost:5432/threat_intel_db?sslmode=disable

# For Firewall connecting to network config
postgresql://safeops:admin@localhost:5432/safeops_network?sslmode=disable

# Go (lib/pq)
host=localhost port=5432 user=threat_intel_app password=admin dbname=threat_intel_db sslmode=disable

# Python (psycopg2)
conn = psycopg2.connect(host="localhost", port=5432, dbname="threat_intel_db", user="threat_intel_app", password="admin")
```

Environment variable overrides supported: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`

---

## Database Overview

| Database | Purpose | Tables | Rows |
|----------|---------|--------|------|
| **threat_intel_db** | Threat intelligence, IP/domain/hash reputation, geolocation, firewall rules | 30 | ~5.8M |
| **safeops_network** | DHCP, routing, NAT, WAN health, network interfaces | 16 | ~2 |
| **safeops** | Reserved for captive portal / general app (empty) | 0 | 0 |

---

## DATABASE: threat_intel_db

This is the primary database for any security program. Contains IP reputation, domain intelligence, file hash lookups, geolocation, and firewall rules.

---

### Quick Reference: What to Query For Each Use Case

| I need to... | Query this table | Key column(s) |
|---|---|---|
| Check if an IP is malicious | `ip_blacklist` | `ip_address` (inet) |
| Check if an IP is VPN/Tor/Proxy | `ip_anonymization` | `ip_address` (inet) |
| Get country/city/ASN for an IP | `ip_geolocation` | `ip_address` (inet) |
| Check if a domain is malicious | `domains` | `domain` (varchar) |
| Check if a file hash is malware | `hashes` | `sha256`, `md5`, `sha1` |
| Get firewall rules to enforce | `firewall_rules` | `rule_id` (uuid) |
| Log a packet event | `packet_logs` | INSERT |
| Update firewall stats | `firewall_stats` | UPDATE |

---

### ip_blacklist — Malicious IP Database

**Row count:** ~37,000
**Use case:** IDS/IPS/Firewall checks every incoming/outgoing IP against this table. If `is_malicious = true` AND `status = 'active'`, block or alert.

| Column | Type | Description |
|--------|------|-------------|
| `id` | bigint | Primary key |
| `ip_address` | inet | **Lookup key** — the malicious IP (UNIQUE) |
| `is_malicious` | boolean | Always `true` for entries in this table |
| `threat_score` | integer | 0-100, higher = more dangerous |
| `abuse_type` | varchar(50) | Category: `spam`, `malware`, `c2`, `bruteforce`, `botnet`, `scanner`, `phishing`, `ddos`, `exploit`, `proxy_abuse`, `cryptomining`, `tor_exit` |
| `threat_category` | varchar(100) | Broader category grouping |
| `malware_family` | varchar(255) | e.g. "Emotet", "Mirai" (if known) |
| `confidence` | integer | 0-100, how sure we are this is malicious |
| `evidence_count` | integer | How many sources reported this IP |
| `reputation_score` | integer | 0-100 reputation (lower = worse) |
| `sources` | jsonb | Array of feed sources: `["feodo_tracker", "blocklist_de"]` |
| `tags` | jsonb | Additional tags: `["apt", "ransomware"]` |
| `status` | varchar(20) | `active`, `expired`, `whitelisted` |
| `first_seen` | timestamptz | When first reported |
| `last_seen` | timestamptz | When last reported |
| `expires_at` | timestamptz | Auto-expiry time (NULL = never expires) |

**Indexes:** `ip_address` (UNIQUE + btree), `threat_score`, `abuse_type`, `is_malicious`, `last_seen`, `expires_at`, `sources` (GIN)

#### Example Queries

```sql
-- Quick check: Is this IP blacklisted?
SELECT is_malicious, threat_score, abuse_type
FROM ip_blacklist
WHERE ip_address = '192.168.1.100'::inet AND status = 'active';

-- Get all active C2 server IPs with high threat score
SELECT ip_address, threat_score, malware_family
FROM ip_blacklist
WHERE abuse_type = 'c2' AND threat_score >= 80 AND status = 'active'
ORDER BY threat_score DESC;

-- Bulk check: multiple IPs at once (for firewall batch processing)
SELECT ip_address, threat_score, abuse_type
FROM ip_blacklist
WHERE ip_address = ANY($1::inet[]) AND status = 'active';

-- Get IPs that should have expired (for cleanup)
SELECT ip_address FROM ip_blacklist
WHERE expires_at IS NOT NULL AND expires_at < NOW();
```

#### Recommended Firewall Integration

```
Decision Logic:
  threat_score >= 80  → BLOCK immediately
  threat_score >= 60  → BLOCK + ALERT admin
  threat_score >= 40  → ALERT only (monitor)
  threat_score < 40   → LOG only

  abuse_type = 'c2'   → Always BLOCK regardless of score
  abuse_type = 'tor_exit' → Policy-dependent (block or allow)
```

---

### ip_anonymization — VPN/Tor/Proxy Detection

**Row count:** ~1,400
**Use case:** Detect if traffic is coming through anonymization services. Useful for policy enforcement (e.g., block all Tor exit nodes, flag VPN IPs).

| Column | Type | Description |
|--------|------|-------------|
| `ip_address` | inet | **Lookup key** (UNIQUE) |
| `is_vpn` | boolean | Commercial VPN service |
| `is_tor` | boolean | Tor network node |
| `is_proxy` | boolean | Open/public proxy |
| `is_datacenter` | boolean | Hosted in datacenter (not residential) |
| `is_relay` | boolean | Relay/CDN node |
| `is_hosting` | boolean | Hosting provider IP |
| `provider_name` | varchar(255) | VPN/proxy provider name |
| `service_type` | varchar(50) | `vpn`, `tor`, `proxy`, `datacenter`, `unknown` |
| `anonymity_level` | varchar(50) | Level of anonymization |
| `tor_exit_node` | boolean | Specifically a Tor exit node |
| `tor_node_name` | varchar(255) | Tor relay/exit name |
| `proxy_type` | varchar(50) | HTTP, SOCKS4, SOCKS5, etc. |
| `risk_score` | integer | 0-100 risk rating |
| `is_active` | boolean | Currently active anonymizer |
| `country_code` | varchar(2) | Country of the proxy/VPN |

**Indexes:** `ip_address` (UNIQUE + GiST), `is_vpn`, `is_tor`, `is_proxy`, `is_active`, `service_type`

#### Example Queries

```sql
-- Is this IP a known VPN/Tor/Proxy?
SELECT is_vpn, is_tor, is_proxy, provider_name, risk_score
FROM ip_anonymization
WHERE ip_address = '1.2.3.4'::inet AND is_active = true;

-- Get all active Tor exit nodes (for blocking)
SELECT ip_address, tor_node_name, country_code
FROM ip_anonymization
WHERE is_tor = true AND tor_exit_node = true AND is_active = true;

-- Combined check: blacklist + anonymization in one query
SELECT
    b.ip_address,
    b.threat_score,
    b.abuse_type,
    a.is_vpn,
    a.is_tor,
    a.is_proxy
FROM ip_blacklist b
LEFT JOIN ip_anonymization a ON b.ip_address = a.ip_address
WHERE b.ip_address = '1.2.3.4'::inet;
```

---

### ip_geolocation — IP-to-Location Mapping

**Row count:** ~4,456,000
**Use case:** Geo-blocking, traffic origin analysis, compliance (data residency), dashboard visualization. Contains both IP range data (from feeds) and individual IP lookups (from enrichment).

| Column | Type | Description |
|--------|------|-------------|
| `ip_address` | inet | Start IP of range OR single IP |
| `ip_end` | inet | End IP of range (NULL for single IPs) |
| `country_code` | varchar(10) | ISO country code: `US`, `IN`, `DE` |
| `country_name` | varchar(100) | Full name: `United States` |
| `region` | varchar(100) | State/province: `California` |
| `city` | varchar(100) | City: `San Jose` |
| `latitude` | numeric | GPS latitude |
| `longitude` | numeric | GPS longitude |
| `asn` | bigint | Autonomous System Number |
| `asn_org` | varchar(255) | ASN organization: `CLOUDFLARENET` |
| `isp` | varchar(255) | ISP name: `Cloudflare, Inc.` |
| `timezone` | varchar(50) | `America/Los_Angeles` |
| `is_mobile` | boolean | Mobile carrier IP |
| `is_hosting` | boolean | Hosting/datacenter IP |
| `confidence` | integer | Data confidence score |
| `sources` | jsonb | Data source: `["iptoasn"]` or `["ip-api.com"]` |

**Indexes:** `ip_address` (btree + GiST), `ip_end`, `country_code`, `city`, `country_code+city`, `asn`, `is_mobile`, `is_hosting`, `sources` (GIN)

**Note:** This table does NOT have a UNIQUE constraint on `ip_address` because it contains overlapping IP ranges from bulk feeds. Use range queries or exact matches.

#### Example Queries

```sql
-- Get country for a single IP (exact match first)
SELECT country_code, country_name, city, asn, asn_org, isp
FROM ip_geolocation
WHERE ip_address = '8.8.8.8'::inet
LIMIT 1;

-- Find which range contains an IP (for bulk-imported range data)
SELECT country_code, asn, asn_org
FROM ip_geolocation
WHERE ip_address <= '8.8.8.8'::inet AND ip_end >= '8.8.8.8'::inet
LIMIT 1;

-- Combined lookup: try exact match, then range match
SELECT country_code, country_name, city, asn, asn_org
FROM ip_geolocation
WHERE ip_address = '8.8.8.8'::inet
   OR ('8.8.8.8'::inet BETWEEN ip_address AND ip_end)
ORDER BY ip_address DESC
LIMIT 1;

-- Geo-block: get all IPs from a specific country
SELECT ip_address FROM ip_geolocation
WHERE country_code = 'CN' AND sources::text LIKE '%ip-api.com%';

-- Count IPs per country (dashboard)
SELECT country_code, COUNT(*) as ip_count
FROM ip_geolocation
WHERE country_code IS NOT NULL AND country_code != ''
GROUP BY country_code
ORDER BY ip_count DESC LIMIT 20;
```

#### Geo-Blocking Integration

```
Policy examples:
  country_code IN ('CN', 'RU', 'KP', 'IR') → BLOCK (sanctioned countries)
  is_hosting = true AND country_code != 'IN' → FLAG (foreign datacenter traffic)
  is_mobile = true → Different rate limits
```

---

### domains — Malicious Domain Database

**Row count:** ~1,280,000
**Use case:** DNS filtering, web proxy blocking, phishing detection.

| Column | Type | Description |
|--------|------|-------------|
| `domain` | varchar(255) | **Lookup key** (UNIQUE): `evil.example.com` |
| `root_domain` | varchar(255) | Root: `example.com` |
| `tld` | varchar(50) | Top-level: `com`, `xyz`, `tk` |
| `is_malicious` | boolean | Flagged as malicious |
| `threat_score` | integer | 0-100 danger level |
| `category` | varchar(100) | `phishing`, `malware`, `c2`, `spam`, `ransomware`, `cryptojacking`, `typosquatting` |
| `subcategory` | varchar(100) | More specific classification |
| `confidence` | integer | 0-100 confidence |
| `detection_count` | integer | How many times detected |
| `phishing_target` | varchar(100) | Brand being impersonated (if phishing) |
| `registrar` | varchar(255) | Domain registrar |
| `is_newly_registered` | boolean | Registered in last 30 days (high risk) |
| `sources` | jsonb | Feed sources |
| `status` | varchar(20) | `active`, `expired`, `whitelisted` |

**Indexes:** `domain` (UNIQUE + btree + trigram), `root_domain`, `tld`, `category`, `threat_score`, `is_malicious`, `status`, `sources` (GIN)

#### Example Queries

```sql
-- DNS filter: is this domain malicious?
SELECT is_malicious, threat_score, category, phishing_target
FROM domains
WHERE domain = 'suspicious-site.xyz' AND status = 'active';

-- Check root domain and all subdomains
SELECT domain, threat_score, category
FROM domains
WHERE root_domain = 'evil.com' AND is_malicious = true;

-- Find all phishing domains targeting a brand
SELECT domain, threat_score, phishing_target
FROM domains
WHERE category = 'phishing' AND phishing_target ILIKE '%paypal%'
ORDER BY threat_score DESC;

-- Get newly registered domains (high risk)
SELECT domain, registration_date
FROM domains
WHERE is_newly_registered = true
ORDER BY registration_date DESC LIMIT 100;

-- Fuzzy domain matching (typosquatting detection)
SELECT domain, similarity(domain, 'google.com') as sim
FROM domains
WHERE domain % 'google.com'
ORDER BY sim DESC LIMIT 10;
```

---

### hashes — Malware File Hash Database

**Row count:** ~8,900
**Use case:** File scanning, endpoint detection, malware analysis.

| Column | Type | Description |
|--------|------|-------------|
| `sha256` | varchar(64) | **Primary lookup key** (UNIQUE) |
| `md5` | varchar(128) | MD5 hash (also indexed) |
| `sha1` | varchar(128) | SHA1 hash (also indexed) |
| `is_malicious` | boolean | Known malware |
| `threat_score` | integer | 0-100 |
| `file_name` | varchar(500) | Original filename |
| `file_type` | varchar(100) | `exe`, `dll`, `pdf`, `doc` |
| `file_size` | bigint | Size in bytes |
| `malware_family` | varchar(255) | `Emotet`, `WannaCry`, `Mirai` |
| `malware_type` | varchar(100) | `trojan`, `ransomware`, `worm`, `rat` |
| `av_detections` | integer | How many AV engines detect it |
| `total_av_engines` | integer | Total AV engines tested |
| `av_detection_rate` | numeric | Percentage detected |
| `sandbox_verdict` | varchar(50) | Sandbox analysis result |
| `virustotal_link` | varchar(500) | VirusTotal report URL |
| `sources` | jsonb | Feed sources |

**Indexes:** `sha256` (UNIQUE), `md5`, `sha1`, `threat_score`, `malware_family`, `is_malicious`

#### Example Queries

```sql
-- Check file by SHA256
SELECT is_malicious, threat_score, malware_family, malware_type, av_detection_rate
FROM hashes
WHERE sha256 = 'a1b2c3...';

-- Check by MD5 (legacy systems)
SELECT sha256, is_malicious, threat_score, malware_family
FROM hashes
WHERE md5 = 'd41d8cd98f00b204e9800998ecf8427e';

-- Get all ransomware hashes for endpoint blocking
SELECT sha256, md5, file_name, malware_family
FROM hashes
WHERE malware_type = 'ransomware' AND is_malicious = true;
```

---

### firewall_rules — Active Firewall Policy

**Row count:** ~6
**Use case:** Firewall engine reads these rules to decide packet actions.

| Column | Type | Description |
|--------|------|-------------|
| `rule_id` | uuid | Primary key |
| `name` | varchar(255) | Rule name |
| `action` | varchar(20) | `ALLOW`, `BLOCK`, `LOG` |
| `protocol` | varchar(20) | `TCP`, `UDP`, `ICMP`, `ANY` |
| `src_ip` | varchar(100) | Source IP/CIDR or `*` for any |
| `dst_ip` | varchar(100) | Destination IP/CIDR or `*` for any |
| `src_port` | varchar(100) | Source port or `*` |
| `dst_port` | varchar(100) | Destination port or `*` |
| `device_mac` | varchar(50) | Specific device MAC or `*` |
| `priority` | integer | Lower = evaluated first |
| `enabled` | boolean | Rule active? |
| `hit_count` | bigint | Times this rule matched |

#### Example Query

```sql
-- Get all active rules, ordered by priority (for firewall engine startup)
SELECT rule_id, name, action, protocol, src_ip, dst_ip, src_port, dst_port, device_mac, priority
FROM firewall_rules
WHERE enabled = true
ORDER BY priority ASC;
```

---

### packet_logs — Packet Event Log

**Use case:** Firewall and IDS write packet events here for audit/analysis.

| Column | Type | Description |
|--------|------|-------------|
| `log_id` | bigint | Primary key |
| `timestamp` | timestamptz | When the packet was seen |
| `src_ip` | inet | Source IP |
| `dst_ip` | inet | Destination IP |
| `src_port` | integer | Source port |
| `dst_port` | integer | Destination port |
| `protocol` | varchar(10) | `TCP`, `UDP`, `ICMP` |
| `action` | varchar(20) | `ALLOW`, `BLOCK`, `LOG`, `ALERT` |
| `rule_name` | varchar(255) | Which rule matched |
| `rule_id` | uuid | FK to firewall_rules |
| `packet_size` | integer | Packet size in bytes |
| `device_mac` | varchar(50) | Source device MAC |

#### Insert Example

```sql
-- Log a blocked packet
INSERT INTO packet_logs (src_ip, dst_ip, src_port, dst_port, protocol, action, rule_name, packet_size, device_mac)
VALUES ('192.168.1.50'::inet, '185.220.101.1'::inet, 54321, 443, 'TCP', 'BLOCK', 'Block Tor Exits', 1500, 'AA:BB:CC:DD:EE:FF');
```

---

### threat_feeds — Feed Configuration and Status

**Row count:** 19
**Use case:** Dashboard shows feed health; scheduler checks `next_scheduled_fetch`.

| Column | Type | Key Fields |
|--------|------|------------|
| `feed_name` | varchar(255) | Feed identifier (UNIQUE) |
| `feed_url` | text | Download URL |
| `feed_type` | varchar(50) | `ip_blacklist`, `domain_blacklist`, `hash_intel`, `ip_geo` |
| `is_active` | boolean | Feed enabled |
| `last_fetched` | timestamptz | Last successful download time |
| `consecutive_failures` | integer | Errors in a row |
| `reliability_score` | integer | Feed quality rating |

---

### Pre-Built Views

These views provide ready-made aggregations. Query them directly for dashboards.

| View | What It Shows |
|------|---------------|
| `threat_summary_stats` | Total IPs, domains, hashes, active threats, high-risk counts |
| `country_ip_distribution` | IP count per country from geolocation data |
| `top_asns` | Most common ASNs in geolocation data |
| `mobile_networks` | All mobile carrier IPs |
| `datacenter_ips` | All datacenter/hosting IPs |
| `ip_full_intelligence` | Joined view: blacklist + anonymization + geolocation per IP |
| `feed_performance_summary` | Feed health: success rates, record counts |
| `recent_feed_activity` | Last 24h feed fetch activity |
| `potential_typosquats` | Domains similar to known legitimate brands |
| `malware_statistics` | Malware family breakdown, AV detection rates |

```sql
-- Dashboard: threat summary
SELECT * FROM threat_summary_stats;

-- Dashboard: top countries
SELECT * FROM country_ip_distribution LIMIT 20;

-- Full IP intelligence in one query
SELECT * FROM ip_full_intelligence WHERE ip_address = '1.2.3.4'::inet;
```

---

### Reference Tables (Lookup/Classification)

These tables contain static reference data for categories, severity levels, and recommended actions. Useful for UI display and policy mapping.

| Table | Rows | Purpose |
|-------|------|---------|
| `ip_abuse_types` | 12 | Abuse type definitions (spam, c2, malware, etc.) with severity and recommended actions |
| `domain_threat_categories` | 12 | Domain threat categories with severity and actions |
| `malware_type_classifications` | 15 | Malware types (trojan, ransomware, worm, etc.) with capabilities |
| `connection_type_classifications` | 12 | Connection types (residential, datacenter, VPN, etc.) with risk levels |
| `severity_level_definitions` | 10 | Severity 1-10 with response times and escalation rules |
| `threat_action_definitions` | 8 | Actions (allow, block, alert, quarantine, geo_block) with implementation details |

```sql
-- Get recommended action for a severity level
SELECT severity_name, default_action, response_time, escalation_required
FROM severity_level_definitions
WHERE severity_level >= 7;

-- Get all abuse types with recommended actions
SELECT category_code, display_name, severity_level, recommended_action
FROM ip_abuse_types ORDER BY severity_level DESC;
```

---

## DATABASE: safeops_network

Used by DHCP server, network management, and routing components.

### Key Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `dhcp_pools` | DHCP address pools | `subnet` (cidr), `range_start`, `range_end`, `gateway`, `dns_servers` |
| `dhcp_leases` | Active DHCP leases | `mac_address`, `ip_address`, `hostname`, `state`, `lease_end` |
| `dhcp_reservations` | Static DHCP reservations | `mac_address`, `ip_address`, `hostname` |
| `dhcp_lease_events` | DHCP event log | `event_type`, `mac_address`, `ip_address`, `event_time` |
| `network_interfaces` | NIC inventory | `interface_name`, `ip_address`, `mac_address`, `state`, `speed_mbps` |
| `static_routes` | Routing table | `destination`, `gateway`, `metric` |
| `nat_mappings` | NAT translation table | `internal_ip:port` to `external_ip:port` |
| `connection_tracking` | Active connections | 5-tuple: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol` |
| `wan_health_history` | WAN link quality | `latency_ms`, `jitter_ms`, `packet_loss_percent`, `state` |
| `failover_events` | WAN failover log | `from_wan_id`, `to_wan_id`, `reason`, `success` |

### Pre-Built Views

| View | What It Shows |
|------|---------------|
| `v_dhcp_active_leases` | Currently active DHCP leases with pool info |
| `v_dhcp_pool_utilization` | How full each DHCP pool is |
| `v_wan_status` | Current WAN link health and status |
| `v_connection_summary` | Active connection counts by state/protocol |
| `v_nat_utilization` | NAT table usage |

#### Example Queries

```sql
-- DHCP: Get active lease for a MAC address
SELECT ip_address, hostname, lease_end
FROM dhcp_leases
WHERE mac_address = 'AA:BB:CC:DD:EE:FF'::macaddr AND state = 'ACTIVE';

-- Network: Get all UP interfaces
SELECT interface_name, ip_address, mac_address, speed_mbps
FROM network_interfaces
WHERE state = 'UP' AND is_enabled = true;

-- Routing: Get all enabled static routes
SELECT destination, gateway, metric
FROM static_routes
WHERE is_enabled = true ORDER BY metric ASC;

-- WAN: Latest health status per interface
SELECT DISTINCT ON (wan_interface_id)
    wan_interface_id, state, latency_ms, packet_loss_percent, checked_at
FROM wan_health_history
ORDER BY wan_interface_id, checked_at DESC;
```

---

## Complete IDS/IPS Integration Example

A typical IDS/IPS packet inspection flow that checks all relevant tables:

```sql
-- Step 1: Check if source IP is blacklisted
SELECT threat_score, abuse_type, malware_family
FROM ip_blacklist
WHERE ip_address = $src_ip::inet AND status = 'active';

-- Step 2: Check if source IP is anonymized (VPN/Tor/Proxy)
SELECT is_vpn, is_tor, is_proxy, risk_score
FROM ip_anonymization
WHERE ip_address = $src_ip::inet AND is_active = true;

-- Step 3: Get geolocation for country-based policy
SELECT country_code, asn, is_hosting
FROM ip_geolocation
WHERE ip_address = $src_ip::inet
LIMIT 1;

-- Step 4: If DNS traffic, check domain reputation
SELECT is_malicious, threat_score, category
FROM domains
WHERE domain = $queried_domain AND status = 'active';

-- Step 5: Log the decision
INSERT INTO packet_logs (src_ip, dst_ip, src_port, dst_port, protocol, action, rule_name, packet_size)
VALUES ($src_ip::inet, $dst_ip::inet, $src_port, $dst_port, $protocol, $decision, $rule, $size);
```

### Optimized: Single-Query Full IP Check

```sql
SELECT
    b.threat_score   AS blacklist_score,
    b.abuse_type,
    a.is_vpn,
    a.is_tor,
    a.is_proxy,
    g.country_code,
    g.asn,
    g.is_hosting     AS geo_hosting
FROM (SELECT $1::inet AS ip) q
LEFT JOIN ip_blacklist b      ON b.ip_address = q.ip AND b.status = 'active'
LEFT JOIN ip_anonymization a  ON a.ip_address = q.ip AND a.is_active = true
LEFT JOIN ip_geolocation g    ON g.ip_address = q.ip
LIMIT 1;
```

This single query tells you:
- Is the IP blacklisted? (if `blacklist_score` is not NULL)
- Is it VPN/Tor/Proxy?
- What country is it from?
- Is it a datacenter/hosting IP?

Decision matrix:
```
blacklist_score >= 80                → BLOCK
is_tor = true                       → BLOCK (or policy-dependent)
country_code IN blocked_countries   → BLOCK
blacklist_score >= 40               → ALERT
is_vpn = true                       → LOG
everything NULL                     → ALLOW (unknown = clean)
```

---

## Performance Notes

- All lookup columns have B-tree indexes for fast point queries
- `ip_address` columns use PostgreSQL `inet` type with GiST indexes for range queries
- `sources` and `tags` columns use GIN indexes for JSON containment queries
- For high-throughput packet inspection, use connection pooling (PgBouncer recommended)
- The `ip_geolocation` table is large (~4.5M rows); use `LIMIT 1` on lookups
- Batch lookups with `ANY($1::inet[])` are faster than individual queries in a loop
