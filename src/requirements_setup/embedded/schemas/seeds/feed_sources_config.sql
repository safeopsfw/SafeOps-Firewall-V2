-- ============================================================================
-- FILE: database/seeds/feed_sources_config.sql
-- PURPOSE: Populate threat_feeds table with initial threat intelligence sources
-- DEPENDENCIES: Requires 008_threat_feeds.sql schema to be executed first
-- LAST UPDATED: 2025-12-22
-- ============================================================================

-- This file configures publicly available threat intelligence feeds across
-- multiple categories: IP blacklists, domain blacklists, malware hashes,
-- VPN/Tor detection, and geolocation data.
--
-- All feeds listed here are FREE and publicly accessible. No API keys required
-- unless specifically noted. Update frequencies are set conservatively to
-- avoid rate limiting.
--
-- LICENSE NOTES:
-- - abuse.ch feeds: Free for any use, attribution appreciated
-- - BlockList.de: Free, check terms at https://www.blocklist.de/en/index.html
-- - PhishTank: Free API key required, see https://www.phishtank.com/api_info.php
-- - OpenPhish: Free tier available, see https://openphish.com/
-- - Tor Project: Public data, no restrictions

-- ============================================================================
-- SECTION 1: IP BLACKLIST FEED SOURCES
-- ============================================================================

-- Feodo Tracker (abuse.ch) - Botnet C2 Server IPs
-- Update Frequency: Every 5 minutes (300 seconds)
-- Reliability: Very High (95/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'Feodo Tracker IP Blocklist',
    'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    'ip_blacklist',
    'txt',
    'Feodo/Dridex/Emotet/TrickBot C2 server IP addresses updated in real-time',
    300,  -- 5 minutes
    TRUE,
    95,
    100,  -- Highest priority
    '{"format": "plain_text", "comment_char": "#", "skip_lines": 0}'::jsonb,
    '{"max_retries": 5, "backoff_seconds": 60, "timeout_seconds": 30}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- BlockList.de All Service Attacks
-- Update Frequency: Hourly (3600 seconds)
-- Reliability: High (85/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'BlockList.de All Attacks',
    'https://lists.blocklist.de/lists/all.txt',
    'ip_blacklist',
    'txt',
    'Combined blocklist of IPs attacking mail, SSH, FTP, and web services',
    3600,  -- 1 hour
    TRUE,
    85,
    90,
    '{"format": "plain_text", "comment_char": "#", "skip_lines": 0}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 120, "timeout_seconds": 60}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- IPsum Aggregated Threat Feed
-- Update Frequency: Daily (86400 seconds)
-- Reliability: High (80/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'IPsum Aggregated Feed',
    'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
    'ip_blacklist',
    'txt',
    'Aggregated feed of malicious IPs from 30+ sources with threat scores',
    86400,  -- 24 hours
    TRUE,
    80,
    85,
    '{"format": "plain_text", "comment_char": "#", "skip_lines": 0}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 300, "timeout_seconds": 90}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- Emerging Threats Compromised IPs
-- Update Frequency: Daily (86400 seconds)
-- Reliability: Very High (90/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'ET Compromised IPs',
    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    'ip_blacklist',
    'txt',
    'Known compromised hosts distributing malware or participating in botnets',
    86400,  -- 24 hours
    TRUE,
    90,
    88,
    '{"format": "plain_text", "comment_char": "#", "skip_lines": 0}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 180, "timeout_seconds": 60}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- FireHOL Level 1 (High Confidence)
-- Update Frequency: Daily (86400 seconds)
-- Reliability: Very High (92/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'FireHOL Level 1',
    'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    'ip_blacklist',
    'txt',
    'High-confidence malicious IPs from multiple reputable sources (attacks in last 48h)',
    86400,  -- 24 hours
    TRUE,
    92,
    95,
    '{"format": "plain_text", "comment_char": "#", "skip_lines": 0}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 240, "timeout_seconds": 90}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- ============================================================================
-- SECTION 2: DOMAIN BLACKLIST FEED SOURCES
-- ============================================================================

-- PhishTank Verified Phishing URLs
-- Update Frequency: Every 6 hours (21600 seconds)
-- Reliability: Very High (95/100)
-- NOTE: API key recommended but not required for basic access
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config, authentication_required
) VALUES (
    'PhishTank Verified',
    'http://data.phishtank.com/data/online-valid.json',
    'domain',
    'json',
    'Community-verified phishing URLs with high accuracy, updated multiple times daily',
    21600,  -- 6 hours
    TRUE,
    95,
    98,
    '{"format": "json", "url_field": "url", "verified_field": "verified"}'::jsonb,
    '{"max_retries": 4, "backoff_seconds": 300, "timeout_seconds": 120}'::jsonb,
    FALSE
) ON CONFLICT (feed_name) DO NOTHING;

-- OpenPhish Active Phishing Sites
-- Update Frequency: Every 2 hours (7200 seconds)
-- Reliability: Very High (93/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'OpenPhish Feed',
    'https://openphish.com/feed.txt',
    'domain',
    'txt',
    'Actively validated phishing URLs with high precision, premium accuracy',
    7200,  -- 2 hours
    TRUE,
    93,
    96,
    '{"format": "plain_text", "comment_char": null, "skip_lines": 0}'::jsonb,
    '{"max_retries": 4, "backoff_seconds": 180, "timeout_seconds": 90}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- URLhaus (abuse.ch) - Malware Distribution URLs
-- Update Frequency: Every 5 minutes (300 seconds)
-- Reliability: Very High (97/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'URLhaus Malware URLs',
    'https://urlhaus.abuse.ch/downloads/csv_recent/',
    'domain',
    'csv',
    'URLs hosting malware payloads, updated in real-time from abuse.ch',
    300,  -- 5 minutes
    TRUE,
    97,
    100,
    '{"format": "csv", "has_header": true, "url_column": "url", "threat_column": "threat"}'::jsonb,
    '{"max_retries": 5, "backoff_seconds": 60, "timeout_seconds": 45}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- Phishing Army Community Blocklist
-- Update Frequency: Every 12 hours (43200 seconds)
-- Reliability: High (85/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'Phishing Army',
    'https://phishing.army/download/phishing_army_blocklist_extended.txt',
    'domain',
    'txt',
    'Community-maintained phishing domain blocklist with extended coverage',
    43200,  -- 12 hours
    TRUE,
    85,
    82,
    '{"format": "plain_text", "comment_char": "#", "skip_lines": 0}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 300, "timeout_seconds": 90}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- ThreatFox (abuse.ch) - IOCs including Domains
-- Update Frequency: Every 5 minutes (300 seconds)
-- Reliability: Very High (96/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'ThreatFox IOC Feed',
    'https://threatfox.abuse.ch/export/csv/recent/',
    'domain',
    'csv',
    'Indicators of Compromise including domains, IPs, and hashes from active threats',
    300,  -- 5 minutes
    TRUE,
    96,
    99,
    '{"format": "csv", "has_header": true, "ioc_column": "ioc", "type_column": "ioc_type"}'::jsonb,
    '{"max_retries": 5, "backoff_seconds": 60, "timeout_seconds": 45}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- ============================================================================
-- SECTION 3: HASH INTELLIGENCE FEED SOURCES
-- ============================================================================

-- MalwareBazaar (abuse.ch) - Malware Sample Hashes
-- Update Frequency: Every 5 minutes (300 seconds)
-- Reliability: Very High (98/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'MalwareBazaar Recent',
    'https://mb-api.abuse.ch/api/v1/',
    'hash',
    'json',
    'Recent malware samples database with SHA256/MD5 hashes and malware families',
    300,  -- 5 minutes
    TRUE,
    98,
    100,
    '{"format": "json", "api_endpoint": "get_recent", "hash_fields": ["sha256_hash", "md5_hash"], "family_field": "signature"}'::jsonb,
    '{"max_retries": 5, "backoff_seconds": 60, "timeout_seconds": 60}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- SSL Blacklist (abuse.ch) - Malicious SSL Certificate Hashes
-- Update Frequency: Daily (86400 seconds)
-- Reliability: Very High (94/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'SSL Blacklist',
    'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
    'hash',
    'csv',
    'SHA1 fingerprints of malicious SSL certificates used by botnet C2 servers',
    86400,  -- 24 hours
    TRUE,
    94,
    88,
    '{"format": "csv", "has_header": true, "hash_column": "SHA1", "reason_column": "Reason"}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 180, "timeout_seconds": 60}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- VirusShare Hash List
-- Update Frequency: Weekly (604800 seconds)
-- Reliability: High (80/100)
-- NOTE: Large dataset, careful with update frequency
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'VirusShare Hash List',
    'https://virusshare.com/hashfiles/VirusShare-00000.md5',
    'hash',
    'txt',
    'Comprehensive malware hash database (MD5) - large dataset, weekly updates',
    604800,  -- 7 days
    TRUE,
    80,
    70,
    '{"format": "plain_text", "comment_char": "#", "skip_lines": 0}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 600, "timeout_seconds": 300}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- ============================================================================
-- SECTION 4: VPN/PROXY/TOR FEED SOURCES
-- ============================================================================

-- Tor Project Official Exit Node List
-- Update Frequency: Every hour (3600 seconds)
-- Reliability: Perfect (100/100) - Official source
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'Tor Exit Nodes',
    'https://check.torproject.org/torbulkexitlist',
    'vpn',
    'txt',
    'Official Tor Project exit node IP addresses, authoritative source',
    3600,  -- 1 hour
    TRUE,
    100,
    95,
    '{"format": "plain_text", "comment_char": null, "skip_lines": 0}'::jsonb,
    '{"max_retries": 5, "backoff_seconds": 120, "timeout_seconds": 60}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- VPN Gate Public VPN Servers
-- Update Frequency: Every 6 hours (21600 seconds)
-- Reliability: High (85/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'VPN Gate Servers',
    'https://www.vpngate.net/api/iphone/',
    'vpn',
    'csv',
    'Public VPN relay server list from VPN Gate academic project',
    21600,  -- 6 hours
    TRUE,
    85,
    75,
    '{"format": "csv", "has_header": true, "skip_lines": 2, "ip_column": "IP"}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 300, "timeout_seconds": 90}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- ProxyCheck.io Free Proxy List
-- Update Frequency: Daily (86400 seconds)
-- Reliability: Medium (70/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'Open Proxy List',
    'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
    'vpn',
    'txt',
    'Open HTTP/HTTPS/SOCKS proxy servers detected globally',
    86400,  -- 24 hours
    TRUE,
    70,
    65,
    '{"format": "plain_text", "comment_char": null, "skip_lines": 0}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 180, "timeout_seconds": 60}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- ============================================================================
-- SECTION 5: GEOIP DATA SOURCES
-- ============================================================================

-- IPtoASN Database
-- Update Frequency: Weekly (604800 seconds)
-- Reliability: Very High (95/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'IPtoASN Mapping',
    'https://iptoasn.com/data/ip2asn-v4.tsv.gz',
    'geolocation',
    'csv',
    'IP to ASN and country code mapping, TSV format, gzip compressed',
    604800,  -- 7 days
    TRUE,
    95,
    80,
    '{"format": "csv", "delimiter": "\\t", "has_header": false, "compressed": "gzip"}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 300, "timeout_seconds": 180}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- IP2Location LITE DB1 (Country)
-- Update Frequency: Monthly (2592000 seconds)
-- Reliability: Very High (92/100)
-- NOTE: Requires registration for download link
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config, authentication_required
) VALUES (
    'IP2Location LITE IPv4',
    'https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP',
    'geolocation',
    'csv',
    'IP geolocation database with country-level accuracy (free LITE version)',
    2592000,  -- 30 days
    FALSE,  -- Disabled by default - requires registration
    92,
    75,
    '{"format": "csv", "has_header": false, "compressed": "zip"}'::jsonb,
    '{"max_retries": 3, "backoff_seconds": 300, "timeout_seconds": 240}'::jsonb,
    TRUE
) ON CONFLICT (feed_name) DO NOTHING;

-- sapics IP Location Database (GitHub)
-- Update Frequency: Daily (86400 seconds)
-- Reliability: High (88/100)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, description,
    update_frequency, is_active, reliability_score, priority,
    parser_config, retry_config
) VALUES (
    'sapics GeoIP DB',
    'https://github.com/sapics/ip-location-db/raw/main/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv',
    'geolocation',
    'csv',
    'Daily updated IP geolocation with ASN, country, and region from WHOIS data',
    86400,  -- 24 hours
    TRUE,
    88,
    82,
    '{"format": "csv", "has_header": false, "ip_range": true}'::jsonb,
    '{"max_retries": 4, "backoff_seconds": 240, "timeout_seconds": 120}'::jsonb
) ON CONFLICT (feed_name) DO NOTHING;

-- ============================================================================
-- SECTION 6: FEED CONFIGURATION DEFAULTS AND METADATA
-- ============================================================================

-- Update system metadata to track seed file execution
INSERT INTO system_metadata (key, value, description, category)
VALUES (
    'feed_sources_seed_version',
    '1.0.0',
    'Version of feed_sources_config.sql last executed',
    'database_seeds'
) ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_metadata (key, value, description, category)
VALUES (
    'total_configured_feeds',
    (SELECT COUNT(*)::text FROM threat_feeds),
    'Total number of threat feeds configured in database',
    'threat_intelligence'
) ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_metadata (key, value, description, category)
VALUES (
    'feeds_seeded_at',
    CURRENT_TIMESTAMP::text,
    'Timestamp when feed sources were last seeded/updated',
    'database_seeds'
) ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Display summary of configured feeds by type
DO $$
DECLARE
    feed_count INT;
    ip_count INT;
    domain_count INT;
    hash_count INT;
    vpn_count INT;
    geo_count INT;
BEGIN
    SELECT COUNT(*) INTO feed_count FROM threat_feeds;
    SELECT COUNT(*) INTO ip_count FROM threat_feeds WHERE feed_type = 'ip_blacklist';
    SELECT COUNT(*) INTO domain_count FROM threat_feeds WHERE feed_type = 'domain';
    SELECT COUNT(*) INTO hash_count FROM threat_feeds WHERE feed_type = 'hash';
    SELECT COUNT(*) INTO vpn_count FROM threat_feeds WHERE feed_type = 'vpn';
    SELECT COUNT(*) INTO geo_count FROM threat_feeds WHERE feed_type = 'geolocation';
    
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Threat Feed Configuration Summary';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Total Feeds Configured: %', feed_count;
    RAISE NOTICE 'IP Blacklist Feeds: %', ip_count;
    RAISE NOTICE 'Domain Blacklist Feeds: %', domain_count;
    RAISE NOTICE 'Hash Intelligence Feeds: %', hash_count;
    RAISE NOTICE 'VPN/Proxy/Tor Feeds: %', vpn_count;
    RAISE NOTICE 'Geolocation Feeds: %', geo_count;
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Active Feeds: %', (SELECT COUNT(*) FROM threat_feeds WHERE is_active = TRUE);
    RAISE NOTICE 'Disabled Feeds: %', (SELECT COUNT(*) FROM threat_feeds WHERE is_active = FALSE);
    RAISE NOTICE '========================================';
END $$;

-- Display all configured feeds
SELECT 
    id,
    feed_name,
    feed_type,
    feed_format,
    update_frequency,
    reliability_score,
    is_active,
    priority
FROM threat_feeds
ORDER BY priority DESC NULLS LAST, reliability_score DESC;

-- ============================================================================
-- END OF FILE
-- ============================================================================
