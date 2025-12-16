-- ============================================================================
-- SafeOps Threat Intelligence Database - Feed Sources Configuration
-- File: feed_sources_config.sql
-- Purpose: Initial configuration for external threat intelligence feeds
-- ============================================================================

-- =============================================================================
-- PUBLIC/FREE THREAT FEEDS
-- =============================================================================

-- 1. AbuseIPDB
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format, 
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'AbuseIPDB',
    'https://api.abuseipdb.com/api/v2/blacklist',
    'IP',
    'JSON',
    3600,
    2,
    true,
    true,
    'Community-driven IP abuse database with confidence scores'
) ON CONFLICT (feed_name) DO NOTHING;

-- 2. AlienVault OTX
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'AlienVault OTX',
    'https://otx.alienvault.com/api/v1/pulses/subscribed',
    'IOC_MIXED',
    'JSON',
    1800,
    2,
    true,
    true,
    'Open Threat Exchange - community threat intelligence with mixed IOC types'
) ON CONFLICT (feed_name) DO NOTHING;

-- 3. Abuse.ch URLhaus
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'URLhaus',
    'https://urlhaus.abuse.ch/downloads/csv_recent/',
    'URL',
    'CSV',
    3600,
    3,
    false,
    true,
    'Malware URL database from Abuse.ch'
) ON CONFLICT (feed_name) DO NOTHING;

-- 4. Abuse.ch Feodo Tracker
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'Feodo Tracker',
    'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
    'IP',
    'CSV',
    3600,
    3,
    false,
    true,
    'Botnet C2 IP addresses - Feodo, Emotet, TrickBot, QakBot'
) ON CONFLICT (feed_name) DO NOTHING;

-- 5. MalwareBazaar
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'MalwareBazaar',
    'https://mb-api.abuse.ch/api/v1/',
    'HASH',
    'JSON',
    1800,
    2,
    false,
    true,
    'Malware sample hashes from Abuse.ch MalwareBazaar'
) ON CONFLICT (feed_name) DO NOTHING;

-- 6. PhishTank
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'PhishTank',
    'http://data.phishtank.com/data/online-valid.json',
    'URL',
    'JSON',
    3600,
    3,
    false,
    true,
    'Community-submitted phishing URL database'
) ON CONFLICT (feed_name) DO NOTHING;

-- 7. Spamhaus DROP
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'Spamhaus DROP',
    'https://www.spamhaus.org/drop/drop.txt',
    'IP',
    'CSV',
    43200,
    2,
    false,
    true,
    'Spamhaus Don''t Route Or Peer list - netblocks controlled by spammers/criminals'
) ON CONFLICT (feed_name) DO NOTHING;

-- 8. Tor Exit Nodes
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'TorProject Exit Nodes',
    'https://check.torproject.org/torbulkexitlist',
    'IP',
    'CSV',
    3600,
    4,
    false,
    true,
    'TOR exit node IP addresses (informational - not inherently malicious)'
) ON CONFLICT (feed_name) DO NOTHING;

-- 9. Emerging Threats
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'Emerging Threats',
    'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
    'IP',
    'CSV',
    3600,
    2,
    false,
    true,
    'Proofpoint Emerging Threats blocked IP list'
) ON CONFLICT (feed_name) DO NOTHING;

-- 10. Blocklist.de
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'Blocklist.de',
    'https://lists.blocklist.de/lists/all.txt',
    'IP',
    'CSV',
    3600,
    3,
    false,
    true,
    'Attack IPs from fail2ban and other security reports'
) ON CONFLICT (feed_name) DO NOTHING;

-- =============================================================================
-- ADDITIONAL FREE FEEDS
-- =============================================================================

-- 11. SSL Blacklist (SSLBL)
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'SSL Blacklist',
    'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
    'IP',
    'CSV',
    3600,
    3,
    false,
    true,
    'IPs associated with malicious SSL certificates'
) ON CONFLICT (feed_name) DO NOTHING;

-- 12. Botvrij.eu
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'Botvrij.eu',
    'https://www.botvrij.eu/data/ioclist.domain',
    'DOMAIN',
    'CSV',
    3600,
    3,
    false,
    true,
    'Dutch threat intelligence IoC list - domains'
) ON CONFLICT (feed_name) DO NOTHING;

-- =============================================================================
-- COMMERCIAL THREAT FEEDS (DISABLED BY DEFAULT - REQUIRE API KEYS)
-- =============================================================================

-- 13. VirusTotal Intelligence
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'VirusTotal Intelligence',
    'https://www.virustotal.com/api/v3/intelligence/search',
    'IOC_MIXED',
    'JSON',
    1800,
    1,
    true,
    false,
    'Premium threat intelligence from VirusTotal (requires subscription and API key)'
) ON CONFLICT (feed_name) DO NOTHING;

-- 14. Recorded Future
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'Recorded Future',
    'https://api.recordedfuture.com/v2/threat/list',
    'IOC_MIXED',
    'JSON',
    3600,
    1,
    true,
    false,
    'Commercial threat intelligence platform (requires subscription and API key)'
) ON CONFLICT (feed_name) DO NOTHING;

-- 15. ThreatConnect
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'ThreatConnect',
    'https://api.threatconnect.com/v3/indicators',
    'IOC_MIXED',
    'JSON',
    1800,
    1,
    true,
    false,
    'Commercial threat intelligence platform (requires subscription and API key)'
) ON CONFLICT (feed_name) DO NOTHING;

-- 16. Anomali ThreatStream
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'Anomali ThreatStream',
    'https://api.threatstream.com/api/v2/intelligence/',
    'IOC_MIXED',
    'JSON',
    1800,
    1,
    true,
    false,
    'Commercial threat intelligence aggregation platform (requires subscription and API key)'
) ON CONFLICT (feed_name) DO NOTHING;

-- 17. CrowdStrike Falcon Intelligence
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'CrowdStrike Falcon',
    'https://api.crowdstrike.com/intel/combined/indicators/v1',
    'IOC_MIXED',
    'JSON',
    1800,
    1,
    true,
    false,
    'CrowdStrike Falcon threat intelligence (requires subscription and API key)'
) ON CONFLICT (feed_name) DO NOTHING;

-- 18. Palo Alto Networks AutoFocus
INSERT INTO threat_feeds (
    feed_name, feed_url, feed_type, feed_format,
    update_interval, priority, api_key_required, enabled, description
) VALUES (
    'Palo Alto AutoFocus',
    'https://autofocus.paloaltonetworks.com/api/v1.0/samples/search',
    'IOC_MIXED',
    'JSON',
    1800,
    1,
    true,
    false,
    'Palo Alto Networks threat intelligence (requires subscription and API key)'
) ON CONFLICT (feed_name) DO NOTHING;

-- =============================================================================
-- VERIFICATION AND STATISTICS
-- =============================================================================

DO $$
DECLARE
    total_feeds INTEGER;
    enabled_feeds INTEGER;
    free_feeds INTEGER;
    commercial_feeds INTEGER;
BEGIN
    SELECT COUNT(*) INTO total_feeds FROM threat_feeds;
    SELECT COUNT(*) INTO enabled_feeds FROM threat_feeds WHERE enabled = true;
    SELECT COUNT(*) INTO free_feeds FROM threat_feeds WHERE api_key_required = false;
    SELECT COUNT(*) INTO commercial_feeds FROM threat_feeds WHERE api_key_required = true;
    
    RAISE NOTICE '=== Threat Feed Sources Configured ===';
    RAISE NOTICE 'Total feeds configured: %', total_feeds;
    RAISE NOTICE 'Enabled feeds: %', enabled_feeds;
    RAISE NOTICE 'Free feeds (no API key): %', free_feeds;
    RAISE NOTICE 'Commercial feeds (require API key): %', commercial_feeds;
    RAISE NOTICE '';
    RAISE NOTICE 'Priority breakdown:';
    RAISE NOTICE '  Priority 1 (Premium): % feeds', (SELECT COUNT(*) FROM threat_feeds WHERE priority = 1);
    RAISE NOTICE '  Priority 2 (High quality): % feeds', (SELECT COUNT(*) FROM threat_feeds WHERE priority = 2);
    RAISE NOTICE '  Priority 3 (Standard): % feeds', (SELECT COUNT(*) FROM threat_feeds WHERE priority = 3);
    RAISE NOTICE '  Priority 4 (Informational): % feeds', (SELECT COUNT(*) FROM threat_feeds WHERE priority = 4);
    RAISE NOTICE '';
    RAISE NOTICE 'Feed type breakdown:';
    RAISE NOTICE '  IP feeds: %', (SELECT COUNT(*) FROM threat_feeds WHERE feed_type = 'IP');
    RAISE NOTICE '  Domain feeds: %', (SELECT COUNT(*) FROM threat_feeds WHERE feed_type = 'DOMAIN');
    RAISE NOTICE '  URL feeds: %', (SELECT COUNT(*) FROM threat_feeds WHERE feed_type = 'URL');
    RAISE NOTICE '  Hash feeds: %', (SELECT COUNT(*) FROM threat_feeds WHERE feed_type = 'HASH');
    RAISE NOTICE '  Mixed IOC feeds: %', (SELECT COUNT(*) FROM threat_feeds WHERE feed_type = 'IOC_MIXED');
    RAISE NOTICE '';
    RAISE NOTICE 'To enable commercial feeds, configure API credentials in feed_credentials table';
    RAISE NOTICE 'To start feed updates, run the threat intelligence feed scheduler service';
END $$;
