-- ============================================================================
-- Initial Threat Intelligence Feeds
-- Popular open-source threat feeds configuration
-- ============================================================================

INSERT INTO threat_feeds (
    feed_name, 
    feed_url, 
    feed_type, 
    feed_format, 
    update_frequency, 
    is_active,
    feed_description
) VALUES
(
    'Feodo Tracker', 
    'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 
    'ip_blacklist', 
    'txt', 
    300, 
    TRUE,
    'Feodo Tracker - Botnet C2 IP addresses'
),
(
    'URLhaus Recent', 
    'https://urlhaus.abuse.ch/downloads/csv_recent/', 
    'domain', 
    'csv', 
    300, 
    TRUE,
    'URLhaus - Recent malicious URLs'
),
(
    'Blocklist.de All', 
    'https://lists.blocklist.de/lists/all.txt', 
    'ip_blacklist', 
    'txt', 
    900, 
    TRUE,
    'Blocklist.de - IP addresses that attacked servers'
),
(
    'IPsum', 
    'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt', 
    'ip_blacklist', 
    'txt', 
    86400, 
    TRUE,
    'IPsum - Daily malicious IP threat list'
),
(
    'Tor Exit Nodes', 
    'https://check.torproject.org/exit-addresses', 
    'ip_anonymization', 
    'txt', 
    3600, 
    TRUE,
    'Tor Project - Current Tor exit node IPs'
),
(
    'PhishTank', 
    'http://data.phishtank.com/data/online-valid.csv', 
    'domain', 
    'csv', 
    3600, 
    TRUE,
    'PhishTank - Verified phishing URLs'
),
(
    'OpenPhish', 
    'https://openphish.com/feed.txt', 
    'domain', 
    'txt', 
    3600, 
    TRUE,
    'OpenPhish - Active phishing URLs'
),
(
    'MalwareBazaar', 
    'https://bazaar.abuse.ch/export/csv/recent/', 
    'hash', 
    'csv', 
    300, 
    TRUE,
    'MalwareBazaar - Recent malware file hashes'
),
(
    'ThreatFox', 
    'https://threatfox.abuse.ch/export/csv/recent/', 
    'ioc', 
    'csv', 
    300, 
    TRUE,
    'ThreatFox - IOCs from various threat campaigns'
),
(
    'Emerging Threats', 
    'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', 
    'ip_blacklist', 
    'txt', 
    86400, 
    TRUE,
    'Emerging Threats - Compromised and malicious IPs'
);

-- Update next_scheduled_fetch for all feeds
UPDATE threat_feeds 
SET next_scheduled_fetch = CURRENT_TIMESTAMP 
WHERE next_scheduled_fetch IS NULL;
