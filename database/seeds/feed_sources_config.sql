-- Feed Sources Configuration
-- Initial threat intelligence feed sources

INSERT INTO threat_feeds (feed_name, feed_url, feed_type, update_frequency, status) VALUES
    ('AlienVault IP Reputation', 'https://reputation.alienvault.com/reputation.generic', 'ip', 86400, 'active'),
    ('Abuse.ch URLhaus', 'https://urlhaus.abuse.ch/downloads/csv_recent/', 'url', 3600, 'active'),
    ('Tor Exit Nodes', 'https://check.torproject.org/torbulkexitlist', 'proxy', 3600, 'active'),
    ('Feodo Tracker', 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', 'ip', 3600, 'active')
ON CONFLICT (feed_name) DO NOTHING;
