-- ============================================================================
-- Threat Intelligence Database - Views
-- Common query views for easy access to threat data
-- ============================================================================

-- View: High Threat IPs (threat_score >= 70)
CREATE OR REPLACE VIEW high_threat_ips AS
SELECT 
    ip_address,
    threat_score,
    abuse_type,
    malware_family,
    confidence,
    sources,
    first_seen,
    last_seen
FROM ip_blacklist
WHERE is_malicious = TRUE AND threat_score >= 70 AND status = 'active'
ORDER BY threat_score DESC;

-- View: Active Malicious Domains
CREATE OR REPLACE VIEW active_malicious_domains AS
SELECT 
    domain,
    category,
    threat_score,
    phishing_target,
    registration_date,
    first_seen,
    last_seen
FROM domains
WHERE is_malicious = TRUE AND status = 'active'
ORDER BY threat_score DESC;

-- View: Recent Malware Hashes (last 7 days)
CREATE OR REPLACE VIEW recent_malware_hashes AS
SELECT 
    sha256,
    md5,
    file_type,
    malware_family,
    av_detection_rate,
    first_seen
FROM hashes
WHERE is_malicious = TRUE 
  AND first_seen >= NOW() - INTERVAL '7 days'
ORDER BY first_seen DESC;

-- View: Active Tor Exit Nodes
CREATE OR REPLACE VIEW active_tor_exits AS
SELECT 
    ip_address,
    tor_node_name,
    country_code,
    first_seen,
    last_seen
FROM ip_anonymization
WHERE is_tor = TRUE AND tor_exit_node = TRUE AND is_active = TRUE
ORDER BY last_seen DESC;

-- View: Critical IOCs
CREATE OR REPLACE VIEW critical_iocs AS
SELECT 
    ioc_type,
    ioc_value,
    threat_type,
    severity,
    threat_actor,
    confidence,
    first_seen
FROM iocs
WHERE severity = 'critical' AND status = 'active'
ORDER BY first_seen DESC;

-- View: Feed Performance Summary
CREATE OR REPLACE VIEW feed_performance_summary AS
SELECT 
    tf.feed_name,
    tf.feed_type,
    tf.is_active,
    tf.reliability_score,
    tf.total_records_imported,
    tf.last_successful_fetch,
    COUNT(fh.id) as total_executions,
    AVG(fh.execution_time_ms) as avg_execution_time,
    SUM(CASE WHEN fh.status = 'failed' THEN 1 ELSE 0 END) as failed_executions
FROM threat_feeds tf
LEFT JOIN feed_history fh ON tf.id = fh.feed_id
GROUP BY tf.id, tf.feed_name, tf.feed_type, tf.is_active, tf.reliability_score, 
         tf.total_records_imported, tf.last_successful_fetch;

-- View: Newly Registered Suspicious Domains (< 30 days)
CREATE OR REPLACE VIEW newly_registered_domains AS
SELECT 
    domain,
    registration_date,
    threat_score,
    category,
    age_days,
    first_seen
FROM domains
WHERE is_newly_registered = TRUE 
  AND (is_malicious = TRUE OR threat_score > 30)
ORDER BY registration_date DESC;

-- View: VPN Providers Summary
CREATE OR REPLACE VIEW vpn_providers_summary AS
SELECT 
    provider_name,
    COUNT(*) as ip_count,
    COUNT(DISTINCT country_code) as countries,
    AVG(risk_score) as avg_risk_score,
    MAX(last_seen) as last_seen
FROM ip_anonymization
WHERE is_vpn = TRUE AND provider_name IS NOT NULL
GROUP BY provider_name
ORDER BY ip_count DESC;

-- View: Threat Intelligence Statistics
CREATE OR REPLACE VIEW threat_stats AS
SELECT 
    'Total Malicious IPs' as metric,
    COUNT(*)::TEXT as value
FROM ip_blacklist WHERE is_malicious = TRUE
UNION ALL
SELECT 
    'Total Malicious Domains',
    COUNT(*)::TEXT
FROM domains WHERE is_malicious = TRUE
UNION ALL
SELECT 
    'Total Malware Hashes',
    COUNT(*)::TEXT
FROM hashes WHERE is_malicious = TRUE
UNION ALL
SELECT 
    'Active Tor Exit Nodes',
    COUNT(*)::TEXT
FROM ip_anonymization WHERE is_tor = TRUE AND is_active = TRUE
UNION ALL
SELECT 
    'Active IOCs',
    COUNT(*)::TEXT
FROM iocs WHERE status = 'active'
UNION ALL
SELECT 
    'Active Threat Feeds',
    COUNT(*)::TEXT
FROM threat_feeds WHERE is_active = TRUE;

-- ============================================================================
-- Materialized Views for Performance
-- ============================================================================

-- Materialized View: Daily Threat Statistics (refreshed daily)
CREATE MATERIALIZED VIEW daily_threat_stats AS
SELECT 
    CURRENT_DATE as stat_date,
    COUNT(DISTINCT ip_address) as total_malicious_ips,
    COUNT(DISTINCT domain) as total_malicious_domains,
    COUNT(DISTINCT sha256) as total_malware_hashes,
    (SELECT COUNT(*) FROM ip_anonymization WHERE is_tor = TRUE) as total_tor_nodes,
    (SELECT COUNT(*) FROM ip_anonymization WHERE is_vpn = TRUE) as total_vpn_ips
FROM ip_blacklist
CROSS JOIN domains
CROSS JOIN hashes
WHERE ip_blacklist.is_malicious = TRUE
  AND domains.is_malicious = TRUE
  AND hashes.is_malicious = TRUE;

CREATE UNIQUE INDEX ON daily_threat_stats(stat_date);

-- Materialized View: Top Threat Actors
CREATE MATERIALIZED VIEW top_threat_actors AS
SELECT 
    threat_actor,
    COUNT(*) as ioc_count,
    COUNT(DISTINCT ioc_type) as ioc_types,
    MAX(first_seen) as last_activity
FROM iocs
WHERE threat_actor IS NOT NULL AND status = 'active'
GROUP BY threat_actor
ORDER BY ioc_count DESC;

CREATE UNIQUE INDEX ON top_threat_actors(threat_actor);

COMMENT ON MATERIALIZED VIEW daily_threat_stats IS 'Daily aggregated threat statistics';
COMMENT ON MATERIALIZED VIEW top_threat_actors IS 'Most active threat actors by IOC count';
