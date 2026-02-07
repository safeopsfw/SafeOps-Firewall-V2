-- ============================================================================
-- SafeOps v2.0 - Views and Functions for Threat Intel Dashboard
-- ============================================================================
-- Purpose: Creates corrected views and helper functions.
--          Fixes column references from base schemas (ip_range -> ip_address,
--          updated_at -> last_seen).
-- Run after: 001_threat_intel_patches.sql
-- Idempotent: Uses CREATE OR REPLACE, DROP IF EXISTS
-- ============================================================================

-- ============================================================================
-- GEOLOCATION VIEWS
-- ============================================================================

CREATE OR REPLACE VIEW country_ip_distribution AS
SELECT
    country_code,
    country_name,
    COUNT(*) as ip_count,
    COUNT(DISTINCT asn) as unique_asns,
    AVG(confidence)::DECIMAL(5,2) as avg_confidence
FROM ip_geolocation
WHERE country_code IS NOT NULL
GROUP BY country_code, country_name
ORDER BY ip_count DESC;

CREATE OR REPLACE VIEW top_asns AS
SELECT
    g.asn,
    g.asn_org,
    a.reputation_score,
    COUNT(g.ip_address) as ip_count,
    COUNT(DISTINCT g.country_code) as countries
FROM ip_geolocation g
LEFT JOIN asn_info a ON g.asn = a.asn
WHERE g.asn IS NOT NULL
GROUP BY g.asn, g.asn_org, a.reputation_score
ORDER BY ip_count DESC
LIMIT 100;

CREATE OR REPLACE VIEW mobile_networks AS
SELECT
    country_code,
    isp,
    COUNT(*) as ip_count
FROM ip_geolocation
WHERE is_mobile = TRUE
GROUP BY country_code, isp
ORDER BY country_code, ip_count DESC;

CREATE OR REPLACE VIEW datacenter_ips AS
SELECT
    asn_org,
    country_code,
    COUNT(*) as ip_count
FROM ip_geolocation
WHERE is_hosting = TRUE
GROUP BY asn_org, country_code
ORDER BY ip_count DESC;

-- ============================================================================
-- DASHBOARD STATISTICS VIEW
-- ============================================================================
-- Corrected column references:
--   ip_range -> ip_address (ip_geolocation join)
--   updated_at -> last_seen (domains weekly activity)

DROP VIEW IF EXISTS threat_summary_stats CASCADE;

CREATE OR REPLACE VIEW threat_summary_stats AS

WITH overall_counts AS (
    SELECT
        'overall' AS metric_type,
        (SELECT COUNT(*) FROM ip_blacklist WHERE is_malicious = TRUE) AS total_malicious_ips,
        (SELECT COUNT(*) FROM domains WHERE is_malicious = TRUE AND status = 'active') AS total_malicious_domains,
        (SELECT COUNT(*) FROM file_hashes WHERE is_malicious = TRUE AND status = 'active') AS total_malware_hashes,
        (SELECT COUNT(*) FROM vpn_ips WHERE is_active = TRUE) AS total_vpn_ips,
        (SELECT COUNT(*) FROM vpn_ips WHERE service_type = 'tor_exit' AND is_active = TRUE) AS total_tor_nodes,
        (SELECT COUNT(*) FROM threat_feeds WHERE is_active = TRUE) AS total_active_feeds,
        (SELECT COUNT(*) FROM threat_feeds) AS total_feeds,
        (SELECT MAX(last_successful_fetch) FROM threat_feeds) AS last_feed_update
),

total_active_threats AS (
    SELECT
        (SELECT total_malicious_ips FROM overall_counts) +
        (SELECT total_malicious_domains FROM overall_counts) +
        (SELECT total_malware_hashes FROM overall_counts) AS total_active_threats
),

ip_by_category AS (
    SELECT 'ip_abuse' AS threat_type, abuse_type AS category_name, COUNT(*) AS category_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score, MAX(threat_score) AS highest_threat_score,
        COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '24 hours') AS new_24h
    FROM ip_blacklist WHERE is_malicious = TRUE GROUP BY abuse_type
),

domain_by_category AS (
    SELECT 'domain' AS threat_type, category AS category_name, COUNT(*) AS category_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score, MAX(threat_score) AS highest_threat_score,
        COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '24 hours') AS new_24h
    FROM domains WHERE is_malicious = TRUE AND status = 'active' GROUP BY category
),

malware_by_type AS (
    SELECT 'malware' AS threat_type, malware_type AS category_name, COUNT(*) AS category_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score, MAX(threat_score) AS highest_threat_score,
        COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '24 hours') AS new_24h
    FROM file_hashes WHERE is_malicious = TRUE AND status = 'active' AND malware_type IS NOT NULL GROUP BY malware_type
),

category_summary AS (
    SELECT * FROM ip_by_category UNION ALL SELECT * FROM domain_by_category UNION ALL SELECT * FROM malware_by_type
),

threats_by_country AS (
    SELECT geo.country_code, geo.country_name, COUNT(DISTINCT ip.ip_address) AS threat_count,
        ROUND(AVG(ip.threat_score), 2) AS avg_threat_score,
        MODE() WITHIN GROUP (ORDER BY ip.abuse_type) AS top_abuse_type,
        COUNT(*) FILTER (WHERE ip.first_seen >= NOW() - INTERVAL '24 hours') AS new_24h
    FROM ip_blacklist ip
    JOIN ip_geolocation geo ON ip.ip_address = geo.ip_address
    WHERE ip.is_malicious = TRUE
    GROUP BY geo.country_code, geo.country_name ORDER BY threat_count DESC LIMIT 50
),

ip_trends_24h AS (
    SELECT date_trunc('hour', first_seen) AS hour_bucket, 'ip' AS threat_type,
        COUNT(*) AS new_threats_count, ROUND(AVG(threat_score), 2) AS avg_threat_score
    FROM ip_blacklist WHERE first_seen >= NOW() - INTERVAL '24 hours'
    GROUP BY date_trunc('hour', first_seen)
),

domain_trends_24h AS (
    SELECT date_trunc('hour', first_seen) AS hour_bucket, 'domain' AS threat_type,
        COUNT(*) AS new_threats_count, ROUND(AVG(threat_score), 2) AS avg_threat_score
    FROM domains WHERE first_seen >= NOW() - INTERVAL '24 hours' AND is_malicious = TRUE
    GROUP BY date_trunc('hour', first_seen)
),

hash_trends_24h AS (
    SELECT date_trunc('hour', first_seen) AS hour_bucket, 'hash' AS threat_type,
        COUNT(*) AS new_threats_count, ROUND(AVG(threat_score), 2) AS avg_threat_score
    FROM file_hashes WHERE first_seen >= NOW() - INTERVAL '24 hours' AND is_malicious = TRUE
    GROUP BY date_trunc('hour', first_seen)
),

hourly_trends AS (
    SELECT * FROM ip_trends_24h UNION ALL SELECT * FROM domain_trends_24h
    UNION ALL SELECT * FROM hash_trends_24h
    ORDER BY hour_bucket DESC, threat_type
),

threats_by_asn AS (
    SELECT geo.asn, geo.asn_org, COUNT(DISTINCT ip.ip_address) AS threat_count,
        ROUND(AVG(ip.threat_score), 2) AS avg_threat_score,
        ARRAY_AGG(DISTINCT geo.country_code) AS country_codes,
        MODE() WITHIN GROUP (ORDER BY ip.abuse_type) AS top_abuse_type
    FROM ip_blacklist ip
    JOIN ip_geolocation geo ON ip.ip_address = geo.ip_address
    WHERE ip.is_malicious = TRUE AND geo.asn IS NOT NULL
    GROUP BY geo.asn, geo.asn_org ORDER BY threat_count DESC LIMIT 25
),

feed_performance AS (
    SELECT COUNT(*) AS total_feeds,
        COUNT(*) FILTER (WHERE is_active = TRUE) AS active_feeds_count,
        COUNT(*) FILTER (WHERE is_active = FALSE) AS inactive_feeds_count,
        COUNT(*) FILTER (WHERE last_fetch_status = 'failed') AS failing_feeds_count,
        COUNT(*) FILTER (WHERE last_fetch_status = 'success') AS successful_feeds_count,
        MAX(last_successful_fetch) AS last_successful_update,
        MIN(last_successful_fetch) AS oldest_successful_update,
        ROUND(AVG(total_records_imported), 2) AS avg_records_per_feed,
        SUM(total_records_imported) AS total_records_imported,
        ROUND(AVG(reliability_score), 2) AS avg_reliability_score
    FROM threat_feeds
),

database_health AS (
    SELECT pg_size_pretty(pg_database_size(current_database())) AS database_size,
        pg_database_size(current_database()) AS database_size_bytes,
        ((SELECT COUNT(*) FROM ip_blacklist) + (SELECT COUNT(*) FROM domains) +
         (SELECT COUNT(*) FROM file_hashes) + (SELECT COUNT(*) FROM vpn_ips)) AS total_records,
        (SELECT MIN(first_seen) FROM (
            SELECT MIN(first_seen) AS first_seen FROM ip_blacklist UNION ALL
            SELECT MIN(first_seen) FROM domains UNION ALL
            SELECT MIN(first_seen) FROM file_hashes) AS min_dates) AS oldest_threat,
        (SELECT MAX(last_seen) FROM (
            SELECT MAX(last_seen) AS last_seen FROM ip_blacklist UNION ALL
            SELECT MAX(last_seen) FROM domains UNION ALL
            SELECT MAX(last_seen) FROM file_hashes) AS max_dates) AS newest_threat,
        NOW() AS stats_generated_at
),

severity_distribution AS (
    SELECT CASE WHEN threat_score >= 9 THEN 'critical' WHEN threat_score >= 7 THEN 'high'
        WHEN threat_score >= 5 THEN 'medium' WHEN threat_score >= 3 THEN 'low'
        ELSE 'informational' END AS severity_level, COUNT(*) AS count
    FROM (SELECT threat_score FROM ip_blacklist WHERE is_malicious = TRUE UNION ALL
          SELECT threat_score FROM domains WHERE is_malicious = TRUE UNION ALL
          SELECT threat_score FROM file_hashes WHERE is_malicious = TRUE) AS all_threats
    GROUP BY severity_level
),

weekly_activity AS (
    SELECT 'last_7_days' AS period,
        (SELECT COUNT(*) FROM ip_blacklist WHERE first_seen >= NOW() - INTERVAL '7 days') AS new_ips,
        (SELECT COUNT(*) FROM domains WHERE first_seen >= NOW() - INTERVAL '7 days' AND is_malicious = TRUE) AS new_domains,
        (SELECT COUNT(*) FROM file_hashes WHERE first_seen >= NOW() - INTERVAL '7 days' AND is_malicious = TRUE) AS new_hashes,
        (SELECT COUNT(*) FROM ip_blacklist WHERE last_seen >= NOW() - INTERVAL '7 days') AS active_ips,
        (SELECT COUNT(*) FROM domains WHERE last_seen >= NOW() - INTERVAL '7 days' AND is_malicious = TRUE) AS active_domains
)

SELECT
    (SELECT total_malicious_ips FROM overall_counts) AS total_malicious_ips,
    (SELECT total_malicious_domains FROM overall_counts) AS total_malicious_domains,
    (SELECT total_malware_hashes FROM overall_counts) AS total_malware_hashes,
    (SELECT total_vpn_ips FROM overall_counts) AS total_vpn_ips,
    (SELECT total_tor_nodes FROM overall_counts) AS total_tor_nodes,
    (SELECT total_active_feeds FROM overall_counts) AS total_active_feeds,
    (SELECT total_feeds FROM overall_counts) AS total_feeds,
    (SELECT total_active_threats FROM total_active_threats) AS total_active_threats,
    (SELECT active_feeds_count FROM feed_performance) AS active_feeds_count,
    (SELECT failing_feeds_count FROM feed_performance) AS failing_feeds_count,
    (SELECT last_successful_update FROM feed_performance) AS last_feed_update,
    (SELECT avg_records_per_feed FROM feed_performance) AS avg_records_per_feed,
    (SELECT avg_reliability_score FROM feed_performance) AS avg_reliability_score,
    (SELECT database_size FROM database_health) AS database_size,
    (SELECT database_size_bytes FROM database_health) AS database_size_bytes,
    (SELECT total_records FROM database_health) AS total_records,
    (SELECT oldest_threat FROM database_health) AS oldest_threat,
    (SELECT newest_threat FROM database_health) AS newest_threat,
    (SELECT stats_generated_at FROM database_health) AS stats_generated_at,
    (SELECT new_ips FROM weekly_activity) AS new_ips_7d,
    (SELECT new_domains FROM weekly_activity) AS new_domains_7d,
    (SELECT new_hashes FROM weekly_activity) AS new_hashes_7d,
    (SELECT active_ips FROM weekly_activity) AS active_ips_7d,
    (SELECT active_domains FROM weekly_activity) AS active_domains_7d,
    (SELECT json_agg(row_to_json(c.*)) FROM category_summary c) AS threats_by_category,
    (SELECT json_agg(row_to_json(t.*)) FROM threats_by_country t) AS threats_by_country,
    (SELECT json_agg(row_to_json(h.*)) FROM hourly_trends h) AS hourly_trends_24h,
    (SELECT json_agg(row_to_json(a.*)) FROM threats_by_asn a) AS threats_by_asn,
    (SELECT json_agg(row_to_json(s.*)) FROM severity_distribution s) AS severity_distribution;

-- ============================================================================
-- HELPER FUNCTIONS FOR DASHBOARD API
-- ============================================================================

CREATE OR REPLACE FUNCTION get_threat_count_summary()
RETURNS TABLE(metric_name TEXT, metric_value BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT 'malicious_ips'::TEXT, COUNT(*)::BIGINT FROM ip_blacklist WHERE is_malicious = TRUE
    UNION ALL SELECT 'malicious_domains'::TEXT, COUNT(*)::BIGINT FROM domains WHERE is_malicious = TRUE
    UNION ALL SELECT 'malware_hashes'::TEXT, COUNT(*)::BIGINT FROM file_hashes WHERE is_malicious = TRUE
    UNION ALL SELECT 'vpn_ips'::TEXT, COUNT(*)::BIGINT FROM vpn_ips WHERE is_active = TRUE
    UNION ALL SELECT 'active_feeds'::TEXT, COUNT(*)::BIGINT FROM threat_feeds WHERE is_active = TRUE;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_category_breakdown(p_threat_type TEXT)
RETURNS TABLE(category_name TEXT, count BIGINT, avg_score NUMERIC, max_score INTEGER) AS $$
BEGIN
    IF p_threat_type = 'ip' THEN
        RETURN QUERY SELECT abuse_type::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2), MAX(threat_score)
            FROM ip_blacklist WHERE is_malicious = TRUE GROUP BY abuse_type ORDER BY COUNT(*) DESC;
    ELSIF p_threat_type = 'domain' THEN
        RETURN QUERY SELECT category::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2), MAX(threat_score)
            FROM domains WHERE is_malicious = TRUE AND status = 'active' GROUP BY category ORDER BY COUNT(*) DESC;
    ELSIF p_threat_type = 'malware' THEN
        RETURN QUERY SELECT malware_type::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2), MAX(threat_score)
            FROM file_hashes WHERE is_malicious = TRUE AND status = 'active' AND malware_type IS NOT NULL
            GROUP BY malware_type ORDER BY COUNT(*) DESC;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_hourly_trends(p_hours INTEGER DEFAULT 24)
RETURNS TABLE(hour TIMESTAMP, threat_type TEXT, new_count BIGINT, avg_score NUMERIC) AS $$
BEGIN
    RETURN QUERY
    SELECT date_trunc('hour', first_seen)::TIMESTAMP, 'ip'::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2)
        FROM ip_blacklist WHERE first_seen >= NOW() - (p_hours || ' hours')::INTERVAL
        GROUP BY date_trunc('hour', first_seen)
    UNION ALL
    SELECT date_trunc('hour', first_seen)::TIMESTAMP, 'domain'::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2)
        FROM domains WHERE first_seen >= NOW() - (p_hours || ' hours')::INTERVAL AND is_malicious = TRUE
        GROUP BY date_trunc('hour', first_seen)
    UNION ALL
    SELECT date_trunc('hour', first_seen)::TIMESTAMP, 'hash'::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2)
        FROM file_hashes WHERE first_seen >= NOW() - (p_hours || ' hours')::INTERVAL AND is_malicious = TRUE
        GROUP BY date_trunc('hour', first_seen)
    ORDER BY 1 DESC, 2;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- END OF VIEWS AND FUNCTIONS
-- ============================================================================
