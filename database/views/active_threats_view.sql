-- ============================================================================
-- SafeOps Threat Intelligence Database - Active Threats View
-- File: active_threats_view.sql
-- Purpose: Unified real-time view of active high-severity threats for SOC monitoring
-- ============================================================================

-- =============================================================================
-- VIEW: active_threats_view
-- =============================================================================

CREATE OR REPLACE VIEW active_threats_view AS

-- IP Threats
SELECT 
    'IP_' || r.ip_id::TEXT AS threat_id,
    'IP'::TEXT AS threat_type,
    host(r.ip_address)::TEXT AS threat_value,
    r.reputation_score,
    r.confidence_level,
    CASE 
        WHEN r.reputation_score <= -80 THEN 10
        WHEN r.reputation_score <= -70 THEN 9
        WHEN r.reputation_score <= -60 THEN 8
        WHEN r.reputation_score <= -50 THEN 7
        WHEN r.reputation_score <= -40 THEN 6
        WHEN r.reputation_score <= -30 THEN 5
        ELSE 4
    END AS severity_level,
    COALESCE(tc.category_name, 'UNKNOWN') AS threat_category,
    r.first_seen,
    r.last_seen,
    r.total_reports,
    true AS is_active,
    r.country_code,
    r.asn_id,
    NULL::TEXT[] AS associated_campaigns,
    COALESCE(
        ARRAY_AGG(DISTINCT tf.feed_name ORDER BY tf.feed_name) 
        FILTER (WHERE tf.feed_name IS NOT NULL),
        ARRAY[]::TEXT[]
    ) AS feed_sources,
    CASE 
        WHEN (ABS(r.reputation_score) * r.confidence_level * 
              CASE WHEN r.reputation_score <= -80 THEN 10 ELSE 7 END / 10) > 75 
             AND r.confidence_level > 0.80 
        THEN 'BLOCK'
        WHEN (ABS(r.reputation_score) * r.confidence_level * 
              CASE WHEN r.reputation_score <= -80 THEN 10 ELSE 7 END / 10) > 50 
             AND r.confidence_level > 0.60 
        THEN 'ALERT'
        WHEN (ABS(r.reputation_score) * r.confidence_level * 
              CASE WHEN r.reputation_score <= -80 THEN 10 ELSE 7 END / 10) > 25 
             OR r.confidence_level > 0.40 
        THEN 'MONITOR'
        ELSE 'LOG'
    END AS action_recommended,
    ROUND((ABS(r.reputation_score) * r.confidence_level * 
           CASE WHEN r.reputation_score <= -80 THEN 10 ELSE 7 END / 10)::NUMERIC)::INTEGER AS priority
FROM ip_reputation r
LEFT JOIN threat_categories tc ON tc.category_id = r.threat_category_id
LEFT JOIN ip_reputation_sources rs ON rs.ip_id = r.ip_id
LEFT JOIN threat_feeds tf ON tf.feed_id = rs.feed_id
WHERE r.reputation_score < -25
  AND r.last_seen > NOW() - INTERVAL '30 days'
  AND r.is_whitelisted = false
GROUP BY r.ip_id, r.ip_address, r.reputation_score, r.confidence_level, 
         r.first_seen, r.last_seen, r.total_reports, r.country_code, 
         r.asn_id, tc.category_name

UNION ALL

-- Domain Threats
SELECT 
    'DOMAIN_' || d.domain_id::TEXT AS threat_id,
    'DOMAIN'::TEXT AS threat_type,
    d.domain_name::TEXT AS threat_value,
    d.reputation_score,
    d.confidence_level,
    CASE 
        WHEN d.reputation_score <= -80 THEN 10
        WHEN d.reputation_score <= -70 THEN 9
        WHEN d.reputation_score <= -60 THEN 8
        WHEN d.reputation_score <= -50 THEN 7
        WHEN d.reputation_score <= -40 THEN 6
        WHEN d.reputation_score <= -30 THEN 5
        ELSE 4
    END AS severity_level,
    COALESCE(tc.category_name, 'UNKNOWN') AS threat_category,
    d.first_seen,
    d.last_seen,
    d.total_reports,
    true AS is_active,
    NULL::CHAR(2) AS country_code,
    NULL::INTEGER AS asn_id,
    NULL::TEXT[] AS associated_campaigns,
    COALESCE(
        ARRAY_AGG(DISTINCT tf.feed_name ORDER BY tf.feed_name) 
        FILTER (WHERE tf.feed_name IS NOT NULL),
        ARRAY[]::TEXT[]
    ) AS feed_sources,
    CASE 
        WHEN (ABS(d.reputation_score) * d.confidence_level * 
              CASE WHEN d.reputation_score <= -80 THEN 10 ELSE 7 END / 10) > 75 
             AND d.confidence_level > 0.80 
        THEN 'BLOCK'
        WHEN (ABS(d.reputation_score) * d.confidence_level * 
              CASE WHEN d.reputation_score <= -80 THEN 10 ELSE 7 END / 10) > 50 
             AND d.confidence_level > 0.60 
        THEN 'ALERT'
        WHEN (ABS(d.reputation_score) * d.confidence_level * 
              CASE WHEN d.reputation_score <= -80 THEN 10 ELSE 7 END / 10) > 25 
             OR d.confidence_level > 0.40 
        THEN 'MONITOR'
        ELSE 'LOG'
    END AS action_recommended,
    ROUND((ABS(d.reputation_score) * d.confidence_level * 
           CASE WHEN d.reputation_score <= -80 THEN 10 ELSE 7 END / 10)::NUMERIC)::INTEGER AS priority
FROM domain_reputation d
LEFT JOIN threat_categories tc ON tc.category_id = d.threat_category_id
LEFT JOIN domain_reputation_sources ds ON ds.domain_id = d.domain_id
LEFT JOIN threat_feeds tf ON tf.feed_id = ds.feed_id
WHERE d.reputation_score < -25
  AND d.last_seen > NOW() - INTERVAL '30 days'
  AND d.is_whitelisted = false
GROUP BY d.domain_id, d.domain_name, d.reputation_score, d.confidence_level,
         d.first_seen, d.last_seen, d.total_reports, tc.category_name

UNION ALL

-- Hash Threats
SELECT 
    'HASH_' || h.hash_id::TEXT AS threat_id,
    'HASH'::TEXT AS threat_type,
    h.sha256_hash::TEXT AS threat_value,
    h.reputation_score,
    h.confidence_level,
    CASE 
        WHEN h.reputation_score <= -80 THEN 10
        WHEN h.reputation_score <= -70 THEN 9
        WHEN h.reputation_score <= -60 THEN 8
        ELSE 7
    END AS severity_level,
    COALESCE(tc.category_name, h.malware_family, 'UNKNOWN') AS threat_category,
    h.first_seen,
    h.last_seen,
    h.total_reports,
    true AS is_active,
    NULL::CHAR(2) AS country_code,
    NULL::INTEGER AS asn_id,
    NULL::TEXT[] AS associated_campaigns,
    COALESCE(
        ARRAY_AGG(DISTINCT tf.feed_name ORDER BY tf.feed_name) 
        FILTER (WHERE tf.feed_name IS NOT NULL),
        ARRAY[]::TEXT[]
    ) AS feed_sources,
    CASE 
        WHEN (ABS(h.reputation_score) * h.confidence_level * 9 / 10) > 75 
             AND h.confidence_level > 0.80 
        THEN 'BLOCK'
        WHEN (ABS(h.reputation_score) * h.confidence_level * 9 / 10) > 50 
             AND h.confidence_level > 0.60 
        THEN 'ALERT'
        WHEN (ABS(h.reputation_score) * h.confidence_level * 9 / 10) > 25 
             OR h.confidence_level > 0.40 
        THEN 'MONITOR'
        ELSE 'LOG'
    END AS action_recommended,
    ROUND((ABS(h.reputation_score) * h.confidence_level * 9 / 10)::NUMERIC)::INTEGER AS priority
FROM hash_reputation h
LEFT JOIN threat_categories tc ON tc.category_id = h.threat_category_id
LEFT JOIN hash_reputation_sources hs ON hs.hash_id = h.hash_id
LEFT JOIN threat_feeds tf ON tf.feed_id = hs.feed_id
WHERE h.reputation_score < -50
  AND h.last_seen > NOW() - INTERVAL '90 days'
  AND h.is_whitelisted = false
GROUP BY h.hash_id, h.sha256_hash, h.reputation_score, h.confidence_level,
         h.first_seen, h.last_seen, h.total_reports, h.malware_family, tc.category_name

UNION ALL

-- IOC Indicators
SELECT 
    'IOC_' || i.ioc_id::TEXT AS threat_id,
    'IOC_' || i.ioc_type AS threat_type,
    i.ioc_value AS threat_value,
    i.reputation_score,
    i.confidence_level,
    i.severity AS severity_level,
    COALESCE(tc.category_name, 'UNKNOWN') AS threat_category,
    i.first_seen,
    i.last_seen,
    i.total_reports,
    i.is_active,
    NULL::CHAR(2) AS country_code,
    NULL::INTEGER AS asn_id,
    COALESCE(
        ARRAY_AGG(DISTINCT c.campaign_name ORDER BY c.campaign_name) 
        FILTER (WHERE c.campaign_name IS NOT NULL),
        ARRAY[]::TEXT[]
    ) AS associated_campaigns,
    COALESCE(
        ARRAY_AGG(DISTINCT tf.feed_name ORDER BY tf.feed_name) 
        FILTER (WHERE tf.feed_name IS NOT NULL),
        ARRAY[]::TEXT[]
    ) AS feed_sources,
    CASE 
        WHEN (ABS(i.reputation_score) * i.confidence_level * i.severity / 10) > 75 
             AND i.confidence_level > 0.80 
        THEN 'BLOCK'
        WHEN (ABS(i.reputation_score) * i.confidence_level * i.severity / 10) > 50 
             AND i.confidence_level > 0.60 
        THEN 'ALERT'
        WHEN (ABS(i.reputation_score) * i.confidence_level * i.severity / 10) > 25 
             OR i.confidence_level > 0.40 
        THEN 'MONITOR'
        ELSE 'LOG'
    END AS action_recommended,
    ROUND((ABS(i.reputation_score) * i.confidence_level * i.severity / 10)::NUMERIC)::INTEGER AS priority
FROM ioc_indicators i
LEFT JOIN threat_categories tc ON tc.category_id = i.threat_category_id
LEFT JOIN ioc_sources isrc ON isrc.ioc_id = i.ioc_id
LEFT JOIN threat_feeds tf ON tf.feed_id = isrc.feed_id
LEFT JOIN ioc_campaign_associations ica ON ica.ioc_id = i.ioc_id
LEFT JOIN ioc_campaigns c ON c.campaign_id = ica.campaign_id
WHERE i.reputation_score < -25
  AND i.is_active = true
GROUP BY i.ioc_id, i.ioc_type, i.ioc_value, i.reputation_score, i.confidence_level,
         i.severity, i.first_seen, i.last_seen, i.total_reports, i.is_active, tc.category_name;

-- Add comment
COMMENT ON VIEW active_threats_view IS 'Unified real-time view of active high-severity threats for SOC monitoring';

-- =============================================================================
-- MATERIALIZED VIEW VERSION (Optional - for better performance)
-- =============================================================================

-- Uncomment to create materialized version:
/*
CREATE MATERIALIZED VIEW active_threats_mv AS
SELECT * FROM active_threats_view;

CREATE INDEX idx_active_threats_mv_type ON active_threats_mv(threat_type);
CREATE INDEX idx_active_threats_mv_priority ON active_threats_mv(priority DESC);
CREATE INDEX idx_active_threats_mv_last_seen ON active_threats_mv(last_seen DESC);
CREATE INDEX idx_active_threats_mv_action ON active_threats_mv(action_recommended);
CREATE INDEX idx_active_threats_mv_severity ON active_threats_mv(severity_level DESC);

COMMENT ON MATERIALIZED VIEW active_threats_mv IS 'Materialized version of active_threats_view - refresh every 15 minutes';
*/

-- =============================================================================
-- HELPER VIEWS
-- =============================================================================

-- View: active_threats_by_severity
CREATE OR REPLACE VIEW active_threats_by_severity AS
SELECT 
    threat_type,
    severity_level,
    COUNT(*) AS threat_count,
    AVG(priority)::INTEGER AS avg_priority,
    MAX(last_seen) AS most_recent
FROM active_threats_view
GROUP BY threat_type, severity_level
ORDER BY threat_type, severity_level DESC;

COMMENT ON VIEW active_threats_by_severity IS 'Summary of active threats grouped by type and severity';

-- View: critical_active_threats  
CREATE OR REPLACE VIEW critical_active_threats AS
SELECT *
FROM active_threats_view
WHERE priority >= 75
   OR (severity_level >= 9 AND confidence_level >= 0.80)
ORDER BY priority DESC, last_seen DESC;

COMMENT ON VIEW critical_active_threats IS 'Only critical threats requiring immediate action';

-- View: active_threats_by_country
CREATE OR REPLACE VIEW active_threats_by_country AS
SELECT 
    country_code,
    threat_type,
    COUNT(*) AS threat_count,
    AVG(reputation_score)::INTEGER AS avg_reputation,
    AVG(priority)::INTEGER AS avg_priority
FROM active_threats_view
WHERE country_code IS NOT NULL
GROUP BY country_code, threat_type
ORDER BY threat_count DESC;

COMMENT ON VIEW active_threats_by_country IS 'Active threats grouped by country and type';

-- =============================================================================
-- VERIFICATION
-- =============================================================================

DO $$
DECLARE
    view_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO view_count 
    FROM pg_views 
    WHERE schemaname = 'public' 
      AND viewname LIKE '%active_threat%';
    
    RAISE NOTICE '=== Active Threats Views Initialized ===';
    RAISE NOTICE 'Views created: %', view_count;
    RAISE NOTICE 'Main view: active_threats_view';
    RAISE NOTICE 'Helper views:';
    RAISE NOTICE '  - active_threats_by_severity';
    RAISE NOTICE '  - critical_active_threats';
    RAISE NOTICE '  - active_threats_by_country';
    RAISE NOTICE '';
    RAISE NOTICE 'To create materialized version for better performance:';
    RAISE NOTICE '  Uncomment materialized view section in this file';
    RAISE NOTICE '  Schedule refresh: SELECT cron.schedule(''refresh_threats'', ''*/15 * * * *'', $$REFRESH MATERIALIZED VIEW CONCURRENTLY active_threats_mv$$);';
END $$;
