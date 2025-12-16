-- ============================================================================
-- SafeOps Threat Intelligence Database - Threat Summary Statistics
-- File: threat_summary_stats.sql
-- Purpose: Aggregated statistical summaries for reporting and dashboards
-- ============================================================================

-- =============================================================================
-- MATERIALIZED VIEW: threat_summary_stats
-- =============================================================================
-- Note: Using materialized view for performance (refresh every 15-30 minutes)

CREATE MATERIALIZED VIEW IF NOT EXISTS threat_summary_stats AS
WITH time_periods AS (
    SELECT 
        '24H' AS time_period,
        NOW() - INTERVAL '24 hours' AS cutoff_time
    UNION ALL SELECT '7D', NOW() - INTERVAL '7 days'
    UNION ALL SELECT '30D', NOW() - INTERVAL '30 days'
    UNION ALL SELECT '90D', NOW() - INTERVAL '90 days'
    UNION ALL SELECT 'ALL_TIME', '1970-01-01'::TIMESTAMP WITH TIME ZONE
),
threat_counts_by_period AS (
    SELECT 
        tp.time_period,
        COUNT(DISTINCT r.ip_id) FILTER (
            WHERE r.reputation_score < -25 AND r.last_seen >= tp.cutoff_time
        ) AS ip_count,
        COUNT(DISTINCT d.domain_id) FILTER (
            WHERE d.reputation_score < -25 AND d.last_seen >= tp.cutoff_time
        ) AS domain_count,
        COUNT(DISTINCT h.hash_id) FILTER (
            WHERE h.reputation_score < -50 AND h.last_seen >= tp.cutoff_time
        ) AS hash_count,
        COUNT(DISTINCT i.ioc_id) FILTER (
            WHERE i.is_active = true AND i.last_seen >= tp.cutoff_time
        ) AS ioc_count
    FROM time_periods tp
    CROSS JOIN ip_reputation r
    CROSS JOIN domain_reputation d
    CROSS JOIN hash_reputation h
    CROSS JOIN ioc_indicators i
    GROUP BY tp.time_period
),
severity_stats AS (
    SELECT 
        tp.time_period,
        COUNT(*) FILTER (WHERE severity >= 9) AS critical_count,
        COUNT(*) FILTER (WHERE severity BETWEEN 7 AND 8) AS high_count,
        COUNT(*) FILTER (WHERE severity BETWEEN 4 AND 6) AS medium_count,
        COUNT(*) FILTER (WHERE severity BETWEEN 1 AND 3) AS low_count
    FROM time_periods tp
    CROSS JOIN (
        SELECT severity, last_seen FROM ip_reputation WHERE reputation_score < -25
        UNION ALL
        SELECT severity, last_seen FROM domain_reputation WHERE reputation_score < -25
        UNION ALL
        SELECT 8 AS severity, last_seen FROM hash_reputation WHERE reputation_score < -50
        UNION ALL
        SELECT severity, last_seen FROM ioc_indicators WHERE is_active = true
    ) threats
    WHERE threats.last_seen >= tp.cutoff_time
    GROUP BY tp.time_period
)
SELECT 
    NOW() AS summary_timestamp,
    tp.time_period,
    
    -- Total threats
    (tc.ip_count + tc.domain_count + tc.hash_count + tc.ioc_count) AS total_threats,
    
    -- Threats by type (JSONB)
    jsonb_build_object(
        'ip', tc.ip_count,
        'domain', tc.domain_count,
        'hash', tc.hash_count,
        'ioc', tc.ioc_count
    ) AS threats_by_type,
    
    -- Threats by severity (JSONB)
    jsonb_build_object(
        'critical', COALESCE(ss.critical_count, 0),
        'high', COALESCE(ss.high_count, 0),
        'medium', COALESCE(ss.medium_count, 0),
        'low', COALESCE(ss.low_count, 0)
    ) AS threats_by_severity,
    
    -- Threats by category (top 10)
    COALESCE((
        SELECT jsonb_agg(
            jsonb_build_object('category', category_name, 'count', threat_count)
            ORDER BY threat_count DESC
        )
        FROM (
            SELECT tc.category_name, COUNT(*) AS threat_count
            FROM threat_categories tc
            JOIN (
                SELECT threat_category_id FROM ip_reputation 
                WHERE reputation_score < -25 AND last_seen >= tp.cutoff_time
                UNION ALL
                SELECT threat_category_id FROM domain_reputation 
                WHERE reputation_score < -25 AND last_seen >= tp.cutoff_time
                UNION ALL
                SELECT threat_category_id FROM ioc_indicators 
                WHERE is_active = true AND last_seen >= tp.cutoff_time
            ) threats ON threats.threat_category_id = tc.category_id
            GROUP BY tc.category_name
            ORDER BY threat_count DESC
            LIMIT 10
        ) sub
    ), '[]'::jsonb) AS threats_by_category,
    
    -- Threats by country (top 20)
    COALESCE((
        SELECT jsonb_agg(
            jsonb_build_object(
                'country_code', country_code,
                'country_name', country_name,
                'count', threat_count
            )
            ORDER BY threat_count DESC
        )
        FROM (
            SELECT 
                r.country_code,
                COALESCE(c.country_name, r.country_code) AS country_name,
                COUNT(*) AS threat_count
            FROM ip_reputation r
            LEFT JOIN country_info c ON c.country_code = r.country_code
            WHERE r.reputation_score < -25 
              AND r.last_seen >= tp.cutoff_time
              AND r.country_code IS NOT NULL
            GROUP BY r.country_code, c.country_name
            ORDER BY threat_count DESC
            LIMIT 20
        ) sub
    ), '[]'::jsonb) AS threats_by_country,
    
    -- Threats by ASN (top 10)
    COALESCE((
        SELECT jsonb_agg(
            jsonb_build_object(
                'asn', asn_id,
                'asn_name', asn_name,
                'organization', organization,
                'count', threat_count
            )
            ORDER BY threat_count DESC
        )
        FROM (
            SELECT 
                a.asn_id,
                a.asn_name,
                a.organization,
                COUNT(*) AS threat_count
            FROM ip_reputation r
            JOIN asn_data a ON a.asn_id = r.asn_id
            WHERE r.reputation_score < -25 
              AND r.last_seen >= tp.cutoff_time
            GROUP BY a.asn_id, a.asn_name, a.organization
            ORDER BY threat_count DESC
            LIMIT 10
        ) sub
    ), '[]'::jsonb) AS threats_by_asn,
    
    -- Active campaigns count
    (SELECT COUNT(*) FROM ioc_campaigns WHERE is_active = true) AS active_campaigns,
    
    -- Top campaigns (top 5 by IOC count)
    COALESCE((
        SELECT jsonb_agg(
            jsonb_build_object(
                'campaign_name', campaign_name,
                'ioc_count', ioc_count,
                'severity', severity,
                'threat_actor', threat_actor
            )
            ORDER BY ioc_count DESC
        )
        FROM (
            SELECT 
                c.campaign_name,
                c.severity,
                c.threat_actor,
                COUNT(ica.ioc_id) AS ioc_count
            FROM ioc_campaigns c
            JOIN ioc_campaign_associations ica ON ica.campaign_id = c.campaign_id
            WHERE c.is_active = true
            GROUP BY c.campaign_id, c.campaign_name, c.severity, c.threat_actor
            ORDER BY ioc_count DESC
            LIMIT 5
        ) sub
    ), '[]'::jsonb) AS top_campaigns,
    
    -- Feed statistics
    jsonb_build_object(
        'total_feeds', (SELECT COUNT(*) FROM threat_feeds),
        'active_feeds', (SELECT COUNT(*) FROM threat_feeds WHERE enabled = true),
        'avg_success_rate', COALESCE((
            SELECT AVG(success_rate_percent)::DECIMAL(5,2)
            FROM feed_health_metrics
            WHERE metric_timestamp >= NOW() - INTERVAL '24 hours'
        ), 0.00),
        'total_updates_24h', COALESCE((
            SELECT SUM(total_updates_24h)::INTEGER
            FROM feed_health_metrics
            WHERE metric_timestamp >= NOW() - INTERVAL '24 hours'
        ), 0),
        'failed_feeds', COALESCE((
            SELECT COUNT(DISTINCT feed_id)
            FROM feed_health_metrics
            WHERE metric_timestamp >= NOW() - INTERVAL '1 hour'
              AND health_status IN ('UNHEALTHY', 'DOWN')
        ), 0)
    ) AS feed_statistics,
    
    -- Detection statistics (24h only)
    CASE WHEN tp.time_period = '24H' THEN
        jsonb_build_object(
            'total_sightings_24h', COALESCE((
                SELECT COUNT(*) FROM ioc_sightings 
                WHERE sighted_at >= NOW() - INTERVAL '24 hours'
            ), 0),
            'total_blocks_24h', COALESCE((
                SELECT COUNT(*) FROM ioc_sightings 
                WHERE sighted_at >= NOW() - INTERVAL '24 hours'
                  AND action_taken = 'BLOCKED'
            ), 0),
            'total_alerts_24h', COALESCE((
                SELECT COUNT(*) FROM ioc_sightings 
                WHERE sighted_at >= NOW() - INTERVAL '24 hours'
                  AND action_taken = 'ALERTED'
            ), 0),
            'unique_sources_24h', COALESCE((
                SELECT COUNT(DISTINCT sighted_by) FROM ioc_sightings 
                WHERE sighted_at >= NOW() - INTERVAL '24 hours'
            ), 0)
        )
    ELSE NULL
    END AS detection_statistics,
    
    -- Reputation distribution
    jsonb_build_object(
        'blocked', (
            SELECT COUNT(*) FROM (
                SELECT reputation_score FROM ip_reputation WHERE last_seen >= tp.cutoff_time
                UNION ALL
                SELECT reputation_score FROM domain_reputation WHERE last_seen >= tp.cutoff_time
                UNION ALL
                SELECT reputation_score FROM hash_reputation WHERE last_seen >= tp.cutoff_time
            ) r WHERE r.reputation_score <= -75
        ),
        'alerted', (
            SELECT COUNT(*) FROM (
                SELECT reputation_score FROM ip_reputation WHERE last_seen >= tp.cutoff_time
                UNION ALL
                SELECT reputation_score FROM domain_reputation WHERE last_seen >= tp.cutoff_time
                UNION ALL
                SELECT reputation_score FROM hash_reputation WHERE last_seen >= tp.cutoff_time
            ) r WHERE r.reputation_score BETWEEN -74 AND -40
        ),
        'monitored', (
            SELECT COUNT(*) FROM (
                SELECT reputation_score FROM ip_reputation WHERE last_seen >= tp.cutoff_time
                UNION ALL
                SELECT reputation_score FROM domain_reputation WHERE last_seen >= tp.cutoff_time
                UNION ALL
                SELECT reputation_score FROM hash_reputation WHERE last_seen >= tp.cutoff_time
            ) r WHERE r.reputation_score BETWEEN -39 AND -25
        )
    ) AS reputation_distribution,
    
    -- New threats in last 24 hours (24H period only)
    CASE WHEN tp.time_period = '24H' THEN
        (
            SELECT COUNT(*) FROM (
                SELECT first_seen FROM ip_reputation WHERE first_seen >= NOW() - INTERVAL '24 hours'
                UNION ALL
                SELECT first_seen FROM domain_reputation WHERE first_seen >= NOW() - INTERVAL '24 hours'
                UNION ALL
                SELECT first_seen FROM hash_reputation WHERE first_seen >= NOW() - INTERVAL '24 hours'
                UNION ALL
                SELECT first_seen FROM ioc_indicators WHERE first_seen >= NOW() - INTERVAL '24 hours'
            ) new_threats
        )
    ELSE NULL
    END AS new_threats_24h,
    
    -- Malware families (top 10)
    COALESCE((
        SELECT jsonb_agg(
            jsonb_build_object('family', malware_family, 'count', family_count)
            ORDER BY family_count DESC
        )
        FROM (
            SELECT 
                malware_family,
                COUNT(*) AS family_count
            FROM hash_reputation
            WHERE malware_family IS NOT NULL
              AND last_seen >= tp.cutoff_time
            GROUP BY malware_family
            ORDER BY family_count DESC
            LIMIT 10
        ) sub
    ), '[]'::jsonb) AS malware_families,
    
    -- Placeholder for complex aggregations
    '[]'::jsonb AS trending_threats,
    '[]'::jsonb AS geographic_hotspots,
    '[]'::jsonb AS ttps_observed

FROM time_periods tp
CROSS JOIN threat_counts_by_period tc ON tc.time_period = tp.time_period
LEFT JOIN severity_stats ss ON ss.time_period = tp.time_period;

-- Create indexes on materialized view
CREATE INDEX IF NOT EXISTS idx_threat_summary_stats_period 
ON threat_summary_stats(time_period);

CREATE INDEX IF NOT EXISTS idx_threat_summary_stats_timestamp 
ON threat_summary_stats(summary_timestamp DESC);

COMMENT ON MATERIALIZED VIEW threat_summary_stats IS 'Aggregated threat intelligence statistics for dashboards and reporting (refresh every 15-30 minutes)';

-- =============================================================================
-- SIMPLIFIED VIEWS FOR QUICK ACCESS
-- =============================================================================

-- View: current_24h_stats
CREATE OR REPLACE VIEW current_24h_stats AS
SELECT * FROM threat_summary_stats WHERE time_period = '24H';

COMMENT ON VIEW current_24h_stats IS 'Last 24 hours threat statistics (from materialized view)';

-- View: current_7d_stats
CREATE OR REPLACE VIEW current_7d_stats AS
SELECT * FROM threat_summary_stats WHERE time_period = '7D';

COMMENT ON VIEW current_7d_stats IS 'Last 7 days threat statistics (from materialized view)';

-- View: current_30d_stats
CREATE OR REPLACE VIEW current_30d_stats AS
SELECT * FROM threat_summary_stats WHERE time_period = '30D';

COMMENT ON VIEW current_30d_stats IS 'Last 30 days threat statistics (from materialized view)';

-- =============================================================================
-- REAL-TIME TRENDING THREATS VIEW
-- =============================================================================

CREATE OR REPLACE VIEW trending_threats_realtime AS
WITH current_24h AS (
    SELECT ioc_id, COUNT(*) AS current_count
    FROM ioc_sightings
    WHERE sighted_at >= NOW() - INTERVAL '24 hours'
    GROUP BY ioc_id
),
previous_24h AS (
    SELECT ioc_id, COUNT(*) AS previous_count
    FROM ioc_sightings
    WHERE sighted_at >= NOW() - INTERVAL '48 hours'
      AND sighted_at < NOW() - INTERVAL '24 hours'
    GROUP BY ioc_id
)
SELECT 
    i.ioc_type,
    i.ioc_value,
    i.severity,
    c.current_count,
    COALESCE(p.previous_count, 0) AS previous_count,
    CASE 
        WHEN COALESCE(p.previous_count, 0) = 0 THEN 100
        ELSE ROUND(((c.current_count - COALESCE(p.previous_count, 0))::DECIMAL / 
                    NULLIF(p.previous_count, 0) * 100))::INTEGER
    END AS growth_rate_percent
FROM current_24h c
JOIN ioc_indicators i ON i.ioc_id = c.ioc_id
LEFT JOIN previous_24h p ON p.ioc_id = c.ioc_id
WHERE c.current_count > COALESCE(p.previous_count, 0) * 1.5  -- 50% increase
ORDER BY growth_rate_percent DESC, c.current_count DESC
LIMIT 10;

COMMENT ON VIEW trending_threats_realtime IS 'IOCs with significant activity increases (50%+ growth in last 24h)';

-- =============================================================================
-- GEOGRAPHIC HOTSPOTS VIEW
-- =============================================================================

CREATE OR REPLACE VIEW geographic_hotspots AS
WITH country_threats AS (
    SELECT 
        country_code,
        COUNT(*) AS threat_count
    FROM ip_reputation
    WHERE reputation_score < -25
      AND last_seen >= NOW() - INTERVAL '24 hours'
      AND country_code IS NOT NULL
    GROUP BY country_code
),
global_avg AS (
    SELECT AVG(threat_count)::DECIMAL AS avg_threats
    FROM country_threats
)
SELECT 
    ct.country_code,
    ci.country_name,
    ct.threat_count,
    ROUND((ct.threat_count::DECIMAL / ga.avg_threats), 2) AS threat_density_score
FROM country_threats ct
CROSS JOIN global_avg ga
LEFT JOIN country_info ci ON ci.country_code = ct.country_code
WHERE ct.threat_count > ga.avg_threats * 2  -- 2x above average
ORDER BY threat_density_score DESC, ct.threat_count DESC
LIMIT 15;

COMMENT ON VIEW geographic_hotspots IS 'Countries with abnormally high threat activity (2x+ global average)';

-- =============================================================================
-- VERIFICATION
-- =============================================================================

DO $$
DECLARE
    view_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO view_count 
    FROM pg_matviews 
    WHERE schemaname = 'public' 
      AND matviewname = 'threat_summary_stats';
    
    RAISE NOTICE '=== Threat Summary Statistics Views Initialized ===';
    RAISE NOTICE 'Materialized view created: threat_summary_stats';
    RAISE NOTICE 'Time periods: 24H, 7D, 30D, 90D, ALL_TIME';
    RAISE NOTICE '';
    RAISE NOTICE 'Helper views:';
    RAISE NOTICE '  - current_24h_stats (last 24 hours)';
    RAISE NOTICE '  - current_7d_stats (last 7 days)';
    RAISE NOTICE '  - current_30d_stats (last 30 days)';
    RAISE NOTICE '  - trending_threats_realtime (50%%+ growth)';
    RAISE NOTICE '  - geographic_hotspots (2x+ average)';
    RAISE NOTICE '';
    RAISE NOTICE 'To refresh materialized view:';
    RAISE NOTICE '  REFRESH MATERIALIZED VIEW CONCURRENTLY threat_summary_stats;';
    RAISE NOTICE '';
    RAISE NOTICE 'Schedule periodic refresh (every 15 minutes):';
    RAISE NOTICE '  SELECT cron.schedule(''refresh_stats'', ''*/15 * * * *'', $$REFRESH MATERIALIZED VIEW CONCURRENTLY threat_summary_stats$$);';
END $$;
