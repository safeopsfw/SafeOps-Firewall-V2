-- ============================================================================
-- SafeOps Threat Intelligence Database - High Confidence IOCs View
-- File: high_confidence_iocs.sql
-- Purpose: High-confidence, validated IOCs suitable for automated blocking
-- ============================================================================

-- =============================================================================
-- VIEW: high_confidence_iocs
-- =============================================================================

CREATE OR REPLACE VIEW high_confidence_iocs AS
WITH ioc_feed_stats AS (
    SELECT 
        isrc.ioc_id,
        COUNT(DISTINCT isrc.feed_id) AS feed_count,
        COUNT(DISTINCT isrc.feed_id) FILTER (
            WHERE tf.priority <= 3
        ) AS high_priority_feed_count,
        ARRAY_AGG(DISTINCT tf.feed_name ORDER BY tf.priority, tf.feed_name) FILTER (
            WHERE tf.priority <= 3
        ) AS trusted_feed_sources,
        MAX(CASE 
            WHEN isrc.tlp_level = 'RED' THEN 4
            WHEN isrc.tlp_level = 'AMBER' THEN 3
            WHEN isrc.tlp_level = 'GREEN' THEN 2
            WHEN isrc.tlp_level = 'WHITE' THEN 1
            ELSE 0
        END) AS tlp_numeric
    FROM ioc_sources isrc
    JOIN threat_feeds tf ON tf.feed_id = isrc.feed_id
    WHERE tf.enabled = true
    GROUP BY isrc.ioc_id
),
ioc_sighting_stats AS (
    SELECT 
        ioc_id,
        COUNT(*) AS sighting_count,
        MAX(sighted_at) AS last_sighting
    FROM ioc_sightings
    WHERE sighted_at >= NOW() - INTERVAL '90 days'
    GROUP BY ioc_id
),
ioc_campaign_info AS (
    SELECT 
        ica.ioc_id,
        ARRAY_AGG(DISTINCT c.campaign_name ORDER BY c.campaign_name) AS associated_campaigns
    FROM ioc_campaign_associations ica
    JOIN ioc_campaigns c ON c.campaign_id = ica.campaign_id
    WHERE c.is_active = true
    GROUP BY ica.ioc_id
)
SELECT 
    i.ioc_id,
    i.ioc_type,
    i.ioc_value,
    i.ioc_value_normalized AS ioc_normalized,
    i.reputation_score,
    i.confidence_level,
    i.severity,
    COALESCE(tc.category_name, 'UNKNOWN') AS threat_category,
    i.kill_chain_phase,
    i.first_seen,
    i.last_seen,
    COALESCE(fs.feed_count, 0)::INTEGER AS feed_count,
    COALESCE(fs.high_priority_feed_count, 0)::INTEGER AS high_priority_feed_count,
    COALESCE(fs.trusted_feed_sources, ARRAY[]::TEXT[]) AS trusted_feed_sources,
    COALESCE(ss.sighting_count, 0)::INTEGER AS sighting_count,
    ss.last_sighting,
    
    -- Validation score calculation (0-100)
    LEAST(100, ROUND(
        (i.confidence_level * 40) +
        (LEAST(fs.feed_count, 5) * 10) +
        (LEAST(fs.high_priority_feed_count, 4) * 15) +
        (LEAST(COALESCE(ss.sighting_count, 0), 10) * 0.5) +
        (CASE 
            WHEN i.last_seen >= NOW() - INTERVAL '7 days' THEN 30
            WHEN i.last_seen >= NOW() - INTERVAL '14 days' THEN 25
            WHEN i.last_seen >= NOW() - INTERVAL '30 days' THEN 20
            WHEN i.last_seen >= NOW() - INTERVAL '45 days' THEN 15
            ELSE 10
        END)
    ))::INTEGER AS validation_score,
    
    -- False positive likelihood
    CASE 
        WHEN (i.confidence_level * 40 + LEAST(fs.high_priority_feed_count, 4) * 15) > 75 
             AND fs.high_priority_feed_count >= 2 
        THEN 'LOW'
        WHEN (i.confidence_level * 40 + LEAST(fs.high_priority_feed_count, 4) * 15) >= 50 
             OR fs.high_priority_feed_count >= 1 
        THEN 'MEDIUM'
        ELSE 'HIGH'
    END AS false_positive_likelihood,
    
    -- Recommended action
    CASE 
        WHEN (i.confidence_level * 40 + LEAST(fs.feed_count, 5) * 10 + 
              LEAST(fs.high_priority_feed_count, 4) * 15 + 20) >= 80 
             AND i.confidence_level >= 0.90 
             AND i.severity >= 7 
        THEN 'AUTO_BLOCK'
        WHEN (i.confidence_level * 40 + LEAST(fs.feed_count, 5) * 10 + 
              LEAST(fs.high_priority_feed_count, 4) * 15 + 20) >= 65 
             OR i.severity BETWEEN 5 AND 6 
        THEN 'MANUAL_REVIEW'
        ELSE 'ALERT'
    END AS recommended_action,
    
    -- TLP level (as text)
    CASE fs.tlp_numeric
        WHEN 4 THEN 'RED'
        WHEN 3 THEN 'AMBER'
        WHEN 2 THEN 'GREEN'
        WHEN 1 THEN 'WHITE'
        ELSE 'UNKNOWN'
    END AS tlp_level,
    
    COALESCE(ci.associated_campaigns, ARRAY[]::TEXT[]) AS associated_campaigns,
    i.tags

FROM ioc_indicators i
LEFT JOIN threat_categories tc ON tc.category_id = i.threat_category_id
LEFT JOIN ioc_feed_stats fs ON fs.ioc_id = i.ioc_id
LEFT JOIN ioc_sighting_stats ss ON ss.ioc_id = i.ioc_id
LEFT JOIN ioc_campaign_info ci ON ci.ioc_id = i.ioc_id

WHERE i.is_active = true
  AND i.confidence_level >= 0.80
  AND (i.reputation_score <= -50 OR i.severity >= 8)
  AND i.last_seen >= NOW() - INTERVAL '60 days'
  AND (
      -- Multi-source validation
      fs.feed_count >= 2
      OR
      -- OR single trusted source
      fs.high_priority_feed_count >= 1
  )
  AND fs.tlp_numeric < 4  -- Exclude TLP RED
  
ORDER BY 
    -- Prioritize by validation score
    LEAST(100, ROUND(
        (i.confidence_level * 40) +
        (LEAST(fs.feed_count, 5) * 10) +
        (LEAST(fs.high_priority_feed_count, 4) * 15) +
        (LEAST(COALESCE(ss.sighting_count, 0), 10) * 0.5) +
        (CASE 
            WHEN i.last_seen >= NOW() - INTERVAL '7 days' THEN 30
            ELSE 15
        END)
    )) DESC,
    i.severity DESC,
    i.last_seen DESC;

COMMENT ON VIEW high_confidence_iocs IS 'High-confidence, validated IOCs suitable for automated blocking (confidence >= 0.80, multi-source validation)';

-- =============================================================================
-- HELPER VIEWS
-- =============================================================================

-- View: auto_block_iocs
CREATE OR REPLACE VIEW auto_block_iocs AS
SELECT 
    ioc_id,
    ioc_type,
    ioc_value,
    ioc_normalized,
    reputation_score,
    confidence_level,
    severity,
    threat_category,
    validation_score,
    feed_count,
    high_priority_feed_count,
    trusted_feed_sources,
    last_seen
FROM high_confidence_iocs
WHERE recommended_action = 'AUTO_BLOCK'
  AND false_positive_likelihood = 'LOW'
ORDER BY validation_score DESC, severity DESC;

COMMENT ON VIEW auto_block_iocs IS 'IOCs approved for automated blocking (highest confidence, lowest FP risk)';

-- View: high_confidence_by_type
CREATE OR REPLACE VIEW high_confidence_by_type AS
SELECT 
    ioc_type,
    COUNT(*) AS ioc_count,
    AVG(confidence_level)::DECIMAL(3,2) AS avg_confidence,
    AVG(validation_score)::INTEGER AS avg_validation_score,
    COUNT(*) FILTER (WHERE recommended_action = 'AUTO_BLOCK') AS auto_block_count,
    COUNT(*) FILTER (WHERE false_positive_likelihood = 'LOW') AS low_fp_count
FROM high_confidence_iocs
GROUP BY ioc_type
ORDER BY ioc_count DESC;

COMMENT ON VIEW high_confidence_by_type IS 'Summary of high-confidence IOCs by type';

-- View: trusted_feed_iocs
CREATE OR REPLACE VIEW trusted_feed_iocs AS
SELECT 
    ioc_id,
    ioc_type,
    ioc_value,
    confidence_level,
    severity,
    threat_category,
    high_priority_feed_count,
    trusted_feed_sources,
    validation_score,
    recommended_action
FROM high_confidence_iocs
WHERE high_priority_feed_count >= 2
ORDER BY validation_score DESC;

COMMENT ON VIEW trusted_feed_iocs IS 'IOCs validated by multiple trusted feeds (priority 1-3)';

-- View: recent_high_confidence_iocs
CREATE OR REPLACE VIEW recent_high_confidence_iocs AS
SELECT 
    ioc_id,
    ioc_type,
    ioc_value,
    reputation_score,
    confidence_level,
    severity,
    threat_category,
    last_seen,
    validation_score,
    sighting_count,
    recommended_action,
    associated_campaigns
FROM high_confidence_iocs
WHERE last_seen >= NOW() - INTERVAL '7 days'
ORDER BY last_seen DESC, validation_score DESC;

COMMENT ON VIEW recent_high_confidence_iocs IS 'High-confidence IOCs seen in the last 7 days';

-- =============================================================================
-- CAMPAIGN-SPECIFIC VIEWS
-- =============================================================================

-- View: campaign_iocs_high_confidence
CREATE OR REPLACE VIEW campaign_iocs_high_confidence AS
SELECT 
    UNNEST(associated_campaigns) AS campaign_name,
    ioc_type,
    COUNT(*) AS ioc_count,
    AVG(confidence_level)::DECIMAL(3,2) AS avg_confidence,
    AVG(validation_score)::INTEGER AS avg_validation_score,
    MAX(last_seen) AS most_recent_ioc
FROM high_confidence_iocs
WHERE associated_campaigns IS NOT NULL 
  AND array_length(associated_campaigns, 1) > 0
GROUP BY UNNEST(associated_campaigns), ioc_type
ORDER BY campaign_name, ioc_count DESC;

COMMENT ON VIEW campaign_iocs_high_confidence IS 'High-confidence IOCs grouped by associated campaigns';

-- =============================================================================
-- VERIFICATION AND STATISTICS
-- =============================================================================

-- View: ioc_confidence_statistics
CREATE OR REPLACE VIEW ioc_confidence_statistics AS
SELECT 
    'Total IOCs' AS metric,
    COUNT(*)::TEXT AS value
FROM ioc_indicators
UNION ALL
SELECT 
    'High Confidence IOCs',
    COUNT(*)::TEXT
FROM high_confidence_iocs
UNION ALL
SELECT 
    'Auto-Block Ready',
    COUNT(*)::TEXT
FROM high_confidence_iocs
WHERE recommended_action = 'AUTO_BLOCK'
UNION ALL
SELECT 
    'Low False Positive Risk',
    COUNT(*)::TEXT
FROM high_confidence_iocs
WHERE false_positive_likelihood = 'LOW'
UNION ALL
SELECT 
    'Multi-Source Validated',
    COUNT(*)::TEXT
FROM high_confidence_iocs
WHERE feed_count >= 2
UNION ALL
SELECT 
    'Trusted Feed Validated',
    COUNT(*)::TEXT
FROM high_confidence_iocs
WHERE high_priority_feed_count >= 1;

COMMENT ON VIEW ioc_confidence_statistics IS 'Key statistics about IOC validation and confidence levels';

-- =============================================================================
-- VERIFICATION
-- =============================================================================

DO $$
DECLARE
    view_count INTEGER;
    ioc_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO view_count 
    FROM pg_views 
    WHERE schemaname = 'public' 
      AND (viewname LIKE '%confidence%' OR viewname LIKE '%auto_block%');
    
    SELECT COUNT(*) INTO ioc_count 
    FROM high_confidence_iocs;
    
    RAISE NOTICE '=== High Confidence IOCs Views Initialized ===';
    RAISE NOTICE 'Views created: %', view_count;
    RAISE NOTICE 'Current high-confidence IOCs: %', ioc_count;
    RAISE NOTICE '';
    RAISE NOTICE 'Main view: high_confidence_iocs';
    RAISE NOTICE 'Helper views:';
    RAISE NOTICE '  - auto_block_iocs (automated blocking candidates)';
    RAISE NOTICE '  - high_confidence_by_type (summary by IOC type)';
    RAISE NOTICE '  - trusted_feed_iocs (trusted source validation)';
    RAISE NOTICE '  - recent_high_confidence_iocs (last 7 days)';
    RAISE NOTICE '  - campaign_iocs_high_confidence (campaign attribution)';
    RAISE NOTICE '  - ioc_confidence_statistics (validation metrics)';
    RAISE NOTICE '';
    RAISE NOTICE 'Filtering criteria:';
    RAISE NOTICE '  - Confidence >= 0.80';
    RAISE NOTICE '  - Reputation <= -50 OR Severity >= 8';
    RAISE NOTICE '  - Last seen within 60 days';
    RAISE NOTICE '  - 2+ feeds OR 1+ priority 1-3 feed';
    RAISE NOTICE '  - TLP != RED';
END $$;
