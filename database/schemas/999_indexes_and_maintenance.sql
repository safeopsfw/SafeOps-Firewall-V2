-- ============================================================================
-- SafeOps Threat Intelligence Database - Indexes and Maintenance
-- File: 999_indexes_and_maintenance.sql
-- Purpose: Performance indexes, maintenance procedures, and database optimization
-- ============================================================================

-- =============================================================================
-- ADDITIONAL PERFORMANCE INDEXES
-- =============================================================================

-- Cross-table correlation indexes
-- Note: Some of these reference columns that may not exist yet - create cautiously

-- Campaign threat analysis
CREATE INDEX IF NOT EXISTS idx_campaign_threat_analysis 
ON ioc_campaign_associations(campaign_id, ioc_id);

-- Feed performance analysis
CREATE INDEX IF NOT EXISTS idx_feed_performance_analysis 
ON feed_update_history(feed_id, status, started_at DESC);

-- Geographic threat correlation  
CREATE INDEX IF NOT EXISTS idx_geo_threat_correlation
ON ip_geolocation(country_code, asn);

-- =============================================================================
-- TIME-SERIES BRIN INDEXES
-- =============================================================================

-- BRIN indexes for efficient time-range scans on partitioned tables
-- Note: Create on parent tables after partitions exist

DO $$
BEGIN
    -- ip_reputation_history
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'ip_reputation_history') THEN
        CREATE INDEX IF NOT EXISTS idx_ip_rep_history_ts_brin 
        ON ip_reputation_history USING brin(changed_at);
    END IF;
    
    -- domain_reputation_history
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'domain_reputation_history') THEN
        CREATE INDEX IF NOT EXISTS idx_domain_rep_history_ts_brin 
        ON domain_reputation_history USING brin(changed_at);
    END IF;
    
    -- hash_reputation_history
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'hash_reputation_history') THEN
        CREATE INDEX IF NOT EXISTS idx_hash_rep_history_ts_brin 
        ON hash_reputation_history USING brin(changed_at);
    END IF;
    
    -- ioc_sightings
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'ioc_sightings') THEN
        CREATE INDEX IF NOT EXISTS idx_ioc_sightings_ts_brin 
        ON ioc_sightings USING brin(sighted_at);
    END IF;
    
    -- proxy_detection_log
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'proxy_detection_log') THEN
        CREATE INDEX IF NOT EXISTS idx_proxy_detection_ts_brin 
        ON proxy_detection_log USING brin(detection_timestamp);
    END IF;
    
    -- ip_location_history
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'ip_location_history') THEN
        CREATE INDEX IF NOT EXISTS idx_ip_location_history_ts_brin 
        ON ip_location_history USING brin(detected_at);
    END IF;
    
    -- feed_update_history
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'feed_update_history') THEN
        CREATE INDEX IF NOT EXISTS idx_feed_update_history_ts_brin 
        ON feed_update_history USING brin(started_at);
    END IF;
    
    -- asn_abuse_reports
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'asn_abuse_reports') THEN
        CREATE INDEX IF NOT EXISTS idx_asn_abuse_reports_ts_brin 
        ON asn_abuse_reports USING brin(reported_at);
    END IF;
    
    -- asn_statistics
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'asn_statistics') THEN
        CREATE INDEX IF NOT EXISTS idx_asn_statistics_ts_brin 
        ON asn_statistics USING brin(stat_period_end);
    END IF;
    
    RAISE NOTICE 'BRIN indexes created for time-series data';
END $$;

-- =============================================================================
-- FULL-TEXT SEARCH INDEXES
-- =============================================================================

-- IOC indicators full-text search
CREATE INDEX IF NOT EXISTS idx_ioc_indicators_fts 
ON ioc_indicators USING gin(to_tsvector('english', 
    COALESCE(description, '') || ' ' || COALESCE(context, '')));

-- IOC campaigns full-text search
CREATE INDEX IF NOT EXISTS idx_ioc_campaigns_fts 
ON ioc_campaigns USING gin(to_tsvector('english', 
    COALESCE(description, '') || ' ' || COALESCE(campaign_name, '')));

-- ASN data full-text search
CREATE INDEX IF NOT EXISTS idx_asn_data_fts 
ON asn_data USING gin(to_tsvector('english', 
    COALESCE(asn_name, '') || ' ' || COALESCE(organization, '')));

-- Proxy services full-text search
CREATE INDEX IF NOT EXISTS idx_proxy_services_fts 
ON proxy_services USING gin(to_tsvector('english', 
    COALESCE(service_name, '') || ' ' || COALESCE(description, '')));

-- =============================================================================
-- DATA RETENTION POLICIES TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS data_retention_policies (
    policy_id SERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL UNIQUE,
    retention_days INTEGER NOT NULL CHECK (retention_days > 0),
    partition_column VARCHAR(100),
    archive_enabled BOOLEAN DEFAULT false,
    archive_location TEXT,
    enabled BOOLEAN DEFAULT true,
    last_cleanup TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default retention policies
INSERT INTO data_retention_policies (table_name, retention_days, partition_column) VALUES
('ip_reputation_history', 365, 'changed_at'),
('domain_reputation_history', 365, 'changed_at'),
('hash_reputation_history', 365, 'changed_at'),
('ioc_sightings', 180, 'sighted_at'),
('proxy_detection_log', 90, 'detection_timestamp'),
('ip_location_history', 365, 'detected_at'),
('feed_update_history', 180, 'started_at'),
('feed_health_metrics', 90, 'metric_timestamp'),
('asn_reputation_history', 365, 'changed_at'),
('asn_abuse_reports', 365, 'reported_at'),
('asn_statistics', 730, 'stat_period_end')
ON CONFLICT (table_name) DO NOTHING;

-- =============================================================================
-- MAINTENANCE SCHEDULE TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS maintenance_schedule (
    job_id SERIAL PRIMARY KEY,
    job_name VARCHAR(100) NOT NULL UNIQUE,
    function_name VARCHAR(100) NOT NULL,
    schedule_cron VARCHAR(100) NOT NULL,
    timeout_seconds INTEGER DEFAULT 3600 CHECK (timeout_seconds > 0),
    enabled BOOLEAN DEFAULT true,
    last_run TIMESTAMP WITH TIME ZONE,
    last_duration_ms INTEGER,
    last_status VARCHAR(20),
    failure_count INTEGER DEFAULT 0 CHECK (failure_count >= 0),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default maintenance jobs
INSERT INTO maintenance_schedule (job_name, function_name, schedule_cron) VALUES
('cleanup_expired_records', 'cleanup_expired_records', '0 2 * * *'),
('update_reputation_scores', 'update_reputation_scores', '0 3 * * *'),
('vacuum_and_analyze_tables', 'vacuum_and_analyze_tables', '0 4 * * *'),
('partition_maintenance', 'partition_maintenance', '0 1 * * 0'),
('update_statistics', 'update_statistics', '0 * * * *'),
('detect_anomalies', 'detect_anomalies', '*/30 * * * *')
ON CONFLICT (job_name) DO NOTHING;

-- =============================================================================
-- DATABASE METRICS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS database_metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    metric_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    database_size_bytes BIGINT,
    total_tables INTEGER,
    total_indexes INTEGER,
    total_rows BIGINT,
    cache_hit_ratio DECIMAL(5,4),
    transaction_rate INTEGER,
    active_connections INTEGER,
    blocked_queries INTEGER,
    deadlocks_count INTEGER,
    temp_files_size_bytes BIGINT,
    longest_query_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_database_metrics_timestamp 
ON database_metrics(metric_timestamp);

-- =============================================================================
-- SLOW QUERY LOG TABLE (PARTITIONED BY WEEK)
-- =============================================================================

CREATE TABLE IF NOT EXISTS slow_query_log (
    log_id BIGSERIAL,
    query_text TEXT NOT NULL,
    query_hash VARCHAR(64),
    execution_time_ms INTEGER NOT NULL,
    rows_returned BIGINT,
    database_name VARCHAR(100),
    username VARCHAR(100),
    client_address INET,
    logged_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    PRIMARY KEY (log_id, logged_at)
) PARTITION BY RANGE (logged_at);

-- Indexes for slow_query_log
CREATE INDEX IF NOT EXISTS idx_slow_query_hash 
ON slow_query_log(query_hash);
CREATE INDEX IF NOT EXISTS idx_slow_query_time 
ON slow_query_log(execution_time_ms DESC);
CREATE INDEX IF NOT EXISTS idx_slow_query_logged 
ON slow_query_log(logged_at);

-- =============================================================================
-- MAINTENANCE FUNCTIONS
-- =============================================================================

-- Function: cleanup_expired_records
CREATE OR REPLACE FUNCTION cleanup_expired_records(dry_run BOOLEAN DEFAULT false)
RETURNS JSONB AS $$
DECLARE
    v_deleted_counts JSONB := '{}';
    v_count INTEGER;
BEGIN
    -- ip_reputation_sources
    IF dry_run THEN
        SELECT COUNT(*) INTO v_count FROM ip_reputation_sources WHERE expires_at < NOW();
    ELSE
        DELETE FROM ip_reputation_sources WHERE expires_at < NOW();
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    v_deleted_counts := v_deleted_counts || jsonb_build_object('ip_reputation_sources', v_count);
    
    -- domain_reputation_sources
    IF dry_run THEN
        SELECT COUNT(*) INTO v_count FROM domain_reputation_sources WHERE expires_at < NOW();
    ELSE
        DELETE FROM domain_reputation_sources WHERE expires_at < NOW();
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    v_deleted_counts := v_deleted_counts || jsonb_build_object('domain_reputation_sources', v_count);
    
    -- hash_reputation_sources
    IF dry_run THEN
        SELECT COUNT(*) INTO v_count FROM hash_reputation_sources WHERE expires_at < NOW();
    ELSE
        DELETE FROM hash_reputation_sources WHERE expires_at < NOW();
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    v_deleted_counts := v_deleted_counts || jsonb_build_object('hash_reputation_sources', v_count);
    
    -- ioc_sources
    IF dry_run THEN
        SELECT COUNT(*) INTO v_count FROM ioc_sources WHERE expires_at < NOW();
    ELSE
        DELETE FROM ioc_sources WHERE expires_at < NOW();
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    v_deleted_counts := v_deleted_counts || jsonb_build_object('ioc_sources', v_count);
    
    -- Mark inactive IOCs
    IF NOT dry_run THEN
        UPDATE ioc_indicators SET is_active = false
        WHERE last_seen < NOW() - INTERVAL '90 days' AND is_active = true;
        GET DIAGNOSTICS v_count = ROW_COUNT;
    ELSE
        SELECT COUNT(*) INTO v_count FROM ioc_indicators 
        WHERE last_seen < NOW() - INTERVAL '90 days' AND is_active = true;
    END IF;
    v_deleted_counts := v_deleted_counts || jsonb_build_object('inactive_iocs', v_count);
    
    RETURN v_deleted_counts;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_records IS 'Remove expired threat intelligence records';

-- Function: update_reputation_scores
CREATE OR REPLACE FUNCTION update_reputation_scores(
    decay_rate DECIMAL DEFAULT 0.95,
    min_confidence DECIMAL DEFAULT 0.20
) RETURNS INTEGER AS $$
DECLARE
    v_updated_count INTEGER := 0;
BEGIN
    -- Apply time decay to IP reputation scores
    UPDATE ip_reputation
    SET reputation_score = GREATEST(-100, LEAST(100, 
        ROUND(reputation_score * POWER(decay_rate, 
            EXTRACT(DAYS FROM NOW() - last_updated)::INTEGER))::INTEGER
    )),
    confidence_level = GREATEST(min_confidence, 
        confidence_level * POWER(decay_rate, 
            EXTRACT(DAYS FROM NOW() - last_updated)::INTEGER / 7)
    ),
    updated_at = NOW()
    WHERE last_updated < NOW() - INTERVAL '1 day';
    
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    
    RETURN v_updated_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_reputation_scores IS 'Recalculate reputation scores with time-based decay';

-- Function: vacuum_and_analyze_tables
CREATE OR REPLACE FUNCTION vacuum_and_analyze_tables(full_vacuum BOOLEAN DEFAULT false)
RETURNS JSONB AS $$
DECLARE
    v_table RECORD;
    v_start_time TIMESTAMP;
    v_results JSONB := '[]';
    v_duration_ms INTEGER;
BEGIN
    FOR v_table IN 
        SELECT schemaname, tablename 
        FROM pg_tables 
        WHERE schemaname = 'public'
          AND tablename NOT LIKE '%_prt_%' -- Skip partition tables
    LOOP
        v_start_time := clock_timestamp();
        
        IF full_vacuum THEN
            EXECUTE format('VACUUM FULL ANALYZE %I.%I', v_table.schemaname, v_table.tablename);
        ELSE
            EXECUTE format('VACUUM ANALYZE %I.%I', v_table.schemaname, v_table.tablename);
        END IF;
        
        v_duration_ms := EXTRACT(MILLISECONDS FROM clock_timestamp() - v_start_time)::INTEGER;
        
        v_results := v_results || jsonb_build_object(
            'table', v_table.tablename,
            'duration_ms', v_duration_ms
        );
    END LOOP;
    
    RETURN jsonb_build_object('tables', v_results, 'full_vacuum', full_vacuum);
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION vacuum_and_analyze_tables IS 'Database maintenance and statistics update';

-- Function: partition_maintenance
CREATE OR REPLACE FUNCTION partition_maintenance()
RETURNS JSONB AS $$
DECLARE
    v_results JSONB := '{}';
    v_created INTEGER := 0;
    v_dropped INTEGER := 0;
BEGIN
    -- Note: Actual partition creation logic would be more complex
    -- This is a simplified version
    
    RAISE NOTICE 'Partition maintenance: check for new partitions needed';
    RAISE NOTICE 'Partition maintenance: check for old partitions to drop';
    
    v_results := jsonb_build_object(
        'partitions_created', v_created,
        'partitions_dropped', v_dropped,
        'timestamp', NOW()
    );
    
    RETURN v_results;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION partition_maintenance IS 'Create future partitions and drop old partitions';

-- Function: update_statistics
CREATE OR REPLACE FUNCTION update_statistics()
RETURNS INTEGER AS $$
DECLARE
    v_stats_count INTEGER := 0;
BEGIN
    -- Update aggregate statistics
    -- This would calculate and insert into asn_statistics, feed_health_metrics, etc.
    -- Simplified version
    
    -- Example: Refresh important aggregates
    ANALYZE threat_feeds;
    ANALYZE ip_reputation;
    ANALYZE domain_reputation;
    
    RETURN v_stats_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_statistics IS 'Update aggregate statistics tables';

-- Function: detect_anomalies
CREATE OR REPLACE FUNCTION detect_anomalies(sensitivity INTEGER DEFAULT 3)
RETURNS JSONB AS $$
DECLARE
    v_anomalies JSONB := '[]';
    v_spike_threshold INTEGER;
BEGIN
    -- Calculate threshold based on sensitivity
    v_spike_threshold := 100 * (6 - sensitivity);
    
    -- Detect threat spikes
    -- Simplified version - would check various metrics
    
    RAISE NOTICE 'Anomaly detection running with sensitivity %', sensitivity;
    
    RETURN jsonb_build_object(
        'anomalies', v_anomalies,
        'sensitivity', sensitivity,
        'checked_at', NOW()
    );
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION detect_anomalies IS 'Detect unusual patterns in threat data';

-- Function: collect_database_metrics
CREATE OR REPLACE FUNCTION collect_database_metrics()
RETURNS VOID AS $$
DECLARE
    v_db_size BIGINT;
    v_cache_hit_ratio DECIMAL(5,4);
BEGIN
    -- Get database size
    SELECT pg_database_size(current_database()) INTO v_db_size;
    
    -- Calculate cache hit ratio
    SELECT 
        CASE WHEN (blks_hit + blks_read) > 0 
        THEN ROUND(blks_hit::NUMERIC / (blks_hit + blks_read), 4)
        ELSE 0
        END
    INTO v_cache_hit_ratio
    FROM pg_stat_database
    WHERE datname = current_database();
    
    -- Insert metrics
    INSERT INTO database_metrics (
        database_size_bytes,
        cache_hit_ratio,
        active_connections
    ) VALUES (
        v_db_size,
        v_cache_hit_ratio,
        (SELECT count(*) FROM pg_stat_activity WHERE state = 'active')::INTEGER
    );
    
    -- Clean up old metrics (keep 30 days)
    DELETE FROM database_metrics 
    WHERE metric_timestamp < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION collect_database_metrics IS 'Collect and store database health metrics';

-- =============================================================================
-- MATERIALIZED VIEWS
-- =============================================================================

-- Materialized View: active_high_threat_ips
CREATE MATERIALIZED VIEW IF NOT EXISTS active_high_threat_ips AS
SELECT 
    r.ip_address,
    r.reputation_score,
    r.confidence_level,
    r.last_seen,
    r.country_code,
    r.asn_id,
    c.category_name AS threat_category_name,
    r.total_reports
FROM ip_reputation r
LEFT JOIN threat_categories c ON c.category_id = r.threat_category_id
WHERE r.reputation_score <= -50
  AND r.last_seen >= NOW() - INTERVAL '30 days'
ORDER BY r.reputation_score ASC, r.last_seen DESC;

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_high_threat_ips_address 
ON active_high_threat_ips(ip_address);
CREATE INDEX IF NOT EXISTS idx_active_high_threat_ips_score 
ON active_high_threat_ips(reputation_score DESC);

-- Materialized View: feed_performance_summary
CREATE MATERIALIZED VIEW IF NOT EXISTS feed_performance_summary AS
SELECT 
    f.feed_id,
    f.feed_name,
    COUNT(*) FILTER (WHERE h.status = 'SUCCESS' AND h.started_at >= NOW() - INTERVAL '7 days')::DECIMAL / 
        NULLIF(COUNT(*) FILTER (WHERE h.started_at >= NOW() - INTERVAL '7 days'), 0) * 100 AS success_rate_7d,
    AVG(h.duration_ms) FILTER (WHERE h.started_at >= NOW() - INTERVAL '7 days')::INTEGER AS avg_response_time_ms,
    COUNT(*) FILTER (WHERE h.started_at >= NOW() - INTERVAL '7 days')::INTEGER AS total_updates_7d,
    MAX(h.started_at) FILTER (WHERE h.status = 'SUCCESS') AS last_successful_update,
    'UNKNOWN'::VARCHAR(20) AS health_status,
    0.00::DECIMAL(5,2) AS data_quality_score
FROM threat_feeds f
LEFT JOIN feed_update_history h ON h.feed_id = f.feed_id
WHERE f.enabled = true
GROUP BY f.feed_id, f.feed_name;

CREATE UNIQUE INDEX IF NOT EXISTS idx_feed_performance_summary_feed 
ON feed_performance_summary(feed_id);

-- =============================================================================
-- HELPER FUNCTIONS FOR MATERIALIZED VIEW REFRESH
-- =============================================================================

CREATE OR REPLACE FUNCTION refresh_materialized_views()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY active_high_threat_ips;
    REFRESH MATERIALIZED VIEW CONCURRENTLY feed_performance_summary;
    
    RAISE NOTICE 'Materialized views refreshed at %', NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION refresh_materialized_views IS 'Refresh all materialized views';

-- =============================================================================
-- VERIFICATION
-- =============================================================================

DO $$
DECLARE
    index_count INTEGER;
    function_count INTEGER;
    matview_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO index_count 
    FROM pg_indexes 
    WHERE schemaname = 'public'
      AND indexname LIKE '%_brin' OR indexname LIKE '%_fts';
    
    SELECT COUNT(*) INTO function_count 
    FROM pg_proc 
    WHERE proname IN ('cleanup_expired_records', 'update_reputation_scores', 
                      'vacuum_and_analyze_tables', 'partition_maintenance',
                      'update_statistics', 'detect_anomalies');
    
    SELECT COUNT(*) INTO matview_count 
    FROM pg_matviews 
    WHERE schemaname = 'public';
    
    RAISE NOTICE '=== Database Indexes and Maintenance Initialized ===';
    RAISE NOTICE 'Performance indexes (BRIN/FTS): %', index_count;
    RAISE NOTICE 'Maintenance functions: %', function_count;
    RAISE NOTICE 'Materialized views: %', matview_count;
    RAISE NOTICE 'Data retention policies: % tables', (SELECT COUNT(*) FROM data_retention_policies);
    RAISE NOTICE 'Scheduled jobs: % jobs', (SELECT COUNT(*) FROM maintenance_schedule);
    RAISE NOTICE '';
    RAISE NOTICE 'RECOMMENDED POSTGRESQL SETTINGS:';
    RAISE NOTICE '  shared_buffers = 25%% of RAM';
    RAISE NOTICE '  effective_cache_size = 75%% of RAM';
    RAISE NOTICE '  maintenance_work_mem = 2GB';
    RAISE NOTICE '  work_mem = 256MB';
    RAISE NOTICE '  random_page_cost = 1.1 (for SSD)';
    RAISE NOTICE '  effective_io_concurrency = 200';
    RAISE NOTICE '  autovacuum_naptime = 30s';
    RAISE NOTICE '';
    RAISE NOTICE 'REQUIRED EXTENSIONS:';
    RAISE NOTICE '  pg_cron - for scheduled maintenance jobs';
    RAISE NOTICE '  pg_stat_statements - for query monitoring';
    RAISE NOTICE '';
    RAISE NOTICE 'Setup scheduled jobs using pg_cron:';
    RAISE NOTICE '  SELECT cron.schedule(''cleanup'', ''0 2 * * *'', ''SELECT cleanup_expired_records()'');';
    RAISE NOTICE '  SELECT cron.schedule(''reputation'', ''0 3 * * *'', ''SELECT update_reputation_scores()'');';
    RAISE NOTICE '  SELECT cron.schedule(''vacuum'', ''0 4 * * *'', ''SELECT vacuum_and_analyze_tables()'');';
    RAISE NOTICE '  SELECT cron.schedule(''stats'', ''0 * * * *'', ''SELECT update_statistics()'');';
    RAISE NOTICE '  SELECT cron.schedule(''metrics'', ''*/5 * * * *'', ''SELECT collect_database_metrics()'');';
    RAISE NOTICE '  SELECT cron.schedule(''matviews'', ''*/15 * * * *'', ''SELECT refresh_materialized_views()'');';
END $$;
