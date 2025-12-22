-- ============================================================================
-- SafeOps v2.0 - Threat Feed Management Schema
-- ============================================================================
-- File: 008_threat_feeds.sql
-- Purpose: Threat feed configuration, scheduling, and execution tracking
-- Version: 1.0.0
-- Created: 2025-12-22
-- Dependencies: 001_initial_setup.sql
-- ============================================================================

-- ============================================================================
-- SECTION 1: THREAT FEEDS CONFIGURATION TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS threat_feeds (
    -- Feed Identification
    id BIGSERIAL PRIMARY KEY,
    feed_name VARCHAR(255) UNIQUE NOT NULL,
    feed_url TEXT NOT NULL,
    feed_description TEXT,
    
    -- Feed Classification
    feed_type VARCHAR(50) NOT NULL CHECK (feed_type IN ('ip_blacklist', 'vpn_list', 'domain', 'hash', 'geo', 'mixed')),
    feed_format VARCHAR(20) NOT NULL CHECK (feed_format IN ('csv', 'json', 'txt', 'xml', 'stix')),
    
    -- Update Configuration
    is_active BOOLEAN DEFAULT TRUE,
    update_frequency INTEGER NOT NULL,
    update_schedule VARCHAR(50),
    priority INTEGER CHECK (priority >= 1 AND priority <= 10),
    
    -- Authentication
    requires_auth BOOLEAN DEFAULT FALSE,
    auth_type VARCHAR(50) CHECK (auth_type IN ('api_key', 'basic', 'bearer_token', 'none')),
    auth_config JSONB DEFAULT '{}'::jsonb,
    
    -- Feed Quality Metrics
    reliability_score INTEGER CHECK (reliability_score >= 0 AND reliability_score <= 100),
    false_positive_rate DECIMAL(5,2) CHECK (false_positive_rate >= 0 AND false_positive_rate <= 100),
    average_quality DECIMAL(5,2) CHECK (average_quality >= 0 AND average_quality <= 100),
    
    -- Statistics
    total_records_fetched BIGINT DEFAULT 0,
    total_records_imported BIGINT DEFAULT 0,
    total_records_rejected BIGINT DEFAULT 0,
    last_record_count INTEGER DEFAULT 0,
    
    -- Status Tracking
    last_fetch_status VARCHAR(20) CHECK (last_fetch_status IN ('success', 'failed', 'partial', 'timeout', 'pending')),
    last_error TEXT,
    consecutive_failures INTEGER DEFAULT 0,
    last_fetched TIMESTAMP WITH TIME ZONE,
    last_successful_fetch TIMESTAMP WITH TIME ZONE,
    next_scheduled_fetch TIMESTAMP WITH TIME ZONE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add table comments
COMMENT ON TABLE threat_feeds IS 'Threat feed configuration and management for external intelligence sources';
COMMENT ON COLUMN threat_feeds.feed_name IS 'Human-readable feed name (e.g., Feodo Tracker, PhishTank)';
COMMENT ON COLUMN threat_feeds.feed_url IS 'Download URL for the feed';
COMMENT ON COLUMN threat_feeds.feed_type IS 'Target category: ip_blacklist, vpn_list, domain, hash, geo, mixed';
COMMENT ON COLUMN threat_feeds.feed_format IS 'Data format: csv, json, txt, xml, stix';
COMMENT ON COLUMN threat_feeds.update_frequency IS 'Seconds between updates (3600=hourly, 86400=daily)';
COMMENT ON COLUMN threat_feeds.priority IS 'Update priority 1-10 (higher = update first)';
COMMENT ON COLUMN threat_feeds.auth_config IS 'JSONB with encrypted authentication credentials';
COMMENT ON COLUMN threat_feeds.reliability_score IS 'Feed reliability 0-100';
COMMENT ON COLUMN threat_feeds.consecutive_failures IS 'Failure streak counter (auto-disable after threshold)';
COMMENT ON COLUMN threat_feeds.next_scheduled_fetch IS 'When next update should run';

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_threat_feeds_name ON threat_feeds(feed_name);
CREATE INDEX IF NOT EXISTS idx_threat_feeds_active ON threat_feeds(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_threat_feeds_next_fetch ON threat_feeds(next_scheduled_fetch);
CREATE INDEX IF NOT EXISTS idx_threat_feeds_type ON threat_feeds(feed_type);
CREATE INDEX IF NOT EXISTS idx_threat_feeds_priority ON threat_feeds(priority DESC);
CREATE INDEX IF NOT EXISTS idx_threat_feeds_status ON threat_feeds(last_fetch_status);

COMMIT;

-- ============================================================================
-- SECTION 2: FEED EXECUTION HISTORY TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS feed_history (
    -- Execution Tracking
    id BIGSERIAL PRIMARY KEY,
    feed_id BIGINT NOT NULL REFERENCES threat_feeds(id) ON DELETE CASCADE,
    feed_name VARCHAR(255) NOT NULL,
    fetch_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms INTEGER,
    
    -- Execution Status
    status VARCHAR(20) CHECK (status IN ('started', 'downloading', 'parsing', 'storing', 'completed', 'failed')),
    records_downloaded INTEGER DEFAULT 0,
    records_parsed INTEGER DEFAULT 0,
    records_added INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    records_skipped INTEGER DEFAULT 0,
    records_rejected INTEGER DEFAULT 0,
    
    -- Error Tracking
    error_message TEXT,
    error_details JSONB,
    warnings JSONB,
    
    -- File Metadata
    downloaded_file_size BIGINT,
    file_hash VARCHAR(64),
    
    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE feed_history IS 'Execution history for all threat feed updates';
COMMENT ON COLUMN feed_history.feed_id IS 'Foreign key to threat_feeds table';
COMMENT ON COLUMN feed_history.feed_name IS 'Denormalized feed name for faster queries';
COMMENT ON COLUMN feed_history.execution_time_ms IS 'Update duration in milliseconds';
COMMENT ON COLUMN feed_history.status IS 'Execution state: started, downloading, parsing, storing, completed, failed';
COMMENT ON COLUMN feed_history.file_hash IS 'SHA256 of downloaded file to detect changes';

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_feed_history_feed_id ON feed_history(feed_id);
CREATE INDEX IF NOT EXISTS idx_feed_history_timestamp ON feed_history(fetch_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_feed_history_status ON feed_history(status);
CREATE INDEX IF NOT EXISTS idx_feed_history_feed_name ON feed_history(feed_name);

COMMIT;

-- ============================================================================
-- SECTION 3: FEED PERFORMANCE VIEWS
-- ============================================================================

BEGIN;

CREATE OR REPLACE VIEW feed_performance_summary AS
SELECT 
    tf.id,
    tf.feed_name,
    tf.feed_type,
    tf.is_active,
    tf.reliability_score,
    tf.total_records_imported,
    tf.last_successful_fetch,
    tf.consecutive_failures,
    COUNT(fh.id) as total_executions,
    AVG(fh.execution_time_ms)::INTEGER as avg_execution_time_ms,
    SUM(CASE WHEN fh.status = 'failed' THEN 1 ELSE 0 END) as failed_count,
    SUM(CASE WHEN fh.status = 'completed' THEN 1 ELSE 0 END) as success_count,
    MAX(fh.fetch_timestamp) as last_execution
FROM threat_feeds tf
LEFT JOIN feed_history fh ON tf.id = fh.feed_id
GROUP BY tf.id, tf.feed_name, tf.feed_type, tf.is_active, 
         tf.reliability_score, tf.total_records_imported, 
         tf.last_successful_fetch, tf.consecutive_failures
ORDER BY tf.priority DESC NULLS LAST, tf.feed_name;

COMMENT ON VIEW feed_performance_summary IS 'Dashboard-ready feed health metrics and performance statistics';

-- View: Recent feed activity
CREATE OR REPLACE VIEW recent_feed_activity AS
SELECT 
    fh.feed_name,
    fh.status,
    fh.records_added,
    fh.records_updated,
    fh.execution_time_ms,
    fh.fetch_timestamp,
    fh.error_message
FROM feed_history fh
ORDER BY fh.fetch_timestamp DESC
LIMIT 100;

COMMENT ON VIEW recent_feed_activity IS 'Most recent 100 feed executions for monitoring';

COMMIT;

-- ============================================================================
-- SECTION 4: HELPER FUNCTIONS
-- ============================================================================

BEGIN;

-- Function: Get feeds due for update
CREATE OR REPLACE FUNCTION get_feeds_due_for_update()
RETURNS TABLE(
    feed_id BIGINT,
    feed_name VARCHAR(255),
    feed_url TEXT,
    feed_type VARCHAR(50),
    priority INTEGER,
    update_frequency INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        tf.id,
        tf.feed_name,
        tf.feed_url,
        tf.feed_type,
        tf.priority,
        tf.update_frequency
    FROM threat_feeds tf
    WHERE tf.is_active = TRUE
    AND (
        tf.next_scheduled_fetch IS NULL 
        OR tf.next_scheduled_fetch <= CURRENT_TIMESTAMP
    )
    AND tf.consecutive_failures < 10  -- Don't retry feeds with too many failures
    ORDER BY tf.priority DESC NULLS LAST, tf.next_scheduled_fetch ASC NULLS FIRST;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION get_feeds_due_for_update() IS 'Returns active feeds that need updating, ordered by priority';

-- Function: Record feed execution start
CREATE OR REPLACE FUNCTION start_feed_execution(
    p_feed_id BIGINT,
    p_feed_name VARCHAR
)
RETURNS BIGINT AS $$
DECLARE
    history_id BIGINT;
BEGIN
    -- Insert feed history record
    INSERT INTO feed_history (
        feed_id,
        feed_name,
        status,
        started_at
    ) VALUES (
        p_feed_id,
        p_feed_name,
        'started',
        CURRENT_TIMESTAMP
    )
    RETURNING id INTO history_id;
    
    -- Update feed status
    UPDATE threat_feeds
    SET 
        last_fetched = CURRENT_TIMESTAMP,
        last_fetch_status = 'pending',
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_feed_id;
    
    RETURN history_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION start_feed_execution(BIGINT, VARCHAR) IS 'Records the start of a feed execution and returns history ID';

-- Function: Complete feed execution
CREATE OR REPLACE FUNCTION complete_feed_execution(
    p_history_id BIGINT,
    p_status VARCHAR,
    p_records_added INTEGER,
    p_records_updated INTEGER,
    p_records_skipped INTEGER,
    p_execution_time_ms INTEGER,
    p_error_message TEXT DEFAULT NULL
)
RETURNS VOID AS $$
DECLARE
    v_feed_id BIGINT;
    v_records_total INTEGER;
BEGIN
    -- Get feed_id from history
    SELECT feed_id INTO v_feed_id FROM feed_history WHERE id = p_history_id;
    
    v_records_total := COALESCE(p_records_added, 0) + COALESCE(p_records_updated, 0);
    
    -- Update feed history
    UPDATE feed_history
    SET 
        status = p_status,
        records_added = p_records_added,
        records_updated = p_records_updated,
        records_skipped = p_records_skipped,
        execution_time_ms = p_execution_time_ms,
        error_message = p_error_message,
        completed_at = CURRENT_TIMESTAMP
    WHERE id = p_history_id;
    
    -- Update feed stats
    IF p_status = 'completed' THEN
        UPDATE threat_feeds
        SET 
            last_fetch_status = 'success',
            last_successful_fetch = CURRENT_TIMESTAMP,
            total_records_imported = total_records_imported + v_records_total,
            last_record_count = v_records_total,
            consecutive_failures = 0,
            next_scheduled_fetch = CURRENT_TIMESTAMP + (update_frequency || ' seconds')::INTERVAL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_feed_id;
    ELSE
        -- Failed execution
        UPDATE threat_feeds
        SET 
            last_fetch_status = p_status,
            last_error = p_error_message,
            consecutive_failures = consecutive_failures + 1,
            next_scheduled_fetch = CURRENT_TIMESTAMP + (update_frequency || ' seconds')::INTERVAL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = v_feed_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION complete_feed_execution(BIGINT, VARCHAR, INTEGER, INTEGER, INTEGER, INTEGER, TEXT) IS 'Records feed execution completion and updates feed statistics';

COMMIT;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Uncomment to verify setup (for manual testing)
-- SELECT * FROM threat_feeds LIMIT 5;
-- SELECT * FROM feed_history LIMIT 10;
-- SELECT * FROM feed_performance_summary;
-- SELECT * FROM recent_feed_activity LIMIT 10;
-- SELECT * FROM get_feeds_due_for_update();

-- ============================================================================
-- END OF THREAT FEEDS SCHEMA
-- ============================================================================
