-- ============================================================================
-- SafeOps Threat Intelligence Database - Threat Feed Management
-- File: 008_threat_feeds.sql
-- Purpose: Feed credentials, scheduling, health metrics, and quality monitoring
-- ============================================================================

-- =============================================================================
-- TABLE: feed_credentials
-- =============================================================================

CREATE TABLE feed_credentials (
    credential_id SERIAL PRIMARY KEY,
    feed_id INTEGER NOT NULL UNIQUE,
    auth_type VARCHAR(50) NOT NULL CHECK (auth_type IN (
        'API_KEY', 'OAUTH2', 'BASIC_AUTH', 'BEARER_TOKEN', 'CERTIFICATE', 'NONE'
    )),
    api_key TEXT,
    api_secret TEXT,
    username VARCHAR(255),
    password_hash TEXT,
    oauth_token TEXT,
    oauth_refresh_token TEXT,
    oauth_expires_at TIMESTAMP WITH TIME ZONE,
    certificate_path TEXT,
    additional_headers JSONB DEFAULT '{}',
    rate_limit_per_hour INTEGER,
    rate_limit_per_day INTEGER,
    quota_used_today INTEGER DEFAULT 0,
    quota_reset_at TIMESTAMP WITH TIME ZONE,
    last_rotated TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE
);

-- Indexes for feed_credentials
CREATE UNIQUE INDEX idx_feed_credentials_feed ON feed_credentials(feed_id);
CREATE INDEX idx_feed_credentials_auth_type ON feed_credentials(auth_type);
CREATE INDEX idx_feed_credentials_expires ON feed_credentials(expires_at);
CREATE INDEX idx_feed_credentials_oauth_expires ON feed_credentials(oauth_expires_at);

COMMENT ON TABLE feed_credentials IS 'Store API keys and authentication credentials for threat feeds (ENCRYPT SENSITIVE DATA)';
COMMENT ON COLUMN feed_credentials.api_key IS 'MUST be encrypted at rest using pgcrypto';
COMMENT ON COLUMN feed_credentials.password_hash IS 'MUST be encrypted at rest';

-- =============================================================================
-- TABLE: feed_update_schedule
-- =============================================================================

CREATE TABLE feed_update_schedule (
    schedule_id SERIAL PRIMARY KEY,
    feed_id INTEGER NOT NULL,
    schedule_type VARCHAR(20) NOT NULL CHECK (schedule_type IN ('INTERVAL', 'CRON', 'ON_DEMAND')),
    update_interval_seconds INTEGER CHECK (update_interval_seconds IS NULL OR update_interval_seconds >= 300),
    cron_expression VARCHAR(100),
    timezone VARCHAR(50) DEFAULT 'UTC',
    next_run_at TIMESTAMP WITH TIME ZONE,
    last_run_at TIMESTAMP WITH TIME ZONE,
    last_run_status VARCHAR(20) CHECK (last_run_status IN (
        'SUCCESS', 'FAILED', 'TIMEOUT', 'SKIPPED', 'RUNNING'
    )),
    consecutive_failures INTEGER DEFAULT 0,
    max_consecutive_failures INTEGER DEFAULT 5,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    timeout_seconds INTEGER DEFAULT 300 CHECK (timeout_seconds > 0),
    retry_on_failure BOOLEAN DEFAULT true,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    backoff_multiplier DECIMAL(3,2) DEFAULT 2.0 CHECK (backoff_multiplier >= 1.0),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE
);

-- Indexes for feed_update_schedule
CREATE INDEX idx_feed_schedule_feed ON feed_update_schedule(feed_id);
CREATE INDEX idx_feed_schedule_enabled_next ON feed_update_schedule(enabled, next_run_at);
CREATE INDEX idx_feed_schedule_type ON feed_update_schedule(schedule_type);
CREATE INDEX idx_feed_schedule_priority ON feed_update_schedule(priority);
CREATE INDEX idx_feed_schedule_status ON feed_update_schedule(last_run_status);

COMMENT ON TABLE feed_update_schedule IS 'Define and track feed update schedules';
COMMENT ON COLUMN feed_update_schedule.schedule_type IS 'INTERVAL=fixed interval, CRON=cron expression, ON_DEMAND=manual';
COMMENT ON COLUMN feed_update_schedule.backoff_multiplier IS 'Exponential backoff multiplier for retries';

-- =============================================================================
-- TABLE: feed_update_history (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE feed_update_history (
    update_id BIGSERIAL,
    feed_id INTEGER NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER CHECK (duration_ms >= 0),
    status VARCHAR(20) NOT NULL CHECK (status IN (
        'SUCCESS', 'FAILED', 'TIMEOUT', 'PARTIAL', 'CANCELLED'
    )),
    records_fetched INTEGER DEFAULT 0 CHECK (records_fetched >= 0),
    records_processed INTEGER DEFAULT 0 CHECK (records_processed >= 0),
    records_inserted INTEGER DEFAULT 0 CHECK (records_inserted >= 0),
    records_updated INTEGER DEFAULT 0 CHECK (records_updated >= 0),
    records_deleted INTEGER DEFAULT 0 CHECK (records_deleted >= 0),
    http_status_code INTEGER,
    error_message TEXT,
    error_type VARCHAR(50) CHECK (error_type IN (
        'NETWORK', 'AUTH', 'PARSE', 'QUOTA', 'TIMEOUT', 'RATE_LIMIT', 'INVALID_DATA', 'UNKNOWN'
    )),
    retry_attempt INTEGER DEFAULT 0,
    data_size_bytes BIGINT,
    feed_version VARCHAR(50),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (update_id, started_at),
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE
) PARTITION BY RANGE (started_at);

-- Indexes for feed_update_history
CREATE INDEX idx_feed_update_history_feed ON feed_update_history(feed_id);
CREATE INDEX idx_feed_update_history_started ON feed_update_history(started_at);
CREATE INDEX idx_feed_update_history_status ON feed_update_history(status);
CREATE INDEX idx_feed_update_history_feed_started ON feed_update_history(feed_id, started_at DESC);
CREATE INDEX idx_feed_update_history_error_type ON feed_update_history(error_type);
CREATE INDEX idx_feed_update_history_metadata ON feed_update_history USING gin(metadata);

COMMENT ON TABLE feed_update_history IS 'Detailed log of feed update attempts and results (partitioned monthly)';
COMMENT ON COLUMN feed_update_history.duration_ms IS 'Update duration in milliseconds';

-- Create initial partitions (current month + next 2 months)
DO $$
DECLARE
    partition_date DATE;
    partition_name TEXT;
    start_date TIMESTAMP WITH TIME ZONE;
    end_date TIMESTAMP WITH TIME ZONE;
BEGIN
    FOR i IN 0..2 LOOP
        partition_date := DATE_TRUNC('month', CURRENT_DATE + (i || ' months')::INTERVAL)::DATE;
        partition_name := 'feed_update_history_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF feed_update_history
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: feed_health_metrics (PARTITIONED BY WEEK)
-- =============================================================================

CREATE TABLE feed_health_metrics (
    metric_id BIGSERIAL,
    feed_id INTEGER NOT NULL,
    metric_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    availability_percent DECIMAL(5,2) CHECK (availability_percent BETWEEN 0.00 AND 100.00),
    success_rate_percent DECIMAL(5,2) CHECK (success_rate_percent BETWEEN 0.00 AND 100.00),
    average_response_time_ms INTEGER,
    average_records_per_update INTEGER,
    total_updates_24h INTEGER CHECK (total_updates_24h >= 0),
    failed_updates_24h INTEGER CHECK (failed_updates_24h >= 0),
    quota_usage_percent DECIMAL(5,2) CHECK (quota_usage_percent BETWEEN 0.00 AND 100.00),
    data_freshness_hours INTEGER,
    error_rate_percent DECIMAL(5,2) CHECK (error_rate_percent BETWEEN 0.00 AND 100.00),
    health_status VARCHAR(20) CHECK (health_status IN (
        'HEALTHY', 'DEGRADED', 'UNHEALTHY', 'DOWN', 'UNKNOWN'
    )),
    alert_triggered BOOLEAN DEFAULT false,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (metric_id, metric_timestamp),
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE
) PARTITION BY RANGE (metric_timestamp);

-- Indexes for feed_health_metrics
CREATE INDEX idx_feed_health_feed ON feed_health_metrics(feed_id);
CREATE INDEX idx_feed_health_timestamp ON feed_health_metrics(metric_timestamp);
CREATE INDEX idx_feed_health_status ON feed_health_metrics(health_status);
CREATE INDEX idx_feed_health_feed_time ON feed_health_metrics(feed_id, metric_timestamp DESC);
CREATE INDEX idx_feed_health_alert ON feed_health_metrics(alert_triggered);

COMMENT ON TABLE feed_health_metrics IS 'Track feed health and performance metrics (partitioned weekly)';
COMMENT ON COLUMN feed_health_metrics.data_freshness_hours IS 'Hours since last successful update';

-- Create initial partitions (current week + next 3 weeks)
DO $$
DECLARE
    partition_date DATE;
    partition_name TEXT;
    start_date TIMESTAMP WITH TIME ZONE;
    end_date TIMESTAMP WITH TIME ZONE;
BEGIN
    FOR i IN 0..3 LOOP
        partition_date := DATE_TRUNC('week', CURRENT_DATE + (i || ' weeks')::INTERVAL)::DATE;
        partition_name := 'feed_health_metrics_' || TO_CHAR(partition_date, 'IYYY_IW');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 week')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF feed_health_metrics
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: feed_data_quality
-- =============================================================================

CREATE TABLE feed_data_quality (
    quality_id BIGSERIAL PRIMARY KEY,
    feed_id INTEGER NOT NULL,
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    sample_size INTEGER CHECK (sample_size >= 0),
    valid_records INTEGER CHECK (valid_records >= 0),
    invalid_records INTEGER CHECK (invalid_records >= 0),
    duplicate_records INTEGER CHECK (duplicate_records >= 0),
    stale_records INTEGER CHECK (stale_records >= 0),
    malformed_records INTEGER CHECK (malformed_records >= 0),
    accuracy_score DECIMAL(5,2) CHECK (accuracy_score BETWEEN 0.00 AND 100.00),
    completeness_score DECIMAL(5,2) CHECK (completeness_score BETWEEN 0.00 AND 100.00),
    timeliness_score DECIMAL(5,2) CHECK (timeliness_score BETWEEN 0.00 AND 100.00),
    consistency_score DECIMAL(5,2) CHECK (consistency_score BETWEEN 0.00 AND 100.00),
    overall_quality_score DECIMAL(5,2) CHECK (overall_quality_score BETWEEN 0.00 AND 100.00),
    quality_grade CHAR(1) CHECK (quality_grade IN ('A', 'B', 'C', 'D', 'F')),
    validation_errors JSONB DEFAULT '{}',
    recommendations TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE
);

-- Indexes for feed_data_quality
CREATE INDEX idx_feed_quality_feed ON feed_data_quality(feed_id);
CREATE INDEX idx_feed_quality_assessed ON feed_data_quality(assessed_at);
CREATE INDEX idx_feed_quality_score ON feed_data_quality(overall_quality_score);
CREATE INDEX idx_feed_quality_grade ON feed_data_quality(quality_grade);
CREATE INDEX idx_feed_quality_feed_assessed ON feed_data_quality(feed_id, assessed_at DESC);
CREATE INDEX idx_feed_quality_errors ON feed_data_quality USING gin(validation_errors);

COMMENT ON TABLE feed_data_quality IS 'Track data quality metrics for feed validation';
COMMENT ON COLUMN feed_data_quality.quality_grade IS 'Overall grade: A (90-100), B (80-89), C (70-79), D (60-69), F (<60)';

-- =============================================================================
-- TABLE: feed_source_reliability
-- =============================================================================

CREATE TABLE feed_source_reliability (
    reliability_id SERIAL PRIMARY KEY,
    feed_id INTEGER NOT NULL,
    evaluation_period_start TIMESTAMP WITH TIME ZONE,
    evaluation_period_end TIMESTAMP WITH TIME ZONE,
    total_indicators_provided INTEGER CHECK (total_indicators_provided >= 0),
    true_positives INTEGER CHECK (true_positives >= 0),
    false_positives INTEGER CHECK (false_positives >= 0),
    false_negatives INTEGER CHECK (false_negatives >= 0),
    precision DECIMAL(5,4) CHECK (precision BETWEEN 0.0000 AND 1.0000),
    recall DECIMAL(5,4) CHECK (recall BETWEEN 0.0000 AND 1.0000),
    f1_score DECIMAL(5,4) CHECK (f1_score BETWEEN 0.0000 AND 1.0000),
    reliability_score DECIMAL(5,2) CHECK (reliability_score BETWEEN 0.00 AND 100.00),
    trust_level VARCHAR(20) CHECK (trust_level IN (
        'VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW', 'VERY_LOW'
    )),
    recommendation VARCHAR(20) CHECK (recommendation IN (
        'INCREASE_PRIORITY', 'MAINTAIN', 'DECREASE_PRIORITY', 'DISABLE', 'REVIEW'
    )),
    notes TEXT,
    evaluated_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE
);

-- Indexes for feed_source_reliability
CREATE INDEX idx_feed_reliability_feed ON feed_source_reliability(feed_id);
CREATE INDEX idx_feed_reliability_period_end ON feed_source_reliability(evaluation_period_end);
CREATE INDEX idx_feed_reliability_score ON feed_source_reliability(reliability_score);
CREATE INDEX idx_feed_reliability_trust ON feed_source_reliability(trust_level);
CREATE INDEX idx_feed_reliability_recommendation ON feed_source_reliability(recommendation);

COMMENT ON TABLE feed_source_reliability IS 'Track feed reliability and trust scores over time';
COMMENT ON COLUMN feed_source_reliability.precision IS 'Precision metric: TP / (TP + FP)';
COMMENT ON COLUMN feed_source_reliability.recall IS 'Recall metric: TP / (TP + FN)';
COMMENT ON COLUMN feed_source_reliability.f1_score IS 'F1 score: harmonic mean of precision and recall';

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_feed_management_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_feed_credentials_updated
    BEFORE UPDATE ON feed_credentials
    FOR EACH ROW EXECUTE FUNCTION update_feed_management_updated_at();

CREATE TRIGGER trigger_feed_schedule_updated
    BEFORE UPDATE ON feed_update_schedule
    FOR EACH ROW EXECUTE FUNCTION update_feed_management_updated_at();

-- Auto-calculate duration_ms on completion
CREATE OR REPLACE FUNCTION calculate_update_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
        NEW.duration_ms := EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at)) * 1000;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_calculate_duration
    BEFORE UPDATE ON feed_update_history
    FOR EACH ROW EXECUTE FUNCTION calculate_update_duration();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Check if OAuth token needs refresh
CREATE OR REPLACE FUNCTION needs_oauth_refresh(p_feed_id INTEGER)
RETURNS BOOLEAN AS $$
DECLARE
    v_expires_at TIMESTAMP WITH TIME ZONE;
BEGIN
    SELECT oauth_expires_at INTO v_expires_at
    FROM feed_credentials
    WHERE feed_id = p_feed_id
      AND auth_type = 'OAUTH2';
    
    IF v_expires_at IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Refresh if expiring within 5 minutes
    RETURN v_expires_at <= NOW() + INTERVAL '5 minutes';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION needs_oauth_refresh IS 'Check if OAuth token needs refresh (within 5 minutes of expiry)';

-- Function: Get feeds due for update
CREATE OR REPLACE FUNCTION get_feeds_due_for_update()
RETURNS TABLE (
    feed_id INTEGER,
    feed_name VARCHAR(255),
    schedule_type VARCHAR(20),
    priority INTEGER,
    last_run_at TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        f.feed_id,
        f.feed_name,
        s.schedule_type,
        s.priority,
        s.last_run_at
    FROM threat_feeds f
    JOIN feed_update_schedule s ON s.feed_id = f.feed_id
    WHERE f.enabled = true
      AND s.enabled = true
      AND s.schedule_type != 'ON_DEMAND'
      AND s.last_run_status != 'RUNNING'
      AND (s.next_run_at IS NULL OR s.next_run_at <= NOW())
      AND s.consecutive_failures < s.max_consecutive_failures
    ORDER BY s.priority ASC, s.next_run_at ASC NULLS FIRST;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_feeds_due_for_update IS 'Get feeds that are due for update, ordered by priority';

-- Function: Record feed update result
CREATE OR REPLACE FUNCTION record_feed_update(
    p_feed_id INTEGER,
    p_status VARCHAR(20),
    p_records_fetched INTEGER DEFAULT 0,
    p_records_processed INTEGER DEFAULT 0,
    p_error_message TEXT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    v_update_id BIGINT;
    v_started_at TIMESTAMP WITH TIME ZONE;
BEGIN
    -- Get the running update's start time
    SELECT started_at INTO v_started_at
    FROM feed_update_history
    WHERE feed_id = p_feed_id
      AND status = 'RUNNING'
      AND completed_at IS NULL
    ORDER BY started_at DESC
    LIMIT 1;
    
    IF v_started_at IS NULL THEN
        -- No running update found, create new entry
        INSERT INTO feed_update_history (
            feed_id, status, records_fetched, records_processed, 
            error_message, completed_at
        ) VALUES (
            p_feed_id, p_status, p_records_fetched, p_records_processed,
            p_error_message, NOW()
        ) RETURNING update_id INTO v_update_id;
    ELSE
        -- Update existing entry
        UPDATE feed_update_history
        SET status = p_status,
            records_fetched = p_records_fetched,
            records_processed = p_records_processed,
            error_message = p_error_message,
            completed_at = NOW()
        WHERE feed_id = p_feed_id
          AND started_at = v_started_at
        RETURNING update_id INTO v_update_id;
    END IF;
    
    -- Update schedule
    UPDATE feed_update_schedule
    SET last_run_at = NOW(),
        last_run_status = p_status,
        consecutive_failures = CASE 
            WHEN p_status = 'SUCCESS' THEN 0
            ELSE consecutive_failures + 1
        END
    WHERE feed_id = p_feed_id;
    
    RETURN v_update_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION record_feed_update IS 'Record feed update result and update schedule status';

-- Function: Calculate next run time for interval-based schedule
CREATE OR REPLACE FUNCTION calculate_next_run(p_schedule_id INTEGER)
RETURNS TIMESTAMP WITH TIME ZONE AS $$
DECLARE
    v_schedule RECORD;
    v_next_run TIMESTAMP WITH TIME ZONE;
BEGIN
    SELECT * INTO v_schedule FROM feed_update_schedule WHERE schedule_id = p_schedule_id;
    
    IF v_schedule.schedule_type = 'INTERVAL' THEN
        v_next_run := NOW() + (v_schedule.update_interval_seconds || ' seconds')::INTERVAL;
    ELSIF v_schedule.schedule_type = 'ON_DEMAND' THEN
        v_next_run := NULL;
    ELSE
        -- For CRON, would need external cron parser
        v_next_run := NOW() + INTERVAL '1 hour'; -- Default fallback
    END IF;
    
    UPDATE feed_update_schedule
    SET next_run_at = v_next_run
    WHERE schedule_id = p_schedule_id;
    
    RETURN v_next_run;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION calculate_next_run IS 'Calculate and set next run time for a schedule';

-- Function: Get feed health summary
CREATE OR REPLACE FUNCTION get_feed_health_summary()
RETURNS TABLE (
    feed_name VARCHAR(255),
    health_status VARCHAR(20),
    success_rate DECIMAL(5,2),
    last_update TIMESTAMP WITH TIME ZONE,
    consecutive_failures INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        f.feed_name,
        COALESCE(m.health_status, 'UNKNOWN') AS health_status,
        COALESCE(m.success_rate_percent, 0.00) AS success_rate,
        s.last_run_at,
        s.consecutive_failures
    FROM threat_feeds f
    LEFT JOIN feed_update_schedule s ON s.feed_id = f.feed_id
    LEFT JOIN LATERAL (
        SELECT health_status, success_rate_percent
        FROM feed_health_metrics
        WHERE feed_id = f.feed_id
        ORDER BY metric_timestamp DESC
        LIMIT 1
    ) m ON TRUE
    WHERE f.enabled = true
    ORDER BY s.consecutive_failures DESC, f.feed_name;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_feed_health_summary IS 'Get current health status for all enabled feeds';

-- =============================================================================
-- VERIFICATION
-- =============================================================================

DO $$
DECLARE
    table_count INTEGER;
    index_count INTEGER;
    function_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO table_count FROM information_schema.tables 
    WHERE table_schema = 'public' 
      AND table_name LIKE 'feed_%';
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public' 
      AND tablename LIKE 'feed_%';
    
    SELECT COUNT(*) INTO function_count FROM pg_proc 
    WHERE proname LIKE '%feed%';
    
    RAISE NOTICE '=== Threat Feed Management Schema Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Functions created: %', function_count;
    RAISE NOTICE 'WARNING: Encrypt sensitive credentials using pgcrypto';
    RAISE NOTICE 'Update history partitioned by month';
    RAISE NOTICE 'Health metrics partitioned by week';
    RAISE NOTICE 'OAuth token refresh detection enabled';
END $$;
