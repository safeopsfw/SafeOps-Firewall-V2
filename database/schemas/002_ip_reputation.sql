-- ============================================================================
-- SafeOps Threat Intelligence Database - IP Reputation
-- File: 002_ip_reputation.sql
-- Purpose: IP address reputation scoring, tracking, and manual override management
-- ============================================================================

-- =============================================================================
-- CORE TABLE: ip_reputation
-- =============================================================================

CREATE TABLE ip_reputation (
    ip_id BIGSERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence_level BETWEEN 0.00 AND 1.00),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    total_reports INTEGER DEFAULT 0,
    is_whitelisted BOOLEAN DEFAULT false,
    is_blacklisted BOOLEAN DEFAULT false,
    asn_id INTEGER,
    country_code CHAR(2),
    threat_category_id INTEGER,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraint: Cannot be both whitelisted AND blacklisted
    CONSTRAINT check_not_both_lists CHECK (NOT (is_whitelisted = true AND is_blacklisted = true)),
    
    -- Foreign keys
    FOREIGN KEY (threat_category_id) REFERENCES threat_categories(category_id) ON DELETE SET NULL
);

-- Indexes for ip_reputation
CREATE UNIQUE INDEX idx_ip_reputation_address ON ip_reputation(ip_address);
CREATE INDEX idx_ip_reputation_score ON ip_reputation(reputation_score);
CREATE INDEX idx_ip_reputation_last_seen_score ON ip_reputation(last_seen, reputation_score);
CREATE INDEX idx_ip_reputation_country ON ip_reputation(country_code);
CREATE INDEX idx_ip_reputation_asn ON ip_reputation(asn_id);
CREATE INDEX idx_ip_reputation_overrides ON ip_reputation(is_whitelisted, is_blacklisted);
CREATE INDEX idx_ip_reputation_gist ON ip_reputation USING gist(ip_address inet_ops);

COMMENT ON TABLE ip_reputation IS 'Primary table storing current reputation scores for IP addresses';
COMMENT ON COLUMN ip_reputation.reputation_score IS 'Current reputation score (-100=malicious to +100=benign)';
COMMENT ON COLUMN ip_reputation.confidence_level IS 'Confidence in reputation score (0.00-1.00, 0.80+ is high confidence)';
COMMENT ON COLUMN ip_reputation.total_reports IS 'Total number of threat reports across all feeds';
COMMENT ON CONSTRAINT check_not_both_lists ON ip_reputation IS 'Prevents IP from being both whitelisted and blacklisted';

-- =============================================================================
-- TABLE: ip_reputation_sources
-- =============================================================================

CREATE TABLE ip_reputation_sources (
    source_id BIGSERIAL PRIMARY KEY,
    ip_id BIGINT NOT NULL,
    feed_id INTEGER NOT NULL,
    reported_score INTEGER NOT NULL CHECK (reported_score BETWEEN -100 AND 100),
    feed_confidence DECIMAL(3,2) DEFAULT 0.50 CHECK (feed_confidence BETWEEN 0.00 AND 1.00),
    report_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_types TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (ip_id) REFERENCES ip_reputation(ip_id) ON DELETE CASCADE,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE,
    
    -- Prevent duplicate feed reports for same IP
    CONSTRAINT unique_ip_feed UNIQUE (ip_id, feed_id)
);

-- Indexes for ip_reputation_sources
CREATE INDEX idx_ip_rep_sources_ip ON ip_reputation_sources(ip_id);
CREATE INDEX idx_ip_rep_sources_feed ON ip_reputation_sources(feed_id);
CREATE INDEX idx_ip_rep_sources_timestamp ON ip_reputation_sources(report_timestamp);
CREATE INDEX idx_ip_rep_sources_expires ON ip_reputation_sources(expires_at);
CREATE INDEX idx_ip_rep_sources_threat_types ON ip_reputation_sources USING gin(threat_types);
CREATE INDEX idx_ip_rep_sources_metadata ON ip_reputation_sources USING gin(metadata);

COMMENT ON TABLE ip_reputation_sources IS 'Many-to-many relationship tracking which feeds reported which IPs';
COMMENT ON CONSTRAINT unique_ip_feed ON ip_reputation_sources IS 'Prevents duplicate reports from same feed for same IP';

-- =============================================================================
-- TABLE: ip_reputation_history (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE ip_reputation_history (
    history_id BIGSERIAL,
    ip_id BIGINT NOT NULL,
    old_score INTEGER,
    new_score INTEGER,
    score_delta INTEGER,
    change_reason VARCHAR(100) CHECK (change_reason IN (
        'FEED_UPDATE', 'DECAY', 'MANUAL_ADJUSTMENT', 'WHITELIST', 'BLACKLIST', 'SYSTEM_RECALCULATION'
    )),
    changed_by VARCHAR(100),
    feed_id INTEGER,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    PRIMARY KEY (history_id, changed_at),
    FOREIGN KEY (ip_id) REFERENCES ip_reputation(ip_id) ON DELETE CASCADE,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE SET NULL
) PARTITION BY RANGE (changed_at);

-- Indexes for ip_reputation_history
CREATE INDEX idx_ip_rep_history_ip ON ip_reputation_history(ip_id);
CREATE INDEX idx_ip_rep_history_changed_at ON ip_reputation_history(changed_at);
CREATE INDEX idx_ip_rep_history_ip_time ON ip_reputation_history(ip_id, changed_at DESC);
CREATE INDEX idx_ip_rep_history_reason ON ip_reputation_history(change_reason);

COMMENT ON TABLE ip_reputation_history IS 'Time-series audit log of reputation score changes (partitioned monthly)';
COMMENT ON COLUMN ip_reputation_history.score_delta IS 'Change amount (new_score - old_score)';

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
        partition_name := 'ip_reputation_history_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF ip_reputation_history
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: ip_whitelist
-- =============================================================================

CREATE TABLE ip_whitelist (
    whitelist_id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    added_by VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for ip_whitelist
CREATE UNIQUE INDEX idx_ip_whitelist_address ON ip_whitelist(ip_address);
CREATE INDEX idx_ip_whitelist_enabled ON ip_whitelist(enabled);
CREATE INDEX idx_ip_whitelist_expires ON ip_whitelist(expires_at);
CREATE INDEX idx_ip_whitelist_gist ON ip_whitelist USING gist(ip_address inet_ops);

COMMENT ON TABLE ip_whitelist IS 'Trusted IP addresses that should never be blocked';
COMMENT ON COLUMN ip_whitelist.ip_address IS 'IP or CIDR range (e.g., 192.168.1.0/24)';
COMMENT ON COLUMN ip_whitelist.expires_at IS 'Optional expiration (NULL = permanent)';

-- =============================================================================
-- TABLE: ip_blacklist
-- =============================================================================

CREATE TABLE ip_blacklist (
    blacklist_id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 10),
    added_by VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for ip_blacklist
CREATE UNIQUE INDEX idx_ip_blacklist_address ON ip_blacklist(ip_address);
CREATE INDEX idx_ip_blacklist_enabled_severity ON ip_blacklist(enabled, severity DESC);
CREATE INDEX idx_ip_blacklist_expires ON ip_blacklist(expires_at);
CREATE INDEX idx_ip_blacklist_gist ON ip_blacklist USING gist(ip_address inet_ops);

COMMENT ON TABLE ip_blacklist IS 'Known malicious IP addresses that should always be blocked';
COMMENT ON COLUMN ip_blacklist.severity IS 'Severity 1-10 (10=critical, 1=low)';

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_ip_reputation_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_ip_reputation_updated
    BEFORE UPDATE ON ip_reputation
    FOR EACH ROW EXECUTE FUNCTION update_ip_reputation_updated_at();

CREATE TRIGGER trigger_ip_whitelist_updated
    BEFORE UPDATE ON ip_whitelist
    FOR EACH ROW EXECUTE FUNCTION update_ip_reputation_updated_at();

CREATE TRIGGER trigger_ip_blacklist_updated
    BEFORE UPDATE ON ip_blacklist
    FOR EACH ROW EXECUTE FUNCTION update_ip_reputation_updated_at();

-- Auto-log reputation score changes to history
CREATE OR REPLACE FUNCTION log_ip_reputation_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.reputation_score IS DISTINCT FROM NEW.reputation_score THEN
        INSERT INTO ip_reputation_history (
            ip_id, old_score, new_score, score_delta, 
            change_reason, changed_by, changed_at
        ) VALUES (
            NEW.ip_id, 
            OLD.reputation_score, 
            NEW.reputation_score,
            NEW.reputation_score - OLD.reputation_score,
            COALESCE(NEW.notes, 'FEED_UPDATE'),
            current_user,
            NOW()
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_log_reputation_change
    AFTER UPDATE ON ip_reputation
    FOR EACH ROW EXECUTE FUNCTION log_ip_reputation_change();

-- Auto-update is_whitelisted flag when IP added to whitelist
CREATE OR REPLACE FUNCTION sync_whitelist_flag()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE ip_reputation 
        SET is_whitelisted = true, updated_at = NOW()
        WHERE ip_address = NEW.ip_address;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE ip_reputation 
        SET is_whitelisted = false, updated_at = NOW()
        WHERE ip_address = OLD.ip_address;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_sync_whitelist
    AFTER INSERT OR DELETE ON ip_whitelist
    FOR EACH ROW EXECUTE FUNCTION sync_whitelist_flag();

-- Auto-update is_blacklisted flag when IP added to blacklist
CREATE OR REPLACE FUNCTION sync_blacklist_flag()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE ip_reputation 
        SET is_blacklisted = true, updated_at = NOW()
        WHERE ip_address = NEW.ip_address;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE ip_reputation 
        SET is_blacklisted = false, updated_at = NOW()
        WHERE ip_address = OLD.ip_address;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_sync_blacklist
    AFTER INSERT OR DELETE ON ip_blacklist
    FOR EACH ROW EXECUTE FUNCTION sync_blacklist_flag();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Get IP reputation with all related data
CREATE OR REPLACE FUNCTION get_ip_reputation(search_ip INET)
RETURNS TABLE (
    ip_address INET,
    reputation_score INTEGER,
    confidence_level DECIMAL,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    total_reports INTEGER,
    is_whitelisted BOOLEAN,
    is_blacklisted BOOLEAN,
    country_code CHAR(2),
    feed_count INTEGER,
    threat_types TEXT[]
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        r.ip_address,
        r.reputation_score,
        r.confidence_level,
        r.first_seen,
        r.last_seen,
        r.total_reports,
        r.is_whitelisted,
        r.is_blacklisted,
        r.country_code,
        COUNT(DISTINCT s.feed_id)::INTEGER AS feed_count,
        ARRAY_AGG(DISTINCT unnest(s.threat_types)) AS threat_types
    FROM ip_reputation r
    LEFT JOIN ip_reputation_sources s ON s.ip_id = r.ip_id
    WHERE r.ip_address = search_ip
    GROUP BY r.ip_id, r.ip_address, r.reputation_score, r.confidence_level, 
             r.first_seen, r.last_seen, r.total_reports, r.is_whitelisted, 
             r.is_blacklisted, r.country_code;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_ip_reputation IS 'Retrieve complete IP reputation data including aggregated feed info';

-- Function: Calculate weighted reputation score
CREATE OR REPLACE FUNCTION calculate_ip_reputation_score(target_ip_id BIGINT)
RETURNS INTEGER AS $$
DECLARE
    weighted_score DECIMAL;
    total_weight DECIMAL;
    final_score INTEGER;
BEGIN
    -- Calculate weighted average based on feed priority and confidence
    SELECT 
        COALESCE(SUM(s.reported_score * f.priority * s.feed_confidence), 0),
        COALESCE(SUM(f.priority * s.feed_confidence), 1)
    INTO weighted_score, total_weight
    FROM ip_reputation_sources s
    JOIN threat_feeds f ON f.feed_id = s.feed_id
    WHERE s.ip_id = target_ip_id 
      AND (s.expires_at IS NULL OR s.expires_at > NOW());
    
    final_score := ROUND(weighted_score / total_weight)::INTEGER;
    
    -- Ensure score stays within bounds
    RETURN GREATEST(-100, LEAST(100, final_score));
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION calculate_ip_reputation_score IS 'Calculate weighted average reputation score from all active feed reports';

-- Function: Check if IP is in whitelist (including CIDR ranges)
CREATE OR REPLACE FUNCTION is_ip_whitelisted(search_ip INET)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM ip_whitelist
        WHERE enabled = true 
          AND (expires_at IS NULL OR expires_at > NOW())
          AND search_ip <<= ip_address
    );
END;
$$ LANGUAGE plpgsql;

-- Function: Check if IP is in blacklist (including CIDR ranges)
CREATE OR REPLACE FUNCTION is_ip_blacklisted(search_ip INET)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM ip_blacklist
        WHERE enabled = true 
          AND (expires_at IS NULL OR expires_at > NOW())
          AND search_ip <<= ip_address
    );
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- MAINTENANCE FUNCTIONS
-- =============================================================================

-- Function: Clean up expired entries
CREATE OR REPLACE FUNCTION cleanup_expired_ip_data()
RETURNS TABLE (
    expired_sources INTEGER,
    expired_whitelist INTEGER,
    expired_blacklist INTEGER
) AS $$
DECLARE
    src_count INTEGER;
    wl_count INTEGER;
    bl_count INTEGER;
BEGIN
    -- Clean expired feed reports
    DELETE FROM ip_reputation_sources WHERE expires_at < NOW();
    GET DIAGNOSTICS src_count = ROW_COUNT;
    
    -- Clean expired whitelist entries
    DELETE FROM ip_whitelist WHERE expires_at < NOW();
    GET DIAGNOSTICS wl_count = ROW_COUNT;
    
    -- Clean expired blacklist entries
    DELETE FROM ip_blacklist WHERE expires_at < NOW();
    GET DIAGNOSTICS bl_count = ROW_COUNT;
    
    RETURN QUERY SELECT src_count, wl_count, bl_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_ip_data IS 'Remove expired entries from sources, whitelist, and blacklist';

-- =============================================================================
-- VERIFICATION
-- =============================================================================

DO $$
DECLARE
    table_count INTEGER;
    index_count INTEGER;
    trigger_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO table_count FROM information_schema.tables 
    WHERE table_schema = 'public' 
      AND table_name LIKE 'ip_%';
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public' 
      AND tablename LIKE 'ip_%';
    
    SELECT COUNT(*) INTO trigger_count FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE c.relname LIKE 'ip_%';
    
    RAISE NOTICE '=== IP Reputation Schema Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Triggers created: %', trigger_count;
    RAISE NOTICE 'GiST indexes enabled for CIDR range matching';
    RAISE NOTICE 'History table partitioned by month';
END $$;
