-- ============================================================================
-- SafeOps Threat Intelligence Database - Domain Reputation
-- File: 003_domain_reputation.sql
-- Purpose: Domain name reputation scoring, DNS filtering, and threat detection
-- ============================================================================

-- =============================================================================
-- CORE TABLE: domain_reputation
-- =============================================================================

CREATE TABLE domain_reputation (
    domain_id BIGSERIAL PRIMARY KEY,
    domain_name CITEXT NOT NULL UNIQUE,
    domain_tld CITEXT,
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence_level BETWEEN 0.00 AND 1.00),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    total_reports INTEGER DEFAULT 0,
    dns_query_count BIGINT DEFAULT 0,
    is_whitelisted BOOLEAN DEFAULT false,
    is_blacklisted BOOLEAN DEFAULT false,
    is_sinkholed BOOLEAN DEFAULT false,
    parent_domain_id BIGINT,
    threat_category_id INTEGER,
    registrar VARCHAR(255),
    registration_date DATE,
    expiration_date DATE,
    nameservers TEXT[],
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT check_not_both_domain_lists CHECK (NOT (is_whitelisted = true AND is_blacklisted = true)),
    CONSTRAINT check_domain_dates CHECK (expiration_date IS NULL OR registration_date IS NULL OR expiration_date >= registration_date),
    
    -- Foreign keys
    FOREIGN KEY (parent_domain_id) REFERENCES domain_reputation(domain_id) ON DELETE SET NULL,
    FOREIGN KEY (threat_category_id) REFERENCES threat_categories(category_id) ON DELETE SET NULL
);

-- Indexes for domain_reputation
CREATE UNIQUE INDEX idx_domain_reputation_name ON domain_reputation(domain_name);
CREATE INDEX idx_domain_reputation_score ON domain_reputation(reputation_score);
CREATE INDEX idx_domain_reputation_last_seen_score ON domain_reputation(last_seen, reputation_score);
CREATE INDEX idx_domain_reputation_tld ON domain_reputation(domain_tld);
CREATE INDEX idx_domain_reputation_parent ON domain_reputation(parent_domain_id);
CREATE INDEX idx_domain_reputation_overrides ON domain_reputation(is_whitelisted, is_blacklisted);
CREATE INDEX idx_domain_reputation_category ON domain_reputation(threat_category_id);
CREATE INDEX idx_domain_reputation_trgm ON domain_reputation USING gin(domain_name gin_trgm_ops);
CREATE INDEX idx_domain_reputation_query_count ON domain_reputation(dns_query_count DESC);
CREATE INDEX idx_domain_reputation_nameservers ON domain_reputation USING gin(nameservers);

COMMENT ON TABLE domain_reputation IS 'Primary table storing current reputation scores for domain names';
COMMENT ON COLUMN domain_reputation.domain_name IS 'Fully qualified domain name (case-insensitive via CITEXT)';
COMMENT ON COLUMN domain_reputation.reputation_score IS 'Current reputation score (-100=malicious to +100=benign)';
COMMENT ON COLUMN domain_reputation.dns_query_count IS 'Number of DNS queries for this domain';
COMMENT ON COLUMN domain_reputation.parent_domain_id IS 'Self-referencing for subdomain hierarchy';

-- =============================================================================
-- TABLE: domain_reputation_sources
-- =============================================================================

CREATE TABLE domain_reputation_sources (
    source_id BIGSERIAL PRIMARY KEY,
    domain_id BIGINT NOT NULL,
    feed_id INTEGER NOT NULL,
    reported_score INTEGER NOT NULL CHECK (reported_score BETWEEN -100 AND 100),
    feed_confidence DECIMAL(3,2) DEFAULT 0.50 CHECK (feed_confidence BETWEEN 0.00 AND 1.00),
    report_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_types TEXT[],
    associated_ips INET[],
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (domain_id) REFERENCES domain_reputation(domain_id) ON DELETE CASCADE,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE,
    
    -- Prevent duplicate feed reports for same domain
    CONSTRAINT unique_domain_feed UNIQUE (domain_id, feed_id)
);

-- Indexes for domain_reputation_sources
CREATE INDEX idx_domain_rep_sources_domain ON domain_reputation_sources(domain_id);
CREATE INDEX idx_domain_rep_sources_feed ON domain_reputation_sources(feed_id);
CREATE INDEX idx_domain_rep_sources_timestamp ON domain_reputation_sources(report_timestamp);
CREATE INDEX idx_domain_rep_sources_expires ON domain_reputation_sources(expires_at);
CREATE INDEX idx_domain_rep_sources_threat_types ON domain_reputation_sources USING gin(threat_types);
CREATE INDEX idx_domain_rep_sources_ips ON domain_reputation_sources USING gin(associated_ips);
CREATE INDEX idx_domain_rep_sources_metadata ON domain_reputation_sources USING gin(metadata);

COMMENT ON TABLE domain_reputation_sources IS 'Many-to-many relationship tracking which feeds reported which domains';
COMMENT ON COLUMN domain_reputation_sources.associated_ips IS 'Array of IPs resolved for this domain';

-- =============================================================================
-- TABLE: domain_reputation_history (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE domain_reputation_history (
    history_id BIGSERIAL,
    domain_id BIGINT NOT NULL,
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
    FOREIGN KEY (domain_id) REFERENCES domain_reputation(domain_id) ON DELETE CASCADE,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE SET NULL
) PARTITION BY RANGE (changed_at);

-- Indexes for domain_reputation_history
CREATE INDEX idx_domain_rep_history_domain ON domain_reputation_history(domain_id);
CREATE INDEX idx_domain_rep_history_changed_at ON domain_reputation_history(changed_at);
CREATE INDEX idx_domain_rep_history_domain_time ON domain_reputation_history(domain_id, changed_at DESC);
CREATE INDEX idx_domain_rep_history_reason ON domain_reputation_history(change_reason);

COMMENT ON TABLE domain_reputation_history IS 'Time-series audit log of domain reputation changes (partitioned monthly)';

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
        partition_name := 'domain_reputation_history_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF domain_reputation_history
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: domain_whitelist
-- =============================================================================

CREATE TABLE domain_whitelist (
    whitelist_id SERIAL PRIMARY KEY,
    domain_pattern CITEXT NOT NULL UNIQUE,
    pattern_type VARCHAR(20) NOT NULL CHECK (pattern_type IN ('EXACT', 'WILDCARD', 'REGEX')),
    reason TEXT NOT NULL,
    added_by VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for domain_whitelist
CREATE UNIQUE INDEX idx_domain_whitelist_pattern ON domain_whitelist(domain_pattern);
CREATE INDEX idx_domain_whitelist_enabled ON domain_whitelist(enabled);
CREATE INDEX idx_domain_whitelist_expires ON domain_whitelist(expires_at);
CREATE INDEX idx_domain_whitelist_type ON domain_whitelist(pattern_type);

COMMENT ON TABLE domain_whitelist IS 'Trusted domains that should never be blocked';
COMMENT ON COLUMN domain_whitelist.domain_pattern IS 'Domain or pattern (supports wildcards: *.example.com)';
COMMENT ON COLUMN domain_whitelist.pattern_type IS 'Matching strategy: EXACT, WILDCARD, or REGEX';

-- =============================================================================
-- TABLE: domain_blacklist
-- =============================================================================

CREATE TABLE domain_blacklist (
    blacklist_id SERIAL PRIMARY KEY,
    domain_pattern CITEXT NOT NULL UNIQUE,
    pattern_type VARCHAR(20) NOT NULL CHECK (pattern_type IN ('EXACT', 'WILDCARD', 'REGEX')),
    reason TEXT NOT NULL,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 10),
    action VARCHAR(20) DEFAULT 'BLOCK' CHECK (action IN ('BLOCK', 'SINKHOLE', 'REDIRECT')),
    sinkhole_ip INET,
    added_by VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- If action is SINKHOLE, sinkhole_ip must be provided
    CONSTRAINT check_sinkhole_ip CHECK (action != 'SINKHOLE' OR sinkhole_ip IS NOT NULL)
);

-- Indexes for domain_blacklist
CREATE UNIQUE INDEX idx_domain_blacklist_pattern ON domain_blacklist(domain_pattern);
CREATE INDEX idx_domain_blacklist_enabled_severity ON domain_blacklist(enabled, severity DESC);
CREATE INDEX idx_domain_blacklist_expires ON domain_blacklist(expires_at);
CREATE INDEX idx_domain_blacklist_type ON domain_blacklist(pattern_type);
CREATE INDEX idx_domain_blacklist_action ON domain_blacklist(action);

COMMENT ON TABLE domain_blacklist IS 'Known malicious domains that should always be blocked';
COMMENT ON COLUMN domain_blacklist.action IS 'Action to take: BLOCK, SINKHOLE (redirect to sinkhole_ip), or REDIRECT';
COMMENT ON COLUMN domain_blacklist.sinkhole_ip IS 'IP address to return when action=SINKHOLE';

-- =============================================================================
-- TABLE: domain_dns_cache
-- =============================================================================

CREATE TABLE domain_dns_cache (
    cache_id BIGSERIAL PRIMARY KEY,
    domain_id BIGINT NOT NULL UNIQUE,
    resolved_ips INET[],
    ttl INTEGER,
    record_type VARCHAR(10),
    queried_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    query_count INTEGER DEFAULT 1,
    
    FOREIGN KEY (domain_id) REFERENCES domain_reputation(domain_id) ON DELETE CASCADE
);

-- Indexes for domain_dns_cache
CREATE UNIQUE INDEX idx_domain_dns_cache_domain ON domain_dns_cache(domain_id);
CREATE INDEX idx_domain_dns_cache_expires ON domain_dns_cache(expires_at);
CREATE INDEX idx_domain_dns_cache_ips ON domain_dns_cache USING gin(resolved_ips);

COMMENT ON TABLE domain_dns_cache IS 'Cache frequently queried domain resolutions for performance';
COMMENT ON COLUMN domain_dns_cache.ttl IS 'DNS TTL in seconds';
COMMENT ON COLUMN domain_dns_cache.expires_at IS 'Cache expiration (queried_at + ttl)';

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_domain_reputation_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_domain_reputation_updated
    BEFORE UPDATE ON domain_reputation
    FOR EACH ROW EXECUTE FUNCTION update_domain_reputation_updated_at();

CREATE TRIGGER trigger_domain_whitelist_updated
    BEFORE UPDATE ON domain_whitelist
    FOR EACH ROW EXECUTE FUNCTION update_domain_reputation_updated_at();

CREATE TRIGGER trigger_domain_blacklist_updated
    BEFORE UPDATE ON domain_blacklist
    FOR EACH ROW EXECUTE FUNCTION update_domain_reputation_updated_at();

-- Auto-extract TLD from domain name
CREATE OR REPLACE FUNCTION extract_domain_tld()
RETURNS TRIGGER AS $$
BEGIN
    -- Extract TLD (everything after last dot)
    NEW.domain_tld := substring(NEW.domain_name from '[^.]+$');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_extract_tld
    BEFORE INSERT OR UPDATE ON domain_reputation
    FOR EACH ROW EXECUTE FUNCTION extract_domain_tld();

-- Auto-log reputation score changes to history
CREATE OR REPLACE FUNCTION log_domain_reputation_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.reputation_score IS DISTINCT FROM NEW.reputation_score THEN
        INSERT INTO domain_reputation_history (
            domain_id, old_score, new_score, score_delta, 
            change_reason, changed_by, changed_at
        ) VALUES (
            NEW.domain_id, 
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

CREATE TRIGGER trigger_log_domain_reputation_change
    AFTER UPDATE ON domain_reputation
    FOR EACH ROW EXECUTE FUNCTION log_domain_reputation_change();

-- Auto-sync whitelist flag
CREATE OR REPLACE FUNCTION sync_domain_whitelist_flag()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE domain_reputation 
        SET is_whitelisted = true, updated_at = NOW()
        WHERE domain_name = NEW.domain_pattern;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE domain_reputation 
        SET is_whitelisted = false, updated_at = NOW()
        WHERE domain_name = OLD.domain_pattern;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_sync_domain_whitelist
    AFTER INSERT OR DELETE ON domain_whitelist
    FOR EACH ROW EXECUTE FUNCTION sync_domain_whitelist_flag();

-- Auto-sync blacklist flag
CREATE OR REPLACE FUNCTION sync_domain_blacklist_flag()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE domain_reputation 
        SET is_blacklisted = true, is_sinkholed = (NEW.action = 'SINKHOLE'), updated_at = NOW()
        WHERE domain_name = NEW.domain_pattern;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE domain_reputation 
        SET is_blacklisted = false, is_sinkholed = false, updated_at = NOW()
        WHERE domain_name = OLD.domain_pattern;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_sync_domain_blacklist
    AFTER INSERT OR DELETE ON domain_blacklist
    FOR EACH ROW EXECUTE FUNCTION sync_domain_blacklist_flag();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Get domain reputation with all related data
CREATE OR REPLACE FUNCTION get_domain_reputation(search_domain CITEXT)
RETURNS TABLE (
    domain_name CITEXT,
    reputation_score INTEGER,
    confidence_level DECIMAL,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    total_reports INTEGER,
    dns_query_count BIGINT,
    is_whitelisted BOOLEAN,
    is_blacklisted BOOLEAN,
    is_sinkholed BOOLEAN,
    parent_domain CITEXT,
    feed_count INTEGER,
    threat_types TEXT[]
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        r.domain_name,
        r.reputation_score,
        r.confidence_level,
        r.first_seen,
        r.last_seen,
        r.total_reports,
        r.dns_query_count,
        r.is_whitelisted,
        r.is_blacklisted,
        r.is_sinkholed,
        p.domain_name AS parent_domain,
        COUNT(DISTINCT s.feed_id)::INTEGER AS feed_count,
        ARRAY_AGG(DISTINCT unnest(s.threat_types)) AS threat_types
    FROM domain_reputation r
    LEFT JOIN domain_reputation p ON p.domain_id = r.parent_domain_id
    LEFT JOIN domain_reputation_sources s ON s.domain_id = r.domain_id
    WHERE r.domain_name = search_domain
    GROUP BY r.domain_id, r.domain_name, r.reputation_score, r.confidence_level, 
             r.first_seen, r.last_seen, r.total_reports, r.dns_query_count,
             r.is_whitelisted, r.is_blacklisted, r.is_sinkholed, p.domain_name;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_domain_reputation IS 'Retrieve complete domain reputation data including aggregated feed info';

-- Function: Check if domain matches whitelist (supports EXACT, WILDCARD, REGEX)
CREATE OR REPLACE FUNCTION is_domain_whitelisted(search_domain CITEXT)
RETURNS BOOLEAN AS $$
DECLARE
    wl RECORD;
BEGIN
    FOR wl IN 
        SELECT domain_pattern, pattern_type 
        FROM domain_whitelist 
        WHERE enabled = true 
          AND (expires_at IS NULL OR expires_at > NOW())
    LOOP
        CASE wl.pattern_type
            WHEN 'EXACT' THEN
                IF search_domain = wl.domain_pattern THEN
                    RETURN TRUE;
                END IF;
            WHEN 'WILDCARD' THEN
                -- Convert wildcard to regex: *.example.com -> ^.*\.example\.com$
                IF search_domain ~ ('^' || replace(replace(wl.domain_pattern, '.', '\.'), '*', '.*') || '$') THEN
                    RETURN TRUE;
                END IF;
            WHEN 'REGEX' THEN
                IF search_domain ~ wl.domain_pattern THEN
                    RETURN TRUE;
                END IF;
        END CASE;
    END LOOP;
    
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION is_domain_whitelisted IS 'Check if domain matches any whitelist pattern (EXACT, WILDCARD, or REGEX)';

-- Function: Check if domain matches blacklist
CREATE OR REPLACE FUNCTION is_domain_blacklisted(search_domain CITEXT)
RETURNS TABLE (
    is_blocked BOOLEAN,
    action VARCHAR(20),
    sinkhole_ip INET,
    severity INTEGER
) AS $$
DECLARE
    bl RECORD;
BEGIN
    FOR bl IN 
        SELECT domain_pattern, pattern_type, blacklist.action, blacklist.sinkhole_ip, blacklist.severity
        FROM domain_blacklist 
        WHERE enabled = true 
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY severity DESC
    LOOP
        CASE bl.pattern_type
            WHEN 'EXACT' THEN
                IF search_domain = bl.domain_pattern THEN
                    RETURN QUERY SELECT TRUE, bl.action, bl.sinkhole_ip, bl.severity;
                    RETURN;
                END IF;
            WHEN 'WILDCARD' THEN
                IF search_domain ~ ('^' || replace(replace(bl.domain_pattern, '.', '\.'), '*', '.*') || '$') THEN
                    RETURN QUERY SELECT TRUE, bl.action, bl.sinkhole_ip, bl.severity;
                    RETURN;
                END IF;
            WHEN 'REGEX' THEN
                IF search_domain ~ bl.domain_pattern THEN
                    RETURN QUERY SELECT TRUE, bl.action, bl.sinkhole_ip, bl.severity;
                    RETURN;
                END IF;
        END CASE;
    END LOOP;
    
    RETURN QUERY SELECT FALSE, NULL::VARCHAR(20), NULL::INET, NULL::INTEGER;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION is_domain_blacklisted IS 'Check if domain matches any blacklist pattern, returns action and sinkhole IP';

-- Function: Find similar domains (typosquatting detection)
CREATE OR REPLACE FUNCTION find_similar_domains(search_domain CITEXT, similarity_threshold REAL DEFAULT 0.3)
RETURNS TABLE (
    domain_name CITEXT,
    similarity_score REAL,
    reputation_score INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        r.domain_name,
        similarity(r.domain_name::TEXT, search_domain::TEXT) AS sim_score,
        r.reputation_score
    FROM domain_reputation r
    WHERE similarity(r.domain_name::TEXT, search_domain::TEXT) > similarity_threshold
      AND r.domain_name != search_domain
    ORDER BY sim_score DESC
    LIMIT 10;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION find_similar_domains IS 'Find domains similar to input using trigram similarity (typosquatting detection)';

-- Function: Update DNS query count
CREATE OR REPLACE FUNCTION increment_dns_query_count(search_domain CITEXT)
RETURNS VOID AS $$
BEGIN
    UPDATE domain_reputation 
    SET dns_query_count = dns_query_count + 1,
        last_seen = NOW()
    WHERE domain_name = search_domain;
END;
$$ LANGUAGE plpgsql;

-- Function: Clean up expired entries
CREATE OR REPLACE FUNCTION cleanup_expired_domain_data()
RETURNS TABLE (
    expired_sources INTEGER,
    expired_whitelist INTEGER,
    expired_blacklist INTEGER,
    expired_cache INTEGER
) AS $$
DECLARE
    src_count INTEGER;
    wl_count INTEGER;
    bl_count INTEGER;
    cache_count INTEGER;
BEGIN
    DELETE FROM domain_reputation_sources WHERE expires_at < NOW();
    GET DIAGNOSTICS src_count = ROW_COUNT;
    
    DELETE FROM domain_whitelist WHERE expires_at < NOW();
    GET DIAGNOSTICS wl_count = ROW_COUNT;
    
    DELETE FROM domain_blacklist WHERE expires_at < NOW();
    GET DIAGNOSTICS bl_count = ROW_COUNT;
    
    DELETE FROM domain_dns_cache WHERE expires_at < NOW();
    GET DIAGNOSTICS cache_count = ROW_COUNT;
    
    RETURN QUERY SELECT src_count, wl_count, bl_count, cache_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_domain_data IS 'Remove expired entries from all domain-related tables';

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
      AND table_name LIKE 'domain_%';
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public' 
      AND tablename LIKE 'domain_%';
    
    SELECT COUNT(*) INTO trigger_count FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE c.relname LIKE 'domain_%';
    
    RAISE NOTICE '=== Domain Reputation Schema Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Triggers created: %', trigger_count;
    RAISE NOTICE 'Pattern matching: EXACT, WILDCARD, REGEX supported';
    RAISE NOTICE 'DNS cache enabled for performance';
    RAISE NOTICE 'Sinkhole support enabled for malicious domains';
END $$;
