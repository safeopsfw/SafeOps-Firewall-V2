-- ============================================================================
-- SafeOps Threat Intelligence Database - Hash Reputation
-- File: 004_hash_reputation.sql
-- Purpose: File hash reputation scoring, malware detection, and file analysis
-- ============================================================================

-- =============================================================================
-- CORE TABLE: hash_reputation
-- =============================================================================

CREATE TABLE hash_reputation (
    hash_id BIGSERIAL PRIMARY KEY,
    md5_hash CHAR(32),
    sha1_hash CHAR(40),
    sha256_hash CHAR(64) NOT NULL UNIQUE,
    sha512_hash CHAR(128),
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence_level BETWEEN 0.00 AND 1.00),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    total_reports INTEGER DEFAULT 0,
    file_size BIGINT CHECK (file_size >= 0),
    file_type VARCHAR(100),
    mime_type VARCHAR(255),
    file_name TEXT,
    is_whitelisted BOOLEAN DEFAULT false,
    is_blacklisted BOOLEAN DEFAULT false,
    threat_category_id INTEGER,
    malware_family VARCHAR(255),
    signature_match TEXT[],
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT check_not_both_hash_lists CHECK (NOT (is_whitelisted = true AND is_blacklisted = true)),
    CONSTRAINT check_hash_lowercase_md5 CHECK (md5_hash IS NULL OR md5_hash = lower(md5_hash)),
    CONSTRAINT check_hash_lowercase_sha1 CHECK (sha1_hash IS NULL OR sha1_hash = lower(sha1_hash)),
    CONSTRAINT check_hash_lowercase_sha256 CHECK (sha256_hash = lower(sha256_hash)),
    CONSTRAINT check_hash_lowercase_sha512 CHECK (sha512_hash IS NULL OR sha512_hash = lower(sha512_hash)),
    
    -- Foreign keys
    FOREIGN KEY (threat_category_id) REFERENCES threat_categories(category_id) ON DELETE SET NULL
);

-- Indexes for hash_reputation
CREATE UNIQUE INDEX idx_hash_reputation_sha256 ON hash_reputation(sha256_hash);
CREATE INDEX idx_hash_reputation_md5 ON hash_reputation(md5_hash);
CREATE INDEX idx_hash_reputation_sha1 ON hash_reputation(sha1_hash);
CREATE INDEX idx_hash_reputation_sha512 ON hash_reputation(sha512_hash);
CREATE INDEX idx_hash_reputation_score ON hash_reputation(reputation_score);
CREATE INDEX idx_hash_reputation_last_seen_score ON hash_reputation(last_seen, reputation_score);
CREATE INDEX idx_hash_reputation_file_type ON hash_reputation(file_type);
CREATE INDEX idx_hash_reputation_overrides ON hash_reputation(is_whitelisted, is_blacklisted);
CREATE INDEX idx_hash_reputation_category ON hash_reputation(threat_category_id);
CREATE INDEX idx_hash_reputation_family ON hash_reputation(malware_family);
CREATE INDEX idx_hash_reputation_signatures ON hash_reputation USING gin(signature_match);

COMMENT ON TABLE hash_reputation IS 'Primary table storing reputation scores for file hashes';
COMMENT ON COLUMN hash_reputation.sha256_hash IS 'SHA256 hash - primary identifier (lowercase hex)';
COMMENT ON COLUMN hash_reputation.reputation_score IS 'Current reputation score (-100=malicious to +100=benign)';
COMMENT ON COLUMN hash_reputation.file_size IS 'File size in bytes';

-- =============================================================================
-- TABLE: hash_reputation_sources
-- =============================================================================

CREATE TABLE hash_reputation_sources (
    source_id BIGSERIAL PRIMARY KEY,
    hash_id BIGINT NOT NULL,
    feed_id INTEGER NOT NULL,
    reported_score INTEGER NOT NULL CHECK (reported_score BETWEEN -100 AND 100),
    feed_confidence DECIMAL(3,2) DEFAULT 0.50 CHECK (feed_confidence BETWEEN 0.00 AND 1.00),
    report_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_types TEXT[],
    detection_names TEXT[],
    submission_source VARCHAR(100),
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (hash_id) REFERENCES hash_reputation(hash_id) ON DELETE CASCADE,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE,
    
    -- Prevent duplicate feed reports for same hash
    CONSTRAINT unique_hash_feed UNIQUE (hash_id, feed_id)
);

-- Indexes for hash_reputation_sources
CREATE INDEX idx_hash_rep_sources_hash ON hash_reputation_sources(hash_id);
CREATE INDEX idx_hash_rep_sources_feed ON hash_reputation_sources(feed_id);
CREATE INDEX idx_hash_rep_sources_timestamp ON hash_reputation_sources(report_timestamp);
CREATE INDEX idx_hash_rep_sources_expires ON hash_reputation_sources(expires_at);
CREATE INDEX idx_hash_rep_sources_threat_types ON hash_reputation_sources USING gin(threat_types);
CREATE INDEX idx_hash_rep_sources_detections ON hash_reputation_sources USING gin(detection_names);
CREATE INDEX idx_hash_rep_sources_metadata ON hash_reputation_sources USING gin(metadata);

COMMENT ON TABLE hash_reputation_sources IS 'Many-to-many relationship tracking which feeds reported which hashes';
COMMENT ON COLUMN hash_reputation_sources.detection_names IS 'Array of AV detection names from this feed';
COMMENT ON COLUMN hash_reputation_sources.submission_source IS 'Source: sandbox, AV, manual, automated';

-- =============================================================================
-- TABLE: hash_reputation_history (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE hash_reputation_history (
    history_id BIGSERIAL,
    hash_id BIGINT NOT NULL,
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
    FOREIGN KEY (hash_id) REFERENCES hash_reputation(hash_id) ON DELETE CASCADE,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE SET NULL
) PARTITION BY RANGE (changed_at);

-- Indexes for hash_reputation_history
CREATE INDEX idx_hash_rep_history_hash ON hash_reputation_history(hash_id);
CREATE INDEX idx_hash_rep_history_changed_at ON hash_reputation_history(changed_at);
CREATE INDEX idx_hash_rep_history_hash_time ON hash_reputation_history(hash_id, changed_at DESC);
CREATE INDEX idx_hash_rep_history_reason ON hash_reputation_history(change_reason);

COMMENT ON TABLE hash_reputation_history IS 'Time-series audit log of hash reputation changes (partitioned monthly)';

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
        partition_name := 'hash_reputation_history_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF hash_reputation_history
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: hash_whitelist
-- =============================================================================

CREATE TABLE hash_whitelist (
    whitelist_id SERIAL PRIMARY KEY,
    sha256_hash CHAR(64) NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    added_by VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT check_whitelist_hash_lowercase CHECK (sha256_hash = lower(sha256_hash))
);

-- Indexes for hash_whitelist
CREATE UNIQUE INDEX idx_hash_whitelist_sha256 ON hash_whitelist(sha256_hash);
CREATE INDEX idx_hash_whitelist_enabled ON hash_whitelist(enabled);
CREATE INDEX idx_hash_whitelist_expires ON hash_whitelist(expires_at);

COMMENT ON TABLE hash_whitelist IS 'Trusted file hashes that should never be blocked';

-- =============================================================================
-- TABLE: hash_blacklist
-- =============================================================================

CREATE TABLE hash_blacklist (
    blacklist_id SERIAL PRIMARY KEY,
    sha256_hash CHAR(64) NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 10),
    malware_family VARCHAR(255),
    added_by VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT check_blacklist_hash_lowercase CHECK (sha256_hash = lower(sha256_hash))
);

-- Indexes for hash_blacklist
CREATE UNIQUE INDEX idx_hash_blacklist_sha256 ON hash_blacklist(sha256_hash);
CREATE INDEX idx_hash_blacklist_enabled_severity ON hash_blacklist(enabled, severity DESC);
CREATE INDEX idx_hash_blacklist_expires ON hash_blacklist(expires_at);
CREATE INDEX idx_hash_blacklist_family ON hash_blacklist(malware_family);

COMMENT ON TABLE hash_blacklist IS 'Known malicious file hashes that should always be blocked';
COMMENT ON COLUMN hash_blacklist.severity IS 'Severity 1-10 (10=critical, 1=low)';

-- =============================================================================
-- TABLE: hash_file_relationships
-- =============================================================================

CREATE TABLE hash_file_relationships (
    relationship_id BIGSERIAL PRIMARY KEY,
    parent_hash_id BIGINT NOT NULL,
    child_hash_id BIGINT NOT NULL,
    relationship_type VARCHAR(50) NOT NULL CHECK (relationship_type IN (
        'DROPS', 'UNPACKS', 'DOWNLOADS', 'EXECUTES', 'LOADS', 'INJECTS'
    )),
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    discovered_by VARCHAR(100),
    metadata JSONB DEFAULT '{}',
    
    FOREIGN KEY (parent_hash_id) REFERENCES hash_reputation(hash_id) ON DELETE CASCADE,
    FOREIGN KEY (child_hash_id) REFERENCES hash_reputation(hash_id) ON DELETE CASCADE,
    
    CONSTRAINT unique_hash_relationship UNIQUE (parent_hash_id, child_hash_id, relationship_type),
    CONSTRAINT prevent_self_relationship CHECK (parent_hash_id != child_hash_id)
);

-- Indexes for hash_file_relationships
CREATE INDEX idx_hash_rel_parent ON hash_file_relationships(parent_hash_id);
CREATE INDEX idx_hash_rel_child ON hash_file_relationships(child_hash_id);
CREATE INDEX idx_hash_rel_type ON hash_file_relationships(relationship_type);
CREATE INDEX idx_hash_rel_metadata ON hash_file_relationships USING gin(metadata);

COMMENT ON TABLE hash_file_relationships IS 'Track relationships between files (droppers, payloads, etc.)';
COMMENT ON COLUMN hash_file_relationships.relationship_type IS 'DROPS=creates file, UNPACKS=extracts, DOWNLOADS=retrieves, EXECUTES=runs, LOADS=DLL, INJECTS=code injection';

-- =============================================================================
-- TABLE: hash_scan_results
-- =============================================================================

CREATE TABLE hash_scan_results (
    scan_id BIGSERIAL PRIMARY KEY,
    hash_id BIGINT NOT NULL,
    scan_engine VARCHAR(100) NOT NULL,
    detection_ratio VARCHAR(20),
    scan_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_malicious BOOLEAN,
    threat_names TEXT[],
    scan_report_url TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (hash_id) REFERENCES hash_reputation(hash_id) ON DELETE CASCADE
);

-- Indexes for hash_scan_results
CREATE INDEX idx_hash_scan_hash ON hash_scan_results(hash_id);
CREATE INDEX idx_hash_scan_engine ON hash_scan_results(scan_engine);
CREATE INDEX idx_hash_scan_date ON hash_scan_results(scan_date);
CREATE INDEX idx_hash_scan_malicious ON hash_scan_results(is_malicious);
CREATE INDEX idx_hash_scan_threat_names ON hash_scan_results USING gin(threat_names);
CREATE INDEX idx_hash_scan_metadata ON hash_scan_results USING gin(metadata);

COMMENT ON TABLE hash_scan_results IS 'Store results from antivirus and sandbox scans';
COMMENT ON COLUMN hash_scan_results.scan_engine IS 'Scanner name: VirusTotal, Cuckoo, Hybrid Analysis, etc.';
COMMENT ON COLUMN hash_scan_results.detection_ratio IS 'Format: "45/67" = 45 detections out of 67 engines';

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_hash_reputation_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_hash_reputation_updated
    BEFORE UPDATE ON hash_reputation
    FOR EACH ROW EXECUTE FUNCTION update_hash_reputation_updated_at();

CREATE TRIGGER trigger_hash_whitelist_updated
    BEFORE UPDATE ON hash_whitelist
    FOR EACH ROW EXECUTE FUNCTION update_hash_reputation_updated_at();

CREATE TRIGGER trigger_hash_blacklist_updated
    BEFORE UPDATE ON hash_blacklist
    FOR EACH ROW EXECUTE FUNCTION update_hash_reputation_updated_at();

-- Auto-log reputation score changes to history
CREATE OR REPLACE FUNCTION log_hash_reputation_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.reputation_score IS DISTINCT FROM NEW.reputation_score THEN
        INSERT INTO hash_reputation_history (
            hash_id, old_score, new_score, score_delta, 
            change_reason, changed_by, changed_at
        ) VALUES (
            NEW.hash_id, 
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

CREATE TRIGGER trigger_log_hash_reputation_change
    AFTER UPDATE ON hash_reputation
    FOR EACH ROW EXECUTE FUNCTION log_hash_reputation_change();

-- Auto-sync whitelist flag
CREATE OR REPLACE FUNCTION sync_hash_whitelist_flag()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE hash_reputation 
        SET is_whitelisted = true, updated_at = NOW()
        WHERE sha256_hash = NEW.sha256_hash;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE hash_reputation 
        SET is_whitelisted = false, updated_at = NOW()
        WHERE sha256_hash = OLD.sha256_hash;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_sync_hash_whitelist
    AFTER INSERT OR DELETE ON hash_whitelist
    FOR EACH ROW EXECUTE FUNCTION sync_hash_whitelist_flag();

-- Auto-sync blacklist flag
CREATE OR REPLACE FUNCTION sync_hash_blacklist_flag()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE hash_reputation 
        SET is_blacklisted = true, updated_at = NOW()
        WHERE sha256_hash = NEW.sha256_hash;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE hash_reputation 
        SET is_blacklisted = false, updated_at = NOW()
        WHERE sha256_hash = OLD.sha256_hash;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_sync_hash_blacklist
    AFTER INSERT OR DELETE ON hash_blacklist
    FOR EACH ROW EXECUTE FUNCTION sync_hash_blacklist_flag();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Lookup hash by any hash type
CREATE OR REPLACE FUNCTION get_hash_reputation(
    search_md5 CHAR(32) DEFAULT NULL,
    search_sha1 CHAR(40) DEFAULT NULL,
    search_sha256 CHAR(64) DEFAULT NULL,
    search_sha512 CHAR(128) DEFAULT NULL
) RETURNS TABLE (
    hash_id BIGINT,
    md5_hash CHAR(32),
    sha1_hash CHAR(40),
    sha256_hash CHAR(64),
    sha512_hash CHAR(128),
    reputation_score INTEGER,
    confidence_level DECIMAL,
    malware_family VARCHAR(255),
    is_whitelisted BOOLEAN,
    is_blacklisted BOOLEAN,
    file_type VARCHAR(100),
    feed_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        r.hash_id,
        r.md5_hash,
        r.sha1_hash,
        r.sha256_hash,
        r.sha512_hash,
        r.reputation_score,
        r.confidence_level,
        r.malware_family,
        r.is_whitelisted,
        r.is_blacklisted,
        r.file_type,
        COUNT(DISTINCT s.feed_id)::INTEGER AS feed_count
    FROM hash_reputation r
    LEFT JOIN hash_reputation_sources s ON s.hash_id = r.hash_id
    WHERE (search_md5 IS NULL OR r.md5_hash = lower(search_md5))
      AND (search_sha1 IS NULL OR r.sha1_hash = lower(search_sha1))
      AND (search_sha256 IS NULL OR r.sha256_hash = lower(search_sha256))
      AND (search_sha512 IS NULL OR r.sha512_hash = lower(search_sha512))
    GROUP BY r.hash_id, r.md5_hash, r.sha1_hash, r.sha256_hash, r.sha512_hash,
             r.reputation_score, r.confidence_level, r.malware_family,
             r.is_whitelisted, r.is_blacklisted, r.file_type;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_hash_reputation IS 'Lookup hash by any hash type (MD5, SHA1, SHA256, SHA512)';

-- Function: Check if hash is whitelisted
CREATE OR REPLACE FUNCTION is_hash_whitelisted(search_sha256 CHAR(64))
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM hash_whitelist
        WHERE enabled = true 
          AND (expires_at IS NULL OR expires_at > NOW())
          AND sha256_hash = lower(search_sha256)
    );
END;
$$ LANGUAGE plpgsql;

-- Function: Check if hash is blacklisted
CREATE OR REPLACE FUNCTION is_hash_blacklisted(search_sha256 CHAR(64))
RETURNS TABLE (
    is_blocked BOOLEAN,
    severity INTEGER,
    malware_family VARCHAR(255)
) AS $$
BEGIN
    RETURN QUERY
    SELECT TRUE, b.severity, b.malware_family
    FROM hash_blacklist b
    WHERE b.enabled = true 
      AND (b.expires_at IS NULL OR b.expires_at > NOW())
      AND b.sha256_hash = lower(search_sha256)
    ORDER BY b.severity DESC
    LIMIT 1;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::INTEGER, NULL::VARCHAR(255);
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function: Get related hashes (malware family, dropped files)
CREATE OR REPLACE FUNCTION get_related_hashes(search_hash_id BIGINT, max_depth INTEGER DEFAULT 2)
RETURNS TABLE (
    related_hash_id BIGINT,
    sha256_hash CHAR(64),
    relationship_type VARCHAR(50),
    depth INTEGER
) AS $$
WITH RECURSIVE hash_tree AS (
    -- Base case: the starting hash
    SELECT 
        search_hash_id AS hash_id,
        0 AS depth
    
    UNION ALL
    
    -- Recursive case: find related hashes
    SELECT 
        r.child_hash_id,
        ht.depth + 1
    FROM hash_tree ht
    JOIN hash_file_relationships r ON r.parent_hash_id = ht.hash_id
    WHERE ht.depth < max_depth
)
SELECT 
    ht.hash_id,
    hr.sha256_hash,
    r.relationship_type,
    ht.depth
FROM hash_tree ht
JOIN hash_reputation hr ON hr.hash_id = ht.hash_id
LEFT JOIN hash_file_relationships r ON r.child_hash_id = ht.hash_id
WHERE ht.hash_id != search_hash_id
ORDER BY ht.depth, hr.sha256_hash;
$$ LANGUAGE sql;

COMMENT ON FUNCTION get_related_hashes IS 'Get related hashes via file relationships (recursive, max_depth levels)';

-- Function: Clean up expired entries
CREATE OR REPLACE FUNCTION cleanup_expired_hash_data()
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
    DELETE FROM hash_reputation_sources WHERE expires_at < NOW();
    GET DIAGNOSTICS src_count = ROW_COUNT;
    
    DELETE FROM hash_whitelist WHERE expires_at < NOW();
    GET DIAGNOSTICS wl_count = ROW_COUNT;
    
    DELETE FROM hash_blacklist WHERE expires_at < NOW();
    GET DIAGNOSTICS bl_count = ROW_COUNT;
    
    RETURN QUERY SELECT src_count, wl_count, bl_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_hash_data IS 'Remove expired entries from hash-related tables';

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
      AND table_name LIKE 'hash_%';
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public' 
      AND tablename LIKE 'hash_%';
    
    SELECT COUNT(*) INTO trigger_count FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE c.relname LIKE 'hash_%';
    
    RAISE NOTICE '=== Hash Reputation Schema Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Triggers created: %', trigger_count;
    RAISE NOTICE 'Hash types supported: MD5, SHA1, SHA256 (primary), SHA512';
    RAISE NOTICE 'File relationships tracking enabled';
    RAISE NOTICE 'Scan results integration enabled';
END $$;
