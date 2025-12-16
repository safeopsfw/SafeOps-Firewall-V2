-- ============================================================================
-- SafeOps Threat Intelligence Database - IOC Storage
-- File: 005_ioc_storage.sql
-- Purpose: Indicators of Compromise storage with campaign tracking and STIX support
-- ============================================================================

-- =============================================================================
-- CORE TABLE: ioc_indicators
-- =============================================================================

CREATE TABLE ioc_indicators (
    ioc_id BIGSERIAL PRIMARY KEY,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN (
        'IP', 'DOMAIN', 'HASH', 'URL', 'EMAIL', 'FILENAME', 'REGISTRY_KEY', 
        'MUTEX', 'USER_AGENT', 'SSL_CERT_HASH', 'CVE', 'PDB_PATH', 'PIPE_NAME'
    )),
    ioc_value TEXT NOT NULL,
    ioc_value_normalized TEXT,
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence_level BETWEEN 0.00 AND 1.00),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    total_reports INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    threat_category_id INTEGER,
    severity INTEGER DEFAULT 5 CHECK (severity BETWEEN 1 AND 10),
    kill_chain_phase VARCHAR(50),
    description TEXT,
    context TEXT,
    tags TEXT[],
    related_cves TEXT[],
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (threat_category_id) REFERENCES threat_categories(category_id) ON DELETE SET NULL,
    
    -- Prevent duplicate IOCs
    CONSTRAINT unique_ioc UNIQUE (ioc_type, ioc_value_normalized)
);

-- Indexes for ioc_indicators
CREATE UNIQUE INDEX idx_ioc_indicators_type_value ON ioc_indicators(ioc_type, ioc_value_normalized);
CREATE INDEX idx_ioc_indicators_score ON ioc_indicators(reputation_score);
CREATE INDEX idx_ioc_indicators_last_seen_active ON ioc_indicators(last_seen, is_active);
CREATE INDEX idx_ioc_indicators_category ON ioc_indicators(threat_category_id);
CREATE INDEX idx_ioc_indicators_severity ON ioc_indicators(severity);
CREATE INDEX idx_ioc_indicators_kill_chain ON ioc_indicators(kill_chain_phase);
CREATE INDEX idx_ioc_indicators_tags ON ioc_indicators USING gin(tags);
CREATE INDEX idx_ioc_indicators_cves ON ioc_indicators USING gin(related_cves);

COMMENT ON TABLE ioc_indicators IS 'Primary table storing all types of indicators of compromise';
COMMENT ON COLUMN ioc_indicators.ioc_value_normalized IS 'Normalized form for matching (lowercase, trimmed)';
COMMENT ON COLUMN ioc_indicators.kill_chain_phase IS 'MITRE ATT&CK kill chain phase';

-- =============================================================================
-- TABLE: ioc_sources
-- =============================================================================

CREATE TABLE ioc_sources (
    source_id BIGSERIAL PRIMARY KEY,
    ioc_id BIGINT NOT NULL,
    feed_id INTEGER NOT NULL,
    reported_score INTEGER NOT NULL CHECK (reported_score BETWEEN -100 AND 100),
    feed_confidence DECIMAL(3,2) DEFAULT 0.50 CHECK (feed_confidence BETWEEN 0.00 AND 1.00),
    report_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threat_types TEXT[],
    stix_id VARCHAR(255),
    tlp_level VARCHAR(20) CHECK (tlp_level IN ('WHITE', 'GREEN', 'AMBER', 'RED')),
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE,
    
    CONSTRAINT unique_ioc_source UNIQUE (ioc_id, feed_id)
);

-- Indexes for ioc_sources
CREATE INDEX idx_ioc_sources_ioc ON ioc_sources(ioc_id);
CREATE INDEX idx_ioc_sources_feed ON ioc_sources(feed_id);
CREATE INDEX idx_ioc_sources_timestamp ON ioc_sources(report_timestamp);
CREATE INDEX idx_ioc_sources_stix ON ioc_sources(stix_id);
CREATE INDEX idx_ioc_sources_tlp ON ioc_sources(tlp_level);
CREATE INDEX idx_ioc_sources_expires ON ioc_sources(expires_at);
CREATE INDEX idx_ioc_sources_threat_types ON ioc_sources USING gin(threat_types);
CREATE INDEX idx_ioc_sources_metadata ON ioc_sources USING gin(metadata);

COMMENT ON TABLE ioc_sources IS 'Many-to-many relationship tracking which feeds reported which IOCs';
COMMENT ON COLUMN ioc_sources.stix_id IS 'STIX 2.x identifier for correlation';
COMMENT ON COLUMN ioc_sources.tlp_level IS 'Traffic Light Protocol: WHITE, GREEN, AMBER, RED';

-- =============================================================================
-- TABLE: ioc_campaigns
-- =============================================================================

CREATE TABLE ioc_campaigns (
    campaign_id SERIAL PRIMARY KEY,
    campaign_name VARCHAR(255) NOT NULL UNIQUE,
    campaign_alias TEXT[],
    description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    threat_actor VARCHAR(255),
    objective TEXT,
    targets TEXT[],
    ttps TEXT[],
    severity INTEGER DEFAULT 5 CHECK (severity BETWEEN 1 AND 10),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for ioc_campaigns
CREATE UNIQUE INDEX idx_ioc_campaigns_name ON ioc_campaigns(campaign_name);
CREATE INDEX idx_ioc_campaigns_active ON ioc_campaigns(is_active);
CREATE INDEX idx_ioc_campaigns_actor ON ioc_campaigns(threat_actor);
CREATE INDEX idx_ioc_campaigns_severity ON ioc_campaigns(severity);
CREATE INDEX idx_ioc_campaigns_alias ON ioc_campaigns USING gin(campaign_alias);
CREATE INDEX idx_ioc_campaigns_targets ON ioc_campaigns USING gin(targets);
CREATE INDEX idx_ioc_campaigns_ttps ON ioc_campaigns USING gin(ttps);
CREATE INDEX idx_ioc_campaigns_metadata ON ioc_campaigns USING gin(metadata);

COMMENT ON TABLE ioc_campaigns IS 'Track threat campaigns and operations';
COMMENT ON COLUMN ioc_campaigns.ttps IS 'Array of MITRE ATT&CK TTP IDs';
COMMENT ON COLUMN ioc_campaigns.targets IS 'Array of targeted sectors/countries';

-- =============================================================================
-- TABLE: ioc_campaign_associations
-- =============================================================================

CREATE TABLE ioc_campaign_associations (
    association_id BIGSERIAL PRIMARY KEY,
    ioc_id BIGINT NOT NULL,
    campaign_id INTEGER NOT NULL,
    role VARCHAR(50) CHECK (role IN (
        'INFRASTRUCTURE', 'PAYLOAD', 'C2', 'EXFILTRATION', 'DELIVERY', 
        'RECONNAISSANCE', 'WEAPONIZATION'
    )),
    confidence DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence BETWEEN 0.00 AND 1.00),
    first_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_observed TIMESTAMP WITH TIME ZONE,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE,
    FOREIGN KEY (campaign_id) REFERENCES ioc_campaigns(campaign_id) ON DELETE CASCADE,
    
    CONSTRAINT unique_ioc_campaign UNIQUE (ioc_id, campaign_id)
);

-- Indexes for ioc_campaign_associations
CREATE INDEX idx_ioc_campaign_assoc_ioc ON ioc_campaign_associations(ioc_id);
CREATE INDEX idx_ioc_campaign_assoc_campaign ON ioc_campaign_associations(campaign_id);
CREATE INDEX idx_ioc_campaign_assoc_role ON ioc_campaign_associations(role);
CREATE INDEX idx_ioc_campaign_assoc_confidence ON ioc_campaign_associations(confidence);

COMMENT ON TABLE ioc_campaign_associations IS 'Many-to-many relationship linking IOCs to campaigns';
COMMENT ON COLUMN ioc_campaign_associations.role IS 'IOC role: INFRASTRUCTURE, PAYLOAD, C2, etc.';

-- =============================================================================
-- TABLE: ioc_relationships
-- =============================================================================

CREATE TABLE ioc_relationships (
    relationship_id BIGSERIAL PRIMARY KEY,
    source_ioc_id BIGINT NOT NULL,
    target_ioc_id BIGINT NOT NULL,
    relationship_type VARCHAR(50) NOT NULL CHECK (relationship_type IN (
        'RESOLVES_TO', 'DOWNLOADS_FROM', 'COMMUNICATES_WITH', 'DROPS', 
        'SIMILAR_TO', 'PART_OF', 'USES', 'EXPLOITS'
    )),
    confidence DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence BETWEEN 0.00 AND 1.00),
    first_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_observed TIMESTAMP WITH TIME ZONE,
    observation_count INTEGER DEFAULT 1,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (source_ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE,
    FOREIGN KEY (target_ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE,
    
    CONSTRAINT unique_ioc_relationship UNIQUE (source_ioc_id, target_ioc_id, relationship_type),
    CONSTRAINT prevent_self_reference CHECK (source_ioc_id != target_ioc_id)
);

-- Indexes for ioc_relationships
CREATE INDEX idx_ioc_relationships_source ON ioc_relationships(source_ioc_id);
CREATE INDEX idx_ioc_relationships_target ON ioc_relationships(target_ioc_id);
CREATE INDEX idx_ioc_relationships_type ON ioc_relationships(relationship_type);
CREATE INDEX idx_ioc_relationships_metadata ON ioc_relationships USING gin(metadata);

COMMENT ON TABLE ioc_relationships IS 'Track relationships between different IOCs';
COMMENT ON COLUMN ioc_relationships.relationship_type IS 'RESOLVES_TO, DOWNLOADS_FROM, COMMUNICATES_WITH, etc.';

-- =============================================================================
-- TABLE: ioc_sightings (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE ioc_sightings (
    sighting_id BIGSERIAL,
    ioc_id BIGINT NOT NULL,
    sighted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    sighted_by VARCHAR(100),
    source_ip INET,
    destination_ip INET,
    protocol VARCHAR(20),
    action_taken VARCHAR(50) CHECK (action_taken IN (
        'BLOCKED', 'ALERTED', 'LOGGED', 'ALLOWED', 'QUARANTINED'
    )),
    severity INTEGER CHECK (severity BETWEEN 1 AND 10),
    context TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (sighting_id, sighted_at),
    FOREIGN KEY (ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE
) PARTITION BY RANGE (sighted_at);

-- Indexes for ioc_sightings
CREATE INDEX idx_ioc_sightings_ioc ON ioc_sightings(ioc_id);
CREATE INDEX idx_ioc_sightings_sighted_at ON ioc_sightings(sighted_at);
CREATE INDEX idx_ioc_sightings_by ON ioc_sightings(sighted_by);
CREATE INDEX idx_ioc_sightings_source_ip ON ioc_sightings(source_ip);
CREATE INDEX idx_ioc_sightings_action ON ioc_sightings(action_taken);
CREATE INDEX idx_ioc_sightings_severity ON ioc_sightings(severity);
CREATE INDEX idx_ioc_sightings_metadata ON ioc_sightings USING gin(metadata);

COMMENT ON TABLE ioc_sightings IS 'Track real-world sightings/detections of IOCs (partitioned monthly)';
COMMENT ON COLUMN ioc_sightings.action_taken IS 'Action: BLOCKED, ALERTED, LOGGED, ALLOWED, QUARANTINED';

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
        partition_name := 'ioc_sightings_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF ioc_sightings
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_ioc_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_ioc_indicators_updated
    BEFORE UPDATE ON ioc_indicators
    FOR EACH ROW EXECUTE FUNCTION update_ioc_updated_at();

CREATE TRIGGER trigger_ioc_campaigns_updated
    BEFORE UPDATE ON ioc_campaigns
    FOR EACH ROW EXECUTE FUNCTION update_ioc_updated_at();

-- Auto-normalize IOC values
CREATE OR REPLACE FUNCTION normalize_ioc_value()
RETURNS TRIGGER AS $$
BEGIN
    -- Normalize to lowercase and trim whitespace
    NEW.ioc_value_normalized := lower(trim(NEW.ioc_value));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_normalize_ioc
    BEFORE INSERT OR UPDATE ON ioc_indicators
    FOR EACH ROW EXECUTE FUNCTION normalize_ioc_value();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Get IOC by type and value
CREATE OR REPLACE FUNCTION get_ioc(search_type VARCHAR(50), search_value TEXT)
RETURNS TABLE (
    ioc_id BIGINT,
    ioc_type VARCHAR(50),
    ioc_value TEXT,
    reputation_score INTEGER,
    confidence_level DECIMAL,
    is_active BOOLEAN,
    severity INTEGER,
    kill_chain_phase VARCHAR(50),
    tags TEXT[],
    feed_count INTEGER,
    campaign_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        i.ioc_id,
        i.ioc_type,
        i.ioc_value,
        i.reputation_score,
        i.confidence_level,
        i.is_active,
        i.severity,
        i.kill_chain_phase,
        i.tags,
        COUNT(DISTINCT s.feed_id)::INTEGER AS feed_count,
        COUNT(DISTINCT a.campaign_id)::INTEGER AS campaign_count
    FROM ioc_indicators i
    LEFT JOIN ioc_sources s ON s.ioc_id = i.ioc_id
    LEFT JOIN ioc_campaign_associations a ON a.ioc_id = i.ioc_id
    WHERE i.ioc_type = search_type 
      AND i.ioc_value_normalized = lower(trim(search_value))
    GROUP BY i.ioc_id, i.ioc_type, i.ioc_value, i.reputation_score, 
             i.confidence_level, i.is_active, i.severity, i.kill_chain_phase, i.tags;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_ioc IS 'Retrieve IOC with aggregated feed and campaign counts';

-- Function: Get IOCs by campaign
CREATE OR REPLACE FUNCTION get_campaign_iocs(search_campaign_id INTEGER)
RETURNS TABLE (
    ioc_id BIGINT,
    ioc_type VARCHAR(50),
    ioc_value TEXT,
    role VARCHAR(50),
    confidence DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        i.ioc_id,
        i.ioc_type,
        i.ioc_value,
        a.role,
        a.confidence
    FROM ioc_indicators i
    JOIN ioc_campaign_associations a ON a.ioc_id = i.ioc_id
    WHERE a.campaign_id = search_campaign_id
      AND i.is_active = true
    ORDER BY a.role, i.ioc_type;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_campaign_iocs IS 'Get all active IOCs associated with a campaign';

-- Function: Get related IOCs (via relationships)
CREATE OR REPLACE FUNCTION get_related_iocs(search_ioc_id BIGINT, max_depth INTEGER DEFAULT 2)
RETURNS TABLE (
    related_ioc_id BIGINT,
    ioc_type VARCHAR(50),
    ioc_value TEXT,
    relationship_type VARCHAR(50),
    depth INTEGER
) AS $$
WITH RECURSIVE ioc_tree AS (
    -- Base case
    SELECT 
        search_ioc_id AS ioc_id,
        0 AS depth
    
    UNION ALL
    
    -- Recursive case
    SELECT 
        r.target_ioc_id,
        it.depth + 1
    FROM ioc_tree it
    JOIN ioc_relationships r ON r.source_ioc_id = it.ioc_id
    WHERE it.depth < max_depth
)
SELECT 
    it.ioc_id,
    i.ioc_type,
    i.ioc_value,
    r.relationship_type,
    it.depth
FROM ioc_tree it
JOIN ioc_indicators i ON i.ioc_id = it.ioc_id
LEFT JOIN ioc_relationships r ON r.target_ioc_id = it.ioc_id
WHERE it.ioc_id != search_ioc_id
ORDER BY it.depth, i.ioc_type;
$$ LANGUAGE sql;

COMMENT ON FUNCTION get_related_iocs IS 'Get related IOCs via relationships (recursive traversal)';

-- Function: Record IOC sighting
CREATE OR REPLACE FUNCTION record_ioc_sighting(
    p_ioc_id BIGINT,
    p_sighted_by VARCHAR(100),
    p_source_ip INET DEFAULT NULL,
    p_action_taken VARCHAR(50) DEFAULT 'LOGGED',
    p_severity INTEGER DEFAULT 5
) RETURNS BIGINT AS $$
DECLARE
    v_sighting_id BIGINT;
BEGIN
    INSERT INTO ioc_sightings (
        ioc_id, sighted_by, source_ip, action_taken, severity
    ) VALUES (
        p_ioc_id, p_sighted_by, p_source_ip, p_action_taken, p_severity
    ) RETURNING sighting_id INTO v_sighting_id;
    
    -- Update last_seen in IOC table
    UPDATE ioc_indicators 
    SET last_seen = NOW(), total_reports = total_reports + 1
    WHERE ioc_id = p_ioc_id;
    
    RETURN v_sighting_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION record_ioc_sighting IS 'Record a new IOC sighting and update last_seen timestamp';

-- Function: Clean up expired IOCs
CREATE OR REPLACE FUNCTION cleanup_expired_iocs()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    -- Mark IOCs as inactive if all sources have expired
    UPDATE ioc_indicators i
    SET is_active = false, updated_at = NOW()
    WHERE i.is_active = true
      AND NOT EXISTS (
          SELECT 1 FROM ioc_sources s 
          WHERE s.ioc_id = i.ioc_id 
            AND (s.expires_at IS NULL OR s.expires_at > NOW())
      );
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    
    -- Delete expired source records
    DELETE FROM ioc_sources WHERE expires_at < NOW();
    
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_iocs IS 'Mark IOCs as inactive when all sources have expired';

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
      AND table_name LIKE 'ioc_%';
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public' 
      AND tablename LIKE 'ioc_%';
    
    SELECT COUNT(*) INTO trigger_count FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE c.relname LIKE 'ioc_%';
    
    RAISE NOTICE '=== IOC Storage Schema Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Triggers created: %', trigger_count;
    RAISE NOTICE 'IOC types supported: 13 (IP, DOMAIN, HASH, URL, EMAIL, etc.)';
    RAISE NOTICE 'Campaign tracking enabled';
    RAISE NOTICE 'STIX/TAXII support enabled';
    RAISE NOTICE 'Sightings partitioned by month';
END $$;
