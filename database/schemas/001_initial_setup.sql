-- ============================================================================
-- SafeOps Threat Intelligence Database - Initial Setup
-- File: 001_initial_setup.sql
-- Purpose: Foundation schema - database, extensions, core tables for threat feeds and IOC management
-- ============================================================================

-- =============================================================================
-- DATABASE CREATION (Run as postgres superuser)
-- =============================================================================

-- Create database with proper settings
CREATE DATABASE safeops_threat_intel
    WITH 
    OWNER = safeops_admin
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    CONNECTION LIMIT = -1
    TEMPLATE = template0;

COMMENT ON DATABASE safeops_threat_intel IS 'SafeOps Threat Intelligence Database - Core threat data and IOC management';

-- Connect to the new database
\c safeops_threat_intel;

-- =============================================================================
-- POSTGRESQL EXTENSIONS
-- =============================================================================

-- Extension 1: pg_trgm - Fast text search and fuzzy matching
CREATE EXTENSION IF NOT EXISTS pg_trgm;
COMMENT ON EXTENSION pg_trgm IS 'Trigram matching for domain similarity and pattern searches';

-- Extension 2: btree_gist - Advanced indexing for ranges
CREATE EXTENSION IF NOT EXISTS btree_gist;
COMMENT ON EXTENSION btree_gist IS 'B-tree over GiST for time ranges and exclusion constraints';

-- Extension 3: citext - Case-insensitive text
CREATE EXTENSION IF NOT EXISTS citext;
COMMENT ON EXTENSION citext IS 'Case-insensitive string comparisons for domains and hashes';

-- Extension 4: uuid-ossp - UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'UUID generation functions for record identifiers';

-- Extension 5: pgcrypto - Cryptographic functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
COMMENT ON EXTENSION pgcrypto IS 'Hashing and encryption for sensitive data';

-- =============================================================================
-- CORE TABLE: threat_feeds
-- =============================================================================

CREATE TABLE threat_feeds (
    feed_id SERIAL PRIMARY KEY,
    feed_name VARCHAR(255) NOT NULL UNIQUE,
    feed_url TEXT NOT NULL,
    feed_type VARCHAR(50) NOT NULL CHECK (feed_type IN ('IP', 'DOMAIN', 'HASH', 'URL', 'IOC_MIXED')),
    feed_format VARCHAR(50),
    enabled BOOLEAN DEFAULT true,
    update_interval INTEGER DEFAULT 3600 CHECK (update_interval >= 300),
    last_update TIMESTAMP WITH TIME ZONE,
    last_update_status VARCHAR(50),
    failure_count INTEGER DEFAULT 0,
    api_key_required BOOLEAN DEFAULT false,
    priority INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_threat_feeds_name ON threat_feeds(feed_name);
CREATE INDEX idx_threat_feeds_enabled_update ON threat_feeds(enabled, last_update);
CREATE INDEX idx_threat_feeds_type ON threat_feeds(feed_type);
CREATE INDEX idx_threat_feeds_priority ON threat_feeds(priority);

COMMENT ON TABLE threat_feeds IS 'Central registry of external threat intelligence feed sources';
COMMENT ON COLUMN threat_feeds.priority IS 'Feed priority for conflict resolution (1=highest, 10=lowest)';
COMMENT ON COLUMN threat_feeds.update_interval IS 'Update frequency in seconds (minimum 300 = 5 minutes)';

-- =============================================================================
-- CORE TABLE: threat_categories
-- =============================================================================

CREATE TABLE threat_categories (
    category_id SERIAL PRIMARY KEY,
    category_name VARCHAR(100) NOT NULL UNIQUE,
    category_description TEXT,
    severity_level INTEGER NOT NULL CHECK (severity_level BETWEEN 1 AND 10),
    parent_category_id INTEGER,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (parent_category_id) REFERENCES threat_categories(category_id)
);

CREATE INDEX idx_threat_categories_name ON threat_categories(category_name);
CREATE INDEX idx_threat_categories_parent ON threat_categories(parent_category_id);
CREATE INDEX idx_threat_categories_severity ON threat_categories(severity_level);

COMMENT ON TABLE threat_categories IS 'Classification taxonomy for threat types';
COMMENT ON COLUMN threat_categories.severity_level IS 'Severity score 1-10 (10=critical)';
COMMENT ON COLUMN threat_categories.parent_category_id IS 'Self-referencing for hierarchical categorization';

-- =============================================================================
-- CORE TABLE: update_history
-- =============================================================================

CREATE TABLE update_history (
    update_id SERIAL PRIMARY KEY,
    schema_file VARCHAR(255) NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    applied_by VARCHAR(100),
    status VARCHAR(50) NOT NULL CHECK (status IN ('SUCCESS', 'FAILED', 'ROLLED_BACK')),
    error_message TEXT,
    execution_time_ms INTEGER
);

CREATE INDEX idx_update_history_file ON update_history(schema_file);
CREATE INDEX idx_update_history_applied ON update_history(applied_at);

COMMENT ON TABLE update_history IS 'Audit log for database schema migrations and updates';

-- =============================================================================
-- CORE TABLE: system_config
-- =============================================================================

CREATE TABLE system_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT NOT NULL,
    value_type VARCHAR(20) NOT NULL CHECK (value_type IN ('STRING', 'INTEGER', 'BOOLEAN', 'JSON')),
    description TEXT,
    editable BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_system_config_editable ON system_config(editable);

COMMENT ON TABLE system_config IS 'System-wide configuration parameters for threat intelligence engine';

-- Insert default configuration
INSERT INTO system_config (config_key, config_value, value_type, description, editable) VALUES
('reputation.threshold.block', '-50', 'INTEGER', 'Minimum score to block', true),
('reputation.threshold.alert', '-25', 'INTEGER', 'Minimum score to alert', true),
('reputation.decay.enabled', 'true', 'BOOLEAN', 'Enable score decay over time', true),
('reputation.decay.days', '30', 'INTEGER', 'Days before scores start decaying', true),
('cache.ttl.seconds', '3600', 'INTEGER', 'Redis cache TTL', true);

-- =============================================================================
-- IOC TABLE: ioc_indicators
-- =============================================================================

CREATE TABLE ioc_indicators (
    ioc_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN (
        'IP', 'DOMAIN', 'URL', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'HASH_SHA512',
        'EMAIL', 'FILENAME', 'REGISTRY', 'MUTEX', 'CVE', 'YARA', 'JA3', 'JA3S', 'CERTIFICATE'
    )),
    ioc_value TEXT NOT NULL,
    ioc_value_normalized TEXT NOT NULL,
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level VARCHAR(20) DEFAULT 'LOW' CHECK (confidence_level IN ('HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    tlp_level VARCHAR(20) DEFAULT 'WHITE' CHECK (tlp_level IN ('WHITE', 'GREEN', 'AMBER', 'RED')),
    stix_id VARCHAR(255),
    mitre_attack_phase VARCHAR(100),
    related_cves TEXT[],
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expiration_date TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_ioc UNIQUE (ioc_type, ioc_value_normalized)
);

CREATE INDEX idx_ioc_indicators_type_value ON ioc_indicators(ioc_type, ioc_value_normalized);
CREATE INDEX idx_ioc_indicators_reputation ON ioc_indicators(reputation_score);
CREATE INDEX idx_ioc_indicators_active ON ioc_indicators(is_active);
CREATE INDEX idx_ioc_indicators_stix ON ioc_indicators(stix_id);
CREATE INDEX idx_ioc_indicators_tlp ON ioc_indicators(tlp_level);
CREATE INDEX idx_ioc_indicators_cves ON ioc_indicators USING gin(related_cves);
CREATE INDEX idx_ioc_indicators_metadata ON ioc_indicators USING gin(metadata);

COMMENT ON TABLE ioc_indicators IS 'Master IOC table with 15+ indicator types';
COMMENT ON COLUMN ioc_indicators.ioc_value_normalized IS 'Lowercase normalized value for case-insensitive matching';
COMMENT ON COLUMN ioc_indicators.reputation_score IS 'Score between -100 (malicious) and +100 (benign)';
COMMENT ON COLUMN ioc_indicators.stix_id IS 'STIX 2.x correlation identifier';

-- =============================================================================
-- IOC TABLE: ioc_sources
-- =============================================================================

CREATE TABLE ioc_sources (
    source_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_id UUID NOT NULL,
    feed_id INTEGER NOT NULL,
    raw_data JSONB,
    confidence_score INTEGER CHECK (confidence_score BETWEEN 0 AND 100),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(feed_id) ON DELETE CASCADE,
    CONSTRAINT unique_ioc_feed UNIQUE (ioc_id, feed_id)
);

CREATE INDEX idx_ioc_sources_ioc ON ioc_sources(ioc_id);
CREATE INDEX idx_ioc_sources_feed ON ioc_sources(feed_id);
CREATE INDEX idx_ioc_sources_raw ON ioc_sources USING gin(raw_data);

COMMENT ON TABLE ioc_sources IS 'Tracks which feeds contributed each IOC (prevents duplicates)';

-- =============================================================================
-- IOC TABLE: ioc_campaigns
-- =============================================================================

CREATE TABLE ioc_campaigns (
    campaign_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_name VARCHAR(255) NOT NULL UNIQUE,
    threat_actor VARCHAR(255),
    description TEXT,
    mitre_attack_tactics TEXT[],
    target_industries TEXT[],
    target_regions TEXT[],
    first_observed TIMESTAMP WITH TIME ZONE,
    last_observed TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_ioc_campaigns_name ON ioc_campaigns(campaign_name);
CREATE INDEX idx_ioc_campaigns_actor ON ioc_campaigns(threat_actor);
CREATE INDEX idx_ioc_campaigns_active ON ioc_campaigns(is_active);
CREATE INDEX idx_ioc_campaigns_tactics ON ioc_campaigns USING gin(mitre_attack_tactics);
CREATE INDEX idx_ioc_campaigns_industries ON ioc_campaigns USING gin(target_industries);
CREATE INDEX idx_ioc_campaigns_metadata ON ioc_campaigns USING gin(metadata);

COMMENT ON TABLE ioc_campaigns IS 'APT campaigns and threat actor attribution';

-- =============================================================================
-- IOC TABLE: ioc_campaign_associations
-- =============================================================================

CREATE TABLE ioc_campaign_associations (
    association_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_id UUID NOT NULL,
    campaign_id UUID NOT NULL,
    confidence_level VARCHAR(20) CHECK (confidence_level IN ('HIGH', 'MEDIUM', 'LOW')),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE,
    FOREIGN KEY (campaign_id) REFERENCES ioc_campaigns(campaign_id) ON DELETE CASCADE,
    CONSTRAINT unique_ioc_campaign UNIQUE (ioc_id, campaign_id)
);

CREATE INDEX idx_ioc_campaign_assoc_ioc ON ioc_campaign_associations(ioc_id);
CREATE INDEX idx_ioc_campaign_assoc_campaign ON ioc_campaign_associations(campaign_id);

COMMENT ON TABLE ioc_campaign_associations IS 'Links IOCs to threat campaigns';

-- =============================================================================
-- IOC TABLE: ioc_relationships
-- =============================================================================

CREATE TABLE ioc_relationships (
    relationship_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_ioc_id UUID NOT NULL,
    target_ioc_id UUID NOT NULL,
    relationship_type VARCHAR(50) NOT NULL CHECK (relationship_type IN (
        'RESOLVES_TO', 'DROPS', 'DOWNLOADS', 'CONTACTS', 'VARIANT_OF', 
        'RELATED_TO', 'COMMUNICATES_WITH', 'USES', 'TARGETS'
    )),
    confidence_level VARCHAR(20) CHECK (confidence_level IN ('HIGH', 'MEDIUM', 'LOW')),
    first_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (source_ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE,
    FOREIGN KEY (target_ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE,
    CONSTRAINT prevent_self_reference CHECK (source_ioc_id != target_ioc_id),
    CONSTRAINT unique_ioc_relationship UNIQUE (source_ioc_id, target_ioc_id, relationship_type)
);

CREATE INDEX idx_ioc_relationships_source ON ioc_relationships(source_ioc_id);
CREATE INDEX idx_ioc_relationships_target ON ioc_relationships(target_ioc_id);
CREATE INDEX idx_ioc_relationships_type ON ioc_relationships(relationship_type);

COMMENT ON TABLE ioc_relationships IS 'IOC connections (RESOLVES_TO, DROPS, etc.)';
COMMENT ON CONSTRAINT prevent_self_reference ON ioc_relationships IS 'Prevents IOC from referencing itself';

-- =============================================================================
-- IOC TABLE: ioc_sightings (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE ioc_sightings (
    sighting_id UUID DEFAULT uuid_generate_v4(),
    ioc_id UUID NOT NULL,
    sighting_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    source_system VARCHAR(100),
    source_ip INET,
    destination_ip INET,
    action_taken VARCHAR(50),
    severity VARCHAR(20),
    context JSONB DEFAULT '{}',
    PRIMARY KEY (sighting_id, sighting_timestamp),
    FOREIGN KEY (ioc_id) REFERENCES ioc_indicators(ioc_id) ON DELETE CASCADE
) PARTITION BY RANGE (sighting_timestamp);

CREATE INDEX idx_ioc_sightings_ioc ON ioc_sightings(ioc_id);
CREATE INDEX idx_ioc_sightings_timestamp ON ioc_sightings(sighting_timestamp);
CREATE INDEX idx_ioc_sightings_source_system ON ioc_sightings(source_system);
CREATE INDEX idx_ioc_sightings_context ON ioc_sightings USING gin(context);

COMMENT ON TABLE ioc_sightings IS 'Detection events - partitioned by month for scalability';

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
    END LOOP;
END $$;

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_threat_feeds_updated
    BEFORE UPDATE ON threat_feeds
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_threat_categories_updated
    BEFORE UPDATE ON threat_categories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_system_config_updated
    BEFORE UPDATE ON system_config
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_ioc_indicators_updated
    BEFORE UPDATE ON ioc_indicators
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_ioc_campaigns_updated
    BEFORE UPDATE ON ioc_campaigns
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Auto-normalize IOC values
CREATE OR REPLACE FUNCTION normalize_ioc_value()
RETURNS TRIGGER AS $$
BEGIN
    NEW.ioc_value_normalized = LOWER(TRIM(NEW.ioc_value));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_normalize_ioc
    BEFORE INSERT OR UPDATE ON ioc_indicators
    FOR EACH ROW EXECUTE FUNCTION normalize_ioc_value();

-- =============================================================================
-- INITIAL DATA
-- =============================================================================

-- Insert default threat categories
INSERT INTO threat_categories (category_name, category_description, severity_level) VALUES
('Malware C2', 'Command and Control infrastructure', 9),
('Phishing', 'Phishing campaigns and infrastructure', 8),
('Botnet', 'Botnet command servers and infected hosts', 9),
('Ransomware', 'Ransomware-related infrastructure', 10),
('DDoS', 'Distributed Denial of Service sources', 7),
('Scanner', 'Network scanning and reconnaissance', 5),
('Exploit Kit', 'Exploit kit delivery infrastructure', 8),
('APT', 'Advanced Persistent Threat activity', 10),
('Spam', 'Spam email sources', 4),
('Malvertising', 'Malicious advertising infrastructure', 6);

-- Record this schema installation
INSERT INTO update_history (schema_file, applied_by, status, execution_time_ms)
VALUES ('001_initial_setup.sql', current_user, 'SUCCESS', 
        EXTRACT(EPOCH FROM (NOW() - pg_postmaster_start_time()) * 1000)::INTEGER);

-- =============================================================================
-- VERIFICATION
-- =============================================================================

DO $$
DECLARE
    table_count INTEGER;
    index_count INTEGER;
    extension_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO table_count FROM information_schema.tables 
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public';
    
    SELECT COUNT(*) INTO extension_count FROM pg_extension 
    WHERE extname IN ('pg_trgm', 'btree_gist', 'citext', 'uuid-ossp', 'pgcrypto');
    
    RAISE NOTICE '=== SafeOps Threat Intel Database Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Extensions enabled: %', extension_count;
    RAISE NOTICE 'Database ready for threat intelligence ingestion';
END $$;
