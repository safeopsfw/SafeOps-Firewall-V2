-- ============================================================================
-- SafeOps v2.0 - Schema Patches for Threat Intel Pipeline
-- ============================================================================
-- Purpose: Fixes schema drift between database/schemas/ SQL files and what
--          the compiled threat_intel.exe binary expects.
-- Run after: All base schemas (001-021, users.sql)
-- Idempotent: Safe to run multiple times (uses IF NOT EXISTS, DO blocks)
-- ============================================================================

-- ============================================================================
-- PATCH 1: threat_feeds - add missing columns and widen constraints
-- ============================================================================

ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS parser_config JSONB;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS retry_config JSONB;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS authentication_required BOOLEAN DEFAULT FALSE;

-- Widen priority constraint from (1-10) to (0-100)
DO $$
BEGIN
    ALTER TABLE threat_feeds DROP CONSTRAINT IF EXISTS threat_feeds_priority_check;
    ALTER TABLE threat_feeds ADD CONSTRAINT threat_feeds_priority_check
        CHECK (priority >= 0 AND priority <= 100);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Widen feed_type constraint to include all types used by feed sources
DO $$
BEGIN
    ALTER TABLE threat_feeds DROP CONSTRAINT IF EXISTS threat_feeds_feed_type_check;
    ALTER TABLE threat_feeds ADD CONSTRAINT threat_feeds_feed_type_check
        CHECK (feed_type IN ('ip_blacklist', 'domain_blacklist', 'hash_list', 'mixed',
            'url_list', 'vpn', 'hash_malware', 'anonymization', 'geolocation', 'exploit'));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- ============================================================================
-- PATCH 2: system_metadata table (required by seed data)
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_metadata (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT,
    description TEXT,
    category VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- PATCH 3: ip_blacklist - add columns expected by threat_intel binary
-- ============================================================================

-- Add missing columns the Go BulkInsert expects
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS status VARCHAR(20);
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS reputation_score INTEGER;
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS threat_category VARCHAR(100);
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS malware_family VARCHAR(255);
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS false_positive_count INTEGER;
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS tags JSONB;
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS last_updated TIMESTAMP WITH TIME ZONE;

-- Relax NOT NULL constraints that block bulk inserts (processor doesn't always provide these)
DO $$
BEGIN
    ALTER TABLE ip_blacklist ALTER COLUMN threat_score DROP NOT NULL;
    ALTER TABLE ip_blacklist ALTER COLUMN abuse_type DROP NOT NULL;
    ALTER TABLE ip_blacklist ALTER COLUMN confidence DROP NOT NULL;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Set sensible defaults
ALTER TABLE ip_blacklist ALTER COLUMN threat_score SET DEFAULT 0;
ALTER TABLE ip_blacklist ALTER COLUMN confidence SET DEFAULT 0;
ALTER TABLE ip_blacklist ALTER COLUMN is_malicious SET DEFAULT TRUE;

-- Widen abuse_type constraint (Go binary uses 20 categories)
DO $$
BEGIN
    ALTER TABLE ip_blacklist DROP CONSTRAINT IF EXISTS ip_blacklist_abuse_type_check;
    ALTER TABLE ip_blacklist ADD CONSTRAINT ip_blacklist_abuse_type_check
        CHECK (abuse_type IN ('spam', 'malware', 'c2', 'bruteforce', 'botnet', 'scanner',
            'unknown', 'phishing', 'ransomware', 'dridex', 'emotet', 'trickbot',
            'exploitation', 'apt', 'ddos', 'tor', 'vpn', 'proxy', 'abuse', 'suspicious'));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- ============================================================================
-- PATCH 4: ip_anonymization - create full table (not in base schemas)
-- ============================================================================
-- The Go binary expects 27 columns. Base schemas only have vpn_ips table.
-- This creates ip_anonymization if it doesn't exist, or rebuilds if too few columns.

DO $$
DECLARE col_count INTEGER;
BEGIN
    -- Check if table exists and has correct column count
    SELECT COUNT(*) INTO col_count FROM information_schema.columns
    WHERE table_name = 'ip_anonymization' AND table_schema = 'public';

    IF col_count = 0 OR col_count < 27 THEN
        DROP TABLE IF EXISTS ip_anonymization CASCADE;
        CREATE TABLE ip_anonymization (
            id BIGSERIAL PRIMARY KEY,
            ip_address INET NOT NULL,
            is_vpn BOOLEAN DEFAULT FALSE,
            is_tor BOOLEAN DEFAULT FALSE,
            is_proxy BOOLEAN DEFAULT FALSE,
            is_datacenter BOOLEAN DEFAULT FALSE,
            is_relay BOOLEAN DEFAULT FALSE,
            is_hosting BOOLEAN DEFAULT FALSE,
            provider_name VARCHAR(255),
            service_type VARCHAR(50),
            anonymity_level VARCHAR(50),
            tor_exit_node BOOLEAN DEFAULT FALSE,
            tor_node_name VARCHAR(255),
            proxy_type VARCHAR(50),
            proxy_port INTEGER,
            datacenter_name VARCHAR(255),
            hosting_provider VARCHAR(255),
            country_code VARCHAR(2),
            city VARCHAR(100),
            risk_score INTEGER,
            abuse_history BOOLEAN DEFAULT FALSE,
            is_active BOOLEAN DEFAULT TRUE,
            sources JSONB,
            tags JSONB,
            first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_ip_anon_ip ON ip_anonymization(ip_address);
        CREATE INDEX IF NOT EXISTS idx_ip_anon_vpn ON ip_anonymization(is_vpn) WHERE is_vpn = TRUE;
        CREATE INDEX IF NOT EXISTS idx_ip_anon_tor ON ip_anonymization(is_tor) WHERE is_tor = TRUE;
        CREATE INDEX IF NOT EXISTS idx_ip_anon_proxy ON ip_anonymization(is_proxy) WHERE is_proxy = TRUE;
        CREATE INDEX IF NOT EXISTS idx_ip_anon_active ON ip_anonymization(is_active);
        CREATE INDEX IF NOT EXISTS idx_ip_anon_datacenter ON ip_anonymization(is_datacenter) WHERE is_datacenter = TRUE;
        CREATE INDEX IF NOT EXISTS idx_ip_anon_sources ON ip_anonymization USING GIN(sources);
    END IF;
END $$;

-- ============================================================================
-- PATCH 5: ip_geolocation - add ip_end, widen country_code and asn
-- ============================================================================

-- Add ip_end column for IP range lookups (IPtoASN data uses start/end ranges)
ALTER TABLE ip_geolocation ADD COLUMN IF NOT EXISTS ip_end INET;

-- Widen country_code from VARCHAR(2) to VARCHAR(10) for IPtoASN data
-- Must drop dependent views first
DO $$
DECLARE cc_len INTEGER;
BEGIN
    SELECT character_maximum_length INTO cc_len FROM information_schema.columns
    WHERE table_name = 'ip_geolocation' AND column_name = 'country_code';

    IF cc_len IS NOT NULL AND cc_len < 10 THEN
        DROP VIEW IF EXISTS country_ip_distribution CASCADE;
        DROP VIEW IF EXISTS top_asns CASCADE;
        DROP VIEW IF EXISTS mobile_networks CASCADE;
        DROP VIEW IF EXISTS datacenter_ips CASCADE;
        DROP VIEW IF EXISTS threat_summary_stats CASCADE;
        ALTER TABLE ip_geolocation ALTER COLUMN country_code TYPE VARCHAR(10);
    END IF;
END $$;

-- Widen asn from INTEGER to BIGINT (ASN numbers can exceed 2^31, e.g. 4230120000)
DO $$
DECLARE asn_type TEXT;
BEGIN
    SELECT data_type INTO asn_type FROM information_schema.columns
    WHERE table_name = 'ip_geolocation' AND column_name = 'asn';

    IF asn_type = 'integer' THEN
        DROP VIEW IF EXISTS country_ip_distribution CASCADE;
        DROP VIEW IF EXISTS top_asns CASCADE;
        DROP VIEW IF EXISTS mobile_networks CASCADE;
        DROP VIEW IF EXISTS datacenter_ips CASCADE;
        DROP VIEW IF EXISTS threat_summary_stats CASCADE;
        ALTER TABLE ip_geolocation ALTER COLUMN asn TYPE BIGINT;
    END IF;
END $$;

-- Also fix asn_info table if it exists
DO $$
DECLARE asn_type TEXT;
BEGIN
    SELECT data_type INTO asn_type FROM information_schema.columns
    WHERE table_name = 'asn_info' AND column_name = 'asn';

    IF asn_type = 'integer' THEN
        ALTER TABLE asn_info ALTER COLUMN asn TYPE BIGINT;
    END IF;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Drop UNIQUE constraint on ip_address that blocks range inserts
DO $$
BEGIN
    ALTER TABLE ip_geolocation DROP CONSTRAINT IF EXISTS ip_geolocation_ip_address_key;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- ============================================================================
-- PATCH 6: domains - add columns, widen category constraint
-- ============================================================================

ALTER TABLE domains ADD COLUMN IF NOT EXISTS subcategory VARCHAR(100);
ALTER TABLE domains ADD COLUMN IF NOT EXISTS tags JSONB;

-- Set default for threat_score
DO $$
BEGIN
    ALTER TABLE domains ALTER COLUMN threat_score SET DEFAULT 0;
    ALTER TABLE domains ALTER COLUMN reported_reason DROP NOT NULL;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Widen category constraint (Go binary uses 17 categories)
DO $$
BEGIN
    ALTER TABLE domains DROP CONSTRAINT IF EXISTS domains_category_check;
    ALTER TABLE domains ADD CONSTRAINT domains_category_check
        CHECK (category IN ('phishing', 'malware', 'c2', 'spam', 'exploit_kit', 'scam',
            'ransomware', 'unknown', 'adware', 'botnet', 'cryptomining', 'dga',
            'parking', 'suspicious', 'tor', 'vpn', 'proxy'));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- ============================================================================
-- PATCH 7: hashes table (Go binary expects "hashes" not "file_hashes")
-- ============================================================================
-- The base schema creates file_hashes with sha1 VARCHAR(40) and md5 VARCHAR(32).
-- The Go binary writes to table "hashes" and needs wider columns for cross-type storage.

CREATE TABLE IF NOT EXISTS hashes (
    id BIGSERIAL PRIMARY KEY,
    md5 VARCHAR(128),
    sha1 VARCHAR(128),
    sha256 VARCHAR(64),
    sha512 VARCHAR(128),
    ssdeep TEXT,
    is_malicious BOOLEAN DEFAULT TRUE,
    threat_score INTEGER DEFAULT 0,
    file_name VARCHAR(500),
    file_type VARCHAR(100),
    file_size BIGINT,
    mime_type VARCHAR(255),
    malware_family VARCHAR(255),
    malware_type VARCHAR(100),
    av_detections INTEGER,
    total_av_engines INTEGER,
    av_detection_rate NUMERIC(5,2),
    sandbox_verdict VARCHAR(50),
    virustotal_link VARCHAR(500),
    sources JSONB,
    tags JSONB,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hashes_md5 ON hashes(md5);
CREATE INDEX IF NOT EXISTS idx_hashes_sha1 ON hashes(sha1);
CREATE INDEX IF NOT EXISTS idx_hashes_sha256 ON hashes(sha256);
CREATE INDEX IF NOT EXISTS idx_hashes_malware ON hashes(malware_family);
CREATE INDEX IF NOT EXISTS idx_hashes_sources ON hashes USING GIN(sources);

-- ============================================================================
-- END OF PATCHES
-- ============================================================================
