-- ============================================================================
-- SafeOps v2.0 - File Hash Reputation Schema
-- ============================================================================
-- File: 004_hash_reputation.sql
-- Purpose: File hash reputation for malware detection and scanning
-- Version: 1.0.0
-- Created: 2025-12-22
-- Dependencies: 001_initial_setup.sql
-- ============================================================================

-- ============================================================================
-- SECTION 1: FILE HASHES TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS file_hashes (
    -- Core Hash Fields
    id BIGSERIAL PRIMARY KEY,
    sha256 VARCHAR(64) UNIQUE NOT NULL,
    sha1 VARCHAR(40),
    md5 VARCHAR(32),
    ssdeep VARCHAR(255),
    
    -- Threat Assessment Fields
    is_malicious BOOLEAN DEFAULT FALSE,
    threat_score INTEGER NOT NULL CHECK (threat_score >= 0 AND threat_score <= 100),
    
    -- Malware Classification
    malware_family VARCHAR(255),
    malware_type VARCHAR(100) CHECK (malware_type IN ('ransomware', 'trojan', 'backdoor', 'worm', 'rootkit', 'spyware', 'adware', 'rat', 'miner', 'unknown')),
    malware_description TEXT,
    
    -- File Metadata
    file_name VARCHAR(500),
    file_type VARCHAR(50),
    file_size BIGINT,
    
    -- Antivirus Detection Data
    av_detection_rate DECIMAL(5,2) CHECK (av_detection_rate >= 0 AND av_detection_rate <= 100),
    av_detections INTEGER,
    av_total_engines INTEGER,
    av_scan_date TIMESTAMP WITH TIME ZONE,
    
    -- Intelligence Sources
    sources JSONB DEFAULT '[]'::jsonb,
    virustotal_link VARCHAR(500),
    detection_count INTEGER DEFAULT 1,
    
    -- Metadata
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'archived', 'whitelisted'))
);

-- Add table comments
COMMENT ON TABLE file_hashes IS 'File hash reputation table for malware detection and scanning';
COMMENT ON COLUMN file_hashes.sha256 IS 'SHA256 hash - primary identifier (most secure, collision-resistant)';
COMMENT ON COLUMN file_hashes.sha1 IS 'SHA1 hash - secondary for legacy compatibility';
COMMENT ON COLUMN file_hashes.md5 IS 'MD5 hash - legacy support (still widely used despite weakness)';
COMMENT ON COLUMN file_hashes.ssdeep IS 'Fuzzy hash for detecting similar malware variants';
COMMENT ON COLUMN file_hashes.threat_score IS 'Numeric threat level 0-100 (90-100=critical, 70-89=high, 50-69=medium, 30-49=low)';
COMMENT ON COLUMN file_hashes.malware_family IS 'Specific family name (Emotet, TrickBot, WannaCry, Cobalt Strike, Mimikatz)';
COMMENT ON COLUMN file_hashes.malware_type IS 'General category: ransomware, trojan, backdoor, worm, rootkit, spyware, adware, rat, miner';
COMMENT ON COLUMN file_hashes.malware_description IS 'Brief description of behavior and impact';
COMMENT ON COLUMN file_hashes.file_name IS 'Original filename if known';
COMMENT ON COLUMN file_hashes.file_type IS 'File extension (exe, dll, pdf, doc, apk, msi)';
COMMENT ON COLUMN file_hashes.file_size IS 'File size in bytes';
COMMENT ON COLUMN file_hashes.av_detection_rate IS 'Percentage of AV engines that flagged this (0-100)';
COMMENT ON COLUMN file_hashes.av_detections IS 'Number of engines that detected it';
COMMENT ON COLUMN file_hashes.av_total_engines IS 'Total number of engines that scanned it';
COMMENT ON COLUMN file_hashes.av_scan_date IS 'When last scanned by AV engines';
COMMENT ON COLUMN file_hashes.sources IS 'JSONB array of feed names (MalwareBazaar, VirusTotal, hybrid-analysis)';
COMMENT ON COLUMN file_hashes.virustotal_link IS 'Direct link to VirusTotal report';
COMMENT ON COLUMN file_hashes.detection_count IS 'Number of times seen across all sources';

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_file_hashes_sha256 ON file_hashes(sha256);
CREATE INDEX IF NOT EXISTS idx_file_hashes_sha1 ON file_hashes(sha1);
CREATE INDEX IF NOT EXISTS idx_file_hashes_md5 ON file_hashes(md5);
CREATE INDEX IF NOT EXISTS idx_file_hashes_malicious ON file_hashes(is_malicious) WHERE is_malicious = TRUE;
CREATE INDEX IF NOT EXISTS idx_file_hashes_threat_score ON file_hashes(threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_file_hashes_malware_family ON file_hashes(malware_family);
CREATE INDEX IF NOT EXISTS idx_file_hashes_malware_type ON file_hashes(malware_type);
CREATE INDEX IF NOT EXISTS idx_file_hashes_av_detection_rate ON file_hashes(av_detection_rate DESC);
CREATE INDEX IF NOT EXISTS idx_file_hashes_sources ON file_hashes USING gin(sources);
CREATE INDEX IF NOT EXISTS idx_file_hashes_file_type ON file_hashes(file_type);
CREATE INDEX IF NOT EXISTS idx_file_hashes_status ON file_hashes(status);
CREATE INDEX IF NOT EXISTS idx_file_hashes_last_seen ON file_hashes(last_seen DESC);

COMMIT;

-- ============================================================================
-- SECTION 2: HELPER FUNCTIONS
-- ============================================================================

BEGIN;

-- Function: Check if hash is malicious (auto-detects hash type)
CREATE OR REPLACE FUNCTION check_hash_malicious(check_hash VARCHAR)
RETURNS TABLE(
    is_malicious BOOLEAN,
    threat_score INTEGER,
    malware_family VARCHAR(255),
    malware_type VARCHAR(100),
    av_detection_rate DECIMAL(5,2),
    file_name VARCHAR(500),
    sources JSONB
) AS $$
DECLARE
    hash_length INTEGER;
BEGIN
    hash_length := LENGTH(check_hash);
    
    -- Auto-detect hash type by length: 32=MD5, 40=SHA1, 64=SHA256
    IF hash_length = 64 THEN
        -- SHA256
        RETURN QUERY
        SELECT 
            fh.is_malicious,
            fh.threat_score,
            fh.malware_family,
            fh.malware_type,
            fh.av_detection_rate,
            fh.file_name,
            fh.sources
        FROM file_hashes fh
        WHERE fh.sha256 = check_hash
        AND fh.status = 'active';
    ELSIF hash_length = 40 THEN
        -- SHA1
        RETURN QUERY
        SELECT 
            fh.is_malicious,
            fh.threat_score,
            fh.malware_family,
            fh.malware_type,
            fh.av_detection_rate,
            fh.file_name,
            fh.sources
        FROM file_hashes fh
        WHERE fh.sha1 = check_hash
        AND fh.status = 'active';
    ELSIF hash_length = 32 THEN
        -- MD5
        RETURN QUERY
        SELECT 
            fh.is_malicious,
            fh.threat_score,
            fh.malware_family,
            fh.malware_type,
            fh.av_detection_rate,
            fh.file_name,
            fh.sources
        FROM file_hashes fh
        WHERE fh.md5 = check_hash
        AND fh.status = 'active';
    END IF;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION check_hash_malicious(VARCHAR) IS 'Auto-detects hash type (MD5/SHA1/SHA256) and returns malware verdict';

-- Function: Bulk check multiple hashes
CREATE OR REPLACE FUNCTION bulk_check_hashes(check_hashes VARCHAR[])
RETURNS TABLE(
    hash VARCHAR,
    is_malicious BOOLEAN,
    threat_score INTEGER,
    malware_family VARCHAR(255),
    malware_type VARCHAR(100),
    av_detection_rate DECIMAL(5,2)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        hashes.h AS hash,
        COALESCE(fh.is_malicious, FALSE) AS is_malicious,
        COALESCE(fh.threat_score, 0) AS threat_score,
        fh.malware_family,
        fh.malware_type,
        fh.av_detection_rate
    FROM UNNEST(check_hashes) AS hashes(h)
    LEFT JOIN file_hashes fh ON (
        (LENGTH(hashes.h) = 64 AND fh.sha256 = hashes.h) OR
        (LENGTH(hashes.h) = 40 AND fh.sha1 = hashes.h) OR
        (LENGTH(hashes.h) = 32 AND fh.md5 = hashes.h)
    )
    AND fh.status = 'active';
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION bulk_check_hashes(VARCHAR[]) IS 'Batch hash reputation check (accepts mixed MD5/SHA1/SHA256)';

-- Function: Get all malware variants for a family
CREATE OR REPLACE FUNCTION get_malware_variants(family_name VARCHAR)
RETURNS TABLE(
    sha256 VARCHAR(64),
    sha1 VARCHAR(40),
    md5 VARCHAR(32),
    threat_score INTEGER,
    file_name VARCHAR(500),
    av_detection_rate DECIMAL(5,2),
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        fh.sha256,
        fh.sha1,
        fh.md5,
        fh.threat_score,
        fh.file_name,
        fh.av_detection_rate,
        fh.first_seen,
        fh.last_seen
    FROM file_hashes fh
    WHERE fh.malware_family ILIKE family_name
    AND fh.is_malicious = TRUE
    ORDER BY fh.last_seen DESC;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION get_malware_variants(VARCHAR) IS 'Returns all known file hashes for a malware family (useful for threat hunting)';

COMMIT;

-- ============================================================================
-- SECTION 3: MALWARE STATISTICS VIEW
-- ============================================================================

BEGIN;

CREATE OR REPLACE VIEW malware_statistics AS
SELECT 
    malware_family,
    malware_type,
    COUNT(*) as sample_count,
    AVG(threat_score)::DECIMAL(5,2) as avg_threat_score,
    AVG(av_detection_rate)::DECIMAL(5,2) as avg_detection_rate,
    MAX(last_seen) as last_activity,
    MIN(first_seen) as first_activity
FROM file_hashes
WHERE is_malicious = TRUE
GROUP BY malware_family, malware_type
ORDER BY sample_count DESC;

COMMENT ON VIEW malware_statistics IS 'Overview of malware family distribution and prevalence';

COMMIT;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Uncomment to verify setup (for manual testing)
-- SELECT * FROM file_hashes LIMIT 5;
-- SELECT * FROM malware_statistics LIMIT 10;
-- SELECT * FROM check_hash_malicious('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
-- SELECT * FROM bulk_check_hashes(ARRAY['d41d8cd98f00b204e9800998ecf8427e', 'da39a3ee5e6b4b0d3255bfef95601890afd80709']);
-- SELECT * FROM get_malware_variants('Emotet');

-- ============================================================================
-- END OF HASH REPUTATION SCHEMA
-- ============================================================================
