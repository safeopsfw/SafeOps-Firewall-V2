-- ============================================================================
-- SafeOps v2.0 - Domain Reputation and Blacklist Schema
-- ============================================================================
-- File: 003_domain_reputation.sql
-- Purpose: Domain reputation tracking with typosquatting detection
-- Version: 1.0.0
-- Created: 2025-12-22
-- Dependencies: 001_initial_setup.sql
-- ============================================================================

-- ============================================================================
-- SECTION 1: DOMAINS BLACKLIST TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS domains (
    -- Core Identification Fields
    id BIGSERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    root_domain VARCHAR(255),
    tld VARCHAR(50),
    
    -- Threat Assessment Fields
    is_malicious BOOLEAN DEFAULT FALSE,
    threat_score INTEGER NOT NULL CHECK (threat_score >= 0 AND threat_score <= 100),
    category VARCHAR(100) CHECK (category IN ('phishing', 'malware', 'c2', 'spam', 'exploit_kit', 'scam', 'ransomware', 'unknown')),
    reported_reason TEXT NOT NULL,
    
    -- Confidence and Evidence
    confidence INTEGER NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
    sources JSONB DEFAULT '[]'::jsonb,
    detection_count INTEGER DEFAULT 1,
    false_positive_count INTEGER DEFAULT 0,
    
    -- Phishing-Specific Fields
    phishing_target VARCHAR(100),
    similarity_domains JSONB DEFAULT '[]'::jsonb,
    
    -- Registration Information
    registration_date TIMESTAMP WITH TIME ZONE,
    is_newly_registered BOOLEAN DEFAULT FALSE,
    registrar VARCHAR(255),
    
    -- Metadata
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'expired', 'whitelisted', 'sinkholed'))
);

-- Add table comments
COMMENT ON TABLE domains IS 'Domain reputation table for tracking malicious, phishing, and suspicious domains';
COMMENT ON COLUMN domains.domain IS 'Full domain name (example.com, subdomain.example.com)';
COMMENT ON COLUMN domains.root_domain IS 'Extracted base domain without subdomain';
COMMENT ON COLUMN domains.tld IS 'Top-level domain (.com, .org, .net, .ru)';
COMMENT ON COLUMN domains.is_malicious IS 'Quick boolean flag for malicious status';
COMMENT ON COLUMN domains.threat_score IS 'Numeric threat level 0-100 for blocking decisions';
COMMENT ON COLUMN domains.category IS 'Primary classification: phishing, malware, c2, spam, etc.';
COMMENT ON COLUMN domains.reported_reason IS 'WHY this domain was flagged - key context field';
COMMENT ON COLUMN domains.confidence IS 'Reliability score 0-100';
COMMENT ON COLUMN domains.sources IS 'JSONB array of feed names that reported this domain';
COMMENT ON COLUMN domains.detection_count IS 'Number of times flagged across all sources';
COMMENT ON COLUMN domains.false_positive_count IS 'Times users reported as false positive';
COMMENT ON COLUMN domains.phishing_target IS 'Brand/service being impersonated (PayPal, Microsoft, etc.)';
COMMENT ON COLUMN domains.similarity_domains IS 'JSONB array of legitimate domains this tries to mimic';
COMMENT ON COLUMN domains.registration_date IS 'When domain was first registered';
COMMENT ON COLUMN domains.is_newly_registered IS 'Flag for domains <30 days old (high risk indicator)';
COMMENT ON COLUMN domains.status IS 'Domain status: active, expired, whitelisted, sinkholed';

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_domains_root_domain ON domains(root_domain);
CREATE INDEX IF NOT EXISTS idx_domains_tld ON domains(tld);
CREATE INDEX IF NOT EXISTS idx_domains_malicious ON domains(is_malicious) WHERE is_malicious = TRUE;
CREATE INDEX IF NOT EXISTS idx_domains_threat_score ON domains(threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_domains_category ON domains(category);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
CREATE INDEX IF NOT EXISTS idx_domains_fuzzy ON domains USING gin(domain gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_domains_sources ON domains USING gin(sources);
CREATE INDEX IF NOT EXISTS idx_domains_registration_date ON domains(registration_date);
CREATE INDEX IF NOT EXISTS idx_domains_newly_registered ON domains(is_newly_registered) WHERE is_newly_registered = TRUE;
CREATE INDEX IF NOT EXISTS idx_domains_last_seen ON domains(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_domains_expires_at ON domains(expires_at);

COMMIT;

-- ============================================================================
-- SECTION 2: LEGITIMATE DOMAINS REFERENCE TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS legitimate_domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    brand_name VARCHAR(255),
    category VARCHAR(50)  -- banking, social_media, email, etc.
);

COMMENT ON TABLE legitimate_domains IS 'Reference table of known-good domains for typosquatting comparisons';
COMMENT ON COLUMN legitimate_domains.domain IS 'Verified legitimate domain name';
COMMENT ON COLUMN legitimate_domains.brand_name IS 'Company or brand name';
COMMENT ON COLUMN legitimate_domains.category IS 'Domain category: banking, social_media, email, etc.';

-- Create index for fuzzy matching
CREATE INDEX IF NOT EXISTS idx_legitimate_domains_fuzzy ON legitimate_domains USING gin(domain gin_trgm_ops);

COMMIT;

-- ============================================================================
-- SECTION 3: TYPOSQUATTING DETECTION VIEW
-- ============================================================================

BEGIN;

CREATE OR REPLACE VIEW potential_typosquats AS
SELECT 
    d1.domain AS suspicious_domain,
    d1.threat_score,
    d1.category,
    d2.domain AS legitimate_domain,
    d2.brand_name,
    similarity(d1.domain, d2.domain) AS similarity_score,
    d1.first_seen,
    d1.sources
FROM domains d1
CROSS JOIN legitimate_domains d2
WHERE similarity(d1.domain, d2.domain) > 0.7
  AND d1.domain != d2.domain
  AND d1.is_malicious = TRUE
ORDER BY similarity_score DESC;

COMMENT ON VIEW potential_typosquats IS 'Identifies potential typosquatting domains using fuzzy matching';

COMMIT;

-- ============================================================================
-- SECTION 4: HELPER FUNCTIONS
-- ============================================================================

BEGIN;

-- Function: Check if domain is malicious
CREATE OR REPLACE FUNCTION check_domain_malicious(check_domain VARCHAR)
RETURNS TABLE(
    is_malicious BOOLEAN,
    threat_score INTEGER,
    category VARCHAR(100),
    reported_reason TEXT,
    confidence INTEGER,
    sources JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.is_malicious,
        d.threat_score,
        d.category,
        d.reported_reason,
        d.confidence,
        d.sources
    FROM domains d
    WHERE d.domain = check_domain
    AND d.status = 'active'
    AND (d.expires_at IS NULL OR d.expires_at > CURRENT_TIMESTAMP);
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION check_domain_malicious(VARCHAR) IS 'Single-query domain reputation check for DNS filtering';

-- Function: Find similar domains (typosquatting detection)
CREATE OR REPLACE FUNCTION find_similar_domains(
    target_domain VARCHAR,
    similarity_threshold FLOAT DEFAULT 0.7
)
RETURNS TABLE(
    domain VARCHAR(255),
    similarity_score FLOAT,
    is_malicious BOOLEAN,
    threat_score INTEGER,
    category VARCHAR(100),
    reported_reason TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.domain,
        similarity(d.domain, target_domain) AS similarity_score,
        d.is_malicious,
        d.threat_score,
        d.category,
        d.reported_reason
    FROM domains d
    WHERE d.domain % target_domain  -- Use trigram similarity operator
    AND d.domain != target_domain
    AND similarity(d.domain, target_domain) >= similarity_threshold
    ORDER BY similarity_score DESC
    LIMIT 100;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION find_similar_domains(VARCHAR, FLOAT) IS 'Uses pg_trgm for fuzzy matching to detect typosquatting attempts';

-- Function: Bulk check multiple domains
CREATE OR REPLACE FUNCTION bulk_check_domains(check_domains VARCHAR[])
RETURNS TABLE(
    domain VARCHAR(255),
    is_malicious BOOLEAN,
    threat_score INTEGER,
    category VARCHAR(100),
    confidence INTEGER,
    reported_reason TEXT,
    status VARCHAR(20)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        doms.dom AS domain,
        COALESCE(d.is_malicious, FALSE) AS is_malicious,
        COALESCE(d.threat_score, 0) AS threat_score,
        d.category,
        COALESCE(d.confidence, 0) AS confidence,
        d.reported_reason,
        COALESCE(d.status, 'unknown'::VARCHAR(20)) AS status
    FROM UNNEST(check_domains) AS doms(dom)
    LEFT JOIN domains d ON d.domain = doms.dom
        AND d.status = 'active'
        AND (d.expires_at IS NULL OR d.expires_at > CURRENT_TIMESTAMP);
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION bulk_check_domains(VARCHAR[]) IS 'Batch domain reputation check optimized for DNS query filtering';

-- Function: Auto-update newly registered flag
CREATE OR REPLACE FUNCTION update_newly_registered_flag()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.registration_date IS NOT NULL THEN
        NEW.is_newly_registered := (CURRENT_TIMESTAMP - NEW.registration_date) < INTERVAL '30 days';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically set newly registered flag
DROP TRIGGER IF EXISTS trigger_update_newly_registered ON domains;
CREATE TRIGGER trigger_update_newly_registered
    BEFORE INSERT OR UPDATE OF registration_date ON domains
    FOR EACH ROW
    EXECUTE FUNCTION update_newly_registered_flag();

COMMENT ON FUNCTION update_newly_registered_flag() IS 'Automatically sets is_newly_registered flag based on registration_date';

COMMIT;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Uncomment to verify setup (for manual testing)
-- SELECT * FROM domains LIMIT 5;
-- SELECT * FROM legitimate_domains LIMIT 5;
-- SELECT * FROM potential_typosquats LIMIT 5;
-- SELECT check_domain_malicious('example.com');
-- SELECT * FROM find_similar_domains('paypal.com', 0.7);
-- SELECT * FROM bulk_check_domains(ARRAY['example.com', 'test.com']);

-- ============================================================================
-- END OF DOMAIN REPUTATION SCHEMA
-- ============================================================================
