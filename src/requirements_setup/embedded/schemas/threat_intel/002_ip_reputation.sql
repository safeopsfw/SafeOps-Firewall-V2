-- ============================================================================
-- SafeOps v2.0 - IP Reputation and Blacklist Schema
-- ============================================================================
-- File: 002_ip_reputation.sql
-- Purpose: IP reputation tracking with malicious IP blacklist and VPN detection
-- Version: 1.0.0
-- Created: 2025-12-22
-- Dependencies: 001_initial_setup.sql
-- ============================================================================

-- ============================================================================
-- SECTION 1: IP BLACKLIST TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS ip_blacklist (
    -- Core Fields
    id BIGSERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    is_malicious BOOLEAN DEFAULT TRUE,
    threat_score INTEGER NOT NULL CHECK (threat_score >= 0 AND threat_score <= 100),
    abuse_type VARCHAR(50) NOT NULL CHECK (abuse_type IN ('spam', 'malware', 'c2', 'bruteforce', 'botnet', 'scanner', 'unknown')),
    confidence INTEGER NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
    
    -- Metadata Fields
    sources JSONB DEFAULT '[]'::jsonb,
    evidence_count INTEGER DEFAULT 1,
    description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Add table comment
COMMENT ON TABLE ip_blacklist IS 'Core IP reputation table for tracking malicious IP addresses';
COMMENT ON COLUMN ip_blacklist.ip_address IS 'IPv4 or IPv6 address using PostgreSQL native INET type';
COMMENT ON COLUMN ip_blacklist.is_malicious IS 'Quick boolean flag for malicious status';
COMMENT ON COLUMN ip_blacklist.threat_score IS 'Numeric threat level 0-100 for firewall decisions';
COMMENT ON COLUMN ip_blacklist.abuse_type IS 'Classification: spam, malware, c2, bruteforce, botnet, scanner';
COMMENT ON COLUMN ip_blacklist.confidence IS 'Reliability score 0-100';
COMMENT ON COLUMN ip_blacklist.sources IS 'JSONB array of feed names that reported this IP';
COMMENT ON COLUMN ip_blacklist.evidence_count IS 'Number of sources that flagged this IP';
COMMENT ON COLUMN ip_blacklist.expires_at IS 'When this entry should be considered stale';

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_ip ON ip_blacklist USING gist(ip_address inet_ops);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_malicious ON ip_blacklist(is_malicious) WHERE is_malicious = TRUE;
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_threat_score ON ip_blacklist(threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_abuse_type ON ip_blacklist(abuse_type);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_expires_at ON ip_blacklist(expires_at);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_sources ON ip_blacklist USING gin(sources);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_last_seen ON ip_blacklist(last_seen DESC);

COMMIT;

-- ============================================================================
-- SECTION 2: VPN DETECTION TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS vpn_ips (
    -- Core Fields
    id BIGSERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    vpn_provider VARCHAR(255) NOT NULL,
    service_type VARCHAR(50) NOT NULL CHECK (service_type IN ('commercial_vpn', 'free_vpn', 'tor_exit', 'proxy')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    
    -- Optional Fields
    country_code VARCHAR(2),
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add table comment
COMMENT ON TABLE vpn_ips IS 'VPN and proxy IP detection table for policy enforcement';
COMMENT ON COLUMN vpn_ips.ip_address IS 'IPv4 or IPv6 address of VPN exit node';
COMMENT ON COLUMN vpn_ips.vpn_provider IS 'Name of VPN service (NordVPN, ExpressVPN, etc.)';
COMMENT ON COLUMN vpn_ips.service_type IS 'Type: commercial_vpn, free_vpn, tor_exit, proxy';
COMMENT ON COLUMN vpn_ips.risk_score IS 'Risk assessment 0-100 (not all VPNs are equal threat)';
COMMENT ON COLUMN vpn_ips.country_code IS 'Exit node country code (ISO 3166-1 alpha-2)';
COMMENT ON COLUMN vpn_ips.is_active IS 'Whether this VPN exit node is still operational';

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_vpn_ips_ip ON vpn_ips USING gist(ip_address inet_ops);
CREATE INDEX IF NOT EXISTS idx_vpn_ips_provider ON vpn_ips(vpn_provider);
CREATE INDEX IF NOT EXISTS idx_vpn_ips_service_type ON vpn_ips(service_type);
CREATE INDEX IF NOT EXISTS idx_vpn_ips_active ON vpn_ips(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_vpn_ips_country ON vpn_ips(country_code);

COMMIT;

-- ============================================================================
-- SECTION 3: COMBINED INTELLIGENCE VIEW
-- ============================================================================

BEGIN;

CREATE OR REPLACE VIEW ip_full_intelligence AS
SELECT 
    COALESCE(bl.ip_address, vpn.ip_address) AS ip_address,
    bl.is_malicious,
    bl.threat_score,
    bl.abuse_type,
    bl.confidence,
    bl.sources,
    bl.evidence_count,
    bl.description,
    bl.first_seen AS bl_first_seen,
    bl.last_seen AS bl_last_seen,
    bl.expires_at,
    vpn.vpn_provider,
    vpn.service_type,
    vpn.risk_score AS vpn_risk_score,
    vpn.country_code,
    (vpn.ip_address IS NOT NULL) AS is_vpn,
    vpn.is_active AS vpn_active
FROM ip_blacklist bl
FULL OUTER JOIN vpn_ips vpn ON bl.ip_address = vpn.ip_address;

COMMENT ON VIEW ip_full_intelligence IS 'Combined view of IP blacklist and VPN data for single-query lookups';

COMMIT;

-- ============================================================================
-- SECTION 4: HELPER FUNCTIONS
-- ============================================================================

BEGIN;

-- Function: Check if IP is malicious
CREATE OR REPLACE FUNCTION check_ip_malicious(check_ip INET)
RETURNS TABLE(
    is_malicious BOOLEAN,
    threat_score INTEGER,
    abuse_type VARCHAR(50),
    confidence INTEGER,
    sources JSONB,
    description TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        bl.is_malicious,
        bl.threat_score,
        bl.abuse_type,
        bl.confidence,
        bl.sources,
        bl.description
    FROM ip_blacklist bl
    WHERE bl.ip_address = check_ip
    AND (bl.expires_at IS NULL OR bl.expires_at > CURRENT_TIMESTAMP);
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION check_ip_malicious(INET) IS 'Single-query IP reputation check for firewall integration';

-- Function: Check if IP is VPN
CREATE OR REPLACE FUNCTION check_ip_vpn(check_ip INET)
RETURNS TABLE(
    is_vpn BOOLEAN,
    vpn_provider VARCHAR(255),
    service_type VARCHAR(50),
    risk_score INTEGER,
    country_code VARCHAR(2)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        TRUE AS is_vpn,
        vpn.vpn_provider,
        vpn.service_type,
        vpn.risk_score,
        vpn.country_code
    FROM vpn_ips vpn
    WHERE vpn.ip_address = check_ip
    AND vpn.is_active = TRUE;
    
    -- Return NULL row if not found
    IF NOT FOUND THEN
        RETURN QUERY
        SELECT FALSE, NULL::VARCHAR(255), NULL::VARCHAR(50), 0, NULL::VARCHAR(2);
    END IF;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION check_ip_vpn(INET) IS 'Dedicated VPN detection function';

-- Function: Bulk check multiple IPs
CREATE OR REPLACE FUNCTION bulk_check_ips(check_ips INET[])
RETURNS TABLE(
    ip_address INET,
    is_malicious BOOLEAN,
    threat_score INTEGER,
    abuse_type VARCHAR(50),
    confidence INTEGER,
    is_vpn BOOLEAN,
    vpn_provider VARCHAR(255),
    risk_score INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ips.ip AS ip_address,
        COALESCE(bl.is_malicious, FALSE) AS is_malicious,
        COALESCE(bl.threat_score, 0) AS threat_score,
        bl.abuse_type,
        COALESCE(bl.confidence, 0) AS confidence,
        (vpn.ip_address IS NOT NULL) AS is_vpn,
        vpn.vpn_provider,
        COALESCE(vpn.risk_score, 0) AS risk_score
    FROM UNNEST(check_ips) AS ips(ip)
    LEFT JOIN ip_blacklist bl ON bl.ip_address = ips.ip 
        AND (bl.expires_at IS NULL OR bl.expires_at > CURRENT_TIMESTAMP)
    LEFT JOIN vpn_ips vpn ON vpn.ip_address = ips.ip 
        AND vpn.is_active = TRUE;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION bulk_check_ips(INET[]) IS 'Batch IP reputation check for log analysis (optimized for 1000+ IPs)';

COMMIT;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Uncomment to verify setup (for manual testing)
-- SELECT * FROM ip_blacklist LIMIT 5;
-- SELECT * FROM vpn_ips LIMIT 5;
-- SELECT * FROM ip_full_intelligence LIMIT 5;
-- SELECT check_ip_malicious('8.8.8.8'::inet);
-- SELECT check_ip_vpn('8.8.8.8'::inet);
-- SELECT * FROM bulk_check_ips(ARRAY['8.8.8.8'::inet, '1.1.1.1'::inet]);

-- ============================================================================
-- END OF IP REPUTATION SCHEMA
-- ============================================================================
