-- ============================================================================
-- SafeOps v2.0 - IP Geolocation Schema
-- ============================================================================
-- File: 007_geolocation.sql
-- Purpose: IP geolocation database for location-based filtering and analytics
-- Version: 1.0.0
-- Created: 2025-12-22
-- Dependencies: 001_initial_setup.sql
-- ============================================================================

-- ============================================================================
-- SECTION 1: IP GEOLOCATION MAIN TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS ip_geolocation (
    -- Core Identification
    id BIGSERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    ip_version SMALLINT CHECK (ip_version IN (4, 6)),
    
    -- Geographic Location
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    region VARCHAR(100),
    region_code VARCHAR(10),
    city VARCHAR(100),
    postal_code VARCHAR(20),
    timezone VARCHAR(50),
    
    -- Geographic Coordinates
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    accuracy_radius INTEGER,
    metro_code INTEGER,
    
    -- Network Information
    asn INTEGER,
    asn_org VARCHAR(255),
    isp VARCHAR(255),
    organization VARCHAR(255),
    connection_type VARCHAR(50) CHECK (connection_type IN ('cable', 'dsl', 'cellular', 'corporate', 'satellite', 'dialup', 'unknown')),
    
    -- Special Flags
    is_anonymous_proxy BOOLEAN DEFAULT FALSE,
    is_satellite_provider BOOLEAN DEFAULT FALSE,
    is_anycast BOOLEAN DEFAULT FALSE,
    is_hosting BOOLEAN DEFAULT FALSE,
    is_mobile BOOLEAN DEFAULT FALSE,
    is_residential BOOLEAN DEFAULT FALSE,
    
    -- Data Quality
    confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
    sources JSONB DEFAULT '[]'::jsonb,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add table comments
COMMENT ON TABLE ip_geolocation IS 'IP geolocation database mapping IPs to physical locations and network information';
COMMENT ON COLUMN ip_geolocation.ip_address IS 'IPv4 or IPv6 address';
COMMENT ON COLUMN ip_geolocation.ip_version IS '4 for IPv4, 6 for IPv6';
COMMENT ON COLUMN ip_geolocation.country_code IS 'ISO 3166-1 alpha-2 country code';
COMMENT ON COLUMN ip_geolocation.latitude IS 'Latitude coordinate (-90.0 to +90.0)';
COMMENT ON COLUMN ip_geolocation.longitude IS 'Longitude coordinate (-180.0 to +180.0)';
COMMENT ON COLUMN ip_geolocation.accuracy_radius IS 'Location accuracy in kilometers';
COMMENT ON COLUMN ip_geolocation.asn IS 'Autonomous System Number';
COMMENT ON COLUMN ip_geolocation.connection_type IS 'Type of internet connection';
COMMENT ON COLUMN ip_geolocation.is_hosting IS 'Datacenter or hosting provider IP';
COMMENT ON COLUMN ip_geolocation.is_mobile IS 'Mobile carrier network IP';
COMMENT ON COLUMN ip_geolocation.confidence IS 'Location accuracy confidence 0-100';

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_ip_geo_ip ON ip_geolocation(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_geo_range ON ip_geolocation USING gist(ip_address inet_ops);
CREATE INDEX IF NOT EXISTS idx_ip_geo_country ON ip_geolocation(country_code);
CREATE INDEX IF NOT EXISTS idx_ip_geo_city ON ip_geolocation(city);
CREATE INDEX IF NOT EXISTS idx_ip_geo_asn ON ip_geolocation(asn);
CREATE INDEX IF NOT EXISTS idx_ip_geo_hosting ON ip_geolocation(is_hosting) WHERE is_hosting = TRUE;
CREATE INDEX IF NOT EXISTS idx_ip_geo_mobile ON ip_geolocation(is_mobile) WHERE is_mobile = TRUE;
CREATE INDEX IF NOT EXISTS idx_ip_geo_country_city ON ip_geolocation(country_code, city);
CREATE INDEX IF NOT EXISTS idx_ip_geo_updated ON ip_geolocation(last_updated);
CREATE INDEX IF NOT EXISTS idx_ip_geo_sources ON ip_geolocation USING gin(sources);

COMMIT;

-- ============================================================================
-- SECTION 2: ASN INFORMATION TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS asn_info (
    -- Core ASN Data
    id SERIAL PRIMARY KEY,
    asn INTEGER UNIQUE NOT NULL,
    asn_name VARCHAR(255),
    organization VARCHAR(255),
    registration_date DATE,
    
    -- Geographic & Administrative
    country_code VARCHAR(2),
    registry VARCHAR(20) CHECK (registry IN ('ARIN', 'RIPE', 'APNIC', 'LACNIC', 'AFRINIC', 'unknown')),
    
    -- Threat Intelligence Context
    reputation_score INTEGER CHECK (reputation_score >= 0 AND reputation_score <= 100),
    is_known_bad BOOLEAN DEFAULT FALSE,
    abuse_contacts JSONB DEFAULT '[]'::jsonb,
    notes TEXT,
    
    -- Metadata
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE asn_info IS 'Autonomous System Number information and reputation tracking';
COMMENT ON COLUMN asn_info.asn IS 'Autonomous System Number';
COMMENT ON COLUMN asn_info.registry IS 'Regional Internet Registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC)';
COMMENT ON COLUMN asn_info.reputation_score IS 'Overall reputation 0-100 (100=trusted, 0=suspicious)';
COMMENT ON COLUMN asn_info.abuse_contacts IS 'JSONB array of abuse reporting emails/contacts';

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_asn_info_asn ON asn_info(asn);
CREATE INDEX IF NOT EXISTS idx_asn_info_country ON asn_info(country_code);
CREATE INDEX IF NOT EXISTS idx_asn_info_known_bad ON asn_info(is_known_bad) WHERE is_known_bad = TRUE;
CREATE INDEX IF NOT EXISTS idx_asn_info_reputation ON asn_info(reputation_score DESC);

COMMIT;

-- ============================================================================
-- SECTION 3: IP RANGE CACHE TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS ip_range_cache (
    id BIGSERIAL PRIMARY KEY,
    network CIDR NOT NULL,
    country_code VARCHAR(2),
    asn INTEGER,
    organization VARCHAR(255),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ip_range_cache IS 'Pre-computed IP ranges for optimized CIDR block lookups';
COMMENT ON COLUMN ip_range_cache.network IS 'Network CIDR block (e.g., 192.168.0.0/24)';

-- Create GiST index for range queries
CREATE INDEX IF NOT EXISTS idx_ip_range_network ON ip_range_cache USING gist(network inet_ops);
CREATE INDEX IF NOT EXISTS idx_ip_range_country ON ip_range_cache(country_code);
CREATE INDEX IF NOT EXISTS idx_ip_range_asn ON ip_range_cache(asn);

COMMIT;

-- ============================================================================
-- SECTION 4: HELPER FUNCTIONS
-- ============================================================================

BEGIN;

-- Function: Get IP location
CREATE OR REPLACE FUNCTION get_ip_location(check_ip INET)
RETURNS TABLE(
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    asn INTEGER,
    asn_org VARCHAR(255),
    connection_type VARCHAR(50)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        g.country_code,
        g.country_name,
        g.city,
        g.latitude,
        g.longitude,
        g.asn,
        g.asn_org,
        g.connection_type
    FROM ip_geolocation g
    WHERE g.ip_address = check_ip;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION get_ip_location(INET) IS 'Single-query location lookup for threat enrichment';

-- Function: Get IP country (fast lookup)
CREATE OR REPLACE FUNCTION get_ip_country(check_ip INET)
RETURNS VARCHAR(2) AS $$
DECLARE
    result VARCHAR(2);
BEGIN
    SELECT country_code INTO result
    FROM ip_geolocation
    WHERE ip_address = check_ip;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION get_ip_country(INET) IS 'Fast country-only lookup optimized for firewall rules';

-- Function: Check if IP is in allowed countries
CREATE OR REPLACE FUNCTION is_ip_in_country(check_ip INET, allowed_countries VARCHAR[])
RETURNS BOOLEAN AS $$
DECLARE
    ip_country VARCHAR(2);
BEGIN
    SELECT country_code INTO ip_country
    FROM ip_geolocation
    WHERE ip_address = check_ip;
    
    RETURN ip_country = ANY(allowed_countries);
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION is_ip_in_country(INET, VARCHAR[]) IS 'Checks if IP is from allowed countries for geo-blocking';

-- Function: Find IPs within geographic radius
CREATE OR REPLACE FUNCTION find_ips_in_radius(
    center_lat DECIMAL,
    center_lon DECIMAL,
    radius_km INTEGER
)
RETURNS TABLE(
    ip_address INET,
    distance_km DECIMAL,
    country_name VARCHAR(100),
    city VARCHAR(100)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        g.ip_address,
        -- Haversine formula for distance calculation
        (6371 * acos(
            cos(radians(center_lat)) * 
            cos(radians(g.latitude)) * 
            cos(radians(g.longitude) - radians(center_lon)) + 
            sin(radians(center_lat)) * 
            sin(radians(g.latitude))
        ))::DECIMAL(10,2) AS distance_km,
        g.country_name,
        g.city
    FROM ip_geolocation g
    WHERE g.latitude IS NOT NULL 
    AND g.longitude IS NOT NULL
    HAVING distance_km <= radius_km
    ORDER BY distance_km ASC
    LIMIT 1000;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION find_ips_in_radius(DECIMAL, DECIMAL, INTEGER) IS 'Geographic radius search using haversine formula';

-- Function: Get ASN information
CREATE OR REPLACE FUNCTION get_asn_info(check_asn INTEGER)
RETURNS TABLE(
    asn INTEGER,
    asn_name VARCHAR(255),
    organization VARCHAR(255),
    country_code VARCHAR(2),
    reputation_score INTEGER,
    is_known_bad BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.asn,
        a.asn_name,
        a.organization,
        a.country_code,
        a.reputation_score,
        a.is_known_bad
    FROM asn_info a
    WHERE a.asn = check_asn;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION get_asn_info(INTEGER) IS 'Detailed ASN information lookup with reputation data';

COMMIT;

-- ============================================================================
-- SECTION 5: GEOGRAPHIC ANALYSIS VIEWS
-- ============================================================================

BEGIN;

-- View: Country IP distribution
CREATE OR REPLACE VIEW country_ip_distribution AS
SELECT 
    country_code,
    country_name,
    COUNT(*) as ip_count,
    COUNT(DISTINCT asn) as unique_asns,
    AVG(confidence)::DECIMAL(5,2) as avg_confidence
FROM ip_geolocation
WHERE country_code IS NOT NULL
GROUP BY country_code, country_name
ORDER BY ip_count DESC;

COMMENT ON VIEW country_ip_distribution IS 'IP distribution statistics by country';

-- View: Top ASNs
CREATE OR REPLACE VIEW top_asns AS
SELECT 
    g.asn,
    g.asn_org,
    a.reputation_score,
    COUNT(g.ip_address) as ip_count,
    COUNT(DISTINCT g.country_code) as countries
FROM ip_geolocation g
LEFT JOIN asn_info a ON g.asn = a.asn
WHERE g.asn IS NOT NULL
GROUP BY g.asn, g.asn_org, a.reputation_score
ORDER BY ip_count DESC
LIMIT 100;

COMMENT ON VIEW top_asns IS 'Top 100 ASNs by IP count with reputation scores';

-- View: Mobile networks
CREATE OR REPLACE VIEW mobile_networks AS
SELECT 
    country_code,
    isp,
    COUNT(*) as ip_count
FROM ip_geolocation
WHERE is_mobile = TRUE
GROUP BY country_code, isp
ORDER BY country_code, ip_count DESC;

COMMENT ON VIEW mobile_networks IS 'Mobile carrier networks grouped by country';

-- View: Datacenter IPs
CREATE OR REPLACE VIEW datacenter_ips AS
SELECT 
    asn_org,
    country_code,
    COUNT(*) as ip_count
FROM ip_geolocation
WHERE is_hosting = TRUE
GROUP BY asn_org, country_code
ORDER BY ip_count DESC;

COMMENT ON VIEW datacenter_ips IS 'Datacenter and hosting provider IPs';

COMMIT;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Uncomment to verify setup (for manual testing)
-- SELECT * FROM ip_geolocation LIMIT 5;
-- SELECT * FROM asn_info LIMIT 5;
-- SELECT * FROM country_ip_distribution LIMIT 10;
-- SELECT * FROM top_asns LIMIT 10;
-- SELECT * FROM get_ip_location('8.8.8.8'::inet);
-- SELECT get_ip_country('8.8.8.8'::inet);
-- SELECT is_ip_in_country('8.8.8.8'::inet, ARRAY['US', 'CA']);
-- SELECT * FROM find_ips_in_radius(37.7749, -122.4194, 50);
-- SELECT * FROM get_asn_info(15169);

-- ============================================================================
-- END OF GEOLOCATION SCHEMA
-- ============================================================================
