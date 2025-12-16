-- ============================================================================
-- SafeOps Threat Intelligence Database - Geolocation
-- File: 007_geolocation.sql
-- Purpose: IP geolocation data for threat analysis and geographic filtering
-- ============================================================================

-- =============================================================================
-- TABLE: ip_geolocation
-- =============================================================================

CREATE TABLE ip_geolocation (
    geo_id BIGSERIAL PRIMARY KEY,
    ip_range_start INET NOT NULL,
    ip_range_end INET NOT NULL,
    country_code CHAR(2) NOT NULL,
    country_name VARCHAR(100),
    region_code VARCHAR(10),
    region_name VARCHAR(100),
    city_name VARCHAR(100),
    postal_code VARCHAR(20),
    latitude DECIMAL(10,7) CHECK (latitude BETWEEN -90.0000000 AND 90.0000000),
    longitude DECIMAL(10,7) CHECK (longitude BETWEEN -180.0000000 AND 180.0000000),
    timezone VARCHAR(50),
    metro_code INTEGER,
    accuracy_radius INTEGER CHECK (accuracy_radius >= 0),
    asn INTEGER,
    organization VARCHAR(255),
    isp VARCHAR(255),
    connection_type VARCHAR(50) CHECK (connection_type IN (
        'RESIDENTIAL', 'BUSINESS', 'CELLULAR', 'SATELLITE', 'DIALUP', 'CABLE', 'DSL', 'FIBER'
    )),
    user_type VARCHAR(50) CHECK (user_type IN (
        'RESIDENTIAL', 'BUSINESS', 'GOVERNMENT', 'MILITARY', 'EDUCATION', 
        'LIBRARY', 'CONTENT_DELIVERY', 'HOSTING'
    )),
    data_source VARCHAR(100),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT check_ip_range_order CHECK (ip_range_end >= ip_range_start)
);

-- Indexes for ip_geolocation
CREATE INDEX idx_ip_geolocation_country ON ip_geolocation(country_code);
CREATE INDEX idx_ip_geolocation_coords ON ip_geolocation(latitude, longitude);
CREATE INDEX idx_ip_geolocation_asn ON ip_geolocation(asn);
CREATE INDEX idx_ip_geolocation_connection ON ip_geolocation(connection_type);
CREATE INDEX idx_ip_geolocation_user_type ON ip_geolocation(user_type);
CREATE INDEX idx_ip_geolocation_gist ON ip_geolocation USING gist(ip_range_start inet_ops, ip_range_end inet_ops);
CREATE INDEX idx_ip_geolocation_updated ON ip_geolocation(last_updated);

COMMENT ON TABLE ip_geolocation IS 'Primary table storing geolocation data for IP addresses and ranges';
COMMENT ON COLUMN ip_geolocation.accuracy_radius IS 'Accuracy radius in kilometers';
COMMENT ON COLUMN ip_geolocation.timezone IS 'IANA timezone identifier (e.g., America/New_York)';

-- =============================================================================
-- TABLE: country_info
-- =============================================================================

CREATE TABLE country_info (
    country_code CHAR(2) PRIMARY KEY,
    country_name VARCHAR(100) NOT NULL,
    country_name_native VARCHAR(100),
    iso3 CHAR(3) UNIQUE,
    continent_code CHAR(2) CHECK (continent_code IN ('AF', 'AN', 'AS', 'EU', 'NA', 'OC', 'SA')),
    continent_name VARCHAR(50),
    capital_city VARCHAR(100),
    currency_code CHAR(3),
    phone_prefix VARCHAR(10),
    tld VARCHAR(10),
    languages TEXT[],
    population BIGINT CHECK (population >= 0),
    area_km2 DECIMAL(15,2) CHECK (area_km2 > 0),
    gdp_usd BIGINT,
    risk_level INTEGER DEFAULT 3 CHECK (risk_level BETWEEN 1 AND 10),
    is_high_risk BOOLEAN DEFAULT false,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for country_info
CREATE UNIQUE INDEX idx_country_info_iso3 ON country_info(iso3);
CREATE INDEX idx_country_info_continent ON country_info(continent_code);
CREATE INDEX idx_country_info_high_risk ON country_info(is_high_risk, risk_level DESC);
CREATE INDEX idx_country_info_languages ON country_info USING gin(languages);

COMMENT ON TABLE country_info IS 'Reference table for country metadata';
COMMENT ON COLUMN country_info.risk_level IS 'Cybersecurity risk level 1-10';
COMMENT ON COLUMN country_info.is_high_risk IS 'High-risk country flag for quick filtering';

-- =============================================================================
-- TABLE: ip_location_history (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE ip_location_history (
    history_id BIGSERIAL,
    ip_address INET NOT NULL,
    old_country_code CHAR(2),
    new_country_code CHAR(2),
    old_city VARCHAR(100),
    new_city VARCHAR(100),
    old_latitude DECIMAL(10,7),
    new_latitude DECIMAL(10,7),
    old_longitude DECIMAL(10,7),
    new_longitude DECIMAL(10,7),
    distance_km INTEGER CHECK (distance_km >= 0),
    change_type VARCHAR(50) CHECK (change_type IN (
        'COUNTRY_CHANGE', 'CITY_CHANGE', 'MINOR_SHIFT', 'RELOCATION', 'DATA_UPDATE'
    )),
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    suspicious BOOLEAN DEFAULT false,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (history_id, detected_at)
) PARTITION BY RANGE (detected_at);

-- Indexes for ip_location_history
CREATE INDEX idx_ip_location_history_ip ON ip_location_history(ip_address);
CREATE INDEX idx_ip_location_history_detected ON ip_location_history(detected_at);
CREATE INDEX idx_ip_location_history_type ON ip_location_history(change_type);
CREATE INDEX idx_ip_location_history_suspicious ON ip_location_history(suspicious, detected_at DESC);
CREATE INDEX idx_ip_location_history_distance ON ip_location_history(distance_km);

COMMENT ON TABLE ip_location_history IS 'Track IP address location changes over time (partitioned monthly)';
COMMENT ON COLUMN ip_location_history.distance_km IS 'Distance between old and new locations in kilometers';

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
        partition_name := 'ip_location_history_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF ip_location_history
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: geographic_threat_zones
-- =============================================================================

CREATE TABLE geographic_threat_zones (
    zone_id SERIAL PRIMARY KEY,
    zone_name VARCHAR(255) NOT NULL UNIQUE,
    countries CHAR(2)[],
    cities TEXT[],
    latitude_min DECIMAL(10,7) CHECK (latitude_min BETWEEN -90 AND 90),
    latitude_max DECIMAL(10,7) CHECK (latitude_max BETWEEN -90 AND 90),
    longitude_min DECIMAL(10,7) CHECK (longitude_min BETWEEN -180 AND 180),
    longitude_max DECIMAL(10,7) CHECK (longitude_max BETWEEN -180 AND 180),
    risk_level INTEGER NOT NULL CHECK (risk_level BETWEEN 1 AND 10),
    threat_types TEXT[],
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    created_by VARCHAR(100),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT check_latitude_range CHECK (latitude_min IS NULL OR latitude_max IS NULL OR latitude_min < latitude_max),
    CONSTRAINT check_longitude_range CHECK (longitude_min IS NULL OR longitude_max IS NULL OR longitude_min < longitude_max)
);

-- Indexes for geographic_threat_zones
CREATE UNIQUE INDEX idx_geo_threat_zones_name ON geographic_threat_zones(zone_name);
CREATE INDEX idx_geo_threat_zones_risk ON geographic_threat_zones(risk_level);
CREATE INDEX idx_geo_threat_zones_enabled ON geographic_threat_zones(enabled);
CREATE INDEX idx_geo_threat_zones_expires ON geographic_threat_zones(expires_at);
CREATE INDEX idx_geo_threat_zones_countries ON geographic_threat_zones USING gin(countries);
CREATE INDEX idx_geo_threat_zones_cities ON geographic_threat_zones USING gin(cities);
CREATE INDEX idx_geo_threat_zones_threats ON geographic_threat_zones USING gin(threat_types);

COMMENT ON TABLE geographic_threat_zones IS 'Define geographic regions with elevated threat levels';
COMMENT ON COLUMN geographic_threat_zones.risk_level IS 'Risk level 1-10 for this geographic zone';

-- =============================================================================
-- TABLE: geo_fencing_rules
-- =============================================================================

CREATE TABLE geo_fencing_rules (
    rule_id SERIAL PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL UNIQUE,
    rule_action VARCHAR(20) NOT NULL CHECK (rule_action IN (
        'ALLOW', 'BLOCK', 'ALERT', 'RATE_LIMIT', 'CHALLENGE'
    )),
    countries_allowed CHAR(2)[],
    countries_blocked CHAR(2)[],
    regions_allowed TEXT[],
    regions_blocked TEXT[],
    rule_priority INTEGER DEFAULT 100 CHECK (rule_priority > 0),
    applies_to VARCHAR(50) CHECK (applies_to IN (
        'ALL', 'INBOUND', 'OUTBOUND', 'MANAGEMENT', 'WEB', 'API'
    )),
    enabled BOOLEAN DEFAULT true,
    description TEXT,
    created_by VARCHAR(100),
    last_modified_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for geo_fencing_rules
CREATE UNIQUE INDEX idx_geo_fencing_name ON geo_fencing_rules(rule_name);
CREATE INDEX idx_geo_fencing_enabled_priority ON geo_fencing_rules(enabled, rule_priority);
CREATE INDEX idx_geo_fencing_action ON geo_fencing_rules(rule_action);
CREATE INDEX idx_geo_fencing_applies ON geo_fencing_rules(applies_to);
CREATE INDEX idx_geo_fencing_countries_allowed ON geo_fencing_rules USING gin(countries_allowed);
CREATE INDEX idx_geo_fencing_countries_blocked ON geo_fencing_rules USING gin(countries_blocked);
CREATE INDEX idx_geo_fencing_regions_allowed ON geo_fencing_rules USING gin(regions_allowed);
CREATE INDEX idx_geo_fencing_regions_blocked ON geo_fencing_rules USING gin(regions_blocked);

COMMENT ON TABLE geo_fencing_rules IS 'Define geofencing rules for traffic filtering';
COMMENT ON COLUMN geo_fencing_rules.rule_priority IS 'Priority (lower number = higher priority)';

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_geo_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_country_info_updated
    BEFORE UPDATE ON country_info
    FOR EACH ROW EXECUTE FUNCTION update_geo_updated_at();

CREATE TRIGGER trigger_geo_threat_zones_updated
    BEFORE UPDATE ON geographic_threat_zones
    FOR EACH ROW EXECUTE FUNCTION update_geo_updated_at();

CREATE TRIGGER trigger_geo_fencing_rules_updated
    BEFORE UPDATE ON geo_fencing_rules
    FOR EACH ROW EXECUTE FUNCTION update_geo_updated_at();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Lookup geolocation for an IP address
CREATE OR REPLACE FUNCTION get_ip_geolocation(search_ip INET)
RETURNS TABLE (
    country_code CHAR(2),
    country_name VARCHAR(100),
    region_name VARCHAR(100),
    city_name VARCHAR(100),
    latitude DECIMAL(10,7),
    longitude DECIMAL(10,7),
    timezone VARCHAR(50),
    asn INTEGER,
    isp VARCHAR(255),
    connection_type VARCHAR(50)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        g.country_code,
        g.country_name,
        g.region_name,
        g.city_name,
        g.latitude,
        g.longitude,
        g.timezone,
        g.asn,
        g.isp,
        g.connection_type
    FROM ip_geolocation g
    WHERE search_ip BETWEEN g.ip_range_start AND g.ip_range_end
    ORDER BY (g.ip_range_end - g.ip_range_start)
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_ip_geolocation IS 'Lookup geolocation data for an IP address';

-- Function: Check if IP is in high-risk country
CREATE OR REPLACE FUNCTION is_high_risk_country(search_ip INET)
RETURNS TABLE (
    is_high_risk BOOLEAN,
    country_code CHAR(2),
    country_name VARCHAR(100),
    risk_level INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.is_high_risk,
        c.country_code,
        c.country_name,
        c.risk_level
    FROM ip_geolocation g
    JOIN country_info c ON c.country_code = g.country_code
    WHERE search_ip BETWEEN g.ip_range_start AND g.ip_range_end
      AND c.is_high_risk = true
    ORDER BY (g.ip_range_end - g.ip_range_start)
    LIMIT 1;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::CHAR(2), NULL::VARCHAR(100), NULL::INTEGER;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION is_high_risk_country IS 'Check if IP is in a high-risk country';

-- Function: Check if IP is in threat zone
CREATE OR REPLACE FUNCTION is_in_threat_zone(search_ip INET)
RETURNS TABLE (
    in_zone BOOLEAN,
    zone_name VARCHAR(255),
    risk_level INTEGER,
    threat_types TEXT[]
) AS $$
DECLARE
    ip_geo RECORD;
BEGIN
    -- First get IP geolocation
    SELECT * INTO ip_geo FROM get_ip_geolocation(search_ip);
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::VARCHAR(255), NULL::INTEGER, NULL::TEXT[];
        RETURN;
    END IF;
    
    -- Check if in any threat zone
    RETURN QUERY
    SELECT 
        TRUE,
        z.zone_name,
        z.risk_level,
        z.threat_types
    FROM geographic_threat_zones z
    WHERE z.enabled = true
      AND (z.expires_at IS NULL OR z.expires_at > NOW())
      AND (
          -- Check country membership
          (ip_geo.country_code = ANY(z.countries))
          OR
          -- Check city membership
          (ip_geo.city_name = ANY(z.cities))
          OR
          -- Check bounding box
          (ip_geo.latitude BETWEEN z.latitude_min AND z.latitude_max
           AND ip_geo.longitude BETWEEN z.longitude_min AND z.longitude_max)
      )
    ORDER BY z.risk_level DESC
    LIMIT 1;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::VARCHAR(255), NULL::INTEGER, NULL::TEXT[];
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION is_in_threat_zone IS 'Check if IP is in any defined geographic threat zone';

-- Function: Evaluate geofencing rules for an IP
CREATE OR REPLACE FUNCTION evaluate_geofencing(search_ip INET, traffic_type VARCHAR(50) DEFAULT 'ALL')
RETURNS TABLE (
    action VARCHAR(20),
    rule_name VARCHAR(255),
    rule_priority INTEGER
) AS $$
DECLARE
    ip_geo RECORD;
BEGIN
    -- Get IP geolocation
    SELECT * INTO ip_geo FROM get_ip_geolocation(search_ip);
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'ALLOW'::VARCHAR(20), 'No geolocation data'::VARCHAR(255), 999::INTEGER;
        RETURN;
    END IF;
    
    -- Evaluate rules in priority order
    RETURN QUERY
    SELECT 
        r.rule_action,
        r.rule_name,
        r.rule_priority
    FROM geo_fencing_rules r
    WHERE r.enabled = true
      AND (r.applies_to = 'ALL' OR r.applies_to = traffic_type)
      AND (
          -- Check blocked countries
          (ip_geo.country_code = ANY(r.countries_blocked))
          OR
          -- Check allowed countries (if whitelist exists, must be in it)
          (r.countries_allowed IS NOT NULL 
           AND array_length(r.countries_allowed, 1) > 0
           AND NOT (ip_geo.country_code = ANY(r.countries_allowed)))
      )
    ORDER BY r.rule_priority ASC
    LIMIT 1;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'ALLOW'::VARCHAR(20), 'Default allow'::VARCHAR(255), 999::INTEGER;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION evaluate_geofencing IS 'Evaluate geofencing rules for an IP address';

-- Function: Calculate distance between two coordinates
CREATE OR REPLACE FUNCTION calculate_distance_km(
    lat1 DECIMAL, lon1 DECIMAL,
    lat2 DECIMAL, lon2 DECIMAL
) RETURNS INTEGER AS $$
DECLARE
    earth_radius CONSTANT DECIMAL := 6371; -- km
    dlat DECIMAL;
    dlon DECIMAL;
    a DECIMAL;
    c DECIMAL;
BEGIN
    -- Haversine formula
    dlat := radians(lat2 - lat1);
    dlon := radians(lon2 - lon1);
    
    a := sin(dlat/2) * sin(dlat/2) + 
         cos(radians(lat1)) * cos(radians(lat2)) * 
         sin(dlon/2) * sin(dlon/2);
    
    c := 2 * atan2(sqrt(a), sqrt(1-a));
    
    RETURN ROUND(earth_radius * c)::INTEGER;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION calculate_distance_km IS 'Calculate distance between two coordinates using Haversine formula';

-- Function: Record IP location change
CREATE OR REPLACE FUNCTION record_location_change(
    p_ip_address INET,
    p_old_country CHAR(2),
    p_new_country CHAR(2),
    p_old_lat DECIMAL,
    p_new_lat DECIMAL,
    p_old_lon DECIMAL,
    p_new_lon DECIMAL
) RETURNS BIGINT AS $$
DECLARE
    v_history_id BIGINT;
    v_distance INTEGER;
    v_change_type VARCHAR(50);
    v_suspicious BOOLEAN := FALSE;
BEGIN
    -- Calculate distance
    v_distance := calculate_distance_km(p_old_lat, p_old_lon, p_new_lat, p_new_lon);
    
    -- Determine change type
    IF p_old_country != p_new_country THEN
        v_change_type := 'COUNTRY_CHANGE';
        -- Country changes over 1000km are suspicious
        IF v_distance > 1000 THEN
            v_suspicious := TRUE;
        END IF;
    ELSIF v_distance > 100 THEN
        v_change_type := 'RELOCATION';
        -- Large relocations within a day could be suspicious
        v_suspicious := TRUE;
    ELSIF v_distance > 10 THEN
        v_change_type := 'CITY_CHANGE';
    ELSE
        v_change_type := 'MINOR_SHIFT';
    END IF;
    
    INSERT INTO ip_location_history (
        ip_address, old_country_code, new_country_code,
        old_latitude, new_latitude, old_longitude, new_longitude,
        distance_km, change_type, suspicious
    ) VALUES (
        p_ip_address, p_old_country, p_new_country,
        p_old_lat, p_new_lat, p_old_lon, p_new_lon,
        v_distance, v_change_type, v_suspicious
    ) RETURNING history_id INTO v_history_id;
    
    RETURN v_history_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION record_location_change IS 'Record IP location change with distance and suspicion calculation';

-- =============================================================================
-- INITIAL DATA
-- =============================================================================

-- Insert sample high-risk countries
INSERT INTO country_info (country_code, country_name, iso3, continent_code, continent_name, risk_level, is_high_risk) VALUES
('KP', 'North Korea', 'PRK', 'AS', 'Asia', 10, true),
('IR', 'Iran', 'IRN', 'AS', 'Asia', 9, true),
('CN', 'China', 'CHN', 'AS', 'Asia', 7, true),
('RU', 'Russia', 'RUS', 'EU', 'Europe', 8, true),
('SY', 'Syria', 'SYR', 'AS', 'Asia', 9, true)
ON CONFLICT (country_code) DO NOTHING;

-- Insert sample geofencing rule
INSERT INTO geo_fencing_rules (
    rule_name, rule_action, countries_blocked, applies_to, rule_priority, description
) VALUES (
    'Block High-Risk Countries', 'BLOCK', ARRAY['KP','IR','SY'], 'ALL', 10,
    'Block traffic from known high-risk countries'
) ON CONFLICT (rule_name) DO NOTHING;

-- =============================================================================
-- VERIFICATION
-- =============================================================================

DO $$
DECLARE
    table_count INTEGER;
    index_count INTEGER;
    function_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO table_count FROM information_schema.tables 
    WHERE table_schema = 'public' 
      AND (table_name LIKE 'ip_%' OR table_name LIKE 'geo%' OR table_name LIKE 'country%');
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public' 
      AND (tablename LIKE 'ip_%' OR tablename LIKE 'geo%' OR tablename LIKE 'country%');
    
    SELECT COUNT(*) INTO function_count FROM pg_proc 
    WHERE proname LIKE '%geo%' OR proname LIKE '%location%';
    
    RAISE NOTICE '=== Geolocation Schema Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Functions created: %', function_count;
    RAISE NOTICE 'GiST indexes enabled for IP range lookups';
    RAISE NOTICE 'Location history partitioned by month';
    RAISE NOTICE 'Geofencing and threat zones configured';
    RAISE NOTICE 'Initial high-risk countries loaded';
END $$;
