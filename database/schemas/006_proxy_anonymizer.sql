-- ============================================================================
-- SafeOps Threat Intelligence Database - Proxy and Anonymizer Detection
-- File: 006_proxy_anonymizer.sql
-- Purpose: Track proxy servers, VPNs, TOR nodes, and anonymization services
-- ============================================================================

-- =============================================================================
-- TABLE: proxy_services
-- =============================================================================

CREATE TABLE proxy_services (
    service_id SERIAL PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL UNIQUE,
    service_type VARCHAR(50) NOT NULL CHECK (service_type IN (
        'VPN', 'PROXY', 'TOR', 'HOSTING_PROXY', 'MOBILE_PROXY', 
        'RESIDENTIAL_PROXY', 'DATACENTER_PROXY', 'WEB_PROXY'
    )),
    provider_website TEXT,
    commercial BOOLEAN DEFAULT false,
    risk_level INTEGER DEFAULT 5 CHECK (risk_level BETWEEN 1 AND 10),
    legitimate_use BOOLEAN DEFAULT true,
    country_of_origin CHAR(2),
    description TEXT,
    detection_confidence DECIMAL(3,2) DEFAULT 0.80 CHECK (detection_confidence BETWEEN 0.00 AND 1.00),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    enabled BOOLEAN DEFAULT true,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for proxy_services
CREATE UNIQUE INDEX idx_proxy_services_name ON proxy_services(service_name);
CREATE INDEX idx_proxy_services_type ON proxy_services(service_type);
CREATE INDEX idx_proxy_services_risk ON proxy_services(risk_level);
CREATE INDEX idx_proxy_services_enabled_risk ON proxy_services(enabled, risk_level DESC);
CREATE INDEX idx_proxy_services_country ON proxy_services(country_of_origin);

COMMENT ON TABLE proxy_services IS 'Track known proxy and anonymizer service providers';
COMMENT ON COLUMN proxy_services.risk_level IS 'Risk level 1-10 (10=highest risk)';
COMMENT ON COLUMN proxy_services.legitimate_use IS 'Whether service has legitimate uses';

-- =============================================================================
-- TABLE: proxy_ip_ranges
-- =============================================================================

CREATE TABLE proxy_ip_ranges (
    range_id BIGSERIAL PRIMARY KEY,
    service_id INTEGER NOT NULL,
    ip_range CIDR NOT NULL,
    asn INTEGER,
    country_code CHAR(2),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_verified TIMESTAMP WITH TIME ZONE,
    confidence DECIMAL(3,2) DEFAULT 0.75 CHECK (confidence BETWEEN 0.00 AND 1.00),
    active BOOLEAN DEFAULT true,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (service_id) REFERENCES proxy_services(service_id) ON DELETE CASCADE
);

-- Indexes for proxy_ip_ranges
CREATE INDEX idx_proxy_ip_ranges_service ON proxy_ip_ranges(service_id);
CREATE INDEX idx_proxy_ip_ranges_asn ON proxy_ip_ranges(asn);
CREATE INDEX idx_proxy_ip_ranges_country ON proxy_ip_ranges(country_code);
CREATE INDEX idx_proxy_ip_ranges_active_seen ON proxy_ip_ranges(active, last_seen DESC);
CREATE INDEX idx_proxy_ip_ranges_gist ON proxy_ip_ranges USING gist(ip_range inet_ops);

COMMENT ON TABLE proxy_ip_ranges IS 'Store IP ranges associated with proxy/VPN services';
COMMENT ON COLUMN proxy_ip_ranges.ip_range IS 'IP range in CIDR notation';

-- =============================================================================
-- TABLE: proxy_detection_log (PARTITIONED BY WEEK)
-- =============================================================================

CREATE TABLE proxy_detection_log (
    detection_id BIGSERIAL,
    ip_address INET NOT NULL,
    service_id INTEGER,
    detection_method VARCHAR(50) NOT NULL CHECK (detection_method IN (
        'IP_RANGE', 'DNS_LEAK', 'HEADER_ANALYSIS', 'TIMING_ANALYSIS', 
        'BEHAVIOR', 'PORT_PATTERN', 'TLS_FINGERPRINT'
    )),
    detection_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    confidence DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence BETWEEN 0.00 AND 1.00),
    source_ip INET,
    detected_by VARCHAR(100),
    connection_count INTEGER DEFAULT 1,
    data_transferred BIGINT DEFAULT 0,
    protocols_used TEXT[],
    indicators JSONB DEFAULT '{}',
    action_taken VARCHAR(50) CHECK (action_taken IN (
        'LOGGED', 'ALERTED', 'BLOCKED', 'RATE_LIMITED', 'CHALLENGED'
    )),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (detection_id, detection_timestamp),
    FOREIGN KEY (service_id) REFERENCES proxy_services(service_id) ON DELETE SET NULL
) PARTITION BY RANGE (detection_timestamp);

-- Indexes for proxy_detection_log
CREATE INDEX idx_proxy_detection_ip ON proxy_detection_log(ip_address);
CREATE INDEX idx_proxy_detection_service ON proxy_detection_log(service_id);
CREATE INDEX idx_proxy_detection_timestamp ON proxy_detection_log(detection_timestamp);
CREATE INDEX idx_proxy_detection_method ON proxy_detection_log(detection_method);
CREATE INDEX idx_proxy_detection_confidence ON proxy_detection_log(confidence);
CREATE INDEX idx_proxy_detection_action ON proxy_detection_log(action_taken);
CREATE INDEX idx_proxy_detection_protocols ON proxy_detection_log USING gin(protocols_used);
CREATE INDEX idx_proxy_detection_indicators ON proxy_detection_log USING gin(indicators);

COMMENT ON TABLE proxy_detection_log IS 'Log detections of proxy/anonymizer traffic (partitioned weekly)';
COMMENT ON COLUMN proxy_detection_log.detection_method IS 'IP_RANGE, DNS_LEAK, HEADER_ANALYSIS, TIMING_ANALYSIS, etc.';

-- Create initial partitions (current week + next 3 weeks)
DO $$
DECLARE
    partition_date DATE;
    partition_name TEXT;
    start_date TIMESTAMP WITH TIME ZONE;
    end_date TIMESTAMP WITH TIME ZONE;
BEGIN
    FOR i IN 0..3 LOOP
        partition_date := DATE_TRUNC('week', CURRENT_DATE + (i || ' weeks')::INTERVAL)::DATE;
        partition_name := 'proxy_detection_log_' || TO_CHAR(partition_date, 'IYYY_IW');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 week')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF proxy_detection_log
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: tor_exit_nodes
-- =============================================================================

CREATE TABLE tor_exit_nodes (
    node_id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    fingerprint VARCHAR(40),
    nickname VARCHAR(19),
    country_code CHAR(2),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    bandwidth BIGINT,
    uptime INTEGER,
    consensus_weight INTEGER,
    exit_policy TEXT,
    flags TEXT[],
    contact_info TEXT,
    is_active BOOLEAN DEFAULT true,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT check_nickname_length CHECK (length(nickname) <= 19)
);

-- Indexes for tor_exit_nodes
CREATE UNIQUE INDEX idx_tor_exit_nodes_ip ON tor_exit_nodes(ip_address);
CREATE INDEX idx_tor_exit_nodes_fingerprint ON tor_exit_nodes(fingerprint);
CREATE INDEX idx_tor_exit_nodes_country ON tor_exit_nodes(country_code);
CREATE INDEX idx_tor_exit_nodes_active_seen ON tor_exit_nodes(is_active, last_seen DESC);
CREATE INDEX idx_tor_exit_nodes_updated ON tor_exit_nodes(last_updated);
CREATE INDEX idx_tor_exit_nodes_flags ON tor_exit_nodes USING gin(flags);

COMMENT ON TABLE tor_exit_nodes IS 'Track TOR exit node IP addresses';
COMMENT ON COLUMN tor_exit_nodes.fingerprint IS 'TOR node fingerprint (hex)';
COMMENT ON COLUMN tor_exit_nodes.nickname IS 'TOR node nickname (max 19 chars)';

-- =============================================================================
-- TABLE: hosting_providers
-- =============================================================================

CREATE TABLE hosting_providers (
    provider_id SERIAL PRIMARY KEY,
    provider_name VARCHAR(255) NOT NULL UNIQUE,
    provider_type VARCHAR(50) NOT NULL CHECK (provider_type IN (
        'CLOUD', 'DEDICATED', 'VPS', 'COLOCATION', 'CDN', 'SHARED_HOSTING'
    )),
    asn_list INTEGER[],
    country_of_origin CHAR(2),
    risk_score INTEGER DEFAULT 3 CHECK (risk_score BETWEEN 1 AND 10),
    commonly_used_for_proxies BOOLEAN DEFAULT false,
    terms_of_service_url TEXT,
    abuse_contact VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for hosting_providers
CREATE UNIQUE INDEX idx_hosting_providers_name ON hosting_providers(provider_name);
CREATE INDEX idx_hosting_providers_type ON hosting_providers(provider_type);
CREATE INDEX idx_hosting_providers_risk ON hosting_providers(risk_score);
CREATE INDEX idx_hosting_providers_proxy_usage ON hosting_providers(commonly_used_for_proxies);
CREATE INDEX idx_hosting_providers_asn ON hosting_providers USING gin(asn_list);

COMMENT ON TABLE hosting_providers IS 'Track hosting providers commonly used for proxies';
COMMENT ON COLUMN hosting_providers.asn_list IS 'Array of ASNs owned by provider';
COMMENT ON COLUMN hosting_providers.risk_score IS 'Risk score 1-10 for proxy usage';

-- =============================================================================
-- TABLE: anonymizer_detection_rules
-- =============================================================================

CREATE TABLE anonymizer_detection_rules (
    rule_id SERIAL PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL UNIQUE,
    rule_type VARCHAR(50) NOT NULL CHECK (rule_type IN (
        'IP_RANGE', 'HEADER_PATTERN', 'BEHAVIOR', 'PROTOCOL_ANALYSIS', 
        'TLS_FINGERPRINT', 'DNS_PATTERN', 'TIMING_PATTERN'
    )),
    detection_pattern TEXT NOT NULL,
    service_type VARCHAR(50),
    confidence_weight DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence_weight BETWEEN 0.00 AND 1.00),
    enabled BOOLEAN DEFAULT true,
    false_positive_rate DECIMAL(5,4) DEFAULT 0.0100 CHECK (false_positive_rate BETWEEN 0.0000 AND 1.0000),
    description TEXT,
    created_by VARCHAR(100),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for anonymizer_detection_rules
CREATE UNIQUE INDEX idx_anon_rules_name ON anonymizer_detection_rules(rule_name);
CREATE INDEX idx_anon_rules_type ON anonymizer_detection_rules(rule_type);
CREATE INDEX idx_anon_rules_service ON anonymizer_detection_rules(service_type);
CREATE INDEX idx_anon_rules_enabled ON anonymizer_detection_rules(enabled);
CREATE INDEX idx_anon_rules_confidence ON anonymizer_detection_rules(confidence_weight);

COMMENT ON TABLE anonymizer_detection_rules IS 'Define detection rules for identifying anonymizer traffic';
COMMENT ON COLUMN anonymizer_detection_rules.false_positive_rate IS 'Historical false positive rate';

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_proxy_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_proxy_services_updated
    BEFORE UPDATE ON proxy_services
    FOR EACH ROW EXECUTE FUNCTION update_proxy_updated_at();

CREATE TRIGGER trigger_proxy_ip_ranges_updated
    BEFORE UPDATE ON proxy_ip_ranges
    FOR EACH ROW EXECUTE FUNCTION update_proxy_updated_at();

CREATE TRIGGER trigger_hosting_providers_updated
    BEFORE UPDATE ON hosting_providers
    FOR EACH ROW EXECUTE FUNCTION update_proxy_updated_at();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Check if IP is in any proxy range
CREATE OR REPLACE FUNCTION is_proxy_ip(search_ip INET)
RETURNS TABLE (
    is_proxy BOOLEAN,
    service_name VARCHAR(255),
    service_type VARCHAR(50),
    risk_level INTEGER,
    confidence DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        TRUE,
        ps.service_name,
        ps.service_type,
        ps.risk_level,
        pr.confidence
    FROM proxy_ip_ranges pr
    JOIN proxy_services ps ON ps.service_id = pr.service_id
    WHERE search_ip <<= pr.ip_range
      AND pr.active = true
      AND ps.enabled = true
    ORDER BY pr.confidence DESC, ps.risk_level DESC
    LIMIT 1;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::VARCHAR(255), NULL::VARCHAR(50), NULL::INTEGER, NULL::DECIMAL;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION is_proxy_ip IS 'Check if IP is in any known proxy/VPN range';

-- Function: Check if IP is TOR exit node
CREATE OR REPLACE FUNCTION is_tor_exit_node(search_ip INET)
RETURNS TABLE (
    is_tor BOOLEAN,
    nickname VARCHAR(19),
    country_code CHAR(2),
    last_seen TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        TRUE,
        t.nickname,
        t.country_code,
        t.last_seen
    FROM tor_exit_nodes t
    WHERE t.ip_address = search_ip
      AND t.is_active = true
    LIMIT 1;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::VARCHAR(19), NULL::CHAR(2), NULL::TIMESTAMP WITH TIME ZONE;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION is_tor_exit_node IS 'Check if IP is an active TOR exit node';

-- Function: Record proxy detection
CREATE OR REPLACE FUNCTION record_proxy_detection(
    p_ip_address INET,
    p_detection_method VARCHAR(50),
    p_service_id INTEGER DEFAULT NULL,
    p_confidence DECIMAL DEFAULT 0.50,
    p_action_taken VARCHAR(50) DEFAULT 'LOGGED'
) RETURNS BIGINT AS $$
DECLARE
    v_detection_id BIGINT;
BEGIN
    INSERT INTO proxy_detection_log (
        ip_address, service_id, detection_method, confidence, action_taken
    ) VALUES (
        p_ip_address, p_service_id, p_detection_method, p_confidence, p_action_taken
    ) RETURNING detection_id INTO v_detection_id;
    
    RETURN v_detection_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION record_proxy_detection IS 'Record a proxy/VPN detection event';

-- Function: Get proxy statistics
CREATE OR REPLACE FUNCTION get_proxy_statistics(p_days INTEGER DEFAULT 7)
RETURNS TABLE (
    service_name VARCHAR(255),
    service_type VARCHAR(50),
    detection_count BIGINT,
    unique_ips BIGINT,
    avg_confidence DECIMAL,
    blocked_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ps.service_name,
        ps.service_type,
        COUNT(*)::BIGINT AS detection_count,
        COUNT(DISTINCT pdl.ip_address)::BIGINT AS unique_ips,
        AVG(pdl.confidence)::DECIMAL(5,2) AS avg_confidence,
        COUNT(*) FILTER (WHERE pdl.action_taken = 'BLOCKED')::BIGINT AS blocked_count
    FROM proxy_detection_log pdl
    LEFT JOIN proxy_services ps ON ps.service_id = pdl.service_id
    WHERE pdl.detection_timestamp >= NOW() - (p_days || ' days')::INTERVAL
    GROUP BY ps.service_name, ps.service_type
    ORDER BY detection_count DESC;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_proxy_statistics IS 'Get proxy detection statistics for the last N days';

-- Function: Update TOR exit node list (called by external feed updater)
CREATE OR REPLACE FUNCTION upsert_tor_exit_node(
    p_ip_address INET,
    p_fingerprint VARCHAR(40),
    p_nickname VARCHAR(19),
    p_country_code CHAR(2),
    p_flags TEXT[]
) RETURNS INTEGER AS $$
DECLARE
    v_node_id INTEGER;
BEGIN
    INSERT INTO tor_exit_nodes (
        ip_address, fingerprint, nickname, country_code, flags, 
        is_active, last_seen, last_updated
    ) VALUES (
        p_ip_address, p_fingerprint, p_nickname, p_country_code, p_flags,
        TRUE, NOW(), NOW()
    )
    ON CONFLICT (ip_address) DO UPDATE SET
        fingerprint = EXCLUDED.fingerprint,
        nickname = EXCLUDED.nickname,
        country_code = EXCLUDED.country_code,
        flags = EXCLUDED.flags,
        is_active = TRUE,
        last_seen = NOW(),
        last_updated = NOW()
    RETURNING node_id INTO v_node_id;
    
    RETURN v_node_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION upsert_tor_exit_node IS 'Insert or update TOR exit node information';

-- Function: Mark stale TOR nodes as inactive
CREATE OR REPLACE FUNCTION cleanup_stale_tor_nodes(p_hours INTEGER DEFAULT 24)
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE tor_exit_nodes
    SET is_active = false, last_updated = NOW()
    WHERE is_active = true
      AND last_seen < NOW() - (p_hours || ' hours')::INTERVAL;
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_stale_tor_nodes IS 'Mark TOR nodes as inactive if not seen in N hours';

-- Function: Get high-risk proxy services
CREATE OR REPLACE FUNCTION get_high_risk_proxies(p_min_risk INTEGER DEFAULT 7)
RETURNS TABLE (
    service_name VARCHAR(255),
    service_type VARCHAR(50),
    risk_level INTEGER,
    ip_range_count BIGINT,
    recent_detections BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ps.service_name,
        ps.service_type,
        ps.risk_level,
        COUNT(DISTINCT pr.range_id)::BIGINT AS ip_range_count,
        COUNT(DISTINCT pdl.detection_id) FILTER (
            WHERE pdl.detection_timestamp >= NOW() - INTERVAL '7 days'
        )::BIGINT AS recent_detections
    FROM proxy_services ps
    LEFT JOIN proxy_ip_ranges pr ON pr.service_id = ps.service_id AND pr.active = true
    LEFT JOIN proxy_detection_log pdl ON pdl.service_id = ps.service_id
    WHERE ps.risk_level >= p_min_risk
      AND ps.enabled = true
    GROUP BY ps.service_id, ps.service_name, ps.service_type, ps.risk_level
    ORDER BY ps.risk_level DESC, recent_detections DESC;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_high_risk_proxies IS 'Get high-risk proxy services with detection stats';

-- =============================================================================
-- INITIAL DATA
-- =============================================================================

-- Insert common proxy/VPN services
INSERT INTO proxy_services (service_name, service_type, risk_level, legitimate_use, commercial) VALUES
('TOR Network', 'TOR', 7, true, false),
('NordVPN', 'VPN', 4, true, true),
('ExpressVPN', 'VPN', 4, true, true),
('ProtonVPN', 'VPN', 3, true, true),
('HideMyAss', 'VPN', 5, true, true),
('Unknown Public Proxy', 'PROXY', 8, false, false),
('Unknown Residential Proxy', 'RESIDENTIAL_PROXY', 9, false, false)
ON CONFLICT (service_name) DO NOTHING;

-- Insert common hosting providers
INSERT INTO hosting_providers (provider_name, provider_type, risk_score, commonly_used_for_proxies) VALUES
('Amazon Web Services', 'CLOUD', 4, true),
('DigitalOcean', 'CLOUD', 5, true),
('OVH', 'CLOUD', 6, true),
('Hetzner', 'DEDICATED', 5, true),
('Vultr', 'VPS', 5, true),
('Linode', 'VPS', 4, true),
('Cloudflare', 'CDN', 3, false)
ON CONFLICT (provider_name) DO NOTHING;

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
      AND (table_name LIKE 'proxy_%' OR table_name LIKE 'tor_%' 
           OR table_name LIKE 'hosting_%' OR table_name LIKE 'anonymizer_%');
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public' 
      AND (tablename LIKE 'proxy_%' OR tablename LIKE 'tor_%' 
           OR tablename LIKE 'hosting_%' OR tablename LIKE 'anonymizer_%');
    
    SELECT COUNT(*) INTO function_count FROM pg_proc 
    WHERE proname LIKE '%proxy%' OR proname LIKE '%tor%';
    
    RAISE NOTICE '=== Proxy/Anonymizer Detection Schema Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Functions created: %', function_count;
    RAISE NOTICE 'GiST indexes enabled for CIDR matching';
    RAISE NOTICE 'Detection log partitioned by week';
    RAISE NOTICE 'TOR exit node tracking enabled';
    RAISE NOTICE 'Initial proxy services and hosting providers loaded';
END $$;
