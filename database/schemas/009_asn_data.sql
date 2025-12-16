-- ============================================================================
-- SafeOps Threat Intelligence Database - ASN Data
-- File: 009_asn_data.sql
-- Purpose: Autonomous System Number tracking, reputation, and network analysis
-- ============================================================================

-- =============================================================================
-- TABLE: asn_data
-- =============================================================================

CREATE TABLE asn_data (
    asn_id INTEGER PRIMARY KEY CHECK (asn_id > 0),
    asn_name VARCHAR(255) NOT NULL,
    organization VARCHAR(255) NOT NULL,
    organization_country CHAR(2),
    registry VARCHAR(20) NOT NULL CHECK (registry IN ('ARIN', 'RIPE', 'APNIC', 'LACNIC', 'AFRINIC')),
    registration_date DATE,
    asn_type VARCHAR(50) CHECK (asn_type IN (
        'ISP', 'HOSTING', 'ENTERPRISE', 'EDUCATION', 'GOVERNMENT', 
        'CDN', 'CLOUD', 'CONTENT', 'EYEBALL', 'TRANSIT'
    )),
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN -100 AND 100),
    confidence_level DECIMAL(3,2) DEFAULT 0.50 CHECK (confidence_level BETWEEN 0.00 AND 1.00),
    total_ip_count BIGINT,
    abuse_contact VARCHAR(255),
    abuse_phone VARCHAR(50),
    noc_contact VARCHAR(255),
    website TEXT,
    is_transit_provider BOOLEAN DEFAULT false,
    is_hosting_provider BOOLEAN DEFAULT false,
    is_vpn_provider BOOLEAN DEFAULT false,
    risk_level INTEGER DEFAULT 3 CHECK (risk_level BETWEEN 1 AND 10),
    commonly_abused BOOLEAN DEFAULT false,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for asn_data
CREATE INDEX idx_asn_data_organization ON asn_data(organization);
CREATE INDEX idx_asn_data_country ON asn_data(organization_country);
CREATE INDEX idx_asn_data_registry ON asn_data(registry);
CREATE INDEX idx_asn_data_type ON asn_data(asn_type);
CREATE INDEX idx_asn_data_reputation ON asn_data(reputation_score);
CREATE INDEX idx_asn_data_risk_abused ON asn_data(risk_level, commonly_abused);
CREATE INDEX idx_asn_data_providers ON asn_data(is_hosting_provider, is_vpn_provider);

COMMENT ON TABLE asn_data IS 'Primary table storing ASN information and metadata';
COMMENT ON COLUMN asn_data.asn_id IS 'Autonomous System Number';
COMMENT ON COLUMN asn_data.registry IS 'Regional Internet Registry: ARIN, RIPE, APNIC, LACNIC, AFRINIC';

-- =============================================================================
-- TABLE: asn_prefixes
-- =============================================================================

CREATE TABLE asn_prefixes (
    prefix_id BIGSERIAL PRIMARY KEY,
    asn_id INTEGER NOT NULL,
    ip_prefix CIDR NOT NULL,
    prefix_description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    bgp_origin VARCHAR(20) CHECK (bgp_origin IN ('IGP', 'EGP', 'INCOMPLETE')),
    country_code CHAR(2),
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN -100 AND 100),
    threat_count INTEGER DEFAULT 0 CHECK (threat_count >= 0),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (asn_id) REFERENCES asn_data(asn_id) ON DELETE CASCADE
);

-- Indexes for asn_prefixes
CREATE INDEX idx_asn_prefixes_asn ON asn_prefixes(asn_id);
CREATE INDEX idx_asn_prefixes_country ON asn_prefixes(country_code);
CREATE INDEX idx_asn_prefixes_active_seen ON asn_prefixes(is_active, last_seen DESC);
CREATE INDEX idx_asn_prefixes_reputation ON asn_prefixes(reputation_score);
CREATE INDEX idx_asn_prefixes_threats ON asn_prefixes(threat_count);
CREATE INDEX idx_asn_prefixes_gist ON asn_prefixes USING gist(ip_prefix inet_ops);

COMMENT ON TABLE asn_prefixes IS 'IP prefixes announced by each ASN';
COMMENT ON COLUMN asn_prefixes.bgp_origin IS 'BGP origin type: IGP, EGP, INCOMPLETE';

-- =============================================================================
-- TABLE: asn_reputation_history (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE asn_reputation_history (
    history_id BIGSERIAL,
    asn_id INTEGER NOT NULL,
    old_score INTEGER,
    new_score INTEGER,
    score_delta INTEGER,
    change_reason VARCHAR(100) CHECK (change_reason IN (
        'THREAT_INCREASE', 'THREAT_DECREASE', 'ABUSE_REPORT', 
        'CLEANUP', 'MANUAL_ADJUSTMENT', 'FEED_UPDATE'
    )),
    threat_count_delta INTEGER,
    changed_by VARCHAR(100),
    metadata JSONB DEFAULT '{}',
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    PRIMARY KEY (history_id, changed_at),
    FOREIGN KEY (asn_id) REFERENCES asn_data(asn_id) ON DELETE CASCADE
) PARTITION BY RANGE (changed_at);

-- Indexes for asn_reputation_history
CREATE INDEX idx_asn_rep_history_asn ON asn_reputation_history(asn_id);
CREATE INDEX idx_asn_rep_history_changed ON asn_reputation_history(changed_at);
CREATE INDEX idx_asn_rep_history_asn_time ON asn_reputation_history(asn_id, changed_at DESC);
CREATE INDEX idx_asn_rep_history_reason ON asn_reputation_history(change_reason);
CREATE INDEX idx_asn_rep_history_metadata ON asn_reputation_history USING gin(metadata);

COMMENT ON TABLE asn_reputation_history IS 'Track ASN reputation changes over time (partitioned monthly)';

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
        partition_name := 'asn_reputation_history_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF asn_reputation_history
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: asn_peering
-- =============================================================================

CREATE TABLE asn_peering (
    peering_id BIGSERIAL PRIMARY KEY,
    asn_id INTEGER NOT NULL,
    peer_asn_id INTEGER NOT NULL,
    peering_type VARCHAR(20) NOT NULL CHECK (peering_type IN (
        'CUSTOMER', 'PROVIDER', 'PEER', 'IX', 'SIBLING'
    )),
    relationship VARCHAR(20) CHECK (relationship IN (
        'UPSTREAM', 'DOWNSTREAM', 'LATERAL', 'MUTUAL'
    )),
    exchange_point VARCHAR(255),
    first_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_observed TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (asn_id) REFERENCES asn_data(asn_id) ON DELETE CASCADE,
    FOREIGN KEY (peer_asn_id) REFERENCES asn_data(asn_id) ON DELETE CASCADE,
    
    CONSTRAINT unique_asn_peering UNIQUE (asn_id, peer_asn_id, peering_type),
    CONSTRAINT prevent_self_peering CHECK (asn_id != peer_asn_id)
);

-- Indexes for asn_peering
CREATE INDEX idx_asn_peering_asn ON asn_peering(asn_id);
CREATE INDEX idx_asn_peering_peer ON asn_peering(peer_asn_id);
CREATE INDEX idx_asn_peering_type ON asn_peering(peering_type);
CREATE INDEX idx_asn_peering_active ON asn_peering(is_active);
CREATE INDEX idx_asn_peering_metadata ON asn_peering USING gin(metadata);

COMMENT ON TABLE asn_peering IS 'Track ASN peering relationships for network topology';
COMMENT ON COLUMN asn_peering.peering_type IS 'CUSTOMER=pays for transit, PROVIDER=provides transit, PEER=settlement-free, IX=internet exchange';

-- =============================================================================
-- TABLE: asn_abuse_reports (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE asn_abuse_reports (
    report_id BIGSERIAL,
    asn_id INTEGER NOT NULL,
    report_type VARCHAR(50) NOT NULL CHECK (report_type IN (
        'SPAM', 'MALWARE', 'PHISHING', 'BOTNET', 'SCANNING', 
        'DDOS', 'FRAUD', 'ABUSE', 'COPYRIGHT'
    )),
    reported_ip INET,
    reported_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    reported_by VARCHAR(100),
    severity INTEGER DEFAULT 5 CHECK (severity BETWEEN 1 AND 10),
    description TEXT,
    evidence JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'OPEN' CHECK (status IN (
        'OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'DISMISSED', 'ESCALATED'
    )),
    resolution_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (report_id, reported_at),
    FOREIGN KEY (asn_id) REFERENCES asn_data(asn_id) ON DELETE CASCADE
) PARTITION BY RANGE (reported_at);

-- Indexes for asn_abuse_reports
CREATE INDEX idx_asn_abuse_asn ON asn_abuse_reports(asn_id);
CREATE INDEX idx_asn_abuse_type ON asn_abuse_reports(report_type);
CREATE INDEX idx_asn_abuse_reported ON asn_abuse_reports(reported_at);
CREATE INDEX idx_asn_abuse_ip ON asn_abuse_reports(reported_ip);
CREATE INDEX idx_asn_abuse_severity ON asn_abuse_reports(severity);
CREATE INDEX idx_asn_abuse_status ON asn_abuse_reports(status);
CREATE INDEX idx_asn_abuse_pending ON asn_abuse_reports(asn_id, status, reported_at DESC);
CREATE INDEX idx_asn_abuse_evidence ON asn_abuse_reports USING gin(evidence);

COMMENT ON TABLE asn_abuse_reports IS 'Track abuse reports associated with ASNs (partitioned monthly)';
COMMENT ON COLUMN asn_abuse_reports.status IS 'Workflow: OPEN → ACKNOWLEDGED → RESOLVED/DISMISSED';

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
        partition_name := 'asn_abuse_reports_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF asn_abuse_reports
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        
        RAISE NOTICE 'Created partition: % for range [%, %)', partition_name, start_date, end_date;
    END LOOP;
END $$;

-- =============================================================================
-- TABLE: asn_statistics (PARTITIONED BY MONTH)
-- =============================================================================

CREATE TABLE asn_statistics (
    stat_id BIGSERIAL,
    asn_id INTEGER NOT NULL,
    stat_period_start TIMESTAMP WITH TIME ZONE,
    stat_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    total_threats_detected INTEGER DEFAULT 0 CHECK (total_threats_detected >= 0),
    unique_malicious_ips INTEGER DEFAULT 0 CHECK (unique_malicious_ips >= 0),
    spam_incidents INTEGER DEFAULT 0 CHECK (spam_incidents >= 0),
    malware_incidents INTEGER DEFAULT 0 CHECK (malware_incidents >= 0),
    scan_incidents INTEGER DEFAULT 0 CHECK (scan_incidents >= 0),
    ddos_incidents INTEGER DEFAULT 0 CHECK (ddos_incidents >= 0),
    total_connections BIGINT DEFAULT 0 CHECK (total_connections >= 0),
    blocked_connections BIGINT DEFAULT 0 CHECK (blocked_connections >= 0),
    bytes_transferred BIGINT DEFAULT 0 CHECK (bytes_transferred >= 0),
    average_threat_severity DECIMAL(4,2) CHECK (average_threat_severity BETWEEN 0.00 AND 10.00),
    reputation_trend VARCHAR(20) CHECK (reputation_trend IN (
        'IMPROVING', 'STABLE', 'DECLINING', 'UNKNOWN'
    )),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (stat_id, stat_period_end),
    FOREIGN KEY (asn_id) REFERENCES asn_data(asn_id) ON DELETE CASCADE,
    
    CONSTRAINT check_stat_period CHECK (stat_period_end > stat_period_start)
) PARTITION BY RANGE (stat_period_end);

-- Indexes for asn_statistics
CREATE INDEX idx_asn_stats_asn ON asn_statistics(asn_id);
CREATE INDEX idx_asn_stats_period_end ON asn_statistics(stat_period_end);
CREATE INDEX idx_asn_stats_asn_period ON asn_statistics(asn_id, stat_period_end DESC);
CREATE INDEX idx_asn_stats_threats ON asn_statistics(total_threats_detected);
CREATE INDEX idx_asn_stats_trend ON asn_statistics(reputation_trend);

COMMENT ON TABLE asn_statistics IS 'Aggregate statistics for ASN traffic and threats (partitioned monthly)';
COMMENT ON COLUMN asn_statistics.reputation_trend IS 'IMPROVING, STABLE, or DECLINING based on recent activity';

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
        partition_name := 'asn_statistics_' || TO_CHAR(partition_date, 'YYYY_MM');
        start_date := partition_date::TIMESTAMP WITH TIME ZONE;
        end_date := (partition_date + INTERVAL '1 month')::TIMESTAMP WITH TIME ZONE;
        
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF asn_statistics
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
CREATE OR REPLACE FUNCTION update_asn_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_asn_data_updated
    BEFORE UPDATE ON asn_data
    FOR EACH ROW EXECUTE FUNCTION update_asn_updated_at();

CREATE TRIGGER trigger_asn_prefixes_updated
    BEFORE UPDATE ON asn_prefixes
    FOR EACH ROW EXECUTE FUNCTION update_asn_updated_at();

-- Auto-log ASN reputation changes
CREATE OR REPLACE FUNCTION log_asn_reputation_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.reputation_score IS DISTINCT FROM NEW.reputation_score THEN
        INSERT INTO asn_reputation_history (
            asn_id, old_score, new_score, score_delta, 
            change_reason, changed_by, changed_at
        ) VALUES (
            NEW.asn_id,
            OLD.reputation_score,
            NEW.reputation_score,
            NEW.reputation_score - OLD.reputation_score,
            'FEED_UPDATE',
            current_user,
            NOW()
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_log_asn_reputation_change
    AFTER UPDATE ON asn_data
    FOR EACH ROW EXECUTE FUNCTION log_asn_reputation_change();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Lookup ASN for an IP address
CREATE OR REPLACE FUNCTION get_asn_for_ip(search_ip INET)
RETURNS TABLE (
    asn_id INTEGER,
    asn_name VARCHAR(255),
    organization VARCHAR(255),
    reputation_score INTEGER,
    risk_level INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.asn_id,
        a.asn_name,
        a.organization,
        a.reputation_score,
        a.risk_level
    FROM asn_prefixes p
    JOIN asn_data a ON a.asn_id = p.asn_id
    WHERE search_ip <<= p.ip_prefix
      AND p.is_active = true
    ORDER BY masklen(p.ip_prefix) DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_asn_for_ip IS 'Lookup ASN information for an IP address';

-- Function: Get ASN reputation summary
CREATE OR REPLACE FUNCTION get_asn_reputation(search_asn_id INTEGER)
RETURNS TABLE (
    asn_id INTEGER,
    asn_name VARCHAR(255),
    organization VARCHAR(255),
    reputation_score INTEGER,
    risk_level INTEGER,
    prefix_count BIGINT,
    open_abuse_reports BIGINT,
    recent_threats BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.asn_id,
        a.asn_name,
        a.organization,
        a.reputation_score,
        a.risk_level,
        COUNT(DISTINCT p.prefix_id) AS prefix_count,
        COUNT(DISTINCT r.report_id) FILTER (WHERE r.status = 'OPEN') AS open_abuse_reports,
        COUNT(DISTINCT s.stat_id) FILTER (
            WHERE s.stat_period_end >= NOW() - INTERVAL '7 days'
        ) AS recent_threats
    FROM asn_data a
    LEFT JOIN asn_prefixes p ON p.asn_id = a.asn_id AND p.is_active = true
    LEFT JOIN asn_abuse_reports r ON r.asn_id = a.asn_id
    LEFT JOIN asn_statistics s ON s.asn_id = a.asn_id
    WHERE a.asn_id = search_asn_id
    GROUP BY a.asn_id, a.asn_name, a.organization, a.reputation_score, a.risk_level;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_asn_reputation IS 'Get comprehensive reputation data for an ASN';

-- Function: Get ASN peers
CREATE OR REPLACE FUNCTION get_asn_peers(search_asn_id INTEGER)
RETURNS TABLE (
    peer_asn_id INTEGER,
    peer_name VARCHAR(255),
    peering_type VARCHAR(20),
    relationship VARCHAR(20)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        p.peer_asn_id,
        a.asn_name,
        p.peering_type,
        p.relationship
    FROM asn_peering p
    JOIN asn_data a ON a.asn_id = p.peer_asn_id
    WHERE p.asn_id = search_asn_id
      AND p.is_active = true
    ORDER BY p.peering_type, a.asn_name;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_asn_peers IS 'Get active peering relationships for an ASN';

-- Function: Record abuse report
CREATE OR REPLACE FUNCTION record_asn_abuse(
    p_asn_id INTEGER,
    p_report_type VARCHAR(50),
    p_reported_ip INET DEFAULT NULL,
    p_severity INTEGER DEFAULT 5,
    p_description TEXT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    v_report_id BIGINT;
BEGIN
    INSERT INTO asn_abuse_reports (
        asn_id, report_type, reported_ip, severity, description, reported_by
    ) VALUES (
        p_asn_id, p_report_type, p_reported_ip, p_severity, p_description, current_user
    ) RETURNING report_id INTO v_report_id;
    
    -- Update ASN commonly_abused flag if many open reports
    UPDATE asn_data
    SET commonly_abused = true,
        updated_at = NOW()
    WHERE asn_id = p_asn_id
      AND (SELECT COUNT(*) FROM asn_abuse_reports 
           WHERE asn_id = p_asn_id AND status = 'OPEN') >= 10;
    
    RETURN v_report_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION record_asn_abuse IS 'Record an abuse report for an ASN';

-- Function: Get high-risk ASNs
CREATE OR REPLACE FUNCTION get_high_risk_asns(p_min_risk INTEGER DEFAULT 7)
RETURNS TABLE (
    asn_id INTEGER,
    asn_name VARCHAR(255),
    organization VARCHAR(255),
    risk_level INTEGER,
    reputation_score INTEGER,
    open_abuse_reports BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.asn_id,
        a.asn_name,
        a.organization,
        a.risk_level,
        a.reputation_score,
        COUNT(r.report_id) FILTER (WHERE r.status = 'OPEN')::BIGINT AS open_abuse_reports
    FROM asn_data a
    LEFT JOIN asn_abuse_reports r ON r.asn_id = a.asn_id
    WHERE a.risk_level >= p_min_risk
       OR a.commonly_abused = true
    GROUP BY a.asn_id, a.asn_name, a.organization, a.risk_level, a.reputation_score
    ORDER BY a.risk_level DESC, open_abuse_reports DESC;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_high_risk_asns IS 'Get high-risk ASNs with abuse report counts';

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
      AND table_name LIKE 'asn_%';
    
    SELECT COUNT(*) INTO index_count FROM pg_indexes 
    WHERE schemaname = 'public' 
      AND tablename LIKE 'asn_%';
    
    SELECT COUNT(*) INTO function_count FROM pg_proc 
    WHERE proname LIKE '%asn%';
    
    RAISE NOTICE '=== ASN Data Schema Initialized ===';
    RAISE NOTICE 'Tables created: %', table_count;
    RAISE NOTICE 'Indexes created: %', index_count;
    RAISE NOTICE 'Functions created: %', function_count;
    RAISE NOTICE 'All 5 RIRs supported: ARIN, RIPE, APNIC, LACNIC, AFRINIC';
    RAISE NOTICE 'GiST indexes enabled for prefix lookups';
    RAISE NOTICE 'Reputation history, abuse reports, and statistics partitioned';
    RAISE NOTICE 'Peering relationships tracking enabled';
END $$;
