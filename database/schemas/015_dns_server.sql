-- DNS Server Database Schema
-- FILE: database/schemas/015_dns_server.sql
-- Version: 1.0
-- Database: PostgreSQL 12+
-- Purpose: Complete relational database structure for the DNS Server component

-- ============================================================================
-- TABLE: dns_zones
-- Purpose: Stores DNS zone definitions the server is authoritative for
-- ============================================================================

CREATE TABLE IF NOT EXISTS dns_zones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,      -- Zone name (e.g., "safeops.local")
    type VARCHAR(20) NOT NULL DEFAULT 'primary', -- "primary" or "secondary"
    description TEXT,                        -- Administrative notes
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dns_zones_name ON dns_zones(name);
CREATE INDEX IF NOT EXISTS idx_dns_zones_type ON dns_zones(type);

-- ============================================================================
-- TABLE: dns_soa
-- Purpose: Start of Authority records for each zone
-- ============================================================================

CREATE TABLE IF NOT EXISTS dns_soa (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    zone_id UUID UNIQUE NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    primary_ns VARCHAR(255) NOT NULL,        -- Primary nameserver (e.g., "ns1.safeops.local")
    admin_email VARCHAR(255) NOT NULL,       -- Admin email in DNS format (admin.safeops.local)
    serial INTEGER NOT NULL DEFAULT 1,       -- Zone version (YYYYMMDDnn format)
    refresh INTEGER NOT NULL DEFAULT 3600,   -- Secondary refresh interval (seconds)
    retry INTEGER NOT NULL DEFAULT 600,      -- Retry after failed refresh (seconds)
    expire INTEGER NOT NULL DEFAULT 604800,  -- Zone expiration time (seconds)
    minimum_ttl INTEGER NOT NULL DEFAULT 300 -- Negative caching TTL (seconds)
);

CREATE INDEX IF NOT EXISTS idx_dns_soa_zone ON dns_soa(zone_id);

-- ============================================================================
-- TABLE: dns_records
-- Purpose: All DNS resource records (A, AAAA, CNAME, MX, TXT, NS, PTR, SRV)
-- ============================================================================

CREATE TABLE IF NOT EXISTS dns_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    zone_id UUID NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,              -- FQDN or hostname
    type VARCHAR(10) NOT NULL,               -- A, AAAA, CNAME, MX, TXT, NS, PTR, SRV
    ttl INTEGER NOT NULL DEFAULT 3600,       -- Time-to-live in seconds
    value TEXT NOT NULL,                     -- Record data (IP, hostname, text)
    priority INTEGER,                        -- For MX and SRV records
    weight INTEGER,                          -- For SRV records
    port INTEGER,                            -- For SRV records
    is_dynamic BOOLEAN DEFAULT FALSE,        -- Created by DHCP dynamic update
    lease_expiry TIMESTAMPTZ,                -- When DHCP lease expires (for dynamic records)
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT unique_record UNIQUE (zone_id, name, type, value)
);

CREATE INDEX IF NOT EXISTS idx_dns_records_zone ON dns_records(zone_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_name ON dns_records(name);
CREATE INDEX IF NOT EXISTS idx_dns_records_name_type ON dns_records(name, type);
CREATE INDEX IF NOT EXISTS idx_dns_records_dynamic ON dns_records(is_dynamic) WHERE is_dynamic = true;

-- ============================================================================
-- TABLE: dns_blocklist
-- Purpose: Domains blocked by filtering engine (malware, phishing, etc.)
-- ============================================================================

CREATE TABLE IF NOT EXISTS dns_blocklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) UNIQUE NOT NULL,     -- FQDN to block
    reason VARCHAR(500),                     -- Human-readable justification
    category VARCHAR(50),                    -- malware, phishing, spam, ads, adult, tracking
    blocked_by VARCHAR(100),                 -- Source: IDS, IPS, Admin, ThreatIntel
    expires_at TIMESTAMPTZ,                  -- NULL = permanent, timestamp = temporary
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blocklist_domain ON dns_blocklist(domain);
CREATE INDEX IF NOT EXISTS idx_blocklist_expires ON dns_blocklist(expires_at);
CREATE INDEX IF NOT EXISTS idx_blocklist_category ON dns_blocklist(category);
CREATE INDEX IF NOT EXISTS idx_blocklist_active ON dns_blocklist(domain) 
    WHERE expires_at IS NULL OR expires_at > NOW();

-- ============================================================================
-- TABLE: dns_allowlist
-- Purpose: Trusted domains that bypass all filtering
-- ============================================================================

CREATE TABLE IF NOT EXISTS dns_allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) UNIQUE NOT NULL,     -- FQDN to always allow
    reason VARCHAR(500),                     -- Justification for allowlisting
    added_by VARCHAR(100),                   -- Who added the entry
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_allowlist_domain ON dns_allowlist(domain);

-- ============================================================================
-- TABLE: dns_query_stats
-- Purpose: Query logs and statistics for monitoring and analytics
-- ============================================================================

CREATE TABLE IF NOT EXISTS dns_query_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_ip INET NOT NULL,                 -- Source IP address
    domain VARCHAR(255) NOT NULL,            -- Queried domain name
    query_type VARCHAR(10) NOT NULL,         -- A, AAAA, CNAME, MX, TXT, PTR, etc.
    response_code VARCHAR(20) NOT NULL,      -- NOERROR, NXDOMAIN, SERVFAIL, REFUSED
    blocked BOOLEAN DEFAULT FALSE,           -- Blocked by filtering
    cache_hit BOOLEAN DEFAULT FALSE,         -- Served from cache
    response_time_ms FLOAT,                  -- Query latency in milliseconds
    upstream_server VARCHAR(100),            -- Which upstream resolved the query
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_query_stats_timestamp ON dns_query_stats(timestamp);
CREATE INDEX IF NOT EXISTS idx_query_stats_domain ON dns_query_stats(domain);
CREATE INDEX IF NOT EXISTS idx_query_stats_client ON dns_query_stats(client_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_query_stats_blocked ON dns_query_stats(blocked, timestamp) 
    WHERE blocked = true;
CREATE INDEX IF NOT EXISTS idx_query_stats_response ON dns_query_stats(response_code);

-- ============================================================================
-- TABLE: device_enrollment (Phase 17: Captive Portal)
-- Purpose: Track device CA certificate enrollment status
-- ============================================================================

CREATE TABLE IF NOT EXISTS device_enrollment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(64) NOT NULL UNIQUE,   -- Generated UUID
    ip_address INET NOT NULL,
    mac_address MACADDR,
    os_type VARCHAR(32),                     -- Windows, Linux, macOS, iOS, Android
    user_agent TEXT,
    ca_installed BOOLEAN DEFAULT FALSE,
    installed_at TIMESTAMPTZ,
    install_method VARCHAR(32),              -- portal, script, mdm
    certificate_fingerprint VARCHAR(128),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_enrollment_ip ON device_enrollment(ip_address);
CREATE INDEX IF NOT EXISTS idx_device_enrollment_mac ON device_enrollment(mac_address);
CREATE INDEX IF NOT EXISTS idx_device_enrollment_ca ON device_enrollment(ca_installed);
CREATE INDEX IF NOT EXISTS idx_device_enrollment_last_seen ON device_enrollment(last_seen);

-- ============================================================================
-- TRIGGERS: Automatic timestamp updates
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- dns_zones update trigger
DROP TRIGGER IF EXISTS update_zones_updated_at ON dns_zones;
CREATE TRIGGER update_zones_updated_at 
    BEFORE UPDATE ON dns_zones
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- dns_records update trigger
DROP TRIGGER IF EXISTS update_records_updated_at ON dns_records;
CREATE TRIGGER update_records_updated_at 
    BEFORE UPDATE ON dns_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- device_enrollment update trigger
DROP TRIGGER IF EXISTS update_device_enrollment_updated_at ON device_enrollment;
CREATE TRIGGER update_device_enrollment_updated_at 
    BEFORE UPDATE ON device_enrollment
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- TRIGGER: Auto-increment SOA serial on record changes
-- ============================================================================

CREATE OR REPLACE FUNCTION increment_soa_serial()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE dns_soa SET serial = serial + 1 WHERE zone_id = OLD.zone_id;
        RETURN OLD;
    ELSE
        UPDATE dns_soa SET serial = serial + 1 WHERE zone_id = NEW.zone_id;
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_serial_on_record_change ON dns_records;
CREATE TRIGGER update_serial_on_record_change 
    AFTER INSERT OR UPDATE OR DELETE ON dns_records
    FOR EACH ROW EXECUTE FUNCTION increment_soa_serial();

-- ============================================================================
-- VIEWS: Convenience views for common queries
-- ============================================================================

-- Active blocklist (excludes expired entries)
CREATE OR REPLACE VIEW dns_active_blocklist AS
SELECT * FROM dns_blocklist
WHERE expires_at IS NULL OR expires_at > NOW();

-- Pending device enrollments (CA not installed)
CREATE OR REPLACE VIEW dns_pending_enrollments AS
SELECT * FROM device_enrollment
WHERE ca_installed = FALSE
ORDER BY first_seen ASC;

-- ============================================================================
-- MATERIALIZED VIEW: Daily query statistics
-- ============================================================================

DROP MATERIALIZED VIEW IF EXISTS dns_daily_stats;
CREATE MATERIALIZED VIEW dns_daily_stats AS
SELECT
    DATE(timestamp) as query_date,
    COUNT(*) as total_queries,
    COUNT(*) FILTER (WHERE cache_hit = true) as cache_hits,
    COUNT(*) FILTER (WHERE blocked = true) as blocked_queries,
    COUNT(*) FILTER (WHERE response_code = 'NOERROR') as successful_queries,
    COUNT(*) FILTER (WHERE response_code = 'NXDOMAIN') as nxdomain_queries,
    AVG(response_time_ms) as avg_response_time_ms,
    COUNT(DISTINCT client_ip) as unique_clients,
    COUNT(DISTINCT domain) as unique_domains
FROM dns_query_stats
GROUP BY DATE(timestamp);

-- Create index on materialized view
CREATE INDEX IF NOT EXISTS idx_daily_stats_date ON dns_daily_stats(query_date);

-- ============================================================================
-- COMMENTS: Documentation for tables
-- ============================================================================

COMMENT ON TABLE dns_zones IS 'DNS zones the server is authoritative for';
COMMENT ON TABLE dns_soa IS 'Start of Authority records for each zone';
COMMENT ON TABLE dns_records IS 'All DNS resource records (A, AAAA, CNAME, MX, etc.)';
COMMENT ON TABLE dns_blocklist IS 'Domains blocked by filtering engine';
COMMENT ON TABLE dns_allowlist IS 'Trusted domains that bypass filtering';
COMMENT ON TABLE dns_query_stats IS 'Query logs for monitoring and analytics';
COMMENT ON TABLE device_enrollment IS 'Device CA certificate enrollment tracking';

-- ============================================================================
-- SEED DATA: Default zone for local network
-- ============================================================================

-- Create default local zone if not exists
INSERT INTO dns_zones (name, type, description)
VALUES ('safeops.local', 'primary', 'SafeOps local network zone')
ON CONFLICT (name) DO NOTHING;

-- Create SOA for default zone
INSERT INTO dns_soa (zone_id, primary_ns, admin_email, serial, refresh, retry, expire, minimum_ttl)
SELECT id, 'ns1.safeops.local', 'admin.safeops.local', 2025123001, 3600, 600, 604800, 300
FROM dns_zones WHERE name = 'safeops.local'
ON CONFLICT (zone_id) DO NOTHING;

-- Create reverse DNS zone for 192.168.x.x
INSERT INTO dns_zones (name, type, description)
VALUES ('168.192.in-addr.arpa', 'primary', 'Reverse DNS for 192.168.x.x network')
ON CONFLICT (name) DO NOTHING;

-- Create SOA for reverse zone
INSERT INTO dns_soa (zone_id, primary_ns, admin_email, serial, refresh, retry, expire, minimum_ttl)
SELECT id, 'ns1.safeops.local', 'admin.safeops.local', 2025123001, 3600, 600, 604800, 300
FROM dns_zones WHERE name = '168.192.in-addr.arpa'
ON CONFLICT (zone_id) DO NOTHING;

-- End of schema
