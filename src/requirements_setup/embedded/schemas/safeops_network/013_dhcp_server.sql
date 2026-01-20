-- ============================================================================
-- DHCP Server Database Schema
-- Migration: 013_dhcp_server.sql
-- Version: 2.0.0
-- Database: PostgreSQL 14+ (requires INET, CIDR, MACADDR, JSONB types)
-- Purpose: Persistent storage for DHCP leases, pools, reservations, and options
-- ============================================================================

-- Enable btree_gist for GiST indexes on INET types (optional but recommended)
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- ============================================================================
-- TABLE: dhcp_pools
-- Stores IP address pool configurations for different network segments
-- ============================================================================

CREATE TABLE IF NOT EXISTS dhcp_pools (
    id SERIAL PRIMARY KEY,
    pool_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    subnet CIDR NOT NULL,
    range_start INET NOT NULL,
    range_end INET NOT NULL,
    lease_time INTEGER NOT NULL DEFAULT 86400,          -- Default 24 hours
    gateway INET,
    dns_servers INET[] DEFAULT ARRAY[]::INET[],
    ntp_servers INET[] DEFAULT ARRAY[]::INET[],
    domain_name VARCHAR(255),
    interface VARCHAR(64),                               -- e.g., 'lan0', 'wifi0'
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT chk_range_within_subnet CHECK (
        range_start::INET <<= subnet::CIDR AND 
        range_end::INET <<= subnet::CIDR
    ),
    CONSTRAINT chk_range_order CHECK (range_start <= range_end),
    CONSTRAINT chk_lease_time_positive CHECK (lease_time > 0)
);

-- Indexes for dhcp_pools
CREATE INDEX IF NOT EXISTS idx_dhcp_pools_subnet ON dhcp_pools USING GIST (subnet inet_ops);
CREATE INDEX IF NOT EXISTS idx_dhcp_pools_interface ON dhcp_pools(interface);
CREATE INDEX IF NOT EXISTS idx_dhcp_pools_enabled ON dhcp_pools(enabled) WHERE enabled = TRUE;

COMMENT ON TABLE dhcp_pools IS 'IP address pool configurations for DHCP server';
COMMENT ON COLUMN dhcp_pools.subnet IS 'Network CIDR (e.g., 192.168.1.0/24)';
COMMENT ON COLUMN dhcp_pools.lease_time IS 'Default lease duration in seconds';

-- ============================================================================
-- TABLE: dhcp_leases
-- Tracks active and historical IP address assignments
-- ============================================================================

CREATE TABLE IF NOT EXISTS dhcp_leases (
    id BIGSERIAL PRIMARY KEY,
    lease_id UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    pool_id VARCHAR(64) REFERENCES dhcp_pools(pool_id) ON DELETE CASCADE,
    mac_address MACADDR NOT NULL,
    ip_address INET NOT NULL,
    hostname VARCHAR(255),
    lease_start TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    lease_end TIMESTAMP WITH TIME ZONE NOT NULL,
    state VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    renewal_count INTEGER NOT NULL DEFAULT 0,
    client_identifier VARCHAR(255),
    vendor_class VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT chk_lease_state CHECK (
        state IN ('ACTIVE', 'EXPIRED', 'RELEASED', 'ABANDONED')
    ),
    CONSTRAINT chk_lease_times CHECK (lease_end > lease_start),
    CONSTRAINT chk_renewal_count CHECK (renewal_count >= 0)
);

-- Unique partial indexes to prevent conflicts on active leases only
CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_leases_active_mac 
    ON dhcp_leases(mac_address) 
    WHERE state = 'ACTIVE';

CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_leases_active_ip 
    ON dhcp_leases(ip_address) 
    WHERE state = 'ACTIVE';

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_pool_id ON dhcp_leases(pool_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_state ON dhcp_leases(state);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_expiry ON dhcp_leases(lease_end) WHERE state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_hostname ON dhcp_leases(hostname) WHERE hostname IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_mac ON dhcp_leases(mac_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_ip ON dhcp_leases(ip_address);

COMMENT ON TABLE dhcp_leases IS 'Active and historical DHCP lease records';
COMMENT ON COLUMN dhcp_leases.state IS 'ACTIVE, EXPIRED, RELEASED, or ABANDONED';

-- ============================================================================
-- TABLE: dhcp_reservations
-- Stores static MAC-to-IP bindings (fixed addresses)
-- ============================================================================

CREATE TABLE IF NOT EXISTS dhcp_reservations (
    id SERIAL PRIMARY KEY,
    reservation_id UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    pool_id VARCHAR(64) REFERENCES dhcp_pools(pool_id) ON DELETE CASCADE,
    mac_address MACADDR UNIQUE NOT NULL,
    ip_address INET UNIQUE NOT NULL,
    hostname VARCHAR(255),
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for dhcp_reservations
CREATE INDEX IF NOT EXISTS idx_dhcp_reservations_pool_id ON dhcp_reservations(pool_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_reservations_active ON dhcp_reservations(active) WHERE active = TRUE;

COMMENT ON TABLE dhcp_reservations IS 'Static MAC-to-IP address bindings';
COMMENT ON COLUMN dhcp_reservations.ip_address IS 'Reserved IP address (must be within pool subnet)';

-- ============================================================================
-- TABLE: dhcp_options
-- Stores pool-specific and global DHCP option overrides
-- ============================================================================

CREATE TABLE IF NOT EXISTS dhcp_options (
    id SERIAL PRIMARY KEY,
    pool_id VARCHAR(64) REFERENCES dhcp_pools(pool_id) ON DELETE CASCADE,
    option_code INTEGER NOT NULL,
    option_value BYTEA NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT chk_option_code CHECK (option_code BETWEEN 1 AND 255)
);

-- Unique index on (pool_id, option_code) - NULL pool_id = global option
CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_options_unique 
    ON dhcp_options(COALESCE(pool_id, ''), option_code);

-- Index for global options lookup
CREATE INDEX IF NOT EXISTS idx_dhcp_options_global 
    ON dhcp_options(option_code) 
    WHERE pool_id IS NULL;

COMMENT ON TABLE dhcp_options IS 'DHCP option overrides per pool or globally';
COMMENT ON COLUMN dhcp_options.pool_id IS 'NULL for global options, pool_id for pool-specific';
COMMENT ON COLUMN dhcp_options.option_code IS 'DHCP option code (1-255)';

-- ============================================================================
-- TABLE: dhcp_statistics
-- Aggregated DHCP server statistics (time-series)
-- ============================================================================

CREATE TABLE IF NOT EXISTS dhcp_statistics (
    id BIGSERIAL PRIMARY KEY,
    collected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    discover_count BIGINT NOT NULL DEFAULT 0,
    offer_count BIGINT NOT NULL DEFAULT 0,
    request_count BIGINT NOT NULL DEFAULT 0,
    ack_count BIGINT NOT NULL DEFAULT 0,
    nak_count BIGINT NOT NULL DEFAULT 0,
    release_count BIGINT NOT NULL DEFAULT 0,
    decline_count BIGINT NOT NULL DEFAULT 0,
    inform_count BIGINT NOT NULL DEFAULT 0,
    total_active_leases INTEGER NOT NULL DEFAULT 0
);

-- Index for time-series queries
CREATE INDEX IF NOT EXISTS idx_dhcp_statistics_time 
    ON dhcp_statistics(collected_at DESC);

COMMENT ON TABLE dhcp_statistics IS 'DHCP server statistics aggregated over time';

-- ============================================================================
-- TABLE: dhcp_lease_events
-- Audit log for all lease lifecycle events
-- ============================================================================

CREATE TABLE IF NOT EXISTS dhcp_lease_events (
    id BIGSERIAL PRIMARY KEY,
    event_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    event_type VARCHAR(20) NOT NULL,
    lease_id UUID,
    mac_address MACADDR NOT NULL,
    ip_address INET NOT NULL,
    pool_id VARCHAR(64),
    hostname VARCHAR(255),
    details JSONB DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT chk_event_type CHECK (
        event_type IN ('ASSIGNED', 'RENEWED', 'RELEASED', 'EXPIRED', 'DECLINED', 'ABANDONED')
    )
);

-- Indexes for event queries
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_events_time 
    ON dhcp_lease_events(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_events_mac 
    ON dhcp_lease_events(mac_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_events_ip 
    ON dhcp_lease_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_events_type 
    ON dhcp_lease_events(event_type);
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_events_lease_id 
    ON dhcp_lease_events(lease_id) WHERE lease_id IS NOT NULL;

COMMENT ON TABLE dhcp_lease_events IS 'Audit log for DHCP lease lifecycle events';
COMMENT ON COLUMN dhcp_lease_events.details IS 'Additional event metadata as JSON';

-- ============================================================================
-- TRIGGER FUNCTION: update_updated_at_column
-- Automatically updates updated_at timestamp on row modifications
-- ============================================================================

CREATE OR REPLACE FUNCTION dhcp_update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers to tables with updated_at columns
DROP TRIGGER IF EXISTS trigger_dhcp_pools_updated_at ON dhcp_pools;
CREATE TRIGGER trigger_dhcp_pools_updated_at
    BEFORE UPDATE ON dhcp_pools
    FOR EACH ROW
    EXECUTE FUNCTION dhcp_update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_dhcp_leases_updated_at ON dhcp_leases;
CREATE TRIGGER trigger_dhcp_leases_updated_at
    BEFORE UPDATE ON dhcp_leases
    FOR EACH ROW
    EXECUTE FUNCTION dhcp_update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_dhcp_reservations_updated_at ON dhcp_reservations;
CREATE TRIGGER trigger_dhcp_reservations_updated_at
    BEFORE UPDATE ON dhcp_reservations
    FOR EACH ROW
    EXECUTE FUNCTION dhcp_update_updated_at_column();

-- ============================================================================
-- VIEW: v_active_leases
-- Convenience view joining active leases with pool information
-- ============================================================================

CREATE OR REPLACE VIEW v_dhcp_active_leases AS
SELECT 
    l.lease_id,
    l.mac_address,
    l.ip_address,
    l.hostname,
    l.lease_start,
    l.lease_end,
    l.renewal_count,
    l.client_identifier,
    l.vendor_class,
    p.pool_id,
    p.name AS pool_name,
    p.subnet,
    p.domain_name,
    EXTRACT(EPOCH FROM (l.lease_end - NOW()))::INTEGER AS seconds_remaining
FROM dhcp_leases l
LEFT JOIN dhcp_pools p ON l.pool_id = p.pool_id
WHERE l.state = 'ACTIVE';

COMMENT ON VIEW v_dhcp_active_leases IS 'Active DHCP leases with pool details';

-- ============================================================================
-- VIEW: v_pool_utilization
-- Calculates IP utilization per pool
-- ============================================================================

CREATE OR REPLACE VIEW v_dhcp_pool_utilization AS
SELECT 
    p.pool_id,
    p.name,
    p.subnet,
    p.range_start,
    p.range_end,
    p.enabled,
    -- Calculate total IPs in range (simplified for /24 and larger)
    (p.range_end - p.range_start + 1)::INTEGER AS total_ips,
    -- Count active leases
    COALESCE(active_counts.active_leases, 0) AS allocated_ips,
    -- Count reservations
    COALESCE(res_counts.reservation_count, 0) AS reserved_ips,
    -- Calculate utilization percentage
    CASE 
        WHEN (p.range_end - p.range_start + 1) > 0 THEN
            ROUND(
                (COALESCE(active_counts.active_leases, 0)::NUMERIC / 
                (p.range_end - p.range_start + 1)::NUMERIC) * 100, 2
            )
        ELSE 0
    END AS utilization_percent,
    -- Calculate available IPs
    (p.range_end - p.range_start + 1)::INTEGER - 
        COALESCE(active_counts.active_leases, 0) - 
        COALESCE(res_counts.reservation_count, 0) AS available_ips
FROM dhcp_pools p
LEFT JOIN (
    SELECT pool_id, COUNT(*) AS active_leases
    FROM dhcp_leases
    WHERE state = 'ACTIVE'
    GROUP BY pool_id
) active_counts ON p.pool_id = active_counts.pool_id
LEFT JOIN (
    SELECT pool_id, COUNT(*) AS reservation_count
    FROM dhcp_reservations
    WHERE active = TRUE
    GROUP BY pool_id
) res_counts ON p.pool_id = res_counts.pool_id;

COMMENT ON VIEW v_dhcp_pool_utilization IS 'Pool utilization statistics';

-- ============================================================================
-- INITIAL DATA: Default LAN Pool (Optional)
-- Insert default pool configuration for initial setup
-- ============================================================================

INSERT INTO dhcp_pools (
    pool_id, 
    name, 
    subnet, 
    range_start, 
    range_end, 
    lease_time, 
    gateway, 
    dns_servers, 
    domain_name, 
    interface, 
    enabled
)
VALUES (
    'default-lan',
    'Default LAN Pool',
    '192.168.1.0/24',
    '192.168.1.100',
    '192.168.1.200',
    86400,
    '192.168.1.1',
    ARRAY['192.168.1.1'::INET, '8.8.8.8'::INET],
    'local.network',
    'lan0',
    TRUE
)
ON CONFLICT (pool_id) DO NOTHING;

-- ============================================================================
-- FUNCTION: Check IP within pool subnet (for reservation validation)
-- ============================================================================

CREATE OR REPLACE FUNCTION dhcp_validate_reservation_ip()
RETURNS TRIGGER AS $$
DECLARE
    pool_subnet CIDR;
BEGIN
    -- Get the pool's subnet
    SELECT subnet INTO pool_subnet
    FROM dhcp_pools
    WHERE pool_id = NEW.pool_id;
    
    -- Check if IP is within subnet
    IF pool_subnet IS NOT NULL AND NOT (NEW.ip_address <<= pool_subnet) THEN
        RAISE EXCEPTION 'Reservation IP % is not within pool subnet %', 
            NEW.ip_address, pool_subnet;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_validate_reservation_ip ON dhcp_reservations;
CREATE TRIGGER trigger_validate_reservation_ip
    BEFORE INSERT OR UPDATE ON dhcp_reservations
    FOR EACH ROW
    WHEN (NEW.pool_id IS NOT NULL)
    EXECUTE FUNCTION dhcp_validate_reservation_ip();

-- ============================================================================
-- GRANTS: Set appropriate permissions
-- ============================================================================

-- Grant usage to application role (adjust role name as needed)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safeops_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safeops_app;

-- ============================================================================
-- Migration Complete
-- ============================================================================

COMMENT ON SCHEMA public IS 'DHCP Server schema migration 013 applied';
