-- =============================================================================
-- NIC Management Database Schema
-- =============================================================================
-- This schema defines all database tables, indexes, constraints, and functions
-- required for the NIC Management service to persist network interface state,
-- connection tracking, NAT mapping sessions, WAN health history, failover events,
-- and routing statistics.
--
-- Prerequisites: PostgreSQL 14+
-- =============================================================================

-- =============================================================================
-- SECTION 1: Extension Declarations
-- =============================================================================

-- UUID generation for unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Trigram indexing for fast text search on interface names
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- GIN indexes for multi-column queries
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- =============================================================================
-- SECTION 2: Table - network_interfaces
-- Stores inventory of all detected network interfaces (WAN, LAN, WiFi)
-- =============================================================================

CREATE TABLE IF NOT EXISTS network_interfaces (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    interface_name      VARCHAR(255) UNIQUE NOT NULL,
    interface_type      VARCHAR(50) NOT NULL CHECK (interface_type IN ('WAN', 'LAN', 'WIFI', 'VIRTUAL', 'LOOPBACK', 'BRIDGE')),
    mac_address         MACADDR UNIQUE,
    ip_address          INET,
    netmask             VARCHAR(50),
    gateway             INET,
    dns_servers         INET[],
    mtu                 INTEGER DEFAULT 1500 CHECK (mtu >= 68 AND mtu <= 65535),
    state               VARCHAR(20) DEFAULT 'DOWN' CHECK (state IN ('UP', 'DOWN', 'DORMANT', 'ERROR', 'NOT_PRESENT', 'LOWER_LAYER_DOWN')),
    speed_mbps          INTEGER CHECK (speed_mbps IS NULL OR speed_mbps > 0),
    duplex              VARCHAR(20) DEFAULT 'UNKNOWN' CHECK (duplex IN ('FULL', 'HALF', 'AUTO', 'UNKNOWN')),
    driver_name         VARCHAR(255),
    driver_version      VARCHAR(100),
    firmware_version    VARCHAR(100),
    pci_address         VARCHAR(50),
    hardware_id         VARCHAR(255),
    vendor_name         VARCHAR(255),
    device_model        VARCHAR(255),
    is_virtual          BOOLEAN DEFAULT FALSE,
    is_enabled          BOOLEAN DEFAULT TRUE,
    is_dhcp             BOOLEAN DEFAULT FALSE,
    description         TEXT,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for network_interfaces
CREATE INDEX IF NOT EXISTS idx_interfaces_type ON network_interfaces(interface_type);
CREATE INDEX IF NOT EXISTS idx_interfaces_state ON network_interfaces(state);
CREATE INDEX IF NOT EXISTS idx_interfaces_enabled ON network_interfaces(is_enabled);
CREATE INDEX IF NOT EXISTS idx_interfaces_name_trgm ON network_interfaces USING gin(interface_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_interfaces_ip ON network_interfaces(ip_address);

COMMENT ON TABLE network_interfaces IS 'Inventory of all detected network interfaces (WAN, LAN, WiFi, Virtual)';
COMMENT ON COLUMN network_interfaces.interface_type IS 'Classification: WAN, LAN, WIFI, VIRTUAL, LOOPBACK, BRIDGE';
COMMENT ON COLUMN network_interfaces.state IS 'Operational state: UP, DOWN, DORMANT, ERROR, NOT_PRESENT';

-- =============================================================================
-- SECTION 3: Table - connection_tracking
-- Tracks active network connections for NAT and firewall state management
-- =============================================================================

CREATE TABLE IF NOT EXISTS connection_tracking (
    connection_id       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    src_ip              INET NOT NULL,
    src_port            INTEGER NOT NULL CHECK (src_port >= 0 AND src_port <= 65535),
    dst_ip              INET NOT NULL,
    dst_port            INTEGER NOT NULL CHECK (dst_port >= 0 AND dst_port <= 65535),
    protocol            VARCHAR(20) NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'ICMPv6', 'SCTP', 'GRE')),
    state               VARCHAR(20) DEFAULT 'NEW' CHECK (state IN ('NEW', 'ESTABLISHED', 'RELATED', 'INVALID', 'CLOSING', 'CLOSED', 'TIME_WAIT', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT')),
    wan_interface_id    UUID REFERENCES network_interfaces(id) ON DELETE SET NULL,
    lan_interface_id    UUID REFERENCES network_interfaces(id) ON DELETE SET NULL,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen           TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at          TIMESTAMP WITH TIME ZONE,
    bytes_sent          BIGINT DEFAULT 0 CHECK (bytes_sent >= 0),
    bytes_received      BIGINT DEFAULT 0 CHECK (bytes_received >= 0),
    packets_sent        BIGINT DEFAULT 0 CHECK (packets_sent >= 0),
    packets_received    BIGINT DEFAULT 0 CHECK (packets_received >= 0),
    is_nat              BOOLEAN DEFAULT FALSE,
    mark                INTEGER DEFAULT 0,
    zone                VARCHAR(50)
);

-- Indexes for connection_tracking (high-performance lookups)
CREATE INDEX IF NOT EXISTS idx_connections_state ON connection_tracking(state);
CREATE INDEX IF NOT EXISTS idx_connections_expires ON connection_tracking(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_connections_5tuple ON connection_tracking(src_ip, src_port, dst_ip, dst_port, protocol);
CREATE INDEX IF NOT EXISTS idx_connections_wan ON connection_tracking(wan_interface_id);
CREATE INDEX IF NOT EXISTS idx_connections_lan ON connection_tracking(lan_interface_id);
CREATE INDEX IF NOT EXISTS idx_connections_src_ip ON connection_tracking(src_ip);
CREATE INDEX IF NOT EXISTS idx_connections_dst_ip ON connection_tracking(dst_ip);
CREATE INDEX IF NOT EXISTS idx_connections_last_seen ON connection_tracking(last_seen);
CREATE INDEX IF NOT EXISTS idx_connections_protocol ON connection_tracking(protocol);

-- Composite GIN index for multi-column queries
CREATE INDEX IF NOT EXISTS idx_connections_gin ON connection_tracking USING gin(protocol, state);

COMMENT ON TABLE connection_tracking IS 'Tracks active network connections for NAT and stateful firewall';
COMMENT ON COLUMN connection_tracking.state IS 'Connection state: NEW, ESTABLISHED, RELATED, INVALID, CLOSING, CLOSED';

-- =============================================================================
-- SECTION 4: Table - nat_mappings
-- Stores NAT/NAPT translation mappings (internal IP:port → external IP:port)
-- =============================================================================

CREATE TABLE IF NOT EXISTS nat_mappings (
    mapping_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    internal_ip         INET NOT NULL,
    internal_port       INTEGER NOT NULL CHECK (internal_port >= 0 AND internal_port <= 65535),
    external_ip         INET NOT NULL,
    external_port       INTEGER NOT NULL CHECK (external_port >= 0 AND external_port <= 65535),
    protocol            VARCHAR(20) NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'ICMPv6')),
    wan_interface_id    UUID REFERENCES network_interfaces(id) ON DELETE CASCADE,
    connection_id       UUID REFERENCES connection_tracking(connection_id) ON DELETE CASCADE,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used           TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    bytes_sent          BIGINT DEFAULT 0 CHECK (bytes_sent >= 0),
    bytes_received      BIGINT DEFAULT 0 CHECK (bytes_received >= 0),
    packets_sent        BIGINT DEFAULT 0 CHECK (packets_sent >= 0),
    packets_received    BIGINT DEFAULT 0 CHECK (packets_received >= 0),
    is_static           BOOLEAN DEFAULT FALSE,
    description         TEXT,
    
    -- Prevent duplicate external port allocations
    CONSTRAINT unique_external_mapping UNIQUE (external_ip, external_port, protocol)
);

-- Indexes for nat_mappings
CREATE INDEX IF NOT EXISTS idx_nat_internal ON nat_mappings(internal_ip, internal_port, protocol);
CREATE INDEX IF NOT EXISTS idx_nat_external ON nat_mappings(external_ip, external_port, protocol);
CREATE INDEX IF NOT EXISTS idx_nat_expires ON nat_mappings(expires_at);
CREATE INDEX IF NOT EXISTS idx_nat_wan ON nat_mappings(wan_interface_id);
CREATE INDEX IF NOT EXISTS idx_nat_connection ON nat_mappings(connection_id);
CREATE INDEX IF NOT EXISTS idx_nat_static ON nat_mappings(is_static) WHERE is_static = TRUE;
CREATE INDEX IF NOT EXISTS idx_nat_last_used ON nat_mappings(last_used);

COMMENT ON TABLE nat_mappings IS 'NAT/NAPT translation mappings (internal IP:port → external IP:port)';
COMMENT ON COLUMN nat_mappings.is_static IS 'TRUE if this is a static port forwarding rule';

-- =============================================================================
-- SECTION 5: Table - wan_health_history
-- Historical WAN link health metrics for uptime tracking and SLA monitoring
-- =============================================================================

CREATE TABLE IF NOT EXISTS wan_health_history (
    health_id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wan_interface_id        UUID NOT NULL REFERENCES network_interfaces(id) ON DELETE CASCADE,
    state                   VARCHAR(20) NOT NULL CHECK (state IN ('HEALTHY', 'DEGRADED', 'FAILING', 'DOWN', 'RECOVERING', 'UNKNOWN')),
    latency_ms              REAL CHECK (latency_ms IS NULL OR latency_ms >= 0),
    jitter_ms               REAL CHECK (jitter_ms IS NULL OR jitter_ms >= 0),
    packet_loss_percent     REAL CHECK (packet_loss_percent IS NULL OR (packet_loss_percent >= 0 AND packet_loss_percent <= 100)),
    bandwidth_up_mbps       REAL CHECK (bandwidth_up_mbps IS NULL OR bandwidth_up_mbps >= 0),
    bandwidth_down_mbps     REAL CHECK (bandwidth_down_mbps IS NULL OR bandwidth_down_mbps >= 0),
    consecutive_failures    INTEGER DEFAULT 0 CHECK (consecutive_failures >= 0),
    consecutive_successes   INTEGER DEFAULT 0 CHECK (consecutive_successes >= 0),
    health_check_target     VARCHAR(255),
    checked_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for wan_health_history
CREATE INDEX IF NOT EXISTS idx_wan_health_interface ON wan_health_history(wan_interface_id);
CREATE INDEX IF NOT EXISTS idx_wan_health_time ON wan_health_history(checked_at);
CREATE INDEX IF NOT EXISTS idx_wan_health_state ON wan_health_history(state);
CREATE INDEX IF NOT EXISTS idx_wan_health_interface_time ON wan_health_history(wan_interface_id, checked_at DESC);

-- Partial index for recent health data (last 7 days)
CREATE INDEX IF NOT EXISTS idx_wan_health_recent ON wan_health_history(wan_interface_id, checked_at)
    WHERE checked_at > NOW() - INTERVAL '7 days';

COMMENT ON TABLE wan_health_history IS 'Historical WAN link health metrics for uptime tracking and SLA monitoring';
COMMENT ON COLUMN wan_health_history.latency_ms IS 'Ping latency to gateway in milliseconds';
COMMENT ON COLUMN wan_health_history.packet_loss_percent IS 'Packet loss percentage (0-100)';

-- =============================================================================
-- SECTION 6: Table - failover_events
-- Records WAN failover events for audit and troubleshooting
-- =============================================================================

CREATE TABLE IF NOT EXISTS failover_events (
    event_id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    from_wan_id             UUID REFERENCES network_interfaces(id) ON DELETE SET NULL,
    to_wan_id               UUID REFERENCES network_interfaces(id) ON DELETE SET NULL,
    reason                  VARCHAR(50) NOT NULL CHECK (reason IN (
        'MANUAL', 'HEALTH_CHECK_FAILED', 'GATEWAY_UNREACHABLE', 
        'HIGH_PACKET_LOSS', 'HIGH_LATENCY', 'ADMINISTRATIVE', 
        'SCHEDULED', 'INTERFACE_DOWN', 'DNS_FAILURE'
    )),
    triggered_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at            TIMESTAMP WITH TIME ZONE,
    duration_seconds        INTEGER,
    affected_connections    BIGINT DEFAULT 0 CHECK (affected_connections >= 0),
    migrated_connections    BIGINT DEFAULT 0 CHECK (migrated_connections >= 0),
    dropped_connections     BIGINT DEFAULT 0 CHECK (dropped_connections >= 0),
    success                 BOOLEAN DEFAULT TRUE,
    error_message           TEXT,
    triggered_by            VARCHAR(50) DEFAULT 'automatic' CHECK (triggered_by IN ('automatic', 'manual', 'scheduled', 'api')),
    recovery_time_ms        INTEGER,
    notes                   TEXT
);

-- Indexes for failover_events
CREATE INDEX IF NOT EXISTS idx_failover_time ON failover_events(triggered_at);
CREATE INDEX IF NOT EXISTS idx_failover_from_wan ON failover_events(from_wan_id);
CREATE INDEX IF NOT EXISTS idx_failover_to_wan ON failover_events(to_wan_id);
CREATE INDEX IF NOT EXISTS idx_failover_success ON failover_events(success);
CREATE INDEX IF NOT EXISTS idx_failover_reason ON failover_events(reason);
CREATE INDEX IF NOT EXISTS idx_failover_triggered_by ON failover_events(triggered_by);

COMMENT ON TABLE failover_events IS 'Records WAN failover events for audit and troubleshooting';
COMMENT ON COLUMN failover_events.reason IS 'Reason for failover: MANUAL, HEALTH_CHECK_FAILED, GATEWAY_UNREACHABLE, etc.';

-- =============================================================================
-- SECTION 7: Table - routing_statistics
-- Per-interface routing statistics for performance monitoring
-- =============================================================================

CREATE TABLE IF NOT EXISTS routing_statistics (
    stat_id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    interface_id        UUID NOT NULL REFERENCES network_interfaces(id) ON DELETE CASCADE,
    collected_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rx_bytes            BIGINT DEFAULT 0 CHECK (rx_bytes >= 0),
    tx_bytes            BIGINT DEFAULT 0 CHECK (tx_bytes >= 0),
    rx_packets          BIGINT DEFAULT 0 CHECK (rx_packets >= 0),
    tx_packets          BIGINT DEFAULT 0 CHECK (tx_packets >= 0),
    rx_errors           BIGINT DEFAULT 0 CHECK (rx_errors >= 0),
    tx_errors           BIGINT DEFAULT 0 CHECK (tx_errors >= 0),
    rx_dropped          BIGINT DEFAULT 0 CHECK (rx_dropped >= 0),
    tx_dropped          BIGINT DEFAULT 0 CHECK (tx_dropped >= 0),
    multicast           BIGINT DEFAULT 0 CHECK (multicast >= 0),
    collisions          BIGINT DEFAULT 0 CHECK (collisions >= 0),
    active_connections  INTEGER DEFAULT 0 CHECK (active_connections >= 0),
    throughput_rx_bps   BIGINT DEFAULT 0 CHECK (throughput_rx_bps >= 0),
    throughput_tx_bps   BIGINT DEFAULT 0 CHECK (throughput_tx_bps >= 0),
    packets_per_second  INTEGER DEFAULT 0 CHECK (packets_per_second >= 0),
    utilization_percent REAL DEFAULT 0 CHECK (utilization_percent >= 0 AND utilization_percent <= 100)
);

-- Indexes for routing_statistics
CREATE INDEX IF NOT EXISTS idx_routing_stats_interface ON routing_statistics(interface_id);
CREATE INDEX IF NOT EXISTS idx_routing_stats_time ON routing_statistics(collected_at);
CREATE INDEX IF NOT EXISTS idx_routing_stats_interface_time ON routing_statistics(interface_id, collected_at DESC);

-- Partial index for recent statistics (last 24 hours)
CREATE INDEX IF NOT EXISTS idx_routing_stats_recent ON routing_statistics(interface_id, collected_at)
    WHERE collected_at > NOW() - INTERVAL '24 hours';

COMMENT ON TABLE routing_statistics IS 'Per-interface routing statistics for performance monitoring';
COMMENT ON COLUMN routing_statistics.throughput_rx_bps IS 'Receive throughput in bits per second';

-- =============================================================================
-- SECTION 8: Table - load_balancer_config
-- Stores load balancing configuration for multi-WAN scenarios
-- =============================================================================

CREATE TABLE IF NOT EXISTS load_balancer_config (
    config_id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wan_interface_id    UUID NOT NULL REFERENCES network_interfaces(id) ON DELETE CASCADE,
    mode                VARCHAR(50) DEFAULT 'ROUND_ROBIN' CHECK (mode IN (
        'DISABLED', 'ROUND_ROBIN', 'WEIGHTED', 'LEAST_CONNECTIONS', 
        'HASH_BASED', 'FAILOVER_ONLY', 'BANDWIDTH_BASED'
    )),
    weight              INTEGER DEFAULT 1 CHECK (weight >= 1 AND weight <= 100),
    priority            INTEGER DEFAULT 100 CHECK (priority >= 1 AND priority <= 1000),
    max_connections     INTEGER,
    max_bandwidth_mbps  INTEGER,
    is_primary          BOOLEAN DEFAULT FALSE,
    is_active           BOOLEAN DEFAULT TRUE,
    health_check_url    VARCHAR(512),
    health_check_interval_sec INTEGER DEFAULT 30 CHECK (health_check_interval_sec >= 5),
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Only one primary WAN per configuration
    CONSTRAINT unique_wan_config UNIQUE (wan_interface_id)
);

-- Indexes for load_balancer_config
CREATE INDEX IF NOT EXISTS idx_lb_config_wan ON load_balancer_config(wan_interface_id);
CREATE INDEX IF NOT EXISTS idx_lb_config_mode ON load_balancer_config(mode);
CREATE INDEX IF NOT EXISTS idx_lb_config_active ON load_balancer_config(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_lb_config_primary ON load_balancer_config(is_primary) WHERE is_primary = TRUE;

COMMENT ON TABLE load_balancer_config IS 'Load balancing configuration for multi-WAN scenarios';
COMMENT ON COLUMN load_balancer_config.weight IS 'Load balancing weight (1-100), higher = more traffic';
COMMENT ON COLUMN load_balancer_config.priority IS 'Failover priority (1-1000), lower = higher priority';

-- =============================================================================
-- SECTION 9: Table - static_routes
-- Stores static routing entries configured by administrator
-- =============================================================================

CREATE TABLE IF NOT EXISTS static_routes (
    route_id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    destination         INET NOT NULL,
    netmask             VARCHAR(50) NOT NULL,
    gateway             INET NOT NULL,
    interface_id        UUID REFERENCES network_interfaces(id) ON DELETE CASCADE,
    metric              INTEGER DEFAULT 100 CHECK (metric >= 0),
    is_enabled          BOOLEAN DEFAULT TRUE,
    description         TEXT,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by          VARCHAR(255),
    
    CONSTRAINT unique_route UNIQUE (destination, netmask, gateway)
);

-- Indexes for static_routes
CREATE INDEX IF NOT EXISTS idx_routes_destination ON static_routes(destination);
CREATE INDEX IF NOT EXISTS idx_routes_gateway ON static_routes(gateway);
CREATE INDEX IF NOT EXISTS idx_routes_interface ON static_routes(interface_id);
CREATE INDEX IF NOT EXISTS idx_routes_enabled ON static_routes(is_enabled) WHERE is_enabled = TRUE;

COMMENT ON TABLE static_routes IS 'Static routing entries configured by administrator';

-- =============================================================================
-- SECTION 10: Cleanup Functions
-- Stored procedures for automatic cleanup of expired data
-- =============================================================================

-- Function: Cleanup expired connections
CREATE OR REPLACE FUNCTION cleanup_expired_connections()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM connection_tracking
    WHERE expires_at IS NOT NULL AND expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_connections() IS 'Deletes expired connection tracking entries, returns count of deleted rows';

-- Function: Cleanup expired NAT mappings
CREATE OR REPLACE FUNCTION cleanup_expired_nat_mappings()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM nat_mappings
    WHERE expires_at < NOW() AND is_static = FALSE;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_nat_mappings() IS 'Deletes expired NAT mappings (except static), returns count of deleted rows';

-- Function: Cleanup old routing statistics (older than 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_statistics(retention_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM routing_statistics
    WHERE collected_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_old_statistics(INTEGER) IS 'Deletes routing statistics older than specified days (default 30)';

-- Function: Cleanup old health history (older than 90 days)
CREATE OR REPLACE FUNCTION cleanup_old_health_history(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM wan_health_history
    WHERE checked_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_old_health_history(INTEGER) IS 'Deletes health history older than specified days (default 90)';

-- Function: Cleanup old failover events (older than 365 days)
CREATE OR REPLACE FUNCTION cleanup_old_failover_events(retention_days INTEGER DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM failover_events
    WHERE triggered_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_old_failover_events(INTEGER) IS 'Deletes failover events older than specified days (default 365)';

-- =============================================================================
-- SECTION 11: Triggers
-- Automatic triggers for data consistency
-- =============================================================================

-- Trigger function: Update timestamp on modification
CREATE OR REPLACE FUNCTION update_modified_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger: Auto-update network_interfaces.updated_at
DROP TRIGGER IF EXISTS trigger_update_interface_timestamp ON network_interfaces;
CREATE TRIGGER trigger_update_interface_timestamp
    BEFORE UPDATE ON network_interfaces
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_timestamp();

-- Trigger: Auto-update load_balancer_config.updated_at
DROP TRIGGER IF EXISTS trigger_update_lb_config_timestamp ON load_balancer_config;
CREATE TRIGGER trigger_update_lb_config_timestamp
    BEFORE UPDATE ON load_balancer_config
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_timestamp();

-- Trigger: Auto-update static_routes.updated_at
DROP TRIGGER IF EXISTS trigger_update_routes_timestamp ON static_routes;
CREATE TRIGGER trigger_update_routes_timestamp
    BEFORE UPDATE ON static_routes
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_timestamp();

-- Trigger function: Update connection last_seen on modification
CREATE OR REPLACE FUNCTION update_connection_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_seen = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger: Auto-update connection_tracking.last_seen
DROP TRIGGER IF EXISTS trigger_update_connection_last_seen ON connection_tracking;
CREATE TRIGGER trigger_update_connection_last_seen
    BEFORE UPDATE ON connection_tracking
    FOR EACH ROW
    EXECUTE FUNCTION update_connection_last_seen();

-- Trigger function: Calculate failover duration when completed_at is set
CREATE OR REPLACE FUNCTION calculate_failover_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
        NEW.duration_seconds = EXTRACT(EPOCH FROM (NEW.completed_at - NEW.triggered_at))::INTEGER;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger: Auto-calculate failover_events.duration_seconds
DROP TRIGGER IF EXISTS trigger_calculate_failover_duration ON failover_events;
CREATE TRIGGER trigger_calculate_failover_duration
    BEFORE UPDATE ON failover_events
    FOR EACH ROW
    EXECUTE FUNCTION calculate_failover_duration();

-- =============================================================================
-- SECTION 12: Views
-- Pre-defined views for common queries
-- =============================================================================

-- View: Current WAN interface status with latest health
CREATE OR REPLACE VIEW v_wan_status AS
SELECT 
    ni.id,
    ni.interface_name,
    ni.ip_address,
    ni.gateway,
    ni.state,
    ni.speed_mbps,
    lbc.mode AS lb_mode,
    lbc.weight,
    lbc.priority,
    lbc.is_primary,
    lbc.is_active,
    wh.state AS health_state,
    wh.latency_ms,
    wh.packet_loss_percent,
    wh.checked_at AS last_health_check
FROM network_interfaces ni
LEFT JOIN load_balancer_config lbc ON ni.id = lbc.wan_interface_id
LEFT JOIN LATERAL (
    SELECT state, latency_ms, packet_loss_percent, checked_at
    FROM wan_health_history
    WHERE wan_interface_id = ni.id
    ORDER BY checked_at DESC
    LIMIT 1
) wh ON TRUE
WHERE ni.interface_type = 'WAN';

COMMENT ON VIEW v_wan_status IS 'Current WAN interface status with latest health check data';

-- View: Active connection summary by interface
CREATE OR REPLACE VIEW v_connection_summary AS
SELECT 
    ni.interface_name,
    ni.interface_type,
    COUNT(ct.connection_id) AS total_connections,
    COUNT(ct.connection_id) FILTER (WHERE ct.state = 'ESTABLISHED') AS established,
    COUNT(ct.connection_id) FILTER (WHERE ct.state = 'NEW') AS new_connections,
    SUM(ct.bytes_sent) AS total_bytes_sent,
    SUM(ct.bytes_received) AS total_bytes_received
FROM network_interfaces ni
LEFT JOIN connection_tracking ct ON ni.id = ct.wan_interface_id OR ni.id = ct.lan_interface_id
WHERE ct.state NOT IN ('CLOSED', 'INVALID') OR ct.state IS NULL
GROUP BY ni.id, ni.interface_name, ni.interface_type;

COMMENT ON VIEW v_connection_summary IS 'Active connection summary grouped by interface';

-- View: NAT utilization per WAN
CREATE OR REPLACE VIEW v_nat_utilization AS
SELECT 
    ni.interface_name,
    ni.ip_address AS external_ip,
    COUNT(nm.mapping_id) AS active_mappings,
    COUNT(nm.mapping_id) FILTER (WHERE nm.is_static = TRUE) AS static_mappings,
    SUM(nm.bytes_sent + nm.bytes_received) AS total_bytes,
    MIN(nm.external_port) AS min_port_used,
    MAX(nm.external_port) AS max_port_used
FROM network_interfaces ni
LEFT JOIN nat_mappings nm ON ni.id = nm.wan_interface_id AND nm.expires_at > NOW()
WHERE ni.interface_type = 'WAN'
GROUP BY ni.id, ni.interface_name, ni.ip_address;

COMMENT ON VIEW v_nat_utilization IS 'NAT port utilization per WAN interface';

-- =============================================================================
-- SECTION 13: Initial Data / Defaults
-- =============================================================================

-- Insert default load balancer mode (disabled until configured)
-- This would typically be done by the application on first run

-- =============================================================================
-- GRANTS (uncomment and modify for production)
-- =============================================================================
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nic_management_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nic_management_app;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO nic_management_app;

-- =============================================================================
-- Schema Version Tracking
-- =============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'schema_versions') THEN
        CREATE TABLE schema_versions (
            id SERIAL PRIMARY KEY,
            schema_name VARCHAR(100) NOT NULL,
            version VARCHAR(20) NOT NULL,
            applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            description TEXT
        );
    END IF;
    
    INSERT INTO schema_versions (schema_name, version, description)
    VALUES ('nic_management', '1.0.0', 'Initial NIC Management schema with interfaces, connections, NAT, health, failover tables');
END $$;
