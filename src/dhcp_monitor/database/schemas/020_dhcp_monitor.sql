-- ============================================================================
-- FILE: 020_dhcp_monitor.sql
-- PURPOSE: PostgreSQL schema for DHCP Monitor Phase 2
-- RUN: psql -U postgres -f 020_dhcp_monitor.sql
-- ============================================================================

-- ============================================================================
-- STEP 1: CREATE DATABASE
-- ============================================================================
-- Run this as postgres superuser:
-- CREATE DATABASE safeops_network WITH ENCODING 'UTF8';

-- ============================================================================
-- STEP 2: CREATE USER (run as superuser)
-- ============================================================================
-- CREATE USER safeops_admin WITH PASSWORD 'YourSecurePassword123!';
-- GRANT ALL PRIVILEGES ON DATABASE safeops_network TO safeops_admin;

-- ============================================================================
-- STEP 3: CONNECT TO DATABASE
-- ============================================================================
-- \c safeops_network

-- ============================================================================
-- STEP 4: ENABLE UUID EXTENSION (may require superuser - already exists in most DBs)
-- ============================================================================
-- Try uuid-ossp first, fallback to pgcrypto (PostgreSQL 13+)
DO $$
BEGIN
    -- Try to create uuid-ossp (preferred)
    BEGIN
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    EXCEPTION WHEN insufficient_privilege THEN
        -- Try pgcrypto as fallback (uses gen_random_uuid)
        BEGIN
            CREATE EXTENSION IF NOT EXISTS "pgcrypto";
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'UUID extension already available or cannot be created';
        END;
    END;
END $$;

-- ============================================================================
-- TABLE: devices
-- Primary device registry - tracks ALL network devices
-- ============================================================================
CREATE TABLE IF NOT EXISTS devices (
    -- Primary Key (uses gen_random_uuid from pgcrypto or PostgreSQL 13+)
    device_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Device Identity (Required)
    mac_address         VARCHAR(17) NOT NULL UNIQUE,  -- Format: AA:BB:CC:DD:EE:FF
    
    -- Current Network State
    current_ip          INET,                          -- IPv4 or IPv6 address
    previous_ip         INET,                          -- Last known IP before current
    
    -- Device Information
    hostname            VARCHAR(255),                  -- Device-reported hostname
    device_type         VARCHAR(50) DEFAULT 'Unknown', -- Laptop, Phone, IoT, Printer
    vendor              VARCHAR(100),                  -- MAC OUI vendor (Apple, Samsung)
    
    -- Security Status
    trust_status        VARCHAR(20) DEFAULT 'UNTRUSTED' 
                        CHECK (trust_status IN ('UNTRUSTED', 'TRUSTED', 'BLOCKED')),
    
    -- Network Interface
    interface_name      VARCHAR(100),                  -- "Mobile Hotspot", "Ethernet"
    interface_index     INTEGER,                       -- Windows interface index
    interface_guid      VARCHAR(50),                   -- Windows adapter GUID
    
    -- Connection Status
    status              VARCHAR(20) DEFAULT 'ACTIVE'
                        CHECK (status IN ('ACTIVE', 'OFFLINE', 'EXPIRED')),
    is_online           BOOLEAN DEFAULT TRUE,
    
    -- Detection Method
    detection_method    VARCHAR(30) DEFAULT 'IP_HELPER_API'
                        CHECK (detection_method IN ('IP_HELPER_API', 'DHCP_EVENT_LOG', 'ARP_TABLE', 'MANUAL')),
    
    -- Timestamps
    first_seen          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen           TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Notes
    notes               TEXT
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_devices_current_ip ON devices(current_ip);
CREATE INDEX IF NOT EXISTS idx_devices_trust_status ON devices(trust_status);
CREATE INDEX IF NOT EXISTS idx_devices_interface_name ON devices(interface_name);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_devices_is_online ON devices(is_online);

-- ============================================================================
-- TABLE: dhcp_leases
-- DHCP lease lifecycle tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS dhcp_leases (
    -- Primary Key
    lease_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Device Reference
    device_id           UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    
    -- Lease Information
    ip_address          INET NOT NULL,
    interface_name      VARCHAR(100),
    
    -- Lease Timing
    lease_start         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    lease_end           TIMESTAMP WITH TIME ZONE,
    lease_duration      INTERVAL,
    
    -- Lease State
    lease_state         VARCHAR(20) DEFAULT 'ACTIVE'
                        CHECK (lease_state IN ('ACTIVE', 'EXPIRED', 'RELEASED', 'RENEWED')),
    lease_renewals      INTEGER DEFAULT 0,
    
    -- Event Type
    event_type          VARCHAR(20) DEFAULT 'ASSIGNED'
                        CHECK (event_type IN ('ASSIGNED', 'RENEWED', 'EXPIRED', 'RELEASED')),
    
    -- Timestamp
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_device_id ON dhcp_leases(device_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_ip_address ON dhcp_leases(ip_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_interface_name ON dhcp_leases(interface_name);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_lease_state ON dhcp_leases(lease_state);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_lease_start ON dhcp_leases(lease_start DESC);

-- ============================================================================
-- TABLE: ip_history
-- IP address change tracking for troubleshooting
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_history (
    -- Primary Key
    history_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Device Reference
    device_id           UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    
    -- IP Change Information
    ip_address          INET NOT NULL,
    previous_ip         INET,
    
    -- Interface Information
    interface_name      VARCHAR(100),
    interface_index     INTEGER,
    
    -- Change Reason
    change_reason       VARCHAR(30) DEFAULT 'IP_CHANGE_CALLBACK'
                        CHECK (change_reason IN (
                            'IP_CHANGE_CALLBACK',
                            'DHCP_RENEW',
                            'NIC_SWITCH',
                            'RECONNECT',
                            'MANUAL',
                            'ARP_DETECTION'
                        )),
    
    -- Timestamps
    assigned_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    released_at         TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_ip_history_device_id ON ip_history(device_id);
CREATE INDEX IF NOT EXISTS idx_ip_history_ip_address ON ip_history(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_history_assigned_at ON ip_history(assigned_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_history_interface_name ON ip_history(interface_name);

-- ============================================================================
-- TABLE: schema_migrations
-- Tracks applied database migrations
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_migrations (
    version             INTEGER PRIMARY KEY,
    applied_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    description         TEXT,
    checksum            VARCHAR(64)
);

-- Record this migration
INSERT INTO schema_migrations (version, description, checksum)
VALUES (20, 'DHCP Monitor Phase 2 - Initial Schema', 'manual_execution')
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- TRIGGER: Auto-update updated_at timestamp
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_devices_updated_at ON devices;
CREATE TRIGGER update_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- SAMPLE DATA (Optional - for testing)
-- ============================================================================
-- Uncomment to insert test devices:

-- INSERT INTO devices (mac_address, current_ip, hostname, device_type, vendor, trust_status, interface_name, detection_method)
-- VALUES 
--     ('AA:BB:CC:11:22:33', '192.168.137.50', 'iPhone-John', 'Phone', 'Apple', 'UNTRUSTED', 'Mobile Hotspot', 'IP_HELPER_API'),
--     ('DD:EE:FF:44:55:66', '192.168.137.51', 'Galaxy-S21', 'Phone', 'Samsung', 'UNTRUSTED', 'Mobile Hotspot', 'IP_HELPER_API'),
--     ('11:22:33:AA:BB:CC', '192.168.1.100', 'DESKTOP-WORK', 'Laptop', 'Dell', 'TRUSTED', 'Ethernet', 'IP_HELPER_API');

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================
-- After running this script, verify with:
-- \dt                           -- List all tables
-- \d devices                    -- Describe devices table
-- SELECT * FROM schema_migrations;  -- Check migration applied

-- ============================================================================
-- GRANT PERMISSIONS (run as superuser after table creation)
-- ============================================================================
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO safeops_admin;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO safeops_admin;
-- GRANT USAGE ON SCHEMA public TO safeops_admin;

COMMENT ON TABLE devices IS 'Primary device registry - tracks ALL network devices across all NICs';
COMMENT ON TABLE dhcp_leases IS 'DHCP lease lifecycle tracking - historical record of IP assignments';
COMMENT ON TABLE ip_history IS 'IP address change history - audit trail for troubleshooting';
COMMENT ON TABLE schema_migrations IS 'Database migration version tracking';
