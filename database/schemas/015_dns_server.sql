-- ============================================================================
-- DNS Server Database Schema
-- Schema: 015_dns_server.sql
-- Purpose: Store DNS zones and records for authoritative DNS
-- ============================================================================

-- DNS Zones table
CREATE TABLE IF NOT EXISTS dns_zones (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,        -- Zone name (e.g., "safeops.local")
    type VARCHAR(50) NOT NULL DEFAULT 'master', -- master, slave, forward
    enabled BOOLEAN NOT NULL DEFAULT true,
    
    -- SOA record fields
    soa_mname VARCHAR(255),                   -- Primary nameserver
    soa_rname VARCHAR(255),                   -- Admin email
    soa_serial INTEGER DEFAULT 1,
    soa_refresh INTEGER DEFAULT 3600,         -- 1 hour
    soa_retry INTEGER DEFAULT 600,            -- 10 minutes
    soa_expire INTEGER DEFAULT 604800,        -- 1 week
    soa_minimum INTEGER DEFAULT 300,          -- 5 minutes (negative cache TTL)
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- DNS Records table
CREATE TABLE IF NOT EXISTS dns_records (
    id SERIAL PRIMARY KEY,
    zone_id INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,               -- Record name (e.g., "server1" or "@")
    type VARCHAR(10) NOT NULL,                -- A, AAAA, CNAME, PTR, MX, TXT, NS
    value VARCHAR(1024) NOT NULL,             -- Record value (IP, hostname, etc.)
    ttl INTEGER NOT NULL DEFAULT 300,         -- TTL in seconds
    priority INTEGER,                         -- For MX records
    enabled BOOLEAN NOT NULL DEFAULT true,
    
    -- Metadata
    source VARCHAR(50) DEFAULT 'manual',      -- manual, dhcp, api
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Unique constraint per zone/name/type/value
    UNIQUE(zone_id, name, type, value)
);

-- Reverse DNS zones (for PTR records)
CREATE TABLE IF NOT EXISTS dns_reverse_zones (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,        -- e.g., "168.192.in-addr.arpa"
    network_prefix VARCHAR(50) NOT NULL,      -- e.g., "192.168.0.0/16"
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_dns_records_zone_id ON dns_records(zone_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_name ON dns_records(name);
CREATE INDEX IF NOT EXISTS idx_dns_records_type ON dns_records(type);
CREATE INDEX IF NOT EXISTS idx_dns_zones_name ON dns_zones(name);

-- Insert default safeops.local zone (Phase 2+)
-- INSERT INTO dns_zones (name, type, soa_mname, soa_rname)
-- VALUES ('safeops.local', 'master', 'ns1.safeops.local', 'admin.safeops.local');
