-- Firewall Engine Database Schema
-- SafeOps V2 - Packet Filtering and Rule Management

-- =============================================================================
-- FIREWALL RULES TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS firewall_rules (
    rule_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    action          VARCHAR(20) NOT NULL DEFAULT 'BLOCK' CHECK (action IN ('ALLOW', 'BLOCK', 'LOG', 'REJECT')),
    protocol        VARCHAR(20) NOT NULL DEFAULT 'ANY' CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'ANY')),
    src_ip          VARCHAR(100) DEFAULT '*',
    dst_ip          VARCHAR(100) DEFAULT '*',
    src_port        VARCHAR(100) DEFAULT '*',
    dst_port        VARCHAR(100) DEFAULT '*',
    device_mac      VARCHAR(50) DEFAULT '*',
    priority        INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 1 AND priority <= 1000),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    hit_count       BIGINT NOT NULL DEFAULT 0,
    status          VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'staging', 'disabled')),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by      VARCHAR(100) DEFAULT 'system'
);

-- Index for faster rule lookups
CREATE INDEX IF NOT EXISTS idx_firewall_rules_priority ON firewall_rules(priority ASC);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_action ON firewall_rules(action);

-- =============================================================================
-- FIREWALL STATISTICS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS firewall_stats (
    stat_id         SERIAL PRIMARY KEY,
    stat_date       DATE NOT NULL DEFAULT CURRENT_DATE,
    total_packets   BIGINT NOT NULL DEFAULT 0,
    allowed_packets BIGINT NOT NULL DEFAULT 0,
    blocked_packets BIGINT NOT NULL DEFAULT 0,
    logged_packets  BIGINT NOT NULL DEFAULT 0,
    tcp_packets     BIGINT NOT NULL DEFAULT 0,
    udp_packets     BIGINT NOT NULL DEFAULT 0,
    icmp_packets    BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(stat_date)
);

-- =============================================================================
-- PACKET LOGS TABLE (Recent Activity for Real-Time Monitor)
-- =============================================================================
CREATE TABLE IF NOT EXISTS packet_logs (
    log_id          BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    src_ip          INET NOT NULL,
    dst_ip          INET NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(10) NOT NULL,
    action          VARCHAR(20) NOT NULL,
    rule_name       VARCHAR(255),
    rule_id         UUID REFERENCES firewall_rules(rule_id) ON DELETE SET NULL,
    packet_size     INTEGER,
    device_mac      VARCHAR(50)
);

-- Index for faster log queries
CREATE INDEX IF NOT EXISTS idx_packet_logs_timestamp ON packet_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_packet_logs_action ON packet_logs(action);

-- Auto-cleanup old logs (keep only last 1000 entries per day)
CREATE INDEX IF NOT EXISTS idx_packet_logs_cleanup ON packet_logs(timestamp);

-- =============================================================================
-- DEVICE POLICIES TABLE (Per-device firewall overrides)
-- =============================================================================
CREATE TABLE IF NOT EXISTS device_policies (
    policy_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_mac      VARCHAR(50) NOT NULL UNIQUE,
    policy_name     VARCHAR(255),
    default_action  VARCHAR(20) DEFAULT 'ALLOW' CHECK (default_action IN ('ALLOW', 'BLOCK')),
    bandwidth_limit INTEGER,              -- KB/s limit (NULL = unlimited)
    time_restriction JSONB,               -- e.g., {"start": "22:00", "end": "06:00", "action": "BLOCK"}
    blocked_ports   TEXT[],               -- Array of blocked ports
    allowed_ports   TEXT[],               -- Array of allowed ports (whitelist mode)
    notes           TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_policies_mac ON device_policies(device_mac);

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function to increment rule hit count
CREATE OR REPLACE FUNCTION increment_rule_hit(p_rule_id UUID)
RETURNS void AS $$
BEGIN
    UPDATE firewall_rules 
    SET hit_count = hit_count + 1, updated_at = NOW()
    WHERE rule_id = p_rule_id;
END;
$$ LANGUAGE plpgsql;

-- Function to update daily stats
CREATE OR REPLACE FUNCTION update_firewall_stats(
    p_action VARCHAR(20),
    p_protocol VARCHAR(10)
)
RETURNS void AS $$
BEGIN
    INSERT INTO firewall_stats (stat_date, total_packets, allowed_packets, blocked_packets, tcp_packets, udp_packets, icmp_packets)
    VALUES (CURRENT_DATE, 1, 
            CASE WHEN p_action = 'ALLOW' THEN 1 ELSE 0 END,
            CASE WHEN p_action = 'BLOCK' THEN 1 ELSE 0 END,
            CASE WHEN p_protocol = 'TCP' THEN 1 ELSE 0 END,
            CASE WHEN p_protocol = 'UDP' THEN 1 ELSE 0 END,
            CASE WHEN p_protocol = 'ICMP' THEN 1 ELSE 0 END)
    ON CONFLICT (stat_date) DO UPDATE SET
        total_packets = firewall_stats.total_packets + 1,
        allowed_packets = firewall_stats.allowed_packets + CASE WHEN p_action = 'ALLOW' THEN 1 ELSE 0 END,
        blocked_packets = firewall_stats.blocked_packets + CASE WHEN p_action = 'BLOCK' THEN 1 ELSE 0 END,
        tcp_packets = firewall_stats.tcp_packets + CASE WHEN p_protocol = 'TCP' THEN 1 ELSE 0 END,
        udp_packets = firewall_stats.udp_packets + CASE WHEN p_protocol = 'UDP' THEN 1 ELSE 0 END,
        icmp_packets = firewall_stats.icmp_packets + CASE WHEN p_protocol = 'ICMP' THEN 1 ELSE 0 END,
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- SEED DATA - Default Rules
-- =============================================================================
INSERT INTO firewall_rules (name, description, action, protocol, src_ip, dst_ip, src_port, dst_port, priority, enabled)
VALUES 
    ('Allow DNS', 'Allow all DNS queries', 'ALLOW', 'UDP', '*', '*', '*', '53', 5, true),
    ('Allow HTTP/HTTPS', 'Allow web traffic', 'ALLOW', 'TCP', '*', '*', '*', '80,443', 10, true),
    ('Allow Gaming - Steam', 'Fast-path for Steam gaming', 'ALLOW', 'UDP', '*', '*', '*', '27000-27050', 1, true),
    ('Allow Gaming - Discord', 'Fast-path for Discord voice', 'ALLOW', 'UDP', '*', '*', '*', '50000-65535', 1, true),
    ('Block SMB', 'Block Windows file sharing', 'BLOCK', 'TCP', '*', '*', '*', '445,139', 15, true),
    ('Block Telnet', 'Block insecure Telnet', 'BLOCK', 'TCP', '*', '*', '*', '23', 20, true)
ON CONFLICT DO NOTHING;

-- Insert initial stats row for today
INSERT INTO firewall_stats (stat_date, total_packets, allowed_packets, blocked_packets)
VALUES (CURRENT_DATE, 0, 0, 0)
ON CONFLICT (stat_date) DO NOTHING;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE firewall_rules IS 'Firewall rule definitions for packet filtering';
COMMENT ON TABLE firewall_stats IS 'Daily aggregated firewall statistics';
COMMENT ON TABLE packet_logs IS 'Recent packet activity for real-time monitoring';
COMMENT ON TABLE device_policies IS 'Per-device firewall policy overrides';
