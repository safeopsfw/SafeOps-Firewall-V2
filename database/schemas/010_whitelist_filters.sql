-- SafeOps Whitelist & Filter Rules
-- For managing allowed IPs, domains, and custom filter rules

-- Whitelist entries table
CREATE TABLE IF NOT EXISTS whitelist_entries (
    id SERIAL PRIMARY KEY,
    entry_type VARCHAR(20) NOT NULL, -- 'ip', 'domain', 'hash', 'cidr', 'regex'
    entry_value VARCHAR(512) NOT NULL,
    description TEXT,
    category VARCHAR(100), -- 'internal', 'partner', 'cdn', 'saas', 'custom'
    scope VARCHAR(50) DEFAULT 'global', -- 'global', 'sensor_group', 'specific_sensor'
    scope_target VARCHAR(255), -- sensor group name or sensor ID
    priority INTEGER DEFAULT 0, -- higher = processed first
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE, -- null = never expires
    created_by INTEGER REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Custom filter rules (JSON-based matching)
CREATE TABLE IF NOT EXISTS filter_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    rule_type VARCHAR(50) NOT NULL, -- 'suppress', 'enrich', 'redirect', 'transform'
    description TEXT,
    
    -- JSON filter conditions
    match_conditions JSONB NOT NULL, -- {"field": "source_ip", "operator": "in_cidr", "value": "10.0.0.0/8"}
    
    -- Action to take when matched
    action_type VARCHAR(50) NOT NULL, -- 'drop', 'allow', 'tag', 'route', 'modify'
    action_params JSONB, -- {"tag": "internal", "route_to": "low_priority_queue"}
    
    -- Rule behavior
    priority INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    mode VARCHAR(20) DEFAULT 'production', -- 'production', 'simulation', 'both'
    
    -- Statistics
    match_count BIGINT DEFAULT 0,
    last_matched_at TIMESTAMP WITH TIME ZONE,
    
    -- Audit
    created_by INTEGER REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Suppression rules (specific to IDS/IPS)
CREATE TABLE IF NOT EXISTS suppression_rules (
    id SERIAL PRIMARY KEY,
    rule_sid VARCHAR(50) NOT NULL, -- Suricata/Snort SID to suppress
    suppression_type VARCHAR(20) NOT NULL, -- 'ip', 'cidr', 'all'
    target_value VARCHAR(255), -- IP or CIDR to suppress for
    track_by VARCHAR(20) DEFAULT 'src', -- 'src', 'dst', 'both'
    threshold_type VARCHAR(20), -- 'limit', 'threshold', 'both'
    threshold_count INTEGER,
    threshold_seconds INTEGER,
    reason TEXT NOT NULL,
    ticket_reference VARCHAR(100), -- reference to ticketing system
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_whitelist_type ON whitelist_entries(entry_type);
CREATE INDEX IF NOT EXISTS idx_whitelist_value ON whitelist_entries(entry_value);
CREATE INDEX IF NOT EXISTS idx_whitelist_active ON whitelist_entries(is_active);
CREATE INDEX IF NOT EXISTS idx_filter_rules_type ON filter_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_filter_rules_active ON filter_rules(is_active);
CREATE INDEX IF NOT EXISTS idx_suppression_sid ON suppression_rules(rule_sid);

-- Sample whitelist entries
INSERT INTO whitelist_entries (entry_type, entry_value, description, category) VALUES
('cidr', '10.0.0.0/8', 'Internal RFC1918 - Private Network', 'internal'),
('cidr', '172.16.0.0/12', 'Internal RFC1918 - Private Network', 'internal'),
('cidr', '192.168.0.0/16', 'Internal RFC1918 - Private Network', 'internal'),
('domain', 'google.com', 'Google Services', 'saas'),
('domain', 'microsoft.com', 'Microsoft Services', 'saas'),
('domain', 'github.com', 'GitHub Services', 'saas')
ON CONFLICT DO NOTHING;
