-- IP Reputation & Blacklist Schema
-- IP Blacklist & Reputation tracking

CREATE TABLE IF NOT EXISTS ip_blacklist (
    id BIGSERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    threat_score INT DEFAULT 50,
    category VARCHAR(50),
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    source VARCHAR(255),
    metadata JSONB
);

CREATE INDEX idx_ip_blacklist_ip ON ip_blacklist(ip_address);
CREATE INDEX idx_ip_blacklist_score ON ip_blacklist(threat_score);
CREATE INDEX idx_ip_blacklist_category ON ip_blacklist(category);
