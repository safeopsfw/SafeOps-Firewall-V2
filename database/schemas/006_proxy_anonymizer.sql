-- Proxy & Anonymizer Schema
-- VPN/Tor/Proxy data tracking

CREATE TABLE IF NOT EXISTS ip_anonymization (
    id BIGSERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    anonymization_type VARCHAR(50), -- tor, vpn, proxy, hosting
    provider VARCHAR(255),
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    source VARCHAR(255),
    metadata JSONB
);

CREATE INDEX idx_ip_anonymization_ip ON ip_anonymization(ip_address);
CREATE INDEX idx_ip_anonymization_type ON ip_anonymization(anonymization_type);
CREATE INDEX idx_ip_anonymization_provider ON ip_anonymization(provider);
