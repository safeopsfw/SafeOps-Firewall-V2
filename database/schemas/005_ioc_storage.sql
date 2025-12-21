-- IOC Storage Schema
-- Indicator of Compromise (IOC) management

CREATE TABLE IF NOT EXISTS ioc_storage (
    id BIGSERIAL PRIMARY KEY,
    ioc_value TEXT NOT NULL,
    ioc_type VARCHAR(50) NOT NULL, -- ip, domain, url, hash, email
    threat_score INT DEFAULT 50,
    confidence INT DEFAULT 50,
    category VARCHAR(50),
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    source VARCHAR(255),
    metadata JSONB
);

CREATE INDEX idx_ioc_storage_value ON ioc_storage(ioc_value);
CREATE INDEX idx_ioc_storage_type ON ioc_storage(ioc_type);
CREATE INDEX idx_ioc_storage_score ON ioc_storage(threat_score);
CREATE INDEX idx_ioc_storage_confidence ON ioc_storage(confidence);
