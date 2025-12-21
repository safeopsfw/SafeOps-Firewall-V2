-- Hash Intelligence Schema
-- File hash reputation tracking

CREATE TABLE IF NOT EXISTS hash_intelligence (
    id BIGSERIAL PRIMARY KEY,
    hash_value VARCHAR(128) NOT NULL UNIQUE,
    hash_type VARCHAR(10) NOT NULL, -- md5, sha1, sha256
    threat_score INT DEFAULT 50,
    category VARCHAR(50),
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    source VARCHAR(255),
    metadata JSONB
);

CREATE INDEX idx_hash_intelligence_hash ON hash_intelligence(hash_value);
CREATE INDEX idx_hash_intelligence_type ON hash_intelligence(hash_type);
CREATE INDEX idx_hash_intelligence_score ON hash_intelligence(threat_score);
