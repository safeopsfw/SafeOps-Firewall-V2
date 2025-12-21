-- Domain Intelligence Schema
-- Domain reputation and intelligence tracking

CREATE TABLE IF NOT EXISTS domain_intelligence (
    id BIGSERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    threat_score INT DEFAULT 50,
    category VARCHAR(50),
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    source VARCHAR(255),
    metadata JSONB
);

CREATE INDEX idx_domain_intelligence_domain ON domain_intelligence(domain);
CREATE INDEX idx_domain_intelligence_score ON domain_intelligence(threat_score);
CREATE INDEX idx_domain_intelligence_category ON domain_intelligence(category);
