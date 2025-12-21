-- Threat Feeds Schema
-- Feed source management and tracking

CREATE TABLE IF NOT EXISTS threat_feeds (
    id SERIAL PRIMARY KEY,
    feed_name VARCHAR(255) NOT NULL UNIQUE,
    feed_url TEXT,
    feed_type VARCHAR(50), -- ip, domain, hash, ioc, geo, proxy
    update_frequency INT DEFAULT 86400, -- seconds
    last_fetch TIMESTAMP,
    last_success TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active', -- active, inactive, error
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS feed_fetch_history (
    id BIGSERIAL PRIMARY KEY,
    feed_id INT REFERENCES threat_feeds(id),
    fetch_time TIMESTAMP DEFAULT NOW(),
    status VARCHAR(50),
    records_fetched INT DEFAULT 0,
    error_message TEXT,
    metadata JSONB
);

CREATE INDEX idx_threat_feeds_type ON threat_feeds(feed_type);
CREATE INDEX idx_threat_feeds_status ON threat_feeds(status);
CREATE INDEX idx_feed_history_feed_id ON feed_fetch_history(feed_id);
CREATE INDEX idx_feed_history_time ON feed_fetch_history(fetch_time);
