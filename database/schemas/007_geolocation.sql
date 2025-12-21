-- Geolocation Schema
-- IP geolocation data

CREATE TABLE IF NOT EXISTS ip_geolocation (
    id BIGSERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    country_code CHAR(2),
    country_name VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    timezone VARCHAR(50),
    isp VARCHAR(255),
    organization VARCHAR(255),
    asn INTEGER,
    asn_org VARCHAR(255),
    updated_at TIMESTAMP DEFAULT NOW(),
    source VARCHAR(255),
    metadata JSONB
);

CREATE INDEX idx_ip_geolocation_ip ON ip_geolocation(ip_address);
CREATE INDEX idx_ip_geolocation_country ON ip_geolocation(country_code);
CREATE INDEX idx_ip_geolocation_asn ON ip_geolocation(asn);
