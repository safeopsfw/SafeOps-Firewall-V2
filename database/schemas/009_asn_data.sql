-- ASN Data Schema
-- Autonomous System Number information

CREATE TABLE IF NOT EXISTS asn_data (
    id SERIAL PRIMARY KEY,
    asn INTEGER NOT NULL UNIQUE,
    organization VARCHAR(255),
    country_code CHAR(2),
    description TEXT,
    updated_at TIMESTAMP DEFAULT NOW(),
    source VARCHAR(255),
    metadata JSONB
);

CREATE INDEX idx_asn_data_asn ON asn_data(asn);
CREATE INDEX idx_asn_data_org ON asn_data(organization);
CREATE INDEX idx_asn_data_country ON asn_data(country_code);
