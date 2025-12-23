-- SafeOps Network Packet IOC Storage
-- For storing IP/Domain data from network packets to compare against threat intel

-- Network packet IOC cache table
CREATE TABLE IF NOT EXISTS network_packet_iocs (
    id BIGSERIAL PRIMARY KEY,
    ioc_type VARCHAR(20) NOT NULL, -- 'ip', 'domain', 'url', 'hash'
    ioc_value VARCHAR(512) NOT NULL,
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    packet_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    sensor_id VARCHAR(100),
    sensor_name VARCHAR(255),
    geo_country VARCHAR(100),
    geo_city VARCHAR(100),
    asn_number INTEGER,
    asn_name VARCHAR(255),
    threat_match BOOLEAN DEFAULT false,
    threat_score INTEGER,
    matched_feeds JSONB,
    raw_packet_ref VARCHAR(255), -- reference to PCAP storage
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast IOC lookup
CREATE INDEX IF NOT EXISTS idx_network_ioc_value ON network_packet_iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_network_ioc_type ON network_packet_iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_packet_iocs(packet_timestamp);
CREATE INDEX IF NOT EXISTS idx_network_threat_match ON network_packet_iocs(threat_match);
CREATE INDEX IF NOT EXISTS idx_network_source_ip ON network_packet_iocs(source_ip);
CREATE INDEX IF NOT EXISTS idx_network_dest_ip ON network_packet_iocs(destination_ip);

-- Partitioning by month for performance (run separately for each month)
-- CREATE TABLE network_packet_iocs_2024_01 PARTITION OF network_packet_iocs
-- FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
