-- ============================================================================
-- Threat Intelligence Database - Complete Setup Script
-- Database: threat_intel_db
-- PostgreSQL 18+
-- ============================================================================

-- Create database
CREATE DATABASE threat_intel_db;

-- Connect to database
\c threat_intel_db;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pg_trgm;          -- Fuzzy text matching
CREATE EXTENSION IF NOT EXISTS btree_gin;        -- Better GIN indexes
CREATE EXTENSION IF NOT EXISTS btree_gist;       -- Better GiST indexes

-- ============================================================================
-- TABLE 1: IP Geolocation
-- ============================================================================

CREATE TABLE ip_geolocation (
    -- Primary Key
    id BIGSERIAL PRIMARY KEY,
    
    -- IP Address (uses PostgreSQL INET type for efficient storage)
    ip_address INET NOT NULL UNIQUE,
    
    -- Location Data
    country_code VARCHAR(2),                    -- ISO 2-letter code (US, GB, CN)
    country_name VARCHAR(100),                  -- Full country name
    city VARCHAR(100),                          -- City name
    region VARCHAR(100),                        -- State/Province
    postal_code VARCHAR(20),                    -- ZIP/Postal code
    
    -- Geographic Coordinates
    latitude DECIMAL(10,8),                     -- -90 to +90
    longitude DECIMAL(11,8),                    -- -180 to +180
    accuracy_radius INTEGER,                    -- Accuracy in KM
    
    -- Network Information
    asn INTEGER,                                -- Autonomous System Number
    asn_org VARCHAR(255),                       -- ASN Organization name
    isp VARCHAR(255),                           -- Internet Service Provider
    connection_type VARCHAR(50),                -- Cable/DSL/Cellular/Corporate
    
    -- Additional Data
    timezone VARCHAR(50),                       -- IANA timezone (America/New_York)
    is_mobile BOOLEAN DEFAULT FALSE,            -- Mobile network?
    is_hosting BOOLEAN DEFAULT FALSE,           -- Hosting/datacenter IP?
    
    -- Metadata
    sources JSONB DEFAULT '[]'::jsonb,          -- Array of source names
    confidence INTEGER DEFAULT 50,              -- Data confidence 0-100
    
    -- Timestamps
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast lookups
CREATE INDEX idx_ip_geo_ip ON ip_geolocation(ip_address);
CREATE INDEX idx_ip_geo_country ON ip_geolocation(country_code);
CREATE INDEX idx_ip_geo_asn ON ip_geolocation(asn);
CREATE INDEX idx_ip_geo_city ON ip_geolocation(city);
CREATE INDEX idx_ip_geo_updated ON ip_geolocation(last_updated);

-- Comments
COMMENT ON TABLE ip_geolocation IS 'IP address geolocation and network information';
COMMENT ON COLUMN ip_geolocation.ip_address IS 'IPv4 or IPv6 address';
COMMENT ON COLUMN ip_geolocation.asn IS 'Autonomous System Number identifying the network';

-- ============================================================================
-- TABLE 2: IP Blacklist
-- ============================================================================

CREATE TABLE ip_blacklist (
    -- Primary Key
    id BIGSERIAL PRIMARY KEY,
    
    -- IP Address
    ip_address INET NOT NULL UNIQUE,
    
    -- Threat Assessment
    is_malicious BOOLEAN DEFAULT TRUE,
    threat_score INTEGER DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN 0 AND 100),
    
    -- Threat Classification
    abuse_type VARCHAR(50),                     -- spam, malware, phishing, bruteforce, c2, ddos
    threat_category VARCHAR(100),               -- More specific category
    malware_family VARCHAR(100),                -- If associated with malware
    
    -- Confidence & Evidence
    confidence INTEGER DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    evidence_count INTEGER DEFAULT 1,           -- How many sources reported this
    false_positive_count INTEGER DEFAULT 0,     -- Times marked as false positive
    
    -- Attack Information
    attack_types JSONB DEFAULT '[]'::jsonb,     -- Array of attack types
    target_ports JSONB DEFAULT '[]'::jsonb,     -- Commonly targeted ports
    target_services JSONB DEFAULT '[]'::jsonb,  -- Targeted services (SSH, RDP, HTTP)
    
    -- Description
    description TEXT,
    notes TEXT,                                 -- Additional analyst notes
    
    -- Metadata
    tags JSONB DEFAULT '[]'::jsonb,             -- Custom tags
    sources JSONB DEFAULT '[]'::jsonb,          -- Array of source names
    raw_data JSONB,                             -- Original source data
    
    -- Status
    status VARCHAR(20) DEFAULT 'active',        -- active, expired, whitelisted
    
    -- Timestamps
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP                        -- When this entry should be removed
);

-- Indexes
CREATE INDEX idx_ip_blacklist_ip ON ip_blacklist(ip_address);
CREATE INDEX idx_ip_blacklist_malicious ON ip_blacklist(is_malicious);
CREATE INDEX idx_ip_blacklist_score ON ip_blacklist(threat_score DESC);
CREATE INDEX idx_ip_blacklist_type ON ip_blacklist(abuse_type);
CREATE INDEX idx_ip_blacklist_status ON ip_blacklist(status);
CREATE INDEX idx_ip_blacklist_first_seen ON ip_blacklist(first_seen);
CREATE INDEX idx_ip_blacklist_expires ON ip_blacklist(expires_at);

-- Partial index for only malicious IPs (faster queries)
CREATE INDEX idx_ip_blacklist_malicious_only ON ip_blacklist(ip_address) WHERE is_malicious = TRUE;

-- GIN index for JSONB tags
CREATE INDEX idx_ip_blacklist_tags ON ip_blacklist USING gin(tags);

COMMENT ON TABLE ip_blacklist IS 'Malicious and blacklisted IP addresses';

-- ============================================================================
-- TABLE 3: IP Anonymization
-- ============================================================================

CREATE TABLE ip_anonymization (
    -- Primary Key
    id BIGSERIAL PRIMARY KEY,
    
    -- IP Address
    ip_address INET NOT NULL UNIQUE,
    
    -- Anonymization Types (can be multiple)
    is_vpn BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,
    is_proxy BOOLEAN DEFAULT FALSE,
    is_datacenter BOOLEAN DEFAULT FALSE,
    is_relay BOOLEAN DEFAULT FALSE,
    is_hosting BOOLEAN DEFAULT FALSE,
    
    -- VPN/Proxy Details
    provider_name VARCHAR(255),                 -- NordVPN, ExpressVPN, etc.
    service_type VARCHAR(50),                   -- commercial_vpn, free_vpn, proxy, tor_exit
    anonymity_level VARCHAR(20),                -- transparent, anonymous, elite
    
    -- Tor Specific
    tor_exit_node BOOLEAN DEFAULT FALSE,
    tor_node_name VARCHAR(255),
    
    -- Proxy Specific
    proxy_type VARCHAR(20),                     -- http, https, socks4, socks5
    proxy_port INTEGER,
    
    -- Datacenter/Hosting
    datacenter_name VARCHAR(255),
    hosting_provider VARCHAR(255),
    infrastructure_type VARCHAR(50),            -- cloud, colocation, dedicated
    
    -- Geographic Information
    country_code VARCHAR(2),
    city VARCHAR(100),
    
    -- Risk Assessment
    risk_score INTEGER DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    abuse_history BOOLEAN DEFAULT FALSE,        -- History of abuse from this IP
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,             -- Currently operational?
    
    -- Metadata
    sources JSONB DEFAULT '[]'::jsonb,
    tags JSONB DEFAULT '[]'::jsonb,
    
    -- Timestamps
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_ip_anon_ip ON ip_anonymization(ip_address);
CREATE INDEX idx_ip_anon_vpn ON ip_anonymization(is_vpn) WHERE is_vpn = TRUE;
CREATE INDEX idx_ip_anon_tor ON ip_anonymization(is_tor) WHERE is_tor = TRUE;
CREATE INDEX idx_ip_anon_proxy ON ip_anonymization(is_proxy) WHERE is_proxy = TRUE;
CREATE INDEX idx_ip_anon_datacenter ON ip_anonymization(is_datacenter) WHERE is_datacenter = TRUE;
CREATE INDEX idx_ip_anon_provider ON ip_anonymization(provider_name);
CREATE INDEX idx_ip_anon_active ON ip_anonymization(is_active);

COMMENT ON TABLE ip_anonymization IS 'VPN, Tor, Proxy, and datacenter IP detection';

-- ============================================================================
-- TABLE 4: Domains
-- ============================================================================

CREATE TABLE domains (
    -- Primary Key
    id BIGSERIAL PRIMARY KEY,
    
    -- Domain Information
    domain VARCHAR(255) NOT NULL UNIQUE,
    tld VARCHAR(50),                            -- .com, .org, .net
    subdomain VARCHAR(255),                     -- www, mail, api
    root_domain VARCHAR(255),                   -- example.com (without subdomain)
    
    -- Threat Assessment
    is_malicious BOOLEAN DEFAULT FALSE,
    threat_score INTEGER DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    reputation_score INTEGER DEFAULT 50 CHECK (reputation_score BETWEEN 0 AND 100),
    
    -- Classification
    category VARCHAR(100),                      -- phishing, malware, c2, spam, adult, gambling
    subcategory VARCHAR(100),
    threat_types JSONB DEFAULT '[]'::jsonb,     -- Multiple threat types
    
    -- Domain Registration
    registrar VARCHAR(255),
    registration_date TIMESTAMP,
    expiration_date TIMESTAMP,
    updated_date TIMESTAMP,
    registrant_name VARCHAR(255),
    registrant_org VARCHAR(255),
    registrant_country VARCHAR(2),
    
    -- DNS Information
    nameservers JSONB,                          -- Array of nameservers
    dns_records JSONB,                          -- A, AAAA, MX, TXT, CNAME records
    ip_addresses JSONB DEFAULT '[]'::jsonb,     -- IPs this domain resolves to
    
    -- SSL/TLS Certificate
    has_ssl BOOLEAN DEFAULT FALSE,
    ssl_issuer VARCHAR(255),
    ssl_valid_from TIMESTAMP,
    ssl_valid_to TIMESTAMP,
    ssl_fingerprint VARCHAR(64),
    
    -- Web Content
    page_title TEXT,
    page_description TEXT,
    content_language VARCHAR(10),
    
    -- Reputation Indicators
    age_days INTEGER,                           -- Domain age in days
    is_newly_registered BOOLEAN DEFAULT FALSE,  -- < 30 days old
    is_recently_active BOOLEAN DEFAULT TRUE,
    alexa_rank INTEGER,                         -- Popularity rank
    
    -- Malware/Phishing Specific
    phishing_target VARCHAR(100),               -- PayPal, Microsoft, etc.
    malware_families JSONB DEFAULT '[]'::jsonb,
    exploits JSONB DEFAULT '[]'::jsonb,
    
    -- Detection Information
    detection_count INTEGER DEFAULT 0,          -- Times flagged
    false_positive_count INTEGER DEFAULT 0,
    
    -- Metadata
    tags JSONB DEFAULT '[]'::jsonb,
    sources JSONB DEFAULT '[]'::jsonb,
    raw_whois JSONB,
    
    -- Status
    status VARCHAR(20) DEFAULT 'active',        -- active, expired, sinkholed, seized
    
    -- Timestamps
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_domain_name ON domains(domain);
CREATE INDEX idx_domain_root ON domains(root_domain);
CREATE INDEX idx_domain_tld ON domains(tld);
CREATE INDEX idx_domain_malicious ON domains(is_malicious);
CREATE INDEX idx_domain_score ON domains(threat_score DESC);
CREATE INDEX idx_domain_category ON domains(category);
CREATE INDEX idx_domain_newly_registered ON domains(is_newly_registered) WHERE is_newly_registered = TRUE;
CREATE INDEX idx_domain_registration_date ON domains(registration_date);

-- Full-text search for domain names (fuzzy matching)
CREATE INDEX idx_domain_name_trgm ON domains USING gin(domain gin_trgm_ops);

-- GIN indexes for JSONB
CREATE INDEX idx_domain_tags ON domains USING gin(tags);
CREATE INDEX idx_domain_ip_addresses ON domains USING gin(ip_addresses);

COMMENT ON TABLE domains IS 'Domain reputation and intelligence data';

-- ============================================================================
-- TABLE 5: Hashes
-- ============================================================================

CREATE TABLE hashes (
    -- Primary Key
    id BIGSERIAL PRIMARY KEY,
    
    -- Hash Values
    md5 VARCHAR(32),
    sha1 VARCHAR(40),
    sha256 VARCHAR(64) UNIQUE NOT NULL,         -- Primary hash identifier
    sha512 VARCHAR(128),
    ssdeep VARCHAR(255),                        -- Fuzzy hash for similarity
    imphash VARCHAR(32),                        -- Import hash for PE files
    
    -- Threat Assessment
    is_malicious BOOLEAN DEFAULT FALSE,
    threat_score INTEGER DEFAULT 0 CHECK (threat_score BETWEEN 0 AND 100),
    
    -- File Information
    file_name VARCHAR(500),
    file_type VARCHAR(50),                      -- exe, dll, pdf, doc, apk
    file_size BIGINT,                           -- Size in bytes
    mime_type VARCHAR(100),
    
    -- Malware Classification
    malware_family VARCHAR(255),                -- Emotet, Dridex, Ransomware.WannaCry
    malware_type VARCHAR(100),                  -- trojan, ransomware, backdoor, spyware
    malware_aliases JSONB DEFAULT '[]'::jsonb,  -- Other names for same malware
    
    -- Antivirus Detection
    av_detections INTEGER DEFAULT 0,            -- How many AVs detected it
    total_av_engines INTEGER DEFAULT 0,         -- Total AVs scanned
    av_detection_rate DECIMAL(5,2),             -- Percentage (0-100)
    av_results JSONB,                           -- Individual AV results
    
    -- Sandbox Analysis
    sandbox_verdict VARCHAR(50),                -- malicious, suspicious, benign
    sandbox_score INTEGER,
    sandbox_behaviors JSONB DEFAULT '[]'::jsonb, -- Array of observed behaviors
    network_activity JSONB,                     -- IPs/domains contacted
    
    -- File Behavior
    creates_files JSONB DEFAULT '[]'::jsonb,
    modifies_registry JSONB DEFAULT '[]'::jsonb,
    creates_processes JSONB DEFAULT '[]'::jsonb,
    
    -- PE File Specific (Windows executables)
    pe_compile_time TIMESTAMP,
    pe_original_filename VARCHAR(500),
    pe_company VARCHAR(255),
    pe_product VARCHAR(255),
    pe_version VARCHAR(50),
    pe_signature_valid BOOLEAN,
    
    -- External References
    virustotal_link VARCHAR(500),
    hybrid_analysis_link VARCHAR(500),
    
    -- Metadata
    tags JSONB DEFAULT '[]'::jsonb,
    sources JSONB DEFAULT '[]'::jsonb,
    
    -- Timestamps
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_hash_md5 ON hashes(md5);
CREATE INDEX idx_hash_sha1 ON hashes(sha1);
CREATE INDEX idx_hash_sha256 ON hashes(sha256);
CREATE INDEX idx_hash_sha512 ON hashes(sha512);
CREATE INDEX idx_hash_malicious ON hashes(is_malicious);
CREATE INDEX idx_hash_score ON hashes(threat_score DESC);
CREATE INDEX idx_hash_family ON hashes(malware_family);
CREATE INDEX idx_hash_type ON hashes(malware_type);
CREATE INDEX idx_hash_file_type ON hashes(file_type);
CREATE INDEX idx_hash_av_rate ON hashes(av_detection_rate DESC);

-- Partial index for malicious only
CREATE INDEX idx_hash_malicious_only ON hashes(sha256) WHERE is_malicious = TRUE;

-- GIN indexes
CREATE INDEX idx_hash_tags ON hashes USING gin(tags);
CREATE INDEX idx_hash_behaviors ON hashes USING gin(sandbox_behaviors);

COMMENT ON TABLE hashes IS 'File hash intelligence and malware analysis';

-- ============================================================================
-- TABLE 6: IOCs (Indicators of Compromise)
-- ============================================================================

CREATE TABLE iocs (
    -- Primary Key
    id BIGSERIAL PRIMARY KEY,
    
    -- IOC Information
    ioc_type VARCHAR(50) NOT NULL,              -- ip, domain, url, hash_md5, hash_sha256, email
    ioc_value TEXT NOT NULL,                    -- The actual IOC value
    
    -- Threat Classification
    threat_type VARCHAR(100),                   -- malware, phishing, c2, exploit
    threat_category VARCHAR(100),
    severity VARCHAR(20),                       -- low, medium, high, critical
    
    -- Confidence & Context
    confidence INTEGER DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    tlp_level VARCHAR(20) DEFAULT 'white',      -- Traffic Light Protocol: white, green, amber, red
    
    -- Description
    title VARCHAR(500),
    description TEXT,
    context TEXT,                               -- Additional context
    
    -- Attribution
    threat_actor VARCHAR(255),                  -- APT28, Lazarus, etc.
    campaign_name VARCHAR(255),                 -- Operation X, Campaign Y
    
    -- Relationships
    related_iocs JSONB DEFAULT '[]'::jsonb,     -- Array of related IOC IDs
    
    -- Metadata
    tags JSONB DEFAULT '[]'::jsonb,
    sources JSONB DEFAULT '[]'::jsonb,
    mitre_attack_ids JSONB DEFAULT '[]'::jsonb, -- MITRE ATT&CK technique IDs
    
    -- External References
    external_references JSONB DEFAULT '[]'::jsonb,
    
    -- Status
    status VARCHAR(20) DEFAULT 'active',        -- active, expired, false_positive
    
    -- Timestamps
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP                        -- When this IOC should be removed
);

-- Indexes
CREATE UNIQUE INDEX idx_ioc_unique ON iocs(ioc_type, ioc_value);
CREATE INDEX idx_ioc_type ON iocs(ioc_type);
CREATE INDEX idx_ioc_value ON iocs(ioc_value);
CREATE INDEX idx_ioc_threat_type ON iocs(threat_type);
CREATE INDEX idx_ioc_severity ON iocs(severity);
CREATE INDEX idx_ioc_status ON iocs(status);
CREATE INDEX idx_ioc_expires ON iocs(expires_at);

-- Full-text search on description
CREATE INDEX idx_ioc_description_fts ON iocs USING gin(to_tsvector('english', description));

-- GIN indexes
CREATE INDEX idx_ioc_tags ON iocs USING gin(tags);
CREATE INDEX idx_ioc_sources ON iocs USING gin(sources);

COMMENT ON TABLE iocs IS 'Indicators of Compromise - centralized IOC repository';

-- ============================================================================
-- TABLE 7: Threat Feeds (Management Table)
-- ============================================================================

CREATE TABLE threat_feeds (
    -- Primary Key
    id BIGSERIAL PRIMARY KEY,
    
    -- Feed Information
    feed_name VARCHAR(255) NOT NULL UNIQUE,
    feed_url TEXT,
    feed_description TEXT,
    
    -- Feed Classification
    feed_type VARCHAR(50),                      -- ip_geo, ip_blacklist, domain, hash, ioc, mixed
    feed_format VARCHAR(20),                    -- csv, json, xml, txt, stix, misp
    feed_category VARCHAR(100),
    
    -- Configuration
    is_active BOOLEAN DEFAULT TRUE,
    is_premium BOOLEAN DEFAULT FALSE,           -- Premium/paid feed?
    update_frequency INTEGER DEFAULT 3600,      -- Seconds between updates
    update_schedule VARCHAR(50),                -- cron expression
    
    -- Authentication (if needed)
    requires_auth BOOLEAN DEFAULT FALSE,
    auth_type VARCHAR(50),                      -- api_key, basic, oauth
    auth_config JSONB,                          -- Encrypted auth credentials
    
    -- Parsing Configuration
    parser_type VARCHAR(50),                    -- csv, json, custom
    parser_config JSONB,                        -- Column mappings, delimiters
    
    -- Quality Metrics
    reliability_score INTEGER DEFAULT 50 CHECK (reliability_score BETWEEN 0 AND 100),
    false_positive_rate DECIMAL(5,2),           -- Percentage
    
    -- Statistics
    total_records_fetched BIGINT DEFAULT 0,
    total_records_imported BIGINT DEFAULT 0,
    total_records_rejected BIGINT DEFAULT 0,
    last_record_count INTEGER,
    
    -- Status
    last_fetch_status VARCHAR(20),              -- success, failed, partial
    last_error TEXT,
    consecutive_failures INTEGER DEFAULT 0,
    
    -- Timestamps
    last_fetched TIMESTAMP,
    last_successful_fetch TIMESTAMP,
    next_scheduled_fetch TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_feed_active ON threat_feeds(is_active);
CREATE INDEX idx_feed_type ON threat_feeds(feed_type);
CREATE INDEX idx_feed_next_fetch ON threat_feeds(next_scheduled_fetch);
CREATE INDEX idx_feed_last_fetch ON threat_feeds(last_fetched);

COMMENT ON TABLE threat_feeds IS 'Configuration and management of threat intelligence feeds';

-- ============================================================================
-- TABLE 8: Feed History (Management Table)
-- ============================================================================

CREATE TABLE feed_history (
    -- Primary Key
    id BIGSERIAL PRIMARY KEY,
    
    -- Feed Reference
    feed_id BIGINT REFERENCES threat_feeds(id) ON DELETE CASCADE,
    feed_name VARCHAR(255),                     -- Denormalized for faster queries
    
    -- Execution Information
    fetch_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms INTEGER,                  -- How long did it take
    
    -- Status
    status VARCHAR(20),                         -- started, parsing, storing, completed, failed
    
    -- Statistics
    records_downloaded INTEGER DEFAULT 0,
    records_parsed INTEGER DEFAULT 0,
    records_added INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    records_skipped INTEGER DEFAULT 0,
    records_rejected INTEGER DEFAULT 0,
    
    -- Error Information
    error_message TEXT,
    error_details JSONB,
    warnings JSONB DEFAULT '[]'::jsonb,
    
    -- File Information
    downloaded_file_path VARCHAR(500),
    file_size_bytes BIGINT,
    file_hash VARCHAR(64),                      -- SHA256 of downloaded file
    
    -- Metadata
    user_agent VARCHAR(255),
    source_ip INET,
    
    -- Timestamps
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- Indexes
CREATE INDEX idx_feed_history_feed ON feed_history(feed_id);
CREATE INDEX idx_feed_history_timestamp ON feed_history(fetch_timestamp DESC);
CREATE INDEX idx_feed_history_status ON feed_history(status);
CREATE INDEX idx_feed_history_feed_name ON feed_history(feed_name);

COMMENT ON TABLE feed_history IS 'Execution history and logs for threat intelligence feeds';

-- ============================================================================
-- Initial Seed Data - Popular Threat Feeds
-- ============================================================================

INSERT INTO threat_feeds (feed_name, feed_url, feed_type, feed_format, update_frequency, is_active) VALUES
('Feodo Tracker', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'ip_blacklist', 'txt', 300, TRUE),
('URLhaus Recent', 'https://urlhaus.abuse.ch/downloads/csv_recent/', 'domain', 'csv', 300, TRUE),
('Blocklist.de All', 'https://lists.blocklist.de/lists/all.txt', 'ip_blacklist', 'txt', 900, TRUE),
('IPsum', 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt', 'ip_blacklist', 'txt', 86400, TRUE),
('Tor Exit Nodes', 'https://check.torproject.org/exit-addresses', 'ip_anonymization', 'txt', 3600, TRUE),
('PhishTank', 'http://data.phishtank.com/data/online-valid.csv', 'domain', 'csv', 3600, TRUE),
('OpenPhish', 'https://openphish.com/feed.txt', 'domain', 'txt', 3600, TRUE),
('MalwareBazaar', 'https://bazaar.abuse.ch/export/csv/recent/', 'hash', 'csv', 300, TRUE),
('ThreatFox', 'https://threatfox.abuse.ch/export/csv/recent/', 'ioc', 'csv', 300, TRUE),
('Emerging Threats', 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', 'ip_blacklist', 'txt', 86400, TRUE);

COMMENT ON DATABASE threat_intel_db IS 'Threat Intelligence Database - Standalone system for IP/Domain/Hash intelligence';

-- ============================================================================
-- Database Setup Complete
-- ============================================================================
