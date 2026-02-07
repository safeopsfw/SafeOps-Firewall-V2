-- ============================================================================
-- FILE: database/seeds/initial_threat_categories.sql
-- PURPOSE: Define standardized threat categories and abuse types for taxonomy
-- DEPENDENCIES: Requires core schema files to be executed first
-- LAST UPDATED: 2025-12-22
-- ============================================================================

-- This file populates reference data for threat categorization used across
-- the entire SafeOps threat intelligence system. It ensures consistent
-- terminology, enables category-based filtering, and provides human-readable
-- descriptions for UI components.
--
-- TAXONOMY ALIGNMENT:
-- - Categories align with MITRE ATT&CK framework
-- - Classification follows STIX 2.1 threat taxonomy
-- - Severity levels compatible with CVSS scoring
--
-- USAGE:
-- These categories are referenced by foreign keys in threat intelligence
-- tables (ip_blacklist, domains, file_hashes) and used for filtering,
-- reporting, and automated response actions.

-- ============================================================================
-- SECTION 1: IP ABUSE TYPE REFERENCE DATA
-- ============================================================================

-- Create reference table for IP abuse types (if not exists in schema)
CREATE TABLE IF NOT EXISTS ip_abuse_types (
    id SERIAL PRIMARY KEY,
    category_code VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    severity_level INTEGER CHECK (severity_level BETWEEN 1 AND 10),
    recommended_action VARCHAR(20) CHECK (recommended_action IN ('allow', 'monitor', 'alert', 'block', 'quarantine')),
    color_code VARCHAR(7),  -- Hex color for UI display
    icon_name VARCHAR(50),  -- Icon identifier for UI
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert standard IP abuse type categories
INSERT INTO ip_abuse_types (category_code, display_name, description, severity_level, recommended_action, color_code, icon_name) VALUES
('spam', 'Email Spam', 'IP addresses identified as sources of unsolicited bulk email, often part of spam botnets or compromised mail servers.', 4, 'alert', '#FFA500', 'mail-spam'),
('malware', 'Malware Distribution', 'Servers hosting or distributing malware payloads, including exploit kits, drive-by downloads, and malicious file repositories.', 9, 'block', '#DC143C', 'virus'),
('c2', 'Command & Control', 'Command and Control (C2) servers coordinating botnet operations, ransomware campaigns, or APT infrastructure.', 10, 'block', '#8B0000', 'network-attack'),
('bruteforce', 'Brute Force Attack', 'IP addresses performing credential stuffing, password spraying, or brute force attacks against SSH, RDP, FTP, or web authentication.', 7, 'block', '#FF4500', 'shield-alert'),
('botnet', 'Botnet Member', 'Infected hosts participating in botnet operations, including DDoS attacks, spam campaigns, or cryptocurrency mining.', 8, 'block', '#B22222', 'robot-angry'),
('scanner', 'Port Scanner', 'Automated scanners probing for vulnerabilities, open ports, or service fingerprinting, often precursors to attacks.', 5, 'alert', '#DAA520', 'radar'),
('phishing', 'Phishing Infrastructure', 'Servers hosting phishing pages, credential harvesting forms, or fake login portals impersonating legitimate services.', 9, 'block', '#CD5C5C', 'fish'),
('ddos', 'DDoS Attack Source', 'Participating in Distributed Denial of Service attacks, including amplification attacks and volumetric floods.', 8, 'block', '#A52A2A', 'server-network-off'),
('exploit', 'Exploit Delivery', 'Delivering exploits targeting known CVEs, zero-days, or software vulnerabilities to compromise target systems.', 9, 'block', '#8B0000', 'bug'),
('proxy_abuse', 'Proxy Abuse', 'Open proxies or compromised proxy servers being abused for anonymization, traffic relaying, or malicious activities.', 6, 'alert', '#CD853F', 'incognito'),
('cryptomining', 'Cryptomining', 'Servers hosting cryptojacking scripts or coordinating unauthorized cryptocurrency mining operations.', 6, 'alert', '#FFD700', 'currency-btc'),
('tor_exit', 'Tor Exit Node', 'Tor network exit nodes, legitimate anonymization but requiring monitoring for abuse detection.', 3, 'monitor', '#9370DB', 'onion')
ON CONFLICT (category_code) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    severity_level = EXCLUDED.severity_level,
    recommended_action = EXCLUDED.recommended_action,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- SECTION 2: DOMAIN THREAT CATEGORIES
-- ============================================================================

-- Create reference table for domain threat categories
CREATE TABLE IF NOT EXISTS domain_threat_categories (
    id SERIAL PRIMARY KEY,
    category_code VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    severity_level INTEGER CHECK (severity_level BETWEEN 1 AND 10),
    recommended_action VARCHAR(20) CHECK (recommended_action IN ('allow', 'monitor', 'alert', 'block', 'quarantine')),
    common_targets TEXT,  -- Common phishing targets or attack victims
    color_code VARCHAR(7),
    icon_name VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert standard domain threat categories
INSERT INTO domain_threat_categories (category_code, display_name, description, severity_level, recommended_action, common_targets, color_code, icon_name) VALUES
('phishing', 'Phishing', 'Fraudulent websites designed to steal credentials, personal information, or financial data by impersonating legitimate services.', 9, 'block', 'Banking, Social Media, Email Providers, Payment Services', '#DC143C', 'fish-hook'),
('malware', 'Malware Distribution', 'Domains hosting malicious files, exploit kits, or serving as download servers for trojans, ransomware, and other malware.', 10, 'block', 'All Users', '#8B0000', 'bug-outline'),
('c2', 'Command & Control', 'Domains used for botnet coordination, data exfiltration, or remote access trojan (RAT) communications.', 10, 'block', 'Compromised Systems', '#800000', 'server-security'),
('spam', 'Spam Advertised', 'Domains promoted through spam emails, often leading to scams, fake products, or malicious content.', 5, 'alert', 'Email Recipients', '#FFA500', 'email-alert'),
('exploit_kit', 'Exploit Kit', 'Landing pages for exploit kit frameworks (Angler, RIG, Fallout) that deliver browser-based exploits.', 9, 'block', 'Vulnerable Browsers', '#B22222', 'code-braces'),
('scam', 'Scam/Fraud', 'Fraudulent websites offering fake services, counterfeit goods, advance-fee scams, or investment fraud.', 7, 'block', 'Consumers, Investors', '#FF6347', 'alert-decagram'),
('ransomware', 'Ransomware Payment', 'Payment portals for ransomware operations, including victim payment pages and data leak sites.', 10, 'block', 'Ransomware Victims', '#800020', 'file-lock'),
('cryptojacking', 'Cryptojacking', 'Websites running unauthorized browser-based cryptocurrency miners (Coinhive, CryptoLoot variants).', 6, 'block', 'Website Visitors', '#DAA520', 'mine'),
('typosquatting', 'Typosquatting', 'Domains registered to exploit common typos of popular websites for phishing or malvertising.', 8, 'block', 'Mistyped URLs', '#CD5C5C', 'format-letter-case'),
('newly_registered', 'Newly Registered Suspicious', 'Recently registered domains with suspicious patterns, often used in short-lived attack campaigns.', 6, 'alert', 'Early Campaign Targets', '#FFA07A', 'new-box'),
('parked', 'Malicious Parked', 'Parked domains used for ad fraud, redirection chains, or hosting phishing kits temporarily.', 5, 'monitor', 'Ad Networks', '#D2691E', 'parking'),
('adult_malicious', 'Malicious Adult Content', 'Adult content sites distributing malware or running scams, distinct from legitimate adult sites.', 7, 'block', 'Adult Content Seekers', '#9932CC', 'alert-circle')
ON CONFLICT (category_code) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    severity_level = EXCLUDED.severity_level,
    recommended_action = EXCLUDED.recommended_action,
    common_targets = EXCLUDED.common_targets,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- SECTION 3: MALWARE TYPE CLASSIFICATIONS
-- ============================================================================

-- Create reference table for malware classifications
CREATE TABLE IF NOT EXISTS malware_type_classifications (
    id SERIAL PRIMARY KEY,
    category_code VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    severity_level INTEGER CHECK (severity_level BETWEEN 1 AND 10),
    capabilities TEXT,  -- Common capabilities of this malware type
    persistence_level VARCHAR(20) CHECK (persistence_level IN ('low', 'medium', 'high', 'critical')),
    color_code VARCHAR(7),
    icon_name VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert standard malware type classifications
INSERT INTO malware_type_classifications (category_code, display_name, description, severity_level, capabilities, persistence_level, color_code, icon_name) VALUES
('trojan', 'Trojan Horse', 'Malicious programs disguised as legitimate software, providing backdoor access and often delivering additional payloads.', 8, 'Backdoor Access, Payload Delivery, System Modification', 'high', '#DC143C', 'shield-bug'),
('ransomware', 'Ransomware', 'Malware encrypting victim files and demanding payment for decryption keys, including crypto-ransomware and screen lockers.', 10, 'File Encryption, Data Exfiltration, Payment Extortion', 'critical', '#8B0000', 'file-lock-outline'),
('worm', 'Worm', 'Self-replicating malware spreading across networks without user interaction, often exploiting vulnerabilities.', 9, 'Self-Replication, Network Propagation, Automated Spreading', 'high', '#B22222', 'virus-outline'),
('rootkit', 'Rootkit', 'Kernel-level malware providing deep system access while hiding its presence from security tools and users.', 10, 'Privilege Escalation, Stealth, Kernel Access, Process Hiding', 'critical', '#800000', 'incognito-circle'),
('spyware', 'Spyware', 'Information-stealing malware capturing keystrokes, screenshots, credentials, and sensitive data for exfiltration.', 8, 'Keylogging, Screen Capture, Credential Theft, Data Exfiltration', 'high', '#A52A2A', 'eye-outline'),
('adware', 'Adware', 'Unwanted advertising software displaying intrusive ads, browser hijacking, and potentially installing additional malware.', 4, 'Ad Injection, Browser Hijacking, Data Collection', 'low', '#FFA500', 'advertisements'),
('rat', 'Remote Access Trojan', 'RATs providing attackers with remote control capabilities including file access, webcam control, and command execution.', 9, 'Remote Control, File Management, Keylogging, Screen Monitoring', 'critical', '#8B0000', 'remote-desktop'),
('miner', 'Cryptocurrency Miner', 'Unauthorized cryptocurrency mining software consuming system resources for attacker profit.', 6, 'CPU/GPU Mining, Resource Consumption, Network Communication', 'medium', '#DAA520', 'pickaxe'),
('loader', 'Malware Loader', 'Droppers and loaders delivering secondary payloads, often used to bypass detection by delivering malware in stages.', 8, 'Payload Delivery, Staged Execution, Decryption, Process Injection', 'high', '#CD5C5C', 'download-outline'),
('backdoor', 'Backdoor', 'Persistent access mechanisms allowing attackers to bypass authentication and maintain access to compromised systems.', 9, 'Persistent Access, Authentication Bypass, Command Execution', 'critical', '#800020', 'door-open'),
('infostealer', 'Information Stealer', 'Malware specifically designed to harvest credentials, browser data, cryptocurrency wallets, and sensitive documents.', 9, 'Credential Harvesting, Browser Data Theft, Wallet Extraction', 'high', '#B22222', 'database-export'),
('banker', 'Banking Trojan', 'Trojans targeting financial institutions, intercepting online banking sessions and stealing financial credentials.', 10, 'Web Injection, Session Hijacking, Transaction Manipulation', 'critical', '#8B0000', 'bank-outline'),
('botnet_agent', 'Botnet Agent', 'Malware enrolling infected systems into botnets for DDoS attacks, spam distribution, or cryptocurrency mining.', 8, 'C2 Communication, DDoS Participation, Spam Relay', 'high', '#A52A2A', 'robot-angry-outline'),
('downloader', 'Downloader', 'Minimal malware focused on downloading and executing additional malicious payloads from remote servers.', 7, 'Payload Download, Execution, C2 Communication', 'medium', '#FF6347', 'cloud-download-outline'),
('fileless', 'Fileless Malware', 'Memory-resident malware executing in RAM without writing files to disk, evading traditional antivirus detection.', 10, 'Memory Execution, PowerShell Abuse, WMI Exploitation, Stealth', 'critical', '#800000', 'memory')
ON CONFLICT (category_code) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    severity_level = EXCLUDED.severity_level,
    capabilities = EXCLUDED.capabilities,
    persistence_level = EXCLUDED.persistence_level,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- SECTION 4: CONNECTION TYPE CLASSIFICATIONS
-- ============================================================================

-- Create reference table for connection type classifications
CREATE TABLE IF NOT EXISTS connection_type_classifications (
    id SERIAL PRIMARY KEY,
    category_code VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    risk_level INTEGER CHECK (risk_level BETWEEN 1 AND 10),
    typical_usage TEXT,
    monitoring_recommendation VARCHAR(20) CHECK (monitoring_recommendation IN ('low', 'medium', 'high', 'critical')),
    color_code VARCHAR(7),
    icon_name VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert standard connection type classifications
INSERT INTO connection_type_classifications (category_code, display_name, description, risk_level, typical_usage, monitoring_recommendation, color_code, icon_name) VALUES
('residential', 'Residential ISP', 'Home internet connections including DSL, cable modem, and fiber-to-home services from consumer ISPs.', 3, 'Home Users, Remote Workers', 'low', '#4682B4', 'home-network'),
('mobile', 'Mobile/Cellular', 'Cellular network connections including 4G LTE, 5G, and mobile hotspots with dynamic IP assignment.', 3, 'Mobile Devices, Tablets, Mobile Hotspots', 'low', '#32CD32', 'cellphone-wireless'),
('corporate', 'Corporate Network', 'Business and enterprise network connections with dedicated bandwidth and static IP allocations.', 2, 'Businesses, Offices, Enterprise Applications', 'low', '#4169E1', 'office-building'),
('datacenter', 'Datacenter/Cloud', 'Hosting providers, cloud platforms (AWS, Azure, GCP), VPS providers, and colocation facilities.', 5, 'Servers, Cloud Services, Hosting, APIs', 'medium', '#FFD700', 'server-network'),
('satellite', 'Satellite Internet', 'Satellite-based internet connections with high latency, often used in remote or rural areas.', 4, 'Remote Locations, Rural Areas, Maritime', 'low', '#87CEEB', 'satellite-variant'),
('proxy', 'Proxy Service', 'Known commercial proxy services, SOCKS proxies, HTTP proxies used for anonymization or geo-shifting.', 7, 'Anonymization, Geo-Shifting, Scraping', 'high', '#FF8C00', 'shield-lock'),
('vpn', 'VPN Exit Point', 'Commercial and free VPN service exit points, including VPN providers and VPN gateway IPs.', 6, 'Privacy, Geo-Restriction Bypass, Remote Access', 'medium', '#9370DB', 'vpn'),
('tor', 'Tor Network', 'Tor network exit nodes and relays, providing strong anonymization but requiring abuse monitoring.', 7, 'Anonymization, Privacy, Censorship Circumvention', 'high', '#663399', 'incognito'),
('education', 'Educational Institution', 'University, college, and school networks, often with large user populations and research activities.', 3, 'Students, Research, Academic Activities', 'low', '#20B2AA', 'school'),
('government', 'Government Network', 'Government agency networks, military installations, and public sector organizations.', 2, 'Government Services, Public Administration', 'low', '#2F4F4F', 'shield-star'),
('cdn', 'Content Delivery Network', 'CDN edge servers and proxy caches (Cloudflare, Akamai, Fastly) serving cached content.', 4, 'Web Acceleration, DDoS Protection, Caching', 'medium', '#1E90FF', 'cloud-outline'),
('hosting', 'Web Hosting', 'Shared hosting, dedicated servers, and managed WordPress hosting environments.', 5, 'Websites, Web Applications, Blogs', 'medium', '#FFA07A', 'web')
ON CONFLICT (category_code) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    risk_level = EXCLUDED.risk_level,
    typical_usage = EXCLUDED.typical_usage,
    monitoring_recommendation = EXCLUDED.monitoring_recommendation,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- SECTION 5: SEVERITY LEVEL DEFINITIONS
-- ============================================================================

-- Create reference table for severity level definitions
CREATE TABLE IF NOT EXISTS severity_level_definitions (
    severity_level INTEGER PRIMARY KEY CHECK (severity_level BETWEEN 1 AND 10),
    severity_name VARCHAR(20) NOT NULL,
    description TEXT,
    response_time VARCHAR(50),  -- Expected response time
    escalation_required BOOLEAN,
    default_action VARCHAR(20) CHECK (default_action IN ('allow', 'monitor', 'alert', 'block', 'quarantine')),
    color_code VARCHAR(7),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert severity level definitions
INSERT INTO severity_level_definitions (severity_level, severity_name, description, response_time, escalation_required, default_action, color_code) VALUES
(1, 'Informational', 'Minimal threat, informational only. No immediate action required, general awareness.', 'No SLA', FALSE, 'allow', '#87CEEB'),
(2, 'Low', 'Low-severity threat with minimal impact. Monitor for patterns but allow normal operations.', '7 days', FALSE, 'monitor', '#90EE90'),
(3, 'Low-Medium', 'Slightly elevated risk. Logging recommended, no blocking required unless patterns emerge.', '3-5 days', FALSE, 'monitor', '#FFD700'),
(4, 'Medium', 'Moderate threat requiring attention. Generate alerts and log activity for investigation.', '48 hours', FALSE, 'alert', '#FFA500'),
(5, 'Medium-High', 'Elevated threat level. Alert security team and consider temporary blocking.', '24 hours', FALSE, 'alert', '#FF8C00'),
(6, 'High', 'Significant threat requiring immediate attention. Block and alert security operations.', '4-8 hours', TRUE, 'block', '#FF6347'),
(7, 'High-Critical', 'Serious threat with probable malicious intent. Immediate blocking and incident response.', '2-4 hours', TRUE, 'block', '#DC143C'),
(8, 'Critical', 'Critical threat with confirmed malicious activity. Block immediately and escalate.', '1 hour', TRUE, 'block', '#B22222'),
(9, 'Critical-Emergency', 'Critical emergency threat. Immediate blocking, escalation to IR team, containment required.', '30 minutes', TRUE, 'block', '#8B0000'),
(10, 'Emergency', 'Maximum severity. Active attack in progress. Immediate blocking, full incident response, executive notification.', 'Immediate', TRUE, 'quarantine', '#800000')
ON CONFLICT (severity_level) DO UPDATE SET
    severity_name = EXCLUDED.severity_name,
    description = EXCLUDED.description,
    response_time = EXCLUDED.response_time,
    escalation_required = EXCLUDED.escalation_required,
    default_action = EXCLUDED.default_action,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- SECTION 6: RECOMMENDED ACTION DEFINITIONS
-- ============================================================================

-- Create reference table for recommended action definitions
CREATE TABLE IF NOT EXISTS threat_action_definitions (
    action_code VARCHAR(20) PRIMARY KEY,
    display_name VARCHAR(50) NOT NULL,
    description TEXT,
    implementation_details TEXT,
    automated BOOLEAN,  -- Can be automated
    requires_approval BOOLEAN,  -- Requires manual approval
    reversible BOOLEAN,  -- Can be easily reversed
    performance_impact VARCHAR(20) CHECK (performance_impact IN ('none', 'minimal', 'low', 'medium', 'high')),
    color_code VARCHAR(7),
    icon_name VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert recommended action definitions
INSERT INTO threat_action_definitions (action_code, display_name, description, implementation_details, automated, requires_approval, reversible, performance_impact, color_code, icon_name) VALUES
('allow', 'Allow', 'Permit traffic to pass through without restrictions. Used for whitelisted or low-risk indicators.', 'No firewall rules applied. Traffic flows normally. Optionally log for audit purposes.', TRUE, FALSE, TRUE, 'none', '#90EE90', 'check-circle'),
('monitor', 'Monitor', 'Allow traffic but log all connections for analysis and pattern detection. No blocking.', 'Enable detailed logging. Create netflow records. Alert on threshold breaches.', TRUE, FALSE, TRUE, 'minimal', '#87CEEB', 'monitor-eye'),
('alert', 'Alert Only', 'Generate security alerts for SOC review but do not block. Suitable for medium-severity threats.', 'Send SIEM alerts. Create tickets. Log to threat intelligence database.', TRUE, FALSE, TRUE, 'low', '#FFD700', 'bell-alert'),
('block', 'Block', 'Drop packets or connections from/to the threat indicator. Standard response for high-severity threats.', 'Add firewall DROP rule. Send TCP RST. Log blocked attempts. Update threat feed.', TRUE, FALSE, TRUE, 'low', '#DC143C', 'block-helper'),
('quarantine', 'Quarantine', 'Isolate traffic for deep inspection or sandbox analysis. Used for critical unknown threats.', 'Redirect to isolated VLAN. Deep packet inspection. Sandbox execution. Manual review.', FALSE, TRUE, TRUE, 'medium', '#8B0000', 'biohazard'),
('rate_limit', 'Rate Limit', 'Apply connection rate limiting or bandwidth throttling to suspicious sources.', 'Token bucket algorithm. Limit connections per second. Reduce bandwidth allocation.', TRUE, FALSE, TRUE, 'medium', '#FFA500', 'speedometer-slow'),
('captcha', 'CAPTCHA Challenge', 'Require human verification before allowing access. Effective against bots and scanners.', 'Redirect to CAPTCHA page. Validate response. Issue time-limited token.', TRUE, FALSE, TRUE, 'low', '#4682B4', 'robot-confused'),
('geo_block', 'Geographic Block', 'Block based on geolocation. Used when threats originate from specific countries or regions.', 'Lookup IP geolocation. Apply country-based ACLs. Log geo-blocking events.', TRUE, FALSE, TRUE, 'minimal', '#9370DB', 'earth-off')
ON CONFLICT (action_code) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    implementation_details = EXCLUDED.implementation_details,
    automated = EXCLUDED.automated,
    requires_approval = EXCLUDED.requires_approval,
    reversible = EXCLUDED.reversible,
    performance_impact = EXCLUDED.performance_impact,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- SECTION 7: METADATA AND VERIFICATION
-- ============================================================================

-- Update system metadata to track category seed execution
INSERT INTO system_metadata (key, value, description, category)
VALUES (
    'threat_categories_seed_version',
    '1.0.0',
    'Version of initial_threat_categories.sql last executed',
    'database_seeds'
) ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_metadata (key, value, description, category)
VALUES (
    'total_ip_abuse_types',
    (SELECT COUNT(*)::text FROM ip_abuse_types),
    'Total number of IP abuse type categories defined',
    'threat_taxonomy'
) ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_metadata (key, value, description, category)
VALUES (
    'total_domain_categories',
    (SELECT COUNT(*)::text FROM domain_threat_categories),
    'Total number of domain threat categories defined',
    'threat_taxonomy'
) ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_metadata (key, value, description, category)
VALUES (
    'total_malware_types',
    (SELECT COUNT(*)::text FROM malware_type_classifications),
    'Total number of malware type classifications defined',
    'threat_taxonomy'
) ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO system_metadata (key, value, description, category)
VALUES (
    'categories_seeded_at',
    CURRENT_TIMESTAMP::text,
    'Timestamp when threat categories were last seeded/updated',
    'database_seeds'
) ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- VERIFICATION QUERIES AND SUMMARY
-- ============================================================================

DO $$
DECLARE
    ip_count INT;
    domain_count INT;
    malware_count INT;
    connection_count INT;
    severity_count INT;
    action_count INT;
BEGIN
    SELECT COUNT(*) INTO ip_count FROM ip_abuse_types;
    SELECT COUNT(*) INTO domain_count FROM domain_threat_categories;
    SELECT COUNT(*) INTO malware_count FROM malware_type_classifications;
    SELECT COUNT(*) INTO connection_count FROM connection_type_classifications;
    SELECT COUNT(*) INTO severity_count FROM severity_level_definitions;
    SELECT COUNT(*) INTO action_count FROM threat_action_definitions;
    
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Threat Categorization Summary';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'IP Abuse Types: %', ip_count;
    RAISE NOTICE 'Domain Threat Categories: %', domain_count;
    RAISE NOTICE 'Malware Classifications: %', malware_count;
    RAISE NOTICE 'Connection Types: %', connection_count;
    RAISE NOTICE 'Severity Levels: %', severity_count;
    RAISE NOTICE 'Action Definitions: %', action_count;
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Total Category Records: %', ip_count + domain_count + malware_count + connection_count + severity_count + action_count;
    RAISE NOTICE '========================================';
END $$;

-- Display sample data from each category table
SELECT '=== IP ABUSE TYPES ===' AS info;
SELECT category_code, display_name, severity_level, recommended_action FROM ip_abuse_types ORDER BY severity_level DESC;

SELECT '=== DOMAIN THREAT CATEGORIES ===' AS info;
SELECT category_code, display_name, severity_level, recommended_action FROM domain_threat_categories ORDER BY severity_level DESC;

SELECT '=== MALWARE TYPE CLASSIFICATIONS ===' AS info;
SELECT category_code, display_name, severity_level, persistence_level FROM malware_type_classifications ORDER BY severity_level DESC;

SELECT '=== SEVERITY LEVELS ===' AS info;
SELECT severity_level, severity_name, default_action, escalation_required FROM severity_level_definitions ORDER BY severity_level;

-- ============================================================================
-- CREATE INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_ip_abuse_severity ON ip_abuse_types(severity_level DESC);
CREATE INDEX IF NOT EXISTS idx_ip_abuse_action ON ip_abuse_types(recommended_action);

CREATE INDEX IF NOT EXISTS idx_domain_category_severity ON domain_threat_categories(severity_level DESC);
CREATE INDEX IF NOT EXISTS idx_domain_category_action ON domain_threat_categories(recommended_action);

CREATE INDEX IF NOT EXISTS idx_malware_severity ON malware_type_classifications(severity_level DESC);
CREATE INDEX IF NOT EXISTS idx_malware_persistence ON malware_type_classifications(persistence_level);

CREATE INDEX IF NOT EXISTS idx_connection_risk ON connection_type_classifications(risk_level DESC);
CREATE INDEX IF NOT EXISTS idx_connection_monitoring ON connection_type_classifications(monitoring_recommendation);

-- ============================================================================
-- END OF FILE
-- ============================================================================
