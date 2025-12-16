-- ============================================================================
-- SafeOps Threat Intelligence Database - Test IOC Data
-- File: test_ioc_data.sql  
-- Purpose: Sample test data for development, testing, and demonstrations
-- WARNING: This is TEST DATA ONLY using reserved IP ranges and example domains
-- ============================================================================

-- NOTE: Uses TEST-NET-2 (198.51.100.0/24) and TEST-NET-3 (203.0.113.0/24)
-- These are reserved for documentation and testing per RFC 5737

-- =============================================================================
-- TEST IP ADDRESSES
-- =============================================================================

-- Malicious IPs
INSERT INTO ip_reputation (ip_address, reputation_score, confidence_level, threat_category_id, severity, country_code, asn_id, first_seen, last_seen, total_reports, description) VALUES
('198.51.100.1', -85, 0.90, (SELECT category_id FROM threat_categories WHERE category_name = 'C2 Server'), 10, 'RU', NULL, NOW() - INTERVAL '30 days', NOW() - INTERVAL '1 day', 15, 'TEST DATA: Simulated C2 server'),
('198.51.100.2', -70, 0.85, (SELECT category_id FROM threat_categories WHERE category_name = 'Bot Infection'), 8, 'CN', NULL, NOW() - INTERVAL '20 days', NOW() - INTERVAL '2 days', 12, 'TEST DATA: Simulated botnet node'),
('203.0.113.10', -60, 0.75, (SELECT category_id FROM threat_categories WHERE category_name = 'Port Scanning'), 5, 'US', NULL, NOW() - INTERVAL '15 days', NOW() - INTERVAL '3 days', 8, 'TEST DATA: Simulated scanning source'),
('203.0.113.11', -75, 0.82, (SELECT category_id FROM threat_categories WHERE category_name = 'Brute Force'), 7, 'BR', NULL, NOW() - INTERVAL '25 days', NOW() - INTERVAL '1 day', 10, 'TEST DATA: Simulated brute force attacker'),
('198.51.100.10', -90, 0.95, (SELECT category_id FROM threat_categories WHERE category_name = 'DDoS'), 9, 'KP', NULL, NOW() - INTERVAL '10 days', NOW() - INTERVAL '6 hours', 20, 'TEST DATA: Simulated DDoS source'),
('198.51.100.20', -55, 0.70, (SELECT category_id FROM threat_categories WHERE category_name = 'Exploit'), 9, 'IR', NULL, NOW() - INTERVAL '45 days', NOW() - INTERVAL '5 days', 6, 'TEST DATA: Simulated exploit attempt');

-- Suspicious IPs  
INSERT INTO ip_reputation (ip_address, reputation_score, confidence_level, threat_category_id, severity, country_code, first_seen, last_seen, total_reports, description) VALUES
('203.0.113.20', -40, 0.60, (SELECT category_id FROM threat_categories WHERE category_name = 'Spam'), 3, 'BR', NOW() - INTERVAL '60 days', NOW() - INTERVAL '10 days', 5, 'TEST DATA: Simulated spam source'),
('203.0.113.30', -35, 0.55, (SELECT category_id FROM threat_categories WHERE category_name = 'Reconnaissance'), 5, 'VN', NOW() - INTERVAL '50 days', NOW() - INTERVAL '7 days', 4, 'TEST DATA: Simulated reconnaissance'),
('198.51.100.30', -45, 0.65, (SELECT category_id FROM threat_categories WHERE category_name = 'Malware'), 8, 'RO', NOW() - INTERVAL '40 days', NOW() - INTERVAL '15 days', 7, 'TEST DATA: Simulated malware distribution'),
('203.0.113.40', -30, 0.50, (SELECT category_id FROM threat_categories WHERE category_name = 'Anonymization'), 4, 'NL', NOW() - INTERVAL '90 days', NOW() - INTERVAL '20 days', 3, 'TEST DATA: Simulated proxy service');

-- =============================================================================
-- TEST DOMAINS
-- =============================================================================

INSERT INTO domain_reputation (domain_name, reputation_score, confidence_level, threat_category_id, severity, first_seen, last_seen, total_reports, description) VALUES
('evil-command-server.example.com', -90, 0.95, (SELECT category_id FROM threat_categories WHERE category_name = 'C2 Server'), 10, NOW() - INTERVAL '25 days', NOW() - INTERVAL '1 day', 18, 'TEST DATA: Simulated C2 domain'),
('phishing-bank-login.example.com', -80, 0.90, (SELECT category_id FROM threat_categories WHERE category_name = 'Credential Phishing'), 8, NOW() - INTERVAL '20 days', NOW() - INTERVAL '2 days', 14, 'TEST DATA: Simulated phishing site'),
('malware-download.example.com', -75, 0.85, (SELECT category_id FROM threat_categories WHERE category_name = 'Malicious Website'), 7, NOW() - INTERVAL '30 days', NOW() - INTERVAL '5 days', 11, 'TEST DATA: Simulated malware distribution'),
('spam-sender.example.com', -50, 0.70, (SELECT category_id FROM threat_categories WHERE category_name = 'Spam'), 3, NOW() - INTERVAL '60 days', NOW() - INTERVAL '15 days', 6, 'TEST DATA: Simulated spam domain'),
('botnet-c2.example.com', -85, 0.92, (SELECT category_id FROM threat_categories WHERE category_name = 'C2 Server'), 10, NOW() - INTERVAL '35 days', NOW() - INTERVAL '3 days', 16, 'TEST DATA: Simulated botnet C2'),
('cryptominer-pool.example.com', -60, 0.75, (SELECT category_id FROM threat_categories WHERE category_name = 'Cryptominer'), 6, NOW() - INTERVAL '40 days', NOW() - INTERVAL '10 days', 9, 'TEST DATA: Simulated cryptomining pool'),
('exploit-kit.example.com', -70, 0.80, (SELECT category_id FROM threat_categories WHERE category_name = 'Exploit'), 9, NOW() - INTERVAL '15 days', NOW() - INTERVAL '4 days', 10, 'TEST DATA: Simulated exploit kit'),
('trojan-dropper.example.com', -65, 0.78, (SELECT category_id FROM threat_categories WHERE category_name = 'Trojan'), 8, NOW() - INTERVAL '50 days', NOW() - INTERVAL '12 days', 8, 'TEST DATA: Simulated trojan dropper'),
('data-exfil.example.com', -88, 0.93, (SELECT category_id FROM threat_categories WHERE category_name = 'Data Exfiltration'), 9, NOW() - INTERVAL '18 days', NOW() - INTERVAL '2 days', 13, 'TEST DATA: Simulated data exfiltration');

-- =============================================================================
-- TEST FILE HASHES
-- =============================================================================

INSERT INTO hash_reputation (
    md5_hash, sha1_hash, sha256_hash, sha512_hash,
    reputation_score, confidence_level, threat_category_id, severity,
    malware_family, file_type, file_size, first_seen, last_seen, total_reports, description
) VALUES
-- Ransomware sample
('5d41402abc4b2a76b9719d911017c592', 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 
 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 '864651c6c2fa61dc2c67c9f5d8b8a1f3e6b5e7f8c26d3a5b4f7e9a8c1d2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7',
 -95, 0.98, (SELECT category_id FROM threat_categories WHERE category_name = 'Ransomware'), 10,
 'TestRansomware', 'exe', 1048576, NOW() - INTERVAL '20 days', NOW() - INTERVAL '1 day', 25, 'TEST DATA: Simulated ransomware'),

-- Trojan sample  
('098f6bcd4621d373cade4e832627b4f6', '356a192b7913b04c54574d18c28d46e6395428ab',
 '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
 '3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2',
 -85, 0.92, (SELECT category_id FROM threat_categories WHERE category_name = 'Trojan'), 8,
 'TestTrojan', 'dll', 524288, NOW() - INTERVAL '30 days', NOW() - INTERVAL '3 days', 18, 'TEST DATA: Simulated trojan'),

-- Keylogger
('c4ca4238a0b923820dcc509a6f75849b', '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
 'fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9',
 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff',
 -88, 0.94, (SELECT category_id FROM threat_categories WHERE category_name = 'Keylogger'), 8,
 'TestKeylogger', 'exe', 327680, NOW() - INTERVAL '15 days', NOW() - INTERVAL '2 days', 15, 'TEST DATA: Simulated keylogger'),

-- Backdoor
('c4ca4238a0b923820dcc509a6f75849c', '1b6453892473a467d07372d45eb05abc2031647a',
 '5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5',
 'c7ade88fc58c5f9c6821a34f45de23d9191ee535acd69090d39c9dfe03872f34e8d6f78b973c2c9c3f06c3b1c7e8f96e9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4',
 -92, 0.96, (SELECT category_id FROM threat_categories WHERE category_name = 'Backdoor'), 9,
 'TestBackdoor', 'dll', 245760, NOW() - INTERVAL '25 days', NOW() - INTERVAL '1 day', 20, 'TEST DATA: Simulated backdoor'),

-- Cryptominer
('c81e728d9d4c2f636f067f89cc14862c', '4e07408562bedb8b60ce05c1decfe3ad16b72230',
 '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'f391d3a1baa9d6e3e6c8a8d9c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0',
 -60, 0.75, (SELECT category_id FROM threat_categories WHERE category_name = 'Cryptominer'), 6,
 'TestMiner', 'exe', 655360, NOW() - INTERVAL '40 days', NOW() - INTERVAL '10 days', 10, 'TEST DATA: Simulated cryptominer'),

-- Spyware
('eccbc87e4b5ce2fe28308fd9f2a7baf3', '8277e0910d750195b448797616e091ad',
 '6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d',
 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86',
 -78, 0.86, (SELECT category_id FROM threat_categories WHERE category_name = 'Spyware'), 7,
 'TestSpyware', 'exe', 409600, NOW() - INTERVAL '35 days', NOW() - INTERVAL '7 days', 12, 'TEST DATA: Simulated spyware'),

-- Worm
('a87ff679a2f3e71d9181a67b7542122c', '4a0a19218e082a343a1b17e5333409af9d98f0f5',
 '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c',
 '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e1e68f9f74f0f49b2b0e6e5d5e9c5c7a2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8',
 -80, 0.88, (SELECT category_id FROM threat_categories WHERE category_name = 'Worm'), 8,
 'TestWorm', 'exe', 819200, NOW() - INTERVAL '22 days', NOW() - INTERVAL '4 days', 14, 'TEST DATA: Simulated worm');

-- =============================================================================
-- TEST IOC INDICATORS
-- =============================================================================

INSERT INTO ioc_indicators (
    ioc_type, ioc_value, reputation_score, confidence_level, 
    threat_category_id, severity, first_seen, last_seen, total_reports, description
) VALUES
('EMAIL', 'attacker@evil.example.com', -70, 0.80, (SELECT category_id FROM threat_categories WHERE category_name = 'Phishing'), 8, NOW() - INTERVAL '15 days', NOW() - INTERVAL '2 days', 9, 'TEST DATA: Simulated phishing email'),
('URL', 'hxxp://malicious-site.example[.]com/payload.exe', -85, 0.90, (SELECT category_id FROM threat_categories WHERE category_name = 'Malware'), 8, NOW() - INTERVAL '20 days', NOW() - INTERVAL '3 days', 12, 'TEST DATA: Simulated malware URL'),
('REGISTRY_KEY', 'HKLM\\Software\\TestMalware\\Config', -75, 0.85, (SELECT category_id FROM threat_categories WHERE category_name = 'Backdoor'), 9, NOW() - INTERVAL '25 days', NOW() - INTERVAL '5 days', 10, 'TEST DATA: Simulated malicious registry key'),
('MUTEX', 'Global\\TestBotnetMutex', -80, 0.88, (SELECT category_id FROM threat_categories WHERE category_name = 'Botnet'), 8, NOW() - INTERVAL '30 days', NOW() - INTERVAL '1 day', 14, 'TEST DATA: Simulated botnet mutex'),
('USER_AGENT', 'Mozilla/5.0 (TestBot/1.0)', -65, 0.70, (SELECT category_id FROM threat_categories WHERE category_name = 'Bot Infection'), 7, NOW() - INTERVAL '35 days', NOW() - INTERVAL '7 days', 8, 'TEST DATA: Simulated bot user agent'),
('FILENAME', 'evil_payload.exe', -78, 0.82, (SELECT category_id FROM threat_categories WHERE category_name = 'Trojan'), 8, NOW() - INTERVAL '18 days', NOW() - INTERVAL '4 days', 11, 'TEST DATA: Simulated malicious filename'),
('CVE', 'CVE-2024-99999', -88, 0.92, (SELECT category_id FROM threat_categories WHERE category_name = 'Exploit'), 9, NOW() - INTERVAL '10 days', NOW() - INTERVAL '1 day', 16, 'TEST DATA: Simulated CVE'),
('SSL_CERT_HASH', 'testcerthash123456789abcdef', -72, 0.78, (SELECT category_id FROM threat_categories WHERE category_name = 'C2 Server'), 9, NOW() - INTERVAL '28 days', NOW() - INTERVAL '6 days', 9, 'TEST DATA: Simulated malicious SSL cert'),
('PDB_PATH', 'C:\\TestMalware\\Build\\Release\\evil.pdb', -76, 0.84, (SELECT category_id FROM threat_categories WHERE category_name = 'Malware'), 8, NOW() - INTERVAL '22 days', NOW() - INTERVAL '3 days', 10, 'TEST DATA: Simulated PDB path'),
('PIPE_NAME', '\\\\.\\pipe\\TestEvilPipe', -74, 0.80, (SELECT category_id FROM threat_categories WHERE category_name = 'Backdoor'), 8, NOW() - INTERVAL '26 days', NOW() - INTERVAL '5 days', 8, 'TEST DATA: Simulated named pipe');

-- =============================================================================
-- TEST THREAT CAMPAIGNS
-- =============================================================================

INSERT INTO ioc_campaigns (
    campaign_name, description, first_seen, last_seen, is_active,
    threat_actor, objective, targets, ttps, severity
) VALUES
('TestAPT-Operation-Alpha', 
 'TEST DATA: Simulated APT campaign for testing purposes', 
 NOW() - INTERVAL '30 days', NOW() - INTERVAL '1 day', true,
 'TestAPT29', 'Credential theft and data exfiltration',
 ARRAY['FINANCE', 'HEALTHCARE'], 
 ARRAY['T1566.001', 'T1053.005', 'T1078', 'T1071.001'], 9),

('TestRansomware-Wave-2024',
 'TEST DATA: Simulated ransomware campaign',
 NOW() - INTERVAL '45 days', NOW() - INTERVAL '2 days', true,
 'TestCriminalGroup', 'Financial extortion via encryption',
 ARRAY['EDUCATION', 'GOVERNMENT', 'MANUFACTURING'],
 ARRAY['T1486', 'T1490', 'T1489', 'T1048'], 10),

('TestPhishing-Campaign-BEC',
 'TEST DATA: Simulated business email compromise campaign',
 NOW() - INTERVAL '60 days', NOW() - INTERVAL '5 days', true,
 'TestScammerGroup', 'Financial fraud and wire transfer theft',
 ARRAY['FINANCE', 'RETAIL'],
 ARRAY['T1566.002', 'T1534', 'T1114'], 8);

-- =============================================================================
-- VERIFICATION AND STATISTICS
-- =============================================================================

DO $$
DECLARE
    ip_count INTEGER;
    domain_count INTEGER;
    hash_count INTEGER;
    ioc_count INTEGER;
    campaign_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO ip_count FROM ip_reputation WHERE description LIKE 'TEST DATA:%';
    SELECT COUNT(*) INTO domain_count FROM domain_reputation WHERE description LIKE 'TEST DATA:%';
    SELECT COUNT(*) INTO hash_count FROM hash_reputation WHERE description LIKE 'TEST DATA:%';
    SELECT COUNT(*) INTO ioc_count FROM ioc_indicators WHERE description LIKE 'TEST DATA:%';
    SELECT COUNT(*) INTO campaign_count FROM ioc_campaigns WHERE description LIKE 'TEST DATA:%';
    
    RAISE NOTICE '=== Test IOC Data Loaded ===';
    RAISE NOTICE 'WARNING: This is TEST DATA using reserved IP ranges and example domains';
    RAISE NOTICE '';
    RAISE NOTICE 'Test IPs: %', ip_count;
    RAISE NOTICE 'Test Domains: %', domain_count;
    RAISE NOTICE 'Test Hashes: %', hash_count;
    RAISE NOTICE 'Test IOCs: %', ioc_count;
    RAISE NOTICE 'Test Campaigns: %', campaign_count;
    RAISE NOTICE 'Total test records: %', (ip_count + domain_count + hash_count + ioc_count + campaign_count);
    RAISE NOTICE '';
    RAISE NOTICE 'IP Ranges Used:';
    RAISE NOTICE '  198.51.100.0/24 (TEST-NET-2 per RFC 5737)';
    RAISE NOTICE '  203.0.113.0/24 (TEST-NET-3 per RFC 5737)';
    RAISE NOTICE '';
    RAISE NOTICE 'Domains Used: *.example.com (reserved for examples)';
    RAISE NOTICE '';
    RAISE NOTICE 'To remove all test data:';
    RAISE NOTICE '  DELETE FROM ip_reputation WHERE description LIKE ''TEST DATA:%%'';';
    RAISE NOTICE '  DELETE FROM domain_reputation WHERE description LIKE ''TEST DATA:%%'';';
    RAISE NOTICE '  DELETE FROM hash_reputation WHERE description LIKE ''TEST DATA:%%'';';
    RAISE NOTICE '  DELETE FROM ioc_indicators WHERE description LIKE ''TEST DATA:%%'';';
    RAISE NOTICE '  DELETE FROM ioc_campaigns WHERE description LIKE ''TEST DATA:%%'';';
END $$;
