-- ============================================================================
-- SafeOps Threat Intelligence Database - Initial Threat Categories
-- File: initial_threat_categories.sql
-- Purpose: Comprehensive taxonomy of threat types and classifications
-- ============================================================================

-- =============================================================================
-- TOP-LEVEL CATEGORIES (parent_category_id = NULL)
-- =============================================================================

-- 1. Malware
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Malware', 'Malicious software including viruses, trojans, and other harmful code', 8, NULL, true);

-- 2. Network Attacks
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Network Attacks', 'Network-based attacks including DDoS, scanning, and exploitation', 7, NULL, true);

-- 3. Phishing
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Phishing', 'Social engineering attacks designed to steal credentials or information', 6, NULL, true);

-- 4. Spam
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Spam', 'Unsolicited bulk messages and email abuse', 3, NULL, true);

-- 5. Fraud
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Fraud', 'Financial fraud, scams, and deceptive practices', 7, NULL, true);

-- 6. Botnet
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Botnet', 'Command and control infrastructure and bot-infected systems', 8, NULL, true);

-- 7. Anonymization
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Anonymization', 'Proxy, VPN, and TOR services used to hide identity', 4, NULL, true);

-- 8. Reconnaissance
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Reconnaissance', 'Scanning, enumeration, and information gathering activities', 5, NULL, true);

-- 9. Data Exfiltration
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Data Exfiltration', 'Unauthorized data theft and exfiltration', 9, NULL, true);

-- 10. Malicious Website
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Malicious Website', 'Websites hosting or distributing malware', 7, NULL, true);

-- 11. APT
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('APT', 'Advanced Persistent Threat activity', 10, NULL, true);

-- =============================================================================
-- MALWARE SUB-CATEGORIES (parent = Malware, category_id = 1)
-- =============================================================================

-- 12. Ransomware
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Ransomware', 'Malware that encrypts data and demands payment', 10, 1, true);

-- 13. Trojan
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Trojan', 'Malware disguised as legitimate software', 8, 1, true);

-- 14. Backdoor
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Backdoor', 'Remote access trojans and backdoor implants', 9, 1, true);

-- 15. Spyware
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Spyware', 'Software that covertly gathers information', 7, 1, true);

-- 16. Adware
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Adware', 'Unwanted advertising software', 4, 1, true);

-- 17. Rootkit
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Rootkit', 'Malware that hides its presence in the system', 9, 1, true);

-- 18. Keylogger
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Keylogger', 'Software that records keystrokes', 8, 1, true);

-- 19. Cryptominer
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Cryptominer', 'Unauthorized cryptocurrency mining software', 6, 1, true);

-- 20. Worm
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Worm', 'Self-replicating malware that spreads across networks', 8, 1, true);

-- 21. Virus
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Virus', 'Malware that attaches to and infects other files', 7, 1, true);

-- =============================================================================
-- NETWORK ATTACK SUB-CATEGORIES (parent = Network Attacks, category_id = 2)
-- =============================================================================

-- 22. DDoS
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('DDoS', 'Distributed Denial of Service attacks', 9, 2, true);

-- 23. Port Scanning
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Port Scanning', 'Network port scanning and enumeration', 5, 2, true);

-- 24. Brute Force
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Brute Force', 'Password guessing and brute force attacks', 7, 2, true);

-- 25. Exploit
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Exploit', 'Exploitation of software vulnerabilities', 9, 2, true);

-- 26. SQL Injection
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('SQL Injection', 'Database injection attacks', 8, 2, true);

-- 27. Cross-Site Scripting
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Cross-Site Scripting', 'XSS attacks against web applications', 7, 2, true);

-- 28. Man-in-the-Middle
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Man-in-the-Middle', 'Interception and manipulation of network traffic', 8, 2, true);

-- =============================================================================
-- PHISHING SUB-CATEGORIES (parent = Phishing, category_id = 3)
-- =============================================================================

-- 29. Credential Phishing
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Credential Phishing', 'Phishing targeting user credentials', 8, 3, true);

-- 30. Spear Phishing
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Spear Phishing', 'Targeted phishing attacks', 9, 3, true);

-- 31. Business Email Compromise
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Business Email Compromise', 'CEO fraud and email account compromise', 9, 3, true);

-- 32. Whaling
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Whaling', 'Phishing attacks targeting high-profile executives', 9, 3, true);

-- =============================================================================
-- BOTNET SUB-CATEGORIES (parent = Botnet, category_id = 6)
-- =============================================================================

-- 33. C2 Server
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('C2 Server', 'Command and Control server infrastructure', 10, 6, true);

-- 34. Bot Infection
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Bot Infection', 'Infected systems participating in botnets', 8, 6, true);

-- =============================================================================
-- FRAUD SUB-CATEGORIES (parent = Fraud, category_id = 5)
-- =============================================================================

-- 35. Credit Card Fraud
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Credit Card Fraud', 'Stolen credit card data and transactions', 8, 5, true);

-- 36. Identity Theft
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Identity Theft', 'Theft and misuse of personal identity information', 9, 5, true);

-- 37. Scam
INSERT INTO threat_categories (category_name, category_description, severity_level, parent_category_id, enabled) VALUES
('Scam', 'Fraudulent schemes and deceptive practices', 6, 5, true);

-- =============================================================================
-- VERIFICATION AND STATISTICS
-- =============================================================================

DO $$
DECLARE
    total_categories INTEGER;
    top_level_categories INTEGER;
    sub_categories INTEGER;
    avg_severity DECIMAL;
BEGIN
    SELECT COUNT(*) INTO total_categories FROM threat_categories;
    SELECT COUNT(*) INTO top_level_categories FROM threat_categories WHERE parent_category_id IS NULL;
    SELECT COUNT(*) INTO sub_categories FROM threat_categories WHERE parent_category_id IS NOT NULL;
    SELECT AVG(severity_level)::DECIMAL(4,2) INTO avg_severity FROM threat_categories;
    
    RAISE NOTICE '=== Threat Categories Initialized ===';
    RAISE NOTICE 'Total categories: %', total_categories;
    RAISE NOTICE 'Top-level categories: %', top_level_categories;
    RAISE NOTICE 'Sub-categories: %', sub_categories;
    RAISE NOTICE 'Average severity: %', avg_severity;
    RAISE NOTICE '';
    RAISE NOTICE 'Severity distribution:';
    RAISE NOTICE '  Critical (10): % categories', (SELECT COUNT(*) FROM threat_categories WHERE severity_level = 10);
    RAISE NOTICE '  High (9): % categories', (SELECT COUNT(*) FROM threat_categories WHERE severity_level = 9);
    RAISE NOTICE '  High (8): % categories', (SELECT COUNT(*) FROM threat_categories WHERE severity_level = 8);
    RAISE NOTICE '  Medium-High (7): % categories', (SELECT COUNT(*) FROM threat_categories WHERE severity_level = 7);
    RAISE NOTICE '  Medium (6): % categories', (SELECT COUNT(*) FROM threat_categories WHERE severity_level = 6);
    RAISE NOTICE '  Medium (5): % categories', (SELECT COUNT(*) FROM threat_categories WHERE severity_level = 5);
    RAISE NOTICE '  Low-Medium (4): % categories', (SELECT COUNT(*) FROM threat_categories WHERE severity_level = 4);
    RAISE NOTICE '  Low (3): % categories', (SELECT COUNT(*) FROM threat_categories WHERE severity_level = 3);
    RAISE NOTICE '';
    RAISE NOTICE 'Top-level category breakdown:';
    
    FOR i IN (SELECT category_name, 
                     (SELECT COUNT(*) FROM threat_categories sub 
                      WHERE sub.parent_category_id = tc.category_id) as sub_count
              FROM threat_categories tc 
              WHERE parent_category_id IS NULL 
              ORDER BY category_name)
    LOOP
        RAISE NOTICE '  % (% sub-categories)', i.category_name, i.sub_count;
    END LOOP;
END $$;
