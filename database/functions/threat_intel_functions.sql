-- ============================================================================
-- Threat Intelligence Database - Functions and Stored Procedures
-- Helper functions for common operations
-- ============================================================================

-- Function: Check if IP is malicious
CREATE OR REPLACE FUNCTION is_ip_malicious(check_ip INET)
RETURNS TABLE(
    is_malicious BOOLEAN,
    threat_score INTEGER,
    abuse_type VARCHAR,
    confidence INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        b.is_malicious,
        b.threat_score,
        b.abuse_type,
        b.confidence
    FROM ip_blacklist b
    WHERE b.ip_address = check_ip
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Function: Check if domain is malicious
CREATE OR REPLACE FUNCTION is_domain_malicious(check_domain VARCHAR)
RETURNS TABLE(
    is_malicious BOOLEAN,
    threat_score INTEGER,
    category VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.is_malicious,
        d.threat_score,
        d.category
    FROM domains d
    WHERE d.domain = check_domain
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Function: Check if hash is malicious
CREATE OR REPLACE FUNCTION is_hash_malicious(check_hash VARCHAR)
RETURNS TABLE(
    is_malicious BOOLEAN,
    threat_score INTEGER,
    malware_family VARCHAR,
    av_detection_rate DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        h.is_malicious,
        h.threat_score,
        h.malware_family,
        h.av_detection_rate
    FROM hashes h
    WHERE h.sha256 = check_hash 
       OR h.md5 = check_hash 
       OR h.sha1 = check_hash
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Function: Get IP full intelligence (combines all IP tables)
CREATE OR REPLACE FUNCTION get_ip_intelligence(check_ip INET)
RETURNS TABLE(
    ip INET,
    is_malicious BOOLEAN,
    threat_score INTEGER,
    abuse_type VARCHAR,
    country_code VARCHAR,
    city VARCHAR,
    asn INTEGER,
    asn_org VARCHAR,
    is_vpn BOOLEAN,
    is_tor BOOLEAN,
    is_proxy BOOLEAN,
    provider_name VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        check_ip,
        b.is_malicious,
        b.threat_score,
        b.abuse_type,
        g.country_code,
        g.city,
        g.asn,
        g.asn_org,
        a.is_vpn,
        a.is_tor,
        a.is_proxy,
        a.provider_name
    FROM (SELECT check_ip as ip) base
    LEFT JOIN ip_blacklist b ON b.ip_address = check_ip
    LEFT JOIN ip_geolocation g ON g.ip_address = check_ip
    LEFT JOIN ip_anonymization a ON a.ip_address = check_ip;
END;
$$ LANGUAGE plpgsql;

-- Function: Update threat scores based on sources count
CREATE OR REPLACE FUNCTION update_threat_scores()
RETURNS void AS $$
BEGIN
    -- Update IP threat scores based on evidence count
    UPDATE ip_blacklist
    SET threat_score = LEAST(100, evidence_count * 10 + confidence)
    WHERE is_malicious = TRUE;
    
    -- Update domain threat scores
    UPDATE domains
    SET threat_score = LEAST(100, detection_count * 15 + CASE 
        WHEN is_newly_registered THEN 20 
        ELSE 0 
    END)
    WHERE is_malicious = TRUE;
    
    -- Update hash threat scores based on AV detection rate
    UPDATE hashes
    SET threat_score = LEAST(100, ROUND(av_detection_rate))
    WHERE is_malicious = TRUE;
END;
$$ LANGUAGE plpgsql;

-- Function: Clean up expired IOCs
CREATE OR REPLACE FUNCTION cleanup_expired_iocs()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Mark expired IOCs as expired
    UPDATE iocs 
    SET status = 'expired'
    WHERE expires_at < CURRENT_TIMESTAMP 
      AND status = 'active';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Delete very old expired IOCs (older than 1 year)
    DELETE FROM iocs
    WHERE status = 'expired' 
      AND expires_at < CURRENT_TIMESTAMP - INTERVAL '1 year';
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Archive old feed history (keep last 30 days)
CREATE OR REPLACE FUNCTION archive_old_feed_history()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM feed_history
    WHERE fetch_timestamp < CURRENT_TIMESTAMP - INTERVAL '30 days';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Refresh materialized views
CREATE OR REPLACE FUNCTION refresh_all_materialized_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY daily_threat_stats;
    REFRESH MATERIALIZED VIEW CONCURRENTLY top_threat_actors;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION is_ip_malicious IS 'Quick check if an IP address is malicious';
COMMENT ON FUNCTION is_domain_malicious IS 'Quick check if a domain is malicious';
COMMENT ON FUNCTION is_hash_malicious IS 'Quick check if a file hash is malicious';
COMMENT ON FUNCTION get_ip_intelligence IS 'Get complete intelligence for an IP (blacklist + geo + anonymization)';
COMMENT ON FUNCTION update_threat_scores IS 'Recalculate threat scores based on evidence and confidence';
COMMENT ON FUNCTION cleanup_expired_iocs IS 'Mark and delete expired IOCs';
COMMENT ON FUNCTION archive_old_feed_history IS 'Delete feed history older than 30 days';
COMMENT ON FUNCTION refresh_all_materialized_views IS 'Refresh all materialized views';
