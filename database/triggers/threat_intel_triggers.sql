-- ============================================================================
-- Threat Intelligence Database - Triggers
-- Automatic data updates and validations
-- ============================================================================

-- Trigger Function: Auto-update last_updated timestamp on IP blacklist
CREATE OR REPLACE FUNCTION update_ip_blacklist_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = CURRENT_TIMESTAMP;
    NEW.last_seen = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_ip_blacklist_timestamp
BEFORE UPDATE ON ip_blacklist
FOR EACH ROW
EXECUTE FUNCTION update_ip_blacklist_timestamp();

-- Trigger Function: Auto-update last_updated timestamp on domains
CREATE OR REPLACE FUNCTION update_domains_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = CURRENT_TIMESTAMP;
    NEW.last_seen = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_domains_timestamp
BEFORE UPDATE ON domains
FOR EACH ROW
EXECUTE FUNCTION update_domains_timestamp();

-- Trigger Function: Auto-calculate domain age
CREATE OR REPLACE FUNCTION calculate_domain_age()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.registration_date IS NOT NULL THEN
        NEW.age_days = EXTRACT(DAY FROM (CURRENT_TIMESTAMP - NEW.registration_date));
        NEW.is_newly_registered = (NEW.age_days < 30);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_calculate_domain_age
BEFORE INSERT OR UPDATE ON domains
FOR EACH ROW
EXECUTE FUNCTION calculate_domain_age();

-- Trigger Function: Auto-update timestamp on hashes
CREATE OR REPLACE FUNCTION update_hashes_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = CURRENT_TIMESTAMP;
    NEW.last_seen = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_hashes_timestamp
BEFORE UPDATE ON hashes
FOR EACH ROW
EXECUTE FUNCTION update_hashes_timestamp();

-- Trigger Function: Auto-update timestamp on IOCs
CREATE OR REPLACE FUNCTION update_iocs_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = CURRENT_TIMESTAMP;
    NEW.last_seen = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_iocs_timestamp
BEFORE UPDATE ON iocs
FOR EACH ROW
EXECUTE FUNCTION update_iocs_timestamp();

-- Trigger Function: Auto-update timestamp on IP anonymization
CREATE OR REPLACE FUNCTION update_ip_anon_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = CURRENT_TIMESTAMP;
    NEW.last_seen = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_ip_anon_timestamp
BEFORE UPDATE ON ip_anonymization
FOR EACH ROW
EXECUTE FUNCTION update_ip_anon_timestamp();

COMMENT ON FUNCTION update_ip_blacklist_timestamp IS 'Auto-update timestamps when IP blacklist entry is modified';
COMMENT ON FUNCTION update_domains_timestamp IS 'Auto-update timestamps when domain entry is modified';
COMMENT ON FUNCTION calculate_domain_age IS 'Auto-calculate domain age and newly_registered flag';
COMMENT ON FUNCTION update_hashes_timestamp IS 'Auto-update timestamps when hash entry is modified';
COMMENT ON FUNCTION update_iocs_timestamp IS 'Auto-update timestamps when IOC entry is modified';
COMMENT ON FUNCTION update_ip_anon_timestamp IS 'Auto-update timestamps when IP anonymization entry is modified';
