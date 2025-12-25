-- ============================================================================
-- Certificate Manager Schema
-- File: database/schemas/010_certificate_manager.sql
-- Purpose: SSL/TLS certificate storage, ACME accounts, renewal tracking
-- Requires: PostgreSQL 12+, pgcrypto extension
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Section 1: ACME Accounts Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS acme_accounts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    private_key_pem TEXT NOT NULL,
    directory_url VARCHAR(500) NOT NULL DEFAULT 'https://acme-v02.api.letsencrypt.org/directory',
    registration_url VARCHAR(500),
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deactivated', 'revoked')),
    tos_agreed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE acme_accounts IS 'Let''s Encrypt ACME account registration data';

-- ============================================================================
-- Section 2: Certificates Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    common_name VARCHAR(253) NOT NULL,
    subject_alt_names TEXT[] DEFAULT '{}',
    is_wildcard BOOLEAN DEFAULT FALSE,
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    chain_pem TEXT,
    serial_number VARCHAR(255) UNIQUE,
    issuer VARCHAR(255),
    not_before TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active' 
        CHECK (status IN ('pending', 'active', 'expired', 'revoked', 'renewal_pending')),
    acme_order_url VARCHAR(500),
    challenge_type VARCHAR(20) CHECK (challenge_type IN ('http-01', 'dns-01', 'tls-alpn-01')),
    acme_account_id INTEGER REFERENCES acme_accounts(id) ON DELETE SET NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_checked_at TIMESTAMP WITH TIME ZONE,
    next_renewal_check TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT valid_dates CHECK (not_after > not_before),
    CONSTRAINT unique_domain_per_account UNIQUE (common_name, acme_account_id)
);

COMMENT ON TABLE certificates IS 'SSL/TLS certificates with private keys and chains';

-- ============================================================================
-- Section 3: Certificate History Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS certificate_history (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    event_type VARCHAR(30) NOT NULL 
        CHECK (event_type IN ('issued', 'renewed', 'revoked', 'expired', 'distributed', 'validation_failed', 'renewal_failed')),
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    previous_serial VARCHAR(255),
    previous_not_after TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    triggered_by VARCHAR(100) DEFAULT 'system',
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT
);

COMMENT ON TABLE certificate_history IS 'Audit log for certificate lifecycle events';

-- ============================================================================
-- Section 4: Renewal Schedule Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS renewal_schedule (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE UNIQUE,
    next_renewal_check TIMESTAMP WITH TIME ZONE NOT NULL,
    renewal_attempt_count INTEGER DEFAULT 0,
    last_renewal_attempt TIMESTAMP WITH TIME ZONE,
    last_renewal_result VARCHAR(20) CHECK (last_renewal_result IN ('success', 'failed', 'skipped', NULL)),
    renewal_window_start TIMESTAMP WITH TIME ZONE,
    auto_renewal_enabled BOOLEAN DEFAULT TRUE,
    notify_7_days_sent BOOLEAN DEFAULT FALSE,
    notify_3_days_sent BOOLEAN DEFAULT FALSE,
    notify_1_day_sent BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE renewal_schedule IS 'Automatic renewal tracking and notification flags';

-- ============================================================================
-- Section 5: Domain Validation Challenges Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS domain_challenges (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    domain VARCHAR(253) NOT NULL,
    challenge_type VARCHAR(20) NOT NULL CHECK (challenge_type IN ('http-01', 'dns-01', 'tls-alpn-01')),
    token VARCHAR(500) NOT NULL,
    key_authorization TEXT NOT NULL,
    validation_url VARCHAR(500),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' 
        CHECK (status IN ('pending', 'processing', 'valid', 'invalid')),
    attempt_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    validated_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

COMMENT ON TABLE domain_challenges IS 'ACME domain validation challenge data';

-- ============================================================================
-- Section 6: Certificate Distribution Log
-- ============================================================================
CREATE TABLE IF NOT EXISTS distribution_log (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    target_service VARCHAR(100) NOT NULL,
    distribution_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    distribution_method VARCHAR(30) CHECK (distribution_method IN ('grpc_push', 'file_copy', 'api_call')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' 
        CHECK (status IN ('pending', 'success', 'failed', 'retrying')),
    service_ack_timestamp TIMESTAMP WITH TIME ZONE,
    service_version VARCHAR(50),
    retry_count INTEGER DEFAULT 0,
    next_retry_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

COMMENT ON TABLE distribution_log IS 'Certificate deployment tracking to services';

-- ============================================================================
-- Section 7: Indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_cert_common_name ON certificates(common_name);
CREATE INDEX IF NOT EXISTS idx_cert_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_cert_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_cert_acme_account ON certificates(acme_account_id);
CREATE INDEX IF NOT EXISTS idx_renewal_next_check ON renewal_schedule(next_renewal_check);
CREATE INDEX IF NOT EXISTS idx_history_cert_time ON certificate_history(certificate_id, event_timestamp);
CREATE INDEX IF NOT EXISTS idx_challenges_domain_status ON domain_challenges(domain, status);
CREATE INDEX IF NOT EXISTS idx_dist_cert_service ON distribution_log(certificate_id, target_service);

-- ============================================================================
-- Section 8: Triggers for Auto-Update Timestamps
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_acme_accounts_updated_at
    BEFORE UPDATE ON acme_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_certificates_updated_at
    BEFORE UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_renewal_schedule_updated_at
    BEFORE UPDATE ON renewal_schedule
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger to create renewal schedule when certificate is issued
CREATE OR REPLACE FUNCTION create_renewal_schedule()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO renewal_schedule (certificate_id, next_renewal_check, renewal_window_start)
    VALUES (
        NEW.id,
        NEW.not_after - INTERVAL '30 days',
        NEW.not_after - INTERVAL '30 days'
    )
    ON CONFLICT (certificate_id) DO UPDATE SET
        next_renewal_check = EXCLUDED.next_renewal_check,
        renewal_window_start = EXCLUDED.renewal_window_start;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER auto_create_renewal_schedule
    AFTER INSERT ON certificates
    FOR EACH ROW EXECUTE FUNCTION create_renewal_schedule();

-- Trigger to log certificate status changes
CREATE OR REPLACE FUNCTION log_certificate_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO certificate_history (certificate_id, event_type, previous_serial, metadata)
        VALUES (
            NEW.id,
            CASE 
                WHEN NEW.status = 'active' AND OLD.status = 'pending' THEN 'issued'
                WHEN NEW.status = 'active' AND OLD.status = 'renewal_pending' THEN 'renewed'
                WHEN NEW.status = 'revoked' THEN 'revoked'
                WHEN NEW.status = 'expired' THEN 'expired'
                ELSE 'issued'
            END,
            OLD.serial_number,
            jsonb_build_object('old_status', OLD.status, 'new_status', NEW.status)
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER log_cert_status_change
    AFTER UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION log_certificate_status_change();

-- ============================================================================
-- Section 9: Helper Functions
-- ============================================================================
CREATE OR REPLACE FUNCTION get_expiring_certificates(days_threshold INT DEFAULT 30)
RETURNS TABLE (
    id INT,
    common_name VARCHAR,
    not_after TIMESTAMP WITH TIME ZONE,
    days_remaining INT,
    status VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.id,
        c.common_name,
        c.not_after,
        EXTRACT(DAY FROM c.not_after - CURRENT_TIMESTAMP)::INT as days_remaining,
        c.status
    FROM certificates c
    WHERE c.status = 'active'
      AND c.not_after <= CURRENT_TIMESTAMP + (days_threshold || ' days')::INTERVAL
    ORDER BY c.not_after ASC;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION mark_certificate_for_renewal(cert_id INT)
RETURNS VOID AS $$
BEGIN
    UPDATE certificates SET status = 'renewal_pending' WHERE id = cert_id;
    UPDATE renewal_schedule SET 
        last_renewal_attempt = CURRENT_TIMESTAMP,
        renewal_attempt_count = renewal_attempt_count + 1
    WHERE certificate_id = cert_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_challenges()
RETURNS INT AS $$
DECLARE
    deleted_count INT;
BEGIN
    DELETE FROM domain_challenges 
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '7 days'
      AND status IN ('valid', 'invalid');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_certificate_by_domain(domain_name VARCHAR)
RETURNS TABLE (
    id INT,
    common_name VARCHAR,
    certificate_pem TEXT,
    private_key_pem TEXT,
    chain_pem TEXT,
    not_after TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.id,
        c.common_name,
        c.certificate_pem,
        c.private_key_pem,
        c.chain_pem,
        c.not_after
    FROM certificates c
    WHERE c.status = 'active'
      AND (c.common_name = domain_name OR domain_name = ANY(c.subject_alt_names))
    ORDER BY c.not_after DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION revoke_certificate(cert_id INT, reason VARCHAR DEFAULT 'manual revocation')
RETURNS VOID AS $$
BEGIN
    UPDATE certificates SET status = 'revoked' WHERE id = cert_id;
    INSERT INTO certificate_history (certificate_id, event_type, metadata)
    VALUES (cert_id, 'revoked', jsonb_build_object('reason', reason));
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Section 10: Initial Seeds (Optional)
-- ============================================================================
-- Staging ACME account for testing
INSERT INTO acme_accounts (email, private_key_pem, directory_url, status)
VALUES (
    'testing@safeops.local',
    '-- PLACEHOLDER: Generate real key --',
    'https://acme-staging-v02.api.letsencrypt.org/directory',
    'active'
) ON CONFLICT (email) DO NOTHING;

-- ============================================================================
-- Schema Version Tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(50) PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_migrations (version) 
VALUES ('010_certificate_manager') 
ON CONFLICT (version) DO NOTHING;
