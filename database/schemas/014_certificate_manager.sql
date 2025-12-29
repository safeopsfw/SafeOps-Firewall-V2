-- ============================================================================
-- Certificate Manager Schema - Enhanced Migration
-- File: database/schemas/014_certificate_manager.sql
-- Purpose: Adds advanced certificate features to existing 010 schema
-- Requires: PostgreSQL 12+, 010_certificate_manager.sql executed first
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Section 1: Enhanced Certificates Table (adds missing fields to existing)
-- Note: If certificates table already exists from 010, add missing columns
-- ============================================================================

-- Add missing columns to existing certificates table
DO $$
BEGIN
    -- Add fingerprint_sha256 if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'fingerprint_sha256') THEN
        ALTER TABLE certificates ADD COLUMN fingerprint_sha256 VARCHAR(64);
    END IF;

    -- Add subject_dn if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'subject_dn') THEN
        ALTER TABLE certificates ADD COLUMN subject_dn TEXT;
    END IF;

    -- Add issuer_dn if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'issuer_dn') THEN
        ALTER TABLE certificates ADD COLUMN issuer_dn TEXT;
    END IF;

    -- Add key_algorithm if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'key_algorithm') THEN
        ALTER TABLE certificates ADD COLUMN key_algorithm VARCHAR(32) DEFAULT 'RSA';
    END IF;

    -- Add key_size if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'key_size') THEN
        ALTER TABLE certificates ADD COLUMN key_size INTEGER DEFAULT 2048;
    END IF;

    -- Add signature_algorithm if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'signature_algorithm') THEN
        ALTER TABLE certificates ADD COLUMN signature_algorithm VARCHAR(64);
    END IF;

    -- Add is_ca if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'is_ca') THEN
        ALTER TABLE certificates ADD COLUMN is_ca BOOLEAN DEFAULT FALSE;
    END IF;

    -- Add is_self_signed if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'is_self_signed') THEN
        ALTER TABLE certificates ADD COLUMN is_self_signed BOOLEAN DEFAULT FALSE;
    END IF;

    -- Add certificate_der if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'certificate_der') THEN
        ALTER TABLE certificates ADD COLUMN certificate_der BYTEA;
    END IF;

    -- Add san_ip_addresses if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'san_ip_addresses') THEN
        ALTER TABLE certificates ADD COLUMN san_ip_addresses INET[] DEFAULT '{}';
    END IF;

    -- Add san_email_addresses if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'san_email_addresses') THEN
        ALTER TABLE certificates ADD COLUMN san_email_addresses TEXT[] DEFAULT '{}';
    END IF;

    -- Add renewal_failure_count if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'certificates' AND column_name = 'renewal_failure_count') THEN
        ALTER TABLE certificates ADD COLUMN renewal_failure_count INTEGER DEFAULT 0;
    END IF;
END $$;

-- Create additional indexes on certificates
CREATE INDEX IF NOT EXISTS idx_cert_fingerprint ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_san_dns ON certificates USING GIN(subject_alt_names);

-- ============================================================================
-- Section 1.5: Device CA Status Tracking (DHCP Integration)
-- ============================================================================
CREATE TABLE IF NOT EXISTS device_ca_status (
    id SERIAL PRIMARY KEY,
    device_ip INET NOT NULL,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    ca_installed BOOLEAN DEFAULT FALSE,
    detected_at TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    download_count INTEGER DEFAULT 0,
    os_type VARCHAR(64),
    user_agent TEXT,
    trust_status VARCHAR(32) DEFAULT 'unknown' CHECK (trust_status IN (
        'unknown', 'trusted', 'untrusted', 'pending', 'error'
    )),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_device UNIQUE (device_ip, mac_address)
);

COMMENT ON TABLE device_ca_status IS 'Tracks CA installation status on network devices for DHCP integration';
COMMENT ON COLUMN device_ca_status.device_ip IS 'Device IP address from network detection';
COMMENT ON COLUMN device_ca_status.ca_installed IS 'Whether device trusts SafeOps root CA';
COMMENT ON COLUMN device_ca_status.detected_at IS 'When CA installation was verified via TLS handshake';

CREATE INDEX IF NOT EXISTS idx_device_ip ON device_ca_status(device_ip);
CREATE INDEX IF NOT EXISTS idx_mac_address ON device_ca_status(mac_address);
CREATE INDEX IF NOT EXISTS idx_ca_installed ON device_ca_status(ca_installed);
CREATE INDEX IF NOT EXISTS idx_device_last_seen ON device_ca_status(last_seen);

-- ============================================================================
-- Section 1.6: Certificate Download Tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS certificate_downloads (
    id SERIAL PRIMARY KEY,
    device_ip INET NOT NULL,
    format VARCHAR(16) NOT NULL CHECK (format IN ('pem', 'der', 'p7b', 'pkcs12', 'mobileconfig', 'script')),
    user_agent TEXT,
    download_path VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT TRUE,
    source VARCHAR(32) DEFAULT 'http' CHECK (source IN ('http', 'dhcp', 'script', 'api', 'qr_code', 'mobile')),
    bytes_sent BIGINT DEFAULT 0,
    referer TEXT,
    error_message TEXT
);

COMMENT ON TABLE certificate_downloads IS 'Logs CA certificate downloads for analytics and troubleshooting';
COMMENT ON COLUMN certificate_downloads.format IS 'Certificate format: pem, der, p7b, pkcs12, mobileconfig, script';
COMMENT ON COLUMN certificate_downloads.source IS 'Download trigger source: http, dhcp, script, api, qr_code, mobile';

CREATE INDEX IF NOT EXISTS idx_download_device_ip ON certificate_downloads(device_ip);
CREATE INDEX IF NOT EXISTS idx_download_timestamp ON certificate_downloads(timestamp);
CREATE INDEX IF NOT EXISTS idx_download_format ON certificate_downloads(format);
CREATE INDEX IF NOT EXISTS idx_download_source ON certificate_downloads(source);

-- ============================================================================
-- Section 1.7: CA Backups Metadata
-- ============================================================================
CREATE TABLE IF NOT EXISTS ca_backups (
    id SERIAL PRIMARY KEY,
    backup_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    backup_location VARCHAR(500) NOT NULL,
    encryption_key_fingerprint VARCHAR(64),
    backup_size_bytes BIGINT,
    backup_checksum VARCHAR(128),
    ca_certificate_fingerprint VARCHAR(64),
    restored BOOLEAN DEFAULT FALSE,
    restore_timestamp TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(100),
    notes TEXT
);

COMMENT ON TABLE ca_backups IS 'Tracks encrypted CA key backups for disaster recovery';
COMMENT ON COLUMN ca_backups.backup_checksum IS 'SHA-256 checksum for integrity verification';

CREATE INDEX IF NOT EXISTS idx_backup_timestamp ON ca_backups(backup_timestamp);
CREATE INDEX IF NOT EXISTS idx_backup_restored ON ca_backups(restored);

-- ============================================================================
-- Section 2: Private Keys Table (Encrypted Key Storage)
-- ============================================================================
CREATE TABLE IF NOT EXISTS private_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    key_algorithm VARCHAR(32) NOT NULL CHECK (key_algorithm IN ('RSA', 'ECDSA', 'ED25519')),
    key_size INTEGER NOT NULL,
    encrypted_key_pem BYTEA NOT NULL,
    encryption_method VARCHAR(64) NOT NULL DEFAULT 'AES-256-GCM',
    encryption_salt BYTEA NOT NULL,
    encryption_iv BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT unique_private_key_per_cert UNIQUE (certificate_id)
);

COMMENT ON TABLE private_keys IS 'Encrypted private key storage with AES-256-GCM encryption';
COMMENT ON COLUMN private_keys.encrypted_key_pem IS 'AES-256-GCM encrypted private key in PEM format';
COMMENT ON COLUMN private_keys.encryption_salt IS 'Salt used for key derivation (PBKDF2/Argon2)';
COMMENT ON COLUMN private_keys.encryption_iv IS 'Initialization vector for AES-GCM';

CREATE INDEX IF NOT EXISTS idx_private_keys_cert_id ON private_keys(certificate_id);

-- ============================================================================
-- Section 3: Certificate Revocations Table (CRL/OCSP Data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS certificate_revocations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id INTEGER NOT NULL REFERENCES certificates(id),
    serial_number VARCHAR(128) NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revocation_reason VARCHAR(64) NOT NULL CHECK (revocation_reason IN (
        'key_compromise', 'ca_compromise', 'affiliation_changed', 
        'superseded', 'cessation_of_operation', 'certificate_hold',
        'remove_from_crl', 'privilege_withdrawn', 'aa_compromise', 'unspecified'
    )),
    reason_description TEXT,
    revoked_by VARCHAR(255),
    crl_entry_added BOOLEAN DEFAULT FALSE,
    crl_added_at TIMESTAMP WITH TIME ZONE,
    invalidation_date TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE certificate_revocations IS 'Certificate revocation tracking for CRL/OCSP responses';
COMMENT ON COLUMN certificate_revocations.revocation_reason IS 'RFC 5280 revocation reason codes';

CREATE INDEX IF NOT EXISTS idx_revocations_serial ON certificate_revocations(serial_number);
CREATE INDEX IF NOT EXISTS idx_revocations_cert_id ON certificate_revocations(certificate_id);
CREATE INDEX IF NOT EXISTS idx_revocations_timestamp ON certificate_revocations(revoked_at);
CREATE INDEX IF NOT EXISTS idx_revocations_crl ON certificate_revocations(crl_entry_added) WHERE crl_entry_added = FALSE;

-- ============================================================================
-- Section 4: ACME Orders Table (separate from challenges in 010)
-- ============================================================================
CREATE TABLE IF NOT EXISTS acme_orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id INTEGER NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
    order_url VARCHAR(512) UNIQUE NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN ('pending', 'ready', 'processing', 'valid', 'invalid')),
    identifiers JSONB NOT NULL,
    finalize_url VARCHAR(512),
    certificate_url VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    not_before TIMESTAMP WITH TIME ZONE,
    not_after TIMESTAMP WITH TIME ZONE,
    error_detail JSONB,
    
    CONSTRAINT valid_order_identifiers CHECK (jsonb_typeof(identifiers) = 'array')
);

COMMENT ON TABLE acme_orders IS 'ACME certificate order tracking with lifecycle status';
COMMENT ON COLUMN acme_orders.identifiers IS 'JSON array of domain/IP identifiers to certify';

CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id);
CREATE INDEX IF NOT EXISTS idx_acme_orders_status ON acme_orders(status);
CREATE INDEX IF NOT EXISTS idx_acme_orders_expires ON acme_orders(expires_at);

-- ============================================================================
-- Section 5: Certificate Audit Log (Tamper-Proof with Hash Chaining)
-- ============================================================================
CREATE TABLE IF NOT EXISTS certificate_audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    operation VARCHAR(64) NOT NULL CHECK (operation IN (
        'generate', 'import', 'renew', 'revoke', 'delete', 'sign_csr',
        'export', 'distribute', 'validation_success', 'validation_failure',
        'acme_order', 'acme_challenge', 'key_access', 'config_change'
    )),
    certificate_id INTEGER,
    certificate_cn VARCHAR(255),
    user_id VARCHAR(255),
    ip_address INET,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    details JSONB DEFAULT '{}',
    previous_entry_hash VARCHAR(64),
    entry_hash VARCHAR(64) NOT NULL,
    
    CONSTRAINT audit_fk_certificate FOREIGN KEY (certificate_id) 
        REFERENCES certificates(id) ON DELETE SET NULL
);

COMMENT ON TABLE certificate_audit_log IS 'Tamper-proof audit trail with blockchain-style hash chaining';
COMMENT ON COLUMN certificate_audit_log.previous_entry_hash IS 'SHA-256 hash of previous log entry for tamper detection';
COMMENT ON COLUMN certificate_audit_log.entry_hash IS 'SHA-256 hash of this entry (timestamp+operation+details)';

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON certificate_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_cert_id ON certificate_audit_log(certificate_id);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON certificate_audit_log(operation);
CREATE INDEX IF NOT EXISTS idx_audit_user ON certificate_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_composite ON certificate_audit_log(timestamp, operation);

-- ============================================================================
-- Section 6: Certificate Usage Table (Service-to-Certificate Mapping)
-- ============================================================================
CREATE TABLE IF NOT EXISTS certificate_usage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    service_name VARCHAR(128) NOT NULL,
    service_instance_id VARCHAR(255),
    deployment_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_verified TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    deployment_method VARCHAR(64),
    
    CONSTRAINT unique_cert_service UNIQUE (certificate_id, service_name, service_instance_id)
);

COMMENT ON TABLE certificate_usage IS 'Tracks which services are using which certificates for impact analysis';

CREATE INDEX IF NOT EXISTS idx_usage_cert_id ON certificate_usage(certificate_id);
CREATE INDEX IF NOT EXISTS idx_usage_service ON certificate_usage(service_name);
CREATE INDEX IF NOT EXISTS idx_usage_active ON certificate_usage(is_active) WHERE is_active = TRUE;

-- ============================================================================
-- Section 7: Functions
-- ============================================================================

-- Function: Automatically update certificate status based on expiry
CREATE OR REPLACE FUNCTION update_certificate_status()
RETURNS TRIGGER AS $$
BEGIN
    -- Set to expired if past not_after
    IF NEW.not_after < CURRENT_TIMESTAMP AND NEW.status NOT IN ('revoked', 'expired') THEN
        NEW.status := 'expired';
    -- Set to expiring if within 30 days of expiry
    ELSIF NEW.not_after <= CURRENT_TIMESTAMP + INTERVAL '30 days' 
          AND NEW.not_after > CURRENT_TIMESTAMP 
          AND NEW.status NOT IN ('revoked', 'expired', 'expiring') THEN
        NEW.status := 'expiring';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for auto status update
DROP TRIGGER IF EXISTS trigger_update_cert_status ON certificates;
CREATE TRIGGER trigger_update_cert_status
    BEFORE INSERT OR UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION update_certificate_status();

-- Function: Compute audit log entry hash
CREATE OR REPLACE FUNCTION compute_audit_entry_hash(
    p_timestamp TIMESTAMP WITH TIME ZONE,
    p_operation VARCHAR,
    p_certificate_id INTEGER,
    p_user_id VARCHAR,
    p_success BOOLEAN,
    p_details JSONB,
    p_previous_hash VARCHAR
) RETURNS VARCHAR AS $$
DECLARE
    hash_input TEXT;
BEGIN
    hash_input := COALESCE(p_timestamp::TEXT, '') || '|' ||
                  COALESCE(p_operation, '') || '|' ||
                  COALESCE(p_certificate_id::TEXT, '') || '|' ||
                  COALESCE(p_user_id, '') || '|' ||
                  COALESCE(p_success::TEXT, '') || '|' ||
                  COALESCE(p_details::TEXT, '{}') || '|' ||
                  COALESCE(p_previous_hash, 'GENESIS');
    RETURN encode(digest(hash_input, 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Function: Insert audit log entry with hash chaining
CREATE OR REPLACE FUNCTION insert_audit_log(
    p_operation VARCHAR,
    p_certificate_id INTEGER,
    p_certificate_cn VARCHAR,
    p_user_id VARCHAR,
    p_ip_address INET,
    p_success BOOLEAN,
    p_error_message TEXT DEFAULT NULL,
    p_details JSONB DEFAULT '{}'
) RETURNS BIGINT AS $$
DECLARE
    v_previous_hash VARCHAR;
    v_entry_hash VARCHAR;
    v_new_id BIGINT;
    v_timestamp TIMESTAMP WITH TIME ZONE;
BEGIN
    v_timestamp := CURRENT_TIMESTAMP;
    
    -- Get previous entry hash
    SELECT entry_hash INTO v_previous_hash 
    FROM certificate_audit_log 
    ORDER BY id DESC LIMIT 1;
    
    -- Compute this entry's hash
    v_entry_hash := compute_audit_entry_hash(
        v_timestamp, p_operation, p_certificate_id, 
        p_user_id, p_success, p_details, v_previous_hash
    );
    
    -- Insert the log entry
    INSERT INTO certificate_audit_log (
        timestamp, operation, certificate_id, certificate_cn,
        user_id, ip_address, success, error_message, details,
        previous_entry_hash, entry_hash
    ) VALUES (
        v_timestamp, p_operation, p_certificate_id, p_certificate_cn,
        p_user_id, p_ip_address, p_success, p_error_message, p_details,
        v_previous_hash, v_entry_hash
    ) RETURNING id INTO v_new_id;
    
    RETURN v_new_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Section 8: Triggers for Audit Log Immutability
-- ============================================================================

-- Trigger function to prevent audit log modifications
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'certificate_audit_log is immutable. UPDATE and DELETE operations are not allowed.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to block UPDATE operations
DROP TRIGGER IF EXISTS trigger_prevent_audit_update ON certificate_audit_log;
CREATE TRIGGER trigger_prevent_audit_update
    BEFORE UPDATE ON certificate_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

-- Create trigger to block DELETE operations
DROP TRIGGER IF EXISTS trigger_prevent_audit_delete ON certificate_audit_log;
CREATE TRIGGER trigger_prevent_audit_delete
    BEFORE DELETE ON certificate_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

-- ============================================================================
-- Section 9: Views
-- ============================================================================

-- View: Expiring certificates (within 30 days)
CREATE OR REPLACE VIEW v_expiring_certificates AS
SELECT 
    c.id,
    c.common_name,
    c.serial_number,
    c.subject_alt_names AS san_list,
    c.not_after AS expiration_date,
    EXTRACT(DAY FROM c.not_after - CURRENT_TIMESTAMP)::INTEGER AS days_remaining,
    c.status,
    c.issuer,
    CASE WHEN rs.auto_renewal_enabled THEN 'Auto-Renew' ELSE 'Manual' END AS renewal_mode
FROM certificates c
LEFT JOIN renewal_schedule rs ON c.id = rs.certificate_id
WHERE c.status IN ('active', 'expiring')
  AND c.not_after BETWEEN CURRENT_TIMESTAMP AND CURRENT_TIMESTAMP + INTERVAL '30 days'
ORDER BY c.not_after ASC;

COMMENT ON VIEW v_expiring_certificates IS 'Certificates expiring within the next 30 days';

-- View: Certificate health dashboard
CREATE OR REPLACE VIEW v_certificate_health AS
SELECT 
    COUNT(*) AS total_certificates,
    COUNT(*) FILTER (WHERE status = 'active') AS valid_count,
    COUNT(*) FILTER (WHERE status = 'expiring' OR 
        (status = 'active' AND not_after <= CURRENT_TIMESTAMP + INTERVAL '30 days')) AS expiring_count,
    COUNT(*) FILTER (WHERE status = 'expired') AS expired_count,
    COUNT(*) FILTER (WHERE status = 'revoked') AS revoked_count,
    COUNT(*) FILTER (WHERE status = 'pending') AS pending_count,
    (SELECT COUNT(*) FROM renewal_schedule WHERE auto_renewal_enabled = TRUE) AS auto_renew_enabled_count,
    COUNT(*) FILTER (WHERE status IN ('expiring', 'expired') 
        AND id NOT IN (SELECT certificate_id FROM renewal_schedule WHERE auto_renewal_enabled = TRUE))
        AS manual_intervention_required,
    CURRENT_TIMESTAMP AS snapshot_timestamp
FROM certificates;

COMMENT ON VIEW v_certificate_health IS 'Overall certificate inventory health dashboard';

-- View: Revocation list for CRL generation
CREATE OR REPLACE VIEW v_revocation_list AS
SELECT 
    cr.serial_number,
    cr.revoked_at,
    cr.revocation_reason,
    cr.reason_description,
    cr.invalidation_date,
    c.common_name,
    c.issuer,
    c.not_after AS original_expiry
FROM certificate_revocations cr
JOIN certificates c ON cr.certificate_id = c.id
WHERE cr.revocation_reason != 'remove_from_crl'
ORDER BY cr.revoked_at DESC;

COMMENT ON VIEW v_revocation_list IS 'Current CRL data in queryable format for OCSP/CRL responses';

-- View: Certificate usage summary
CREATE OR REPLACE VIEW v_certificate_usage_summary AS
SELECT 
    c.id AS certificate_id,
    c.common_name,
    c.status,
    c.not_after,
    ARRAY_AGG(DISTINCT cu.service_name) FILTER (WHERE cu.is_active) AS active_services,
    COUNT(cu.id) FILTER (WHERE cu.is_active) AS active_deployment_count
FROM certificates c
LEFT JOIN certificate_usage cu ON c.id = cu.certificate_id
GROUP BY c.id, c.common_name, c.status, c.not_after
ORDER BY c.common_name;

COMMENT ON VIEW v_certificate_usage_summary IS 'Summary of certificate deployments across services';

-- ============================================================================
-- Section 10: Schema Version Tracking
-- ============================================================================
INSERT INTO schema_migrations (version) 
VALUES ('014_certificate_manager_enhanced') 
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Migration Complete
-- ============================================================================
