-- ============================================================================
-- SafeOps v2.0 - SSL Certificate Intelligence Schema
-- ============================================================================
-- File: 023_ssl_certificates.sql
-- Purpose: Track malicious SSL/TLS certificate fingerprints from abuse.ch SSLBL
-- Version: 1.0.0
-- Created: 2026-02-25
-- Dependencies: 001_initial_setup.sql
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS ssl_certificates (
    id BIGSERIAL PRIMARY KEY,
    sha1_fingerprint VARCHAR(40) NOT NULL UNIQUE,
    subject_cn VARCHAR(255),
    issuer_cn VARCHAR(255),
    serial_number VARCHAR(128),
    is_malicious BOOLEAN DEFAULT TRUE,
    threat_score INTEGER DEFAULT 90 CHECK (threat_score >= 0 AND threat_score <= 100),
    listing_reason TEXT,
    sources JSONB DEFAULT '[]'::jsonb,
    evidence_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'expired', 'whitelisted'))
);

COMMENT ON TABLE ssl_certificates IS 'Malicious SSL/TLS certificate fingerprints from abuse.ch SSLBL';
COMMENT ON COLUMN ssl_certificates.sha1_fingerprint IS 'SHA1 fingerprint of the certificate';
COMMENT ON COLUMN ssl_certificates.subject_cn IS 'Certificate subject Common Name';
COMMENT ON COLUMN ssl_certificates.issuer_cn IS 'Certificate issuer Common Name';
COMMENT ON COLUMN ssl_certificates.listing_reason IS 'Why this cert is blacklisted (e.g. Cobalt Strike C2, Dridex C2)';

CREATE INDEX IF NOT EXISTS idx_ssl_cert_sha1 ON ssl_certificates(sha1_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ssl_cert_subject ON ssl_certificates(subject_cn);
CREATE INDEX IF NOT EXISTS idx_ssl_cert_malicious ON ssl_certificates(is_malicious) WHERE is_malicious = TRUE;
CREATE INDEX IF NOT EXISTS idx_ssl_cert_sources ON ssl_certificates USING gin(sources);
CREATE INDEX IF NOT EXISTS idx_ssl_cert_last_seen ON ssl_certificates(last_seen DESC);

COMMIT;
