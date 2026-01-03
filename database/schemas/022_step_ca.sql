-- ============================================================================
-- Migration 022: Step-CA Password Storage Infrastructure
-- ============================================================================
-- Database Target: safeops_network (shared with Phase 2 DHCP Monitor)
-- Purpose: Create encrypted password storage for Step-CA master password
-- Author: SafeOps Phase 3A Setup
-- Date: 2026-01-03
-- 
-- Dependencies:
--   - PostgreSQL 13+ with pgcrypto extension
--   - Database safeops_network must exist (Phase 2)
--   - Migrations 001-021 should be applied
--
-- Rollback: See END OF FILE for DROP statements
-- ============================================================================

-- ============================================================================
-- SECTION 1: Enable Required Extensions
-- ============================================================================

-- pgcrypto provides pgp_sym_encrypt() and pgp_sym_decrypt() for AES-256 encryption
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- uuid-ossp provides gen_random_uuid() for generating unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- SECTION 2: Secrets Table Definition
-- ============================================================================
-- Stores encrypted passwords and secrets for SafeOps services
-- Design: Generic schema supports Step-CA, TLS Proxy, Captive Portal secrets

CREATE TABLE IF NOT EXISTS secrets (
    -- Primary key: UUID for distributed-friendly unique identification
    secret_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Service identifier: Unique name for each service's secret
    -- Examples: 'step-ca-master', 'tls-proxy-api-key', 'captive-portal-session'
    service_name VARCHAR(100) UNIQUE NOT NULL,
    
    -- Encrypted secret value stored as binary data
    -- Uses pgcrypto's pgp_sym_encrypt() with AES-256
    secret_value_encrypted BYTEA NOT NULL,
    
    -- Encryption algorithm identifier for future flexibility
    -- Current: 'pgp_sym_aes256' (PostgreSQL pgcrypto symmetric encryption)
    encryption_method VARCHAR(50) NOT NULL DEFAULT 'pgp_sym_aes256',
    
    -- Human-readable description of what this secret is for
    description TEXT,
    
    -- Audit trail fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100) DEFAULT CURRENT_USER
);

-- Add table comments for documentation
COMMENT ON TABLE secrets IS 'Encrypted storage for service passwords and API keys (Phase 3A)';
COMMENT ON COLUMN secrets.secret_id IS 'Unique identifier for each secret entry';
COMMENT ON COLUMN secrets.service_name IS 'Service identifier (e.g., step-ca-master)';
COMMENT ON COLUMN secrets.secret_value_encrypted IS 'Password encrypted with pgp_sym_encrypt()';
COMMENT ON COLUMN secrets.encryption_method IS 'Encryption algorithm used (default: pgp_sym_aes256)';

-- ============================================================================
-- SECTION 3: Performance Indexes
-- ============================================================================

-- Fast lookup by service name (< 5ms for Step-CA startup queries)
CREATE INDEX IF NOT EXISTS idx_secrets_service_name ON secrets(service_name);

-- Audit/compliance queries for secret lifecycle
CREATE INDEX IF NOT EXISTS idx_secrets_created_at ON secrets(created_at DESC);

-- ============================================================================
-- SECTION 4: Automatic Timestamp Update Trigger
-- ============================================================================

-- Function to update the updated_at timestamp on every UPDATE
CREATE OR REPLACE FUNCTION update_secrets_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger that fires BEFORE UPDATE on secrets table
DROP TRIGGER IF EXISTS trigger_update_secrets_timestamp ON secrets;
CREATE TRIGGER trigger_update_secrets_timestamp
    BEFORE UPDATE ON secrets
    FOR EACH ROW
    EXECUTE FUNCTION update_secrets_timestamp();

-- ============================================================================
-- SECTION 5: Encryption/Decryption Examples (Documentation Only)
-- ============================================================================
-- WARNING: These examples use placeholder keys. NEVER hardcode actual keys!

-- Example: INSERT encrypted password
-- INSERT INTO secrets (service_name, secret_value_encrypted, description)
-- VALUES (
--     'step-ca-master',
--     pgp_sym_encrypt('MyPassword123', current_setting('my.encryption_key')),
--     'Step-CA master password for Root CA key encryption'
-- );

-- Example: RETRIEVE decrypted password
-- SELECT pgp_sym_decrypt(secret_value_encrypted, current_setting('my.encryption_key'))::text
-- FROM secrets
-- WHERE service_name = 'step-ca-master';

-- Example: UPDATE password
-- UPDATE secrets
-- SET secret_value_encrypted = pgp_sym_encrypt('NewPassword456', current_setting('my.encryption_key'))
-- WHERE service_name = 'step-ca-master';

-- ============================================================================
-- SECTION 6: Verification Queries
-- ============================================================================
-- Run these after migration to verify success:

-- Check table exists:
-- SELECT table_name FROM information_schema.tables WHERE table_name = 'secrets';

-- Check extension loaded:
-- SELECT extname FROM pg_extension WHERE extname = 'pgcrypto';

-- Test encryption works:
-- SELECT pgp_sym_decrypt(pgp_sym_encrypt('test', 'testkey'), 'testkey') = 'test' AS encryption_works;

-- Count columns:
-- SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'secrets';
-- Expected: 7 columns

-- ============================================================================
-- SECTION 7: Security Notes
-- ============================================================================
-- 
-- ENCRYPTION KEY MANAGEMENT:
-- The encryption key should be set as a PostgreSQL configuration parameter:
--   ALTER DATABASE safeops_network SET my.encryption_key = 'your-secure-key-here';
-- 
-- Or use session-level setting for one-time operations:
--   SET SESSION my.encryption_key = 'your-secure-key-here';
--
-- KEY ROTATION STRATEGY:
-- 1. Decrypt all secrets with old key
-- 2. Re-encrypt with new key
-- 3. Update database parameter
-- 4. Restart services
--
-- BACKUP CONSIDERATIONS:
-- - Database backups include encrypted secrets
-- - Encryption key must be stored separately from database backup
-- - Without key, encrypted data is unrecoverable
--
-- ACCESS CONTROL:
-- REVOKE ALL ON secrets FROM PUBLIC;
-- GRANT SELECT, INSERT, UPDATE ON secrets TO safeops_admin;
-- GRANT SELECT ON secrets TO safeops_services;

-- ============================================================================
-- SECTION 8: Rollback Script (DOWN Migration)
-- ============================================================================
-- To reverse this migration, uncomment and run:

-- DROP TRIGGER IF EXISTS trigger_update_secrets_timestamp ON secrets;
-- DROP FUNCTION IF EXISTS update_secrets_timestamp() CASCADE;
-- DROP TABLE IF EXISTS secrets CASCADE;
-- Note: Extensions are NOT dropped to avoid affecting other migrations

-- ============================================================================
-- END OF MIGRATION 022
-- ============================================================================
