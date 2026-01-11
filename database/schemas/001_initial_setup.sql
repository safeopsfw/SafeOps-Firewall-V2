-- ============================================================================
-- SafeOps v2.0 - Initial Database Setup
-- ============================================================================
-- File: 001_initial_setup.sql
-- Purpose: Foundation schema for threat intelligence database
-- Version: 1.0.0
-- Created: 2025-12-22
-- Dependencies: None (Foundation Layer)
-- ============================================================================

-- ============================================================================
-- SECTION 1: DATABASE CREATION
-- ============================================================================

-- Note: Database creation must be done outside of a transaction block
-- This section is typically executed by a separate connection or setup script

-- Create database if not exists (PostgreSQL doesn't support IF NOT EXISTS for CREATE DATABASE in standard SQL)
-- Use conditional logic via DO block or execute from shell script

-- For reference, the shell command would be:
-- psql -U ${POSTGRES_USER} -tc "SELECT 1 FROM pg_database WHERE datname = 'threat_intel_db'" | grep -q 1 || psql -U ${POSTGRES_USER} -c "CREATE DATABASE threat_intel_db ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8' TEMPLATE template0"

-- ============================================================================
-- SECTION 2: EXTENSION INSTALLATION
-- ============================================================================

-- Connect to threat_intel_db before running the following commands

BEGIN;

-- Enable trigram-based fuzzy text matching for domain similarity detection
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Enhanced GIN indexing for faster JSONB queries
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Enhanced GiST indexing for IP address range queries
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- Cryptographic functions for secure data handling
CREATE EXTENSION IF NOT EXISTS pgcrypto;

COMMIT;

-- ============================================================================
-- SECTION 3: CONNECTION TEST TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS connection_test (
    id SERIAL PRIMARY KEY,
    test_message TEXT NOT NULL DEFAULT 'Database connection successful',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add comment for documentation
COMMENT ON TABLE connection_test IS 'Health check table for database connectivity validation';
COMMENT ON COLUMN connection_test.id IS 'Auto-incrementing primary key';
COMMENT ON COLUMN connection_test.test_message IS 'Sample text field for testing';
COMMENT ON COLUMN connection_test.created_at IS 'Timestamp of record creation';

COMMIT;

-- ============================================================================
-- SECTION 4: SYSTEM METADATA TABLE
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS system_info (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add comment for documentation
COMMENT ON TABLE system_info IS 'System metadata for version tracking and configuration';
COMMENT ON COLUMN system_info.key IS 'Unique identifier for metadata entries';
COMMENT ON COLUMN system_info.value IS 'Stored value (text format, can contain JSON)';
COMMENT ON COLUMN system_info.updated_at IS 'Last update timestamp';

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_system_info_updated_at ON system_info(updated_at);

COMMIT;

-- ============================================================================
-- SECTION 5: INITIAL SEED DATA
-- ============================================================================

BEGIN;

-- Insert or update system information records
INSERT INTO system_info (key, value, updated_at) 
VALUES 
    ('db_version', '1.0.0', CURRENT_TIMESTAMP),
    ('schema_initialized', CURRENT_TIMESTAMP::TEXT, CURRENT_TIMESTAMP),
    ('last_migration', '001_initial_setup', CURRENT_TIMESTAMP),
    ('encoding', 'UTF8', CURRENT_TIMESTAMP),
    ('feature_flag_fuzzy_matching', 'true', CURRENT_TIMESTAMP),
    ('feature_flag_jsonb_indexing', 'true', CURRENT_TIMESTAMP),
    ('feature_flag_ip_range_search', 'true', CURRENT_TIMESTAMP),
    ('feature_flag_crypto', 'true', CURRENT_TIMESTAMP),
    ('system_status', 'initialized', CURRENT_TIMESTAMP)
ON CONFLICT (key) DO UPDATE 
    SET value = EXCLUDED.value,
        updated_at = CURRENT_TIMESTAMP;

-- Insert initial connection test record
INSERT INTO connection_test (test_message, created_at)
VALUES ('Initial setup completed successfully', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;

COMMIT;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Uncomment to verify setup (for manual testing)
-- SELECT * FROM system_info ORDER BY key;
-- SELECT * FROM connection_test ORDER BY created_at DESC LIMIT 1;
-- SELECT extname, extversion FROM pg_extension WHERE extname IN ('pg_trgm', 'btree_gin', 'btree_gist', 'pgcrypto');

-- ============================================================================
-- END OF INITIAL SETUP
-- ============================================================================
