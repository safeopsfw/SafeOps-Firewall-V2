-- ============================================================================
-- Script: Insert Step-CA Master Password
-- ============================================================================
-- File: D:\SafeOpsFV2\database\scripts\insert_stepca_password.sql
-- Purpose: One-time insertion of Step-CA master password into secrets table
-- 
-- EXECUTION ORDER: Must run AFTER migration 022_step_ca.sql
-- 
-- Prerequisites:
--   - pgcrypto extension enabled
--   - secrets table exists (from migration 022)
--   - Encryption key set via: SET SESSION my.encryption_key = 'your-key';
--
-- WARNING: Execute via PowerShell wrapper, NOT manually!
-- SECURITY: Never commit this file with actual password values!
-- ============================================================================

-- ============================================================================
-- SECTION 1: Encryption Key Validation
-- ============================================================================
-- Fail fast if encryption key is not set (prevents silent encryption failure)

DO $$
BEGIN
    IF current_setting('my.encryption_key', true) IS NULL OR 
       current_setting('my.encryption_key', true) = '' THEN
        RAISE EXCEPTION 'Encryption key not set. Use: SET SESSION my.encryption_key = ''your-key'';';
    END IF;
    RAISE NOTICE 'Encryption key validated successfully';
END $$;

-- ============================================================================
-- SECTION 2: Table Existence Check
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'secrets') THEN
        RAISE EXCEPTION 'secrets table does not exist. Run migration 022_step_ca.sql first!';
    END IF;
    RAISE NOTICE 'secrets table exists';
END $$;

-- ============================================================================
-- SECTION 3: Duplicate Entry Check
-- ============================================================================

DO $$
DECLARE
    existing_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO existing_count FROM secrets WHERE service_name = 'step-ca-master';
    IF existing_count > 0 THEN
        RAISE NOTICE 'Password already exists for step-ca-master, skipping insertion';
    ELSE
        RAISE NOTICE 'No existing entry found, proceeding with insertion';
    END IF;
END $$;

-- ============================================================================
-- SECTION 4: Password Insertion
-- ============================================================================
-- Note: :STEP_CA_PASSWORD is a psql variable, passed via -v flag
-- Example: psql -v STEP_CA_PASSWORD="'MyPassword123'" -f insert_stepca_password.sql

INSERT INTO secrets (
    secret_id,
    service_name,
    secret_value_encrypted,
    encryption_method,
    description,
    created_by,
    created_at
) VALUES (
    gen_random_uuid(),
    'step-ca-master',
    pgp_sym_encrypt(:STEP_CA_PASSWORD, current_setting('my.encryption_key')),
    'pgp_sym_aes256',
    'Step-CA master password for Root CA private key encryption (10-year validity)',
    'step-ca-init-script',
    NOW()
)
ON CONFLICT (service_name) DO NOTHING;

-- ============================================================================
-- SECTION 5: Verification Query
-- ============================================================================
-- Confirm successful insertion

SELECT 
    secret_id,
    service_name,
    encryption_method,
    description,
    created_by,
    created_at
FROM secrets 
WHERE service_name = 'step-ca-master';

-- Expected output: One row with the step-ca-master entry

-- ============================================================================
-- SECTION 6: Decryption Test (COMMENTED - SECURITY SENSITIVE)
-- ============================================================================
-- WARNING: Only uncomment during debugging, then re-comment immediately!
-- This will expose plaintext password in query results/logs!

-- TEST DECRYPTION (uncomment to verify, then re-comment immediately)
-- SELECT pgp_sym_decrypt(secret_value_encrypted, current_setting('my.encryption_key'))::text AS decrypted_password
-- FROM secrets WHERE service_name = 'step-ca-master';
-- Expected output: Your actual Step-CA password in plaintext

-- ============================================================================
-- SECTION 7: Cleanup Instructions
-- ============================================================================
-- After running this script:
--
-- 1. Clear encryption key from session:
--    RESET my.encryption_key;
--
-- 2. Delete any temporary password files:
--    Remove-Item "$env:TEMP\stepca-*.txt" -Force
--
-- 3. Clear PowerShell variables:
--    $password = $null
--    $encryptionKey = $null

-- ============================================================================
-- SECTION 8: Rollback/Delete Statement
-- ============================================================================
-- Use this ONLY if you need to re-initialize Step-CA with a new password

-- ROLLBACK: Delete Step-CA password entry
-- DELETE FROM secrets WHERE service_name = 'step-ca-master';

-- ============================================================================
-- SECTION 9: Usage Examples
-- ============================================================================
-- PowerShell execution wrapper example:
--
-- $password = "YourSecurePassword123"
-- $encryptionKey = "YourDatabaseEncryptionKey"
-- $escapedPassword = $password.Replace("'", "''")
-- 
-- $env:PGPASSWORD = "your_db_password"
-- & "C:\Program Files\PostgreSQL\18\bin\psql.exe" `
--     -U safeops_admin `
--     -d safeops_network `
--     -v STEP_CA_PASSWORD="'$escapedPassword'" `
--     -c "SET SESSION my.encryption_key = '$encryptionKey';" `
--     -f "D:\SafeOpsFV2\database\scripts\insert_stepca_password.sql"

-- ============================================================================
-- END OF SCRIPT
-- ============================================================================
