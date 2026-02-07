# ============================================================================
# SafeOps v2.0 - Complete Database Setup Script
# ============================================================================
# Purpose: One-script database setup for fresh system installs
# Creates databases, users, schemas, seeds, views, and applies all
# schema patches required by the threat_intel pipeline binary.
#
# Usage:
#   .\setup_database.ps1
#   .\setup_database.ps1 -PostgresPassword "yourpass" -PsqlPath "C:\path\to\psql.exe"
#
# What this script does:
#   1. Creates databases (threat_intel_db, safeops_network, safeops)
#   2. Creates app users (safeops, threat_intel_app, dns_server, dhcp_server)
#   3. Runs all schema SQL files from database\schemas\
#   4. Runs seed data (feed sources, threat categories)
#   5. Applies schema patches (column types, constraints, missing tables)
#   6. Creates views and helper functions
#   7. Grants table-level permissions to all app users
# ============================================================================

param(
    [string]$PostgresPassword = "admin",
    [string]$PsqlPath = ""
)

$ErrorActionPreference = "Continue"

# ============================================================================
# FIND PSQL
# ============================================================================

function Find-Psql {
    param([string]$UserPath)

    if ($UserPath -and (Test-Path $UserPath)) { return $UserPath }

    $searchPaths = @(
        "C:\Program Files\PostgreSQL\16\bin\psql.exe",
        "C:\Program Files\PostgreSQL\15\bin\psql.exe",
        "C:\Program Files\PostgreSQL\17\bin\psql.exe",
        "D:\Program Files\PostgreSQL\16\bin\psql.exe",
        "D:\Program\PostgreSQL\bin\psql.exe"
    )

    foreach ($p in $searchPaths) {
        if (Test-Path $p) { return $p }
    }

    # Try PATH
    $inPath = Get-Command psql -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    return $null
}

$PSQL = Find-Psql -UserPath $PsqlPath
if (-not $PSQL) {
    Write-Host "[ERROR] psql.exe not found. Pass -PsqlPath parameter." -ForegroundColor Red
    exit 1
}

$env:PGPASSWORD = $PostgresPassword
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SafeOps Database Setup (Complete)     " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  psql: $PSQL" -ForegroundColor DarkGray
Write-Host "  user: postgres" -ForegroundColor DarkGray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Helper: run SQL against a database
function Run-Sql {
    param(
        [string]$Database,
        [string]$Sql,
        [string]$Label = "",
        [switch]$SuppressErrors
    )
    if ($Label) { Write-Host "    $Label" -ForegroundColor DarkGray -NoNewline }

    $result = echo $Sql | & $PSQL -U postgres -h localhost -d $Database 2>&1
    $exitCode = $LASTEXITCODE

    if ($Label) {
        if ($exitCode -eq 0 -and ($result -notmatch "ERROR")) {
            Write-Host " OK" -ForegroundColor Green
        } elseif ($SuppressErrors) {
            Write-Host " (skipped)" -ForegroundColor DarkYellow
        } else {
            Write-Host " WARN" -ForegroundColor Yellow
        }
    }
    return $result
}

function Run-SqlFile {
    param(
        [string]$Database,
        [string]$FilePath,
        [string]$Label = ""
    )
    if ($Label) { Write-Host "    $Label" -ForegroundColor DarkGray -NoNewline }

    $result = & $PSQL -U postgres -h localhost -d $Database -f $FilePath 2>&1
    $exitCode = $LASTEXITCODE

    if ($Label) {
        $errors = $result | Select-String "ERROR" | Where-Object { $_ -notmatch "already exists|does not exist, skipping" }
        if ($errors) {
            Write-Host " WARN ($($errors.Count) errors)" -ForegroundColor Yellow
        } else {
            Write-Host " OK" -ForegroundColor Green
        }
    }
    return $result
}

# ============================================================================
# STEP 1: CREATE DATABASES
# ============================================================================

Write-Host "[1/7] Creating databases..." -ForegroundColor Cyan

$databases = @("threat_intel_db", "safeops_network", "safeops")
foreach ($db in $databases) {
    $exists = echo "SELECT 1 FROM pg_database WHERE datname = '$db';" | & $PSQL -U postgres -h localhost -t 2>&1
    if ($exists -match "1") {
        Write-Host "  [EXISTS] $db" -ForegroundColor DarkGreen
    } else {
        echo "CREATE DATABASE $db OWNER postgres;" | & $PSQL -U postgres -h localhost 2>&1 | Out-Null
        Write-Host "  [CREATED] $db" -ForegroundColor Green
    }
}

# ============================================================================
# STEP 2: CREATE USERS
# ============================================================================

Write-Host ""
Write-Host "[2/7] Creating database users..." -ForegroundColor Cyan

$users = @("safeops", "threat_intel_app", "dns_server", "dhcp_server")
foreach ($user in $users) {
    $exists = echo "SELECT 1 FROM pg_roles WHERE rolname = '$user';" | & $PSQL -U postgres -h localhost -t 2>&1
    if ($exists -match "1") {
        Write-Host "  [EXISTS] $user" -ForegroundColor DarkGreen
    } else {
        echo "CREATE USER $user WITH PASSWORD '$PostgresPassword';" | & $PSQL -U postgres -h localhost 2>&1 | Out-Null
        Write-Host "  [CREATED] $user" -ForegroundColor Green
    }
}

# Grant database-level access
foreach ($db in $databases) {
    foreach ($user in $users) {
        echo "GRANT ALL PRIVILEGES ON DATABASE $db TO $user;" | & $PSQL -U postgres -h localhost 2>&1 | Out-Null
    }
}
Write-Host "  [OK] Database-level grants applied" -ForegroundColor Green

# ============================================================================
# STEP 3: RUN SCHEMA SQL FILES
# ============================================================================

Write-Host ""
Write-Host "[3/7] Running schema migrations..." -ForegroundColor Cyan

$schemaDir = Join-Path $ScriptRoot "schemas"
if (Test-Path $schemaDir) {
    $schemas = Get-ChildItem "$schemaDir\*.sql" | Sort-Object Name
    foreach ($schema in $schemas) {
        # Route schemas to correct database
        $targetDB = "threat_intel_db"
        if ($schema.Name -match "013_dhcp|020_nic") {
            $targetDB = "safeops_network"
        }
        elseif ($schema.Name -match "022_step_ca") {
            $targetDB = "safeops_network"
        }

        Run-SqlFile -Database $targetDB -FilePath $schema.FullName -Label "$($schema.Name) -> $targetDB"
    }
} else {
    Write-Host "  [!] Schema directory not found: $schemaDir" -ForegroundColor Yellow
}

# ============================================================================
# STEP 4: RUN SEED DATA
# ============================================================================

Write-Host ""
Write-Host "[4/7] Running seed data..." -ForegroundColor Cyan

$seedDir = Join-Path $ScriptRoot "seeds"
if (Test-Path $seedDir) {
    # seed files need patches applied first, so we apply them inline
    $seedFiles = Get-ChildItem "$seedDir\*.sql" | Sort-Object Name
    foreach ($seed in $seedFiles) {
        Run-SqlFile -Database "threat_intel_db" -FilePath $seed.FullName -Label "$($seed.Name)"
    }
} else {
    Write-Host "  [SKIP] No seeds directory" -ForegroundColor DarkYellow
}

# Run step-CA script if exists
$stepCaScript = Join-Path $ScriptRoot "scripts\insert_stepca_password.sql"
if (Test-Path $stepCaScript) {
    Run-SqlFile -Database "safeops_network" -FilePath $stepCaScript -Label "insert_stepca_password.sql -> safeops_network"
}

# ============================================================================
# STEP 5: APPLY SCHEMA PATCHES (all fixes from schema drift)
# ============================================================================

Write-Host ""
Write-Host "[5/7] Applying schema patches for threat_intel pipeline..." -ForegroundColor Cyan

$patchSQL = @"

-- =====================================================================
-- PATCH: threat_feeds - add missing columns for seed data
-- =====================================================================
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS parser_config JSONB;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS retry_config JSONB;
ALTER TABLE threat_feeds ADD COLUMN IF NOT EXISTS authentication_required BOOLEAN DEFAULT FALSE;

-- Fix threat_feeds priority constraint (seeds use 0-100 scale)
DO `$`$
BEGIN
    ALTER TABLE threat_feeds DROP CONSTRAINT IF EXISTS threat_feeds_priority_check;
    ALTER TABLE threat_feeds ADD CONSTRAINT threat_feeds_priority_check CHECK (priority >= 0 AND priority <= 100);
EXCEPTION WHEN OTHERS THEN NULL;
END `$`$;

-- Fix threat_feeds feed_type constraint (add all types used by feeds)
DO `$`$
BEGIN
    ALTER TABLE threat_feeds DROP CONSTRAINT IF EXISTS threat_feeds_feed_type_check;
    ALTER TABLE threat_feeds ADD CONSTRAINT threat_feeds_feed_type_check
        CHECK (feed_type IN ('ip_blacklist', 'domain_blacklist', 'hash_list', 'mixed', 'url_list',
            'vpn', 'hash_malware', 'anonymization', 'geolocation', 'exploit'));
EXCEPTION WHEN OTHERS THEN NULL;
END `$`$;

-- =====================================================================
-- PATCH: system_metadata table (required by seeds)
-- =====================================================================
CREATE TABLE IF NOT EXISTS system_metadata (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT,
    description TEXT,
    category VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================================
-- PATCH: ip_blacklist - add columns expected by Go binary
-- =====================================================================
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS status VARCHAR(20);
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS reputation_score INTEGER;
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS threat_category VARCHAR(100);
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS malware_family VARCHAR(255);
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS false_positive_count INTEGER;
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS tags JSONB;
ALTER TABLE ip_blacklist ADD COLUMN IF NOT EXISTS last_updated TIMESTAMP WITH TIME ZONE;

-- Relax NOT NULL constraints that block bulk inserts
DO `$`$
BEGIN
    ALTER TABLE ip_blacklist ALTER COLUMN threat_score DROP NOT NULL;
    ALTER TABLE ip_blacklist ALTER COLUMN abuse_type DROP NOT NULL;
    ALTER TABLE ip_blacklist ALTER COLUMN confidence DROP NOT NULL;
EXCEPTION WHEN OTHERS THEN NULL;
END `$`$;

-- Set defaults
ALTER TABLE ip_blacklist ALTER COLUMN threat_score SET DEFAULT 0;
ALTER TABLE ip_blacklist ALTER COLUMN confidence SET DEFAULT 0;
ALTER TABLE ip_blacklist ALTER COLUMN is_malicious SET DEFAULT TRUE;

-- Widen abuse_type constraint (Go binary uses 20 categories)
DO `$`$
BEGIN
    ALTER TABLE ip_blacklist DROP CONSTRAINT IF EXISTS ip_blacklist_abuse_type_check;
    ALTER TABLE ip_blacklist ADD CONSTRAINT ip_blacklist_abuse_type_check
        CHECK (abuse_type IN ('spam', 'malware', 'c2', 'bruteforce', 'botnet', 'scanner',
            'unknown', 'phishing', 'ransomware', 'dridex', 'emotet', 'trickbot',
            'exploitation', 'apt', 'ddos', 'tor', 'vpn', 'proxy', 'abuse', 'suspicious'));
EXCEPTION WHEN OTHERS THEN NULL;
END `$`$;

-- =====================================================================
-- PATCH: ip_anonymization - rebuild with all 27 columns expected by Go
-- =====================================================================
-- Only rebuild if column count is wrong
DO `$`$
DECLARE col_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO col_count FROM information_schema.columns
    WHERE table_name = 'ip_anonymization' AND table_schema = 'public';

    IF col_count < 27 THEN
        DROP TABLE IF EXISTS ip_anonymization CASCADE;
        CREATE TABLE ip_anonymization (
            id BIGSERIAL PRIMARY KEY,
            ip_address INET NOT NULL,
            is_vpn BOOLEAN DEFAULT FALSE,
            is_tor BOOLEAN DEFAULT FALSE,
            is_proxy BOOLEAN DEFAULT FALSE,
            is_datacenter BOOLEAN DEFAULT FALSE,
            is_relay BOOLEAN DEFAULT FALSE,
            is_hosting BOOLEAN DEFAULT FALSE,
            provider_name VARCHAR(255),
            service_type VARCHAR(50),
            anonymity_level VARCHAR(50),
            tor_exit_node BOOLEAN DEFAULT FALSE,
            tor_node_name VARCHAR(255),
            proxy_type VARCHAR(50),
            proxy_port INTEGER,
            datacenter_name VARCHAR(255),
            hosting_provider VARCHAR(255),
            country_code VARCHAR(2),
            city VARCHAR(100),
            risk_score INTEGER,
            abuse_history BOOLEAN DEFAULT FALSE,
            is_active BOOLEAN DEFAULT TRUE,
            sources JSONB,
            tags JSONB,
            first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_ip_anon_ip ON ip_anonymization(ip_address);
        CREATE INDEX IF NOT EXISTS idx_ip_anon_vpn ON ip_anonymization(is_vpn) WHERE is_vpn = TRUE;
        CREATE INDEX IF NOT EXISTS idx_ip_anon_tor ON ip_anonymization(is_tor) WHERE is_tor = TRUE;
        CREATE INDEX IF NOT EXISTS idx_ip_anon_proxy ON ip_anonymization(is_proxy) WHERE is_proxy = TRUE;
        CREATE INDEX IF NOT EXISTS idx_ip_anon_active ON ip_anonymization(is_active);
        CREATE INDEX IF NOT EXISTS idx_ip_anon_datacenter ON ip_anonymization(is_datacenter) WHERE is_datacenter = TRUE;
        CREATE INDEX IF NOT EXISTS idx_ip_anon_sources ON ip_anonymization USING GIN(sources);
    END IF;
END `$`$;

-- =====================================================================
-- PATCH: ip_geolocation - add ip_end, widen country_code and asn
-- =====================================================================
ALTER TABLE ip_geolocation ADD COLUMN IF NOT EXISTS ip_end INET;

-- Widen country_code from VARCHAR(2) to VARCHAR(10) for IPtoASN data
-- Must drop dependent views first
DO `$`$
DECLARE
    cc_len INTEGER;
BEGIN
    SELECT character_maximum_length INTO cc_len FROM information_schema.columns
    WHERE table_name = 'ip_geolocation' AND column_name = 'country_code';

    IF cc_len IS NOT NULL AND cc_len < 10 THEN
        DROP VIEW IF EXISTS country_ip_distribution CASCADE;
        DROP VIEW IF EXISTS top_asns CASCADE;
        DROP VIEW IF EXISTS mobile_networks CASCADE;
        DROP VIEW IF EXISTS datacenter_ips CASCADE;
        DROP VIEW IF EXISTS threat_summary_stats CASCADE;
        ALTER TABLE ip_geolocation ALTER COLUMN country_code TYPE VARCHAR(10);
    END IF;
END `$`$;

-- Widen asn from INTEGER to BIGINT (ASN values can exceed 2^31)
DO `$`$
DECLARE
    asn_type TEXT;
BEGIN
    SELECT data_type INTO asn_type FROM information_schema.columns
    WHERE table_name = 'ip_geolocation' AND column_name = 'asn';

    IF asn_type = 'integer' THEN
        DROP VIEW IF EXISTS country_ip_distribution CASCADE;
        DROP VIEW IF EXISTS top_asns CASCADE;
        DROP VIEW IF EXISTS mobile_networks CASCADE;
        DROP VIEW IF EXISTS datacenter_ips CASCADE;
        DROP VIEW IF EXISTS threat_summary_stats CASCADE;
        ALTER TABLE ip_geolocation ALTER COLUMN asn TYPE BIGINT;
    END IF;
END `$`$;

-- Also fix asn_info table
DO `$`$
DECLARE
    asn_type TEXT;
BEGIN
    SELECT data_type INTO asn_type FROM information_schema.columns
    WHERE table_name = 'asn_info' AND column_name = 'asn';

    IF asn_type = 'integer' THEN
        ALTER TABLE asn_info ALTER COLUMN asn TYPE BIGINT;
    END IF;
EXCEPTION WHEN OTHERS THEN NULL;
END `$`$;

-- Drop UNIQUE constraint on ip_address that blocks range inserts
DO `$`$
BEGIN
    ALTER TABLE ip_geolocation DROP CONSTRAINT IF EXISTS ip_geolocation_ip_address_key;
EXCEPTION WHEN OTHERS THEN NULL;
END `$`$;

-- =====================================================================
-- PATCH: domains - add columns, widen category constraint
-- =====================================================================
ALTER TABLE domains ADD COLUMN IF NOT EXISTS subcategory VARCHAR(100);
ALTER TABLE domains ADD COLUMN IF NOT EXISTS tags JSONB;

-- Relax NOT NULL if needed
DO `$`$
BEGIN
    ALTER TABLE domains ALTER COLUMN threat_score SET DEFAULT 0;
EXCEPTION WHEN OTHERS THEN NULL;
END `$`$;

-- Widen category constraint (Go binary uses 17 categories)
DO `$`$
BEGIN
    ALTER TABLE domains DROP CONSTRAINT IF EXISTS domains_category_check;
    ALTER TABLE domains ADD CONSTRAINT domains_category_check
        CHECK (category IN ('phishing', 'malware', 'c2', 'spam', 'exploit_kit', 'scam',
            'ransomware', 'unknown', 'adware', 'botnet', 'cryptomining', 'dga',
            'parking', 'suspicious', 'tor', 'vpn', 'proxy'));
EXCEPTION WHEN OTHERS THEN NULL;
END `$`$;

-- =====================================================================
-- PATCH: hashes table (Go binary expects "hashes" not "file_hashes")
-- =====================================================================
CREATE TABLE IF NOT EXISTS hashes (
    id BIGSERIAL PRIMARY KEY,
    md5 VARCHAR(128),
    sha1 VARCHAR(128),
    sha256 VARCHAR(64),
    sha512 VARCHAR(128),
    ssdeep TEXT,
    is_malicious BOOLEAN DEFAULT TRUE,
    threat_score INTEGER DEFAULT 0,
    file_name VARCHAR(500),
    file_type VARCHAR(100),
    file_size BIGINT,
    mime_type VARCHAR(255),
    malware_family VARCHAR(255),
    malware_type VARCHAR(100),
    av_detections INTEGER,
    total_av_engines INTEGER,
    av_detection_rate NUMERIC(5,2),
    sandbox_verdict VARCHAR(50),
    virustotal_link VARCHAR(500),
    sources JSONB,
    tags JSONB,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hashes_md5 ON hashes(md5);
CREATE INDEX IF NOT EXISTS idx_hashes_sha1 ON hashes(sha1);
CREATE INDEX IF NOT EXISTS idx_hashes_sha256 ON hashes(sha256);
CREATE INDEX IF NOT EXISTS idx_hashes_malware ON hashes(malware_family);
CREATE INDEX IF NOT EXISTS idx_hashes_sources ON hashes USING GIN(sources);

"@

Run-Sql -Database "threat_intel_db" -Sql $patchSQL -Label "Schema patches"

# ============================================================================
# STEP 6: CREATE / RECREATE VIEWS
# ============================================================================

Write-Host ""
Write-Host "[6/7] Creating views and functions..." -ForegroundColor Cyan

$viewsSQL = @"

-- =====================================================================
-- Geolocation views
-- =====================================================================
CREATE OR REPLACE VIEW country_ip_distribution AS
SELECT country_code, country_name, COUNT(*) as ip_count,
    COUNT(DISTINCT asn) as unique_asns, AVG(confidence)::DECIMAL(5,2) as avg_confidence
FROM ip_geolocation WHERE country_code IS NOT NULL
GROUP BY country_code, country_name ORDER BY ip_count DESC;

CREATE OR REPLACE VIEW top_asns AS
SELECT g.asn, g.asn_org, a.reputation_score, COUNT(g.ip_address) as ip_count,
    COUNT(DISTINCT g.country_code) as countries
FROM ip_geolocation g LEFT JOIN asn_info a ON g.asn = a.asn
WHERE g.asn IS NOT NULL GROUP BY g.asn, g.asn_org, a.reputation_score
ORDER BY ip_count DESC LIMIT 100;

CREATE OR REPLACE VIEW mobile_networks AS
SELECT country_code, isp, COUNT(*) as ip_count
FROM ip_geolocation WHERE is_mobile = TRUE
GROUP BY country_code, isp ORDER BY country_code, ip_count DESC;

CREATE OR REPLACE VIEW datacenter_ips AS
SELECT asn_org, country_code, COUNT(*) as ip_count
FROM ip_geolocation WHERE is_hosting = TRUE
GROUP BY asn_org, country_code ORDER BY ip_count DESC;

-- =====================================================================
-- Dashboard stats view (with corrected column references)
-- =====================================================================
DROP VIEW IF EXISTS threat_summary_stats CASCADE;

CREATE OR REPLACE VIEW threat_summary_stats AS
WITH overall_counts AS (
    SELECT 'overall' AS metric_type,
        (SELECT COUNT(*) FROM ip_blacklist WHERE is_malicious = TRUE) AS total_malicious_ips,
        (SELECT COUNT(*) FROM domains WHERE is_malicious = TRUE AND status = 'active') AS total_malicious_domains,
        (SELECT COUNT(*) FROM file_hashes WHERE is_malicious = TRUE AND status = 'active') AS total_malware_hashes,
        (SELECT COUNT(*) FROM vpn_ips WHERE is_active = TRUE) AS total_vpn_ips,
        (SELECT COUNT(*) FROM vpn_ips WHERE service_type = 'tor_exit' AND is_active = TRUE) AS total_tor_nodes,
        (SELECT COUNT(*) FROM threat_feeds WHERE is_active = TRUE) AS total_active_feeds,
        (SELECT COUNT(*) FROM threat_feeds) AS total_feeds,
        (SELECT MAX(last_successful_fetch) FROM threat_feeds) AS last_feed_update
),
total_active_threats AS (
    SELECT (SELECT total_malicious_ips FROM overall_counts) +
        (SELECT total_malicious_domains FROM overall_counts) +
        (SELECT total_malware_hashes FROM overall_counts) AS total_active_threats
),
ip_by_category AS (
    SELECT 'ip_abuse' AS threat_type, abuse_type AS category_name, COUNT(*) AS category_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score, MAX(threat_score) AS highest_threat_score,
        COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '24 hours') AS new_24h
    FROM ip_blacklist WHERE is_malicious = TRUE GROUP BY abuse_type
),
domain_by_category AS (
    SELECT 'domain' AS threat_type, category AS category_name, COUNT(*) AS category_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score, MAX(threat_score) AS highest_threat_score,
        COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '24 hours') AS new_24h
    FROM domains WHERE is_malicious = TRUE AND status = 'active' GROUP BY category
),
malware_by_type AS (
    SELECT 'malware' AS threat_type, malware_type AS category_name, COUNT(*) AS category_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score, MAX(threat_score) AS highest_threat_score,
        COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '24 hours') AS new_24h
    FROM file_hashes WHERE is_malicious = TRUE AND status = 'active' AND malware_type IS NOT NULL GROUP BY malware_type
),
category_summary AS (
    SELECT * FROM ip_by_category UNION ALL SELECT * FROM domain_by_category UNION ALL SELECT * FROM malware_by_type
),
threats_by_country AS (
    SELECT geo.country_code, geo.country_name, COUNT(DISTINCT ip.ip_address) AS threat_count,
        ROUND(AVG(ip.threat_score), 2) AS avg_threat_score,
        MODE() WITHIN GROUP (ORDER BY ip.abuse_type) AS top_abuse_type,
        COUNT(*) FILTER (WHERE ip.first_seen >= NOW() - INTERVAL '24 hours') AS new_24h
    FROM ip_blacklist ip JOIN ip_geolocation geo ON ip.ip_address = geo.ip_address
    WHERE ip.is_malicious = TRUE GROUP BY geo.country_code, geo.country_name ORDER BY threat_count DESC LIMIT 50
),
ip_trends_24h AS (
    SELECT date_trunc('hour', first_seen) AS hour_bucket, 'ip' AS threat_type, COUNT(*) AS new_threats_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score
    FROM ip_blacklist WHERE first_seen >= NOW() - INTERVAL '24 hours' GROUP BY date_trunc('hour', first_seen)
),
domain_trends_24h AS (
    SELECT date_trunc('hour', first_seen) AS hour_bucket, 'domain' AS threat_type, COUNT(*) AS new_threats_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score
    FROM domains WHERE first_seen >= NOW() - INTERVAL '24 hours' AND is_malicious = TRUE GROUP BY date_trunc('hour', first_seen)
),
hash_trends_24h AS (
    SELECT date_trunc('hour', first_seen) AS hour_bucket, 'hash' AS threat_type, COUNT(*) AS new_threats_count,
        ROUND(AVG(threat_score), 2) AS avg_threat_score
    FROM file_hashes WHERE first_seen >= NOW() - INTERVAL '24 hours' AND is_malicious = TRUE GROUP BY date_trunc('hour', first_seen)
),
hourly_trends AS (
    SELECT * FROM ip_trends_24h UNION ALL SELECT * FROM domain_trends_24h UNION ALL SELECT * FROM hash_trends_24h
    ORDER BY hour_bucket DESC, threat_type
),
threats_by_asn AS (
    SELECT geo.asn, geo.asn_org, COUNT(DISTINCT ip.ip_address) AS threat_count,
        ROUND(AVG(ip.threat_score), 2) AS avg_threat_score,
        ARRAY_AGG(DISTINCT geo.country_code) AS country_codes,
        MODE() WITHIN GROUP (ORDER BY ip.abuse_type) AS top_abuse_type
    FROM ip_blacklist ip JOIN ip_geolocation geo ON ip.ip_address = geo.ip_address
    WHERE ip.is_malicious = TRUE AND geo.asn IS NOT NULL
    GROUP BY geo.asn, geo.asn_org ORDER BY threat_count DESC LIMIT 25
),
feed_performance AS (
    SELECT COUNT(*) AS total_feeds,
        COUNT(*) FILTER (WHERE is_active = TRUE) AS active_feeds_count,
        COUNT(*) FILTER (WHERE is_active = FALSE) AS inactive_feeds_count,
        COUNT(*) FILTER (WHERE last_fetch_status = 'failed') AS failing_feeds_count,
        COUNT(*) FILTER (WHERE last_fetch_status = 'success') AS successful_feeds_count,
        MAX(last_successful_fetch) AS last_successful_update,
        MIN(last_successful_fetch) AS oldest_successful_update,
        ROUND(AVG(total_records_imported), 2) AS avg_records_per_feed,
        SUM(total_records_imported) AS total_records_imported,
        ROUND(AVG(reliability_score), 2) AS avg_reliability_score
    FROM threat_feeds
),
database_health AS (
    SELECT pg_size_pretty(pg_database_size(current_database())) AS database_size,
        pg_database_size(current_database()) AS database_size_bytes,
        ((SELECT COUNT(*) FROM ip_blacklist) + (SELECT COUNT(*) FROM domains) +
         (SELECT COUNT(*) FROM file_hashes) + (SELECT COUNT(*) FROM vpn_ips)) AS total_records,
        (SELECT MIN(first_seen) FROM (
            SELECT MIN(first_seen) AS first_seen FROM ip_blacklist UNION ALL
            SELECT MIN(first_seen) FROM domains UNION ALL
            SELECT MIN(first_seen) FROM file_hashes) AS min_dates) AS oldest_threat,
        (SELECT MAX(last_seen) FROM (
            SELECT MAX(last_seen) AS last_seen FROM ip_blacklist UNION ALL
            SELECT MAX(last_seen) FROM domains UNION ALL
            SELECT MAX(last_seen) FROM file_hashes) AS max_dates) AS newest_threat,
        NOW() AS stats_generated_at
),
severity_distribution AS (
    SELECT CASE WHEN threat_score >= 9 THEN 'critical' WHEN threat_score >= 7 THEN 'high'
        WHEN threat_score >= 5 THEN 'medium' WHEN threat_score >= 3 THEN 'low' ELSE 'informational' END AS severity_level,
        COUNT(*) AS count
    FROM (SELECT threat_score FROM ip_blacklist WHERE is_malicious = TRUE UNION ALL
          SELECT threat_score FROM domains WHERE is_malicious = TRUE UNION ALL
          SELECT threat_score FROM file_hashes WHERE is_malicious = TRUE) AS all_threats
    GROUP BY severity_level
),
weekly_activity AS (
    SELECT 'last_7_days' AS period,
        (SELECT COUNT(*) FROM ip_blacklist WHERE first_seen >= NOW() - INTERVAL '7 days') AS new_ips,
        (SELECT COUNT(*) FROM domains WHERE first_seen >= NOW() - INTERVAL '7 days' AND is_malicious = TRUE) AS new_domains,
        (SELECT COUNT(*) FROM file_hashes WHERE first_seen >= NOW() - INTERVAL '7 days' AND is_malicious = TRUE) AS new_hashes,
        (SELECT COUNT(*) FROM ip_blacklist WHERE last_seen >= NOW() - INTERVAL '7 days') AS active_ips,
        (SELECT COUNT(*) FROM domains WHERE last_seen >= NOW() - INTERVAL '7 days' AND is_malicious = TRUE) AS active_domains
)
SELECT
    (SELECT total_malicious_ips FROM overall_counts) AS total_malicious_ips,
    (SELECT total_malicious_domains FROM overall_counts) AS total_malicious_domains,
    (SELECT total_malware_hashes FROM overall_counts) AS total_malware_hashes,
    (SELECT total_vpn_ips FROM overall_counts) AS total_vpn_ips,
    (SELECT total_tor_nodes FROM overall_counts) AS total_tor_nodes,
    (SELECT total_active_feeds FROM overall_counts) AS total_active_feeds,
    (SELECT total_feeds FROM overall_counts) AS total_feeds,
    (SELECT total_active_threats FROM total_active_threats) AS total_active_threats,
    (SELECT active_feeds_count FROM feed_performance) AS active_feeds_count,
    (SELECT failing_feeds_count FROM feed_performance) AS failing_feeds_count,
    (SELECT last_successful_update FROM feed_performance) AS last_feed_update,
    (SELECT avg_records_per_feed FROM feed_performance) AS avg_records_per_feed,
    (SELECT avg_reliability_score FROM feed_performance) AS avg_reliability_score,
    (SELECT database_size FROM database_health) AS database_size,
    (SELECT database_size_bytes FROM database_health) AS database_size_bytes,
    (SELECT total_records FROM database_health) AS total_records,
    (SELECT oldest_threat FROM database_health) AS oldest_threat,
    (SELECT newest_threat FROM database_health) AS newest_threat,
    (SELECT stats_generated_at FROM database_health) AS stats_generated_at,
    (SELECT new_ips FROM weekly_activity) AS new_ips_7d,
    (SELECT new_domains FROM weekly_activity) AS new_domains_7d,
    (SELECT new_hashes FROM weekly_activity) AS new_hashes_7d,
    (SELECT active_ips FROM weekly_activity) AS active_ips_7d,
    (SELECT active_domains FROM weekly_activity) AS active_domains_7d,
    (SELECT json_agg(row_to_json(c.*)) FROM category_summary c) AS threats_by_category,
    (SELECT json_agg(row_to_json(t.*)) FROM threats_by_country t) AS threats_by_country,
    (SELECT json_agg(row_to_json(h.*)) FROM hourly_trends h) AS hourly_trends_24h,
    (SELECT json_agg(row_to_json(a.*)) FROM threats_by_asn a) AS threats_by_asn,
    (SELECT json_agg(row_to_json(s.*)) FROM severity_distribution s) AS severity_distribution;

-- =====================================================================
-- Helper functions for dashboard API
-- =====================================================================
CREATE OR REPLACE FUNCTION get_threat_count_summary()
RETURNS TABLE(metric_name TEXT, metric_value BIGINT) AS `$`$
BEGIN
    RETURN QUERY
    SELECT 'malicious_ips'::TEXT, COUNT(*)::BIGINT FROM ip_blacklist WHERE is_malicious = TRUE
    UNION ALL SELECT 'malicious_domains'::TEXT, COUNT(*)::BIGINT FROM domains WHERE is_malicious = TRUE
    UNION ALL SELECT 'malware_hashes'::TEXT, COUNT(*)::BIGINT FROM file_hashes WHERE is_malicious = TRUE
    UNION ALL SELECT 'vpn_ips'::TEXT, COUNT(*)::BIGINT FROM vpn_ips WHERE is_active = TRUE
    UNION ALL SELECT 'active_feeds'::TEXT, COUNT(*)::BIGINT FROM threat_feeds WHERE is_active = TRUE;
END;
`$`$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_category_breakdown(p_threat_type TEXT)
RETURNS TABLE(category_name TEXT, count BIGINT, avg_score NUMERIC, max_score INTEGER) AS `$`$
BEGIN
    IF p_threat_type = 'ip' THEN
        RETURN QUERY SELECT abuse_type::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2), MAX(threat_score)
            FROM ip_blacklist WHERE is_malicious = TRUE GROUP BY abuse_type ORDER BY COUNT(*) DESC;
    ELSIF p_threat_type = 'domain' THEN
        RETURN QUERY SELECT category::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2), MAX(threat_score)
            FROM domains WHERE is_malicious = TRUE AND status = 'active' GROUP BY category ORDER BY COUNT(*) DESC;
    ELSIF p_threat_type = 'malware' THEN
        RETURN QUERY SELECT malware_type::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2), MAX(threat_score)
            FROM file_hashes WHERE is_malicious = TRUE AND status = 'active' AND malware_type IS NOT NULL
            GROUP BY malware_type ORDER BY COUNT(*) DESC;
    END IF;
END;
`$`$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_hourly_trends(p_hours INTEGER DEFAULT 24)
RETURNS TABLE(hour TIMESTAMP, threat_type TEXT, new_count BIGINT, avg_score NUMERIC) AS `$`$
BEGIN
    RETURN QUERY
    SELECT date_trunc('hour', first_seen)::TIMESTAMP, 'ip'::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2)
        FROM ip_blacklist WHERE first_seen >= NOW() - (p_hours || ' hours')::INTERVAL GROUP BY date_trunc('hour', first_seen)
    UNION ALL
    SELECT date_trunc('hour', first_seen)::TIMESTAMP, 'domain'::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2)
        FROM domains WHERE first_seen >= NOW() - (p_hours || ' hours')::INTERVAL AND is_malicious = TRUE GROUP BY date_trunc('hour', first_seen)
    UNION ALL
    SELECT date_trunc('hour', first_seen)::TIMESTAMP, 'hash'::TEXT, COUNT(*)::BIGINT, ROUND(AVG(threat_score), 2)
        FROM file_hashes WHERE first_seen >= NOW() - (p_hours || ' hours')::INTERVAL AND is_malicious = TRUE GROUP BY date_trunc('hour', first_seen)
    ORDER BY 1 DESC, 2;
END;
`$`$ LANGUAGE plpgsql;

"@

Run-Sql -Database "threat_intel_db" -Sql $viewsSQL -Label "Views and functions"

# ============================================================================
# STEP 7: GRANT TABLE-LEVEL PERMISSIONS
# ============================================================================

Write-Host ""
Write-Host "[7/7] Granting table-level permissions..." -ForegroundColor Cyan

$grantSQL = @"
-- Grant on all existing tables and sequences
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO safeops;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO threat_intel_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dhcp_server;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dns_server;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO safeops;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO threat_intel_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO dhcp_server;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO dns_server;

-- Ensure future tables/sequences also get permissions
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO safeops;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO threat_intel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO dhcp_server;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO dns_server;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO safeops;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO threat_intel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO dhcp_server;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO dns_server;
"@

# Apply grants to all databases
foreach ($db in $databases) {
    Run-Sql -Database $db -Sql $grantSQL -Label "Grants -> $db"
}

# ============================================================================
# VERIFICATION
# ============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Verification                         " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$verifySQL = @"
SELECT 'Tables' AS check_type, COUNT(*)::TEXT AS result
FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
UNION ALL
SELECT 'Views', COUNT(*)::TEXT
FROM information_schema.views WHERE table_schema = 'public'
UNION ALL
SELECT 'ip_geolocation.asn type', data_type
FROM information_schema.columns WHERE table_name = 'ip_geolocation' AND column_name = 'asn'
UNION ALL
SELECT 'ip_geolocation.country_code size', character_maximum_length::TEXT
FROM information_schema.columns WHERE table_name = 'ip_geolocation' AND column_name = 'country_code'
UNION ALL
SELECT 'hashes table exists', CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'hashes') THEN 'YES' ELSE 'NO' END
UNION ALL
SELECT 'ip_blacklist columns', COUNT(*)::TEXT
FROM information_schema.columns WHERE table_name = 'ip_blacklist'
UNION ALL
SELECT 'ip_anonymization columns', COUNT(*)::TEXT
FROM information_schema.columns WHERE table_name = 'ip_anonymization';
"@

$result = echo $verifySQL | & $PSQL -U postgres -h localhost -d threat_intel_db 2>&1
Write-Host $result

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Database Setup Complete!              " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  You can now run threat_intel.exe" -ForegroundColor White
Write-Host "  from bin\threat_intel\" -ForegroundColor White
Write-Host ""
