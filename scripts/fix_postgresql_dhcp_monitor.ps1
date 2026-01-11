# ============================================================================
# Fix PostgreSQL for DHCP Monitor
# ============================================================================
# Purpose: Create database and user with proper permissions
# Date: 2026-01-04
# ============================================================================

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  SafeOps - PostgreSQL Setup for DHCP Monitor" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# Check if PostgreSQL is running
Write-Host "[1/7] Checking PostgreSQL status..." -ForegroundColor Yellow
$pgService = Get-Service -Name postgresql* -ErrorAction SilentlyContinue

if ($pgService -eq $null) {
    Write-Host "  ERROR: PostgreSQL service not found!" -ForegroundColor Red
    Write-Host "  Please install PostgreSQL first" -ForegroundColor Red
    exit 1
}

if ($pgService.Status -ne "Running") {
    Write-Host "  PostgreSQL is not running. Starting..." -ForegroundColor Yellow
    Start-Service $pgService.Name
    Start-Sleep -Seconds 2
}

Write-Host "  PostgreSQL is running" -ForegroundColor Green

# Create database
Write-Host ""
Write-Host "[2/7] Creating database 'safeops_network'..." -ForegroundColor Yellow

$createDB = @"
CREATE DATABASE safeops_network
WITH ENCODING 'UTF8'
     TEMPLATE template0;
"@

& psql -U postgres -c $createDB 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Database 'safeops_network' created successfully" -ForegroundColor Green
} else {
    Write-Host "  Database may already exist (this is OK)" -ForegroundColor Yellow
}

# Create user
Write-Host ""
Write-Host "[3/7] Creating user 'safeops_admin'..." -ForegroundColor Yellow

$createUser = @"
CREATE USER safeops_admin WITH PASSWORD 'safeops123';
"@

& psql -U postgres -c $createUser 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  User 'safeops_admin' created successfully" -ForegroundColor Green
} else {
    Write-Host "  User may already exist (this is OK)" -ForegroundColor Yellow
}

# Grant database privileges
Write-Host ""
Write-Host "[4/7] Granting database privileges..." -ForegroundColor Yellow

$grantDB = @"
GRANT ALL PRIVILEGES ON DATABASE safeops_network TO safeops_admin;
"@

& psql -U postgres -c $grantDB
Write-Host "  Database privileges granted" -ForegroundColor Green

# Fix schema permissions (THIS IS THE CRITICAL PART!)
Write-Host ""
Write-Host "[5/7] Fixing schema permissions (CRITICAL)..." -ForegroundColor Yellow

$fixSchema = @"
GRANT ALL ON SCHEMA public TO safeops_admin;
ALTER SCHEMA public OWNER TO safeops_admin;
GRANT CREATE ON SCHEMA public TO safeops_admin;
"@

& psql -U postgres -d safeops_network -c $fixSchema
Write-Host "  Schema permissions fixed!" -ForegroundColor Green

# Grant default privileges for future tables
Write-Host ""
Write-Host "[6/7] Setting default privileges..." -ForegroundColor Yellow

$defaultPrivs = @"
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO safeops_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO safeops_admin;
"@

& psql -U postgres -d safeops_network -c $defaultPrivs
Write-Host "  Default privileges set" -ForegroundColor Green

# Test connection
Write-Host ""
Write-Host "[7/7] Testing connection..." -ForegroundColor Yellow

$testConn = "SELECT 1 as test;"
$result = & psql -U safeops_admin -d safeops_network -c $testConn -t 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Connection test successful!" -ForegroundColor Green
} else {
    Write-Host "  Connection test failed!" -ForegroundColor Red
    Write-Host "  Error: $result" -ForegroundColor Red
    exit 1
}

# Summary
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  PostgreSQL Setup Complete!" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Database Configuration:" -ForegroundColor White
Write-Host "  Database: safeops_network" -ForegroundColor Gray
Write-Host "  User:     safeops_admin" -ForegroundColor Gray
Write-Host "  Password: safeops123" -ForegroundColor Gray
Write-Host "  Host:     localhost" -ForegroundColor Gray
Write-Host "  Port:     5432" -ForegroundColor Gray
Write-Host ""
Write-Host "Connection String:" -ForegroundColor White
Write-Host "  host=localhost port=5432 user=safeops_admin password=safeops123 dbname=safeops_network sslmode=disable" -ForegroundColor Cyan
Write-Host ""
Write-Host "Now you can start DHCP Monitor:" -ForegroundColor Yellow
Write-Host "  cd D:\SafeOpsFV2\bin" -ForegroundColor Gray
Write-Host "  .\dhcp_monitor.exe" -ForegroundColor Gray
Write-Host ""
