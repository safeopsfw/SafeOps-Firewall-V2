# ============================================================================
# SafeOps Threat Intelligence Database - Initialization Script
# File: init_database.ps1
# Purpose: Master database setup script for Windows/PowerShell
# ============================================================================

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$DatabaseName = "safeops_threat_intel",
    [string]$DatabaseUser = "safeops_admin",
    [string]$DatabasePassword,
    [string]$DatabaseHost = "localhost",
    [int]$DatabasePort = 5432,
    [string]$PostgresSuperUser = "postgres",
    [string]$LogFile = "database_init.log",
    [switch]$SkipTestData,
    [switch]$DropExisting,
    [switch]$Quiet,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartTime = Get-Date

# ============================================================================
# FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if (-not $Quiet) {
        switch ($Level) {
            "INFO" { Write-Host $logMessage -ForegroundColor Cyan }
            "WARN" { Write-Host $logMessage -ForegroundColor Yellow }
            "ERROR" { Write-Host $logMessage -ForegroundColor Red }
            "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
            default { Write-Host $logMessage }
        }
    }
    
    Add-Content -Path $LogFile -Value $logMessage
}

function Show-Help {
    $helpText = @"
SafeOps Threat Intelligence Database Initialization Script

USAGE:
    .\init_database.ps1 [OPTIONS]

OPTIONS:
    -DatabaseName NAME       Database name (default: safeops_threat_intel)
    -DatabaseUser USER       Admin user (default: safeops_admin)
    -DatabasePassword PASS   Admin password (prompted if not provided)
    -DatabaseHost HOST       Database host (default: localhost)
    -DatabasePort PORT       Database port (default: 5432)
    -PostgresSuperUser USER  Postgres superuser (default: postgres)
    -LogFile PATH           Log file path (default: database_init.log)
    -SkipTestData           Don't load test IOC data
    -DropExisting           Drop existing database (DANGEROUS!)
    -Quiet                  Suppress console output
    -DryRun                 Show what would be done without executing
    -Help                   Show this help message

EXAMPLES:
    .\init_database.ps1
    .\init_database.ps1 -DatabaseName mydb -SkipTestData
    .\init_database.ps1 -DropExisting -DryRun

ENVIRONMENT VARIABLES:
    DB_PASSWORD             Database password (if not provided as parameter)
    PGPASSWORD              PostgreSQL password for superuser
"@
    Write-Host $helpText
    exit 0
}

function Test-PostgreSQL {
    Write-Log "Checking PostgreSQL availability..." -Level INFO
    
    try {
        $version = & psql --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "psql command not found" -Level ERROR
            return $false
        }
        Write-Log "Found: $version" -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "PostgreSQL not found: $_" -Level ERROR
        return $false
    }
}

function Test-SchemaFiles {
    Write-Log "Checking schema files..." -Level INFO
    
    $requiredFiles = @(
        "schemas\001_initial_setup.sql",
        "schemas\002_ip_reputation.sql",
        "schemas\003_domain_reputation.sql",
        "schemas\004_hash_reputation.sql",
        "schemas\005_ioc_storage.sql",
        "schemas\006_proxy_anonymizer.sql",
        "schemas\007_geolocation.sql",
        "schemas\008_threat_feeds.sql",
        "schemas\009_asn_data.sql",
        "schemas\999_indexes_and_maintenance.sql"
    )
    
    $missing = @()
    foreach ($file in $requiredFiles) {
        $path = Join-Path $ScriptDir $file
        if (-not (Test-Path $path)) {
            $missing += $file
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-Log "Missing schema files:" -Level ERROR
        foreach ($m in $missing) {
            Write-Log "  - $m" -Level ERROR
        }
        return $false
    }
    
    Write-Log "All schema files found (10 files)" -Level SUCCESS
    return $true
}

function Invoke-SqlFile {
    param(
        [string]$FilePath,
        [string]$Database = "postgres"
    )
    
    $fileName = Split-Path -Leaf $FilePath
    Write-Log "Executing: $fileName" -Level INFO
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would execute: $FilePath" -Level WARN
        return $true
    }
    
    try {
        $result = & psql -h $DatabaseHost -p $DatabasePort -U $PostgresSuperUser -d $Database -f $FilePath -v ON_ERROR_STOP=1 2>&1
        $result | Out-File -FilePath $LogFile -Append
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully executed: $fileName" -Level SUCCESS
            return $true
        }
        else {
            Write-Log "Failed to execute: $fileName (exit code: $LASTEXITCODE)" -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "Error executing $fileName : $_" -Level ERROR
        return $false
    }
}

function New-Database {
    Write-Log "Creating database '$DatabaseName'..." -Level INFO
    
    if ($DropExisting) {
        Write-Log "WARNING: Dropping existing database!" -Level WARN
        if (-not $DryRun) {
            & psql -h $DatabaseHost -p $DatabasePort -U $PostgresSuperUser -d postgres -c "DROP DATABASE IF EXISTS $DatabaseName;" 2>&1 | Out-Null
        }
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would create database: $DatabaseName" -Level WARN
        Write-Log "[DRY RUN] Would create user: $DatabaseUser" -Level WARN
        return $true
    }
    
    # Create user using simple SQL (avoiding here-string issues)
    $userSql = "DO `$`$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '$DatabaseUser') THEN CREATE USER $DatabaseUser WITH PASSWORD '$DatabasePassword'; END IF; END `$`$;"
    & psql -h $DatabaseHost -p $DatabasePort -U $PostgresSuperUser -d postgres -c $userSql 2>&1 | Out-File -FilePath $LogFile -Append
    
    # Create database
    $dbSql = "CREATE DATABASE $DatabaseName OWNER $DatabaseUser;"
    & psql -h $DatabaseHost -p $DatabasePort -U $PostgresSuperUser -d postgres -c $dbSql 2>&1 | Out-File -FilePath $LogFile -Append
    
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Database created successfully" -Level SUCCESS
        return $true
    }
    else {
        Write-Log "Failed to create database" -Level ERROR
        return $false
    }
}

function Install-Extensions {
    Write-Log "Installing PostgreSQL extensions..." -Level INFO
    
    $extensions = @("pgcrypto", "uuid-ossp", "citext", "pg_trgm", "btree_gist")
    
    foreach ($ext in $extensions) {
        Write-Log "  Installing extension: $ext" -Level INFO
        if (-not $DryRun) {
            & psql -h $DatabaseHost -p $DatabasePort -U $PostgresSuperUser -d $DatabaseName -c "CREATE EXTENSION IF NOT EXISTS `"$ext`";" 2>&1 | Out-File -FilePath $LogFile -Append
        }
    }
    
    Write-Log "Extensions installed" -Level SUCCESS
    return $true
}

function Install-Schemas {
    Write-Log "Applying database schemas..." -Level INFO
    
    $schemaFiles = @(
        "001_initial_setup.sql",
        "002_ip_reputation.sql",
        "003_domain_reputation.sql",
        "004_hash_reputation.sql",
        "005_ioc_storage.sql",
        "006_proxy_anonymizer.sql",
        "007_geolocation.sql",
        "008_threat_feeds.sql",
        "009_asn_data.sql",
        "999_indexes_and_maintenance.sql"
    )
    
    foreach ($file in $schemaFiles) {
        $path = Join-Path $ScriptDir "schemas" $file
        if (-not (Invoke-SqlFile -FilePath $path -Database $DatabaseName)) {
            return $false
        }
    }
    
    Write-Log "All schemas applied successfully" -Level SUCCESS
    return $true
}

function Install-Views {
    Write-Log "Creating database views..." -Level INFO
    
    $viewFiles = @("active_threats_view.sql", "high_confidence_iocs.sql", "threat_summary_stats.sql")
    
    foreach ($file in $viewFiles) {
        $path = Join-Path $ScriptDir "views" $file
        if (Test-Path $path) {
            Invoke-SqlFile -FilePath $path -Database $DatabaseName | Out-Null
        }
    }
    
    Write-Log "Views created" -Level SUCCESS
    return $true
}

function Install-SeedData {
    Write-Log "Loading seed data..." -Level INFO
    
    $seedFiles = @("initial_threat_categories.sql", "feed_sources_config.sql")
    
    if (-not $SkipTestData) {
        $seedFiles += "test_ioc_data.sql"
    }
    
    foreach ($file in $seedFiles) {
        $path = Join-Path $ScriptDir "seeds" $file
        if (Test-Path $path) {
            Invoke-SqlFile -FilePath $path -Database $DatabaseName | Out-Null
        }
    }
    
    Write-Log "Seed data loaded" -Level SUCCESS
    return $true
}

function Set-Permissions {
    Write-Log "Configuring database permissions..." -Level INFO
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would configure permissions" -Level WARN
        return $true
    }
    
    $permSql = "GRANT CONNECT ON DATABASE $DatabaseName TO $DatabaseUser; GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DatabaseUser; GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DatabaseUser;"
    & psql -h $DatabaseHost -p $DatabasePort -U $PostgresSuperUser -d $DatabaseName -c $permSql 2>&1 | Out-File -FilePath $LogFile -Append
    
    Write-Log "Permissions configured" -Level SUCCESS
    return $true
}

function Test-Installation {
    Write-Log "Verifying installation..." -Level INFO
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would verify installation" -Level WARN
        return $true
    }
    
    $tableCount = & psql -h $DatabaseHost -p $DatabasePort -U $PostgresSuperUser -d $DatabaseName -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>&1
    Write-Log "Tables created: $($tableCount.Trim())" -Level INFO
    
    Write-Log "Verification complete" -Level SUCCESS
    return $true
}

function Show-Summary {
    $duration = (Get-Date) - $StartTime
    $hostPort = $DatabaseHost + ":" + $DatabasePort
    $connString = "postgresql://" + $DatabaseUser + "@" + $hostPort + "/" + $DatabaseName
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host " SafeOps Threat Intelligence Database - Installation Complete" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Database Name:    $DatabaseName" -ForegroundColor Cyan
    Write-Host "Database User:    $DatabaseUser" -ForegroundColor Cyan
    Write-Host "Database Host:    $hostPort" -ForegroundColor Cyan
    Write-Host "Installation Time: $($duration.TotalSeconds) seconds" -ForegroundColor Cyan
    Write-Host "Log File:         $LogFile" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Connection String:" -ForegroundColor Yellow
    Write-Host "  $connString" -ForegroundColor White
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Green
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    if ($Help) { Show-Help }
    
    "SafeOps Database Initialization - $(Get-Date)" | Out-File -FilePath $LogFile
    
    Write-Log "Starting SafeOps Threat Intelligence Database initialization" -Level INFO
    
    if ($DryRun) {
        Write-Log "DRY RUN MODE - No changes will be made" -Level WARN
    }
    
    # Get password if needed
    if (-not $DatabasePassword -and -not $DryRun) {
        if ($env:DB_PASSWORD) {
            $DatabasePassword = $env:DB_PASSWORD
        }
        else {
            $securePassword = Read-Host "Enter password for $DatabaseUser" -AsSecureString
            $DatabasePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            )
        }
    }
    
    # Pre-flight checks
    if (-not (Test-PostgreSQL)) { throw "PostgreSQL check failed" }
    if (-not (Test-SchemaFiles)) { throw "Schema files check failed" }
    
    # Database setup
    if (-not (New-Database)) { throw "Database creation failed" }
    if (-not (Install-Extensions)) { throw "Extension installation failed" }
    if (-not (Install-Schemas)) { throw "Schema application failed" }
    
    Install-Views | Out-Null
    Install-SeedData | Out-Null
    
    if (-not (Set-Permissions)) { throw "Permission configuration failed" }
    
    Test-Installation | Out-Null
    Show-Summary
    
    exit 0
}
catch {
    Write-Log "FATAL ERROR: $_" -Level ERROR
    exit 1
}
