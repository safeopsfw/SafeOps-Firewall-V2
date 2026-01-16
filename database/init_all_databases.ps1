# Initialize All SafeOps Databases
# Run this ONCE to set up all PostgreSQL databases and schemas

param(
    [string]$PostgresPassword = "admin"
)

$ErrorActionPreference = "Continue"

# PostgreSQL binary path
$PSQL = "D:\Program\PostgreSQL\bin\psql.exe"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SafeOps Database Initialization      " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if PostgreSQL is installed
if (-not (Test-Path $PSQL)) {
    Write-Host "[X] PostgreSQL not found at $PSQL!" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Found PostgreSQL at $PSQL" -ForegroundColor Green
Write-Host ""

# Database names
$databases = @(
    "threat_intel_db",
    "safeops_network",
    "safeops"
)

Write-Host "[1] Creating databases..." -ForegroundColor Cyan

foreach ($db in $databases) {
    Write-Host "  Creating $db..." -ForegroundColor Yellow

    # Create database
    $createDB = "CREATE DATABASE $db OWNER postgres;"
    echo $createDB | & $PSQL -U postgres -h localhost 2>&1 | Out-Null

    Write-Host "  [OK] $db ready" -ForegroundColor Green
}

Write-Host ""
Write-Host "[2] Running schema migrations..." -ForegroundColor Cyan

$schemaDir = "$PSScriptRoot\schemas"

if (Test-Path $schemaDir) {
    $schemas = Get-ChildItem "$schemaDir\*.sql" | Sort-Object Name

    foreach ($schema in $schemas) {
        Write-Host "  Running $($schema.Name)..." -ForegroundColor Yellow

        # Determine which database to use
        $targetDB = "threat_intel_db"
        if ($schema.Name -match "dns|dhcp|nic") {
            $targetDB = "safeops_network"
        }
        elseif ($schema.Name -match "firewall|ids|threat") {
            $targetDB = "threat_intel_db"
        }

        # Run schema
        & $PSQL -U postgres -h localhost -d $targetDB -f $schema.FullName 2>&1 | Out-Null
        Write-Host "  [OK] $($schema.Name) applied to $targetDB" -ForegroundColor Green
    }
}
else {
    Write-Host "  [!] Schema directory not found: $schemaDir" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[3] Creating database users..." -ForegroundColor Cyan

$users = @(
    @{Name = "safeops"; Password = $PostgresPassword },
    @{Name = "dns_server"; Password = $PostgresPassword },
    @{Name = "dhcp_server"; Password = $PostgresPassword },
    @{Name = "threat_intel_app"; Password = $PostgresPassword }
)

foreach ($user in $users) {
    Write-Host "  Creating user: $($user.Name)..." -ForegroundColor Yellow

    $createUser = "CREATE USER $($user.Name) WITH PASSWORD '$($user.Password)';"
    echo $createUser | & $PSQL -U postgres -h localhost 2>&1 | Out-Null

    Write-Host "  [OK] User $($user.Name) ready" -ForegroundColor Green
}

Write-Host ""
Write-Host "[4] Granting permissions..." -ForegroundColor Cyan

# Grant permissions
$grants = @(
    "GRANT ALL PRIVILEGES ON DATABASE threat_intel_db TO safeops;",
    "GRANT ALL PRIVILEGES ON DATABASE threat_intel_db TO threat_intel_app;",
    "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO safeops;",
    "GRANT ALL PRIVILEGES ON DATABASE safeops TO safeops;",
    "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO dns_server;",
    "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO dhcp_server;"
)

foreach ($grant in $grants) {
    echo $grant | & $PSQL -U postgres -h localhost 2>&1 | Out-Null
}

Write-Host "  [OK] Permissions granted" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Database Initialization Complete!    " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Databases created:" -ForegroundColor Cyan
Write-Host "  - threat_intel_db (Threat Intelligence)" -ForegroundColor White
Write-Host "  - safeops_network (DNS, DHCP, NIC)" -ForegroundColor White
Write-Host "  - safeops (Main services)" -ForegroundColor White
Write-Host ""
