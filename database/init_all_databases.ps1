# Initialize All SafeOps Databases
# Run this ONCE to set up all PostgreSQL databases and schemas

param(
    [string]$PostgresPassword = "safeops123"
)

$ErrorActionPreference = "Stop"

Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  SafeOps Database Initialization      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if PostgreSQL is installed
$pgExists = Get-Command psql -ErrorAction SilentlyContinue
if (-not $pgExists) {
    Write-Host "✗ PostgreSQL not found!" -ForegroundColor Red
    Write-Host "  Install PostgreSQL first: https://www.postgresql.org/download/" -ForegroundColor Yellow
    exit 1
}

# Database names
$databases = @(
    "safeops_network",
    "safeops"
)

Write-Host "[1] Creating databases..." -ForegroundColor Cyan

foreach ($db in $databases) {
    Write-Host "  Creating $db..." -ForegroundColor Yellow

    # Create database
    $createDB = "CREATE DATABASE $db OWNER postgres;"
    echo $createDB | psql -U postgres -h localhost 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ $db created" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ $db already exists (skipping)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "[2] Running schema migrations..." -ForegroundColor Cyan

$schemaDir = "D:\SafeOpsFV2\database\schemas"
$schemas = Get-ChildItem "$schemaDir\*.sql" | Sort-Object Name

foreach ($schema in $schemas) {
    Write-Host "  Running $($schema.Name)..." -ForegroundColor Yellow

    # Determine which database to use
    $targetDB = "safeops_network"
    if ($schema.Name -match "dns|dhcp|nic") {
        $targetDB = "safeops_network"
    } else {
        $targetDB = "safeops"
    }

    # Run schema
    psql -U postgres -h localhost -d $targetDB -f $schema.FullName 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ $($schema.Name) applied to $targetDB" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($schema.Name) failed!" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "[3] Creating database users..." -ForegroundColor Cyan

$users = @(
    @{Name="safeops"; Password=$PostgresPassword},
    @{Name="dns_server"; Password=$PostgresPassword},
    @{Name="dhcp_server"; Password=$PostgresPassword}
)

foreach ($user in $users) {
    Write-Host "  Creating user: $($user.Name)..." -ForegroundColor Yellow

    $createUser = "CREATE USER $($user.Name) WITH PASSWORD '$($user.Password)';"
    echo $createUser | psql -U postgres -h localhost 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ User $($user.Name) created" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ User $($user.Name) already exists" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "[4] Granting permissions..." -ForegroundColor Cyan

# Grant permissions
$grants = @(
    "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO safeops;",
    "GRANT ALL PRIVILEGES ON DATABASE safeops TO safeops;",
    "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO dns_server;",
    "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO dhcp_server;"
)

foreach ($grant in $grants) {
    echo $grant | psql -U postgres -h localhost 2>&1 | Out-Null
}

Write-Host "  ✓ Permissions granted" -ForegroundColor Green

Write-Host ""
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Database Initialization Complete!    ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Databases created:" -ForegroundColor Cyan
Write-Host "  • safeops_network (DNS, DHCP, NIC)" -ForegroundColor White
Write-Host "  • safeops (Main services)" -ForegroundColor White
Write-Host ""
Write-Host "Users created:" -ForegroundColor Cyan
Write-Host "  • safeops (password: $PostgresPassword)" -ForegroundColor White
Write-Host "  • dns_server (password: $PostgresPassword)" -ForegroundColor White
Write-Host "  • dhcp_server (password: $PostgresPassword)" -ForegroundColor White
Write-Host ""
Write-Host "Set environment variable:" -ForegroundColor Yellow
Write-Host "  `$env:POSTGRES_PASSWORD = '$PostgresPassword'" -ForegroundColor White
Write-Host ""
