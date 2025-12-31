# Fix step-ca Database Corruption
# This script stops step-ca and recreates the database

Write-Host "Fixing step-ca database corruption..." -ForegroundColor Yellow
Write-Host ""

# Step 1: Kill any running step-ca processes
Write-Host "[1/3] Stopping step-ca..." -ForegroundColor Cyan
Get-Process -Name "step-ca" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
Write-Host "  ✓ step-ca stopped" -ForegroundColor Green

# Step 2: Delete corrupted database
Write-Host "[2/3] Removing corrupted database..." -ForegroundColor Cyan
$dbPath = "D:\SafeOpsFV2\certs\step-ca\ca\db"
if (Test-Path $dbPath) {
    Remove-Item $dbPath -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "  ✓ Old database removed" -ForegroundColor Green
} else {
    Write-Host "  ✓ No database to remove" -ForegroundColor Green
}

# Step 3: Create fresh database directory
Write-Host "[3/3] Creating fresh database..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $dbPath -Force | Out-Null
Write-Host "  ✓ Fresh database created" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Database Fixed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "You can now run: .\start-and-monitor-complete.ps1" -ForegroundColor Cyan
