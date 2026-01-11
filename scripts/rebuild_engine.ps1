# SafeOps Engine - Force Rebuild Script
# Kills any running instances and rebuilds the engine

Write-Host "=== SafeOps Engine Force Rebuild ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Kill any running SafeOps-Engine processes
Write-Host "[1/4] Killing any running SafeOps-Engine processes..." -ForegroundColor Yellow
try {
    Stop-Process -Name "SafeOps-Engine" -Force -ErrorAction SilentlyContinue
    Write-Host "  Processes killed (or none were running)" -ForegroundColor Green
} catch {
    Write-Host "  No processes to kill" -ForegroundColor Green
}

# Step 2: Wait for file handles to release
Write-Host ""
Write-Host "[2/4] Waiting for file handles to release..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
Write-Host "  Ready" -ForegroundColor Green

# Step 3: Remove old binary
Write-Host ""
Write-Host "[3/4] Removing old binary..." -ForegroundColor Yellow
$binaryPath = "D:\SafeOpsFV2\bin\SafeOps-Engine.exe"
if (Test-Path $binaryPath) {
    try {
        Remove-Item -Path $binaryPath -Force -ErrorAction Stop
        Write-Host "  Old binary removed" -ForegroundColor Green
    } catch {
        Write-Host "  Error: Binary is still locked by a process!" -ForegroundColor Red
        Write-Host "  Please close all terminals/processes and try again" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  No old binary to remove" -ForegroundColor Green
}

# Step 4: Build new binary
Write-Host ""
Write-Host "[4/4] Building new binary..." -ForegroundColor Yellow
Set-Location D:\SafeOpsFV2\src\safeops-engine
go build -o ..\..\bin\SafeOps-Engine.exe .\cmd

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Build successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "=== Build Complete ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To run SafeOps Engine:" -ForegroundColor White
    Write-Host "  cd D:\SafeOpsFV2" -ForegroundColor Cyan
    Write-Host "  .\bin\SafeOps-Engine.exe" -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host "  Build failed!" -ForegroundColor Red
    exit 1
}
