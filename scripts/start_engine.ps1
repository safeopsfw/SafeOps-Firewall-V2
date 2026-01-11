# SafeOps Engine - Clean Start Script
# Kills leftover processes and starts the engine with admin privileges

Write-Host "=== SafeOps Engine - Clean Start ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Kill any leftover processes
Write-Host "[1/3] Cleaning up leftover processes..." -ForegroundColor Yellow
Stop-Process -Name "SafeOps-Engine","SafeOps-Engine-NEW","dnsproxy","mitmdump" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Write-Host "  Cleanup complete" -ForegroundColor Green

# Step 2: Check for admin privileges
Write-Host ""
Write-Host "[2/3] Checking admin privileges..." -ForegroundColor Yellow
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "  ERROR: Not running as Administrator!" -ForegroundColor Red
    Write-Host "  WinpkFilter requires admin privileges to operate" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please run this script as Administrator:" -ForegroundColor Yellow
    Write-Host "  Right-click PowerShell -> Run as Administrator" -ForegroundColor Cyan
    Write-Host "  Then run: .\scripts\start_engine.ps1" -ForegroundColor Cyan
    Write-Host ""
    pause
    exit 1
}
Write-Host "  Running as Administrator" -ForegroundColor Green

# Step 3: Start SafeOps Engine
Write-Host ""
Write-Host "[3/3] Starting SafeOps Engine..." -ForegroundColor Yellow
Set-Location D:\SafeOpsFV2

# Use the newer binary
$binary = ".\bin\SafeOps-Engine-NEW.exe"
if (-not (Test-Path $binary)) {
    $binary = ".\bin\SafeOps-Engine.exe"
}

Write-Host "  Launching: $binary" -ForegroundColor Cyan
Write-Host ""
Write-Host "=== SafeOps Engine Output ===" -ForegroundColor Cyan
Write-Host ""

# Run the engine (foreground)
& $binary

# If engine exits, show message
Write-Host ""
Write-Host "=== SafeOps Engine Stopped ===" -ForegroundColor Yellow
