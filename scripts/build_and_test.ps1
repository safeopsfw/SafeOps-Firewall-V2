# SafeOps Engine - Build and Test Script
# Run this to build and test the engine

Write-Host "=== SafeOps Engine - Build and Test ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Go version
Write-Host "[1/5] Checking Go installation..." -ForegroundColor Yellow
$goVersion = go version 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Go found: $goVersion" -ForegroundColor Green
} else {
    Write-Host "✗ Go not found! Please install Go first." -ForegroundColor Red
    exit 1
}

# Step 2: Navigate to project
Write-Host ""
Write-Host "[2/5] Navigating to project directory..." -ForegroundColor Yellow
Set-Location D:\SafeOpsFV2\src\safeops-engine
if (Test-Path "go.mod") {
    Write-Host "✓ Found go.mod" -ForegroundColor Green
} else {
    Write-Host "✗ go.mod not found!" -ForegroundColor Red
    exit 1
}

# Step 3: Download dependencies
Write-Host ""
Write-Host "[3/5] Downloading dependencies..." -ForegroundColor Yellow
go mod download
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Dependencies downloaded" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to download dependencies" -ForegroundColor Red
    exit 1
}

# Step 4: Build
Write-Host ""
Write-Host "[4/5] Building SafeOps-Engine.exe..." -ForegroundColor Yellow
go build -o ..\..\bin\SafeOps-Engine.exe ./cmd
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Build successful!" -ForegroundColor Green
    $exePath = "D:\SafeOpsFV2\bin\SafeOps-Engine.exe"
    if (Test-Path $exePath) {
        $fileInfo = Get-Item $exePath
        Write-Host "  Binary: $exePath" -ForegroundColor Cyan
        Write-Host "  Size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor Cyan
    }
} else {
    Write-Host "✗ Build failed!" -ForegroundColor Red
    exit 1
}

# Step 5: Pre-flight checks
Write-Host ""
Write-Host "[5/5] Running pre-flight checks..." -ForegroundColor Yellow

# Check WinpkFilter driver
$service = Get-Service -Name "ndisrd" -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "✓ WinpkFilter driver running" -ForegroundColor Green
} else {
    Write-Host "✗ WinpkFilter driver NOT running!" -ForegroundColor Red
    Write-Host "  Run: D:\SafeOpsFV2\scripts\install_all.ps1" -ForegroundColor Yellow
}

# Check dnsproxy binary
if (Test-Path "D:\SafeOpsFV2\bin\dnsproxy\windows-amd64\dnsproxy.exe") {
    Write-Host "✓ dnsproxy binary found" -ForegroundColor Green
} else {
    Write-Host "✗ dnsproxy binary NOT found!" -ForegroundColor Red
}

# Check mitmproxy
$mitmCheck = mitmdump --version 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ mitmproxy installed: $mitmCheck" -ForegroundColor Green
} else {
    Write-Host "✗ mitmproxy NOT installed!" -ForegroundColor Red
    Write-Host "  Run: pip install mitmproxy" -ForegroundColor Yellow
}

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "✓ Running as Administrator" -ForegroundColor Green
} else {
    Write-Host "⚠ NOT running as Administrator!" -ForegroundColor Yellow
    Write-Host "  WinpkFilter requires admin privileges" -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run SafeOps Engine:" -ForegroundColor White
Write-Host "  cd D:\SafeOpsFV2" -ForegroundColor Cyan
Write-Host "  .\bin\SafeOps-Engine.exe" -ForegroundColor Cyan
Write-Host ""
Write-Host "Expected behavior:" -ForegroundColor White
Write-Host "  ✓ dnsproxy starts on port 15353" -ForegroundColor Green
Write-Host "  ✓ mitmproxy starts on port 8080 (NO MORE CRASH!)" -ForegroundColor Green
Write-Host "  ✓ WinpkFilter captures packets from 5 NICs" -ForegroundColor Green
Write-Host "  ✓ Stats logged every 15 seconds" -ForegroundColor Green
Write-Host ""
Write-Host "If mitmproxy still crashes, check:" -ForegroundColor Yellow
Write-Host "  - Run: mitmdump --version" -ForegroundColor Cyan
Write-Host "  - Ensure Python and mitmproxy are in PATH" -ForegroundColor Cyan
Write-Host ""
