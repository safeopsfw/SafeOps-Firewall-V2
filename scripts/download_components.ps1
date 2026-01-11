# Download All Required Components
# Run as Administrator

Write-Host "=== SafeOps Component Downloader ===" -ForegroundColor Green
Write-Host ""

$ErrorActionPreference = "Stop"

# Create directories
$binDir = "D:\SafeOpsFV2\bin"
New-Item -ItemType Directory -Force -Path "$binDir\winpkfilter" | Out-Null
New-Item -ItemType Directory -Force -Path "$binDir\dnsproxy" | Out-Null
New-Item -ItemType Directory -Force -Path "$binDir\mitmproxy" | Out-Null

# ============================================
# 1. Download WinpkFilter SDK
# ============================================
Write-Host "[1/3] Downloading WinpkFilter SDK..." -ForegroundColor Cyan

$winpkUrl = "https://github.com/wiresock/ndisapi/releases/latest/download/ndisapi-x64.zip"
$winpkZip = "$binDir\winpkfilter\ndisapi.zip"

try {
    Invoke-WebRequest -Uri $winpkUrl -OutFile $winpkZip -UseBasicParsing
    Expand-Archive -Path $winpkZip -DestinationPath "$binDir\winpkfilter" -Force
    Remove-Item $winpkZip
    Write-Host "✓ WinpkFilter SDK downloaded" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to download WinpkFilter: $_" -ForegroundColor Red
    Write-Host "Please download manually from: https://github.com/wiresock/ndisapi/releases" -ForegroundColor Yellow
}

# ============================================
# 2. Download dnsproxy
# ============================================
Write-Host "`n[2/3] Downloading dnsproxy..." -ForegroundColor Cyan

$dnsproxyUrl = "https://github.com/AdguardTeam/dnsproxy/releases/latest/download/dnsproxy-windows-amd64.zip"
$dnsproxyZip = "$binDir\dnsproxy\dnsproxy.zip"

try {
    Invoke-WebRequest -Uri $dnsproxyUrl -OutFile $dnsproxyZip -UseBasicParsing
    Expand-Archive -Path $dnsproxyZip -DestinationPath "$binDir\dnsproxy" -Force
    Remove-Item $dnsproxyZip

    # Rename if needed
    if (Test-Path "$binDir\dnsproxy\dnsproxy-windows-amd64.exe") {
        Rename-Item "$binDir\dnsproxy\dnsproxy-windows-amd64.exe" "dnsproxy.exe"
    }

    Write-Host "✓ dnsproxy downloaded" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to download dnsproxy: $_" -ForegroundColor Red
    Write-Host "Please download manually from: https://github.com/AdguardTeam/dnsproxy/releases" -ForegroundColor Yellow
}

# ============================================
# 3. Download mitmproxy
# ============================================
Write-Host "`n[3/3] Downloading mitmproxy..." -ForegroundColor Cyan

# mitmproxy is best installed via pip
Write-Host "Checking if Python is installed..." -ForegroundColor Yellow

try {
    $pythonVersion = python --version 2>&1
    Write-Host "Python found: $pythonVersion" -ForegroundColor Green

    Write-Host "Installing mitmproxy via pip..." -ForegroundColor Yellow
    pip install --upgrade mitmproxy

    # Verify installation
    $mitmLocation = Get-Command mitmdump -ErrorAction SilentlyContinue
    if ($mitmLocation) {
        Write-Host "✓ mitmproxy installed at: $($mitmLocation.Source)" -ForegroundColor Green
    } else {
        Write-Host "✗ mitmproxy installation failed" -ForegroundColor Red
    }

} catch {
    Write-Host "✗ Python not found. Please install Python first." -ForegroundColor Red
    Write-Host "Run: scripts\install_dependencies.ps1" -ForegroundColor Yellow
}

# ============================================
# Summary
# ============================================
Write-Host "`n=== Download Summary ===" -ForegroundColor Green
Write-Host ""

Write-Host "WinpkFilter:" -NoNewline
if (Test-Path "$binDir\winpkfilter\ndisapi.dll") {
    Write-Host " ✓ Ready" -ForegroundColor Green
} else {
    Write-Host " ✗ Missing" -ForegroundColor Red
}

Write-Host "dnsproxy:    " -NoNewline
if (Test-Path "$binDir\dnsproxy\dnsproxy.exe") {
    Write-Host " ✓ Ready" -ForegroundColor Green
} else {
    Write-Host " ✗ Missing" -ForegroundColor Red
}

Write-Host "mitmproxy:   " -NoNewline
$mitm = Get-Command mitmdump -ErrorAction SilentlyContinue
if ($mitm) {
    Write-Host " ✓ Ready" -ForegroundColor Green
} else {
    Write-Host " ✗ Missing" -ForegroundColor Red
}

Write-Host "`nNext step: Install WinpkFilter driver" -ForegroundColor Yellow
Write-Host "Run: scripts\install_driver.ps1" -ForegroundColor Yellow
