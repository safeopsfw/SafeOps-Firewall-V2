# SafeOps Engine - Complete Setup Script
# This script builds the engine and sets it up to run on boot
# Requires Administrator privileges

param(
    [switch]$SkipBuild,
    [switch]$ServiceOnly
)

$ErrorActionPreference = "Stop"

# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator!"
    exit 1
}

Write-Host "=== SafeOps Engine Setup ===" -ForegroundColor Cyan
Write-Host ""

$rootDir = "D:\SafeOpsFV2"
$engineDir = "$rootDir\src\safeops-engine"
$exePath = "$engineDir\safeops-engine.exe"

# Step 1: Build the engine (unless skipped)
if (-not $SkipBuild) {
    Write-Host "[1/4] Building SafeOps Engine..." -ForegroundColor Yellow

    if (-not (Test-Path $engineDir)) {
        Write-Error "Engine directory not found: $engineDir"
        exit 1
    }

    Set-Location $engineDir

    # Check if Go is installed
    try {
        $goVersion = go version
        Write-Host "  Go found: $goVersion" -ForegroundColor Green
    } catch {
        Write-Error "Go is not installed or not in PATH. Please install Go first."
        exit 1
    }

    # Build the engine
    Write-Host "  Building..." -ForegroundColor Cyan
    go build -o safeops-engine.exe ./cmd

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed!"
        exit 1
    }

    if (Test-Path $exePath) {
        $fileInfo = Get-Item $exePath
        Write-Host "  Build successful! ($($fileInfo.Length / 1MB) MB)" -ForegroundColor Green
    } else {
        Write-Error "Build completed but executable not found!"
        exit 1
    }

    Write-Host ""
} else {
    Write-Host "[1/4] Skipping build (--SkipBuild specified)" -ForegroundColor Yellow

    if (-not (Test-Path $exePath)) {
        Write-Error "Executable not found at: $exePath. Cannot skip build!"
        exit 1
    }
    Write-Host ""
}

# Step 2: Verify dependencies
Write-Host "[2/4] Verifying dependencies..." -ForegroundColor Yellow

$dnsProxyPath = "$rootDir\bin\dnsproxy\windows-amd64\dnsproxy.exe"
if (-not (Test-Path $dnsProxyPath)) {
    Write-Warning "dnsproxy not found at: $dnsProxyPath"
    Write-Host "  Please download dnsproxy from: https://github.com/AdguardTeam/dnsproxy/releases" -ForegroundColor Yellow
} else {
    Write-Host "  dnsproxy found: OK" -ForegroundColor Green
}

# Check WinpkFilter driver
Write-Host "  Checking WinpkFilter driver..." -ForegroundColor Cyan
$driverStatus = sc.exe query ndisapi 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  WinpkFilter driver: OK" -ForegroundColor Green
} else {
    Write-Warning "WinpkFilter driver not found! Please install WinpkFilter."
    Write-Host "  Download from: https://www.ntkernel.com/downloads/" -ForegroundColor Yellow
}

Write-Host ""

# Step 3: Test run (if not service-only mode)
if (-not $ServiceOnly) {
    Write-Host "[3/4] Test run..." -ForegroundColor Yellow
    Write-Host "  Starting SafeOps Engine for 10 seconds to verify it works..." -ForegroundColor Cyan

    Set-Location $rootDir

    $process = Start-Process -FilePath $exePath -WorkingDirectory $rootDir -PassThru -NoNewWindow

    Start-Sleep -Seconds 10

    if ($process.HasExited) {
        Write-Warning "Engine exited during test run. Check logs at: $rootDir\data\logs\engine.log"
    } else {
        Write-Host "  Engine running successfully!" -ForegroundColor Green
        Stop-Process -Id $process.Id -Force
        Start-Sleep -Seconds 2
    }

    Write-Host ""
} else {
    Write-Host "[3/4] Skipping test run (--ServiceOnly specified)" -ForegroundColor Yellow
    Write-Host ""
}

# Step 4: Install as Windows service
Write-Host "[4/4] Installing Windows service..." -ForegroundColor Yellow

$installScript = "$rootDir\scripts\install_safeops_service.ps1"

if (-not (Test-Path $installScript)) {
    Write-Error "Service installer not found at: $installScript"
    exit 1
}

& $installScript

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. The SafeOps Engine service is now installed" -ForegroundColor White
Write-Host "  2. It will start automatically on boot (delayed start)" -ForegroundColor White
Write-Host "  3. DNS will be configured for all network interfaces automatically" -ForegroundColor White
Write-Host "  4. Monitor logs at: D:\SafeOpsFV2\data\logs\engine.log" -ForegroundColor White
Write-Host ""
Write-Host "Service Management:" -ForegroundColor Cyan
Write-Host "  Start:   Start-Service SafeOpsEngine" -ForegroundColor White
Write-Host "  Stop:    Stop-Service SafeOpsEngine" -ForegroundColor White
Write-Host "  Status:  Get-Service SafeOpsEngine" -ForegroundColor White
Write-Host ""
