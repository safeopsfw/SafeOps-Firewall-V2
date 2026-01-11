# SafeOps Complete Installation Script
# Run as Administrator

param(
    [switch]$SkipRestart
)

Write-Host "=== SafeOps Installation Script ===" -ForegroundColor Green
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

$restartNeeded = $false

# Install WinpkFilter Driver
Write-Host "[1/4] Installing WinpkFilter Driver..." -ForegroundColor Cyan

$msiPath = "D:\SafeOpsFV2\bin\winpkfilter\WinpkFilter-3.6.2-x64.msi"
if (Test-Path $msiPath) {
    Write-Host "Installing from: $msiPath" -ForegroundColor Yellow
    Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait -NoNewWindow

    # Verify installation
    $service = Get-Service -Name "ndisrd" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Driver installed successfully" -ForegroundColor Green
        $restartNeeded = $true
    } else {
        Write-Host "Driver installation may have failed. Check manually." -ForegroundColor Red
    }
} else {
    Write-Host "Installer not found: $msiPath" -ForegroundColor Red
    Write-Host "Run: scripts\download_components.ps1" -ForegroundColor Yellow
    exit 1
}

# Configure Windows DNS
Write-Host ""
Write-Host "[2/4] Checking Windows DNS Client..." -ForegroundColor Cyan

try {
    $service = Get-Service -Name "Dnscache" -ErrorAction Stop
    if ($service.Status -eq "Running") {
        Write-Host "Windows DNS Client is running (this is OK)" -ForegroundColor Green
        Write-Host "WinpkFilter will redirect DNS traffic to dnsproxy transparently" -ForegroundColor Yellow
    }
} catch {
    Write-Host "DNS Client service check failed: $_" -ForegroundColor Red
}

# Enable IP Forwarding
Write-Host ""
Write-Host "[3/4] Enabling IP Forwarding..." -ForegroundColor Cyan

try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1
    Write-Host "IP Forwarding enabled" -ForegroundColor Green
    $restartNeeded = $true
} catch {
    Write-Host "Failed to enable IP Forwarding: $_" -ForegroundColor Red
}

# Configure Windows Firewall
Write-Host ""
Write-Host "[4/4] Configuring Windows Firewall..." -ForegroundColor Cyan

try {
    # Remove existing rules if they exist
    Remove-NetFirewallRule -DisplayName "SafeOps DNS" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "SafeOps DNSProxy" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "SafeOps API" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "SafeOps MITM" -ErrorAction SilentlyContinue

    # Add new rules
    New-NetFirewallRule -DisplayName "SafeOps DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "SafeOps DNSProxy" -Direction Inbound -Protocol UDP -LocalPort 15353 -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "SafeOps API" -Direction Inbound -Protocol TCP -LocalPort 9002 -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "SafeOps MITM" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow | Out-Null

    Write-Host "Firewall rules configured" -ForegroundColor Green
    Write-Host "  - Port 53 (DNS redirect)" -ForegroundColor Gray
    Write-Host "  - Port 15353 (dnsproxy)" -ForegroundColor Gray
    Write-Host "  - Port 9002 (SafeOps API)" -ForegroundColor Gray
    Write-Host "  - Port 8080 (mitmproxy)" -ForegroundColor Gray
} catch {
    Write-Host "Failed to configure firewall: $_" -ForegroundColor Red
}

# Summary
Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Green
Write-Host ""

if ($restartNeeded) {
    Write-Host "WARNING: RESTART REQUIRED" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Changes require a system restart to take effect:" -ForegroundColor Yellow
    Write-Host "  - WinpkFilter driver" -ForegroundColor Yellow
    Write-Host "  - IP Forwarding" -ForegroundColor Yellow
    Write-Host ""

    if (-not $SkipRestart) {
        $restart = Read-Host "Restart now? (Y/N)"
        if ($restart -eq "Y" -or $restart -eq "y") {
            Write-Host "Restarting in 10 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            Restart-Computer
        } else {
            Write-Host "Please restart manually before running SafeOps Engine" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "All changes applied successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next step: Build the SafeOps Engine" -ForegroundColor Cyan
    Write-Host "Run: cd D:\SafeOpsFV2\src\safeops-engine" -ForegroundColor Cyan
    Write-Host "Then: go build -o ..\..\bin\SafeOps-Engine.exe cmd\main.go" -ForegroundColor Cyan
}
