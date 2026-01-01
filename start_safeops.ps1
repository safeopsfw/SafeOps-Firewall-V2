# SafeOps Services Startup Script
# This script starts all SafeOps services with correct configuration
# Run as Administrator for DNS (port 53)

param(
    [switch]$StartHotspot,
    [switch]$NoDashboard
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    SafeOps Services Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin rights (needed for port 53)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[WARN] Not running as Administrator!" -ForegroundColor Yellow
    Write-Host "       DNS (port 53) may fail to bind." -ForegroundColor Yellow
    Write-Host ""
}

# Stop any existing services
Write-Host "[INFO] Stopping any existing services..." -ForegroundColor Yellow
Stop-Process -Name dhcp_server, dns_server, nic_api -Force -ErrorAction SilentlyContinue
taskkill /F /IM node.exe 2>$null | Out-Null
Start-Sleep -Seconds 2

# Auto-detect local IP (any non-loopback, non-link-local IPv4)
Write-Host "[INFO] Detecting network configuration..." -ForegroundColor Yellow
$hotspotIP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    Select-Object -First 1).IPAddress

if ($hotspotIP) {
    Write-Host "       Gateway IP: $hotspotIP" -ForegroundColor Green
}
else {
    Write-Host "       ERROR: No network interface found!" -ForegroundColor Red
    Write-Host "       Please connect to a network and try again." -ForegroundColor Red
    exit 1
}

# Create logs directory
$logsDir = Join-Path $ScriptDir "logs"
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir | Out-Null
}

# Function to start a service
function Start-SafeOpsService {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Arguments = "",
        [string]$WorkingDir
    )
    
    if (-not (Test-Path $Path)) {
        Write-Host "[ERROR] $Name not found at: $Path" -ForegroundColor Red
        return $false
    }
    
    $startInfo = @{
        FilePath         = $Path
        WorkingDirectory = $WorkingDir
        WindowStyle      = "Minimized"
    }
    
    if ($Arguments) {
        $startInfo.ArgumentList = $Arguments -split " "
    }
    
    try {
        Start-Process @startInfo
        Write-Host "[OK] $Name started" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to start ${Name}: $_" -ForegroundColor Red
        return $false
    }
}

Write-Host ""
Write-Host "[STEP 1] Starting NIC Management API..." -ForegroundColor Cyan  
Start-SafeOpsService -Name "NIC API" `
    -Path (Join-Path $ScriptDir "src\nic_management\api\nic_api.exe") `
    -WorkingDir (Join-Path $ScriptDir "src\nic_management\api")

Start-Sleep -Seconds 1

Write-Host "[STEP 2] Starting DNS Server (portal: $hotspotIP)..." -ForegroundColor Cyan
$dnsArgs = "-captive true -portal-ip $hotspotIP -portal-port 8093"
Start-SafeOpsService -Name "DNS Server" `
    -Path (Join-Path $ScriptDir "src\dns_server\dns_server.exe") `
    -Arguments $dnsArgs `
    -WorkingDir (Join-Path $ScriptDir "src\dns_server")

Start-Sleep -Seconds 1

Write-Host "[STEP 3] Starting DHCP Server..." -ForegroundColor Cyan
Start-SafeOpsService -Name "DHCP Server" `
    -Path (Join-Path $ScriptDir "src\dhcp_server\dhcp_server.exe") `
    -WorkingDir (Join-Path $ScriptDir "src\dhcp_server")

Start-Sleep -Seconds 1

if (-not $NoDashboard) {
    Write-Host "[STEP 4] Starting Dashboard..." -ForegroundColor Cyan
    $dashboardDir = Join-Path $ScriptDir "src\ui\dev"
    if (Test-Path $dashboardDir) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm run dev" `
            -WorkingDirectory $dashboardDir -WindowStyle Normal
        Write-Host "[OK] Dashboard started" -ForegroundColor Green
    }
}

Start-Sleep -Seconds 2

# Verify services
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Service Status" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$services = @(
    @{Name = "NIC API"; Process = "nic_api"; Port = "8081" },
    @{Name = "DNS Server"; Process = "dns_server"; Port = "53" },
    @{Name = "DHCP Server"; Process = "dhcp_server"; Port = "67" }
)

foreach ($svc in $services) {
    $proc = Get-Process -Name $svc.Process -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "[RUNNING] $($svc.Name) (PID: $($proc.Id)) - Port(s): $($svc.Port)" -ForegroundColor Green
    }
    else {
        Write-Host "[STOPPED] $($svc.Name)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Access URLs" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Dashboard:       http://localhost:3001" -ForegroundColor White
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
