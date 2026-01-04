# SafeOps Phase 1-3 Service Startup Script
# ==========================================
# This script starts all SafeOps services in the correct dependency order.
#
# Services (in order):
#   1. NIC Management     (port 50054) - Network interface service
#   2. DHCP Monitor       (port 50055) - Device discovery & trust status
#   3. TLS Proxy          (port 50051, 50052) - Packet processing & DNS decisions
#   4. Certificate Manager (port 50060, 8082) - Certificate management
#   5. Captive Portal     (port 8444, 8080) - CA certificate download portal
#   6. Packet Engine      (Admin required) - WinDivert packet capture
#
# Prerequisites:
#   - PostgreSQL running on localhost:5432
#   - Database: threat_intel_db
#
# Usage:
#   .\start_safeops_services.ps1           # Start all services
#   .\start_safeops_services.ps1 -StopAll  # Stop all services

param(
    [switch]$StopAll
)

$ErrorActionPreference = "Continue"
$BinDir = "D:\SafeOpsFV2\bin"
$SrcDir = "D:\SafeOpsFV2\src"

# Service definitions: Name, Executable, WorkingDir, Port, RequiresAdmin
$Services = @(
    @{Name="NIC Management"; Exe="nic_management.exe"; Dir=$BinDir; Port=50054; Admin=$false},
    @{Name="DHCP Monitor"; Exe="dhcp_monitor.exe"; Dir="$SrcDir\dhcp_monitor"; Port=50055; Admin=$false},
    @{Name="TLS Proxy"; Exe="$BinDir\tls_proxy.exe"; Dir="$SrcDir\tls_proxy"; Port=50051; Admin=$false},
    @{Name="Certificate Manager"; Exe="certificate_manager.exe"; Dir=$BinDir; Port=50060; Admin=$false},
    @{Name="Captive Portal"; Exe="$BinDir\captive_portal.exe"; Dir="$SrcDir\captive_portal"; Port=8444; Admin=$false},
    @{Name="Packet Engine"; Exe="packet_engine.exe"; Dir=$BinDir; Port=$null; Admin=$true}
)

function Stop-AllServices {
    Write-Host "`n=== Stopping All SafeOps Services ===" -ForegroundColor Yellow
    $processNames = @("nic_management", "dhcp_monitor", "tls_proxy", "certificate_manager", "captive_portal", "packet_engine")
    foreach ($name in $processNames) {
        $proc = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "  Stopping $name (PID: $($proc.Id))..."
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "  All services stopped." -ForegroundColor Green
}

function Start-Service {
    param($Service)
    
    Write-Host "`n[$($Service.Name)]" -ForegroundColor Cyan
    
    $exePath = if ($Service.Exe -like "*\*") { $Service.Exe } else { Join-Path $Service.Dir $Service.Exe }
    
    if (-not (Test-Path $exePath)) {
        Write-Host "  ERROR: Executable not found: $exePath" -ForegroundColor Red
        return $false
    }
    
    $startParams = @{
        FilePath = "cmd"
        ArgumentList = "/k", "cd /d $($Service.Dir) && $exePath"
        WorkingDirectory = $Service.Dir
    }
    
    if ($Service.Admin) {
        $startParams.Verb = "RunAs"
        Write-Host "  Starting (requires Admin)..."
    } else {
        Write-Host "  Starting..."
    }
    
    Start-Process @startParams
    
    # Wait for service to start
    if ($Service.Port) {
        Start-Sleep 3
        $conn = Get-NetTCPConnection -LocalPort $Service.Port -ErrorAction SilentlyContinue
        if ($conn) {
            Write-Host "  ✓ Port $($Service.Port) LISTENING" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ! Port $($Service.Port) not yet bound (check terminal)" -ForegroundColor Yellow
            return $true
        }
    } else {
        Start-Sleep 2
        Write-Host "  ✓ Started (check terminal for status)" -ForegroundColor Green
        return $true
    }
}

# Main
Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║           SafeOps Phase 1-3 Service Manager                   ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

if ($StopAll) {
    Stop-AllServices
    exit 0
}

# Check PostgreSQL
Write-Host "[Prerequisites]" -ForegroundColor Yellow
$pg = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
if ($pg -and $pg.Status -eq "Running") {
    Write-Host "  ✓ PostgreSQL running" -ForegroundColor Green
} else {
    Write-Host "  ! PostgreSQL service not found (may be running differently)" -ForegroundColor Yellow
}

# Stop existing services first
Stop-AllServices

# Start services in order
Write-Host "`n=== Starting Services (Dependency Order) ===" -ForegroundColor Cyan

foreach ($svc in $Services) {
    $result = Start-Service -Service $svc
    if (-not $result) {
        Write-Host "`nERROR: Failed to start $($svc.Name). Aborting." -ForegroundColor Red
        exit 1
    }
    Start-Sleep 2
}

# Final status
Write-Host "`n=== Final Status ===" -ForegroundColor Green
Write-Host @"

Services Started:
  1. NIC Management     - http://localhost:50054
  2. DHCP Monitor       - gRPC localhost:50055
  3. TLS Proxy          - gRPC localhost:50051, DNS localhost:50052
  4. Certificate Manager - gRPC localhost:50060, HTTP localhost:8082
  5. Captive Portal     - HTTPS localhost:8444, HTTP localhost:8080
  6. Packet Engine      - WinDivert (Admin terminal)

Captive Portal URL: https://captive.safeops.local:8444/welcome

"@ -ForegroundColor White

Write-Host "All services started! Check individual terminals for status." -ForegroundColor Green
