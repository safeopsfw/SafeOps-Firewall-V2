# ============================================================================
# Start All SafeOps Services - Proper Order with Dependency Checks
# ============================================================================
# Purpose: Start all services in the correct order with health checks
# Date: 2026-01-04
# ============================================================================

param(
    [switch]$EnableMITM = $false,
    [switch]$SkipDNS = $false,
    [switch]$SkipDHCP = $false
)

$ErrorActionPreference = "Continue"
$BinPath = "D:\SafeOpsFV2\bin"
$ScriptPath = "D:\SafeOpsFV2\scripts"

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  SafeOps Service Startup" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# Helper function to check if port is open
function Test-Port {
    param([int]$Port)
    $connection = New-Object System.Net.Sockets.TcpClient
    try {
        $connection.Connect("localhost", $Port)
        $connection.Close()
        return $true
    } catch {
        return $false
    }
}

# Helper function to wait for service
function Wait-ForService {
    param(
        [string]$Name,
        [int]$Port,
        [int]$TimeoutSeconds = 10
    )

    Write-Host "  Waiting for $Name to start..." -NoNewline
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        if (Test-Port -Port $Port) {
            Write-Host " OK" -ForegroundColor Green
            return $true
        }
        Start-Sleep -Milliseconds 500
        $elapsed++
        Write-Host "." -NoNewline
    }
    Write-Host " TIMEOUT" -ForegroundColor Red
    return $false
}

# ============================================================================
# Step 1: PostgreSQL (for DHCP Monitor)
# ============================================================================
if (-not $SkipDHCP) {
    Write-Host "[1/7] Checking PostgreSQL..." -ForegroundColor Yellow

    $pgService = Get-Service -Name postgresql* -ErrorAction SilentlyContinue

    if ($pgService -eq $null) {
        Write-Host "  WARNING: PostgreSQL not found - DHCP Monitor will not work" -ForegroundColor Red
        Write-Host "  Continuing without DHCP Monitor..." -ForegroundColor Yellow
        $SkipDHCP = $true
    } elseif ($pgService.Status -ne "Running") {
        Write-Host "  Starting PostgreSQL..." -ForegroundColor Yellow
        Start-Service $pgService.Name
        Start-Sleep -Seconds 3
        Write-Host "  PostgreSQL started" -ForegroundColor Green
    } else {
        Write-Host "  PostgreSQL is running" -ForegroundColor Green
    }

    if (-not $SkipDHCP) {
        # Check if database exists
        $dbExists = & psql -U postgres -lqt 2>&1 | Select-String "safeops_network"
        if (-not $dbExists) {
            Write-Host "  WARNING: Database 'safeops_network' not found" -ForegroundColor Red
            Write-Host "  Run: .\scripts\fix_postgresql_dhcp_monitor.ps1" -ForegroundColor Yellow
            $SkipDHCP = $true
        }
    }
}

Write-Host ""

# ============================================================================
# Step 2: DHCP Monitor (for device trust tracking)
# ============================================================================
if (-not $SkipDHCP) {
    Write-Host "[2/7] Starting DHCP Monitor..." -ForegroundColor Yellow

    if (Test-Port -Port 50055) {
        Write-Host "  DHCP Monitor already running on port 50055" -ForegroundColor Yellow
    } else {
        Start-Process -FilePath "$BinPath\dhcp_monitor.exe" -WorkingDirectory $BinPath

        if (Wait-ForService -Name "DHCP Monitor" -Port 50055) {
            Write-Host "  DHCP Monitor started successfully" -ForegroundColor Green
        } else {
            Write-Host "  WARNING: DHCP Monitor failed to start" -ForegroundColor Red
            Write-Host "  Continuing without device trust tracking..." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[2/7] Skipping DHCP Monitor (not available)" -ForegroundColor Gray
}

Write-Host ""

# ============================================================================
# Step 3: Step-CA (for certificate generation)
# ============================================================================
Write-Host "[3/7] Starting Step-CA..." -ForegroundColor Yellow

if (Test-Port -Port 9000) {
    Write-Host "  Step-CA already running on port 9000" -ForegroundColor Yellow
} else {
    $stepCAConfig = "$BinPath\config\ca.json"

    if (-not (Test-Path $stepCAConfig)) {
        Write-Host "  ERROR: Step-CA config not found: $stepCAConfig" -ForegroundColor Red
        Write-Host "  Please configure Step-CA first" -ForegroundColor Red
        exit 1
    }

    Start-Process -FilePath "$BinPath\step-ca.exe" -ArgumentList $stepCAConfig -WorkingDirectory $BinPath

    if (Wait-ForService -Name "Step-CA" -Port 9000 -TimeoutSeconds 15) {
        Write-Host "  Step-CA started successfully" -ForegroundColor Green
    } else {
        Write-Host "  ERROR: Step-CA failed to start" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""

# ============================================================================
# Step 4: DNS Server (CRITICAL - port 53)
# ============================================================================
if (-not $SkipDNS) {
    Write-Host "[4/7] Starting DNS Server..." -ForegroundColor Yellow

    # Check if port 53 is available
    $port53Used = netstat -ano | Select-String "UDP.*:53\s" | Measure-Object

    if ($port53Used.Count -gt 2) {
        Write-Host "  WARNING: Port 53 has multiple processes" -ForegroundColor Yellow
        Write-Host "  Checking if our DNS server is already running..." -ForegroundColor Yellow

        $dnsProcess = Get-Process -Name dns_server -ErrorAction SilentlyContinue
        if ($dnsProcess) {
            Write-Host "  DNS Server already running (PID: $($dnsProcess.Id))" -ForegroundColor Green
        } else {
            Write-Host "  Starting DNS Server with SO_REUSEADDR..." -ForegroundColor Yellow
            Start-Process -FilePath "$BinPath\dns_server.exe" -WorkingDirectory $BinPath
            Start-Sleep -Seconds 2
            Write-Host "  DNS Server started" -ForegroundColor Green
        }
    } else {
        Start-Process -FilePath "$BinPath\dns_server.exe" -WorkingDirectory $BinPath
        Start-Sleep -Seconds 2
        Write-Host "  DNS Server started" -ForegroundColor Green
    }
} else {
    Write-Host "[4/7] Skipping DNS Server" -ForegroundColor Gray
}

Write-Host ""

# ============================================================================
# Step 5: Captive Portal
# ============================================================================
Write-Host "[5/7] Starting Captive Portal..." -ForegroundColor Yellow

if (Test-Port -Port 8444) {
    Write-Host "  Captive Portal already running on port 8444" -ForegroundColor Yellow
} else {
    Start-Process -FilePath "$BinPath\captive_portal.exe" -WorkingDirectory $BinPath

    if (Wait-ForService -Name "Captive Portal" -Port 8444) {
        Write-Host "  Captive Portal started successfully" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Captive Portal failed to start" -ForegroundColor Red
    }
}

Write-Host ""

# ============================================================================
# Step 6: TLS Proxy (with optional MITM)
# ============================================================================
Write-Host "[6/7] Starting TLS Proxy..." -ForegroundColor Yellow

if (Test-Port -Port 50051) {
    Write-Host "  TLS Proxy already running on port 50051" -ForegroundColor Yellow
} else {
    # Set environment variable for MITM
    if ($EnableMITM) {
        $env:TLS_PROXY_ENABLE_MITM = "true"
        Write-Host "  MITM inspection enabled" -ForegroundColor Cyan
    }

    Start-Process -FilePath "$BinPath\tls_proxy.exe" -WorkingDirectory $BinPath

    if (Wait-ForService -Name "TLS Proxy" -Port 50051 -TimeoutSeconds 15) {
        Write-Host "  TLS Proxy started successfully" -ForegroundColor Green

        if ($EnableMITM) {
            Start-Sleep -Seconds 2
            if (Test-Port -Port 443) {
                Write-Host "  Transparent HTTPS Proxy listening on port 443" -ForegroundColor Green
            } else {
                Write-Host "  WARNING: Transparent proxy not listening on port 443" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  ERROR: TLS Proxy failed to start" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""

# ============================================================================
# Step 7: Packet Engine (LAST - needs all services running)
# ============================================================================
Write-Host "[7/7] Starting Packet Engine..." -ForegroundColor Yellow

$packetProcess = Get-Process -Name packet_engine -ErrorAction SilentlyContinue
if ($packetProcess) {
    Write-Host "  Packet Engine already running (PID: $($packetProcess.Id))" -ForegroundColor Yellow
} else {
    Write-Host "  Starting Packet Engine..." -ForegroundColor Yellow
    Start-Process -FilePath "$BinPath\packet_engine.exe" -WorkingDirectory $BinPath
    Start-Sleep -Seconds 2
    Write-Host "  Packet Engine started" -ForegroundColor Green
}

Write-Host ""

# ============================================================================
# Service Status Summary
# ============================================================================
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Service Status Summary" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

$services = @(
    @{Name="PostgreSQL";        Port=5432;  Process="postgres"},
    @{Name="DHCP Monitor";      Port=50055; Process="dhcp_monitor"},
    @{Name="Step-CA";           Port=9000;  Process="step-ca"},
    @{Name="DNS Server";        Port=53;    Process="dns_server"},
    @{Name="Captive Portal";    Port=8444;  Process="captive_portal"},
    @{Name="TLS Proxy (gRPC)";  Port=50051; Process="tls_proxy"},
    @{Name="TLS Proxy (HTTPS)"; Port=443;   Process="tls_proxy"},
    @{Name="Packet Engine";     Port=0;     Process="packet_engine"}
)

foreach ($service in $services) {
    $status = " "

    if ($service.Port -eq 0) {
        # Process-only check
        $proc = Get-Process -Name $service.Process -ErrorAction SilentlyContinue
        if ($proc) {
            $status = "[RUNNING]"
            $color = "Green"
        } else {
            $status = "[STOPPED]"
            $color = "Red"
        }
    } else {
        # Port check
        if (Test-Port -Port $service.Port) {
            $status = "[RUNNING]"
            $color = "Green"
        } else {
            $status = "[STOPPED]"
            $color = "Yellow"
        }
    }

    Write-Host "  $($service.Name.PadRight(20)) " -NoNewline
    Write-Host "$status" -ForegroundColor $color
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  All services started!" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

if ($EnableMITM) {
    Write-Host "MITM Inspection: ENABLED" -ForegroundColor Cyan
    Write-Host "  Devices that install the CA certificate will have" -ForegroundColor Gray
    Write-Host "  their HTTPS traffic decrypted and inspected." -ForegroundColor Gray
} else {
    Write-Host "MITM Inspection: DISABLED" -ForegroundColor Yellow
    Write-Host "  To enable HTTPS inspection, use: -EnableMITM" -ForegroundColor Gray
}

Write-Host ""
Write-Host "To stop all services:" -ForegroundColor Gray
Write-Host "  .\scripts\stop_all_services.ps1" -ForegroundColor Gray
Write-Host ""
