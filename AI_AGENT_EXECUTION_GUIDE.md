# AI Agent Execution Guide - SafeOps with step-ca Integration

## Mission Brief
You are an AI agent responsible for:
1. Starting all SafeOps services in correct order
2. Monitoring logs from all services in real-time
3. Tracking device enrollment process step-by-step
4. Reporting any errors or issues immediately
5. Confirming when a device successfully enrolls

## ✨ Network Flexibility
SafeOps now works on **ANY network interface**:
- ✅ No need for Mobile Hotspot (192.168.137.x)
- ✅ Works on Ethernet, Wi-Fi, VMware, VirtualBox, etc.
- ✅ Auto-detects gateway IP at startup
- ✅ All services bind to 0.0.0.0 (all interfaces)
- ✅ DHCP/DNS use detected IP for device enrollment

The startup script will automatically detect your network and configure everything!

## Prerequisites Check

Before starting, verify these files exist:

```powershell
# Check step-ca binary
Test-Path "D:\SafeOpsFV2\certs\step-ca\step-ca.exe"

# Check step-ca configuration
Test-Path "D:\SafeOpsFV2\certs\step-ca\ca\config\ca.json"

# Check step-ca root CA certificate
Test-Path "D:\SafeOpsFV2\certs\safeops-root-ca.crt"

# Check service executables
Test-Path "D:\SafeOpsFV2\src\certificate_manager\certificate_manager.exe"
Test-Path "D:\SafeOpsFV2\src\dhcp_server\dhcp_server.exe"
Test-Path "D:\SafeOpsFV2\src\dns_server\cmd\dns_server\dns_server.exe"

# Check dashboard
Test-Path "D:\SafeOpsFV2\src\ui\dev\package.json"
```

**Expected Result**: All should return `True`

---

## Step 1: Create Centralized Log Directory

```powershell
# Create logs directory
$LOG_DIR = "D:\SafeOpsFV2\logs\$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $LOG_DIR -Force

Write-Host "✓ Logs will be saved to: $LOG_DIR" -ForegroundColor Green
```

**What to monitor**: Directory creation success

---

## Step 2: Start step-ca (Certificate Authority)

```powershell
# Service 1: step-ca
$STEP_CA_LOG = "$LOG_DIR\step-ca.log"

Write-Host "[1/5] Starting step-ca..." -ForegroundColor Cyan

$stepCA = Start-Process -FilePath "D:\SafeOpsFV2\certs\step-ca\step-ca.exe" `
    -ArgumentList "ca\config\ca.json", "--password-file", "ca\secrets\password.txt" `
    -WorkingDirectory "D:\SafeOpsFV2\certs\step-ca" `
    -RedirectStandardOutput "$STEP_CA_LOG" `
    -RedirectStandardError "$STEP_CA_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 3

# Check if running
if ($stepCA.HasExited) {
    Write-Host "✗ step-ca FAILED to start (Exit Code: $($stepCA.ExitCode))" -ForegroundColor Red
    Get-Content "$STEP_CA_LOG-error.log" | Select-Object -Last 20
    exit 1
} else {
    Write-Host "✓ step-ca RUNNING (PID: $($stepCA.Id))" -ForegroundColor Green
}

# Verify step-ca API is responding
Start-Sleep -Seconds 2
try {
    $health = Invoke-WebRequest -Uri "https://192.168.137.1:9000/health" -SkipCertificateCheck -TimeoutSec 5
    Write-Host "✓ step-ca API responding: HTTP $($health.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "⚠ step-ca API not responding yet (will retry)" -ForegroundColor Yellow
}
```

**What to monitor**:
- Process starts successfully
- No immediate exit
- Health endpoint responds (may take a few seconds)

**Expected log output** (`step-ca.log`):
```
Listening at https://192.168.137.1:9000 ...
```

---

## Step 3: Start Certificate Manager

```powershell
# Service 2: Certificate Manager
$CERT_MGR_LOG = "$LOG_DIR\certificate-manager.log"

Write-Host "[2/5] Starting Certificate Manager..." -ForegroundColor Cyan

$certManager = Start-Process -FilePath "D:\SafeOpsFV2\src\certificate_manager\certificate_manager.exe" `
    -WorkingDirectory "D:\SafeOpsFV2\src\certificate_manager" `
    -RedirectStandardOutput "$CERT_MGR_LOG" `
    -RedirectStandardError "$CERT_MGR_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 3

if ($certManager.HasExited) {
    Write-Host "✗ Certificate Manager FAILED (Exit Code: $($certManager.ExitCode))" -ForegroundColor Red
    Get-Content "$CERT_MGR_LOG-error.log" | Select-Object -Last 20
    exit 1
} else {
    Write-Host "✓ Certificate Manager RUNNING (PID: $($certManager.Id))" -ForegroundColor Green
}

# Verify API
Start-Sleep -Seconds 2
try {
    $health = Invoke-WebRequest -Uri "http://localhost:8082/health" -TimeoutSec 5
    Write-Host "✓ Certificate Manager API responding: HTTP $($health.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "⚠ Certificate Manager API not responding yet" -ForegroundColor Yellow
}
```

**Expected log output** (`certificate-manager.log`):
```
[INFO] Loading configuration...
[INFO] Initializing storage...
[INFO] Initializing step-ca client...
[INFO] step-ca connected successfully at https://192.168.137.1:9000
[INFO] Initializing ACME client...
[INFO] Initializing certificate manager...
[INFO] HTTP server listening on port 8082
[INFO] Certificate Manager started successfully
```

**Critical line to watch for**:
```
[INFO] step-ca connected successfully at https://192.168.137.1:9000
```

---

## Step 4: Start DHCP Server

```powershell
# Service 3: DHCP Server
$DHCP_LOG = "$LOG_DIR\dhcp-server.log"

Write-Host "[3/5] Starting DHCP Server..." -ForegroundColor Cyan

$dhcpServer = Start-Process -FilePath "D:\SafeOpsFV2\src\dhcp_server\dhcp_server.exe" `
    -WorkingDirectory "D:\SafeOpsFV2\src\dhcp_server" `
    -RedirectStandardOutput "$DHCP_LOG" `
    -RedirectStandardError "$DHCP_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 2

if ($dhcpServer.HasExited) {
    Write-Host "✗ DHCP Server FAILED (Exit Code: $($dhcpServer.ExitCode))" -ForegroundColor Red
    Get-Content "$DHCP_LOG-error.log" | Select-Object -Last 20
    exit 1
} else {
    Write-Host "✓ DHCP Server RUNNING (PID: $($dhcpServer.Id))" -ForegroundColor Green
}
```

**Expected log output** (`dhcp-server.log`):
```
[INFO] DHCP Server starting...
[INFO] Loaded CA URL: http://192.168.137.1:8082/ca/download
[INFO] Loaded WPAD URL: http://192.168.137.1:8080/wpad.dat
[INFO] Listening on 0.0.0.0:67
[INFO] CA Integration enabled: true
```

**Critical line to watch for**:
```
[INFO] Loaded CA URL: http://192.168.137.1:8082/ca/download
```

---

## Step 5: Start DNS Server

```powershell
# Service 4: DNS Server
$DNS_LOG = "$LOG_DIR\dns-server.log"

Write-Host "[4/5] Starting DNS Server..." -ForegroundColor Cyan

$dnsServer = Start-Process -FilePath "D:\SafeOpsFV2\src\dns_server\cmd\dns_server\dns_server.exe" `
    -ArgumentList "-captive", "-portal-ip", "192.168.137.1", "-portal-port", "8080" `
    -WorkingDirectory "D:\SafeOpsFV2\src\dns_server" `
    -RedirectStandardOutput "$DNS_LOG" `
    -RedirectStandardError "$DNS_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 2

if ($dnsServer.HasExited) {
    Write-Host "✗ DNS Server FAILED (Exit Code: $($dnsServer.ExitCode))" -ForegroundColor Red
    Get-Content "$DNS_LOG-error.log" | Select-Object -Last 20
    exit 1
} else {
    Write-Host "✓ DNS Server RUNNING (PID: $($dnsServer.Id))" -ForegroundColor Green
}
```

**Expected log output** (`dns-server.log`):
```
SafeOps DNS Server starting...
  Listen: :53
  Captive Portal: true (IP: 192.168.137.1)
Captive portal enabled: redirect to 192.168.137.1
DNS Server running on :53
```

**Critical line to watch for**:
```
Captive portal enabled: redirect to 192.168.137.1
```

---

## Step 6: Start Dashboard

```powershell
# Service 5: Dashboard
$DASHBOARD_LOG = "$LOG_DIR\dashboard.log"

Write-Host "[5/5] Starting Dashboard..." -ForegroundColor Cyan

Set-Location "D:\SafeOpsFV2\src\ui\dev"

$dashboard = Start-Process -FilePath "npm" `
    -ArgumentList "run", "dev" `
    -WorkingDirectory "D:\SafeOpsFV2\src\ui\dev" `
    -RedirectStandardOutput "$DASHBOARD_LOG" `
    -RedirectStandardError "$DASHBOARD_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 5

if ($dashboard.HasExited) {
    Write-Host "✗ Dashboard FAILED (Exit Code: $($dashboard.ExitCode))" -ForegroundColor Red
    Get-Content "$DASHBOARD_LOG-error.log" | Select-Object -Last 20
    exit 1
} else {
    Write-Host "✓ Dashboard RUNNING (PID: $($dashboard.Id))" -ForegroundColor Green
}
```

**Expected log output** (`dashboard.log`):
```
VITE v5.x.x  ready in XXX ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

---

## Step 7: Verify All Services

```powershell
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Service Status Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$services = @(
    @{Name="step-ca";               PID=$stepCA.Id;       Port="9000";  URL="https://192.168.137.1:9000/health"},
    @{Name="Certificate Manager";   PID=$certManager.Id;  Port="8082";  URL="http://localhost:8082/health"},
    @{Name="DHCP Server";            PID=$dhcpServer.Id;   Port="67";    URL="N/A"},
    @{Name="DNS Server";             PID=$dnsServer.Id;    Port="53";    URL="N/A"},
    @{Name="Dashboard";              PID=$dashboard.Id;    Port="5173";  URL="http://localhost:5173"}
)

foreach ($svc in $services) {
    $process = Get-Process -Id $svc.PID -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "✓ $($svc.Name.PadRight(25)) PID: $($svc.PID.ToString().PadRight(6)) Port: $($svc.Port)" -ForegroundColor Green
    } else {
        Write-Host "✗ $($svc.Name.PadRight(25)) STOPPED" -ForegroundColor Red
    }
}

Write-Host "`nDashboard URLs:" -ForegroundColor Cyan
Write-Host "  Main:           http://localhost:5173" -ForegroundColor White
Write-Host "  Certificates:   http://localhost:5173/certificates" -ForegroundColor White
Write-Host "  step-ca Manager: http://localhost:5173/step-ca" -ForegroundColor White
Write-Host "`nLogs Directory:  $LOG_DIR" -ForegroundColor Yellow
```

---

## Step 8: Start Real-Time Log Monitoring

```powershell
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Starting Real-Time Log Monitor" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Create combined log monitor
$COMBINED_LOG = "$LOG_DIR\combined-realtime.log"

# Function to tail logs
function Watch-Logs {
    $logs = @(
        @{File="$STEP_CA_LOG";        Service="STEP-CA"},
        @{File="$CERT_MGR_LOG";       Service="CERT-MGR"},
        @{File="$DHCP_LOG";           Service="DHCP"},
        @{File="$DNS_LOG";            Service="DNS"},
        @{File="$DASHBOARD_LOG";      Service="DASHBOARD"}
    )

    Write-Host "Monitoring logs... (Press Ctrl+C to stop)" -ForegroundColor Yellow
    Write-Host ""

    while ($true) {
        foreach ($log in $logs) {
            if (Test-Path $log.File) {
                $newLines = Get-Content $log.File -Tail 5 -ErrorAction SilentlyContinue
                foreach ($line in $newLines) {
                    $timestamp = Get-Date -Format "HH:mm:ss.fff"
                    $logLine = "[$timestamp] [$($log.Service)] $line"

                    # Color-code based on content
                    if ($line -match "ERROR|FATAL|FAIL") {
                        Write-Host $logLine -ForegroundColor Red
                    }
                    elseif ($line -match "WARN|WARNING") {
                        Write-Host $logLine -ForegroundColor Yellow
                    }
                    elseif ($line -match "DHCP.*DISCOVER|DHCP.*OFFER|DHCP.*REQUEST|DHCP.*ACK") {
                        Write-Host $logLine -ForegroundColor Cyan
                    }
                    elseif ($line -match "DNS.*query|DNS.*redirect|captive") {
                        Write-Host $logLine -ForegroundColor Magenta
                    }
                    elseif ($line -match "certificate|CA|enrollment") {
                        Write-Host $logLine -ForegroundColor Green
                    }
                    else {
                        Write-Host $logLine -ForegroundColor Gray
                    }

                    # Save to combined log
                    Add-Content -Path $COMBINED_LOG -Value $logLine
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }
}

# Start log monitoring in background
Start-Job -ScriptBlock ${function:Watch-Logs} -Name "LogMonitor"
```

---

## Step 9: Device Enrollment Detection Script

```powershell
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Device Enrollment Tracker" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Track device enrollment stages
function Track-DeviceEnrollment {
    $ENROLLMENT_LOG = "$LOG_DIR\device-enrollment-tracker.log"

    Write-Host "Waiting for device to connect..." -ForegroundColor Yellow
    Write-Host ""

    $deviceMAC = $null
    $deviceIP = $null
    $enrollmentStages = @{
        "DHCP_DISCOVER" = $false
        "DHCP_OFFER" = $false
        "DHCP_REQUEST" = $false
        "DHCP_ACK" = $false
        "CA_URL_SENT" = $false
        "DNS_QUERY" = $false
        "DNS_REDIRECT" = $false
        "PORTAL_ACCESS" = $false
        "CA_DOWNLOAD" = $false
        "ENROLLED" = $false
    }

    while ($true) {
        # Monitor DHCP log for device activity
        if (Test-Path $DHCP_LOG) {
            $dhcpLines = Get-Content $DHCP_LOG -Tail 50

            # Stage 1: DHCP DISCOVER
            if (!$enrollmentStages["DHCP_DISCOVER"]) {
                $discover = $dhcpLines | Select-String "DISCOVER" | Select-Object -Last 1
                if ($discover) {
                    $enrollmentStages["DHCP_DISCOVER"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] ✓ Stage 1: DHCP DISCOVER received" -ForegroundColor Green
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DHCP DISCOVER"

                    # Extract MAC address
                    if ($discover -match "MAC:\s*([0-9A-Fa-f:]{17})") {
                        $deviceMAC = $matches[1]
                        Write-Host "           Device MAC: $deviceMAC" -ForegroundColor Cyan
                    }
                }
            }

            # Stage 2: DHCP OFFER
            if ($enrollmentStages["DHCP_DISCOVER"] -and !$enrollmentStages["DHCP_OFFER"]) {
                $offer = $dhcpLines | Select-String "OFFER" | Select-Object -Last 1
                if ($offer) {
                    $enrollmentStages["DHCP_OFFER"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] ✓ Stage 2: DHCP OFFER sent" -ForegroundColor Green
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DHCP OFFER"

                    if ($offer -match "IP:\s*(\d+\.\d+\.\d+\.\d+)") {
                        $deviceIP = $matches[1]
                        Write-Host "           Offered IP: $deviceIP" -ForegroundColor Cyan
                    }
                }
            }

            # Stage 3: DHCP REQUEST
            if ($enrollmentStages["DHCP_OFFER"] -and !$enrollmentStages["DHCP_REQUEST"]) {
                $request = $dhcpLines | Select-String "REQUEST" | Select-Object -Last 1
                if ($request) {
                    $enrollmentStages["DHCP_REQUEST"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] ✓ Stage 3: DHCP REQUEST received" -ForegroundColor Green
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DHCP REQUEST"
                }
            }

            # Stage 4: DHCP ACK + CA URL
            if ($enrollmentStages["DHCP_REQUEST"] -and !$enrollmentStages["DHCP_ACK"]) {
                $ack = $dhcpLines | Select-String "ACK" | Select-Object -Last 1
                if ($ack) {
                    $enrollmentStages["DHCP_ACK"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] ✓ Stage 4: DHCP ACK sent" -ForegroundColor Green
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DHCP ACK"

                    # Check if CA URL was sent (Option 224)
                    $caOption = $dhcpLines | Select-String "Option 224|CA URL" | Select-Object -Last 1
                    if ($caOption) {
                        $enrollmentStages["CA_URL_SENT"] = $true
                        Write-Host "[$timestamp] ✓ Stage 5: CA URL sent via DHCP Option 224" -ForegroundColor Green
                        Write-Host "           CA URL: http://192.168.137.1:8082/ca/download" -ForegroundColor Cyan
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] CA URL SENT"
                    }
                }
            }
        }

        # Monitor DNS log for queries and redirects
        if (Test-Path $DNS_LOG) {
            $dnsLines = Get-Content $DNS_LOG -Tail 50

            # Stage 6: DNS Query
            if ($enrollmentStages["DHCP_ACK"] -and !$enrollmentStages["DNS_QUERY"]) {
                $query = $dnsLines | Select-String "query.*$deviceIP" | Select-Object -Last 1
                if ($query) {
                    $enrollmentStages["DNS_QUERY"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] ✓ Stage 6: DNS query received from device" -ForegroundColor Green
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DNS QUERY"
                }
            }

            # Stage 7: Captive Portal Redirect
            if ($enrollmentStages["DNS_QUERY"] -and !$enrollmentStages["DNS_REDIRECT"]) {
                $redirect = $dnsLines | Select-String "redirect|captive" | Select-Object -Last 1
                if ($redirect) {
                    $enrollmentStages["DNS_REDIRECT"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] ✓ Stage 7: DNS redirected to captive portal" -ForegroundColor Green
                    Write-Host "           Portal: http://192.168.137.1:8080/install" -ForegroundColor Cyan
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DNS REDIRECT"
                }
            }
        }

        # Monitor Certificate Manager log for downloads
        if (Test-Path $CERT_MGR_LOG) {
            $certLines = Get-Content $CERT_MGR_LOG -Tail 50

            # Stage 8: Portal Access
            if ($enrollmentStages["DNS_REDIRECT"] -and !$enrollmentStages["PORTAL_ACCESS"]) {
                $portalHit = $certLines | Select-String "GET /install|GET /ca" | Select-Object -Last 1
                if ($portalHit) {
                    $enrollmentStages["PORTAL_ACCESS"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] ✓ Stage 8: Device accessed captive portal" -ForegroundColor Green
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] PORTAL ACCESS"
                }
            }

            # Stage 9: CA Download
            if ($enrollmentStages["PORTAL_ACCESS"] -and !$enrollmentStages["CA_DOWNLOAD"]) {
                $download = $certLines | Select-String "GET /ca/download|ca.crt" | Select-Object -Last 1
                if ($download) {
                    $enrollmentStages["CA_DOWNLOAD"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] ✓ Stage 9: CA certificate downloaded!" -ForegroundColor Green
                    Write-Host "           File: safeops-root-ca.crt" -ForegroundColor Cyan
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] CA DOWNLOADED"
                }
            }

            # Stage 10: Enrollment Complete
            if ($enrollmentStages["CA_DOWNLOAD"] -and !$enrollmentStages["ENROLLED"]) {
                $enrolled = $certLines | Select-String "enrollment.*complete|device.*enrolled" | Select-Object -Last 1
                if ($enrolled) {
                    $enrollmentStages["ENROLLED"] = $true
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host ""
                    Write-Host "========================================" -ForegroundColor Green
                    Write-Host "  ✓ DEVICE ENROLLMENT COMPLETE!" -ForegroundColor Green
                    Write-Host "========================================" -ForegroundColor Green
                    Write-Host "  Device MAC: $deviceMAC" -ForegroundColor Cyan
                    Write-Host "  Device IP:  $deviceIP" -ForegroundColor Cyan
                    Write-Host "  Timestamp:  $timestamp" -ForegroundColor Cyan
                    Write-Host ""
                    Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] ENROLLMENT COMPLETE"

                    # Exit tracking loop
                    break
                }
            }
        }

        Start-Sleep -Milliseconds 500
    }

    Write-Host "Enrollment tracking complete. Full log: $ENROLLMENT_LOG" -ForegroundColor Yellow
}

# Start enrollment tracker
Track-DeviceEnrollment
```

---

## Step 10: Final Summary Report

```powershell
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Final Status Report" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Service Status
Write-Host "Services Running:" -ForegroundColor White
Get-Process | Where-Object {
    $_.ProcessName -match "step-ca|certificate_manager|dhcp_server|dns_server|node"
} | Format-Table ProcessName, Id, CPU, WorkingSet -AutoSize

# Log File Sizes
Write-Host "`nLog Files Generated:" -ForegroundColor White
Get-ChildItem $LOG_DIR -Filter "*.log" | Format-Table Name, Length, LastWriteTime -AutoSize

# Network Listeners
Write-Host "`nActive Network Listeners:" -ForegroundColor White
netstat -ano | Select-String ":53 |:67 |:8082 |:9000 |:5173 "

Write-Host "`n✓ All logs saved to: $LOG_DIR" -ForegroundColor Green
Write-Host "✓ Combined real-time log: $LOG_DIR\combined-realtime.log" -ForegroundColor Green
Write-Host "✓ Enrollment tracker log: $LOG_DIR\device-enrollment-tracker.log" -ForegroundColor Green
```

---

## Complete Execution Script

Save this as `D:\SafeOpsFV2\start-and-monitor-complete.ps1`:

```powershell
# SafeOps Complete Startup + Monitoring Script
# For AI Agent Execution

# [Paste all steps above in sequence]
# Steps 1-10 combined into single executable script

Write-Host "SafeOps Complete Stack - AI Agent Monitor" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Execute all steps...
# [Steps 1-10 here]

Write-Host "`nMonitoring complete. Press any key to stop all services..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Cleanup
Stop-Process -Id $stepCA.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $certManager.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $dhcpServer.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $dnsServer.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $dashboard.Id -Force -ErrorAction SilentlyContinue

Write-Host "All services stopped." -ForegroundColor Green
```

---

## What the AI Agent Should Report

### At Each Stage:
1. **Service Start**: Report PID and port
2. **Health Check**: Report HTTP status code
3. **Log Activity**: Report key log lines
4. **Device Events**: Report DHCP/DNS/Certificate events
5. **Errors**: Immediately report any errors with context

### Expected Timeline for Device Enrollment:

```
T+0s    : Device connects to network
T+1s    : DHCP DISCOVER received
T+2s    : DHCP OFFER sent (with CA URL in Option 224)
T+3s    : DHCP REQUEST received
T+4s    : DHCP ACK sent (device has IP + CA URL)
T+5-10s : User opens browser
T+11s   : DNS query received
T+12s   : DNS redirects to captive portal (192.168.137.1)
T+13s   : Browser loads captive portal page
T+20s   : User clicks "Download Certificate"
T+21s   : CA certificate downloads (safeops-root-ca.crt)
T+30s   : User installs certificate
T+31s   : Device enrollment COMPLETE!
```

---

## Error Scenarios to Watch For

| Error | Log Location | Solution |
|-------|-------------|----------|
| step-ca won't start | `step-ca-error.log` | Check password file exists |
| Port 9000 in use | `step-ca.log` | Kill conflicting process |
| Certificate Manager can't connect to step-ca | `certificate-manager.log` | Verify step-ca is running |
| DHCP not sending CA URL | `dhcp-server.log` | Check config.go has CAURL set |
| DNS not redirecting | `dns-server.log` | Verify captive portal enabled |
| Dashboard won't start | `dashboard-error.log` | Run `npm install` first |

---

## AI Agent Success Criteria

✅ All 5 services start without errors
✅ All health endpoints respond
✅ DHCP sends Option 224 (CA URL) in OFFER
✅ DNS redirects unenrolled devices to portal
✅ Device successfully downloads CA certificate
✅ No errors in any log files
✅ Complete enrollment tracked from start to finish

**Mission Complete When**: A device successfully enrolls and you can confirm all 10 enrollment stages!
