# SafeOps Complete Stack - AI Agent Monitor
# Starts all services + Real-time monitoring + Device enrollment tracking

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SafeOps Complete Stack" -ForegroundColor Cyan
Write-Host "  AI Agent Monitor v1.0" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Detect Local Gateway IP
Write-Host "Detecting network interface..." -ForegroundColor Cyan
$GATEWAY_IP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    Select-Object -First 1).IPAddress

if (-not $GATEWAY_IP) {
    Write-Host "✗ No network interface found! Please connect to a network." -ForegroundColor Red
    exit 1
}

Write-Host "  ✓ Using Gateway IP: $GATEWAY_IP" -ForegroundColor Green
Write-Host ""

# Step 0.5: Check Database (Optional)
Write-Host "Checking database..." -ForegroundColor Cyan
$pgService = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
if ($pgService) {
    if ($pgService.Status -eq "Running") {
        Write-Host "  ✓ PostgreSQL service running" -ForegroundColor Green
        Write-Host "  ℹ To initialize database: .\database\init_all_databases.ps1" -ForegroundColor Gray
    } else {
        Write-Host "  ⚠ PostgreSQL installed but not running" -ForegroundColor Yellow
        Write-Host "  Start with: Start-Service $($pgService.Name)" -ForegroundColor Gray
    }
} else {
    Write-Host "  ℹ PostgreSQL not detected (optional - services work without it)" -ForegroundColor Gray
}
Write-Host ""

# Step 1: Use Single Log Directory (Always Updated)
$LOG_DIR = "D:\SafeOpsFV2\logs"
New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null

# Clear all previous log files
Write-Host "Clearing previous logs..." -ForegroundColor Cyan
Get-ChildItem -Path $LOG_DIR -Filter "*.log" -File | Remove-Item -Force -ErrorAction SilentlyContinue
Write-Host "✓ Logs directory: $LOG_DIR (cleared)" -ForegroundColor Green
Write-Host ""

# Step 2: Start step-ca
Write-Host "[1/7] Starting step-ca..." -ForegroundColor Cyan
$STEP_CA_LOG = "$LOG_DIR\step-ca.log"
$stepCA = Start-Process -FilePath "D:\SafeOpsFV2\certs\step-ca\step-ca.exe" `
    -ArgumentList "ca\config\ca.json", "--password-file", "ca\secrets\password.txt" `
    -WorkingDirectory "D:\SafeOpsFV2\certs\step-ca" `
    -RedirectStandardOutput "$STEP_CA_LOG" `
    -RedirectStandardError "$STEP_CA_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 3
if ($stepCA.HasExited) {
    Write-Host "✗ step-ca FAILED (Exit: $($stepCA.ExitCode))" -ForegroundColor Red
    Get-Content "$STEP_CA_LOG-error.log"
    exit 1
}
Write-Host "  ✓ PID: $($stepCA.Id) | Port: 9000" -ForegroundColor Green

# Step 3: Start Certificate Manager
Write-Host "[2/7] Starting Certificate Manager..." -ForegroundColor Cyan
$CERT_MGR_LOG = "$LOG_DIR\certificate-manager.log"
$certManager = Start-Process -FilePath "D:\SafeOpsFV2\src\certificate_manager\certificate_manager.exe" `
    -WorkingDirectory "D:\SafeOpsFV2\src\certificate_manager" `
    -RedirectStandardOutput "$CERT_MGR_LOG" `
    -RedirectStandardError "$CERT_MGR_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 3
if ($certManager.HasExited) {
    Write-Host "✗ Certificate Manager FAILED (Exit: $($certManager.ExitCode))" -ForegroundColor Red
    Get-Content "$CERT_MGR_LOG-error.log"
    exit 1
}
Write-Host "  ✓ PID: $($certManager.Id) | Port: 8082" -ForegroundColor Green

# Step 4: Start DHCP Server
Write-Host "[3/7] Starting DHCP Server..." -ForegroundColor Cyan
$DHCP_LOG = "$LOG_DIR\dhcp-server.log"
$dhcpServer = Start-Process -FilePath "D:\SafeOpsFV2\src\dhcp_server\dhcp_server.exe" `
    -WorkingDirectory "D:\SafeOpsFV2\src\dhcp_server" `
    -RedirectStandardOutput "$DHCP_LOG" `
    -RedirectStandardError "$DHCP_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 2
if ($dhcpServer.HasExited) {
    Write-Host "✗ DHCP Server FAILED (Exit: $($dhcpServer.ExitCode))" -ForegroundColor Red
    Get-Content "$DHCP_LOG-error.log"
    exit 1
}
Write-Host "  ✓ PID: $($dhcpServer.Id) | Port: 67" -ForegroundColor Green

# Step 5: Start DNS Server
Write-Host "[4/7] Starting DNS Server..." -ForegroundColor Cyan
$DNS_LOG = "$LOG_DIR\dns-server.log"
$dnsServer = Start-Process -FilePath "D:\SafeOpsFV2\src\dns_server\dns_server.exe" `
    -ArgumentList "-captive", "-portal-ip", "$GATEWAY_IP", "-portal-port", "8080" `
    -WorkingDirectory "D:\SafeOpsFV2\src\dns_server" `
    -RedirectStandardOutput "$DNS_LOG" `
    -RedirectStandardError "$DNS_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 2
if ($dnsServer.HasExited) {
    Write-Host "✗ DNS Server FAILED (Exit: $($dnsServer.ExitCode))" -ForegroundColor Red
    Get-Content "$DNS_LOG-error.log"
    exit 1
}
Write-Host "  ✓ PID: $($dnsServer.Id) | Port: 53" -ForegroundColor Green

# Step 6: Start NIC Management API
Write-Host "[5/7] Starting NIC Management..." -ForegroundColor Cyan
$NIC_LOG = "$LOG_DIR\nic-api.log"
$nicAPI = Start-Process -FilePath "D:\SafeOpsFV2\src\nic_management_api\nic_api.exe" `
    -WorkingDirectory "D:\SafeOpsFV2\src\nic_management_api" `
    -RedirectStandardOutput "$NIC_LOG" `
    -RedirectStandardError "$NIC_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 2
if ($nicAPI.HasExited) {
    Write-Host "✗ NIC API FAILED (Exit: $($nicAPI.ExitCode))" -ForegroundColor Red
    Get-Content "$NIC_LOG-error.log"
    exit 1
}
Write-Host "  ✓ PID: $($nicAPI.Id) | Port: 8081" -ForegroundColor Green

# Step 7: Start Dashboard
Write-Host "[6/7] Starting Dashboard..." -ForegroundColor Cyan
$DASHBOARD_LOG = "$LOG_DIR\dashboard.log"
Set-Location "D:\SafeOpsFV2\src\ui\dev"
$dashboard = Start-Process -FilePath "npm" `
    -ArgumentList "run", "dev" `
    -WorkingDirectory "D:\SafeOpsFV2\src\ui\dev" `
    -RedirectStandardOutput "$DASHBOARD_LOG" `
    -RedirectStandardError "$DASHBOARD_LOG-error.log" `
    -PassThru `
    -WindowStyle Normal

Start-Sleep -Seconds 3
if ($dashboard.HasExited) {
    Write-Host "✗ Dashboard FAILED (Exit: $($dashboard.ExitCode))" -ForegroundColor Red
} else {
    Write-Host "  ✓ PID: $($dashboard.Id) | Port: 5173" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  All Services Started!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Service Ports:" -ForegroundColor Cyan
Write-Host "  step-ca:              9000" -ForegroundColor White
Write-Host "  Certificate Manager:  8082" -ForegroundColor White
Write-Host "  NIC Management:       8081" -ForegroundColor White
Write-Host "  DHCP Server:          67" -ForegroundColor White
Write-Host "  DNS Server:           53" -ForegroundColor White
Write-Host "  Dashboard:            5173" -ForegroundColor White
Write-Host ""
Write-Host "Dashboard URLs:" -ForegroundColor Cyan
Write-Host "  http://localhost:5173" -ForegroundColor White
Write-Host "  http://localhost:5173/network (NIC Management)" -ForegroundColor White
Write-Host "  http://localhost:5173/certificates" -ForegroundColor White
Write-Host "  http://localhost:5173/step-ca" -ForegroundColor White
Write-Host ""
Write-Host "Logs: $LOG_DIR" -ForegroundColor Yellow
Write-Host ""

# Step 7: Real-Time Log Monitor
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Real-Time Log Monitor" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$COMBINED_LOG = "$LOG_DIR\combined-realtime.log"
$ENROLLMENT_LOG = "$LOG_DIR\device-enrollment-tracker.log"

# Initialize enrollment tracker
$script:enrollmentStages = @{
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
$script:deviceMAC = $null
$script:deviceIP = $null
$script:lastLogSize = @{}

Write-Host "Monitoring for device enrollment..." -ForegroundColor Yellow
Write-Host "Connect a device to the network now!" -ForegroundColor Yellow
Write-Host ""

try {
    while ($true) {
        $timestamp = Get-Date -Format "HH:mm:ss.fff"

        # Monitor DHCP log
        if (Test-Path $DHCP_LOG) {
            $currentSize = (Get-Item $DHCP_LOG).Length
            if ($script:lastLogSize["DHCP"] -ne $currentSize) {
                $script:lastLogSize["DHCP"] = $currentSize
                $dhcpLines = Get-Content $DHCP_LOG -Tail 10

                foreach ($line in $dhcpLines) {
                    $logEntry = "[$timestamp] [DHCP] $line"

                    # Stage 1: DHCP DISCOVER
                    if (!$script:enrollmentStages["DHCP_DISCOVER"] -and $line -match "DISCOVER") {
                        $script:enrollmentStages["DHCP_DISCOVER"] = $true
                        Write-Host "[$timestamp] ✓ Stage 1: DHCP DISCOVER" -ForegroundColor Green
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DHCP DISCOVER"
                        if ($line -match "([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}") {
                            $script:deviceMAC = $matches[0]
                            Write-Host "           MAC: $($script:deviceMAC)" -ForegroundColor Cyan
                        }
                    }

                    # Stage 2: DHCP OFFER
                    if ($script:enrollmentStages["DHCP_DISCOVER"] -and !$script:enrollmentStages["DHCP_OFFER"] -and $line -match "OFFER") {
                        $script:enrollmentStages["DHCP_OFFER"] = $true
                        Write-Host "[$timestamp] ✓ Stage 2: DHCP OFFER sent" -ForegroundColor Green
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DHCP OFFER"
                        if ($line -match "(\d+\.\d+\.\d+\.\d+)") {
                            $script:deviceIP = $matches[1]
                            Write-Host "           IP: $($script:deviceIP)" -ForegroundColor Cyan
                        }
                    }

                    # Stage 3: DHCP REQUEST
                    if ($script:enrollmentStages["DHCP_OFFER"] -and !$script:enrollmentStages["DHCP_REQUEST"] -and $line -match "REQUEST") {
                        $script:enrollmentStages["DHCP_REQUEST"] = $true
                        Write-Host "[$timestamp] ✓ Stage 3: DHCP REQUEST received" -ForegroundColor Green
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DHCP REQUEST"
                    }

                    # Stage 4: DHCP ACK
                    if ($script:enrollmentStages["DHCP_REQUEST"] -and !$script:enrollmentStages["DHCP_ACK"] -and $line -match "ACK") {
                        $script:enrollmentStages["DHCP_ACK"] = $true
                        Write-Host "[$timestamp] ✓ Stage 4: DHCP ACK sent" -ForegroundColor Green
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DHCP ACK"
                    }

                    # Stage 5: CA URL sent
                    if ($script:enrollmentStages["DHCP_ACK"] -and !$script:enrollmentStages["CA_URL_SENT"] -and $line -match "Option 224|CA.*URL") {
                        $script:enrollmentStages["CA_URL_SENT"] = $true
                        Write-Host "[$timestamp] ✓ Stage 5: CA URL sent (Option 224)" -ForegroundColor Green
                        Write-Host "           URL: http://${GATEWAY_IP}:8082/ca/download" -ForegroundColor Cyan
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] CA URL SENT"
                    }

                    if ($line -match "ERROR|FAIL") {
                        Write-Host $logEntry -ForegroundColor Red
                    } elseif ($line -match "DISCOVER|OFFER|REQUEST|ACK") {
                        Write-Host $logEntry -ForegroundColor Cyan
                    }

                    Add-Content -Path $COMBINED_LOG -Value $logEntry
                }
            }
        }

        # Monitor DNS log
        if (Test-Path $DNS_LOG) {
            $currentSize = (Get-Item $DNS_LOG).Length
            if ($script:lastLogSize["DNS"] -ne $currentSize) {
                $script:lastLogSize["DNS"] = $currentSize
                $dnsLines = Get-Content $DNS_LOG -Tail 10

                foreach ($line in $dnsLines) {
                    $logEntry = "[$timestamp] [DNS] $line"

                    # Stage 6: DNS Query
                    if ($script:enrollmentStages["DHCP_ACK"] -and !$script:enrollmentStages["DNS_QUERY"] -and $line -match "query") {
                        $script:enrollmentStages["DNS_QUERY"] = $true
                        Write-Host "[$timestamp] ✓ Stage 6: DNS query from device" -ForegroundColor Green
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DNS QUERY"
                    }

                    # Stage 7: Captive Portal Redirect
                    if ($script:enrollmentStages["DNS_QUERY"] -and !$script:enrollmentStages["DNS_REDIRECT"] -and $line -match "redirect|captive") {
                        $script:enrollmentStages["DNS_REDIRECT"] = $true
                        Write-Host "[$timestamp] ✓ Stage 7: Redirected to captive portal" -ForegroundColor Green
                        Write-Host "           Portal: http://${GATEWAY_IP}:8080/install" -ForegroundColor Cyan
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] DNS REDIRECT"
                    }

                    if ($line -match "ERROR|FAIL") {
                        Write-Host $logEntry -ForegroundColor Red
                    } elseif ($line -match "query|redirect|captive") {
                        Write-Host $logEntry -ForegroundColor Magenta
                    }

                    Add-Content -Path $COMBINED_LOG -Value $logEntry
                }
            }
        }

        # Monitor Certificate Manager log
        if (Test-Path $CERT_MGR_LOG) {
            $currentSize = (Get-Item $CERT_MGR_LOG).Length
            if ($script:lastLogSize["CERT"] -ne $currentSize) {
                $script:lastLogSize["CERT"] = $currentSize
                $certLines = Get-Content $CERT_MGR_LOG -Tail 10

                foreach ($line in $certLines) {
                    $logEntry = "[$timestamp] [CERT] $line"

                    # Stage 8: Portal Access
                    if ($script:enrollmentStages["DNS_REDIRECT"] -and !$script:enrollmentStages["PORTAL_ACCESS"] -and $line -match "GET /install|GET /ca") {
                        $script:enrollmentStages["PORTAL_ACCESS"] = $true
                        Write-Host "[$timestamp] ✓ Stage 8: Portal accessed" -ForegroundColor Green
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] PORTAL ACCESS"
                    }

                    # Stage 9: CA Download
                    if ($script:enrollmentStages["PORTAL_ACCESS"] -and !$script:enrollmentStages["CA_DOWNLOAD"] -and $line -match "GET /ca/download|ca\.crt") {
                        $script:enrollmentStages["CA_DOWNLOAD"] = $true
                        Write-Host "[$timestamp] ✓ Stage 9: CA certificate downloaded!" -ForegroundColor Green
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] CA DOWNLOADED"
                    }

                    # Stage 10: Enrollment Complete
                    if ($script:enrollmentStages["CA_DOWNLOAD"] -and !$script:enrollmentStages["ENROLLED"]) {
                        $script:enrollmentStages["ENROLLED"] = $true
                        Write-Host ""
                        Write-Host "========================================" -ForegroundColor Green
                        Write-Host "  ✓ ENROLLMENT COMPLETE!" -ForegroundColor Green
                        Write-Host "========================================" -ForegroundColor Green
                        Write-Host "  MAC: $($script:deviceMAC)" -ForegroundColor Cyan
                        Write-Host "  IP:  $($script:deviceIP)" -ForegroundColor Cyan
                        Write-Host "  Time: $timestamp" -ForegroundColor Cyan
                        Write-Host ""
                        Add-Content -Path $ENROLLMENT_LOG -Value "[$timestamp] ENROLLMENT COMPLETE"
                    }

                    if ($line -match "ERROR|FAIL") {
                        Write-Host $logEntry -ForegroundColor Red
                    } elseif ($line -match "certificate|CA|download") {
                        Write-Host $logEntry -ForegroundColor Green
                    }

                    Add-Content -Path $COMBINED_LOG -Value $logEntry
                }
            }
        }

        Start-Sleep -Milliseconds 500
    }
}
finally {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  Shutting Down Services" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow

    Stop-Process -Id $dashboard.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $nicAPI.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $dnsServer.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $dhcpServer.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $certManager.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $stepCA.Id -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "✓ All services stopped" -ForegroundColor Green
    Write-Host "✓ Logs saved to: $LOG_DIR" -ForegroundColor Green
    Write-Host "✓ Combined log: $COMBINED_LOG" -ForegroundColor Green
    Write-Host "✓ Enrollment tracker: $ENROLLMENT_LOG" -ForegroundColor Green
}
