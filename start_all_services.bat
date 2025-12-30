@echo off
REM SafeOps Complete Integration Suite - Windows Launcher
REM Starts: Certificate Manager + DHCP Server + NIC Management + WiFi AP
REM With comprehensive logging for CA certificate distribution

title SafeOps - Complete Integration Suite

REM Check for admin privileges and auto-elevate if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Requesting administrator privileges...
    echo    DHCP Server and WiFi AP require admin rights
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║     SafeOps - Complete Integration Suite (NAT Ready)         ║
echo ║                                                               ║
echo ║  Services: Certificate Manager + DHCP + NIC + WiFi AP        ║
echo ║  Features: Auto CA Distribution + Device Tracking             ║
echo ║            ✅ Running as Administrator                         ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM Create logs directory
if not exist "logs" mkdir logs
echo 📁 Created logs directory at: %~dp0logs
echo.

REM Clean old logs
del /q logs\*.log 2>nul
echo 🧹 Cleaned old log files
echo.

REM ============================================================================
REM Start Certificate Manager (Port 50060 gRPC, 8080 HTTP)
REM ============================================================================
echo.
echo ═══════════════════════════════════════════════════════════════
echo 🔐 Starting Certificate Manager with Auto-Renewal...
echo ═══════════════════════════════════════════════════════════════
echo    gRPC Port: 50060
echo    HTTP Port: 8080
echo    Renewal Monitor: Enabled
echo    Log File: logs\certificate_manager.log
echo.
cd /d "%~dp0src\certificate_manager"
start "Certificate Manager" cmd /k "go run ./cmd/main.go 2>&1 | tee ..\..\logs\certificate_manager.log"
timeout /t 3 /nobreak >nul

REM ============================================================================
REM Start DHCP Server with CA Integration (Port 67 UDP, 50054 gRPC)
REM ============================================================================
echo.
echo ═══════════════════════════════════════════════════════════════
echo 🌐 Starting DHCP Server with CA Integration...
echo ═══════════════════════════════════════════════════════════════
echo    DHCP Port: 67 (UDP)
echo    gRPC Port: 50054
echo    CA Options: 224-230 (enabled)
echo    Auto-Deploy: Enabled
echo    Log File: logs\dhcp_server.log
echo.
cd /d "%~dp0src\dhcp_server"
start "DHCP Server" cmd /k "go run ./cmd/main.go 2>&1 | tee ..\..\logs\dhcp_server.log"
timeout /t 3 /nobreak >nul

REM ============================================================================
REM Start NIC Management (Port 50051 gRPC, 8081 REST)
REM ============================================================================
echo.
echo ═══════════════════════════════════════════════════════════════
echo 🔌 Starting NIC Management...
echo ═══════════════════════════════════════════════════════════════
echo    gRPC Port: 50051
echo    REST Port: 8081
echo    Device Detection: Enabled
echo    Log File: logs\nic_management.log
echo.
cd /d "%~dp0src\nic_management"
start "NIC Management" cmd /k "go run ./cmd/main.go 2>&1 | tee ..\..\logs\nic_management.log"
timeout /t 2 /nobreak >nul

REM ============================================================================
REM Start WiFi AP / Captive Portal (Port 80 HTTP)
REM ============================================================================
echo.
echo ═══════════════════════════════════════════════════════════════
echo 📡 Starting WiFi AP / Captive Portal...
echo ═══════════════════════════════════════════════════════════════
echo    HTTP Port: 80
echo    Captive Portal: Enabled
echo    Android Support: Enabled
echo    Log File: logs\wifi_ap.log
echo.
cd /d "%~dp0src\wifi_ap"
start "WiFi AP" cmd /k "go run ./cmd/main.go 2>&1 | tee ..\..\logs\wifi_ap.log"
timeout /t 2 /nobreak >nul

REM ============================================================================
REM Start Log Monitor (Real-time log aggregation)
REM ============================================================================
echo.
echo ═══════════════════════════════════════════════════════════════
echo 📊 Starting Real-Time Log Monitor...
echo ═══════════════════════════════════════════════════════════════
cd /d "%~dp0"
start "Log Monitor" powershell -NoExit -Command ^
    "Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Cyan; ^
     Write-Host '          SafeOps Real-Time Log Monitor' -ForegroundColor Green; ^
     Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Cyan; ^
     Write-Host ''; ^
     Write-Host 'Monitoring logs for:' -ForegroundColor Yellow; ^
     Write-Host '  - DHCP DISCOVER/OFFER/REQUEST/ACK' -ForegroundColor White; ^
     Write-Host '  - CA Certificate Distribution (Options 224-230)' -ForegroundColor White; ^
     Write-Host '  - Device Detection and Tracking' -ForegroundColor White; ^
     Write-Host '  - Certificate Installation Reports' -ForegroundColor White; ^
     Write-Host '  - Auto-Renewal Events' -ForegroundColor White; ^
     Write-Host ''; ^
     Write-Host 'Press Ctrl+C to stop monitoring' -ForegroundColor Gray; ^
     Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Cyan; ^
     Write-Host ''; ^
     Get-Content -Path 'logs\certificate_manager.log','logs\dhcp_server.log','logs\nic_management.log','logs\wifi_ap.log' -Wait -Tail 0 | ^
     ForEach-Object { ^
         if ($_ -match 'ERROR|FAILED|FAIL') { ^
             Write-Host $_ -ForegroundColor Red ^
         } elseif ($_ -match 'SUCCESS|COMPLETE|✅') { ^
             Write-Host $_ -ForegroundColor Green ^
         } elseif ($_ -match 'DHCP|ACK|OFFER|DISCOVER') { ^
             Write-Host $_ -ForegroundColor Cyan ^
         } elseif ($_ -match 'CERTIFICATE|CA|Option 224|Option 225|Option 226|Option 227') { ^
             Write-Host $_ -ForegroundColor Magenta ^
         } elseif ($_ -match 'RENEWAL|RENEW') { ^
             Write-Host $_ -ForegroundColor Yellow ^
         } elseif ($_ -match 'DEVICE|CLIENT|INSTALL') { ^
             Write-Host $_ -ForegroundColor Blue ^
         } else { ^
             Write-Host $_ -ForegroundColor White ^
         } ^
     }"

REM ============================================================================
REM Wait for services to initialize
REM ============================================================================
echo.
echo ⏳ Waiting for all services to initialize...
echo    Certificate Manager: 3 seconds
echo    DHCP Server: 3 seconds
echo    NIC Management: 2 seconds
echo    WiFi AP: 2 seconds
echo.
timeout /t 5 /nobreak >nul

REM ============================================================================
REM Service Status Check
REM ============================================================================
echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                   ✅ ALL SERVICES STARTED                      ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo 📋 Service Endpoints:
echo.
echo    🔐 Certificate Manager:
echo       • gRPC API:  localhost:50060
echo       • HTTP API:  localhost:8080
echo       • Status:    http://localhost:8080/health
echo.
echo    🌐 DHCP Server:
echo       • DHCP Port: 0.0.0.0:67 (UDP)
echo       • gRPC API:  localhost:50054
echo       • CA Options: Enabled (224-230)
echo.
echo    🔌 NIC Management:
echo       • gRPC API:  localhost:50051
echo       • REST API:  http://localhost:8081
echo.
echo    📡 WiFi AP / Captive Portal:
echo       • HTTP Portal: http://localhost:80
echo       • Android: http://localhost:80/android
echo.
echo ═══════════════════════════════════════════════════════════════
echo.
echo 📊 Log Files (Real-time):
echo    • logs\certificate_manager.log
echo    • logs\dhcp_server.log
echo    • logs\nic_management.log
echo    • logs\wifi_ap.log
echo.
echo 📱 Testing URLs:
echo    • Android Install: http://192.168.1.1/android
echo    • Kali Install:    curl -s http://192.168.1.1/install-ca.sh ^| bash
echo    • Health Check:    curl http://localhost:8080/health
echo.
echo ═══════════════════════════════════════════════════════════════
echo.
echo 🔍 What to Look For in Logs:
echo.
echo    DHCP Events:
echo       ✅ [DHCP] DISCOVER received from XX:XX:XX:XX:XX:XX
echo       ✅ [DHCP] OFFER sent with IP 192.168.1.X
echo       ✅ [DHCP] REQUEST received
echo       ✅ [DHCP] ACK sent with CA options 224-230
echo.
echo    CA Distribution Events:
echo       ✅ [CA] Option 224: CA URL = http://192.168.1.1/ca.crt
echo       ✅ [CA] Option 227: Fingerprint = XXXX...
echo       ✅ [AUTO-DEPLOY] Triggering installation for device
echo.
echo    Certificate Installation:
echo       ✅ [INSTALLATION] Device XX:XX:XX:XX:XX:XX - Status: success
echo       ✅ [CERT-MANAGER] Device registered in database
echo.
echo    Auto-Renewal Events:
echo       ✅ [RENEWAL] Starting CA certificate renewal...
echo       ✅ [RENEWAL] New CA generated
echo       ✅ [RENEWAL] DHCP options updated
echo.
echo ═══════════════════════════════════════════════════════════════
echo.
echo 🌐 Network Configuration:
echo    • NAT Network: Ready for VirtualBox NAT testing
echo    • Hotspot: Ready for OnePlus connection
echo    • IP Range: 192.168.1.0/24 (typical)
echo.
echo 📝 Next Steps:
echo    1. Check Log Monitor window for real-time events
echo    2. Connect OnePlus to hotspot
echo    3. OnePlus will auto-receive DHCP + CA options
echo    4. Visit http://192.168.1.1/android on OnePlus
echo    5. Tap "Download ^& Install Certificate"
echo    6. Monitor logs for installation confirmation
echo.
echo ═══════════════════════════════════════════════════════════════
echo.
echo Press any key to STOP ALL SERVICES and exit...
echo (Check Log Monitor window for real-time events)
echo.
pause >nul

REM ============================================================================
REM Cleanup: Stop all services
REM ============================================================================
echo.
echo 🛑 Stopping all services...
echo.

taskkill /FI "WindowTitle eq Certificate Manager*" /F >nul 2>&1
if %errorlevel% equ 0 (echo    ✅ Certificate Manager stopped) else (echo    ⚠️  Certificate Manager not running)

taskkill /FI "WindowTitle eq DHCP Server*" /F >nul 2>&1
if %errorlevel% equ 0 (echo    ✅ DHCP Server stopped) else (echo    ⚠️  DHCP Server not running)

taskkill /FI "WindowTitle eq NIC Management*" /F >nul 2>&1
if %errorlevel% equ 0 (echo    ✅ NIC Management stopped) else (echo    ⚠️  NIC Management not running)

taskkill /FI "WindowTitle eq WiFi AP*" /F >nul 2>&1
if %errorlevel% equ 0 (echo    ✅ WiFi AP stopped) else (echo    ⚠️  WiFi AP not running)

taskkill /FI "WindowTitle eq Log Monitor*" /F >nul 2>&1
if %errorlevel% equ 0 (echo    ✅ Log Monitor stopped) else (echo    ⚠️  Log Monitor not running)

echo.
echo ✅ All services stopped successfully!
echo.
echo 📋 Log files preserved in: %~dp0logs\
echo    You can review them for debugging
echo.
echo 👋 Goodbye!
timeout /t 3 /nobreak >nul
