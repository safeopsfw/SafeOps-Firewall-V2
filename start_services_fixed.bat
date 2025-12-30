@echo off
REM SafeOps Complete Integration Suite - Windows Launcher (FIXED)
REM Starts: Certificate Manager + DHCP Server + NIC Management + WiFi AP
REM WITHOUT using 'tee' command (Windows-compatible)

title SafeOps - Complete Integration Suite

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Requesting administrator privileges...
    echo    DHCP Server requires admin rights
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║     SafeOps - Complete Integration Suite (Running)           ║
echo ║  Services: Certificate Manager + DHCP + Components           ║
echo ║            ✅ Running as Administrator                         ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM Create logs directory
if not exist "logs" mkdir logs
echo 📁 Logs directory: %~dp0logs
echo.

REM ============================================================================
REM Start Certificate Manager
REM ============================================================================
echo ═══════════════════════════════════════════════════════════════
echo 🔐 Starting Certificate Manager...
echo    gRPC Port: 50053
echo    HTTP Port: 8093
echo    Log: logs\certificate_manager.log
echo ═══════════════════════════════════════════════════════════════
cd /d "%~dp0"
start "Certificate Manager" cmd /k "bin\certificate_manager.exe > logs\certificate_manager.log 2>&1"
timeout /t 3 /nobreak >nul

REM ============================================================================
REM Start DHCP Server
REM ============================================================================
echo.
echo ═══════════════════════════════════════════════════════════════
echo 🌐 Starting DHCP Server...
echo    DHCP Port: 67 (UDP)
echo    gRPC Port: 50055
echo    Log: logs\dhcp_server.log
echo ═══════════════════════════════════════════════════════════════
start "DHCP Server" cmd /k "bin\dhcp_server.exe > logs\dhcp_server.log 2>&1"
timeout /t 3 /nobreak >nul

REM ============================================================================
REM Service Status
REM ============================================================================
echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                   ✅ SERVICES STARTED                          ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo 📋 Services Running:
echo    • Certificate Manager: localhost:50053 (gRPC), localhost:8093 (HTTP)
echo    • DHCP Server: 0.0.0.0:67 (UDP), localhost:50055 (gRPC)
echo.
echo 📊 Log Files:
echo    • logs\certificate_manager.log
echo    • logs\dhcp_server.log
echo.
echo 🔍 Testing Commands:
echo    curl http://localhost:8093/health
echo    netstat -an ^| findstr "50053 8093 67 50055"
echo.
echo ═══════════════════════════════════════════════════════════════
echo Press any key to STOP ALL SERVICES...
pause >nul

REM ============================================================================
REM Cleanup: Stop all services
REM ============================================================================
echo.
echo 🛑 Stopping all services...
taskkill /FI "WindowTitle eq Certificate Manager*" /F >nul 2>&1
taskkill /FI "WindowTitle eq DHCP Server*" /F >nul 2>&1
echo ✅ All services stopped
echo.
pause
