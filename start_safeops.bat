@echo off
REM SafeOps Complete Network Suite - All 4 Modules
REM Starts: NIC API, DHCP Server, Certificate Manager, Threat Intel, Dev UI
REM Version: 2.0

title SafeOps - Complete 4-Module Suite

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting administrator privileges...
    echo     DHCP and Hotspot require admin rights
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cls
echo.
echo  ============================================================
echo                SafeOps Network Security Suite
echo                     Complete 4-Module Startup
echo                   Running as Administrator
echo  ============================================================
echo.
echo  Modules:
echo    1. Certificate Manager (CA Distribution + Captive Portal)
echo    2. DHCP Server (IP Assignment + CA Integration)
echo    3. NIC Management API (Network Interface Control)
echo    4. Threat Intelligence (Malicious Domain/IP Database)
echo    5. Dev UI (React Dashboard)
echo.
echo  ============================================================
echo.

REM Change to script directory
cd /d "%~dp0"

REM ========================================
REM 1. Start Certificate Manager FIRST
REM ========================================
echo [1/5] Starting Certificate Manager...
cd /d "%~dp0src\certificate_manager"
start "SafeOps-CertManager" cmd /k "title SafeOps Certificate Manager && color 0A && go run ./cmd/."
echo       Waiting for Certificate Manager (5s)...
timeout /t 5 /nobreak >nul

REM ========================================
REM 2. Start DHCP Server
REM ========================================
echo [2/5] Starting DHCP Server...
cd /d "%~dp0src\dhcp_server"
start "SafeOps-DHCP" cmd /k "title SafeOps DHCP Server && color 0B && go run ./cmd/."
echo       Waiting for DHCP Server (3s)...
timeout /t 3 /nobreak >nul

REM ========================================
REM 3. Start NIC Management API
REM ========================================
echo [3/5] Starting NIC Management API...
cd /d "%~dp0src\nic_management\api"
start "SafeOps-NIC" cmd /k "title SafeOps NIC API && color 0C && go run cmd/main.go"
echo       Waiting for NIC API (3s)...
timeout /t 3 /nobreak >nul

REM ========================================
REM 4. Start Threat Intelligence API
REM ========================================
echo [4/5] Starting Threat Intelligence API...
cd /d "%~dp0src\threat_intel"
start "SafeOps-ThreatIntel" cmd /k "title SafeOps Threat Intel && color 0D && go run ./cmd/api/."
echo       Waiting for Threat Intel API (3s)...
timeout /t 3 /nobreak >nul

REM ========================================
REM 5. Start React Dev UI
REM ========================================
echo [5/5] Starting React Dev UI...
cd /d "%~dp0src\ui\dev"
start "SafeOps-UI" cmd /k "title SafeOps Dev UI && color 0E && npm run dev"
echo       Waiting for Dev UI (5s)...
timeout /t 5 /nobreak >nul

REM ========================================
REM Open browser
REM ========================================
echo.
echo [*] Opening browser...
start http://localhost:3001

echo.
echo  ============================================================
echo                    All Services Started!
echo  ============================================================
echo.
echo  Service Endpoints:
echo    Certificate Manager:  http://localhost:8082
echo                          gRPC: 50060
echo    DHCP Server:          Port 67 (UDP)
echo                          gRPC: 50055
echo    NIC Management API:   http://localhost:8081/api
echo    Threat Intel API:     http://localhost:8084/api
echo    Dev UI Dashboard:     http://localhost:3001
echo.
echo  CA Certificate Distribution:
echo    CA Certificate:       http://192.168.137.1:8082/ca.crt
echo    Trust Guide:          http://192.168.137.1:8082/trust-guide
echo    Linux Install:        http://192.168.137.1:8082/install-ca.sh
echo    Android Install:      http://192.168.137.1:8082/ca-android.crt
echo.
echo  ============================================================
echo.
echo  Press any key to STOP all services and exit...
pause >nul

REM ========================================
REM Stop all services
REM ========================================
echo.
echo [*] Stopping all services...
taskkill /FI "WindowTitle eq SafeOps Certificate Manager*" /F >nul 2>&1
taskkill /FI "WindowTitle eq SafeOps DHCP Server*" /F >nul 2>&1
taskkill /FI "WindowTitle eq SafeOps NIC API*" /F >nul 2>&1
taskkill /FI "WindowTitle eq SafeOps Threat Intel*" /F >nul 2>&1
taskkill /FI "WindowTitle eq SafeOps Dev UI*" /F >nul 2>&1

echo [+] All services stopped. Goodbye!
timeout /t 2 /nobreak >nul
